#!/usr/bin/env python3
"""Castle secrets store — encrypted API keys and tokens, per user vault.

The key storage vault has to be goddamn good: real API keys (trading
accounts, crypto) will live here. The bar is production secrets, so
every refusal fails closed and every byte of key material is accounted
for.

Design — no new crypto scheme, just the module's existing patterns:
  - Every secret is encrypted at rest with the vault owner's 256-bit
    data key from the flamethrower keyring (keys/<user>.key), using the
    same suite as vault_lock.py: AES-256-CBC + HMAC-SHA256
    encrypt-then-MAC via the on-machine openssl CLI. HMAC is verified
    before decryption; the plaintext SHA-256 is verified after.
  - Domain separation: the HMAC key is HMAC-SHA256(data_key,
    b"castle-secrets-mac-v1") — never the same MAC key as vault
    sealing, so a sealed .castle file and a secret can never be
    confused for each other.
  - Layout: vaults/<user>/secrets/<name>.secret (0600) — single-line
    JSON header + raw ciphertext, the same shape as .castle files.
    vaults/<user>/secrets/index.json (0600) is the registry: names +
    timestamps only, NEVER values.
  - The secret value arrives via stdin or a 0600 file. It is NEVER a
    CLI argument — argv lands in shell history and the process table.
  - Adult-only surface, same gate as integrations: child accounts are
    refused for every operation. add/rotate/delete write to
    activity.jsonl by NAME only. get-secret prints to stdout and logs
    nothing — a read is not an audit event.
  - Deleting a secret = typed confirmation (the secret's name) +
    3-pass CSPRNG overwrite + unlink (the flamethrower crypto-shred
    primitive), then the index entry is dropped.
  - delete-user crypto-shreds every secret ciphertext before the tree
    wipe (defense in depth); verify() checks secrets perms.

Stdlib only + the on-machine openssl CLI. No network, no new hosts.

Refusals (all fail closed, all ValueError):
  unknown user | child account | empty secret | oversize secret |
  duplicate name | unknown secret name | path traversal in names |
  secret file not 0600 / is a symlink / missing / empty |
  tampered ciphertext (HMAC mismatch) | wrong key
"""

import hashlib
import hmac as hmac_std
import json
import os
import stat
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import vault  # noqa: E402  (shared: _ensure_dirs, _load_users, _activity)
import vault_lock as _vl  # noqa: E402  (openssl suite + helpers)

sys.path.insert(0, os.path.join(_HERE, "..", "flamethrower"))
import keyring  # noqa: E402  (name validation + crypto-shred primitive)

FORMAT = "castle-secret/v1"
MAC_LABEL = b"castle-secrets-mac-v1"
MAX_SECRET_BYTES = 1024 * 1024  # 1 MiB sanity cap; real API keys are tiny
SECRET_EXT = ".secret"
INDEX_NAME = "index.json"


# ---------------------------------------------------------------------------
# plumbing
# ---------------------------------------------------------------------------

def _ts():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _secrets_dir(root, user):
    d = os.path.join(root, "vaults", user, "secrets")
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def _index_path(root, user):
    return os.path.join(_secrets_dir(root, user), INDEX_NAME)


def _load_index(root, user):
    path = _index_path(root, user)
    if not os.path.exists(path):
        return {"version": 1, "secrets": {}}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _save_index(root, user, doc):
    path = _index_path(root, user)
    tmp = path + ".tmp.%d" % os.getpid()
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _secret_path(root, user, name):
    # name is validated before this is ever called — no separators,
    # no "..", no traversal possible.
    return os.path.join(_secrets_dir(root, user), name + SECRET_EXT)


def _check_name(name):
    # The flamethrower name gate: alnum plus -_. only, max 64 chars.
    # Kills path traversal ("../x", "a/b") at the door.
    if not keyring._valid_name(name):
        raise ValueError("invalid secret name: %r" % name)


def _check_secret_bytes(secret):
    if not isinstance(secret, (bytes, bytearray)):
        raise ValueError("secret must be bytes")
    if len(secret) == 0:
        raise ValueError("refusing to store an empty secret")
    if len(secret) > MAX_SECRET_BYTES:
        raise ValueError(
            "secret too large: %d bytes (max %d)" % (len(secret),
                                                     MAX_SECRET_BYTES))


def _require_adult(root, user):
    """The secrets surface is adult-only — same gate as integrations."""
    vault._ensure_dirs(root)
    users = vault._load_users(root)
    rec = vault._require_user(users, user)
    if rec["tier"] != "adult":
        raise ValueError(
            "secrets are adult-only (child account: %s)" % user)
    return rec


def _user_key(root, user):
    """The vault owner's 256-bit data key from the flamethrower keyring."""
    path = os.path.join(vault.keyroot(root), "keys", user + ".key")
    if not os.path.isfile(path):
        raise ValueError("no keyring key for user: %s" % user)
    with open(path, "rb") as f:
        key = f.read()
    if len(key) != keyring.KEY_BYTES:
        raise ValueError("keyring key for %s is not 256 bits" % user)
    return key


# ---------------------------------------------------------------------------
# crypto — the vault_lock suite, domain-separated
# ---------------------------------------------------------------------------

def _mac_key(data_key):
    """HMAC key for the secrets domain. Deterministic, never stored —
    one data key, two purposes, no cross-domain confusion."""
    out = _vl._openssl(["mac", "-digest", "SHA256",
                        "-macopt", "hexkey:" + data_key.hex(), "HMAC"],
                       data=MAC_LABEL)
    return bytes.fromhex(out.decode().strip().replace(":", ""))


def _suite():
    cipher, mac = _vl.select_cipher()
    if (cipher, mac) != ("aes-256-cbc", "hmac-sha256"):
        raise ValueError(
            "fail closed: secrets need aes-256-cbc+hmac-sha256, "
            "on-machine openssl offered %r" % ((cipher, mac),))
    return cipher, mac


def _encrypt(data_key, plaintext):
    cipher, mac = _suite()
    iv = os.urandom(16)  # CSPRNG, same source as secrets.token_bytes
    ct = _vl._openssl(["enc", "-e", "-aes-256-cbc",
                       "-K", data_key.hex(), "-iv", iv.hex()],
                      data=plaintext)
    tag = _vl._openssl(["mac", "-digest", "SHA256",
                        "-macopt", "hexkey:" + _mac_key(data_key).hex(),
                        "HMAC"],
                       data=ct).decode().strip().replace(":", "")
    header = {
        "format": FORMAT,
        "cipher": cipher,
        "mac": mac,
        "iv": iv.hex(),
        "hmac": tag,
        "sha256": hashlib.sha256(plaintext).hexdigest(),
        "created": _ts(),
    }
    return header, ct


def _write_secret_file(path, header, ct):
    tmp = path + ".tmp.%d" % os.getpid()
    with open(tmp, "wb") as f:
        f.write((json.dumps(header, sort_keys=True) + "\n").encode("utf-8"))
        f.write(ct)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _read_secret_file(path):
    with open(path, "rb") as f:
        raw = f.read()
    header_raw, sep, ct = raw.partition(b"\n")
    if not sep:
        raise ValueError("corrupt secret file (no header line)")
    try:
        header = json.loads(header_raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ValueError("corrupt secret file (bad header)")
    if not isinstance(header, dict) or header.get("format") != FORMAT:
        raise ValueError("not a castle secret file (bad format id)")
    return header, ct


def _decrypt(data_key, header, ct):
    """Verify HMAC first, decrypt second, verify plaintext hash third.
    Tampered ciphertext is refused, never half-read."""
    if header.get("cipher") != "aes-256-cbc" or \
            header.get("mac") != "hmac-sha256":
        raise ValueError("unsupported cipher suite in secret header: %r"
                         % header.get("cipher"))
    expect = bytes.fromhex(header["hmac"].replace(":", ""))
    got_hex = _vl._openssl(
        ["mac", "-digest", "SHA256",
         "-macopt", "hexkey:" + _mac_key(data_key).hex(), "HMAC"],
        data=ct).decode().strip().replace(":", "")
    if not hmac_std.compare_digest(bytes.fromhex(got_hex), expect):
        raise ValueError(
            "HMAC mismatch — secret file is tampered or the wrong key; "
            "refusing to decrypt")
    pt = _vl._openssl(["enc", "-d", "-aes-256-cbc",
                       "-K", data_key.hex(), "-iv", header["iv"]],
                      data=ct)
    if hashlib.sha256(pt).hexdigest() != header["sha256"]:
        raise ValueError("plaintext hash mismatch after decrypt — refusing")
    return pt


# ---------------------------------------------------------------------------
# secret input — stdin or a 0600 file, never a CLI arg
# ---------------------------------------------------------------------------

def read_secret_input(secret_file=None):
    """Read the secret value. A CLI argument is never an option: argv
    lands in shell history and the process table."""
    if secret_file is not None:
        if not os.path.isfile(secret_file):
            raise ValueError("secret file not found: %s" % secret_file)
        if os.path.islink(secret_file):
            raise ValueError("secret file must not be a symlink: %s"
                             % secret_file)
        mode = stat.S_IMODE(os.stat(secret_file).st_mode)
        if mode != 0o600:
            raise ValueError(
                "refusing secret file %s: mode is %04o, must be exactly "
                "0600 (chmod it yourself)" % (secret_file, mode))
        with open(secret_file, "rb") as f:
            data = f.read()
    else:
        data = sys.stdin.buffer.read()
    _check_secret_bytes(data)
    return data


# ---------------------------------------------------------------------------
# public operations
# ---------------------------------------------------------------------------

def add_secret(root, user, name, secret):
    """Store a new secret, encrypted with the user's data key.

    Refuses: unknown user, child account, bad/duplicate name, empty
    or oversize secret. Logs the add by NAME only."""
    _check_name(name)
    _check_secret_bytes(secret)
    rec = _require_adult(root, user)
    idx = _load_index(root, user)
    if name in idx["secrets"]:
        raise ValueError(
            "secret already exists: %s (rotate-secret to change it)" % name)
    key = _user_key(root, user)
    try:
        header, ct = _encrypt(key, secret)
        _write_secret_file(_secret_path(root, user, name), header, ct)
    finally:
        # best-effort: drop key material from this process's memory view
        del key
        del secret
    idx["secrets"][name] = {"created": header["created"],
                            "rotated": header["created"],
                            "format": FORMAT}
    _save_index(root, user, idx)
    vault._activity(root, user, "secret.added",
                    "user=%s name=%s" % (user, name))
    return "secret %s stored for %s" % (name, rec["name"])


def get_secret(root, user, name):
    """Return the secret bytes. Prints nothing, logs nothing — the
    caller owns the output channel (the CLI writes it to stdout)."""
    _check_name(name)
    _require_adult(root, user)
    path = _secret_path(root, user, name)
    if not os.path.isfile(path):
        raise ValueError("no such secret: %s" % name)
    key = _user_key(root, user)
    try:
        header, ct = _read_secret_file(path)
        pt = _decrypt(key, header, ct)
    finally:
        del key
    return pt


def list_secrets(root, user):
    """Secret names for a user. Names only — values never leave the
    ciphertext files."""
    _require_adult(root, user)
    return sorted(_load_index(root, user)["secrets"])


def rotate_secret(root, user, name, secret):
    """Replace a secret's value: fresh IV, fresh ciphertext, same name.
    The old ciphertext is atomically replaced. Logged by name only."""
    _check_name(name)
    _check_secret_bytes(secret)
    _require_adult(root, user)
    idx = _load_index(root, user)
    if name not in idx["secrets"]:
        raise ValueError("no such secret: %s" % name)
    key = _user_key(root, user)
    try:
        header, ct = _encrypt(key, secret)
        _write_secret_file(_secret_path(root, user, name), header, ct)
    finally:
        del key
        del secret
    idx["secrets"][name]["rotated"] = header["created"]
    _save_index(root, user, idx)
    vault._activity(root, user, "secret.rotated",
                    "user=%s name=%s" % (user, name))
    return "secret %s rotated for %s" % (name, user)


def delete_secret(root, user, name, confirm=None):
    """Crypto-shred a secret: 3-pass CSPRNG overwrite + unlink, index
    entry dropped. Dry-run by default; the real burn needs the secret's
    name typed back. Logged by name only."""
    _check_name(name)
    _require_adult(root, user)
    idx = _load_index(root, user)
    if name not in idx["secrets"]:
        raise ValueError("no such secret: %s" % name)
    path = _secret_path(root, user, name)
    if confirm != name:
        return {"dry_run": True,
                "would_destroy": ["secret ciphertext: %s" % path],
                "hint": "re-run with --yes %s to burn it" % name}
    if os.path.isfile(path) and not os.path.islink(path):
        keyring._overwrite_and_unlink(path)
    del idx["secrets"][name]
    _save_index(root, user, idx)
    vault._activity(root, user, "secret.deleted",
                    "user=%s name=%s" % (user, name))
    return {"dry_run": False, "kills": [path]}
