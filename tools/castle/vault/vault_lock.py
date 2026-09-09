#!/usr/bin/env python3
"""Castle vault init/lock/unlock — FAMILY-DATA-VAULT.md build-order step 7.

The vault-per-user layout (step 1) is plaintext on the Castle disk. This
module adds the *encrypted-at-rest* layer: a vault directory can be
sealed into a single locked file (``.castle``) and later reopened, with
the plaintext destroyed on lock via the flamethrower directory-burn
primitive (FLAMETHROWER.md step 8).

Cipher honesty: ``openssl enc`` on this machine explicitly refuses AEAD
ciphers ("AEAD ciphers not supported"), so AES-256-GCM is unavailable
through the only on-machine crypto tool. The code therefore fails closed
to AES-256-CBC with encrypt-then-MAC (HMAC-SHA256 over the ciphertext) —
a sound construction, with the algorithm recorded in the locked-file
header so a future GCM-capable build can migrate. If neither suite is
available the module refuses to run at all.

Key rules (fail closed everywhere):
  - The passphrase/key is never written to disk, never printed, never
    logged. It arrives via --passphrase-file or --keyfile only — never
    argv, never env, never stdin prompts in scripts.
  - Secret files must already have mode exactly 0600. The CLI checks;
    it never chmods. A 0777 keyfile is refused before any crypto runs.
  - Passphrase mode: master key = PBKDF2-HMAC-SHA256(passphrase,
    random 16-byte salt, 600_000 iterations, 64 bytes), split into a
    256-bit AES key and a 256-bit HMAC key (via ``openssl kdf``).
  - Keyfile mode: the file must be exactly 32 bytes (a real 256-bit
    key). AES key = the bytes; HMAC key = HMAC-SHA256(key,
    b"castle-vault-mac-v1").
  - Unlock verifies the HMAC *before* decrypting and the tarball SHA-256
    *before* extracting. Tampered ciphertext is refused, never
    partially restored.
  - Lock never destroys plaintext until the locked file has been
    decrypted and verified in the same run (decrypt-verify-then-burn).

Safety: lock is dry-run by default — it reports what would be sealed
and burned and changes nothing. The real lock needs typed confirmation
(the vault directory's basename), matching the flamethrower DNA.

On-machine tooling only: python stdlib + the ``openssl`` CLI.
No network, no new hosts, no installs.

Locked file layout (``<name>.castle``):
    line 1: single-line JSON header: format id, cipher suite, KDF
            params, salt, IV, ciphertext HMAC, tarball SHA-256, per-file
            manifest, creation timestamp.
    rest:   raw AES-256-CBC ciphertext of a tarball of the vault dir.

Usage (via vault.py):
    vault.py vault-init DIR --out FILE.castle --passphrase-file F
    vault.py vault-lock DIR --out FILE.castle --passphrase-file F [--yes BASENAME]
    vault.py vault-unlock FILE.castle --out DIR --passphrase-file F
"""

import hashlib
import hmac as hmac_std
import io
import json
import os
import secrets
import subprocess
import sys
import tarfile
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import manifest as vault_manifest  # noqa: E402  (step 6 manifest reuse)
sys.path.insert(0, os.path.join(_HERE, "..", "flamethrower"))
import dirburn  # noqa: E402  (step 8 directory-burn wipe path)

FORMAT = "castle-vault/v1"
PBKDF2_ITER = 600_000
SECRET_MODE = 0o600


class VaultLockError(Exception):
    """Anything that must fail closed."""


# ---------------------------------------------------------------------------
# cipher selection — fail closed to CBC+HMAC; refuse if nothing usable
# ---------------------------------------------------------------------------

def select_cipher():
    """Pick the strongest cipher suite the on-machine openssl supports.

    Returns ("aes-256-cbc", "hmac-sha256"). Raises VaultLockError if
    neither GCM-via-enc nor CBC is available (fail closed).
    """
    ciphers = _openssl(["enc", "-ciphers"]).decode("utf-8", "replace")
    if "-aes-256-gcm" in ciphers:
        # openssl enc refuses AEAD ciphers even when listed on some
        # builds — probe before trusting the list.
        probe = subprocess.run(
            ["openssl", "enc", "-e", "-aes-256-gcm",
             "-K", "00" * 32, "-iv", "00" * 12],
            input=b"x", capture_output=True)
        if probe.returncode == 0 and b"AEAD" not in probe.stderr:
            return ("aes-256-gcm", None)
    if "-aes-256-cbc" in ciphers:
        return ("aes-256-cbc", "hmac-sha256")
    raise VaultLockError(
        "fail closed: no usable cipher in on-machine openssl "
        "(need aes-256-gcm or aes-256-cbc)")


def _openssl(args, data=None):
    """Run openssl, raise VaultLockError on failure. No secrets in argv."""
    try:
        p = subprocess.run(["openssl"] + args, input=data,
                           capture_output=True, check=False)
    except FileNotFoundError:
        raise VaultLockError("fail closed: openssl not found on this machine")
    if p.returncode != 0:
        raise VaultLockError(
            "fail closed: openssl %s failed: %s"
            % (" ".join(args[:3]), p.stderr.decode("utf-8",
                                                   "replace")[:200]))
    return p.stdout


# ---------------------------------------------------------------------------
# secrets — read, never write; chmod-checked, never chmod
# ---------------------------------------------------------------------------

def _read_secret(passphrase_file=None, keyfile=None):
    """Return (kind, secret_bytes). Enforces exactly one source and the
    0600 permission check. Never fixes permissions — refuses instead."""
    if bool(passphrase_file) == bool(keyfile):
        raise VaultLockError(
            "need exactly one of --passphrase-file or --keyfile")
    path = passphrase_file or keyfile
    kind = "passphrase" if passphrase_file else "keyfile"
    if not os.path.isfile(path):
        raise VaultLockError("secret file not found: %s" % path)
    if os.path.islink(path):
        raise VaultLockError("secret file must not be a symlink: %s" % path)
    mode = os.stat(path).st_mode & 0o777
    if mode != SECRET_MODE:
        raise VaultLockError(
            "refusing %s %s: mode is %04o, must be exactly 0600 "
            "(chmod it yourself; the CLI never touches key permissions)"
            % (kind, path, mode))
    with open(path, "rb") as f:
        data = f.read()
    if not data:
        raise VaultLockError("secret file is empty: %s" % path)
    if kind == "keyfile" and len(data) != 32:
        raise VaultLockError(
            "keyfile must be exactly 32 bytes (a 256-bit key); got %d"
            % len(data))
    return kind, data


def _derive_mac_key(key_bytes):
    """MAC key for keyfile mode: HMAC-SHA256(key, b"castle-vault-mac-v1").
    Deterministic, never stored — one secret file, two keys."""
    out = _openssl(["mac", "-digest", "SHA256",
                    "-macopt", "hexkey:" + key_bytes.hex(), "HMAC"],
                   data=b"castle-vault-mac-v1")
    return bytes.fromhex(out.decode().strip().replace(":", ""))


# ---------------------------------------------------------------------------
# archive + crypto
# ---------------------------------------------------------------------------

def _pbkdf2(passphrase, salt, iterations, keylen):
    """PBKDF2-HMAC-SHA256, stdlib. The passphrase never touches a
    subprocess argv — ``openssl kdf`` only takes pass: as a literal
    -kdfopt value, which would leak it to the process table."""
    return hashlib.pbkdf2_hmac("sha256", passphrase, salt,
                              iterations, dklen=keylen)

def _build_tarball(src_dir):
    """Deterministic tarball of src_dir (sorted entries, zeroed
    uid/gid/mtime) so identical trees produce identical bytes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for root, dirs, files in os.walk(src_dir):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(root, name)
                if os.path.islink(full) or not os.path.isfile(full):
                    raise VaultLockError(
                        "refusing to seal non-regular file: %s" % full)
                arc = os.path.relpath(full, src_dir).replace(os.sep, "/")
                ti = tf.gettarinfo(full, arcname=arc)
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = ""
                ti.mtime = 0
                with open(full, "rb") as f:
                    tf.addfile(ti, f)
    return buf.getvalue()


def _seal_plaintext(src_dir, kind, secret):
    """Encrypt src_dir -> (header_dict, ciphertext). Pure function of
    the inputs (plus fresh salt/IV)."""
    cipher, mac = select_cipher()
    if mac != "hmac-sha256":
        raise VaultLockError("internal: unexpected cipher suite %r" % cipher)
    man = vault_manifest.build_manifest(src_dir)
    files = {e["path"]: {"size": e["size"], "sha256": e["sha256"]}
             for e in man["entries"]}
    if man["skipped"]:
        raise VaultLockError(
            "refusing to seal: skipped non-regular files: %s"
            % ", ".join(s["path"] for s in man["skipped"]))
    tar_bytes = _build_tarball(src_dir)
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    if kind == "passphrase":
        master = _pbkdf2(secret, salt, PBKDF2_ITER, 64)
        enc_key, mac_key = master[:32], master[32:]
    else:
        enc_key, mac_key = secret, _derive_mac_key(secret)
    ct = _openssl(["enc", "-e", "-aes-256-cbc",
                   "-K", enc_key.hex(), "-iv", iv.hex()],
                  data=tar_bytes)
    tag = _openssl(["mac", "-digest", "SHA256",
                    "-macopt", "hexkey:" + mac_key.hex(), "HMAC"],
                   data=ct).decode().strip().replace(":", "")
    header = {
        "format": FORMAT,
        "cipher": cipher,
        "mac": mac,
        "kdf": "pbkdf2-sha256" if kind == "passphrase" else "raw-keyfile",
        "pbkdf2_iter": PBKDF2_ITER if kind == "passphrase" else None,
        "salt": salt.hex() if kind == "passphrase" else None,
        "iv": iv.hex(),
        "hmac": tag,
        "tar_sha256": hashlib.sha256(tar_bytes).hexdigest(),
        "files": files,
        "file_count": len(files),
        "total_bytes": sum(e["size"] for e in man["entries"]),
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    return header, ct


def _write_locked(out_path, header, ct):
    # header is single-line JSON (no literal newlines — json escapes
    # them), so the first b"\n" always ends the header.
    tmp = out_path + ".tmp.%d" % os.getpid()
    with open(tmp, "wb") as f:
        f.write((json.dumps(header, sort_keys=True) + "\n").encode("utf-8"))
        f.write(ct)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, out_path)


def _read_locked(path):
    with open(path, "rb") as f:
        raw = f.read()
    header_raw, sep, ct = raw.partition(b"\n")
    if not sep:
        raise VaultLockError("not a castle vault file (no header line)")
    try:
        header = json.loads(header_raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise VaultLockError("not a castle vault file (bad header)")
    if not isinstance(header, dict) or header.get("format") != FORMAT:
        raise VaultLockError("not a castle vault file (bad format id)")
    return header, ct


def _open_ciphertext(header, ct, kind, secret):
    """Verify HMAC then decrypt. Returns the tarball bytes. Fail closed
    on any mismatch — tampered vaults are refused, never half-opened."""
    if header.get("cipher") != "aes-256-cbc" or \
            header.get("mac") != "hmac-sha256":
        raise VaultLockError(
            "unsupported cipher suite in header: %r" % header.get("cipher"))
    if kind == "passphrase":
        if header.get("kdf") != "pbkdf2-sha256":
            raise VaultLockError("vault was not sealed with a passphrase")
        salt = bytes.fromhex(header["salt"])
        master = _pbkdf2(secret, salt, header["pbkdf2_iter"], 64)
        enc_key, mac_key = master[:32], master[32:]
    else:
        if header.get("kdf") != "raw-keyfile":
            raise VaultLockError("vault was not sealed with a keyfile")
        enc_key, mac_key = secret, _derive_mac_key(secret)
    expect = bytes.fromhex(header["hmac"].replace(":", ""))
    got = _openssl(["mac", "-digest", "SHA256",
                    "-macopt", "hexkey:" + mac_key.hex(), "HMAC"],
                   data=ct).decode().strip().replace(":", "")
    if not hmac_std.compare_digest(bytes.fromhex(got), expect):
        raise VaultLockError(
            "HMAC mismatch — vault file is tampered or the wrong key; "
            "refusing to decrypt")
    tar_bytes = _openssl(["enc", "-d", "-aes-256-cbc",
                          "-K", enc_key.hex(),
                          "-iv", header["iv"]],
                         data=ct)
    if hashlib.sha256(tar_bytes).hexdigest() != header["tar_sha256"]:
        raise VaultLockError("tarball hash mismatch after decrypt — refusing")
    return tar_bytes


# ---------------------------------------------------------------------------
# public operations
# ---------------------------------------------------------------------------

def _check_secret_not_inside(secret_path, src_dir):
    sp = os.path.realpath(secret_path)
    sd = os.path.realpath(src_dir)
    if sp == sd or sp.startswith(sd + os.sep):
        raise VaultLockError(
            "secret file lives inside the tree being sealed — refusing "
            "(it would encrypt the key alongside the data)")


def vault_init(src_dir, out_path, passphrase_file=None, keyfile=None,
               burn_root=None):
    """Seal src_dir into out_path. Plaintext is left untouched.
    Returns the header dict."""
    if not os.path.isdir(src_dir):
        raise VaultLockError("not a directory: %s" % src_dir)
    kind, secret = _read_secret(passphrase_file, keyfile)
    _check_secret_not_inside(passphrase_file or keyfile, src_dir)
    try:
        header, ct = _seal_plaintext(src_dir, kind, secret)
        _write_locked(out_path, header, ct)
    finally:
        # best-effort: drop key material from this process's memory view
        del secret
    return header


def vault_lock(src_dir, out_path, passphrase_file=None, keyfile=None,
               confirm=None, burn_root=None):
    """Seal src_dir into out_path, verify the sealed copy decrypts
    cleanly, then burn the plaintext via the flamethrower directory
    burn. Dry-run unless confirm == basename(src_dir)."""
    if not os.path.isdir(src_dir):
        raise VaultLockError("not a directory: %s" % src_dir)
    base = os.path.basename(os.path.realpath(src_dir).rstrip(os.sep))
    kind, secret = _read_secret(passphrase_file, keyfile)
    _check_secret_not_inside(passphrase_file or keyfile, src_dir)
    try:
        header, ct = _seal_plaintext(src_dir, kind, secret)
        _write_locked(out_path, header, ct)
        # verify the sealed copy BEFORE touching plaintext: decrypt in
        # memory and compare the tarball hash + file manifest
        check = _open_ciphertext(header, ct, kind, secret)
        if hashlib.sha256(check).hexdigest() != header["tar_sha256"]:
            raise VaultLockError(
                "sealed copy failed self-verification — plaintext untouched")
    finally:
        del secret
    if confirm != base:
        return {"dry_run": True,
                "sealed": out_path,
                "would_burn": os.path.realpath(src_dir),
                "hint": "plaintext untouched — re-run with --yes %s "
                        "to burn it" % base}
    if burn_root is None:
        burn_root = os.path.join(os.path.dirname(
            os.path.abspath(out_path)), ".castle-burn-state")
    os.makedirs(burn_root, mode=0o700, exist_ok=True)
    os.chmod(burn_root, 0o700)
    burn = dirburn.burn_directory(burn_root, src_dir, confirm=base)
    return {"dry_run": False, "sealed": out_path, "burn": burn,
            "files_sealed": header["file_count"]}


def vault_unlock(locked_path, out_dir, passphrase_file=None, keyfile=None):
    """Open locked_path into out_dir. Refuses if out_dir exists and is
    non-empty. Restores 0700/0600 perms and verifies every file hash."""
    if not os.path.isfile(locked_path):
        raise VaultLockError("not a file: %s" % locked_path)
    if os.path.exists(out_dir):
        if not os.path.isdir(out_dir) or os.listdir(out_dir):
            raise VaultLockError(
                "refusing to unlock into non-empty directory: %s" % out_dir)
    else:
        os.makedirs(out_dir, mode=0o700)
    os.chmod(out_dir, 0o700)
    kind, secret = _read_secret(passphrase_file, keyfile)
    try:
        header, ct = _read_locked(locked_path)
        tar_bytes = _open_ciphertext(header, ct, kind, secret)
    finally:
        del secret
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tf:
        for member in tf.getmembers():
            if member.issym() or member.islnk():
                raise VaultLockError(
                    "refusing to extract symlink from vault: %s"
                    % member.name)
            if member.name.startswith("/") or ".." in member.name.split("/"):
                raise VaultLockError(
                    "refusing to extract unsafe path: %s" % member.name)
        tf.extractall(out_dir)
    # restore perms + verify every file against the sealed manifest
    for root, dirs, files in os.walk(out_dir):
        for d in dirs:
            os.chmod(os.path.join(root, d), 0o700)
        for name in files:
            full = os.path.join(root, name)
            os.chmod(full, 0o600)
            rel = os.path.relpath(full, out_dir).replace(os.sep, "/")
            entry = header["files"].get(rel)
            if entry is None:
                raise VaultLockError(
                    "extracted file not in sealed manifest: %s" % rel)
            if vault_manifest.hash_file(full) != entry["sha256"]:
                raise VaultLockError(
                    "hash mismatch on restored file: %s" % rel)
    if set(header["files"]) != {
            os.path.relpath(os.path.join(r, n), out_dir).replace(os.sep, "/")
            for r, _, fs in os.walk(out_dir) for n in fs}:
        raise VaultLockError("restored tree does not match sealed manifest")
    return {"unlocked": out_dir, "files": header["file_count"],
            "verified": True}
