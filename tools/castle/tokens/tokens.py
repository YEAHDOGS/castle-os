#!/usr/bin/env python3
"""DOGS encrypted token system — the token authority for the DOGS ecosystem.

The anti-JWT: claims are *encrypted*, not merely signed. Nothing readable
leaks onto the wire, and a token minted for one audience never works on
another.

Crypto discipline (follows castle/vault/vault_lock.py, improves where cheap):
  - On-machine ``openssl`` CLI only. No network, no installs, no new deps.
  - AES-256-CBC via ``openssl enc -pbkdf2``. The key/IV are derived
    internally from a 0600 keyfile passed as ``-pass file:<path>`` — key
    material NEVER appears in argv. (vault_lock passes ``-K <hex>`` on argv,
    briefly exposing it in the process table; this module does not.)
  - HMAC-SHA256 encrypt-then-MAC over the envelope, computed in stdlib
    ``hmac``. The MAC key is HMAC-SHA256(master, b"castle-tokens-mac-v1"+kid)
    via stdlib — domain-separated per key, microseconds, nothing in argv.
  - HMAC is verified BEFORE decrypt. Any tamper -> refused, fail closed.
  - GCM is probed at runtime; this machine's openssl refuses AEAD ciphers
    ("AEAD ciphers not supported"), so the suite is honestly recorded as
    aes-256-cbc + hmac-sha256 in every token header.

Envelope:  dogs1.<b64u(header)>.<b64u(ciphertext)>.<b64u(tag)>
  header     {"v":1,"kid":"...","cipher":"aes-256-cbc","mac":"hmac-sha256",
              "iter":100000}
  tag        HMAC-SHA256(mac_key, "<b64u(header)>.<b64u(ciphertext)>") (ASCII)
  ciphertext raw `openssl enc` output ("Salted__"+salt+ct), b64u-encoded
  plaintext  {"iss","aud","sub","iat","exp","jti","purpose"} (JSON, encrypted)

Key rotation: the keyring holds many kids; header.kid selects the key.
Old kids verify but never mint. Revocation: revoked.jsonl jti blacklist,
checked on every verify. See README.md for the full format spec.
"""

import argparse
import base64
import hashlib
import hmac as hmac_std
import json
import os
import re
import secrets
import subprocess
import sys
import time

FORMAT_PREFIX = "dogs1"
VERSION = 1
CIPHER = "aes-256-cbc"
MAC = "hmac-sha256"
ENC_PBKDF2_ITER = 100_000
# Why 100k and not 600k: keyring keys are 256-bit CSPRNG output, not
# passwords — iteration count is domain separation + per-token salt
# randomization, not brute-force armor. 100k keeps mint/verify ~0.5s.
SKEW = 300            # clock-skew leeway, seconds (documented in README)
MAX_TTL = 86400       # tokens are short-lived: max 24h
SECRET_MODE = 0o600
MAX_TOKEN_LEN = 16384
MAX_REVOKED_BYTES = 10 * 1024 * 1024
MAC_DOMAIN = b"castle-tokens-mac-v1"

KID_RE = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
PRINTABLE_RE = re.compile(r"^[\x20-\x7e]+$")
JTI_RE = re.compile(r"^[0-9a-f]{32}$")


class TokenError(Exception):
    """Anything that must fail closed."""


# ---------------------------------------------------------------------------
# base64url helpers
# ---------------------------------------------------------------------------

def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    if not s or len(s) > MAX_TOKEN_LEN:
        raise TokenError("bad base64url segment")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", s):
        raise TokenError("bad base64url segment")
    pad = "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad)
    except Exception:
        raise TokenError("bad base64url segment")


# ---------------------------------------------------------------------------
# openssl — key material never in argv (paths only)
# ---------------------------------------------------------------------------

def _openssl(args, data=None):
    """Run openssl. Secrets travel via -pass file: / stdin, never argv."""
    try:
        p = subprocess.run(["openssl"] + args, input=data,
                           capture_output=True, check=False)
    except FileNotFoundError:
        raise TokenError("fail closed: openssl not found on this machine")
    if p.returncode != 0:
        raise TokenError(
            "fail closed: openssl %s failed: %s"
            % (" ".join(args[:3]), p.stderr.decode("utf-8",
                                                   "replace")[:200]))
    return p.stdout


# ---------------------------------------------------------------------------
# keyring layout: <root>/ (0700)
#   keys/<kid>.key   32 raw bytes, 0600, never a symlink
#   keys.json        {kid: {created, status, note}}, 0600
#   revoked.jsonl    {"jti","exp","revoked_at","reason"}, 0600
# ---------------------------------------------------------------------------

def _root(d):
    return os.path.expanduser(d or "~/.castle-tokens")


def _key_path(root, kid):
    if not KID_RE.fullmatch(kid):
        raise TokenError("bad kid format (refusing path use)")
    return os.path.join(root, "keys", kid + ".key")


def _read_keyfile(path):
    if not os.path.isfile(path):
        raise TokenError("key file not found")
    if os.path.islink(path):
        raise TokenError("key file must not be a symlink")
    if os.stat(path).st_mode & 0o777 != SECRET_MODE:
        raise TokenError("key file must be mode 0600 (refusing)")
    with open(path, "rb") as f:
        data = f.read()
    if len(data) != 32:
        raise TokenError("key file must be exactly 32 bytes")
    return data


def _write_secret_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, SECRET_MODE)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    if os.stat(path).st_mode & 0o777 != SECRET_MODE:
        raise TokenError("failed to enforce 0600 on " + path)


def _meta_path(root):
    return os.path.join(root, "keys.json")


def _load_meta(root):
    p = _meta_path(root)
    if not os.path.isfile(p):
        raise TokenError("keyring not initialized (run: tokens.py init)")
    try:
        with open(p, "r", encoding="utf-8") as f:
            meta = json.load(f)
    except (ValueError, OSError):
        raise TokenError("keyring metadata unreadable (fail closed)")
    if not isinstance(meta, dict):
        raise TokenError("keyring metadata corrupt (fail closed)")
    return meta


def _save_meta(root, meta):
    p = _meta_path(root)
    tmp = p + ".tmp.%d" % os.getpid()
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(meta, f, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, SECRET_MODE)
    os.replace(tmp, p)


def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def init_keyring(d=None, note="genesis"):
    """Create the keyring layout and mint the first key. Refuses if one
    already exists (fail closed — no silent overwrite)."""
    root = _root(d)
    keys_dir = os.path.join(root, "keys")
    if os.path.exists(_meta_path(root)):
        raise TokenError("keyring already initialized at %s (refusing)" % root)
    os.makedirs(keys_dir, mode=0o700, exist_ok=True)
    os.chmod(keys_dir, 0o700)
    os.chmod(root, 0o700)
    kid = _gen_key(root, note=note)
    return {"root": root, "kid": kid}


def _gen_key(root, note=""):
    meta = _load_meta(root) if os.path.exists(_meta_path(root)) else {}
    while True:
        kid = "k" + secrets.token_hex(6)
        if kid not in meta and not os.path.exists(_key_path(root, kid)):
            break
    _write_secret_file(_key_path(root, kid), secrets.token_bytes(32))
    meta[kid] = {"created": _now_iso(), "status": "active", "note": note}
    _save_meta(root, meta)
    return kid


def _active_kid(root):
    meta = _load_meta(root)
    actives = [k for k, v in meta.items()
               if isinstance(v, dict) and v.get("status") == "active"]
    if not actives:
        raise TokenError("no active key — run: tokens.py rotate-keys")
    actives.sort(key=lambda k: meta[k].get("created", ""))
    return actives[-1]


def rotate_keys(d=None, note=""):
    """Generate a new key; all older kids retire (verify-only, never mint).
    Returns the new kid."""
    root = _root(d)
    meta = _load_meta(root)
    new_kid = _gen_key(root, note=note or "rotation")
    meta = _load_meta(root)
    for k, v in meta.items():
        if k != new_kid and isinstance(v, dict):
            v["status"] = "retired"
    _save_meta(root, meta)
    return {"root": root, "kid": new_kid}


def list_keys(d=None):
    """Kids + metadata only. Key bytes never leave the keyring."""
    root = _root(d)
    meta = _load_meta(root)
    return [{"kid": k,
             "created": v.get("created"),
             "status": v.get("status"),
             "note": v.get("note", "")}
            for k, v in sorted(meta.items()) if isinstance(v, dict)]


# ---------------------------------------------------------------------------
# crypto core
# ---------------------------------------------------------------------------

def _mac_key(master: bytes, kid: str) -> bytes:
    """Domain-separated MAC key, stdlib only (microseconds, no subprocess).

    master is 256-bit CSPRNG output, so a plain HMAC-PRF with a domain
    label is sound key separation — no per-token KDF needed. Same pattern
    as the vault secrets store (HMAC-SHA256(key, domain))."""
    return hmac_std.new(master, MAC_DOMAIN + kid.encode("ascii"),
                        hashlib.sha256).digest()


def _encrypt(keyfile: str, iters: int, plaintext: bytes) -> bytes:
    # -pass file: keeps key material out of argv entirely. Salt is random
    # per encryption and stored in the "Salted__" blob (public metadata).
    return _openssl(["enc", "-e", "-aes-256-cbc", "-pbkdf2",
                     "-iter", str(iters), "-pass", "file:" + keyfile],
                    data=plaintext)


def _decrypt(keyfile: str, iters: int, blob: bytes) -> bytes:
    try:
        return _openssl(["enc", "-d", "-aes-256-cbc", "-pbkdf2",
                         "-iter", str(iters), "-pass", "file:" + keyfile],
                        data=blob)
    except TokenError:
        raise TokenError("decrypt failed (wrong key or corrupt token)")


def _clean_str(name, value, maxlen):
    if not isinstance(value, str) or not value:
        raise TokenError("%s is required" % name)
    if len(value) > maxlen or not PRINTABLE_RE.fullmatch(value):
        raise TokenError("%s invalid (printable ASCII, max %d chars)"
                         % (name, maxlen))
    return value


# ---------------------------------------------------------------------------
# mint / verify
# ---------------------------------------------------------------------------

def mint(d=None, iss="", aud="", sub="", purpose="", ttl=600):
    """Mint a token. Returns the token string (a bearer credential —
    printing it to stdout is the operator's responsibility)."""
    root = _root(d)
    iss = _clean_str("iss", iss, 128)
    aud = _clean_str("aud", aud, 256)
    sub = _clean_str("sub", sub, 256)
    purpose = _clean_str("purpose", purpose, 64)
    if not isinstance(ttl, int) or isinstance(ttl, bool):
        raise TokenError("ttl must be an integer number of seconds")
    if not (1 <= ttl <= MAX_TTL):
        raise TokenError("ttl must be 1..%d seconds" % MAX_TTL)

    kid = _active_kid(root)
    keyfile = _key_path(root, kid)
    master = _read_keyfile(keyfile)

    now = int(time.time())
    claims = {
        "iss": iss,
        "aud": aud,
        "sub": sub,
        "iat": now,
        "exp": now + ttl,
        "jti": secrets.token_hex(16),
        "purpose": purpose,
    }
    plaintext = json.dumps(claims, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
    blob = _encrypt(keyfile, ENC_PBKDF2_ITER, plaintext)

    mac = _mac_key(master, kid)
    try:
        header = {"v": VERSION, "kid": kid, "cipher": CIPHER, "mac": MAC,
                  "iter": ENC_PBKDF2_ITER}
        h_b64 = _b64u_encode(json.dumps(header, sort_keys=True,
                                        separators=(",", ":")).encode("utf-8"))
        c_b64 = _b64u_encode(blob)
        tag = hmac_std.new(mac, (h_b64 + "." + c_b64).encode("ascii"),
                           hashlib.sha256).digest()
        return "%s.%s.%s.%s" % (FORMAT_PREFIX, h_b64, c_b64,
                                _b64u_encode(tag))
    finally:
        del master, mac


def _parse_envelope(token):
    if not isinstance(token, str):
        raise TokenError("token must be a string")
    token = token.strip()
    if len(token) > MAX_TOKEN_LEN or len(token) < 16:
        raise TokenError("bad token length")
    parts = token.split(".")
    if len(parts) != 4 or parts[0] != FORMAT_PREFIX:
        raise TokenError("bad token envelope")
    h_b64, c_b64, t_b64 = parts[1], parts[2], parts[3]
    try:
        header = json.loads(_b64u_decode(h_b64).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, TokenError):
        raise TokenError("bad token header")
    if not isinstance(header, dict) or header.get("v") != VERSION:
        raise TokenError("unsupported token version")
    if header.get("cipher") != CIPHER or header.get("mac") != MAC:
        raise TokenError("unsupported cipher suite")
    kid = header.get("kid")
    if not isinstance(kid, str) or not KID_RE.fullmatch(kid):
        raise TokenError("bad kid")
    iters = header.get("iter")
    if not isinstance(iters, int) or isinstance(iters, bool) or \
            not (1000 <= iters <= 2_000_000):
        raise TokenError("bad kdf iteration count")
    blob = _b64u_decode(c_b64)
    tag = _b64u_decode(t_b64)
    if len(tag) != 32:
        raise TokenError("bad tag length")
    return header, kid, iters, h_b64, c_b64, blob, tag


def _check_claims(claims, aud):
    if not isinstance(claims, dict):
        raise TokenError("claims not an object")
    for k in ("iss", "aud", "sub", "jti", "purpose"):
        v = claims.get(k)
        if not isinstance(v, str) or not v:
            raise TokenError("bad claim: %s" % k)
    for k in ("iat", "exp"):
        v = claims.get(k)
        if not isinstance(v, int) or isinstance(v, bool):
            raise TokenError("bad claim: %s" % k)
    if not JTI_RE.fullmatch(claims["jti"]):
        raise TokenError("bad jti")
    if claims["aud"] != aud:
        raise TokenError("audience mismatch")
    now = int(time.time())
    if now > claims["exp"] + SKEW:
        raise TokenError("token expired")
    if claims["iat"] > now + SKEW:
        raise TokenError("token issued in the future")


def verify(d=None, token="", aud=""):
    """Verify a token for an audience. Returns the claims dict on success;
    raises TokenError (fail closed) on anything wrong. Never leaks key
    material — errors name the failure, never the key."""
    root = _root(d)
    aud = _clean_str("aud", aud, 256)
    header, kid, iters, h_b64, c_b64, blob, tag = _parse_envelope(token)

    keyfile = _key_path(root, kid)   # kid format already validated
    master = _read_keyfile(keyfile)  # unknown kid -> "key file not found"
    try:
        mac = _mac_key(master, kid)
        expect = hmac_std.new(mac, (h_b64 + "." + c_b64).encode("ascii"),
                              hashlib.sha256).digest()
        if not hmac_std.compare_digest(expect, tag):
            raise TokenError("HMAC mismatch — token tampered or wrong key")
        plaintext = _decrypt(keyfile, iters, blob)
    finally:
        del master, mac
    try:
        claims = json.loads(plaintext.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise TokenError("claims undecodable")
    _check_claims(claims, aud)
    if is_revoked(root, claims["jti"]):
        raise TokenError("token revoked")
    return claims


# ---------------------------------------------------------------------------
# revocation — revoked.jsonl jti blacklist
# ---------------------------------------------------------------------------

def _revoked_path(root):
    return os.path.join(root, "revoked.jsonl")


def _read_revoked(root):
    p = _revoked_path(root)
    if not os.path.exists(p):
        return []
    if os.path.getsize(p) > MAX_REVOKED_BYTES:
        raise TokenError("revocation list too large — run prune-revoked")
    entries = []
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                raise TokenError("revocation list corrupt (fail closed)")
            if isinstance(e, dict) and isinstance(e.get("jti"), str):
                entries.append(e)
    return entries


def is_revoked(root, jti):
    root = _root(root)
    return any(e.get("jti") == jti for e in _read_revoked(root))


def revoke(d=None, jti_or_token="", reason=""):
    """Revoke by jti, or by full token (jti+exp are extracted, enabling
    later pruning). reason is optional free text (never key material)."""
    root = _root(d)
    exp = None
    jti = jti_or_token.strip()
    if jti.startswith(FORMAT_PREFIX + "."):
        # full token: parse (but do NOT require it to still verify — a
        # leaked token must be revocable even after expiry)
        try:
            header, kid, iters, h_b64, c_b64, blob, tag = _parse_envelope(jti)
            keyfile = _key_path(root, kid)
            master = _read_keyfile(keyfile)
            try:
                mac = _mac_key(master, kid)
                expect = hmac_std.new(
                    mac, (h_b64 + "." + c_b64).encode("ascii"),
                    hashlib.sha256).digest()
                if not hmac_std.compare_digest(expect, tag):
                    raise TokenError("cannot revoke: token HMAC invalid")
                claims = json.loads(_decrypt(keyfile, iters, blob)
                                    .decode("utf-8"))
            finally:
                del master, mac
            jti = claims.get("jti", "")
            exp = claims.get("exp")
        except TokenError as e:
            raise TokenError("cannot revoke: %s" % e)
    if not isinstance(jti, str) or not JTI_RE.fullmatch(jti):
        raise TokenError("bad jti")
    if reason and (not isinstance(reason, str) or len(reason) > 256 or
                   not PRINTABLE_RE.fullmatch(reason)):
        raise TokenError("bad reason")
    entry = {"jti": jti, "exp": exp if isinstance(exp, int) else None,
             "revoked_at": _now_iso(), "reason": reason or ""}
    p = _revoked_path(root)
    if not os.path.exists(p):
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, SECRET_MODE)
        os.close(fd)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
    return {"jti": jti, "revoked": True}


def prune_revoked(d=None):
    """Drop revocation entries whose token expired beyond the skew window.
    Entries revoked by bare jti (no exp) are kept — they can't be pruned."""
    root = _root(d)
    entries = _read_revoked(root)
    now = int(time.time())
    keep = [e for e in entries
            if not isinstance(e.get("exp"), int) or e["exp"] + SKEW >= now]
    dropped = len(entries) - len(keep)
    if dropped:
        p = _revoked_path(root)
        tmp = p + ".tmp.%d" % os.getpid()
        with open(tmp, "w", encoding="utf-8") as f:
            for e in keep:
                f.write(json.dumps(e, sort_keys=True) + "\n")
        os.chmod(tmp, SECRET_MODE)
        os.replace(tmp, p)
    return {"dropped": dropped, "kept": len(keep)}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser():
    p = argparse.ArgumentParser(
        description="DOGS encrypted token system — mint/verify bearer tokens")
    p.add_argument("--dir", default=None,
                   help="keyring root (default ~/.castle-tokens)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create keyring + first key")
    s.add_argument("--note", default="genesis")

    s = sub.add_parser("mint", help="mint a token (prints to stdout)")
    s.add_argument("--iss", required=True)
    s.add_argument("--aud", required=True)
    s.add_argument("--sub", required=True)
    s.add_argument("--purpose", required=True)
    s.add_argument("--ttl", type=int, default=600,
                   help="seconds, 1..86400 (default 600)")

    s = sub.add_parser("verify", help="verify a token for an audience")
    s.add_argument("token")
    s.add_argument("--aud", required=True)

    s = sub.add_parser("revoke", help="revoke by jti or full token")
    s.add_argument("jti_or_token")
    s.add_argument("--reason", default="")

    s = sub.add_parser("rotate-keys", help="new key; old kids verify-only")
    s.add_argument("--note", default="")

    sub.add_parser("list-keys", help="kids + metadata (never key bytes)")
    sub.add_parser("prune-revoked", help="drop expired revocation entries")
    return p


def main(argv=None):
    a = _build_parser().parse_args(argv)
    try:
        if a.cmd == "init":
            r = init_keyring(a.dir, note=a.note)
            print("keyring initialized: %s (kid %s)" % (r["root"], r["kid"]))
        elif a.cmd == "mint":
            print(mint(a.dir, iss=a.iss, aud=a.aud, sub=a.sub,
                       purpose=a.purpose, ttl=a.ttl))
        elif a.cmd == "verify":
            claims = verify(a.dir, token=a.token, aud=a.aud)
            print(json.dumps(claims, sort_keys=True))
        elif a.cmd == "revoke":
            r = revoke(a.dir, a.jti_or_token, reason=a.reason)
            print("revoked jti %s" % r["jti"])
        elif a.cmd == "rotate-keys":
            r = rotate_keys(a.dir, note=a.note)
            print("new active kid: %s" % r["kid"])
        elif a.cmd == "list-keys":
            print(json.dumps(list_keys(a.dir), indent=2))
        elif a.cmd == "prune-revoked":
            r = prune_revoked(a.dir)
            print("dropped %d, kept %d" % (r["dropped"], r["kept"]))
    except TokenError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
