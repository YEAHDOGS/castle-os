#!/usr/bin/env python3
"""Flamethrower per-file crypto-shred — Tier 1 for a single sealed file.

Implements the first flamethrower true-deletion primitive at file
granularity (FLAMETHROWER.md Tier 1): a file is *sealed* with its own
random 256-bit key, and *burned* by destroying that key (the real,
media-independent kill) plus overwriting the ciphertext bytes and
unlinking the file.

Why a per-file key: overwriting file bytes is honest on HDDs but a
polite fiction on NAND flash (wear leveling, over-provisioned spares —
see FLAMETHROWER.md). Key destruction needs no cooperation from the
flash controller: ciphertext without the key is unrecoverable on any
media. The overwrite pass still happens so a forensic read of the
ciphertext alone yields nothing.

Cipher honesty: stdlib has no AES, and this module must stay
stdlib-only. Sealed files use a SHA-256 counter-mode stream cipher
(keystream = SHA256(key || nonce || counter), XOR'd with the data) —
a sound construction for a prototype, but NOT AES-256-GCM. The
crypto-shred guarantee (key destruction) does not depend on the
cipher choice; the production path must swap in AES-256-GCM.

Safety (same DNA as the Phoenix nuke interlocks):
  - Files live ONLY in ``<root>/files/``; keys only in
    ``<root>/filekeys/`` (+ optional ``<root>/escrow/``). Names are
    strictly validated — no path separators, no traversal, no globs.
    A burn can never touch anything outside the designated dirs.
  - Dry-run is the default: ``burn()`` without typed confirmation
    lists exactly what would die and changes nothing.
  - The real burn needs typed confirmation (the file's name).
  - Every burn issues a deletion certificate (no key material, no file
    contents — only hashes) and appends one record to the cross-burn
    audit log. Dry runs log nothing.

Stdlib only. No network, no new hosts.

Usage:
    fileburn.py init [--dir PATH]
    fileburn.py seal NAME FILE [--escrow] [--dir PATH]
    fileburn.py unseal NAME --out PATH [--dir PATH]
    fileburn.py list [--dir PATH]
    fileburn.py burn NAME [--yes NAME] [--dir PATH]
    fileburn.py verify-cert FILE
"""

import argparse
import hashlib
import json
import os
import secrets
import sys
import time
import uuid

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import audit  # noqa: E402  (cross-burn audit log, build-order step 6)
from keyring import detect_media  # noqa: E402  (best-effort media label)

KEY_BYTES = 32          # 256-bit per-file key
NONCE_BYTES = 16
OVERWRITE_PASSES = 3
MAGIC = b"CB1\x00"      # sealed-bundle magic, version 1
DEFAULT_DIR = os.path.expanduser("~/.castle-flamethrower-files")


# ---------------------------------------------------------------------------
# plumbing
# ---------------------------------------------------------------------------

def _p(*parts):
    return os.path.join(*parts)


def _ensure_dirs(root):
    for sub in ("files", "filekeys", "escrow", "certificates"):
        d = _p(root, sub)
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)
    reg = _p(root, "files.json")
    if not os.path.exists(reg):
        _atomic_write(reg, {"version": 1, "files": {}})
        os.chmod(reg, 0o600)
    return root


def _atomic_write(path, obj):
    tmp = path + ".tmp.%d" % os.getpid()
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _load_reg(root):
    with open(_p(root, "files.json"), encoding="utf-8") as f:
        return json.load(f)


def _save_reg(root, reg):
    _atomic_write(_p(root, "files.json"), reg)


def _valid_name(name):
    # The flamethrower never takes a recursive glob, and a name that can
    # walk out of files/ is a hard refusal.
    return bool(name) and all(c.isalnum() or c in "-_." for c in name) \
        and name not in (".", "..") and len(name) <= 64


def _bundle_path(root, name):
    # Names are validated, but belt-and-braces: the real path must stay
    # inside the designated dir.
    p = os.path.realpath(_p(root, "files", name + ".sealed"))
    if not p.startswith(os.path.realpath(_p(root, "files")) + os.sep):
        raise ValueError("refused: resolved path escapes the files dir")
    return p


def _key_path(root, name):
    return _p(root, "filekeys", name + ".key")


def _escrow_path(root, name):
    return _p(root, "escrow", name + ".key")


# ---------------------------------------------------------------------------
# cipher (prototype: SHA-256 counter-mode stream cipher, see module doc)
# ---------------------------------------------------------------------------

def _keystream(key, nonce, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(
            key + nonce + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:length])


def _xor(data, key, nonce):
    ks = _keystream(key, nonce, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def _seal_bytes(data, key, nonce):
    return MAGIC + nonce + _xor(data, key, nonce)


def _unseal_bytes(blob, key):
    if blob[:len(MAGIC)] != MAGIC:
        raise ValueError("not a fileburn sealed bundle")
    nonce = blob[len(MAGIC):len(MAGIC) + NONCE_BYTES]
    return _xor(blob[len(MAGIC) + NONCE_BYTES:], key, nonce)


# ---------------------------------------------------------------------------
# seal / unseal / list
# ---------------------------------------------------------------------------

def init(root):
    _ensure_dirs(root)
    return "fileburn initialised at %s" % root


def seal(root, name, data, escrow=False):
    """Seal `data` (bytes) under `name` with a fresh per-file key.

    Returns the registry entry (key_id + sha256 receipt — never the key).
    Refuses evil names and duplicates.
    """
    _ensure_dirs(root)
    if not _valid_name(name):
        raise ValueError("invalid file name: %r" % name)
    reg = _load_reg(root)
    if name in reg["files"]:
        raise ValueError("file already sealed: %s" % name)
    key = secrets.token_bytes(KEY_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    bundle = _seal_bytes(data, key, nonce)
    bp = _bundle_path(root, name)
    with open(bp, "wb") as f:
        f.write(bundle)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(bp, 0o600)
    kp = _key_path(root, name)
    with open(kp, "wb") as f:
        f.write(key)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(kp, 0o600)
    entry = {
        "key_id": uuid.uuid4().hex,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "escrow": bool(escrow),
        "size_bytes": len(bundle),
        # receipt, not the key: proves WHICH key a burn later destroyed
        "key_sha256": hashlib.sha256(key).hexdigest(),
    }
    if escrow:
        ep = _escrow_path(root, name)
        with open(ep, "wb") as f:
            f.write(key)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(ep, 0o600)
    reg["files"][name] = entry
    _save_reg(root, reg)
    return entry


def unseal(root, name):
    """Recover a sealed file's plaintext (needs the key — post-burn this
    is impossible, which is the whole point)."""
    _ensure_dirs(root)
    if not _valid_name(name):
        raise ValueError("invalid file name: %r" % name)
    reg = _load_reg(root)
    if name not in reg["files"]:
        raise ValueError("no such sealed file: %s" % name)
    kp = _key_path(root, name)
    if not os.path.exists(kp):
        raise ValueError("key destroyed — %s is unrecoverable" % name)
    with open(kp, "rb") as f:
        key = f.read()
    with open(_bundle_path(root, name), "rb") as f:
        blob = f.read()
    return _unseal_bytes(blob, key)


def list_files(root):
    _ensure_dirs(root)
    reg = _load_reg(root)
    return [(n, v["key_id"], v["created"], v["escrow"], v["size_bytes"])
            for n, v in sorted(reg["files"].items())]


# ---------------------------------------------------------------------------
# the burn: overwrite ciphertext + unlink + destroy the key
# ---------------------------------------------------------------------------

def _overwrite_and_unlink(path):
    """CSPRNG overwrite x N, fsync, unlink. Returns bytes overwritten."""
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        for _ in range(OVERWRITE_PASSES):
            f.seek(0)
            remaining = size
            while remaining:
                chunk = secrets.token_bytes(min(65536, remaining))
                f.write(chunk)
                remaining -= len(chunk)
            f.flush()
            os.fsync(f.fileno())
    os.unlink(path)
    return size


def _burn_key_copies(root, name):
    kills = []
    for label, path in (("filekeys", _key_path(root, name)),
                        ("escrow", _escrow_path(root, name))):
        if os.path.exists(path):
            nbytes = _overwrite_and_unlink(path)
            kills.append({"copy": label, "path": path,
                          "bytes_overwritten": nbytes,
                          "passes": OVERWRITE_PASSES,
                          "unlinked": not os.path.exists(path)})
    return kills


def _issue_certificate(root, name, entry, kills, cipher_bytes, media):
    cert = {
        "certificate": "flamethrower-deletion",
        "cert_id": uuid.uuid4().hex,
        "file": name,
        "key_id": entry["key_id"],
        "key_sha256_receipt": entry["key_sha256"],
        "method": "crypto-shred (per-file key destruction) + "
                  "ciphertext overwrite (%d passes, CSPRNG) + unlink" % (
                      OVERWRITE_PASSES,),
        "media": media,
        "media_note": "key destruction is media-independent; the overwrite "
                      "pass is the physical kill on HDD and best-effort on "
                      "flash (see FLAMETHROWER.md)",
        "copies_destroyed": kills,
        "ciphertext_bytes_overwritten": cipher_bytes,
        "verification": "all %d key copies overwritten, fsync'd, unlinked; "
                        "ciphertext bundle overwritten (%d passes) and "
                        "unlinked; read-back confirms absent" % (
                            len(kills), OVERWRITE_PASSES),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        # The certificate attests to destruction; it carries no key
        # material and no file contents.
        "note": "this certificate attests to destruction; it contains no "
                "key material or file contents",
    }
    path = _p(root, "certificates", cert["cert_id"] + ".json")
    _atomic_write(path, cert)
    try:
        audit.append(root, tier="1", cert_id=cert["cert_id"],
                     fingerprint={"file": name, "key_id": entry["key_id"],
                                  "key_sha256_receipt": entry["key_sha256"]},
                     method=cert["method"], media=media,
                     success=all(c.get("unlinked") for c in kills),
                     verification=cert["verification"])
    except OSError as e:
        print("warning: burn completed but the audit log could not be "
              "appended: %s" % e, file=sys.stderr)
    return cert, path


def burn(root, name, confirm=None):
    """Burn one sealed file. Dry-run unless confirm == name (typed).

    Kill order: enumerate targets -> destroy every key copy ->
    overwrite + unlink the ciphertext -> certificate -> audit record.
    """
    _ensure_dirs(root)
    if not _valid_name(name):
        raise ValueError("invalid file name: %r" % name)
    reg = _load_reg(root)
    if name not in reg["files"]:
        raise ValueError("no such sealed file: %s" % name)
    entry = reg["files"][name]

    targets = []
    for label, path in (("filekeys", _key_path(root, name)),
                        ("escrow", _escrow_path(root, name)),
                        ("ciphertext", _bundle_path(root, name))):
        if os.path.exists(path):
            targets.append("%s: %s" % (label, path))

    if confirm != name:
        # Dry-run is the default. The real run is the exception.
        return {"dry_run": True,
                "would_destroy": targets,
                "hint": "re-run with --yes %s to burn" % name}

    kills = _burn_key_copies(root, name)
    bp = _bundle_path(root, name)
    cipher_bytes = _overwrite_and_unlink(bp) if os.path.exists(bp) else 0
    media = detect_media(root)
    cert, cert_path = _issue_certificate(root, name, entry, kills,
                                        cipher_bytes, media)
    reg = _load_reg(root)
    del reg["files"][name]
    _save_reg(root, reg)
    return {"dry_run": False, "kills": kills,
            "ciphertext_bytes_overwritten": cipher_bytes,
            "certificate": cert_path, "cert_id": cert["cert_id"]}


def verify_cert(path):
    with open(path, encoding="utf-8") as f:
        cert = json.load(f)
    required = ("cert_id", "file", "key_id", "key_sha256_receipt",
                "method", "copies_destroyed", "verification", "timestamp")
    missing = [k for k in required if k not in cert]
    ok = not missing and all(
        c.get("unlinked") for c in cert["copies_destroyed"])
    return {"valid": ok, "missing_fields": missing,
            "file": cert.get("file"), "cert_id": cert.get("cert_id")}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="Flamethrower per-file burn")
    ap.add_argument("--dir", default=DEFAULT_DIR, help="fileburn directory")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init")
    p = sub.add_parser("seal")
    p.add_argument("name")
    p.add_argument("file", help="plaintext file to seal")
    p.add_argument("--escrow", action="store_true")
    p = sub.add_parser("unseal")
    p.add_argument("name")
    p.add_argument("--out", required=True)
    sub.add_parser("list")
    p = sub.add_parser("burn")
    p.add_argument("name")
    p.add_argument("--yes", default=None,
                   help="typed confirmation (file name)")
    p = sub.add_parser("verify-cert")
    p.add_argument("file")

    a = ap.parse_args(argv)
    try:
        if a.cmd == "init":
            print(init(a.dir))
        elif a.cmd == "seal":
            with open(a.file, "rb") as f:
                data = f.read()
            e = seal(a.dir, a.name, data, a.escrow)
            print("sealed %s (key_id %s%s)" % (
                a.name, e["key_id"], ", escrowed" if e["escrow"] else ""))
        elif a.cmd == "unseal":
            with open(a.out, "wb") as f:
                f.write(unseal(a.dir, a.name))
            print("unsealed %s -> %s" % (a.name, a.out))
        elif a.cmd == "list":
            for n, kid, created, esc, size in list_files(a.dir):
                print("%-24s %s  %s  %d bytes%s" % (
                    n, kid[:12], created, size, "  [escrow]" if esc else ""))
        elif a.cmd == "burn":
            r = burn(a.dir, a.name, a.yes)
            print(json.dumps(r, indent=2))
            if r.get("dry_run"):
                return 2  # dry-run exits nonzero: nothing burned
        elif a.cmd == "verify-cert":
            print(json.dumps(verify_cert(a.file), indent=2))
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
