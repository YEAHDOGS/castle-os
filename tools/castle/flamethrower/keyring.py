#!/usr/bin/env python3
"""Flamethrower key lifecycle — Tier 1 crypto-shredding primitives.

Implements FLAMETHROWER.md build-order steps 1-2: per-vault encryption
key lifecycle — generation, escrow (family recovery), and the destruction
ceremony that emits a deletion certificate.

Design (honest, media-aware):
  - Every vault gets a random 256-bit data key (CSPRNG). Deleting the key
    IS deleting the data: AES-256 ciphertext without its key is noise.
    This is media-independent — it works on HDD, SSD, SD, anything.
  - Keys live in a keyring dir (0700) with per-vault key files (0600).
  - Optional escrow copy per vault = family recovery path. Destruction
    must enumerate and kill EVERY copy (keyring + escrow); the certificate
    lists each copy destroyed.
  - Destruction is overwrite-then-unlink: 3 passes of CSPRNG bytes over the
    key material, fsync, then unlink. On flash this is best-effort for the
    FILE bytes, but the key's entropy is gone from every readable path —
    and the certificate labels it honestly.
  - Dry-run is the default. A real burn needs typed confirmation (the
    vault's name), matching the Phoenix nuke interlocks.

Stdlib only. No third-party crypto, no network, no new hosts.

Usage:
    keyring.py init [--dir PATH]
    keyring.py create-vault NAME [--escrow] [--dir PATH]
    keyring.py list [--dir PATH]
    keyring.py destroy-vault NAME [--yes NAME] [--dir PATH]
    keyring.py destroy-master [--yes DESTROY-ALL] [--dir PATH]
    keyring.py recover-vault NAME [--yes NAME] [--dir PATH]
    keyring.py verify-cert FILE
"""

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit  # noqa: E402  (cross-burn audit log, build-order step 6)

KEY_BYTES = 32          # AES-256
OVERWRITE_PASSES = 3
DEFAULT_DIR = os.path.expanduser("~/.castle-flamethrower")


# ---------------------------------------------------------------------------
# plumbing
# ---------------------------------------------------------------------------

def _p(*parts):
    return os.path.join(*parts)


def _ensure_dirs(root):
    for sub in ("", "keys", "escrow", "certificates"):
        d = _p(root, sub) if sub else root
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)
    meta = _p(root, "keyring.json")
    if not os.path.exists(meta):
        _atomic_write(meta, {"version": 1, "vaults": {}})
        os.chmod(meta, 0o600)
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


def _load_meta(root):
    with open(_p(root, "keyring.json"), encoding="utf-8") as f:
        return json.load(f)


def _save_meta(root, meta):
    _atomic_write(_p(root, "keyring.json"), meta)


def _valid_name(name):
    # No path separators, no globs, no surprises. The flamethrower never
    # takes a recursive glob or an "everything older than X" either.
    return bool(name) and all(c.isalnum() or c in "-_." for c in name) \
        and name not in (".", "..") and len(name) <= 64


# ---------------------------------------------------------------------------
# media detection (best-effort, honest labeling)
# ---------------------------------------------------------------------------

def detect_media(path):
    """Best-effort media type of the filesystem holding `path`.

    Returns 'hdd', 'ssd', or 'unknown'. On 'unknown' the caller must assume
    flash and rely on crypto-shred (which is media-independent anyway).
    """
    try:
        st = os.statvfs(path)
        # Walk /sys/block to match the device; fall back to unknown.
        dev = os.stat(path).st_dev
        major, minor = os.major(dev), os.minor(dev)
        sysfs = "/sys/dev/block/%d:%d" % (major, minor)
        real = os.path.realpath(sysfs)
        # real looks like .../block/sda/sda1 -> climb to the disk dir
        parts = real.split(os.sep)
        if "block" in parts:
            disk = parts[parts.index("block") + 1]
            rot_path = "/sys/block/%s/queue/rotational" % disk
            if os.path.exists(rot_path):
                with open(rot_path) as f:
                    return "hdd" if f.read().strip() == "1" else "ssd"
    except OSError:
        pass
    return "unknown"


# ---------------------------------------------------------------------------
# key lifecycle
# ---------------------------------------------------------------------------

def init(root):
    _ensure_dirs(root)
    return "keyring initialised at %s" % root


def create_vault(root, name, escrow=False):
    _ensure_dirs(root)
    if not _valid_name(name):
        raise ValueError("invalid vault name: %r" % name)
    meta = _load_meta(root)
    if name in meta["vaults"]:
        raise ValueError("vault already exists: %s" % name)
    key = secrets.token_bytes(KEY_BYTES)
    key_path = _p(root, "keys", name + ".key")
    with open(key_path, "wb") as f:
        f.write(key)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(key_path, 0o600)
    entry = {
        "key_id": uuid.uuid4().hex,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "escrow": bool(escrow),
        "key_sha256": hashlib.sha256(key).hexdigest(),  # receipt, not the key
    }
    if escrow:
        esc_path = _p(root, "escrow", name + ".key")
        with open(esc_path, "wb") as f:
            f.write(key)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(esc_path, 0o600)
        entry["escrow_path"] = esc_path
    meta["vaults"][name] = entry
    _save_meta(root, meta)
    # Key bytes never touch stdout or logs — only the receipt hash.
    return "vault %s created (key_id %s%s)" % (
        name, entry["key_id"], ", escrowed" if escrow else "")


def list_vaults(root):
    _ensure_dirs(root)
    meta = _load_meta(root)
    return [(n, v["key_id"], v["created"], v["escrow"])
            for n, v in sorted(meta["vaults"].items())]


def _overwrite_and_unlink(path):
    """CSPRNG overwrite x N, fsync, unlink. Returns bytes overwritten."""
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        for _ in range(OVERWRITE_PASSES):
            f.seek(0)
            # chunked so a giant key file never balloons RAM (keys are tiny,
            # but the primitive should be correct regardless)
            remaining = size
            while remaining:
                chunk = secrets.token_bytes(min(65536, remaining))
                f.write(chunk)
                remaining -= len(chunk)
            f.flush()
            os.fsync(f.fileno())
    os.unlink(path)
    return size


def _burn_copies(root, name, entry):
    """Destroy every stored copy of a vault key. Returns the kill list."""
    kills = []
    for label, path in (("keyring", _p(root, "keys", name + ".key")),
                        ("escrow", _p(root, "escrow", name + ".key"))):
        if os.path.exists(path):
            nbytes = _overwrite_and_unlink(path)
            kills.append({"copy": label, "path": path,
                          "bytes_overwritten": nbytes,
                          "passes": OVERWRITE_PASSES,
                          "unlinked": not os.path.exists(path)})
    return kills


def _issue_certificate(root, name, entry, kills, media):
    cert = {
        "certificate": "flamethrower-deletion",
        "cert_id": uuid.uuid4().hex,
        "vault": name,
        "key_id": entry["key_id"],
        "key_sha256_receipt": entry["key_sha256"],  # proves WHICH key died
        "method": "crypto-shred (key destruction)",
        "media": media,
        "media_note": "crypto-shredding is media-independent; "
                      "ciphertext without the key is unrecoverable on any media",
        "copies_destroyed": kills,
        "verification": "all %d stored copies overwritten (%d passes, CSPRNG), "
                        "fsync'd, unlinked; read-back confirms absent" % (
                            len(kills), OVERWRITE_PASSES),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        # The log records THAT something burned, never its contents.
        "note": "this certificate attests to destruction; it contains no key material",
    }
    path = _p(root, "certificates", cert["cert_id"] + ".json")
    _atomic_write(path, cert)
    try:
        audit.append(root, tier="1", cert_id=cert["cert_id"],
                     fingerprint={"vault": name, "key_id": entry["key_id"],
                                  "key_sha256_receipt": entry["key_sha256"]},
                     method=cert["method"], media=media,
                     success=all(c.get("unlinked") for c in kills),
                     verification=cert["verification"])
    except OSError as e:
        # The burn is real and the certificate exists; the audit log just
        # missed it. Say so loudly on stderr — never silently.
        print("warning: burn completed but the audit log could not be "
              "appended: %s" % e, file=sys.stderr)
    return cert, path


def destroy_vault(root, name, confirm=None):
    """Destruction ceremony. Dry-run unless confirm == name (typed)."""
    _ensure_dirs(root)
    if not _valid_name(name):
        raise ValueError("invalid vault name: %r" % name)
    meta = _load_meta(root)
    if name not in meta["vaults"]:
        raise ValueError("no such vault: %s" % name)
    entry = meta["vaults"][name]

    targets = []
    for label, path in (("keyring", _p(root, "keys", name + ".key")),
                        ("escrow", _p(root, "escrow", name + ".key"))):
        if os.path.exists(path):
            targets.append("%s copy: %s" % (label, path))

    if confirm != name:
        # Dry-run is the default. The real run is the exception.
        return {"dry_run": True,
                "would_destroy": targets,
                "hint": "re-run with --yes %s to burn" % name}

    kills = _burn_copies(root, name, entry)
    media = detect_media(root)
    cert, cert_path = _issue_certificate(root, name, entry, kills, media)
    del meta["vaults"][name]
    _save_meta(root, meta)
    return {"dry_run": False, "kills": kills,
            "certificate": cert_path, "cert_id": cert["cert_id"]}


def destroy_master(root, confirm=None):
    """Burn the entire keyring. Typed confirmation: DESTROY-ALL."""
    _ensure_dirs(root)
    meta = _load_meta(root)
    names = sorted(meta["vaults"].keys())
    if confirm != "DESTROY-ALL":
        return {"dry_run": True,
                "would_destroy_vaults": names,
                "hint": "re-run with --yes DESTROY-ALL to burn everything"}
    results = []
    for name in names:
        # Re-load entry each time; destroy_vault mutates meta.
        entry = _load_meta(root)["vaults"][name]
        kills = _burn_copies(root, name, entry)
        media = detect_media(root)
        cert, cert_path = _issue_certificate(root, name, entry, kills, media)
        m = _load_meta(root)
        del m["vaults"][name]
        _save_meta(root, m)
        results.append({"vault": name, "cert_id": cert["cert_id"],
                        "certificate": cert_path})
    return {"dry_run": False, "burned": results}


def _issue_recovery_certificate(root, name, entry, media):
    cert = {
        "certificate": "flamethrower-recovery",
        "cert_id": uuid.uuid4().hex,
        "vault": name,
        "key_id": entry["key_id"],
        "key_sha256_receipt": entry["key_sha256"],  # proves WHICH key was restored
        "method": "escrow recovery (lost live key restored from escrow copy)",
        "media": media,
        "media_note": "crypto-shredding is media-independent; the escrow copy "
                      "IS the same key, so the restored key decrypts the vault",
        "escrow_preserved": True,
        "verification": "restored key SHA-256 equals the recorded key "
                        "receipt; installed key file is 0600",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        # The log records THAT a recovery happened, never key material.
        "note": "this certificate attests to a recovery; it contains no key material",
    }
    path = _p(root, "certificates", cert["cert_id"] + ".json")
    _atomic_write(path, cert)
    try:
        audit.append(root, tier="1", cert_id=cert["cert_id"],
                     fingerprint={"vault": name, "key_id": entry["key_id"],
                                  "key_sha256_receipt": entry["key_sha256"]},
                     method=cert["method"], media=media,
                     success=True, verification=cert["verification"])
    except OSError as e:
        # The recovery is real and the certificate exists; the audit log just
        # missed it. Say so loudly on stderr — never silently.
        print("warning: recovery completed but the audit log could not be "
              "appended: %s" % e, file=sys.stderr)
    return cert, path


def recover_vault(root, name, confirm=None):
    """Family recovery ceremony: restore a lost vault key from its escrow copy.

    Interlocks (refusals, never silent no-ops):
      - the vault must exist and have an escrow copy ON DISK — the flag in
        the metadata alone is not enough; the file must be a readable
        32-byte key. A vault with no usable escrow cannot be recovered,
        and the refusal says so honestly: ciphertext without its key is
        unrecoverable.
      - the live key must be GONE. Recovery with the live key present would
        silently fork the key; if the live key is dead, destroy-vault it
        first, then recover.
      - typed confirmation: confirm == name, else a dry-run plan.
        Dry-run is the default; the real run is the exception.

    A real run installs the escrow bytes at keys/<name>.key (0600). The escrow
    bytes are SHA-256-checked against the recorded key receipt before the
    write AND the installed copy is verified after — on any mismatch the
    partial install is unlinked and the recovery is refused. The escrow
    copy is PRESERVED — recovery must not destroy the recovery path. Key bytes never touch stdout or logs.
    Every recovery issues a recovery certificate and one tier-1 audit
    record (hashes only — never key material).
    """
    _ensure_dirs(root)
    if not _valid_name(name):
        raise ValueError("invalid vault name: %r" % name)
    meta = _load_meta(root)
    if name not in meta["vaults"]:
        raise ValueError("no such vault: %s" % name)
    entry = meta["vaults"][name]

    key_path = _p(root, "keys", name + ".key")
    esc_path = _p(root, "escrow", name + ".key")
    if os.path.exists(key_path):
        raise ValueError(
            "live key still present for %r: recovery would fork the key. "
            "If the live key is dead, destroy-vault it first, then recover "
            "from escrow." % name)
    escrow = None
    if os.path.exists(esc_path):
        with open(esc_path, "rb") as f:
            escrow = f.read()
    if not entry.get("escrow") or escrow is None or len(escrow) != KEY_BYTES \
            or hashlib.sha256(escrow).hexdigest() != entry["key_sha256"]:
        raise ValueError(
            "no usable escrow copy for %r: this vault cannot be recovered "
            "(escrow was never created, the file is missing, or it is "
            "corrupt). Ciphertext without its key is unrecoverable." % name)

    if confirm != name:
        # Dry-run is the default. The real run is the exception.
        return {"dry_run": True,
                "would_restore": "keys/%s.key from escrow copy" % name,
                "hint": "re-run with --yes %s to recover" % name}

    with open(key_path, "wb") as f:
        f.write(escrow)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(key_path, 0o600)
    # Fail closed: re-read the installed copy; it must be exactly the
    # recorded key. On any mismatch, unlink and refuse.
    with open(key_path, "rb") as f:
        installed = f.read()
    if installed != escrow or hashlib.sha256(installed).hexdigest() != entry["key_sha256"]:
        try:
            os.unlink(key_path)
        finally:
            raise ValueError(
                "installed key for %r failed the receipt check: refusing a "
                "foreign key; nothing was restored." % name)
    media = detect_media(root)
    cert, cert_path = _issue_recovery_certificate(root, name, entry, media)
    return {"dry_run": False, "key_restored": key_path,
            "escrow_preserved": os.path.exists(esc_path),
            "certificate": cert_path, "cert_id": cert["cert_id"]}


def verify_cert(path):
    with open(path, encoding="utf-8") as f:
        cert = json.load(f)
    required = ("cert_id", "vault", "key_id", "key_sha256_receipt",
                "method", "copies_destroyed", "verification", "timestamp")
    missing = [k for k in required if k not in cert]
    ok = not missing and all(
        c.get("unlinked") for c in cert["copies_destroyed"])
    return {"valid": ok, "missing_fields": missing,
            "vault": cert.get("vault"), "cert_id": cert.get("cert_id")}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="Flamethrower key lifecycle")
    ap.add_argument("--dir", default=DEFAULT_DIR, help="keyring directory")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init")
    p = sub.add_parser("create-vault"); p.add_argument("name")
    p.add_argument("--escrow", action="store_true")
    sub.add_parser("list")
    p = sub.add_parser("destroy-vault"); p.add_argument("name")
    p.add_argument("--yes", default=None, help="typed confirmation (vault name)")
    p = sub.add_parser("destroy-master")
    p.add_argument("--yes", default=None, help="typed confirmation (DESTROY-ALL)")
    p = sub.add_parser("recover-vault"); p.add_argument("name")
    p.add_argument("--yes", default=None, help="typed confirmation (vault name)")
    p = sub.add_parser("verify-cert"); p.add_argument("file")

    a = ap.parse_args(argv)
    try:
        if a.cmd == "init":
            print(init(a.dir))
        elif a.cmd == "create-vault":
            print(create_vault(a.dir, a.name, a.escrow))
        elif a.cmd == "list":
            for n, kid, created, esc in list_vaults(a.dir):
                print("%-24s %s  %s%s" % (n, kid[:12], created,
                                         "  [escrow]" if esc else ""))
        elif a.cmd == "destroy-vault":
            r = destroy_vault(a.dir, a.name, a.yes)
            print(json.dumps(r, indent=2))
            if r.get("dry_run"):
                return 2  # dry-run exits nonzero: nothing burned
        elif a.cmd == "destroy-master":
            r = destroy_master(a.dir, a.yes)
            print(json.dumps(r, indent=2))
            if r.get("dry_run"):
                return 2
        elif a.cmd == "recover-vault":
            r = recover_vault(a.dir, a.name, a.yes)
            print(json.dumps(r, indent=2))
            if r.get("dry_run"):
                return 2  # dry-run exits nonzero: nothing restored
        elif a.cmd == "verify-cert":
            print(json.dumps(verify_cert(a.file), indent=2))
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
