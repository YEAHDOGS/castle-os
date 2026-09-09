#!/usr/bin/env python3
"""Flamethrower whole-directory burn — Tier 1 crypto-shred for a directory.

FLAMETHROWER.md build-order step 8. This is the only module allowed to
touch paths outside the designated ``<root>/files/`` / ``<root>/filekeys/``
dirs, and it does so under strict interlocks (below).

For every regular file in the target dir it runs the fileburn primitive:
seal the file's bytes under a fresh per-file 256-bit key, then burn the
sealed bundle (key copies destroyed + ciphertext overwritten + unlinked,
one deletion certificate + one tier-1 audit record per file), then
overwrite + unlink the ORIGINAL file. A JSON manifest records
(path, bytes, sha256-before, timestamp) per file — hashes only, never
contents. A verify pass then confirms every listed file is actually gone
and fails LOUDLY with the surviving path if any remain.

Cipher honesty is inherited from fileburn (SHA-256 counter-mode stream
cipher, prototype; production path = AES-256-GCM). The crypto-shred
guarantee — the keys are destroyed — does not depend on the cipher.

Safety (Phoenix-nuke DNA — the most dangerous tool gets the strongest
interlocks):
  - The target must be a REAL directory: not a symlink, not "/", not the
    fileburn root itself, not an ancestor of the fileburn root (a burn can
    never eat its own designated dirs), and not containing the root
    either. Structural refusals, not warnings.
  - Dry-run is the default: ``burn_directory()`` without typed
    confirmation enumerates exactly what would die and changes nothing.
  - The real burn needs typed confirmation — the target's basename.
  - Every enumerated path is resolved through ``os.path.realpath`` and
    must stay under the target's realpath. Any symlink (file, dir, or
    dangling), any hardlinked inode seen twice, any non-regular file, and
    any path that resolves outside the target ABORTS the burn before
    anything dies.
  - No globs, no recursion limits to dodge: explicit target, explicit
    enumeration, explicit typed confirmation.

Stdlib only. No network, no new hosts.

Usage:
    dirburn.py burn TARGET [--yes BASENAME] [--dir PATH]
    dirburn.py verify MANIFEST [--dir PATH]
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
import fileburn  # noqa: E402  (per-file crypto-shred primitive)

DEFAULT_DIR = fileburn.DEFAULT_DIR
MANIFEST_VERSION = 1


# ---------------------------------------------------------------------------
# target validation + enumeration (the dangerous part — contained here)
# ---------------------------------------------------------------------------

def _realpath(p):
    return os.path.realpath(p)


def _validate_target(root, target):
    """Structural refusals for the target dir. Returns its realpath."""
    if os.path.islink(target):
        raise ValueError("refused: target is a symlink: %s" % target)
    if not os.path.isdir(target):
        raise ValueError("refused: not a directory: %s" % target)
    t = _realpath(target)
    r = _realpath(root)
    if t == "/" or t == os.path.expanduser("~"):
        raise ValueError("refused: will not burn %s" % t)
    if t == r:
        raise ValueError("refused: target IS the fileburn root — "
                         "a burn can never eat its own designated dirs")
    if t.startswith(r + os.sep):
        raise ValueError("refused: target is INSIDE the fileburn root — "
                         "a burn can never eat its own designated dirs")
    if r.startswith(t + os.sep):
        raise ValueError("refused: target contains the fileburn root — "
                         "a burn can never eat its own designated dirs")
    return t


def _enumerate(treal):
    """Walk the target, return (files, dirs). Refuses anything shady.

    Symlinks, non-regular files, hardlink duplicates, and paths that
    resolve outside the target all abort the burn BEFORE anything dies.
    """
    files, dirs = [], []
    seen_inodes = set()
    for dirpath, dirnames, filenames in os.walk(treal, followlinks=False):
        # dirnames resolved per-entry; a symlinked dir is a refusal, and a
        # dir whose realpath escapes the target is a refusal
        for d in list(dirnames):
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                raise ValueError(
                    "refused: symlink inside target: %s" % full)
            real = _realpath(full)
            if not (real == treal or real.startswith(treal + os.sep)):
                raise ValueError(
                    "refused: directory resolves outside target: %s" % full)
            dirs.append(real)
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                raise ValueError(
                    "refused: symlink inside target: %s" % full)
            if not os.path.isfile(full):
                raise ValueError(
                    "refused: not a regular file: %s" % full)
            real = _realpath(full)
            if not (real == treal or real.startswith(treal + os.sep)):
                raise ValueError(
                    "refused: file resolves outside target: %s" % full)
            st = os.stat(full)
            if not os.path.isfile(full) or not stat_is_regular(st):
                raise ValueError(
                    "refused: not a regular file: %s" % full)
            key = (st.st_dev, st.st_ino)
            if key in seen_inodes:
                raise ValueError(
                    "refused: hardlinked file seen twice: %s" % full)
            seen_inodes.add(key)
            files.append(real)
    return sorted(files), sorted(dirs)


def stat_is_regular(st):
    import stat as _stat
    return _stat.S_ISREG(st.st_mode)


def _basename(treal):
    return os.path.basename(treal)


def _timestamp():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------------------
# burn
# ---------------------------------------------------------------------------

def burn_directory(root, target, confirm=None):
    """Burn every file under `target` via the fileburn primitive.

    Dry-run unless confirm == target's basename (typed). Real runs seal +
    burn each file, overwrite + unlink the original, write a manifest, and
    run the verify pass (which fails loudly if any file survives).
    """
    fileburn._ensure_dirs(root)
    mdir = os.path.join(root, "manifests")
    os.makedirs(mdir, mode=0o700, exist_ok=True)
    os.chmod(mdir, 0o700)

    treal = _validate_target(root, target)
    files, dirs = _enumerate(treal)
    tbase = _basename(treal)

    if confirm != tbase:
        return {"dry_run": True,
                "target": treal,
                "would_burn_files": files,
                "would_remove_dirs": dirs,
                "hint": "re-run with --yes %s to burn" % tbase}

    burn_id = uuid.uuid4().hex
    entries = []
    for i, path in enumerate(files):
        with open(path, "rb") as f:
            data = f.read()
        name = "dirburn-%s-%04d" % (burn_id[:12], i)
        fileburn.seal(root, name, data)
        r = fileburn.burn(root, name, confirm=name)
        fileburn._overwrite_and_unlink(path)
        entries.append({
            "path": path,
            "bytes": len(data),
            "sha256_before": hashlib.sha256(data).hexdigest(),
            "sealed_name": name,
            "cert_id": r["cert_id"],
            "burned_at": _timestamp(),
            "status": "burned",
        })

    # remove emptied directories bottom-up, deepest first, then the target
    # root itself — the whole tree goes
    removed_dirs = []
    for d in sorted(dirs + [treal], key=len, reverse=True):
        try:
            os.rmdir(d)
            removed_dirs.append(d)
        except OSError:
            pass  # non-empty (refused content) — left standing, honestly

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "burn_id": burn_id,
        "target": treal,
        "burned_at": _timestamp(),
        "files": entries,
        "dirs_removed": removed_dirs,
    }
    mpath = os.path.join(mdir, burn_id + ".json")
    fileburn._atomic_write(mpath, manifest)
    os.chmod(mpath, 0o600)

    survivors = _verify_manifest_entries(treal, entries)
    if survivors:
        raise ValueError(
            "VERIFY FAILED — these files survived the burn: %s"
            % ", ".join(survivors))
    return {"dry_run": False, "burn_id": burn_id, "manifest": mpath,
            "files_burned": len(entries), "dirs_removed": removed_dirs,
            "verified": True}


def _verify_manifest_entries(treal, entries):
    survivors = []
    for e in entries:
        # containment again, belt-and-braces: a manifest path outside the
        # target means something lied during the burn
        p = _realpath(e["path"])
        if not (p == treal or p.startswith(treal + os.sep)):
            raise ValueError(
                "manifest path outside target (tampered?): %s" % e["path"])
        if os.path.lexists(e["path"]):
            survivors.append(e["path"])
    return survivors


def verify_manifest(root, manifest_path):
    """Re-check a burn manifest: fail loudly if any listed file remains."""
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    required = ("manifest_version", "burn_id", "target", "burned_at", "files")
    missing = [k for k in required if k not in manifest]
    if missing:
        return {"valid": False, "missing_fields": missing,
                "burn_id": manifest.get("burn_id")}
    entries = manifest["files"]
    entry_missing = [i for i, e in enumerate(entries)
                     if not all(k in e for k in
                                ("path", "bytes", "sha256_before",
                                 "sealed_name", "cert_id", "burned_at"))]
    treal = _realpath(manifest["target"])
    survivors = _verify_manifest_entries(treal, entries)
    ok = not entry_missing and not survivors
    return {"valid": ok,
            "burn_id": manifest.get("burn_id"),
            "files_listed": len(entries),
            "survivors": survivors,
            "bad_entries": entry_missing,
            "missing_fields": missing}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="Flamethrower whole-directory burn")
    ap.add_argument("--dir", default=DEFAULT_DIR, help="fileburn directory")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("burn")
    p.add_argument("target", help="directory to burn")
    p.add_argument("--yes", default=None,
                   help="typed confirmation (target's basename)")

    p = sub.add_parser("verify")
    p.add_argument("manifest", help="manifest JSON to re-verify")

    a = ap.parse_args(argv)
    try:
        if a.cmd == "burn":
            r = burn_directory(a.dir, a.target, a.yes)
            print(json.dumps(r, indent=2))
            if r.get("dry_run"):
                return 2  # dry-run exits nonzero: nothing burned
        elif a.cmd == "verify":
            v = verify_manifest(a.dir, a.manifest)
            print(json.dumps(v, indent=2))
            if not v["valid"]:
                return 1
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
