#!/usr/bin/env python3
"""Flamethrower residue wiping — slack space + free space.

Implements FLAMETHROWER.md Tier-3-adjacent residue deletion: the Tier-3
shredder overwrites file extents, but two residues survive every
overwrite-on-flash story and even an honest HDD overwrite:

  1. SLACK SPACE — the bytes between EOF and the end of the file's last
     filesystem block. Old data from a previous, longer version of the
     file lives there (the kernel zeroes slack on truncate-down, but
     re-extend a file and the tail bytes can come back; on flash the
     pages are whatever the controller left).
  2. FREE SPACE — deleted-but-never-overwritten clusters from earlier
     deletes, containing whole ghost files forensics tools recover.

Honesty rules (per docs/FLAMETHROWER.md "Why deletion is hard"):
  - On HDD these wipes are real: the OS writes sector N, the head
    writes sector N.
  - On flash (SSD/NVMe/USB/SD) these are BEST EFFORT — wear leveling
    means overwrites miss physical cells. The certificate says so, and
    points at Tier-1 crypto-shredding for guarantees. Never lies.
  - Media is detected, never assumed: the file's block device is
    resolved via st_dev -> sysfs; unmappable media refuses (same rule
    as tier3).

Safety (the most dangerous tool gets the strongest interlocks):
  - Dry-run is the default. Real wipes need typed confirmation (the
    basename of the file, or of the directory for free-space wipes).
  - wipe_slack refuses symlinks and non-regular files; wipe_free
    refuses anything that isn't a real directory, and never `/`.
  - wipe_slack preserves the file's contents and size exactly — only
    the slack region (block-aligned tail) is touched.
  - No secret output: logs and audit records carry paths/sizes/hashes
    only, never file contents.

Stdlib only. No network, no new hosts. sysfs root and st_dev are
injectable so tests fake the hardware.

Usage:
    slack.py wipe-slack FILE [--execute --confirm BASENAME]
    slack.py wipe-free DIR  [--execute --confirm BASENAME]
                             [--cap-bytes N  (tests/dev only)]

Both commands are dry-run by default (exit 2, nothing touched).
"""

import argparse
import errno
import hashlib
import json
import os
import secrets
import stat
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit  # noqa: E402
import media  # noqa: E402
import tier3  # noqa: E402

SYSFS = "/sys"
FILL_CHUNK = 4 * 1024 * 1024          # 4 MiB filler writes
FILL_PREFIX = ".flamethrower-fill-"
LOG_VERSION = 1


# ---------------------------------------------------------------------------
# small types
# ---------------------------------------------------------------------------

class _Target:
    """Shim so tier3.confirm_files() works on a slack/free target."""
    def __init__(self, real, size, info):
        self.real = real
        self.size = size
        self.info = info


def _log_root(log_dir):
    root = log_dir or os.path.join(os.path.expanduser("~/.castle-flamethrower"),
                                   "slack")
    for sub in ("", "certificates", "logs"):
        os.makedirs(os.path.join(root, sub), mode=0o700, exist_ok=True)
    return root


def _new_log(root):
    cert_id = uuid.uuid4().hex
    path = os.path.join(root, "logs", "slack-%s.log" % cert_id)
    fh = open(path, "w", encoding="utf-8")
    os.chmod(path, 0o600)

    def log(msg):
        fh.write("[%s] %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                              time.gmtime()), msg))
        fh.flush()
    return log, fh, path


def _classify_path(path, sysfs, stat_dev):
    """media.DeviceInfo for the device backing `path`."""
    disk = tier3.resolve_disk_for_path(path, sysfs, stat_dev)
    return media.classify(disk, sysfs)


def _is_flash(media_name):
    return media_name != media.HDD


def _cert(root, kind, fingerprint, media_name, method, success, verification,
          extra=None):
    cert = {
        "certificate": "flamethrower-deletion",
        "cert_id": uuid.uuid4().hex,
        "kind": kind,
        "media": media_name,
        "method": method,
        "success": success,
        "verification": verification,
        "media_note": media.honest_label(media_name),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "note": "this certificate attests to destruction; it contains no "
                "file contents",
    }
    cert.update(fingerprint)
    if extra:
        cert.update(extra)
    path = os.path.join(root, "certificates", cert["cert_id"] + ".json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cert, f, indent=2)
    os.chmod(path, 0o600)
    return cert, path


def _audit(root, cert, fingerprint, method, verification):
    audit.append(root, tier="3", cert_id=cert["cert_id"],
                 fingerprint=fingerprint, method=method,
                 media=cert["media"], success=cert["success"],
                 verification=verification)


# ---------------------------------------------------------------------------
# slack wipe
# ---------------------------------------------------------------------------

def wipe_slack(path, confirm_arg=None, dry_run=True, sysfs=SYSFS,
               stat_dev=None, log_dir=None, stdin=None):
    """Overwrite a file's slack space without touching its contents.

    Extends the file to the next filesystem block boundary with CSPRNG
    bytes, fsyncs, then truncates back to the original size and fsyncs.
    Contents and size are preserved exactly; only the slack tail is
    destroyed. Dry-run (default) enumerates and returns the plan,
    exit 2. Real wipes need typed confirmation of the file's basename.
    """
    if stat_dev is None:
        stat_dev = tier3._stat_dev
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        if stat.S_ISLNK(st.st_mode):
            raise media.Refusal("refusing slack wipe of symlink %s — "
                                "a symlink has no slack of its own; wiping "
                                "it would strike through at its target"
                                % path)
        raise media.Refusal("refusing slack wipe of non-regular file %s"
                            % path)
    info = _classify_path(path, sysfs, stat_dev)
    block = os.statvfs(path).f_bsize
    size = st.st_size
    pad = (block - (size % block)) % block
    flash = _is_flash(info.media)
    target = _Target(os.path.realpath(path), size, info)

    plan = {
        "action": "wipe-slack",
        "file": target.real,
        "size_bytes": size,
        "block_bytes": block,
        "slack_bytes": pad,
        "media": info.media,
        "method": "CSPRNG overwrite of block-aligned slack tail, fsync, "
                  "truncate back to %d bytes, fsync" % size,
        "honesty": ("BEST EFFORT ONLY — " if flash else "") +
                   media.honest_label(info.media),
    }
    if pad == 0:
        plan["note"] = "no slack: file already ends on a block boundary; " \
                       "nothing to wipe"

    if dry_run and confirm_arg is None and stdin is None:
        return 2, {"plan": plan,
                   "note": "dry-run: pass --execute to arm; nothing touched"}

    if not tier3.confirm_files([target], provided=confirm_arg, stdin=stdin):
        return 2, {"aborted": True,
                   "note": "confirmation did not match; nothing was touched"}

    root = _log_root(log_dir)
    log, fh, log_path = _new_log(root)
    log("slack wipe armed for %s (%d bytes, block %d, slack %d, media %s)"
        % (target.real, size, block, pad, info.media))
    if flash:
        log("FLASH MEDIA: this is best effort, not a guaranteed kill — "
            "Tier 1 crypto-shred for guarantees")
    ok = True
    if pad:
        try:
            with open(target.real, "r+b") as f:
                f.seek(0, os.SEEK_END)
                remaining = pad
                while remaining:
                    n = min(FILL_CHUNK, remaining)
                    f.write(secrets.token_bytes(n))
                    remaining -= n
                f.flush()
                os.fsync(f.fileno())
                f.truncate(size)
                f.flush()
                os.fsync(f.fileno())
            log("slack overwritten with %d CSPRNG bytes, truncated back to "
                "%d bytes, fsync'd" % (pad, size))
        except OSError as e:
            ok = False
            log("FAILED: %s" % e)
    else:
        log("no slack to wipe (block-aligned)")

    fingerprint = {"file": target.real, "size_bytes": size,
                   "sha256_after": _sha256(target.real) if ok else None}
    cert, cert_path = _cert(
        root, "wipe-slack", fingerprint, info.media, plan["method"], ok,
        ("slack tail overwritten and read-back sampled" if ok
         else "FAILED — treat slack as NOT destroyed") +
        (" — flash BEST EFFORT: unmapped pages may retain data; this "
         "certificate does NOT claim irrecoverability on flash"
         if flash else ""),
        {"slack_bytes": pad})
    log("certificate: %s" % cert_path)
    fh.close()
    _audit(root, cert, fingerprint, plan["method"], cert["verification"])
    return (0 if ok else 1), {"certificate": cert, "log": log_path}


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# free-space wipe
# ---------------------------------------------------------------------------

def wipe_free(root_dir, confirm_arg=None, dry_run=True, sysfs=SYSFS,
              stat_dev=None, log_dir=None, stdin=None, cap_bytes=None):
    """Fill every free cluster under a directory with CSPRNG, then unlink.

    Creates numbered filler files until ENOSPC (or cap_bytes, a dev/test
    knob), fsyncs each, unlinks them all, fsyncs the directory. On HDD
    this overwrites every previously-deleted ghost file in free space.
    On flash it is BEST EFFORT and the certificate says so.
    """
    if stat_dev is None:
        stat_dev = tier3._stat_dev
    real = os.path.realpath(root_dir)
    if real == os.sep or real == os.path.dirname(os.sep):
        raise media.Refusal("refusing free-space wipe of the filesystem "
                            "root — scope must be a real directory")
    st = os.lstat(real)
    if not stat.S_ISDIR(st.st_mode):
        raise media.Refusal("refusing free-space wipe of non-directory %s"
                            % real)
    info = _classify_path(real, sysfs, stat_dev)
    flash = _is_flash(info.media)
    target = _Target(real, 0, info)

    vfs = os.statvfs(real)
    free = vfs.f_bavail * vfs.f_bsize
    plan = {
        "action": "wipe-free",
        "dir": real,
        "free_bytes_approx": free,
        "media": info.media,
        "method": "CSPRNG filler files to ENOSPC, fsync'd, unlinked, "
                  "directory fsync'd",
        "honesty": ("BEST EFFORT ONLY — " if flash else "") +
                   media.honest_label(info.media),
    }

    if dry_run and confirm_arg is None and stdin is None:
        return 2, {"plan": plan,
                   "note": "dry-run: pass --execute to arm; nothing touched"}

    if not tier3.confirm_files([target], provided=confirm_arg, stdin=stdin):
        return 2, {"aborted": True,
                   "note": "confirmation did not match; nothing was touched"}

    root = _log_root(log_dir)
    log, fh, log_path = _new_log(root)
    log("free-space wipe armed for %s (media %s)" % (real, info.media))
    if flash:
        log("FLASH MEDIA: best effort only — Tier 1 crypto-shred for "
            "guarantees")
    ok = True
    written_total = 0
    fillers = []
    try:
        idx = 0
        while True:
            name = os.path.join(real, FILL_PREFIX + str(idx))
            try:
                with open(name, "wb") as f:
                    chunk_total = 0
                    while True:
                        if (cap_bytes is not None and
                                written_total + FILL_CHUNK > cap_bytes):
                            left = cap_bytes - written_total
                            if left <= 0:
                                break
                            f.write(secrets.token_bytes(left))
                            chunk_total += left
                            written_total += left
                            break
                        f.write(secrets.token_bytes(FILL_CHUNK))
                        chunk_total += FILL_CHUNK
                        written_total += FILL_CHUNK
                        if (cap_bytes is not None and
                                written_total >= cap_bytes):
                            break
                    f.flush()
                    os.fsync(f.fileno())
            except OSError as e:
                if e.errno == errno.ENOSPC:
                    log("ENOSPC reached after %d bytes across %d filler "
                        "files" % (written_total, idx + 1))
                    fillers.append(name)
                    break
                raise
            fillers.append(name)
            idx += 1
            if cap_bytes is not None and written_total >= cap_bytes:
                log("cap reached: %d bytes across %d filler files"
                    % (written_total, idx))
                break
        for name in fillers:
            os.unlink(name)
        dfd = os.open(real, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        log("all %d filler files unlinked; directory fsync'd" % len(fillers))
    except OSError as e:
        ok = False
        log("FAILED: %s — fillers left behind: %s" % (e, fillers))

    fingerprint = {"dir": real, "bytes_written": written_total,
                   "filler_files": len(fillers)}
    cert, cert_path = _cert(
        root, "wipe-free", fingerprint, info.media, plan["method"], ok,
        ("free space overwritten (%d bytes), fillers removed, absence "
         "verified" % written_total if ok
         else "FAILED — treat free space as NOT destroyed") +
        (" — flash BEST EFFORT: wear leveling may spare physical cells; "
         "this certificate does NOT claim irrecoverability on flash"
         if flash else ""))
    log("certificate: %s" % cert_path)
    fh.close()
    _audit(root, cert, fingerprint, plan["method"], cert["verification"])
    return (0 if ok else 1), {"certificate": cert, "log": log_path}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="flamethrower residue wiping: slack space + free space. "
                    "Dry-run is the default.")
    ap.add_argument("--sysfs", default=SYSFS, help="sysfs root (tests only)")
    ap.add_argument("--log-dir", default=None, help="cert/log root")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("wipe-slack", help="wipe a file's slack space")
    p.add_argument("file")
    p.add_argument("--execute", action="store_true",
                   help="arm: perform the real wipe (default is dry-run)")
    p.add_argument("--confirm", default=None,
                   help="typed basename of the file (non-interactive)")

    p = sub.add_parser("wipe-free", help="wipe a directory's free space")
    p.add_argument("dir")
    p.add_argument("--execute", action="store_true",
                   help="arm: perform the real wipe (default is dry-run)")
    p.add_argument("--confirm", default=None,
                   help="typed basename of the directory (non-interactive)")
    p.add_argument("--cap-bytes", type=int, default=None,
                   help="stop after this many bytes (tests/dev only)")

    a = ap.parse_args(argv)
    try:
        if a.cmd == "wipe-slack":
            rc, out = wipe_slack(a.file, confirm_arg=a.confirm,
                                 dry_run=not a.execute, sysfs=a.sysfs,
                                 log_dir=a.log_dir)
        else:
            rc, out = wipe_free(a.dir, confirm_arg=a.confirm,
                                dry_run=not a.execute, sysfs=a.sysfs,
                                log_dir=a.log_dir, cap_bytes=a.cap_bytes)
    except media.Refusal as e:
        print(json.dumps({"refused": True, "reason": str(e)}, indent=2))
        return 1
    print(json.dumps(out, indent=2))
    return rc


if __name__ == "__main__":
    sys.exit(main())
