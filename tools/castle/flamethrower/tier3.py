#!/usr/bin/env python3
"""Flamethrower Tier 3 — file shredder with honest media labeling.

Implements FLAMETHROWER.md build-order step 5:

  - HDD (spinning rust): single-pass zero overwrite of the file's extents,
    fsync, read-back sample verification, rename to a random name,
    truncate, unlink. Overwrite is a real kill here: the OS writes sector
    100, the head writes sector 100.
  - Flash (SATA SSD / NVMe / USB / SD), virtual, unknown: the same
    sequence runs as a BEST EFFORT — but the tool says so, loudly. The
    plan, the dry-run output, and the deletion certificate all carry the
    honest label ("best effort — use crypto-shred for guarantees") plus a
    pointer at Tier 1 key destruction. On flash an overwrite is a polite
    fiction (wear leveling, over-provisioning, unmapped pages), and this
    module never claims otherwise.

Safety model (same DNA as tier2.py and the Phoenix nuke tool):
  - Dry-run is the default. `shred` with no confirmation prints the plan
    and exits 2; nothing armed.
  - Typed confirmation: the exact BASENAME of every target file, typed on
    a real console — never Y/N, never a pipe.
  - Structural refusals: directories, nonexistent files, dangling
    symlinks, duplicate inodes (two paths, one file), and anything inside
    the keyring root (keyring.py owns those keys).
  - No recursive globs: explicit file paths only.
  - Abort window before the first destructive step (skippable).
  - Every burn emits a deletion certificate: what died, which method,
    media type, verification result. It records THAT something burned,
    never its contents.

Stdlib only. No network, no new hosts. The sysfs root and the st_dev
resolver are injectable so tests fake them — no test touches real
hardware, and no test shreds a real file outside temp dirs.

Usage:
    tier3.py plan secret.txt [more ...] [--sysfs /sys]
    tier3.py shred secret.txt                       # dry-run plan, exit 2
    tier3.py shred secret.txt --execute --confirm secret.txt
    tier3.py shred a.txt b.txt --execute            # interactive typing
"""

import argparse
import json
import os
import secrets
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import media
import audit  # noqa: E402  (cross-burn audit log, build-order step 6)

SYSFS = "/sys"
KEYRING_ROOT = os.path.expanduser("~/.castle-flamethrower")
ABORT_SECONDS = 5
CHUNK = 1024 * 1024            # 1 MiB write chunks
VERIFY_SAMPLES = 16           # read-back samples per file
VERIFY_READ = 4096            # bytes per sample

FLASH_MEDIA = (media.SATA_SSD, media.NVME, media.FLASH_USB, media.VIRTUAL,
               media.UNKNOWN)

TIER1_POINTER = ("for guarantees on this media, crypto-shred instead: keep "
                 "the data in an encrypted Castle vault and destroy the "
                 "vault key (Tier 1: keyring.py destroy-vault <vault> — "
                 "note the whole vault dies with it)")


# ---------------------------------------------------------------------------
# plumbing
# ---------------------------------------------------------------------------

def _stat_dev(path):
    """Default st_dev resolver: (major, minor) of the file's device."""
    st = os.stat(path)
    return os.major(st.st_dev), os.minor(st.st_dev)


def _default_keyring_root():
    return KEYRING_ROOT


# ---------------------------------------------------------------------------
# targets
# ---------------------------------------------------------------------------

class Target:
    """One enumerated file: path, media classification, size."""

    def __init__(self, given, real, size, inode, info):
        self.given = given      # path as typed by the operator
        self.real = real        # symlink-resolved absolute path
        self.size = size
        self.inode = inode      # (st_dev, st_ino) — duplicate detection
        self.info = info        # media.DeviceInfo for the holding disk
        self.flash = info.media in FLASH_MEDIA

    def as_dict(self):
        return {
            "file": self.real,
            "given": self.given,
            "size_bytes": self.size,
            "media": self.info.media,
            "disk": "/dev/" + self.info.name,
            "honest_label": media.honest_label(self.info.media),
            "guarantee": ("overwrite is a real kill on this media"
                          if not self.flash else
                          "BEST EFFORT ONLY — " + TIER1_POINTER),
        }


def resolve_disk_for_path(path, sysfs=SYSFS, stat_dev=None):
    """Map a file path to its whole-disk name via st_dev -> fakeable sysfs.

    Reads /sys/dev/block/<maj>:<min> (a symlink whose target contains
    .../block/<disk>[/<partition>]) and hands the disk to
    media.resolve_disk. Raises media.Refusal when the mapping is absent —
    an unmappable file is treated as unknown media, never assumed HDD.
    """
    if stat_dev is None:
        stat_dev = _stat_dev
    major, minor = stat_dev(path)
    link = os.path.join(sysfs, "dev", "block", "%d:%d" % (major, minor))
    if not os.path.lexists(link):
        raise media.Refusal(
            "cannot map %s to a block device (no /sys/dev/block/%d:%d) — "
            "media unknown, refusing to assume HDD; use Tier 1 "
            "crypto-shredding" % (path, major, minor))
    target = os.path.realpath(link)
    parts = target.split(os.sep)
    disk = None
    if "block" in parts:
        disk = parts[parts.index("block") + 1]
    if not disk:
        raise media.Refusal(
            "cannot map %s to a block device (no /sys/dev/block/%d:%d) — "
            "media unknown, refusing to assume HDD; use Tier 1 "
            "crypto-shredding" % (path, major, minor))
    resolved = media.resolve_disk(disk, sysfs)
    return resolved or disk


def enumerate_targets(paths, sysfs=SYSFS, stat_dev=None,
                      keyring_root=None):
    """Enumerate and classify every target file. Read-only.

    Raises media.Refusal for: empty list, directories, nonexistent files,
    dangling symlinks, non-regular files, duplicate inodes, and anything
    inside the keyring root (keyring.py owns those keys).
    """
    if stat_dev is None:
        stat_dev = _stat_dev
    if keyring_root is None:
        keyring_root = _default_keyring_root()
    if not paths:
        raise media.Refusal("no target files given — nothing to shred")
    kr = os.path.realpath(keyring_root) + os.sep
    seen = set()
    targets = []
    for given in paths:
        if not os.path.lexists(given):
            raise media.Refusal("target does not exist: %s" % given)
        real = os.path.realpath(os.path.abspath(given))
        if real == kr.rstrip(os.sep) or real.startswith(kr):
            raise media.Refusal(
                "refusing to shred %s: inside the keyring root — vault "
                "keys are destroyed with keyring.py destroy-vault, not "
                "with the file shredder" % given)
        if os.path.isdir(real):
            raise media.Refusal(
                "refusing to shred %s: it is a directory — the "
                "flamethrower takes explicit files only, no recursive "
                "globs" % given)
        if not os.path.exists(real):
            raise media.Refusal("dangling symlink, refusing: %s" % given)
        if not os.path.isfile(real):
            raise media.Refusal("not a regular file, refusing: %s" % given)
        st = os.stat(real)
        inode = (st.st_dev, st.st_ino)
        if inode in seen:
            raise media.Refusal(
                "refusing: %s is the same file as another target "
                "(duplicate inode) — list each file once" % given)
        seen.add(inode)
        disk = resolve_disk_for_path(real, sysfs, stat_dev)
        info = media.classify(disk, sysfs)
        targets.append(Target(given, real, st.st_size, inode, info))
    return targets


# ---------------------------------------------------------------------------
# planning: media -> the honest kill
# ---------------------------------------------------------------------------

def plan_shred(targets):
    """Return the ordered step list per target. Read-only, honest labels.

    HDD: overwrite -> verify -> rename -> truncate -> unlink (real kill).
    Flash/virtual/unknown: the same steps, labeled BEST EFFORT, with the
    Tier-1 pointer attached. The module never blesses an overwrite as a
    guarantee on flash — that is the whole point of step 5.
    """
    plans = []
    for t in targets:
        steps = [
            ("overwrite-extents",
             "single-pass zero overwrite of %d bytes, fsync'd" % t.size),
            ("read-back-verify",
             "%d random %d-byte samples must read back zeroed"
             % (VERIFY_SAMPLES, VERIFY_READ)),
            ("rename-random",
             "rename to a random name in the same directory"),
            ("truncate-unlink",
             "truncate to 0, fsync, unlink, fsync the directory"),
        ]
        if t.flash:
            method = ("Tier 3 file shred (BEST EFFORT — %s media): "
                      "overwrite cannot reach unmapped flash pages; "
                      "%s" % (t.info.media, TIER1_POINTER))
        else:
            method = ("Tier 3 file shred (HDD): single-pass zero overwrite "
                      "+ read-back sample verification + rename/truncate/"
                      "unlink — a real kill on spinning rust")
        plans.append({"target": t.as_dict(), "method": method,
                      "steps": [{"name": n, "note": d} for n, d in steps]})
    return plans


# ---------------------------------------------------------------------------
# confirmation
# ---------------------------------------------------------------------------

def _tty_ok(stdin):
    return stdin.isatty()


def confirm_files(targets, provided=None, stdin=None):
    """Typed confirmation: the exact basename of EVERY target, never Y/N.

    `provided` is a comma-separated string (the --confirm flag).
    Interactive: each basename is typed on its own line. Returns True only
    when every basename matches exactly. Raises media.Refusal when stdin is
    not a TTY and no explicit --confirm was given.
    """
    expected = [os.path.basename(t.real) for t in targets]
    if provided is not None:
        got = [p.strip() for p in provided.split(",")]
        return got == expected
    stdin = stdin or sys.stdin
    if not _tty_ok(stdin):
        raise media.Refusal(
            "refusing to arm: confirmation must be typed on a real console "
            "(stdin is not a TTY). `echo ... | tier3.py shred` can never "
            "arm a shred.")
    got = []
    sys.stdout.write("This will DESTROY %d file(s):\n" % len(targets))
    for t in targets:
        sys.stdout.write("  %s  (%d bytes, %s)\n"
                         % (t.real, t.size, t.info.media))
    for name in expected:
        sys.stdout.write("Type the exact filename to arm ('%s'): " % name)
        sys.stdout.flush()
        got.append(stdin.readline().strip())
    return got == expected


# ---------------------------------------------------------------------------
# the burn (HDD kill; flash runs the same sequence as best-effort)
# ---------------------------------------------------------------------------

def _overwrite_file(path, size, log):
    written = 0
    chunk = b"\x00" * CHUNK
    with open(path, "r+b") as f:
        while written < size:
            n = min(CHUNK, size - written)
            f.write(chunk[:n])
            written += n
        f.flush()
        os.fsync(f.fileno())
    log("  overwrite: %d bytes zeroed, fsync'd" % written)
    return written


def _verify_samples(path, size, log, rng=None):
    """Read-back sample verification. Honest: samples, not full re-read."""
    import random
    rng = rng or random.Random()
    if size == 0:
        log("  verify: empty file, nothing to sample")
        return True, 0
    ok = checked = 0
    with open(path, "rb") as f:
        for _ in range(VERIFY_SAMPLES):
            off = rng.randrange(0, max(size - VERIFY_READ, 1))
            f.seek(off)
            data = f.read(min(VERIFY_READ, size - off))
            checked += 1
            if data == b"\x00" * len(data):
                ok += 1
            else:
                log("  verify MISS at offset %d" % off)
    log("  verify: %d/%d samples read back zeroed" % (ok, checked))
    return ok == checked, checked


def _rename_random(path, log):
    new = os.path.join(os.path.dirname(path), secrets.token_hex(16))
    os.rename(path, new)
    log("  renamed to %s" % os.path.basename(new))
    return new


def _truncate_unlink(path, log):
    with open(path, "r+b") as f:
        f.truncate(0)
        f.flush()
        os.fsync(f.fileno())
    os.unlink(path)
    # fsync the directory so the unlink is durable
    dfd = os.open(os.path.dirname(path) or ".", os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    gone = not os.path.lexists(path)
    log("  truncated, unlinked (absent: %s)" % gone)
    return gone


def shred(paths, confirm_arg=None, dry_run=True, sysfs=SYSFS,
          stat_dev=None, stdin=None, keyring_root=None, log_dir=None,
          no_countdown=False, rng=None):
    """Tier-3 file shred with the full safety ceremony.

    Dry-run (default): enumerate targets, classify media, print the plan,
    exit 2. Real burn (--execute): structural refusals, typed basename
    confirmation, abort window, then per file: overwrite -> verify ->
    rename -> truncate -> unlink. Emits one deletion certificate per file.
    Returns (rc, plan-or-certificates).
    """
    if stat_dev is None:
        stat_dev = _stat_dev
    targets = enumerate_targets(paths, sysfs, stat_dev, keyring_root)
    plans = plan_shred(targets)

    if dry_run and confirm_arg is None and stdin is None:
        return 2, {"targets": [t.as_dict() for t in targets],
                   "plans": plans,
                   "note": "dry-run: pass --execute to arm; nothing destroyed"}

    # --- the real burn: confirmation first ---
    if not confirm_files(targets, provided=confirm_arg, stdin=stdin):
        return 2, {"aborted": True,
                   "note": "confirmation did not match every filename; "
                           "nothing was destroyed"}

    if not no_countdown:
        print("Armed. Starting file shred in %d seconds — Ctrl-C aborts."
              % ABORT_SECONDS, flush=True)
        for s in range(ABORT_SECONDS, 0, -1):
            print("%d... " % s, end="", flush=True)
            time.sleep(1)
        print("")

    root = log_dir or os.path.join(_default_keyring_root(), "tier3")
    for sub in ("", "certificates", "logs"):
        d = os.path.join(root, sub) if sub else root
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)
    cert_id = uuid.uuid4().hex
    log_path = os.path.join(root, "logs", "tier3-%s.log" % cert_id)
    log_lines = []

    def log_fn(msg):
        line = "[%s] %s" % (time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                         time.gmtime()), msg)
        print(line, flush=True)
        log_lines.append(line)

    certs = []
    failed = False
    for t, plan in zip(targets, plans):
        log_fn("TIER-3 SHRED ARMED: %s (%d bytes, media=%s)%s"
               % (t.real, t.size, t.info.media,
                  " — BEST EFFORT, flash media" if t.flash else ""))
        if t.flash:
            log_fn("HONEST LABEL: " + media.honest_label(t.info.media))
            log_fn("RECOMMENDATION: " + TIER1_POINTER)
        step_notes = []
        ok = True
        try:
            _overwrite_file(t.real, t.size, log_fn)
            verified, checked = _verify_samples(t.real, t.size, log_fn,
                                                rng=rng)
            step_notes.append("overwrite %d bytes; verify %d/%d samples "
                              "zeroed" % (t.size, checked if verified else 0,
                                          checked))
            if not verified:
                raise IOError("read-back verification failed")
            renamed = _rename_random(t.real, log_fn)
            gone = _truncate_unlink(renamed, log_fn)
            step_notes.append("renamed, truncated, unlinked (absent: %s)"
                              % gone)
            if not gone:
                raise IOError("file still present after unlink")
        except OSError as e:
            ok = False
            failed = True
            step_notes.append("FAILED: %s" % e)
            log_fn("SHRED FAILED for %s: %s — treat as NOT destroyed"
                   % (t.real, e))
            continue

        cert = {
            "certificate": "flamethrower-deletion",
            "cert_id": uuid.uuid4().hex,
            "file": t.real,
            "size_bytes": t.size,
            "disk": "/dev/" + t.info.name,
            "media": t.info.media,
            "method": plan["method"],
            "steps": step_notes,
            "success": ok,
            "verification": (
                "single-pass zero overwrite, fsync'd, with %d read-back "
                "sample verifications; renamed, truncated, unlinked; "
                "absence confirmed" % VERIFY_SAMPLES
                if not t.flash else
                "overwrite pass + %d read-back samples verify the PASS, "
                "not deletion — unmapped flash pages may retain data; "
                "this certificate does NOT claim irrecoverability on "
                "flash" % VERIFY_SAMPLES),
            "media_note": media.honest_label(t.info.media),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                       time.gmtime()),
            # The log records THAT something burned, never its contents.
            "note": "this certificate attests to destruction; it contains "
                    "no file contents",
        }
        if t.flash:
            cert["recommendation"] = TIER1_POINTER
        cert_path = os.path.join(root, "certificates",
                                 cert["cert_id"] + ".json")
        with open(cert_path, "w", encoding="utf-8") as f:
            json.dump(cert, f, indent=2)
        os.chmod(cert_path, 0o600)
        log_fn("certificate: %s" % cert_path)
        try:
            audit.append(root, tier="3", cert_id=cert["cert_id"],
                         fingerprint={"file": t.real, "size_bytes": t.size,
                                      "inode": t.inode},
                         method=cert["method"], media=cert["media"],
                         success=ok, verification=cert["verification"])
        except OSError as e:
            # The burn is real and the certificate exists; the audit log
            # just missed it. Say so loudly — never silently.
            log_fn("WARNING: burn completed but the audit log could not be "
                   "appended: %s" % e)
        certs.append(cert)

    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines) + "\n")
    os.chmod(log_path, 0o600)

    return (0 if not failed else 1), {"certificates": certs,
                                      "log": log_path}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="flamethrower Tier-3 file shredder")
    ap.add_argument("--sysfs", default=SYSFS, help="sysfs root (tests only)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_plan = sub.add_parser("plan", help="read-only shred plan for files")
    p_plan.add_argument("files", nargs="+")

    p_shred = sub.add_parser("shred", help="dry-run plan; --execute to arm")
    p_shred.add_argument("files", nargs="+")
    p_shred.add_argument("--execute", action="store_true",
                         help="actually arm the file shred")
    p_shred.add_argument("--confirm",
                         help="typed confirmation: comma-separated exact "
                              "basenames of every target")
    p_shred.add_argument("--no-countdown", action="store_true",
                         help="skip the final abort window")

    args = ap.parse_args(argv)
    try:
        if args.cmd == "plan":
            targets = enumerate_targets(args.files, args.sysfs)
            print(json.dumps(plan_shred(targets), indent=2))
            return 0
        rc, result = shred(args.files,
                           confirm_arg=args.confirm,
                           dry_run=not args.execute,
                           sysfs=args.sysfs,
                           no_countdown=args.no_countdown)
        if not args.execute:
            print("DRY-RUN (default). This is what WOULD die:")
            for t in result["targets"]:
                print("  file: %s  (%d bytes, media: %s)"
                      % (t["file"], t["size_bytes"], t["media"]))
                print("  honest label: %s" % t["honest_label"])
                print("  guarantee: %s" % t["guarantee"])
            print("Nothing was destroyed. Re-run with --execute to arm "
                  "(requires typing every filename).")
        else:
            print(json.dumps({"certificates": [
                {k: v for k, v in c.items()} for c in
                result["certificates"]]}, indent=2))
        return rc
    except media.Refusal as e:
        print("REFUSED: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
