#!/usr/bin/env python3
"""Flamethrower Tier 2 — firmware-erase routines (FLAMETHROWER.md step 4).

Shared logic with the Phoenix Invoke-Nuke.sh tooling: NVMe Format with
Secure Erase (crypto erase), NVMe Sanitize, and ATA Secure Erase — the
firmware-level kills that are the ONLY real erases on flash media, plus
the nwipe-style single-pass overwrite kill for spinning rust.

The central honesty rule (step 3's refusal, extended): this module will
NEVER plan or execute a software overwrite as a "kill" on flash media.
If the firmware offers no erase path, it REFUSES and points at Tier 1
crypto-shredding instead. An overwrite on flash is a polite fiction;
the certificate says exactly what really happened.

Safety model (same DNA as keyring.py and the Phoenix nuke tool):
  - Dry-run is the default. `erase` with no confirmation prints the plan
    and exits 2; nothing armed.
  - Typed confirmation: the disk's SERIAL (or "ERASE <serial>"), never Y/N.
  - Structural refusals: mounted partitions / the device holding the root
    filesystem cannot be erased; an empty/unknown serial cannot satisfy
    typed confirmation and is refused.
  - Last-second re-verification: the serial is re-read from sysfs after
    confirmation; if it changed mid-run, abort.
  - 5-second abort window before the first destructive step (skippable).
  - Every burn emits a deletion certificate: what died, which method,
    media type, firmware/overwrite verification result. It records THAT
    something burned, never its contents.

Stdlib only. No network, no new hosts. Probes, the runner, stdin, the
sysfs root, and the mounts table are all injectable so tests fake them
and no test touches real hardware.

Usage:
    tier2.py plan /dev/sda [--sysfs /sys]            # read-only kill plan
    tier2.py erase /dev/sda                          # dry-run plan, exit 2
    tier2.py erase /dev/sda --execute --serial XYZ   # the real burn
    tier2.py erase /dev/sda --execute                # interactive prompt
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import media
import audit  # noqa: E402  (cross-burn audit log, build-order step 6)

SYSFS = "/sys"
MOUNTS = "/proc/mounts"
KEYRING_ROOT = os.path.expanduser("~/.castle-flamethrower")

ERASE_PASSWD = "flamethrower"  # ATA security password; never logged to stdout
ABORT_SECONDS = 5
VERIFY_SAMPLES = 64            # read-back samples for HDD overwrite verify
CHUNK = 1024 * 1024            # 1 MiB write chunks for the HDD overwrite


# ---------------------------------------------------------------------------
# steps & results
# ---------------------------------------------------------------------------

class Step:
    """One planned action: human-readable name, argv, and an honest note."""

    def __init__(self, name, argv, note=""):
        self.name = name
        self.argv = argv
        self.note = note

    def as_dict(self):
        return {"name": self.name, "argv": self.argv, "note": self.note}


def _run(argv):
    """Default command runner: subprocess with captured output."""
    return subprocess.run(argv, capture_output=True, text=True, timeout=600)


# ---------------------------------------------------------------------------
# capability probes (read-only)
# ---------------------------------------------------------------------------

def probe_nvme(dev, runner=None):
    if runner is None:
        runner = _run
    """Probe an NVMe controller's firmware-erase capabilities.

    Returns (crypto_erase_ok, sanitize_ok, detail). `dev` is the namespace
    (e.g. /dev/nvme0n1); the controller is derived (/dev/nvme0).
    """
    ctrl = re.sub(r"n\d+$", "", dev) or dev
    try:
        r = runner(["nvme", "id-ctrl", "-H", ctrl])
    except (OSError, FileNotFoundError, subprocess.TimeoutExpired):
        return False, False, "nvme-cli not available"
    out = (r.stdout or "") + (r.stderr or "")
    crypto_ok = bool(re.search(r"crypto erase.*support", out, re.I))
    sanitize_ok = bool(re.search(r"sanitize.*support|block erase.*support",
                                out, re.I))
    if r.returncode != 0 and not out.strip():
        return False, False, "nvme id-ctrl failed (rc=%d)" % r.returncode
    return crypto_ok, sanitize_ok, out[:400]


def probe_ata(dev, runner=None):
    if runner is None:
        runner = _run
    """Probe an ATA device's Secure Erase capability via hdparm -I.

    Returns one of: "enhanced", "normal", "frozen", "unsupported",
    "unavailable" (hdparm missing / command failed).
    """
    try:
        r = runner(["hdparm", "-I", dev])
    except (OSError, FileNotFoundError, subprocess.TimeoutExpired):
        return "unavailable"
    out = r.stdout or ""
    sec = "\n".join(
        line for line in out.splitlines()
        if re.match(r"^\s*(Security:|not\s+supported|supported|frozen|"
                    r"not\s+enabled|enabled|not\s+locked|locked|"
                    r"enhanced|\d+\s*min\s+for)", line, re.I))
    if r.returncode != 0 and not sec.strip():
        return "unavailable"
    if re.search(r"not\s+supported", sec, re.I):
        return "unsupported"
    if re.search(r"^\s*frozen\s*$", sec, re.M | re.I):
        return "frozen"
    if re.search(r"enhanced", sec, re.I):
        return "enhanced"
    if re.search(r"supported", sec, re.I):
        return "normal"
    return "unavailable"


# ---------------------------------------------------------------------------
# planning: media -> the real kill, or a hard refusal
# ---------------------------------------------------------------------------

def plan_erase(info, runner=None):
    if runner is None:
        runner = _run
    """Return the ordered kill plan for a classified device.

    Raises media.Refusal instead of blessing a fiction:
      - flash/USB/SD with no firmware erase -> refuse (crypto-shred only)
      - virtual / unknown -> refuse
      - frozen ATA security -> refuse (with the suspend/resume remedy)
      - unsupported ATA security -> refuse (overwrite can't reach
        unmapped pages, so it is not offered)
    """
    dev = "/dev/" + info.name

    if info.media == media.NVME:
        crypto_ok, sanitize_ok, detail = probe_nvme(dev, runner)
        if crypto_ok:
            return [Step(
                "nvme-format-crypto-erase",
                ["nvme", "format", dev, "--ses=2", "--force"],
                "SES=2 crypto erase: the controller destroys its internal "
                "encryption keys, so every block (including spares) is "
                "instantly unreadable. NIST 800-88 Purge.")]
        if sanitize_ok:
            ctrl = re.sub(r"n\d+$", "", dev) or dev
            return [Step(
                "nvme-sanitize-block-erase",
                ["nvme", "sanitize", ctrl, "-a", "2"],
                "NVMe Sanitize block erase on %s (controller-level; "
                "crypto erase not offered by this drive). NIST 800-88 "
                "Purge." % ctrl)]
        raise media.Refusal(
            "refusing to erase %s: the drive offers no firmware erase "
            "(nvme id-ctrl: %s) and a software overwrite on flash cannot "
            "reach unmapped pages. Tier 1 crypto-shredding is the real "
            "kill here." % (dev, detail))

    if info.media == media.SATA_SSD:
        state = probe_ata(dev, runner)
        if state == "unavailable":
            raise media.Refusal(
                "refusing to erase %s: hdparm is unavailable so ATA Secure "
                "Erase capability cannot be confirmed. Unconfirmed erase "
                "is not an erase — use Tier 1 crypto-shredding." % dev)
        if state == "unsupported":
            raise media.Refusal(
                "refusing to erase %s: the drive does not support ATA "
                "Secure Erase, and a software overwrite on flash is a "
                "polite fiction (unmapped pages survive). Tier 1 "
                "crypto-shredding is the real kill here." % dev)
        if state == "frozen":
            raise media.Refusal(
                "refusing to erase %s: the drive is in SECURITY FROZEN "
                "state — Secure Erase is locked by firmware. Suspend and "
                "resume the machine once (sleep/wake), then re-run. "
                "Nothing was destroyed." % dev)
        enhanced = state == "enhanced"
        steps = [Step(
            "ata-security-set-password",
            ["hdparm", "--user-master", "u", "--security-set-pass",
             ERASE_PASSWD, dev],
            "sets a temporary ATA security password so Secure Erase can "
            "be issued; the password is a throwaway, never stored")]
        steps.append(Step(
            "ata-secure-erase" + ("-enhanced" if enhanced else ""),
            ["hdparm", "--user-master", "u",
             "--security-erase-enhanced" if enhanced else "--security-erase",
             ERASE_PASSWD, dev],
            ("ENHANCED " if enhanced else "") +
            "Secure Erase: the drive's firmware erases every block, "
            "including over-provisioned spares. NIST 800-88 Purge."))
        return steps

    if info.media == media.HDD:
        return [Step(
            "hdd-single-pass-overwrite",
            ["__builtin_zero_fill__", dev],
            "single-pass zero overwrite of every addressable sector, "
            "fsync'd, followed by %d read-back samples (NIST 800-88 "
            "Clear, nwipe-style). Overwrite is a real kill on spinning "
            "rust: OS sector == physical sector." % VERIFY_SAMPLES)]

    if info.media == media.FLASH_USB:
        raise media.Refusal(
            "refusing to erase %s: USB/SD flash almost never exposes a "
            "firmware erase, and a software overwrite is a polite fiction "
            "(wear leveling + over-provisioning). Tier 1 crypto-shredding "
            "is the ONLY real kill here." % dev)
    if info.media == media.VIRTUAL:
        raise media.Refusal(
            "refusing to erase %s: virtual disks have no physical media "
            "to firmware-erase — crypto-shred the guest data (Tier 1)." % dev)
    raise media.Refusal(
        "refusing to erase %s: unrecognized media. Never assume HDD — "
        "use Tier 1 crypto-shredding or identify the drive first." % dev)


# ---------------------------------------------------------------------------
# guards
# ---------------------------------------------------------------------------

def _read_mounts(mounts_path=MOUNTS):
    try:
        with open(mounts_path) as f:
            return f.read().splitlines()
    except OSError:
        return []


def _mounted_nodes(dev, mounts_path=MOUNTS):
    """Return mounted device nodes that belong to `dev` (itself + partitions)."""
    hits = []
    for line in _read_mounts(mounts_path):
        node = line.split()[0] if line.split() else ""
        if node == dev or re.match(r"^" + re.escape(dev) + r"(p?\d+)$", node):
            hits.append(node)
    return hits


def assert_erasable(info, mounts_path=MOUNTS):
    """Structural refusals before anything destructive.

    Raises media.Refusal if the device (or any of its partitions) is mounted
    — which includes the device holding the root filesystem — or if the
    serial is missing/unknown (typed confirmation must be satisfiable).
    """
    dev = "/dev/" + info.name
    mounted = _mounted_nodes(dev, mounts_path)
    if mounted:
        raise media.Refusal(
            "refusing to erase %s: %s mounted — a mounted disk cannot be "
            "erased. Unmount/detach it first; nothing was destroyed."
            % (dev, ", ".join(mounted)))
    if not info.serial or info.serial.lower() == "unknown":
        raise media.Refusal(
            "refusing to erase %s: the drive reports no serial number, so "
            "typed confirmation cannot be satisfied. Nothing was "
            "destroyed." % dev)
    return True


def _is_root():
    return os.geteuid() == 0


def _tty_ok(stdin):
    return stdin.isatty()


def confirm_serial(expected, provided=None, stdin=None):
    """Typed confirmation: the disk serial (or "ERASE <serial>"), never Y/N.

    Returns True on match, False on mismatch. Raises media.Refusal when
    stdin is not a TTY and no explicit --serial was provided (piped or
    scripted input cannot arm a firmware erase).
    """
    if provided is not None:
        return provided.strip() == expected
    stdin = stdin or sys.stdin
    if not _tty_ok(stdin):
        raise media.Refusal(
            "refusing to arm: confirmation must be typed on a real console "
            "(stdin is not a TTY). `echo $serial | ...` can never arm an "
            "erase.")
    sys.stdout.write("Type the disk serial to arm ('%s') or 'ERASE %s': "
                     % (expected, expected))
    sys.stdout.flush()
    answer = stdin.readline().strip()
    m = re.match(r"^[Ee][Rr][Aa][Ss][Ee]\s+(.+)$", answer)
    typed = m.group(1).strip() if m else answer
    return typed == expected


def _rescan_serial(info, sysfs=SYSFS):
    base = os.path.join(sysfs, "block", info.name)
    try:
        with open(os.path.join(base, "device", "serial")) as f:
            return f.read().strip()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# HDD builtin overwrite (stdlib; no nwipe dependency)
# ---------------------------------------------------------------------------

def _device_size(path):
    """Size of a device/file in bytes. BLKGETSIZE64 for block devices."""
    BLKGETSIZE64 = 0x80081272
    try:
        import fcntl
        with open(path, "rb") as f:
            buf = fcntl.ioctl(f.fileno(), BLKGETSIZE64, b"\x00" * 8)
        return int.from_bytes(buf, "little")
    except (OSError, ImportError):
        pass
    return os.path.getsize(path)


def zero_fill(path, size, log):
    """Single-pass zero overwrite of `size` bytes at `path`, fsync'd.

    `log` is a callable receiving progress strings. Raises on I/O error.
    """
    written = 0
    chunk = b"\x00" * CHUNK
    with open(path, "r+b") as f:
        while written < size:
            n = min(CHUNK, size - written)
            f.write(chunk[:n])
            written += n
            if written % (256 * CHUNK) == 0:
                log("  overwrite: %d/%d MiB" % (written // CHUNK,
                                                size // CHUNK))
        f.flush()
        os.fsync(f.fileno())
    log("  overwrite complete: %d bytes zeroed, fsync'd" % written)
    return written


def readback_verify(path, size, log, rng=None):
    """Read-back sample verification: N random offsets must read as zeros.

    Returns (ok, checked). Honest labeling: this samples, it does not
    re-read every sector.
    """
    import random
    rng = rng or random.Random()
    ok = checked = 0
    with open(path, "rb") as f:
        for _ in range(VERIFY_SAMPLES):
            off = rng.randrange(0, max(size - CHUNK, 1))
            f.seek(off)
            data = f.read(min(CHUNK, size - off))
            checked += 1
            if data == b"\x00" * len(data):
                ok += 1
            else:
                log("  verify MISS at offset %d (%d/%d non-zero)"
                    % (off, len(data) - data.count(0), len(data)))
    log("  verify: %d/%d samples read back zeroed" % (ok, checked))
    return ok == checked, checked


def _run_step(step, dev, log_fn, runner=None):
    if runner is None:
        runner = _run
    """Execute one planned Step. Returns (rc, note)."""
    if step.argv[0] == "__builtin_zero_fill__":
        size = _device_size(dev)
        log_fn("builtin zero-fill on %s (%d bytes)" % (dev, size))
        zero_fill(dev, size, log_fn)
        ok, checked = readback_verify(dev, size, log_fn)
        note = ("single-pass zero overwrite + read-back sample verify: "
                "%d/%d samples zeroed" % (checked if ok else 0, checked))
        return (0 if ok else 1), note
    r = runner(step.argv)
    out = (r.stdout or "") + (r.stderr or "")
    if out.strip():
        for line in out.strip().splitlines()[-5:]:
            log_fn("  | " + line)
    return r.returncode, out.strip()[:500]


# ---------------------------------------------------------------------------
# the burn
# ---------------------------------------------------------------------------

def erase(dev, confirm_serial_arg=None, dry_run=True, runner=None,
          sysfs=SYSFS, mounts_path=MOUNTS, stdin=None, log_dir=None,
          no_countdown=False, require_root=True):
    """Tier-2 firmware erase with the full safety ceremony.

    Dry-run (default): classify, probe (read-only), print the plan, exit 2.
    Real burn (--execute): mount guard, root check, typed serial,
    last-second serial re-verification, abort window, execute steps,
    issue a deletion certificate. Returns (rc, certificate-or-plan).
    """
    if runner is None:
        runner = _run
    info = media.classify(dev, sysfs)
    dev = "/dev/" + info.name
    plan = plan_erase(info, runner)  # raises Refusal before anything else

    if dry_run and confirm_serial_arg is None and stdin is None:
        # default path: enumerate the plan, arm nothing
        return 2, {"device": dev, "media": info.media,
                   "plan": [s.as_dict() for s in plan],
                   "note": "dry-run: pass --execute to arm; nothing destroyed"}

    # --- the real burn: guards first ---
    assert_erasable(info, mounts_path)
    if require_root and not _is_root():
        raise media.Refusal(
            "refusing to erase %s: firmware erase needs root "
            "(block-device access). Nothing was destroyed." % dev)
    if not confirm_serial(info.serial, provided=confirm_serial_arg,
                          stdin=stdin):
        return 2, {"aborted": True,
                   "note": "confirmation did not match serial; "
                           "nothing was destroyed"}

    # last-second re-verification: same disk still attached?
    rescanned = _rescan_serial(info, sysfs)
    if rescanned != info.serial:
        return 1, {"aborted": True,
                   "note": "serial changed between confirmation and "
                           "execution (%r != %r) — hardware state is not "
                           "trustworthy; nothing was destroyed"
                           % (rescanned, info.serial)}

    if not no_countdown:
        print("Armed. Starting firmware erase in %d seconds — Ctrl-C aborts."
              % ABORT_SECONDS, flush=True)
        for s in range(ABORT_SECONDS, 0, -1):
            print("%d... " % s, end="", flush=True)
            time.sleep(1)
        print("")

    root = log_dir or os.path.join(KEYRING_ROOT, "tier2")
    for sub in ("", "certificates", "logs"):
        d = os.path.join(root, sub) if sub else root
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)
    cert_id = uuid.uuid4().hex
    log_path = os.path.join(root, "logs", "tier2-%s.log" % cert_id)
    log_lines = []

    def log_fn(msg):
        line = "[%s] %s" % (time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                         time.gmtime()), msg)
        print(line, flush=True)
        log_lines.append(line)

    log_fn("TIER-2 BURN ARMED: %s (model=%s serial=%s media=%s)"
           % (dev, info.model, info.serial, info.media))
    executed = []
    failed = False
    for step in plan:
        log_fn("STEP: %s — %s" % (step.name, step.note))
        rc, note = _run_step(step, dev, log_fn, runner)
        executed.append({"name": step.name, "argv": step.argv,
                         "rc": rc, "note": note})
        log_fn("STEP %s: rc=%d" % (step.name, rc))
        if rc != 0:
            failed = True
            log_fn("STEP FAILED — aborting remaining steps; partial erase. "
                   "Do NOT assume the disk is clean.")
            break

    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines) + "\n")
    os.chmod(log_path, 0o600)

    cert = {
        "certificate": "flamethrower-deletion",
        "cert_id": cert_id,
        "device": dev,
        "serial": info.serial,
        "model": info.model,
        "media": info.media,
        "method": "Tier 2 firmware erase (%s)" % (
            ", ".join(s["name"] for s in executed)),
        "steps": [{"name": s["name"], "rc": s["rc"], "note": s["note"]}
                  for s in executed],
        "success": not failed,
        "verification": (
            "all %d steps reported firmware success (rc=0); the drive's "
            "own firmware is the authority here — this is firmware-reported "
            "erasure, not independently verified read-back" % len(executed)
            if info.media != media.HDD else
            "single-pass zero overwrite, fsync'd, with %d read-back sample "
            "verifications" % VERIFY_SAMPLES),
        "log": log_path,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        # The log records THAT something burned, never its contents.
        "note": "this certificate attests to destruction; it contains no "
                "data contents",
    }
    if failed:
        cert["warning"] = ("a step failed — the erase is PARTIAL. Treat the "
                           "disk as NOT clean; re-run or fall back to Tier 1 "
                           "crypto-shredding.")
    cert_path = os.path.join(root, "certificates", cert_id + ".json")
    with open(cert_path, "w", encoding="utf-8") as f:
        json.dump(cert, f, indent=2)
    os.chmod(cert_path, 0o600)
    log_fn("certificate: %s" % cert_path)
    try:
        audit.append(root, tier="2", cert_id=cert_id,
                     fingerprint={"device": dev, "serial": info.serial,
                                  "model": info.model},
                     method=cert["method"], media=info.media,
                     success=not failed, verification=cert["verification"])
    except OSError as e:
        # The burn is real and the certificate exists; the audit log just
        # missed it. Say so loudly — never silently.
        log_fn("WARNING: burn completed but the audit log could not be "
               "appended: %s" % e)
    return (0 if not failed else 1), cert


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="flamethrower Tier-2 firmware erase")
    ap.add_argument("--sysfs", default=SYSFS, help="sysfs root (tests only)")
    ap.add_argument("--mounts", default=MOUNTS, help="mounts table (tests only)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_plan = sub.add_parser("plan", help="read-only kill plan for devices")
    p_plan.add_argument("devices", nargs="+")

    p_erase = sub.add_parser("erase", help="dry-run plan; --execute to arm")
    p_erase.add_argument("device")
    p_erase.add_argument("--execute", action="store_true",
                         help="actually arm the firmware erase")
    p_erase.add_argument("--serial",
                         help="typed confirmation: the disk's serial")
    p_erase.add_argument("--no-countdown", action="store_true",
                         help="skip the final abort window")

    args = ap.parse_args(argv)
    try:
        if args.cmd == "plan":
            out = []
            for dev in args.devices:
                info = media.classify(dev, args.sysfs)
                out.append({"device": "/dev/" + info.name,
                            "media": info.media,
                            "plan": [s.as_dict()
                                     for s in plan_erase(info)]})
            print(json.dumps(out, indent=2))
            return 0
        # erase
        rc, result = erase(args.device,
                           confirm_serial_arg=args.serial,
                           dry_run=not args.execute,
                           sysfs=args.sysfs, mounts_path=args.mounts,
                           no_countdown=args.no_countdown)
        if args.cmd == "erase" and not args.execute:
            info = media.classify(args.device, args.sysfs)
            print("DRY-RUN (default). This is what WOULD die:")
            print("  device: /dev/%s  media: %s  serial: %s"
                  % (info.name, info.media, info.serial or "?"))
            for s in result["plan"]:
                print("  step: %-28s %s" % (s["name"], s["note"]))
            print("Nothing was destroyed. Re-run with --execute to arm "
                  "(requires the disk's serial).")
        else:
            print(json.dumps({k: v for k, v in result.items()
                              if k != "log"}, indent=2))
        return rc
    except media.Refusal as e:
        print("REFUSED: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
