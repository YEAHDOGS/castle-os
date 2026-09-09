#!/usr/bin/env python3
"""Flamethrower — the unified true-deletion CLI.

Implements FLAMETHROWER.md build-order step 9: one entrypoint for Tier-3
secure file deletion with multi-pass overwrite, the strongest interlocks,
and an audit record on every real deletion.

Why this exists when tier3.py already shreds files: tier3 is the
single-pass Tier-3 engine. This CLI wraps it with the mission's exact
arming ritual and adds multi-pass overwrite (CSPRNG passes + a final
zero pass with read-back verification) for spinning rust, because a
single zero pass is the floor, not the ceiling.

Safety model (the strongest the flamethrower has):
  - DRY-RUN IS THE DEFAULT. `burn secret.txt` lists exactly what WOULD
    die, exits 2, destroys nothing. The real burn is the exception.
  - Real deletion requires BOTH:
      (1) `--i-understand` — an explicit, greppable admission that you
          know the data is unrecoverable, and
      (2) typed confirmation — the exact BASENAME of every target file,
          via `--confirm a.txt,b.txt` or typed interactively on a real
          console. Never Y/N, never a pipe.
    Mismatch on either side aborts: exit 2, nothing destroyed.
  - Structural refusals (from tier3): directories, nonexistent files,
    dangling symlinks, non-regular files, duplicate inodes, anything
    inside the keyring root. No recursive globs.
  - Abort window before the first destructive step (skippable).
  - Multi-pass overwrite: CSPRNG pass(es) then a final zero pass,
    fsync'd every pass, with read-back sample verification of the final
    pass — on HDD a verified overwrite is a real kill. On flash media
    the whole burn is labeled BEST EFFORT, loudly, with a Tier-1
    crypto-shred pointer (the chips lie; this tool never does).
  - Every real burn emits one deletion certificate per file AND appends
    one audit record per certificate to <root>/audit.jsonl (the vault's
    deletion log). The log records THAT something burned — cert id,
    file path, size, method, media, verification — never its contents.

Usage:
    flamethrower.py plan secret.txt [more ...]
    flamethrower.py burn secret.txt                  # dry-run, exit 2
    flamethrower.py burn secret.txt --i-understand \\
        --confirm secret.txt
    flamethrower.py burn a.txt b.txt --i-understand  # interactive typing

Stdlib only. No network, no new hosts. The sysfs root and the st_dev
resolver are injectable so tests fake them — no test touches real
hardware, and no test shreds a real file outside temp dirs.
"""

import argparse
import json
import os
import secrets
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import media                                     # noqa: E402
import audit                                     # noqa: E402  (cross-burn audit log)
import tier3                                      # noqa: E402  (Tier-3 engine: enumeration, planning, confirmation)

SYSFS = "/sys"
DEFAULT_PASSES = 3           # CSPRNG x (passes-1), final pass zeros
ABORT_SECONDS = 5
CHUNK = 1024 * 1024          # 1 MiB write chunks


# ---------------------------------------------------------------------------
# the multi-pass overwrite
# ---------------------------------------------------------------------------

def overwrite_multipass(path, size, passes=DEFAULT_PASSES, log=None,
                        rng_bytes=None):
    """Overwrite every byte `passes` times: CSPRNG, ..., final pass zeros.

    Each pass is fsync'd before the next begins. Returns total bytes
    written. `log` receives one line per pass (or nothing if log is None).
    `rng_bytes(n)` is injectable for tests; defaults to secrets.token_bytes.
    """
    if passes < 1:
        raise ValueError("passes must be >= 1")
    gen = rng_bytes or secrets.token_bytes
    total = 0
    with open(path, "r+b") as f:
        for p in range(1, passes + 1):
            final = (p == passes)
            f.seek(0)  # every pass starts at byte 0 — never append
            written = 0
            while written < size:
                n = min(CHUNK, size - written)
                f.write(b"\x00" * n if final else gen(n))
                written += n
            f.flush()
            os.fsync(f.fileno())
            total += written
            if log is not None:
                log("  pass %d/%d: %d bytes overwritten (%s), fsync'd"
                    % (p, passes, written,
                       "CSPRNG" if not final else "zeros"))
    return total


# ---------------------------------------------------------------------------
# the burn
# ---------------------------------------------------------------------------

def _default_keyring_root():
    return tier3.KEYRING_ROOT


def plan(paths, sysfs=SYSFS, stat_dev=None, keyring_root=None):
    """Read-only: enumerate targets and return the honest shred plans."""
    targets = tier3.enumerate_targets(paths, sysfs, stat_dev, keyring_root)
    return targets, tier3.plan_shred(targets)


def burn(paths, confirm_arg=None, i_understand=False, dry_run=True,
         passes=DEFAULT_PASSES, sysfs=SYSFS, stat_dev=None, stdin=None,
         keyring_root=None, log_dir=None, no_countdown=False, rng=None,
         rng_bytes=None):
    """Multi-pass Tier-3 burn with the full arming ceremony.

    Dry-run (default): enumerate, classify, print the plan, exit 2.
    Real burn (i_understand=True): typed basename confirmation of every
    target, abort window, then per file: multi-pass overwrite -> final-
    pass read-back verification -> random rename -> truncate -> unlink.
    Emits one deletion certificate per file and appends one audit record
    per certificate to <root>/audit.jsonl.
    Returns (rc, result dict).
    """
    targets, shred_plans = plan(paths, sysfs, stat_dev, keyring_root)

    if dry_run:
        return 2, {"targets": [t.as_dict() for t in targets],
                   "plans": shred_plans,
                   "note": ("dry-run (default): pass --i-understand to arm; "
                            "nothing was destroyed")}

    # --- the real burn: the explicit admission, then the typing ---
    if not i_understand:
        return 2, {"aborted": True,
                   "note": ("refusing to arm: a real burn needs "
                            "--i-understand (typed understanding that the "
                            "data is unrecoverable) AND typed confirmation "
                            "of every filename; nothing was destroyed")}

    try:
        confirmed = tier3.confirm_files(targets, provided=confirm_arg,
                                        stdin=stdin)
    except media.Refusal as e:
        return 1, {"aborted": True,
                   "note": "confirmation refused: %s" % e}
    if not confirmed:
        return 2, {"aborted": True,
                   "note": ("typed confirmation did not match every "
                            "filename exactly; nothing was destroyed")}

    if not no_countdown:
        print("Armed. Multi-pass file burn starts in %d seconds — "
              "Ctrl-C aborts." % ABORT_SECONDS, flush=True)
        for s in range(ABORT_SECONDS, 0, -1):
            print("%d... " % s, end="", flush=True)
            time.sleep(1)
        print("")

    root = log_dir or os.path.join(_default_keyring_root(), "flamethrower")
    for sub in ("", "certificates", "logs"):
        d = os.path.join(root, sub) if sub else root
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)
    burn_id = uuid.uuid4().hex
    log_path = os.path.join(root, "logs", "flamethrower-%s.log" % burn_id)
    log_lines = []

    def log_fn(msg):
        line = "[%s] %s" % (time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                         time.gmtime()), msg)
        print(line, flush=True)
        log_lines.append(line)

    method_of = {
        True: ("Tier 3 file shred, MULTI-PASS (BEST EFFORT — flash media): "
               "%d overwrite passes cannot reach unmapped flash pages; %s"
               % (passes, tier3.TIER1_POINTER)),
        False: ("Tier 3 file shred, MULTI-PASS (HDD): %d overwrite passes "
                "(CSPRNG x %d, final zero pass with read-back sample "
                "verification) + rename/truncate/unlink — a real kill on "
                "spinning rust"
                % (passes, passes - 1)),
    }

    certs = []
    failed = False
    for t, shred_plan in zip(targets, shred_plans):
        method = method_of[t.flash]
        log_fn("FLAMETHROWER BURN ARMED: %s (%d bytes, media=%s)%s"
               % (t.real, t.size, t.info.media,
                  " — BEST EFFORT, flash media" if t.flash else ""))
        if t.flash:
            log_fn("HONEST LABEL: " + media.honest_label(t.info.media))
            log_fn("RECOMMENDATION: " + tier3.TIER1_POINTER)
        step_notes = []
        ok = True
        try:
            overwrite_multipass(t.real, t.size, passes=passes, log=log_fn,
                                rng_bytes=rng_bytes)
            verified, checked = tier3._verify_samples(
                t.real, t.size, log_fn, rng=rng)
            if not verified:
                raise IOError("read-back verification of the final zero "
                              "pass failed")
            step_notes.append(
                "%d overwrite passes (CSPRNG x %d + final zero pass, "
                "fsync'd every pass); final-pass read-back verify %d/%d "
                "samples zeroed" % (passes, passes - 1, checked, checked))
            renamed = tier3._rename_random(t.real, log_fn)
            gone = tier3._truncate_unlink(renamed, log_fn)
            step_notes.append("renamed, truncated, unlinked (absent: %s)"
                              % gone)
            if not gone:
                raise IOError("file still present after unlink")
        except OSError as e:
            ok = False
            failed = True
            step_notes.append("FAILED: %s" % e)
            log_fn("BURN FAILED for %s: %s — treat as NOT destroyed"
                   % (t.real, e))
            continue

        cert = {
            "certificate": "flamethrower-deletion",
            "cert_id": uuid.uuid4().hex,
            "file": t.real,
            "size_bytes": t.size,
            "disk": "/dev/" + t.info.name,
            "media": t.info.media,
            "method": method,
            "overwrite_passes": passes,
            "steps": step_notes,
            "success": ok,
            "verification": (
                "%d-pass overwrite, fsync'd every pass, final zero pass "
                "verified by %d read-back samples; renamed, truncated, "
                "unlinked; absence confirmed"
                % (passes, tier3.VERIFY_SAMPLES)
                if not t.flash else
                "%d overwrite passes + read-back samples verify the "
                "passes, not deletion — unmapped flash pages may retain "
                "data; this certificate does NOT claim irrecoverability "
                "on flash" % passes),
            "media_note": media.honest_label(t.info.media),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                       time.gmtime()),
            # The log records THAT something burned, never its contents.
            "note": "this certificate attests to destruction; it contains "
                    "no file contents",
        }
        if t.flash:
            cert["recommendation"] = tier3.TIER1_POINTER
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
            log_fn("audit record appended: %s" % audit.audit_path(root))
        except (OSError, ValueError) as e:
            # The burn is real and the certificate exists; the audit log
            # just missed it. Say so loudly — never silently.
            log_fn("WARNING: burn completed but the audit log could not "
                   "be appended: %s" % e)
        certs.append(cert)

    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines) + "\n")
    os.chmod(log_path, 0o600)

    return (0 if not failed else 1), {"certificates": certs,
                                      "log": log_path,
                                      "burn_id": burn_id}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="flamethrower — unified true-deletion CLI (Tier 3 "
                    "multi-pass file burn)")
    ap.add_argument("--sysfs", default=SYSFS, help="sysfs root (tests only)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_plan = sub.add_parser("plan", help="read-only burn plan for files")
    p_plan.add_argument("files", nargs="+")

    p_burn = sub.add_parser("burn", help="dry-run plan; --i-understand "
                                        "to arm the real burn")
    p_burn.add_argument("files", nargs="+")
    p_burn.add_argument("--i-understand", action="store_true",
                        help="explicit admission that the data will be "
                             "unrecoverable — required for a real burn")
    p_burn.add_argument("--confirm",
                        help="typed confirmation: comma-separated exact "
                             "basenames of every target (or type "
                             "interactively on a TTY)")
    p_burn.add_argument("--passes", type=int, default=DEFAULT_PASSES,
                        help="overwrite passes: CSPRNG x (n-1) + final "
                             "zero pass (default %d)" % DEFAULT_PASSES)
    p_burn.add_argument("--no-countdown", action="store_true",
                        help="skip the final abort window")

    args = ap.parse_args(argv)
    try:
        if args.cmd == "plan":
            _targets, plans = plan(args.files, args.sysfs)
            print(json.dumps(plans, indent=2))
            return 0
        rc, result = burn(args.files,
                          confirm_arg=args.confirm,
                          i_understand=args.i_understand,
                          dry_run=not args.i_understand,
                          passes=args.passes,
                          sysfs=args.sysfs,
                          no_countdown=args.no_countdown)
        if not args.i_understand:
            if result.get("aborted"):
                print("ABORTED: %s" % result["note"])
            else:
                print("DRY-RUN (default). This is what WOULD die:")
                for t in result["targets"]:
                    print("  file: %s  (%d bytes, media: %s)"
                          % (t["file"], t["size_bytes"], t["media"]))
                    print("  honest label: %s" % t["honest_label"])
                    print("  guarantee: %s" % t["guarantee"])
                print("Nothing was destroyed. Re-run with --i-understand "
                      "to arm (then type every filename).")
        else:
            if result.get("aborted"):
                print("ABORTED: %s" % result["note"])
            else:
                print(json.dumps(
                    {"burn_id": result["burn_id"],
                     "certificates": [{k: v for k, v in c.items()}
                                      for c in result["certificates"]],
                     "log": result["log"]}, indent=2))
        return rc
    except media.Refusal as e:
        print("REFUSED: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
