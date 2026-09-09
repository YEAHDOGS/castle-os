#!/usr/bin/env python3
"""Castle backup intake — the receiving end of Phoenix's emergency runbook.

This module is the CONTRACT Castle offers to any machine that needs a
backup target (Phoenix images the infected laptop, backs data up, then
wipes and rebuilds — Castle's 10TB drive is the landing zone). It owns
the trust boundary on Castle's side:

  - Layout contract: <root>/machines/<machine>/images/ and .../data/.
  - Quarantine: images flagged infected land in images/quarantine/ with a
    DO-NOT-MOUNT marker. Castle NEVER mounts, boots, or opens a
    quarantined image on a daily-driver machine — forensics happens on an
    isolated setup (see Phoenix EMERGENCY-RUNBOOK.md Appendix A).
  - Manifest: every intake writes one append-only record to
    <root>/intake.jsonl with the file's SHA-256. verify re-hashes every
    registered file so bit-rot or tampering is caught, not trusted.
  - Refusals: SHA-256 mismatch, unsafe names, non-regular files, writes
    outside the intake root.

Stdlib only. No network, no third-party hosts, no credentials stored —
the operator supplies transport (SMB/Veeam/USB sneakernet) and Castle
verifies what lands.

Usage:
    intake.py register --machine LAPTOP1 --kind disk-image \\
        --label QUARANTINE-INFECTED-2026-09-09 --sha256 HEX FILE
        [--quarantine] [--note "..."] [--dir PATH]
    intake.py verify [--machine LAPTOP1] [--dir PATH]
    intake.py list   [--machine LAPTOP1] [--dir PATH]
    intake.py retire --id ID16 --confirm-label LABEL [--release-quarantine]
        [--dir PATH]

exit codes: 0 clean/success, 1 usage/refusal, 2 verify found drift.
"""

import argparse
import hashlib
import json
import os
import shutil
import sys
import time

KINDS = ("disk-image", "data")
DEFAULT_DIR = os.path.expanduser("~/.castle-backups")
INTAKE_LOG = "intake.jsonl"
ACTIVITY_FILE = "activity.jsonl"
QUARANTINE_DIRNAME = "quarantine"
QUARANTINE_MARKER = "QUARANTINE-DO-NOT-MOUNT.txt"
QUARANTINE_WARNING = (
    "QUARANTINED BACKUP — DO NOT MOUNT, BOOT, OR OPEN ON A DAILY-DRIVER "
    "MACHINE. This image may contain live malware. Forensics access only "
    "from an isolated setup (see Phoenix EMERGENCY-RUNBOOK.md, Appendix A)."
)
_CHUNK = 1024 * 1024


# ---------------------------------------------------------------------------
# plumbing
# ---------------------------------------------------------------------------

def _p(*parts):
    return os.path.join(*parts)


def _ts():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _valid_name(name):
    """alnum plus - _ . — no path separators, no globs, no surprises."""
    return bool(name) and all(c.isalnum() or c in "-_." for c in name) \
        and name not in (".", "..") and len(name) <= 64


def _ensure_dirs(root):
    for d in (root, _p(root, "machines")):
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)
    act = _p(root, ACTIVITY_FILE)
    if not os.path.exists(act):
        open(act, "a").close()
    os.chmod(act, 0o600)
    return root


def _activity(root, actor, action, detail=""):
    """Append one event. Metadata only — never file bytes, never creds."""
    line = {"ts": _ts(), "actor": actor, "action": action, "detail": detail}
    with open(_p(root, ACTIVITY_FILE), "a", encoding="utf-8") as f:
        f.write(json.dumps(line, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return line


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_records(root):
    path = _p(root, INTAKE_LOG)
    if not os.path.exists(path):
        return []
    recs = []
    with open(path, encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if line:
                try:
                    recs.append(json.loads(line))
                except json.JSONDecodeError:
                    raise ValueError("corrupt intake log at line %d — refuse to trust it" % ln)
    return recs


def _append_record(root, rec):
    with open(_p(root, INTAKE_LOG), "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


# ---------------------------------------------------------------------------
# intake
# ---------------------------------------------------------------------------

def register(root, machine, kind, label, src, sha256, quarantine=False, note=""):
    """Stage a backup file into the intake and record its manifest entry.

    Returns the record. Refusals (ValueError) before anything is written:
    bad names, unknown kind, missing/non-regular src, sha mismatch, or the
    same machine+label+sha already registered (idempotent no-op).
    """
    root = _ensure_dirs(root)
    if not _valid_name(machine):
        raise ValueError("invalid machine name: %r" % machine)
    if not _valid_name(label):
        raise ValueError("invalid label: %r" % label)
    if kind not in KINDS:
        raise ValueError("kind must be %s, got %r" % ("/".join(KINDS), kind))
    if not os.path.isfile(src) or os.path.islink(src):
        raise ValueError("src must be a regular file: %r" % src)
    if not sha256 or not all(c in "0123456789abcdefABCDEF" for c in sha256) \
            or len(sha256) != 64:
        raise ValueError("sha256 must be a 64-hex digest")
    sha256 = sha256.lower()

    existing = [r for r in _read_records(root)
                if r["machine"] == machine and r["label"] == label
                and r["sha256"] == sha256]
    if existing:
        return existing[0]  # idempotent: same bytes, same label = same intake

    digest = _sha256(src)
    if digest != sha256:
        raise ValueError(
            "sha256 mismatch for %s: expected %s, file hashes %s — refused"
            % (src, sha256, digest))

    size = os.path.getsize(src)
    ext = os.path.splitext(os.path.basename(src))[1].lower()
    if len(ext) > 8 or any(c not in ".abcdefghijklmnopqrstuvwxyz0123456789"
                           for c in ext):
        ext = ""
    dest_dir = _p(root, "machines", machine, "images" if kind == "disk-image" else "data")
    if quarantine and kind != "disk-image":
        raise ValueError("quarantine is only meaningful for disk images")
    if quarantine:
        dest_dir = _p(dest_dir, QUARANTINE_DIRNAME)
        os.makedirs(dest_dir, mode=0o700, exist_ok=True)
        os.chmod(dest_dir, 0o700)
        marker = _p(dest_dir, QUARANTINE_MARKER)
        if not os.path.exists(marker):
            with open(marker, "w", encoding="utf-8") as f:
                f.write(QUARANTINE_WARNING + "\n")
            os.chmod(marker, 0o600)
    else:
        os.makedirs(dest_dir, mode=0o700, exist_ok=True)
        os.chmod(dest_dir, 0o700)

    fname = "%s-%s-%s%s" % (label, time.strftime("%Y%m%d", time.gmtime()),
                            digest[:12], ext)
    dest = _p(dest_dir, fname)
    if not os.path.realpath(dest).startswith(os.path.realpath(root) + os.sep):
        raise ValueError("destination escapes intake root — refused")
    shutil.copyfile(src, dest)
    os.chmod(dest, 0o600)

    rec = {
        "type": "intake",
        "id": digest[:16],
        "ts": _ts(),
        "machine": machine,
        "kind": kind,
        "label": label,
        "relpath": os.path.relpath(dest, root),
        "bytes": size,
        "sha256": digest,
        "quarantine": bool(quarantine),
        "note": note[:200],
    }
    _append_record(root, rec)
    _activity(root, "intake", "register",
              "machine=%s kind=%s label=%s bytes=%d quarantine=%s"
              % (machine, kind, label, size, quarantine))
    return rec


def verify(root, machine=None):
    """Re-hash every live registered file. Returns (ok_count, issues).

    issues: list of (relpath, problem) — CORRUPT (sha mismatch) or MISSING.
    Retired intakes (superseded backups destroyed via retire) are skipped —
    they point at files that are supposed to be gone. The intake log itself
    being unreadable is a hard refusal, not a pass.
    """
    root = _ensure_dirs(root)
    recs = _read_records(root)
    if machine is not None:
        recs = [r for r in recs if r["machine"] == machine]
    retired_ids = {r["intake_id"] for r in recs if r.get("type") == "retirement"}
    ok = 0
    issues = []
    for r in recs:
        if r.get("type", "intake") != "intake" or r["id"] in retired_ids:
            continue
        path = _p(root, r["relpath"])
        if not os.path.isfile(path):
            issues.append((r["relpath"], "MISSING"))
            continue
        if _sha256(path) != r["sha256"]:
            issues.append((r["relpath"], "CORRUPT"))
            continue
        ok += 1
    return ok, issues


def list_entries(root, machine=None):
    """Manifest entries only — never file bytes.

    Each intake record carries a "retired" flag when a retirement record
    exists for it, so `list` shows the full lifecycle, not a lie of
    omission. Retirement records themselves are history, not inventory.
    """
    root = _ensure_dirs(root)
    recs = _read_records(root)
    retired_ids = {r["intake_id"] for r in recs if r.get("type") == "retirement"}
    out = []
    for r in recs:
        if r.get("type", "intake") != "intake":
            continue
        if machine is not None and r["machine"] != machine:
            continue
        r = dict(r)
        r["retired"] = r["id"] in retired_ids
        out.append(r)
    return out


# ---------------------------------------------------------------------------
# retire — safe destruction of superseded backups (flamethrower-adjacent)
# ---------------------------------------------------------------------------

_BURN_PASSES = 2          # CSPRNG passes before the final zero pass
_SAMPLE = 32 * 1024       # read-back sample size per spot (head/mid/tail)


def _burn_file(path):
    """Overwrite → read-back-verify → rename → truncate → unlink.

    2x CSPRNG passes + 1 zero pass, fsync after every pass, then a sampled
    read-back (head/mid/tail) that must be all zeros — a sample that fails
    raises LOUDLY before unlink. Honest media note: software overwrite
    cannot guarantee destruction on NAND flash (wear leveling, spare
    area); the certificate says so plainly.
    """
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        for i in range(_BURN_PASSES):
            f.seek(0)
            remaining = size
            while remaining > 0:
                chunk = os.urandom(min(_CHUNK, remaining))
                f.write(chunk)
                remaining -= len(chunk)
            f.flush()
            os.fsync(f.fileno())
        f.seek(0)
        remaining = size
        zeros = b"\x00" * min(_CHUNK, 1024 * 1024)
        while remaining > 0:
            n = min(remaining, len(zeros))
            f.write(zeros[:n])
            remaining -= n
        f.flush()
        os.fsync(f.fileno())
        for spot in (0, max(0, size // 2 - _SAMPLE // 2),
                     max(0, size - _SAMPLE)):
            f.seek(spot)
            sample = f.read(_SAMPLE)
            if sample.strip(b"\x00"):
                raise ValueError(
                    "read-back verification FAILED at offset %d — "
                    "bytes survived the overwrite; refusing to unlink" % spot)
    verification = "sampled-read-back-clean"
    # rename → truncate → unlink, so the name dies with the bytes
    d = os.path.dirname(path)
    tombstone = _p(d, ".retired-%s.tmp" % os.urandom(8).hex())
    os.rename(path, tombstone)
    with open(tombstone, "r+b") as f:
        f.truncate(0)
        f.flush()
        os.fsync(f.fileno())
    os.unlink(tombstone)
    dfd = os.open(d, os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    method = "overwrite-%dx-csprng+zero-verify" % _BURN_PASSES
    return method, verification


def retire(root, record_id, confirm_label, release_quarantine=False,
           actor="operator"):
    """Destroy an intake file and close its manifest loop.

    Refusals (ValueError) before anything is destroyed: unknown id,
    already retired, confirmation not an exact match of the record's
    label, quarantined image without --release-quarantine, file missing
    from disk, or file hash drifting from the manifest (CORRUPT — never
    destroy data you can't verify). Success appends a "retirement"
    record (fingerprints only — never contents) and logs activity.
    Returns the retirement record.
    """
    root = _ensure_dirs(root)
    recs = _read_records(root)
    targets = [r for r in recs
               if r.get("type", "intake") == "intake" and r["id"] == record_id]
    if not targets:
        raise ValueError("no intake record with id %r — nothing retired"
                         % record_id)
    rec = targets[0]
    prior = [r for r in recs if r.get("type") == "retirement"
             and r["intake_id"] == rec["id"]]
    if prior:
        raise ValueError("record %s already retired at %s — refusing a second burn"
                         % (record_id, prior[0]["ts"]))
    if confirm_label != rec["label"]:
        raise ValueError(
            "confirmation %r does not exactly match record label %r — "
            "nothing destroyed" % (confirm_label, rec["label"]))
    if rec.get("quarantine") and not release_quarantine:
        raise ValueError(
            "quarantined image — destroying forensics evidence. Re-run with "
            "--release-quarantine only after the analysis is done.")
    path = _p(root, rec["relpath"])
    if not os.path.isfile(path):
        raise ValueError(
            "file missing at %s — manifest drift; investigate before "
            "retiring, never cover it up" % rec["relpath"])
    if _sha256(path) != rec["sha256"]:
        raise ValueError(
            "file at %s is CORRUPT (sha drift vs manifest) — refusing to "
            "destroy data I cannot verify" % rec["relpath"])

    method, verification = _burn_file(path)

    ret = {
        "type": "retirement",
        "ts": _ts(),
        "intake_id": rec["id"],
        "machine": rec["machine"],
        "kind": rec["kind"],
        "label": rec["label"],
        "relpath": rec["relpath"],
        "bytes": rec["bytes"],
        "sha256": rec["sha256"],
        "quarantine": bool(rec.get("quarantine")),
        "quarantine_released": bool(rec.get("quarantine") and release_quarantine),
        "method": method,
        "verification": verification,
        "media_note": ("software overwrite verified by read-back; on NAND "
                       "flash this is best-effort — for guarantees use "
                       "crypto-shred (flamethrower Tier-1)"),
        "actor": actor,
    }
    _append_record(root, ret)
    _activity(root, actor, "retire",
              "id=%s machine=%s kind=%s label=%s bytes=%d method=%s "
              "verification=%s quarantine=%s" % (
                  rec["id"], rec["machine"], rec["kind"], rec["label"],
                  rec["bytes"], method, verification, rec.get("quarantine")))
    return ret


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(prog="intake.py",
                                 description="Castle backup intake — the Phoenix backup target contract.")
    ap.add_argument("--dir", default=DEFAULT_DIR)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("register", help="intake a backup file")
    p.add_argument("--machine", required=True)
    p.add_argument("--kind", required=True, choices=KINDS)
    p.add_argument("--label", required=True)
    p.add_argument("--sha256", required=True)
    p.add_argument("--quarantine", action="store_true",
                   help="disk images only: quarantine layout + DO-NOT-MOUNT marker")
    p.add_argument("--note", default="")
    p.add_argument("file")

    p = sub.add_parser("verify", help="re-hash everything registered")
    p.add_argument("--machine", default=None)

    p = sub.add_parser("list", help="show intake manifest (metadata only)")
    p.add_argument("--machine", default=None)

    p = sub.add_parser("retire", help="destroy an intake file and close its "
                                       "manifest loop (typed confirmation)")
    p.add_argument("--id", required=True, help="intake record id (16-hex)")
    p.add_argument("--confirm-label", required=True,
                   help="must EXACTLY match the record's label")
    p.add_argument("--release-quarantine", action="store_true",
                   help="required to retire a quarantined image")

    a = ap.parse_args(argv)
    try:
        if a.cmd == "register":
            rec = register(a.dir, a.machine, a.kind, a.label, a.file,
                           a.sha256, quarantine=a.quarantine, note=a.note)
            print("intake: %s -> %s (%d bytes, sha256 %s%s)" % (
                a.file, rec["relpath"], rec["bytes"], rec["sha256"][:16],
                " QUARANTINED" if rec["quarantine"] else ""))
        elif a.cmd == "verify":
            ok, issues = verify(a.dir, a.machine)
            print("%d file(s) verified" % ok)
            for rel, prob in issues:
                print("  %s: %s" % (rel, prob))
            if issues:
                return 2
        elif a.cmd == "list":
            for r in list_entries(a.dir, a.machine):
                print("%s  %-10s %-9s %s  %s  %d bytes%s%s" % (
                    r["ts"][:10], r["machine"], r["kind"], r["label"],
                    r["sha256"][:16], r["bytes"],
                    "  [QUARANTINE — do not mount]" if r["quarantine"] else "",
                    "  [RETIRED %s]" % r["retired"] if r.get("retired") else ""))
        elif a.cmd == "retire":
            ret = retire(a.dir, a.id, a.confirm_label,
                         release_quarantine=a.release_quarantine)
            print("retired: %s (%d bytes, %s, %s)" % (
                ret["relpath"], ret["bytes"], ret["method"],
                ret["verification"]))
    except ValueError as e:
        print("refused: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
