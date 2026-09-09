#!/usr/bin/env python3
"""Flamethrower cross-burn audit log — FLAMETHROWER.md build-order step 6.

Every deletion certificate (Tier 1 keyring, Tier 2 firmware erase, Tier 3
file shred) is recorded here as one entry in a durable, append-only,
tamper-evident log. The log records THAT something was burned — never its
contents: entries carry certificate ids, fingerprints (disk serial, key
receipt hash, file path), the method used, the media label, and the
verification result. No key material, no file bytes, no passwords.

Tamper-evidence is a SHA-256 hash chain: each entry embeds the hash of the
previous entry. verify() recomputes the whole chain and reports any
modification, deletion, or reordering. This is not a blockchain — it's a
lab notebook with numbered pages. An attacker with write access to the log
file can still rewrite history from scratch (they could do that with the
certificates too); what the chain catches is silent edits, partial
deletions, and accidental corruption — which is the realistic threat on a
family server.

Honesty rules (same DNA as the rest of the flamethrower):
  - append() REFUSES incomplete records. A missing cert_id or method is a
    refusal, not a guess — the caller must fix its data, not the log.
  - verify() on a missing log is a clean "no log yet" report, not an
    error: a new keyring simply hasn't burned anything.
  - A broken chain never "repairs itself". verify() reports every problem
    it finds; recovery is the operator's call, with the full problem
    list in hand.

Stdlib only. No network, no new hosts.

Layout: <root>/audit.jsonl — one JSON object per line, 0600 permissions.
"""

import argparse
import getpass
import hashlib
import json
import os
import sys
import time

AUDIT_FILE = "audit.jsonl"
GENESIS_HASH = "GENESIS"
ENTRY_VERSION = 1

_REQUIRED = ("tier", "cert_id", "fingerprint", "method", "media",
             "success", "verification")


# ---------------------------------------------------------------------------
# plumbing
# ---------------------------------------------------------------------------

def audit_path(root):
    """Path of the audit log for a flamethrower root."""
    return os.path.join(root, AUDIT_FILE)


def _operator():
    try:
        return getpass.getuser() or "unknown"
    except Exception:
        return "unknown"


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _entry_hash(body):
    """SHA-256 over the canonical entry body (everything except entry_hash)."""
    return hashlib.sha256(_canonical(body)).hexdigest()


def _read_entries(path):
    """Yield (line_no, raw_text, entry-or-None, parse_error-or-None)."""
    entries = []
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return entries
    for i, raw in enumerate(lines, start=1):
        text = raw.strip()
        if not text:
            continue  # tolerate stray blank lines; they carry no hash
        try:
            entries.append((i, text, json.loads(text), None))
        except json.JSONDecodeError as e:
            entries.append((i, text, None, "line %d: invalid JSON (%s)"
                          % (i, e)))
    return entries


def _last_hash(path):
    """Hash of the last entry, or GENESIS for a fresh log."""
    entries = _read_entries(path)
    for _line, _raw, entry, err in reversed(entries):
        if err is None and entry is not None:
            return entry.get("entry_hash", GENESIS_HASH)
    return GENESIS_HASH


# ---------------------------------------------------------------------------
# append
# ---------------------------------------------------------------------------

def append(root, tier, cert_id, fingerprint, method, media, success,
           verification, operator=None, timestamp=None):
    """Append one burn record. Refuses (ValueError) on incomplete data.

    tier: "1" | "2" | "3"
    cert_id: the deletion certificate's id — links log entry to cert.
    fingerprint: dict identifying WHAT burned, never its contents.
        Tier 1: {"vault": name, "key_id": ..., "key_sha256_receipt": ...}
        Tier 2: {"device": "/dev/...", "serial": ..., "model": ...}
        Tier 3: {"file": path, "size_bytes": n, "inode": n}
    method / media / verification / success: as on the certificate.
    """
    if tier not in ("1", "2", "3"):
        raise ValueError("refusing audit append: tier must be '1', '2' or "
                         "'3', got %r" % (tier,))
    if not cert_id or not isinstance(cert_id, str):
        raise ValueError("refusing audit append: cert_id is required and "
                         "must be a string")
    if not method or not isinstance(method, str):
        raise ValueError("refusing audit append: method is required and "
                         "must be a string")
    if not isinstance(fingerprint, dict) or not fingerprint:
        raise ValueError("refusing audit append: fingerprint must be a "
                         "non-empty dict identifying what burned")
    if media is None or verification is None:
        raise ValueError("refusing audit append: media and verification are "
                         "required")

    os.makedirs(root, mode=0o700, exist_ok=True)
    path = audit_path(root)
    body = {
        "version": ENTRY_VERSION,
        "seq": _next_seq(path),
        "timestamp": (timestamp or
                      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        "operator": operator or _operator(),
        "tier": tier,
        "cert_id": cert_id,
        "fingerprint": fingerprint,
        "method": method,
        "media": media,
        "success": bool(success),
        "verification": verification,
        "prev_hash": _last_hash(path),
        # The log records THAT something burned, never its contents.
        "note": "this entry attests to destruction; it contains no key "
                "material and no file contents",
    }
    entry = dict(body)
    entry["entry_hash"] = _entry_hash(body)

    # Append atomically enough for a single-writer tool: open in append
    # mode, write one line, fsync before close. Concurrent burns are out
    # of scope (the flamethrower is an interactive tool, not a daemon).
    new_file = not os.path.exists(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write(_canonical(entry).decode("utf-8") + "\n")
        f.flush()
        os.fsync(f.fileno())
    if new_file:
        os.chmod(path, 0o600)
    return entry


def _next_seq(path):
    entries = _read_entries(path)
    seqs = [e["seq"] for _l, _r, e, err in entries
            if err is None and isinstance(e.get("seq"), int)]
    return (max(seqs) + 1) if seqs else 1


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

def verify(root):
    """Verify the audit log's integrity chain.

    Returns {"valid": bool, "entries": n, "problems": [...]}. A missing log
    is valid with 0 entries (nothing burned yet). A broken chain is NEVER
    valid — problems list every defect found.
    """
    path = audit_path(root)
    problems = []
    if not os.path.exists(path):
        return {"valid": True, "entries": 0, "problems": [],
                "note": "no audit log yet — no burns recorded"}
    raw_entries = _read_entries(path)
    if not raw_entries:
        return {"valid": True, "entries": 0, "problems": [],
                "note": "audit log is empty"}

    prev = GENESIS_HASH
    expected_seq = 1
    checked = 0
    for line_no, _raw, entry, err in raw_entries:
        if err is not None:
            problems.append(err)
            continue
        missing = [k for k in ("seq", "timestamp", "operator", "tier",
                               "cert_id", "fingerprint", "method", "media",
                               "success", "verification", "prev_hash",
                               "entry_hash") if k not in entry]
        if missing:
            problems.append("line %d: missing fields %s — entry is "
                            "incomplete" % (line_no, ",".join(missing)))
            continue
        if entry["seq"] != expected_seq:
            problems.append("line %d: seq %s breaks continuity (expected "
                            "%d) — entries were deleted or reordered"
                            % (line_no, entry["seq"], expected_seq))
        if entry["prev_hash"] != prev:
            problems.append("line %d: prev_hash does not match the previous "
                            "entry's hash — the chain was edited"
                            % line_no)
        body = {k: v for k, v in entry.items() if k != "entry_hash"}
        if _entry_hash(body) != entry["entry_hash"]:
            problems.append("line %d: entry_hash mismatch — this entry was "
                            "modified after it was written" % line_no)
        prev = entry["entry_hash"]
        expected_seq = entry["seq"] + 1
        checked += 1

    return {"valid": not problems, "entries": checked,
            "problems": problems}


def tail(root, n=10):
    """Return the last n entries (newest last), for quick review."""
    path = audit_path(root)
    entries = [e for _l, _r, e, err in _read_entries(path)
               if err is None]
    return entries[-n:]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="flamethrower cross-burn audit log")
    ap.add_argument("--dir", default=os.path.expanduser("~/.castle-flamethrower"),
                    help="flamethrower root")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("verify", help="verify the audit log's integrity chain")
    p = sub.add_parser("tail", help="show the most recent audit entries")
    p.add_argument("-n", type=int, default=10)

    a = ap.parse_args(argv)
    if a.cmd == "verify":
        print(json.dumps(verify(a.dir), indent=2))
        return 0 if verify(a.dir)["valid"] else 1
    elif a.cmd == "tail":
        for e in tail(a.dir, a.n):
            print("%d  %s  tier %s  %s  %s" % (
                e["seq"], e["timestamp"], e["tier"], e["cert_id"][:12],
                "OK" if e["success"] else "FAILED"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
