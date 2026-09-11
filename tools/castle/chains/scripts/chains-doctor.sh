#!/usr/bin/env bash
# =============================================================================
# chains doctor -- read-only health check for a Chains vault.
#
# Inspects a vault's .chains/ directory and reports health:
#   - config.json validity
#   - journal integrity (parseable lines, no duplicate ids, no dangling
#     parent refs -- the commit chain must be unbroken)
#   - commit id re-derivation: every commit id is recomputed from its
#     parent id, timestamp, message, and file list, exactly like
#     `chains.ps1 verify` -- any hand-edit to a journal entry breaks the
#     tamper-evident chain even when the parent refs still line up
#   - snapshot presence: every blob the journal names must exist, and every
#     blob's bytes must still hash to its own name (read-only re-hash)
#   - orphan snapshots (present on disk, referenced by no commit)
#   - HEAD working-tree drift: every file in the newest commit should still
#     exist at its watched source path, and the bytes still there are
#     re-hashed against the committed blob -- a mismatch means played-but-
#     uncommitted progress (the save changed since the last commit)
#   - untracked save files: saves matching the engine's patterns that live
#     under a watched path but are NOT in HEAD's tracked set (a new game
#     played but never committed) would not come back from a restore
#   - remote fingerprint pin presence (TOFU pins in config.json)
#   - last-sync staleness from pin timestamps
#   - disk-space sanity on the vault's filesystem
#
# READ-ONLY BY DEFAULT: without --fix this script never creates, modifies,
# or deletes anything inside (or outside) the vault -- the read-only contract
# holds and the fixture suite asserts it.
#
# --fix performs a bounded set of safe, reversible repairs -- and ONLY these:
#   1. malformed remote pin entries are deleted from config.json (DOCTOR.md:
#      a wiped remote simply re-pins on the next push, TOFU-style);
#   2. orphan snapshots are MOVED (never deleted) into the repair backup.
# Every other finding stays report-only -- the doctor cannot fabricate
# missing blobs, un-edit a tampered journal, or invent commit data.
# Before any write, --fix snapshots .chains/config.json and
# .chains/journal.jsonl into .chains/repair-backups/<utc-timestamp>/ and
# writes a repairs.json manifest there, so every repair is reversible by
# hand. No network code, no installs, no writes outside the vault.
#
# Exit codes: 0 = healthy, 1 = warnings only, 2 = errors found. With --fix,
# the exit code reflects the PRE-REPAIR scan -- re-run the doctor to
# confirm the vault is clean afterwards.
# --json switches the report to a single machine-readable JSON document on
# stdout (same findings, same exit codes) for scripts and CI.
# Needs: bash, python3 (stdlib only), df, sha256sum.
# =============================================================================
set -u

VAULT="."
FIX=0
JSON=0
MIN_FREE_MB="${CHAINS_DOCTOR_MIN_FREE_MB:-1024}"  # warn below 1 GiB free on the vault's filesystem
STALE_AFTER_DAYS=7      # warn when the newest pin is older than this

usage() {
    echo "Usage: $(basename "$0") [vault-root] [--fix] [--json]"
    echo ""
    echo "  vault-root   Directory containing .chains/ (default: current dir)."
    echo "  --fix        Safe, reversible auto-repairs (pins + orphans) after a"
    echo "               pre-repair backup of config.json and journal.jsonl."
    echo "  --json       Machine-readable report: one JSON document on stdout."
    echo ""
    echo "Exit codes: 0 healthy, 1 warnings, 2 errors."
}

while [ $# -gt 0 ]; do
    case "$1" in
        --fix) FIX=1; shift ;;
        --json) JSON=1; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "  [FAIL] Unknown option: $1" >&2; usage >&2; exit 2 ;;
        *) VAULT="$1"; shift ;;
    esac
done

if ! command -v python3 >/dev/null 2>&1; then
    echo "  [FAIL] chains doctor needs python3 on PATH (stdlib only)." >&2
    exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
    echo "  [FAIL] chains doctor needs sha256sum on PATH." >&2
    exit 2
fi

if [ ! -d "$VAULT" ]; then
    echo "  [FAIL] Vault root does not exist: $VAULT" >&2
    exit 2
fi
VAULT="$(cd "$VAULT" && pwd)"
CHAINS="$VAULT/.chains"

if [ ! -d "$CHAINS" ]; then
    echo "  [FAIL] Not a Chains vault (no .chains/): $VAULT" >&2
    exit 2
fi

if [ "$JSON" -eq 0 ]; then
    echo ""
    echo "  chains doctor -- $VAULT"
    echo "  ================================================================"
fi

# --- reporting ---------------------------------------------------------------
# Every finding flows through report(): human mode prints the familiar
# bracketed lines, JSON mode accumulates machine-readable records in a
# throwaway temp file (never in the vault -- the read-only contract holds).
# Both modes derive the same exit code from the same WARN/FAIL tallies.
FINDINGS="$(mktemp)"
trap 'rm -f "$FINDINGS"' EXIT

report() {  # report <severity> <message>   severity: ok | warn | fail | info
    local sev="$1" msg="$2"
    if [ "$JSON" -eq 1 ]; then
        python3 -c 'import json,sys; print(json.dumps({"severity":sys.argv[1],"message":sys.argv[2]}))' \
            "$sev" "$msg" >> "$FINDINGS"
    else
        case "$sev" in
            ok)   echo "  [OK] $msg" ;;
            warn) echo "  [~] $msg" ;;
            fail) echo "  [FAIL] $msg" ;;
            info) echo "  [i] $msg" ;;
        esac
    fi
}

# The heavy lifting (JSON parsing) runs in python3 stdlib; every finding is
# emitted as a tagged line: OK / WARN / FAIL / INFO. bash tallies the tags
# and derives the exit code. python never touches the disk except reading.
RESULTS="$(python3 - "$CHAINS" "$STALE_AFTER_DAYS" <<'PYEOF'
import hashlib, json, os, sys, re
from datetime import datetime, timezone

chains_dir = sys.argv[1]
stale_days = int(sys.argv[2])

out = []
def ok(msg):    out.append("OK  |" + msg)
def warn(msg):  out.append("WARN|" + msg)
def fail(msg):  out.append("FAIL|" + msg)
def info(msg):  out.append("INFO|" + msg)

config_path  = os.path.join(chains_dir, "config.json")
journal_path = os.path.join(chains_dir, "journal.jsonl")
snap_dir     = os.path.join(chains_dir, "snapshots")

# --- 1. config.json -------------------------------------------------------
config = None
if not os.path.isfile(config_path):
    fail("config.json is missing")
else:
    try:
        with open(config_path, "r", encoding="utf-8-sig") as f:
            config = json.load(f)
        if not isinstance(config, dict):
            fail("config.json is not a JSON object")
            config = None
        else:
            ok("config.json parses")
            if config.get("version") is None:
                warn("config.json has no 'version' field")
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
        fail("config.json is not valid JSON: %s" % e)

# --- 2. journal integrity -------------------------------------------------
entries = []
if not os.path.isfile(journal_path):
    fail("journal.jsonl is missing")
else:
    try:
        with open(journal_path, "r", encoding="utf-8-sig") as f:
            raw_lines = f.read().splitlines()
    except (OSError, UnicodeDecodeError) as e:
        fail("journal.jsonl is unreadable: %s" % e)
        raw_lines = None
    if raw_lines is not None:
        lineno = 0
        for line in raw_lines:
            lineno += 1
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                fail("journal.jsonl line %d is not valid JSON: %s" % (lineno, e))
                continue
            if not isinstance(obj, dict) or not obj.get("id"):
                fail("journal.jsonl line %d has no commit id" % lineno)
                continue
            entries.append(obj)
        ok("journal.jsonl parses (%d commit(s))" % len(entries))

if entries:
    seen = set()
    prev_id = ""
    for i, e in enumerate(entries):
        cid = e["id"]
        if cid in seen:
            fail("duplicate commit id in journal: %s" % cid)
        else:
            seen.add(cid)
        parent = e.get("parent", "")
        if i == 0:
            if parent not in ("", None):
                warn("first journal entry has a non-empty parent ref: %s" % parent)
        else:
            if parent not in seen:
                fail("dangling parent ref: commit %s points at unknown parent %s"
                     % (cid, parent))
        prev_id = cid
    # id format sanity (engine mints 12 lowercase hex chars)
    for cid in seen:
        if not re.fullmatch(r"[0-9a-f]{12}", cid):
            warn("commit id does not look engine-minted (12 hex chars): %s" % cid)
    ok("commit chain is unbroken (%d link(s) checked)" % len(entries))

    # --- 2b. commit id re-derivation (tamper-evident chain) -----------------
    # The engine mints each id as the first 12 hex chars of
    #   SHA256("<parent>|<ts>|<message>|<sorted key=sha256 list joined by ,>")
    # (vault.ps1 New-SaveCommitId). Re-deriving the ids catches any
    # hand-edit of a journal entry -- message, file list, timestamp -- even
    # when the parent refs still line up, mirroring `chains.ps1 verify`
    # (Test-SaveChain). PowerShell's Sort-Object is case-insensitive, so
    # the sort here is casefolded to match. Entries without a "parent"
    # field predate chaining and are skipped, exactly like the engine's
    # legacy path -- their blobs are still re-hashed in check 6.
    id_bad = 0
    id_checked = 0
    id_legacy = 0
    for e in entries:
        if "parent" not in e:
            id_legacy += 1
            continue
        parent = e.get("parent") or ""
        ts = e.get("ts") or ""
        message = e.get("message") or ""
        files = e.get("files") or []
        if not isinstance(files, list):
            files = []
        tree = ",".join(sorted(
            (("%s=%s" % ((f or {}).get("key", ""), (f or {}).get("sha256", "")))
             for f in files),
            key=str.casefold))
        seed = "%s|%s|%s|%s" % (parent, ts, message, tree)
        expected = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
        id_checked += 1
        if expected != e["id"]:
            id_bad += 1
            fail("commit %s fails the integrity check -- journal entry was modified (id re-derivation mismatch)" % e["id"])
    if id_bad == 0 and id_checked > 0:
        ok("commit ids re-derived clean (%d checked)" % id_checked)
    if id_legacy:
        info("%d legacy pre-chain commit(s) skipped (no parent link)" % id_legacy)

# --- 3. snapshots: presence + byte-identity --------------------------------
referenced = {}   # sha256 -> [commit ids]
if entries:
    if not os.path.isdir(snap_dir):
        fail("snapshots/ directory is missing but the journal names blobs")
    else:
        for e in entries:
            files = e.get("files") or []
            if not isinstance(files, list):
                fail("commit %s has a malformed 'files' list" % e.get("id"))
                continue
            for f in files:
                sha = (f or {}).get("sha256", "")
                if not sha:
                    fail("commit %s names a file with no sha256" % e.get("id"))
                    continue
                referenced.setdefault(sha, []).append(e.get("id"))
        ok("journal names %d distinct blob(s)" % len(referenced))

# --- 4. remote fingerprint pins ---------------------------------------------
pins = {}
if config is not None:
    raw_pins = config.get("remotePins") or {}
    if not isinstance(raw_pins, dict):
        fail("config.json 'remotePins' is not an object")
    else:
        pins = raw_pins
        if pins:
            ok("%d remote fingerprint pin(s) recorded" % len(pins))
        if config.get("syncVaultId") and not pins:
            warn("vault has synced before (syncVaultId set) but no pins are recorded")

for key, pin in pins.items():
    if not isinstance(pin, dict):
        fail("pin '%s' is malformed (not an object)" % key)
        continue
    ids = pin.get("ids")
    if not isinstance(ids, list) or not ids:
        fail("pin '%s' has no pinned commit ids" % key)
        continue
    if not pin.get("fingerprint"):
        warn("pin '%s' is missing its fingerprint" % key)
    if not pin.get("when"):
        warn("pin '%s' has no timestamp (staleness unknown)" % key)

# --- 5. last-sync staleness --------------------------------------------------
def parse_when(s):
    try:
        s = s.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        return None

newest = None
newest_key = None
for key, pin in pins.items():
    if not isinstance(pin, dict):
        continue
    dt = parse_when(str(pin.get("when", "")))
    if dt and (newest is None or dt > newest):
        newest, newest_key = dt, key

if pins and newest is None:
    warn("no pin has a parseable timestamp -- last sync is unknown")
elif newest is not None:
    age_days = (datetime.now(timezone.utc) - newest).total_seconds() / 86400.0
    when_s = newest.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if age_days > stale_days:
        warn("last sync was %s (%d day(s) ago) -- older than %d days"
             % (when_s, int(age_days), stale_days))
    else:
        ok("last sync %s (%d day(s) ago)" % (when_s, int(age_days)))
elif entries:
    info("never synced -- no remote pins yet (first sync will TOFU-pin)")

for line in out:
    print(line)

# Machine-readable summary for the bash wrapper.
summary = {
    "commit_count": len(entries),
    "blob_count": len(referenced),
    "pin_count": len(pins),
    "head": entries[-1]["id"] if entries else "",
    "head_files": [{"key": (f or {}).get("key", ""),
                    "rel": (f or {}).get("rel", ""),
                    "sha256": (f or {}).get("sha256", "")}
                   for f in (entries[-1].get("files") or [])] if entries else [],
    "referenced": sorted(referenced.keys()),
    "watch_paths": (config.get("watchPaths") or []) if isinstance(config, dict) else [],
}
print("SUMMARY:" + json.dumps(summary))
PYEOF
)"

SUMMARY_JSON=""
ERRORS=0
WARNINGS=0

while IFS= read -r line; do
    case "$line" in
        SUMMARY:*)
            SUMMARY_JSON="${line#SUMMARY:}"
            ;;
        OK\ \ \|*)
            report ok "${line#OK  |}"
            ;;
        WARN\|*)
            report warn "${line#WARN|}"
            WARNINGS=$((WARNINGS + 1))
            ;;
        FAIL\|*)
            report fail "${line#FAIL|}"
            ERRORS=$((ERRORS + 1))
            ;;
        INFO\|*)
            report info "${line#INFO|}"
            ;;
        *)
            [ -n "$line" ] && report info "[?] $line"
            ;;
    esac
done <<< "$RESULTS"

# --- 6. blob re-hash (read-only) ---------------------------------------------
if [ -n "$SUMMARY_JSON" ]; then
    BLOBS="$(python3 -c 'import json,sys; print("\n".join(json.loads(sys.argv[1])["referenced"]))' "$SUMMARY_JSON")"
    if [ -n "$BLOBS" ]; then
        BAD_HASH=0
        CHECKED=0
        while IFS= read -r sha; do
            [ -z "$sha" ] && continue
            f="$CHAINS/snapshots/$sha"
            if [ ! -f "$f" ]; then
                report fail "missing snapshot blob: $sha"
                ERRORS=$((ERRORS + 1))
                continue
            fi
            CHECKED=$((CHECKED + 1))
            ACTUAL="$(sha256sum "$f" | awk '{print $1}')"
            if [ "$ACTUAL" != "$sha" ]; then
                report fail "blob hash mismatch (corrupt): $sha"
                ERRORS=$((ERRORS + 1))
                BAD_HASH=$((BAD_HASH + 1))
            fi
        done <<< "$BLOBS"
        if [ "$BAD_HASH" -eq 0 ]; then
            report ok "$CHECKED blob(s) present and re-hashed clean"
        fi
        # orphan snapshots: on disk but referenced by no commit
        ORPHANS=0
        while IFS= read -r diskfile; do
            base="$(basename "$diskfile")"
            case "$BLOBS" in
                *"$base"*) ;;
                *) report warn "orphan snapshot (unreferenced by any commit): $base"
                   ORPHANS=$((ORPHANS + 1)) ;;
            esac
        done < <(find "$CHAINS/snapshots" -maxdepth 1 -type f 2>/dev/null)
        if [ "$ORPHANS" -gt 0 ]; then
            WARNINGS=$((WARNINGS + ORPHANS))
        fi
    fi

    # --- 7. HEAD working-tree drift --------------------------------------------
    HEAD_FILES="$(python3 -c '
import json,sys
s=json.loads(sys.argv[1])
for f in s["head_files"]:
    print(f["key"]+"\t"+f["rel"]+"\t"+f["sha256"])' "$SUMMARY_JSON")"
    if [ -n "$HEAD_FILES" ]; then
        MISSING_SRC=0
        DRIFTED=0
        while IFS=$'\t' read -r key rel sha; do
            [ -z "$key" ] && continue
            # Key is "<watch dir>::<relative path>"; split on the LAST "::".
            watch="${key%::*}"
            if [ "$watch" = "$key" ]; then
                continue  # no "::" separator -- can't resolve, skip quietly
            fi
            src="$watch/$rel"
            if [ ! -e "$src" ]; then
                report warn "HEAD save file missing from working tree: $src"
                MISSING_SRC=$((MISSING_SRC + 1))
            elif [ -f "$src" ]; then
                # The file is there -- is it still the bytes HEAD committed?
                # A mismatch is played-but-uncommitted progress: worth a
                # warning before those bytes get wiped, corrupted, or lost.
                LIVE="$(sha256sum "$src" 2>/dev/null | awk '{print $1}')"
                if [ -n "$LIVE" ] && [ "$LIVE" != "$sha" ]; then
                    report warn "save file differs from HEAD commit (uncommitted changes): $src"
                    DRIFTED=$((DRIFTED + 1))
                fi
            fi
        done <<< "$HEAD_FILES"
        WARNINGS=$((WARNINGS + MISSING_SRC + DRIFTED))
        if [ "$MISSING_SRC" -eq 0 ] && [ "$DRIFTED" -eq 0 ]; then
            HEAD_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["head"])' "$SUMMARY_JSON")"
            report ok "all HEAD ($HEAD_ID) save files present and unchanged in working tree"
        fi
    fi

    # --- 8. watched paths that no longer exist ---------------------------------
    WATCHES="$(python3 -c 'import json,sys; print("\n".join(json.loads(sys.argv[1])["watch_paths"]))' "$SUMMARY_JSON")"
    if [ -n "$WATCHES" ]; then
        while IFS= read -r w; do
            [ -z "$w" ] && continue
            if [ ! -d "$w" ]; then
                report warn "watched path no longer exists: $w"
                WARNINGS=$((WARNINGS + 1))
            fi
        done <<< "$WATCHES"
    fi
    # --- 9. untracked save files in watched dirs --------------------------------
    # A save matching one of the engine's tracked patterns that lives under
    # a watched path but is NOT in HEAD's tracked set is a file
    # `chains.ps1 restore HEAD` would never bring back -- e.g. a new game
    # played since the last commit. This is the commit-side twin of check 7
    # (drift covers tracked files that changed; this covers files never
    # tracked at all).
    #
    # Pattern source: the engine's $Script:SavePatterns in
    # modules/vault.ps1 (the single source of truth). When this script runs
    # from the chains repo, the patterns are read from the engine at scan
    # time, so the doctor can never drift behind a newly added format.
    # Standalone copies of this script (no repo tree around it) fall back to
    # the bundled list below -- kept in lockstep with the engine by
    # tests/test-doctor-patterns.sh. Add the new extension in BOTH places
    # when the engine grows.
    SAVE_PATS=()
    _SELF="$0"
    _ENGINE=""
    case "$_SELF" in
        */*) _ENGINE="$(cd "$(dirname "$_SELF")" 2>/dev/null && pwd)/../modules/vault.ps1" ;;
    esac
    if [ -n "$_ENGINE" ] && [ -f "$_ENGINE" ]; then
        while IFS= read -r _pat; do
            [ -n "$_pat" ] && SAVE_PATS+=("$_pat")
        done < <(grep -E '^\$Script:SavePatterns' "$_ENGINE" | grep -oE '"\*[^"]*"' | tr -d '"')
    fi
    if [ "${#SAVE_PATS[@]}" -eq 0 ]; then
        # FALLBACK-PATTERNS-BEGIN -- mirror of $Script:SavePatterns; see above.
        SAVE_PATS=( "*.srm" "*.sav" "*.state*" "*.sgm" "*.zst" "*.savestate"
                    "*.mcr" "*.ps2" "*.gci" "*.ppst" "*.dsv" "*.SaveRAM"
                    "*.sra" "*.eep" "*.fla" "*.vmi" "*.vms" )
        # FALLBACK-PATTERNS-END
    fi
    FIND_PATS=()
    for _pat in "${SAVE_PATS[@]}"; do
        [ "${#FIND_PATS[@]}" -gt 0 ] && FIND_PATS+=( -o )
        FIND_PATS+=( -iname "$_pat" )
    done
    #
    # Watch-relative identity mirrors the engine: key "<watch>::<rel>" where
    # <rel> is the path relative to the watch dir, so rel equality against
    # HEAD's files decides "tracked". Missing watch dirs are skipped --
    # they are already check 8's finding.
    HEAD_TRACKED="$(python3 -c '
import json,sys
s=json.loads(sys.argv[1])
for f in s["head_files"]:
    key=f.get("key","")
    if "::" in key:
        w,rel=key.rsplit("::",1)
        print(w+"\t"+rel)' "$SUMMARY_JSON")"
    UNTRACKED_LIST="$(mktemp)"
    printf '%s\n' "$HEAD_TRACKED" > "$UNTRACKED_LIST"
    UNTRACKED_COUNT=0
    SHOWN=0
    SHOW_MAX=20
    while IFS= read -r w; do
        [ -z "$w" ] && continue
        w="${w%/}"
        [ -d "$w" ] || continue
        while IFS= read -r -d '' cand; do
            # The vault's own .chains dir can never be a save source; skip it
            # if a watch path happens to enclose the vault.
            case "$cand" in
                "$CHAINS"/*) continue ;;
            esac
            rel="${cand#"$w"/}"
            if ! grep -qF -- "$w"$'\t'"$rel" "$UNTRACKED_LIST"; then
                UNTRACKED_COUNT=$((UNTRACKED_COUNT + 1))
                if [ "$SHOWN" -lt "$SHOW_MAX" ]; then
                    report warn "save file not tracked in HEAD (never committed): $cand"
                    WARNINGS=$((WARNINGS + 1))
                    SHOWN=$((SHOWN + 1))
                fi
            fi
        done < <(find "$w" \( "${FIND_PATS[@]}" \) -type f -print0 2>/dev/null)
    done <<< "$WATCHES"
    rm -f "$UNTRACKED_LIST"
    if [ "$UNTRACKED_COUNT" -gt "$SHOWN" ]; then
        report warn "...and $((UNTRACKED_COUNT - SHOWN)) more untracked save file(s) not shown"
        WARNINGS=$((WARNINGS + 1))
    fi

fi

# --- 10. disk-space sanity ----------------------------------------------------
if AVAIL_KB="$(df -k --output=avail "$VAULT" 2>/dev/null | tail -n 1 | tr -d ' ')"; then
    if [ -n "$AVAIL_KB" ] && [ "$AVAIL_KB" -ge 0 ] 2>/dev/null; then
        AVAIL_MB=$((AVAIL_KB / 1024))
        if [ "$AVAIL_MB" -lt "$MIN_FREE_MB" ]; then
            report warn "low disk space on vault filesystem: ${AVAIL_MB} MB free (warn below ${MIN_FREE_MB} MB)"
            WARNINGS=$((WARNINGS + 1))
        else
            report ok "disk space: ${AVAIL_MB} MB free"
        fi
    fi
fi

# --- --fix: safe, reversible auto-repairs -----------------------------------
# Repairs (and ONLY these):
#   1. malformed remote pin entries -> deleted from config.json
#      (a bad pin never blocks sync again; the next push/fetch TOFU-re-pins);
#   2. orphan snapshots -> MOVED to the repair backup, never deleted.
# Everything else (dangling parents, id mismatches, missing/corrupt blobs,
# broken journal lines, drift, untracked saves, stale syncs) is report-only:
# the doctor cannot fabricate bytes or un-edit history.
#
# Snapshot-before-repair: every write is preceded by a backup of
# config.json + journal.jsonl under .chains/repair-backups/<utc-timestamp>/,
# plus a repairs.json manifest. Reversing a repair is a manual copy-back.
# If the journal is unparseable or config.json is not a JSON object, no
# repair is attempted -- the vault is too damaged for safe automation.
if [ "$FIX" -eq 1 ]; then
    REPAIR_PLAN="$(python3 - "$CHAINS" <<'PYEOF'
import json, os, shutil, sys
from datetime import datetime, timezone

chains_dir = sys.argv[1]
plan = {"repairs": [], "skipped": [], "backup": None, "error": None}

def plan_repair(kind, detail):
    plan["repairs"].append({"kind": kind, **detail})

config_path  = os.path.join(chains_dir, "config.json")
journal_path = os.path.join(chains_dir, "journal.jsonl")
snap_dir     = os.path.join(chains_dir, "snapshots")

try:
    with open(config_path, "r", encoding="utf-8-sig") as f:
        config = json.load(f)
except Exception as e:
    plan["skipped"].append("config.json unreadable -- no repairs attempted: %s" % e)
    print(json.dumps(plan)); sys.exit(0)
if not isinstance(config, dict):
    plan["skipped"].append("config.json is not an object -- no repairs attempted")
    print(json.dumps(plan)); sys.exit(0)

# Malformed pin entries: not an object, or no pinned id list. Mirrors the
# scan's FAIL predicates in check 4 (missing fingerprint/timestamp is only
# a warning and is NOT repaired).
bad_pins = []
raw_pins = config.get("remotePins") or {}
if not isinstance(raw_pins, dict):
    plan["skipped"].append("'remotePins' is not an object -- pin repair skipped")
else:
    for key, pin in raw_pins.items():
        ids = pin.get("ids") if isinstance(pin, dict) else None
        if not isinstance(pin, dict) or not isinstance(ids, list) or not ids:
            bad_pins.append(key)
for key in bad_pins:
    plan_repair("pin", {"key": key})

# Orphan snapshots: files under snapshots/ the (parseable) journal never
# names. An unparseable journal means the reference set is unreliable, so
# nothing is moved in that case.
orphans = []
referenced = set()
journal_ok = os.path.isfile(journal_path)
if journal_ok:
    try:
        with open(journal_path, "r", encoding="utf-8-sig") as f:
            for line in f.read().splitlines():
                if line.strip():
                    referenced |= {f.get("sha256", "") for f in
                                   (json.loads(line).get("files") or [])}
        journal_ok = True
    except Exception as e:
        plan["skipped"].append("journal.jsonl unparseable -- blob moves skipped: %s" % e)
        journal_ok = False
else:
    plan["skipped"].append("journal.jsonl missing -- blob moves skipped")
if journal_ok and os.path.isdir(snap_dir):
    for name in os.listdir(snap_dir):
        if os.path.isfile(os.path.join(snap_dir, name)) and name not in referenced:
            orphans.append(name)
for name in sorted(orphans):
    plan_repair("orphan", {"blob": name})

if not plan["repairs"]:
    print(json.dumps(plan)); sys.exit(0)

# --- execute: snapshot first, then repair --------------------------------
ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
backup = os.path.join(chains_dir, "repair-backups", ts)
os.makedirs(os.path.join(backup, "orphans"), exist_ok=True)
for src_name in ("config.json", "journal.jsonl"):
    src = os.path.join(chains_dir, src_name)
    if os.path.isfile(src):
        shutil.copy2(src, os.path.join(backup, src_name))
plan["backup"] = backup

for rep in plan["repairs"]:
    if rep["kind"] == "pin":
        pins = config.setdefault("remotePins", {})
        pins.pop(rep["key"], None)
    elif rep["kind"] == "orphan":
        src = os.path.join(snap_dir, rep["blob"])
        if os.path.isfile(src):
            shutil.move(src, os.path.join(backup, "orphans", rep["blob"]))
        else:
            rep["skipped"] = "blob already gone"

# Atomic config rewrite (temp file + replace, same directory).
tmp = os.path.join(chains_dir, "config.json.repair-tmp")
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2)
    f.write("\n")
os.replace(tmp, config_path)

with open(os.path.join(backup, "repairs.json"), "w", encoding="utf-8") as f:
    json.dump({
        "when": datetime.now(timezone.utc).isoformat(),
        "tool": "chains doctor --fix",
        "reverses": "restore config.json / journal.jsonl from this directory, "
                    "and move orphans/<blob> files back to snapshots/",
        "repairs": plan["repairs"],
    }, f, indent=2)

print(json.dumps(plan))
PYEOF
)"
    # Guard: a failed plan computation must never be misreported as clean.
    if [ -z "$REPAIR_PLAN" ]; then
        report fail "--fix: repair pass failed to run -- no repairs were attempted"
        REPAIR_PLAN='{"repairs": [], "skipped": ["repair pass produced no output"]}'
    fi
    # Report the repair outcome through the normal reporting path, so --json
    # carries it as ordinary findings.
    python3 - "$REPAIR_PLAN" <<'PYEOF' | while IFS= read -r line; do
import json, sys
plan = json.loads(sys.argv[1])
def show(s):
    return s.replace("\n", "\\n").replace("\r", "\\r")
n = 0
for rep in plan.get("repairs", []):
    n += 1
    if rep["kind"] == "pin":
        print("OK|repaired: removed malformed remote pin '%s' (next push/fetch re-pins TOFU-style)" % show(rep["key"]))
    elif rep["kind"] == "orphan":
        if rep.get("skipped"):
            print("INFO|repair note: orphan %s was already gone -- skipped" % show(rep["blob"]))
        else:
            print("OK|repaired: moved orphan snapshot %s into the repair backup (recoverable, not deleted)" % show(rep["blob"]))
if n:
    print("INFO|repair backup: %s -- config.json + journal.jsonl were copied there before any write, and removed pins/orphans are recoverable from it" % show(plan.get("backup") or ""))
    print("INFO|re-run chains doctor to confirm the vault is clean")
else:
    print("INFO|--fix: no auto-repairable issues found -- the remaining findings need manual steps (see docs/DOCTOR.md)")
for s in plan.get("skipped", []):
    print("INFO|--fix skipped: %s" % show(s))
PYEOF
        case "$line" in
            OK\|*)   report ok "${line#OK|}" ;;
            INFO\|*) report info "${line#INFO|}" ;;
            *)      report info "[?] $line" ;;
        esac
    done
fi

if [ "$JSON" -eq 1 ]; then
    # Machine-readable report: one JSON document on stdout, nothing else.
    # Exit codes match human mode: 0 healthy, 1 warnings, 2 errors.
    if [ "$ERRORS" -gt 0 ]; then RESULT="errors"; elif [ "$WARNINGS" -gt 0 ]; then RESULT="warnings"; else RESULT="healthy"; fi
    python3 - "$VAULT" "$RESULT" "$ERRORS" "$WARNINGS" "$SUMMARY_JSON" "$FINDINGS" <<'PYEOF'
import json, sys
vault, result, errors, warnings, summary_json, findings_path = (
    sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]),
    sys.argv[5], sys.argv[6])
findings = []
with open(findings_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            findings.append(json.loads(line))
try:
    summary = json.loads(summary_json) if summary_json else {}
except json.JSONDecodeError:
    summary = {}
exit_code = 2 if errors > 0 else (1 if warnings > 0 else 0)
print(json.dumps({
    "vault": vault,
    "result": result,
    "exit": exit_code,
    "errors": errors,
    "warnings": warnings,
    "findings": findings,
    "summary": summary,
}, indent=2))
PYEOF
    if [ "$ERRORS" -gt 0 ]; then exit 2; fi
    if [ "$WARNINGS" -gt 0 ]; then exit 1; fi
    exit 0
fi

echo ""

if [ "$ERRORS" -gt 0 ]; then
    echo "  RESULT: $ERRORS error(s), $WARNINGS warning(s) -- vault needs attention."
    exit 2
elif [ "$WARNINGS" -gt 0 ]; then
    echo "  RESULT: healthy, with $WARNINGS warning(s)."
    exit 1
else
    echo "  RESULT: vault is healthy."
    exit 0
fi
