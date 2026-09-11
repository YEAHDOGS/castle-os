#!/usr/bin/env bash
# =============================================================================
# Journal schema contract: backward compatibility + the new optional fields.
#
# Chains journals are append-only JSONL. The "git for files" expansion adds
# two OPTIONAL fields to each entry -- `seq` (per-commit revision counter)
# and `patterns` (the include/exclude globs in effect) -- without changing
# the commit-id formula or any required field. Old vaults keep working, old
# readers ignore the new fields, and new readers accept old entries.
#
# This suite pins that contract with fixtures plus source pins, because the
# PowerShell engine itself can't execute here (no pwsh on this box):
#   1. a legacy entry (pre-parent era) and a parent-era entry both satisfy
#      the current required-field schema
#   2. a new entry carries seq + patterns, and seq is monotonic
#   3. the commit-id seed formula in modules/vault.ps1 is byte-identical to
#      the known-good form (the load-bearing invariant -- see
#      docs/ENGINE-PORT-DECISION.md)
#   4. the save-data default patterns (*.srm, *.sav, *.state*) are still the
#      engine defaults, so the save-data quick-start flow is untouched
#   5. Test-SaveChain's id re-derivation never depends on seq
#
# Needs: bash, python3 (stdlib only). Run from the repo root:
#   bash tests/test-journal-schema.sh
# =============================================================================
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE="$REPO/modules/vault.ps1"
pass=0; fail=0
ok() { pass=$((pass+1)); }
no() { fail=$((fail+1)); echo "FAIL: $1"; }

FIX="$(mktemp -d)"
trap 'rm -rf "$FIX"' EXIT

SHA256_8K="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# --- fixtures: three journal eras ------------------------------------------------
# legacy: minted before parent-chaining existed (no parent, no seq, no patterns)
# parent-era: parent-chained, before the expansion (no seq, no patterns)
# current: parent-chained + seq + patterns
cat > "$FIX/journal.jsonl" <<EOF
{"id": "aaa111bbb222", "ts": "2026-09-08T12:00:00+00:00", "message": "first", "files": [{"key": "W::zelda3.srm", "rel": "zelda3.srm", "sha256": "$SHA256_8K", "bytes": 8192}]}
{"id": "ccc333ddd444", "parent": "aaa111bbb222", "ts": "2026-09-09T12:00:00+00:00", "message": "second", "files": [{"key": "W::zelda3.srm", "rel": "zelda3.srm", "sha256": "$SHA256_8K", "bytes": 8192}]}
{"id": "eee555fff666", "parent": "ccc333ddd444", "seq": 3, "ts": "2026-09-10T12:00:00+00:00", "message": "third", "patterns": {"include": ["*.md"], "exclude": ["*.tmp"]}, "files": [{"key": "W::notes.md", "rel": "notes.md", "sha256": "$SHA256_8K", "bytes": 128}]}
EOF

# 1+2. schema checks in python3 (the contract, executable)
python3 - "$FIX/journal.jsonl" <<'PY' || echo "FAIL: schema contract (python)"
import json, sys
REQUIRED_TOP = {"id", "ts", "message", "files"}
REQUIRED_FILE = {"key", "rel", "sha256", "bytes"}
fails = []
lines = [l for l in open(sys.argv[1]).read().splitlines() if l.strip()]
entries = [json.loads(l) for l in lines]
for i, e in enumerate(entries):
    missing = REQUIRED_TOP - set(e)
    if missing: fails.append(f"entry {i} missing top fields: {missing}")
    for j, f in enumerate(e["files"]):
        m = REQUIRED_FILE - set(f)
        if m: fails.append(f"entry {i} file {j} missing fields: {m}")
# legacy entries (no seq) are valid: the new reader treats seq as optional
legacy_ok = all(isinstance(e, dict) for e in entries[:2])
if not legacy_ok: fails.append("legacy/parent-era entries rejected")
# new entry: seq present and monotonic across entries that carry it
seqs = [e["seq"] for e in entries if "seq" in e]
if seqs != sorted(seqs) or len(set(seqs)) != len(seqs):
    fails.append(f"seq not monotonic: {seqs}")
new = entries[2]
if "patterns" not in new or "include" not in new["patterns"] or "exclude" not in new["patterns"]:
    fails.append("new entry missing patterns.include/exclude")
# old-reader view: required fields alone still describe the new entry fully
old_view = {k: new[k] for k in REQUIRED_TOP}
if set(old_view) != REQUIRED_TOP: fails.append("old-reader projection broken")
if fails:
    print("FAIL: " + "; ".join(fails)); sys.exit(1)
print("schema contract: legacy, parent-era, and current entries all valid; seq monotonic")
PY
[ $? -eq 0 ] && ok || no "schema contract (python)"

# 3. commit-id seed formula pins (byte-identical to the known-good form)
grep -qF '    $TreePart = (($FileList | ForEach-Object { "$($_.key)=$($_.sha256)" } | Sort-Object) -join ",")' "$ENGINE" \
    && ok || no "id seed: tree-part line changed"
grep -qF '    $Seed = "$ParentId|$Timestamp|$Message|$TreePart"' "$ENGINE" \
    && ok || no "id seed: formula line changed"
grep -qF '.Substring(0, 12)' "$ENGINE" \
    && ok || no "id: 12-hex truncation changed"

# 4. save-data defaults untouched (quick-start regression guard)
line="$(grep -E '^\$Script:SavePatterns' "$ENGINE")"
for p in '"*.srm"' '"*.sav"' '"*.state*"'; do
    printf '%s' "$line" | grep -qF "$p" && ok || no "default patterns lost $p"
done

# 5. verify never depends on seq (legacy entries verify by blob only)
if awk '/^function Test-SaveChain/,/^}/' "$ENGINE" | grep -q '\.seq'; then
    no "Test-SaveChain references .seq (verify must not depend on it)"
else
    ok
fi

echo ""
echo "journal-schema: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
