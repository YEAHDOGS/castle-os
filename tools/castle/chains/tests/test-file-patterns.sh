#!/usr/bin/env bash
# =============================================================================
# "git for files" pattern contract.
#
# A vault's tracked set = include globs matched against file names, minus
# exclude globs (exclude wins), never descending into the .chains directory
# itself, each file reported once even when several include patterns match
# it. The PowerShell engine implements this in Get-SaveWorkingTree -- and
# pwsh isn't on this box, so this suite pins:
#   1. the contract itself, as an executable spec: a python3 replica of the
#      documented matching rules run over a fixture tree
#   2. the source hooks the contract depends on: Get-TrackedPatterns /
#      Set-TrackedPatterns / Show-TrackedPatterns / Split-PatternList /
#      Test-PatternListMatch exist; the scanner skips .chains path segments;
#      the scan loop keeps its pinned `foreach ($Pattern in
#      $Script:SavePatterns)` form (see tests/test-save-patterns.sh)
#   3. the config rule: includePatterns/excludePatterns present -> override;
#      absent -> save-data defaults (old vaults behave exactly like v1)
#
# Needs: bash, python3 (stdlib only). Run from the repo root:
#   bash tests/test-file-patterns.sh
# =============================================================================
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE="$REPO/modules/vault.ps1"
pass=0; fail=0
ok() { pass=$((pass+1)); }
no() { fail=$((fail+1)); echo "FAIL: $1"; }

# --- 2. source hooks ------------------------------------------------------------
for fn in Get-TrackedPatterns Set-TrackedPatterns Show-TrackedPatterns Split-PatternList Test-PatternListMatch; do
    grep -q "^function $fn" "$ENGINE" && ok || no "missing function $fn"
done
grep -q "contains '.chains'" "$ENGINE" \
    && ok || no "scanner no longer skips .chains segments"
grep -q 'foreach ($Pattern in $Script:SavePatterns)' "$ENGINE" \
    && ok || no "scan loop no longer iterates \$Script:SavePatterns"
grep -q '"includePatterns"' "$ENGINE" && grep -q '"excludePatterns"' "$ENGINE" \
    && ok || no "config pattern fields not wired in engine"

# Split-PatternList splits on ; and , and trims
grep -q "Split-PatternList" "$REPO/chains.ps1" \
    && ok || no "chains.ps1 patterns command doesn't use Split-PatternList"
grep -q "Set-TrackedPatterns" "$REPO/chains.ps1" \
    && ok || no "chains.ps1 missing patterns dispatch"
grep -q "Set-TrackedPatterns" "$REPO/chains.sh" \
    && ok || no "chains.sh missing patterns dispatch"

# --- 1+3. executable contract spec ----------------------------------------------
FIX="$(mktemp -d)"
trap 'rm -rf "$FIX"' EXIT
W="$FIX/watch"
mkdir -p "$W/sub" "$W/.chains/snapshots"
printf 'srm-bytes'   > "$W/game.srm"
printf 'sav-bytes'   > "$W/dup.state.sav"      # matches *.state* AND *.sav: counted once
printf 'md-bytes'    > "$W/notes.md"
printf 'txt-bytes'   > "$W/notes.txt"
printf 'tmp-bytes'   > "$W/backup.tmp"
printf 'deep-bytes'  > "$W/sub/deep.md"
printf 'blob-bytes'  > "$W/.chains/snapshots/deadbeef"

python3 - "$W" <<'PY' || echo "FAIL: pattern contract (python)"
import fnmatch, os, sys
watch = sys.argv[1]

def tracked(include, exclude):
    """Replica of the documented engine rules (Linux: case-sensitive match)."""
    found, seen = [], set()
    for root, dirs, files in os.walk(watch):
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, watch)
            if ".chains" in rel.split(os.sep):
                continue                      # never ingest the vault itself
            if full in seen:
                continue                      # reported once
            if not any(fnmatch.fnmatchcase(name, p) for p in include):
                continue
            if any(fnmatch.fnmatchcase(name, p) for p in exclude):
                continue                      # exclude wins
            seen.add(full); found.append(rel)
    return sorted(found)

fails = []
def check(label, include, exclude, expected):
    got = tracked(include, exclude)
    if got != sorted(expected):
        fails.append(f"{label}: got {got}, want {sorted(expected)}")

DEFAULTS = ["*.srm", "*.sav", "*.state*"]
check("v1 defaults", DEFAULTS, [],
      ["game.srm", "dup.state.sav"])                       # dedupe: dup.state.sav once
check("docs vault", ["*.md"], [],
      ["notes.md", os.path.join("sub", "deep.md")])
check("exclude wins", ["*"], ["*.tmp"],
      ["game.srm", "dup.state.sav", "notes.md", "notes.txt",
       os.path.join("sub", "deep.md")])                    # no backup.tmp, no .chains
check("empty include tracks nothing", [], [], [])
check("multi-pattern dedupe", ["*.md", "*notes*"], [],
      ["notes.md", "notes.txt", os.path.join("sub", "deep.md")])

# config rule: fields present -> override; absent -> defaults
def effective_include(config):
    return config["includePatterns"] if "includePatterns" in config else DEFAULTS
if effective_include({}) != DEFAULTS:
    fails.append("absent includePatterns did not fall back to defaults")
if effective_include({"includePatterns": ["*.md"]}) != ["*.md"]:
    fails.append("present includePatterns did not override")

if fails:
    print("FAIL: " + "; ".join(fails)); sys.exit(1)
print("pattern contract: include/exclude/.chains-skip/dedupe/config-fallback all hold")
PY
[ $? -eq 0 ] && ok || no "pattern contract (python)"

echo ""
echo "file-patterns: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
