#!/usr/bin/env bash
# =============================================================================
# Regression tests for the bash dispatcher twin (chains.sh).
#
# chains.sh is pure arg-parse + dispatch: every engine command is delegated
# to pwsh running modules/vault.ps1. Since pwsh isn't available in this
# environment, the tests install a fake `pwsh` shim on PATH that records
# its invocation (command line + CHAINS_* env) and exits with a canned code.
# The suite asserts, for each CLI surface of chains.ps1:
#   - the right engine snippet is dispatched (function names from vault.ps1)
#   - inputs travel intact (-m wins over -Message, -n/-Oneline, refs, flags)
#   - exit codes match chains.ps1 (usage -> 0, bad path -> 1, verify -> pwsh's
#     code, restore abort -> 0, engine stdout passes through untouched)
#   - the restore confirm is case-insensitive like PowerShell -notmatch
#   - without pwsh on PATH, engine commands fail closed with exit 1
#
# What this does NOT prove (documented gap): the PowerShell bodies inside
# the snippets are copied verbatim from chains.ps1's switch arms, but they
# can't execute here -- no pwsh, and default-deny forbids installing it.
# Run chains.ps1 vs chains.sh side by side on a pwsh machine to close it.
#
# Needs: bash. No network, no installs.
# Run from the repo root:  bash tests/test-chains-sh.sh
# =============================================================================
set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHAINS_SH="$REPO_ROOT/chains.sh"

PASS=0
FAIL=0

pass() { echo "  [PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); }

assert_exit() {  # assert_exit <expected> <actual> <label>
    if [ "$1" = "$2" ]; then pass "$3 (exit $2)"; else fail "$3 (expected exit $1, got $2)"; fi
}

assert_contains() {  # assert_contains <haystack> <needle> <label>
    if printf '%s' "$1" | grep -qF "$2"; then pass "$3"; else fail "$3 (missing: $2)"; fi
}

assert_not_contains() {  # assert_not_contains <haystack> <needle> <label>
    if printf '%s' "$1" | grep -qF "$2"; then fail "$3 (unexpected: $2)"; else pass "$3"; fi
}

assert_eq() {  # assert_eq <expected> <actual> <label>
    if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (expected '$1', got '$2')"; fi
}

# strip ANSI color codes for content assertions
plain() { sed -e 's/\x1b\[[0-9;]*m//g'; }

# --- pwsh shim ----------------------------------------------------------------
# Records: full command line, CHAINS_* env. Prints $PWSH_STDOUT, exits $PWSH_EXIT.
FIX="$(mktemp -d)"
trap 'rm -rf "$FIX"' EXIT
SHIMBIN="$FIX/shimbin"; mkdir -p "$SHIMBIN"
PWSH_LOG="$FIX/pwsh.log"

cat > "$SHIMBIN/pwsh" <<'SHIM'
#!/usr/bin/env bash
{
    echo "CMDLINE: $*"
    env | grep '^CHAINS_' | sort
    echo "---"
} >> "$PWSH_LOG"
printf '%s' "${PWSH_STDOUT-}"
exit "${PWSH_EXIT:-0}"
SHIM
chmod +x "$SHIMBIN/pwsh"

# PATH with shim first (real pwsh, if any, stays reachable behind it)
export PATH="$SHIMBIN:$PATH"
export PWSH_LOG

shim_calls() { grep -c '^CMDLINE:' "$PWSH_LOG" 2>/dev/null || true; }
shim_last()  { awk '/^CMDLINE:/{buf=""} {buf=buf $0 "\n"} /^---$/{last=buf} END{printf "%s", last}' "$PWSH_LOG"; }
reset_shim() { : > "$PWSH_LOG"; unset PWSH_STDOUT PWSH_EXIT || true; }

WORK="$FIX/work"; mkdir -p "$WORK"

# run_sh <stdin-path|-> <args...> : runs chains.sh, sets OUT (ANSI-stripped) and CODE
run_sh() {
    local stdin_file="$1"; shift
    local out_file="$FIX/out.txt"
    if [[ "$stdin_file" == "-" ]]; then
        "$CHAINS_SH" "$@" >"$out_file" 2>&1
    else
        "$CHAINS_SH" "$@" <"$stdin_file" >"$out_file" 2>&1
    fi
    CODE=$?
    OUT="$(plain < "$out_file")"
}

# --- 1. usage -----------------------------------------------------------------
reset_shim
run_sh -
assert_exit 0 "$CODE" "no args -> usage, exit 0"
assert_contains "$OUT" "Chains -- git for files" "usage header"
assert_contains "$OUT" "./chains.sh init" "usage references chains.sh"
assert_eq 0 "$(shim_calls)" "no args never touches pwsh"

reset_shim
run_sh - frobnicate
assert_exit 0 "$CODE" "unknown command -> usage, exit 0 (like PS default arm)"
assert_contains "$OUT" "./chains.sh verify" "unknown command shows usage"

reset_shim
run_sh - INIT -Path "$WORK"
assert_exit 0 "$CODE" "command matching is case-insensitive (INIT)"
assert_contains "$(shim_last)" "Initialize-Chains" "INIT dispatches Initialize-Chains"

# --- 2. vault root resolution ---------------------------------------------------
reset_shim
run_sh - -Path /nonexistent-dir-xyz init
assert_exit 1 "$CODE" "missing -Path -> [FAIL], exit 1"
assert_contains "$OUT" "Path does not exist: /nonexistent-dir-xyz" "missing path message"
assert_eq 0 "$(shim_calls)" "missing path never reaches pwsh"

reset_shim
run_sh - --path "$WORK" init
assert_exit 0 "$CODE" "--path long form works"
assert_contains "$(shim_last)" "CHAINS_VAULT=$WORK" "vault root passed absolute"

# --- 3. init --------------------------------------------------------------------
reset_shim
run_sh - init -Path "$WORK"
assert_exit 0 "$CODE" "init exit 0"
assert_contains "$(shim_last)" "Initialize-Chains" "init dispatches Initialize-Chains"
assert_contains "$(shim_last)" '. $env:CHAINS_MODULE;' "engine dot-sources vault.ps1"

# --- 4. watch -------------------------------------------------------------------
reset_shim
run_sh - watch -Path "$WORK"
assert_exit 1 "$CODE" "watch without -Known/-Add -> exit 1"
assert_contains "$OUT" "Specify -Known or -Add" "watch usage hint"

reset_shim
run_sh - watch -Known -Path "$WORK"
assert_exit 0 "$CODE" "watch -Known exit 0"
last="$(shim_last)"
assert_contains "$last" "Get-KnownEmulatorSaveDir" "watch -Known lists known dirs"
assert_contains "$last" "Add-SaveWatchPath" "watch -Known adds found dirs"
assert_contains "$last" "Not a Chains" "watch guards uninitialized vault"

reset_shim
run_sh - watch -Add /tmp -Path "$WORK"
assert_contains "$(shim_last)" "Add-SaveWatchPath" "watch -Add dispatches Add-SaveWatchPath"
assert_contains "$(shim_last)" "CHAINS_ADD=/tmp" "watch -Add value travels via env"

# --- 5. commit ------------------------------------------------------------------
reset_shim
run_sh - commit -m "beat the Elite Four" -Path "$WORK"
assert_exit 0 "$CODE" "commit exit 0"
last="$(shim_last)"
assert_contains "$last" "New-SaveCommit" "commit dispatches New-SaveCommit"
assert_contains "$last" "CHAINS_MSG=beat the Elite Four" "-m message travels intact"

reset_shim
run_sh - commit --message "long form" -m "short wins" -Path "$WORK"
assert_contains "$(shim_last)" "CHAINS_MSG=short wins" "-m wins over -Message (like PS)"

reset_shim
run_sh - commit -Path "$WORK"
assert_contains "$(shim_last)" "CHAINS_MSG=" "empty message is empty string (like PS)"

# --- 6. status ------------------------------------------------------------------
reset_shim
run_sh - status -Path "$WORK"
assert_contains "$(shim_last)" "Get-SaveStatus" "status dispatches Get-SaveStatus"

# --- 7. log ---------------------------------------------------------------------
reset_shim
run_sh - log -Path "$WORK"
assert_contains "$(shim_last)" "Get-SaveLog" "log dispatches Get-SaveLog"

reset_shim
run_sh - log -n 5 -Oneline -Path "$WORK"
last="$(shim_last)"
assert_contains "$last" "CHAINS_N=5" "-n travels via env"
assert_contains "$last" "CHAINS_ONELINE=1" "-Oneline travels via env"
assert_contains "$last" 'CHAINS_ONELINE -eq' "oneline branch preserved in snippet"

reset_shim
run_sh - log -n abc -Path "$WORK"
assert_exit 1 "$CODE" "non-int -n fails like PS parameter binding"
assert_eq 0 "$(shim_calls)" "bad -n never reaches pwsh"

# --- 7b. patterns ------------------------------------------------------------------
reset_shim
run_sh - patterns -Path "$WORK"
last="$(shim_last)"
assert_contains "$last" "Show-TrackedPatterns" "bare patterns dispatches Show-TrackedPatterns"
assert_contains "$last" "CHAINS_PATTERNS_MODE=show" "bare patterns -> show mode"

reset_shim
run_sh - patterns -SetInclude "*.md;*.txt" -Path "$WORK"
last="$(shim_last)"
assert_contains "$last" "Set-TrackedPatterns" "patterns -SetInclude dispatches Set-TrackedPatterns"
assert_contains "$last" "CHAINS_PATTERNS_MODE=replace" "-SetInclude -> replace mode"
assert_contains "$last" "CHAINS_SETINCLUDE=*.md;*.txt" "-SetInclude value travels via env"
assert_contains "$last" "Split-PatternList" "globs go through Split-PatternList"

reset_shim
run_sh - patterns -Include "*.md" -Exclude "*.tmp" -Path "$WORK"
last="$(shim_last)"
assert_contains "$last" "CHAINS_PATTERNS_MODE=append" "-Include/-Exclude -> append mode"
assert_contains "$last" "CHAINS_INCLUDE=*.md" "-Include value travels via env"
assert_contains "$last" "CHAINS_EXCLUDE=*.tmp" "-Exclude value travels via env"

reset_shim
run_sh - patterns -SetInclude "" -Path "$WORK"
last="$(shim_last)"
assert_contains "$last" "CHAINS_PATTERNS_MODE=replace" "explicit empty -SetInclude is replace (track nothing)"
assert_contains "$last" "CHAINS_SETINCLUDE=" "empty -SetInclude travels as empty"

reset_shim
run_sh - patterns -Reset -SetInclude "*.md" -Path "$WORK"
assert_contains "$(shim_last)" "CHAINS_PATTERNS_MODE=reset" "-Reset wins over -SetInclude (like PS arm order)"

reset_shim
run_sh - patterns -Reset -Path "$WORK"
assert_contains "$(shim_last)" "Set-TrackedPatterns" "patterns -Reset dispatches Set-TrackedPatterns"

# --- 8. push / fetch --------------------------------------------------------------
reset_shim
run_sh - push -Path "$WORK"
assert_exit 1 "$CODE" "push without -Remote -> exit 1"
assert_contains "$OUT" "Usage: ./chains.sh push -Remote <dir>" "push usage hint"

reset_shim
run_sh - push -Remote /tmp/rem -Path "$WORK"
last="$(shim_last)"
assert_contains "$last" "Push-Chains" "push dispatches Push-Chains"
assert_contains "$last" "CHAINS_REMOTE=/tmp/rem" "-Remote travels via env"

reset_shim
run_sh - fetch --remote /tmp/rem -Path "$WORK"
assert_contains "$(shim_last)" "Fetch-Chains" "fetch dispatches Fetch-Chains"

# --- 9. verify --------------------------------------------------------------------
reset_shim
export PWSH_EXIT=0
run_sh - verify -Path "$WORK"
assert_exit 0 "$CODE" "verify passes pwsh exit 0 through"
assert_contains "$(shim_last)" "Test-SaveChain" "verify dispatches Test-SaveChain"
assert_contains "$(shim_last)" "Exit 0" "verify snippet exits 0 on success"

reset_shim
export PWSH_EXIT=1
run_sh - verify -Path "$WORK"
assert_exit 1 "$CODE" "verify passes pwsh exit 1 through (non-zero on failure)"
assert_contains "$(shim_last)" "Exit 1" "verify snippet exits 1 on failure"
unset PWSH_EXIT || true

# --- 10. diff -----------------------------------------------------------------------
reset_shim
run_sh - diff aaa111 bbb222 -Path "$WORK"
last="$(shim_last)"
assert_contains "$last" "Compare-SaveCommit" "diff dispatches Compare-SaveCommit"
assert_contains "$last" "CHAINS_A=aaa111" "diff ref A travels via env"
assert_contains "$last" "CHAINS_B=bbb222" "diff ref B travels via env"

reset_shim
run_sh - diff aaa111 -Path "$WORK"
assert_exit 1 "$CODE" "diff with one ref -> exit 1"
assert_contains "$OUT" "Usage: ./chains.sh diff <commit-a> <commit-b>" "diff usage hint"

# --- 11. restore ----------------------------------------------------------------------
printf 'n\n' > "$FIX/no.txt"
reset_shim
run_sh "$FIX/no.txt" restore abc123 -Path "$WORK"
assert_exit 0 "$CODE" "restore abort -> exit 0 (like PS)"
assert_contains "$OUT" "This overwrites current save files with commit abc123" "restore warns before confirm"
assert_contains "$OUT" "Aborted." "restore abort message"
assert_eq 0 "$(shim_calls)" "aborted restore never reaches pwsh"

printf '\n' > "$FIX/empty.txt"
reset_shim
run_sh "$FIX/empty.txt" restore abc123 -Path "$WORK"
assert_exit 0 "$CODE" "empty answer defaults to No"
assert_eq 0 "$(shim_calls)" "empty answer never reaches pwsh"

for ans in y Y yes YES Yes; do
    printf '%s\n' "$ans" > "$FIX/ans.txt"
    reset_shim
    run_sh "$FIX/ans.txt" restore abc123 -Path "$WORK"
    assert_exit 0 "$CODE" "restore confirm '$ans' -> proceeds"
    assert_contains "$(shim_last)" "Restore-SaveCommit" "restore '$ans' dispatches Restore-SaveCommit"
done

printf 'y\n' > "$FIX/y.txt"
reset_shim
run_sh "$FIX/y.txt" restore abc123 -Force -Path "$WORK"
assert_exit 0 "$CODE" "-Force skips the prompt"
assert_not_contains "$OUT" "Continue?" "-Force asks nothing"
assert_contains "$(shim_last)" "Restore-SaveCommit" "-Force dispatches directly"

reset_shim
run_sh "$FIX/y.txt" restore abc123 -NoBackup -Path "$WORK"
assert_contains "$(shim_last)" "CHAINS_NOBACKUP=1" "-NoBackup travels via env"

reset_shim
run_sh "$FIX/y.txt" restore abc123 -Path "$WORK"
assert_contains "$(shim_last)" "CHAINS_NOBACKUP=0" "-NoBackup defaults off"

reset_shim
run_sh - restore -Path "$WORK"
assert_exit 1 "$CODE" "restore without ref -> exit 1"
assert_contains "$OUT" "Usage: ./chains.sh restore <commit>" "restore usage hint"

# --- 12. engine stdout passes through -----------------------------------------------
reset_shim
export PWSH_STDOUT="  [OK] engine says hi"
run_sh - status -Path "$WORK"
assert_contains "$OUT" "[OK] engine says hi" "engine stdout passes through untouched"
unset PWSH_STDOUT || true

# --- 13. no pwsh -> fail closed -------------------------------------------------------
reset_shim
EMPTYBIN="$FIX/emptybin"; mkdir -p "$EMPTYBIN"
if command -v pwsh >/dev/null 2>&1 && [[ "$(command -v pwsh)" == "$SHIMBIN/pwsh" ]]; then
    PATH="$EMPTYBIN:/usr/bin:/bin" "$CHAINS_SH" status -Path "$WORK" > "$FIX/nopwsh.out" 2>&1
    CODE=$?
    OUT="$(plain < "$FIX/nopwsh.out")"
    assert_exit 1 "$CODE" "no pwsh -> engine command fails closed, exit 1"
    assert_contains "$OUT" "needs PowerShell (pwsh)" "no-pwsh error names pwsh"
    assert_contains "$OUT" "chains-doctor.sh" "no-pwsh error points at bash twins"
else
    pass "no pwsh test skipped (real pwsh shadowing shim)"
fi

# --- 14. unknown flag ------------------------------------------------------------------
reset_shim
run_sh - status --frobnicate -Path "$WORK"
assert_exit 1 "$CODE" "unknown flag -> exit 1 (like PS binding error)"
assert_contains "$OUT" "Unknown parameter" "unknown flag message"

echo ""
echo "chains-sh: $PASS passed, $FAIL failed."
exit "$([ "$FAIL" -eq 0 ] && echo 0 || echo 1)"
