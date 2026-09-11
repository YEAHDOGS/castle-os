#!/usr/bin/env bash
# =============================================================================
# chains.sh -- bash dispatcher twin of chains.ps1 ("git for files" CLI).
#
# Same flags, same commands, same exit codes as the PowerShell dispatcher.
# The engine itself (modules/vault.ps1) is NOT reimplemented here -- each
# command is delegated to pwsh, which dot-sources the one canonical engine.
# See docs/ENGINE-PORT-DECISION.md for why the engine stays PowerShell
# (commit-id parity is load-bearing and can't be proven without pwsh).
#
# Commands mirror chains.ps1:
#   ./chains.sh init                  Initialize a vault here
#   ./chains.sh watch -Known          Auto-watch emulator save dirs
#   ./chains.sh watch -Add <dir>      Watch an explicit directory
#   ./chains.sh commit -m "msg"       Snapshot tracked files
#   ./chains.sh status                Diff working tree vs HEAD
#   ./chains.sh log [-n 10] [-Oneline]  History, newest first
#   ./chains.sh diff <a> <b>          Compare two commits
#   ./chains.sh restore <ref>         Restore a commit (auto-backs up first)
#   ./chains.sh verify                Check journal + blob integrity
#   ./chains.sh push -Remote <dir>    Push vault to a local remote
#   ./chains.sh fetch -Remote <dir>   Fetch from a local remote
#   ./chains.sh patterns [-SetInclude "*.md;*.txt"]  Tracked-file patterns
#
# Flags (PowerShell-style accepted, case-insensitive; --long forms too):
#   -Path <dir>  -Add <dir>  -Known  -m/-Message <msg>  -n <int>  -Oneline
#   -Remote <dir>  -Force  -NoBackup
#   -Include <globs>  -Exclude <globs>  -SetInclude <globs>
#   -SetExclude <globs>  -Reset   (for the patterns command)
#
# Deliberate minor differences from chains.ps1:
#   - PowerShell's unambiguous parameter prefix-matching (-Pat for -Path)
#     is not supported; use full flag names.
#   - Needs: bash, pwsh (PowerShell Core). Without pwsh every engine
#     command fails closed with exit 1; nothing is reimplemented.
# =============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE="$SCRIPT_DIR/modules/vault.ps1"

# --- ANSI colors (mirror Write-Host -ForegroundColor) -------------------------
C_CYAN=$'\033[36m'; C_WHITE=$'\033[37m'; C_GRAY=$'\033[90m'
C_RED=$'\033[31m';   C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
C_RESET=$'\033[0m'

cprint() { # cprint <color> <text...>
    local color="$1"; shift
    printf '%b%s%b\n' "$color" "$*" "$C_RESET"
}

# --- argument parsing (case-insensitive flags, like PowerShell) ----------------
COMMAND=""; VAULT_PATH="."; ADD=""; KNOWN=0
MSG_M=""; MSG_LONG=""; NOBACKUP=0; FORCE=0; N=""; ONELINE=0; REMOTE=""
PAT_INCLUDE=""; PAT_EXCLUDE=""; PAT_SETINCLUDE=""; PAT_SETEXCLUDE=""; PAT_RESET=0
PAT_INCLUDE_GIVEN=0; PAT_EXCLUDE_GIVEN=0; PAT_SETINCLUDE_GIVEN=0; PAT_SETEXCLUDE_GIVEN=0
RAWARGS=()

fail() { # fail <message>  (exit 1, like the PS "[FAIL] ... ; Exit 1" paths)
    cprint "$C_RED" "  [FAIL] $1"
    exit 1
}

need_value() { # need_value <flag> <maybe-value> ; echoes value or fails
    if [[ -n "${2-}" ]]; then printf '%s' "$2"; return 0; fi
    fail "Missing value for $1."
}

take_value() { # take_value <flag> <argc> <maybe-value> ; echoes next arg (even empty) or fails if absent
    if (($2 >= 2)); then printf '%s' "${3-}"; return 0; fi
    fail "Missing value for $1."
}

set_switch() { # set_switch <var> <raw-value>  ("", "true"/"$true", "1" -> 1)
    local var="$1" val="${2-}"
    case "${val,,}" in
        ""|true|"\$true"|1) printf -v "$var" 1 ;;
        false|"\$false"|0)  printf -v "$var" 0 ;;
        *) fail "Invalid switch value: $val (use :\$true / :\$false)." ;;
    esac
}

while (($#)); do
    a="$1"; al="${a,,}"
    # split off PowerShell-style :value suffix ("-Force:$true", "-n:5")
    if [[ "$al" == -* && "$al" == *:* ]]; then
        av="${a#*:}"; a="${a%%:*}"; al="${al%%:*}"
    else
        av=""
    fi
    case "$al" in
        -path|--path)
            if [[ -n "$av" ]]; then VAULT_PATH="$av"; shift
            else VAULT_PATH="$(need_value "-Path" "${2-}")" || exit 1; shift 2; fi ;;
        -path=*|--path=*)        VAULT_PATH="${a#*=}"; shift ;;
        -add|--add)
            if [[ -n "$av" ]]; then ADD="$av"; shift
            else ADD="$(need_value "-Add" "${2-}")" || exit 1; shift 2; fi ;;
        -add=*|--add=*)          ADD="${a#*=}"; shift ;;
        -known|--known)          set_switch KNOWN "$av"; shift ;;
        -m|--m)
            if [[ -n "$av" ]]; then MSG_M="$av"; shift
            else MSG_M="$(need_value "-m" "${2-}")" || exit 1; shift 2; fi ;;
        -m=*|--m=*)              MSG_M="${a#*=}"; shift ;;
        -message|--message)
            if [[ -n "$av" ]]; then MSG_LONG="$av"; shift
            else MSG_LONG="$(need_value "-Message" "${2-}")" || exit 1; shift 2; fi ;;
        -message=*|--message=*)  MSG_LONG="${a#*=}"; shift ;;
        -nobackup|--nobackup)    set_switch NOBACKUP "$av"; shift ;;
        -force|--force)          set_switch FORCE "$av"; shift ;;
        -n|--n)
            if [[ -n "$av" ]]; then N="$av"; shift
            else N="$(need_value "-n" "${2-}")" || exit 1; shift 2; fi ;;
        -n=*|--n=*)              N="${a#*=}"; shift ;;
        -oneline|--oneline)      set_switch ONELINE "$av"; shift ;;
        -remote|--remote)
            if [[ -n "$av" ]]; then REMOTE="$av"; shift
            else REMOTE="$(need_value "-Remote" "${2-}")" || exit 1; shift 2; fi ;;
        -remote=*|--remote=*)    REMOTE="${a#*=}"; shift ;;
        -include|--include)
            if [[ -n "$av" ]]; then PAT_INCLUDE="$av"; shift
            else PAT_INCLUDE="$(take_value "-Include" $# "${2-}")" || exit 1; shift 2; fi
            PAT_INCLUDE_GIVEN=1 ;;
        -include=*|--include=*)  PAT_INCLUDE="${a#*=}"; PAT_INCLUDE_GIVEN=1; shift ;;
        -exclude|--exclude)
            if [[ -n "$av" ]]; then PAT_EXCLUDE="$av"; shift
            else PAT_EXCLUDE="$(take_value "-Exclude" $# "${2-}")" || exit 1; shift 2; fi
            PAT_EXCLUDE_GIVEN=1 ;;
        -exclude=*|--exclude=*)  PAT_EXCLUDE="${a#*=}"; PAT_EXCLUDE_GIVEN=1; shift ;;
        -setinclude|--setinclude)
            if [[ -n "$av" ]]; then PAT_SETINCLUDE="$av"; shift
            else PAT_SETINCLUDE="$(take_value "-SetInclude" $# "${2-}")" || exit 1; shift 2; fi
            PAT_SETINCLUDE_GIVEN=1 ;;
        -setinclude=*|--setinclude=*)  PAT_SETINCLUDE="${a#*=}"; PAT_SETINCLUDE_GIVEN=1; shift ;;
        -setexclude|--setexclude)
            if [[ -n "$av" ]]; then PAT_SETEXCLUDE="$av"; shift
            else PAT_SETEXCLUDE="$(take_value "-SetExclude" $# "${2-}")" || exit 1; shift 2; fi
            PAT_SETEXCLUDE_GIVEN=1 ;;
        -setexclude=*|--setexclude=*)  PAT_SETEXCLUDE="${a#*=}"; PAT_SETEXCLUDE_GIVEN=1; shift ;;
        -reset|--reset)          set_switch PAT_RESET "$av"; shift ;;
        -*)                      fail "Unknown parameter: $1." ;;
        *)
            if [[ -z "$COMMAND" ]]; then COMMAND="$a"
            else RAWARGS+=("$a"); fi
            shift ;;
    esac
done

if [[ -n "$N" && ! "$N" =~ ^-?[0-9]+$ ]]; then
    fail "Cannot convert '$N' to int (-n)."
fi

# -m wins over -Message, exactly like chains.ps1
if [[ -n "$MSG_M" ]]; then COMMIT_MSG="$MSG_M"
elif [[ -n "$MSG_LONG" ]]; then COMMIT_MSG="$MSG_LONG"
else COMMIT_MSG=""; fi

# --- usage --------------------------------------------------------------------
show_usage() {
    echo ""
    cprint "$C_CYAN"  "  Chains -- git for files"
    cprint "$C_GRAY"  "  ================================================================"
    cprint "$C_WHITE" '  ./chains.sh init                  Initialize a vault here'
    cprint "$C_WHITE" '  ./chains.sh watch -Known          Auto-watch emulator save dirs'
    cprint "$C_WHITE" '  ./chains.sh watch -Add <dir>      Watch an explicit directory'
    cprint "$C_WHITE" '  ./chains.sh commit -m "msg"       Snapshot tracked files'
    cprint "$C_WHITE" '  ./chains.sh status                Diff working tree vs HEAD'
    cprint "$C_WHITE" '  ./chains.sh log [-n 10] [-Oneline]  History, newest first'
    cprint "$C_WHITE" '  ./chains.sh diff <a> <b>          Compare two commits'
    cprint "$C_WHITE" '  ./chains.sh restore <ref>         Restore a commit (auto-backs up first)'
    cprint "$C_WHITE" '  ./chains.sh verify                Check journal + blob integrity'
    cprint "$C_WHITE" '  ./chains.sh push -Remote <dir>    Push vault to a local remote'
    cprint "$C_WHITE" '  ./chains.sh fetch -Remote <dir>   Fetch from a local remote'
    cprint "$C_WHITE" '  ./chains.sh patterns              Show tracked file patterns'
    cprint "$C_WHITE" '  ./chains.sh patterns -SetInclude "*.md;*.txt"  Track docs instead of saves'
    cprint "$C_WHITE" '  ./chains.sh patterns -Exclude "*.tmp"          Ignore temp files'
    cprint "$C_WHITE" '  ./chains.sh patterns -Reset       Back to save-data defaults'
    echo ""
    cprint "$C_GRAY" "  -Path <dir> selects the vault root (default: current directory)."
    echo ""
}

# --- engine delegation ---------------------------------------------------------
require_pwsh() {
    if ! command -v pwsh >/dev/null 2>&1; then
        cprint "$C_RED"  "  [FAIL] chains.sh needs PowerShell (pwsh) for the Chains engine."
        cprint "$C_GRAY" "         Install PowerShell Core, or use the dependency-free bash twins"
        cprint "$C_GRAY" "         directly: scripts/chains-doctor.sh, scripts/chains-sync.sh."
        exit 1
    fi
    if [[ ! -f "$MODULE" ]]; then
        cprint "$C_RED" "  [FAIL] Engine module not found: $MODULE"
        exit 1
    fi
}

# engine <powershell-snippet> : dot-source vault.ps1, run the snippet.
# Inputs travel via CHAINS_* env vars so quoting can't break the call.
engine() {
    require_pwsh
    CHAINS_MODULE="$MODULE" \
    CHAINS_VAULT="$VAULT_ROOT" \
    CHAINS_ADD="$ADD" \
    CHAINS_MSG="$COMMIT_MSG" \
    CHAINS_N="$N" \
    CHAINS_ONELINE="$ONELINE" \
    CHAINS_REMOTE="$REMOTE" \
    CHAINS_NOBACKUP="$NOBACKUP" \
    CHAINS_PATTERNS_MODE="$PATTERNS_MODE" \
    CHAINS_INCLUDE="$PAT_INCLUDE" \
    CHAINS_EXCLUDE="$PAT_EXCLUDE" \
    CHAINS_SETINCLUDE="$PAT_SETINCLUDE" \
    CHAINS_SETEXCLUDE="$PAT_SETEXCLUDE" \
    CHAINS_A="${RAWARGS[0]-}" \
    CHAINS_B="${RAWARGS[1]-}" \
        pwsh -NoProfile -NonInteractive -Command '. $env:CHAINS_MODULE; '"$1"
}

# patterns mode, resolved once (mirrors the $PSBoundParameters logic in chains.ps1)
PATTERNS_MODE="show"
if [[ "$PAT_RESET" == "1" ]]; then PATTERNS_MODE="reset"
elif [[ "$PAT_SETINCLUDE_GIVEN" == "1" || "$PAT_SETEXCLUDE_GIVEN" == "1" ]]; then PATTERNS_MODE="replace"
elif [[ "$PAT_INCLUDE_GIVEN" == "1" || "$PAT_EXCLUDE_GIVEN" == "1" ]]; then PATTERNS_MODE="append"
fi

# --- vault root resolution (mirrors Resolve-Path in chains.ps1) ----------------
if [[ ! -e "$VAULT_PATH" ]]; then
    cprint "$C_RED" "  [FAIL] Path does not exist: $VAULT_PATH"
    exit 1
fi
VAULT_ROOT="$(cd "$VAULT_PATH" && pwd)"

# --- dispatch (mirrors switch ($Command.ToLower()) in chains.ps1) --------------
case "${COMMAND,,}" in
    "")
        show_usage; exit 0 ;;
    init)
        engine 'Initialize-Chains -Path $env:CHAINS_VAULT | Out-Null' ;;
    watch)
        if [[ "$KNOWN" == "1" ]]; then
            engine '
$Paths = Get-VaultPaths -VaultRoot $env:CHAINS_VAULT
if (-not (Test-Path $Paths.Dir)) { Write-Host "  [FAIL] Not a Chains. Run '"'"'init'"'"' first." -ForegroundColor Red; Exit 1 }
$Found = Get-KnownEmulatorSaveDir
if ($Found.Count -eq 0) { Write-Host "  [i] No known emulator save dirs found on this machine." -ForegroundColor DarkGray }
foreach ($k in $Found) {
    Write-Host "  [>] Found $($k.Emulator): $($k.Path)" -ForegroundColor Cyan
    Add-SaveWatchPath -Paths $Paths -WatchPath $k.Path | Out-Null
}'
        elif [[ -n "$ADD" ]]; then
            engine '
$Paths = Get-VaultPaths -VaultRoot $env:CHAINS_VAULT
if (-not (Test-Path $Paths.Dir)) { Write-Host "  [FAIL] Not a Chains. Run '"'"'init'"'"' first." -ForegroundColor Red; Exit 1 }
Add-SaveWatchPath -Paths $Paths -WatchPath $env:CHAINS_ADD | Out-Null'
        else
            fail "Specify -Known or -Add <dir>."
        fi ;;
    commit)
        engine '$Paths = Get-VaultPaths -VaultRoot $env:CHAINS_VAULT
New-SaveCommit -Paths $Paths -Message $env:CHAINS_MSG | Out-Null' ;;
    status)
        engine '$Paths = Get-VaultPaths -VaultRoot $env:CHAINS_VAULT
Get-SaveStatus -Paths $Paths' ;;
    log)
        engine '
$Paths = Get-VaultPaths -VaultRoot $env:CHAINS_VAULT
$Entries = @(Get-SaveLog -Paths $Paths -Count ([int]$env:CHAINS_N))
if ($Entries.Count -eq 0) {
    Write-Host "  [i] No commits yet." -ForegroundColor DarkGray
} else {
    Write-Host ""
    foreach ($e in $Entries) {
        $When = ([datetime]$e.When).ToLocalTime().ToString("yyyy-MM-dd HH:mm")
        $Delta = "+$($e.Added) ~$($e.Modified) -$($e.Deleted)"
        $SeqTag = if ($null -ne $e.Seq) { " #$($e.Seq)" } else { "" }
        if ($env:CHAINS_ONELINE -eq "1") {
            Write-Host "  $($e.Id)$SeqTag  $When  $Delta  $($e.Message)" -ForegroundColor Cyan
        } else {
            Write-Host "  $($e.Id)$SeqTag  $When  ($($e.Files) files, $Delta)" -ForegroundColor Cyan
            if ($e.Message) { Write-Host "      $($e.Message)" -ForegroundColor White }
        }
    }
    Write-Host ""
}' ;;
    patterns)
        engine '
$Paths = Get-VaultPaths -VaultRoot $env:CHAINS_VAULT
if (-not (Test-Path $Paths.Dir)) { Write-Host "  [FAIL] Not a Chains. Run '"'"'init'"'"' first." -ForegroundColor Red; Exit 1 }
$Mode = $env:CHAINS_PATTERNS_MODE
if ($Mode -eq "reset") {
    Set-TrackedPatterns -Paths $Paths -Reset | Out-Null
} elseif ($Mode -eq "replace") {
    Set-TrackedPatterns -Paths $Paths -Include (Split-PatternList $env:CHAINS_SETINCLUDE) -Exclude (Split-PatternList $env:CHAINS_SETEXCLUDE) -Replace | Out-Null
} elseif ($Mode -eq "append") {
    Set-TrackedPatterns -Paths $Paths -Include (Split-PatternList $env:CHAINS_INCLUDE) -Exclude (Split-PatternList $env:CHAINS_EXCLUDE) | Out-Null
} else {
    Show-TrackedPatterns -Paths $Paths
}' ;;
    push)
        [[ -n "$REMOTE" ]] || fail "Usage: ./chains.sh push -Remote <dir>"
        engine '$Paths = Get-VaultPaths -VaultRoot $env:CHAINS_VAULT
Push-Chains -Paths $Paths -RemoteRoot $env:CHAINS_REMOTE | Out-Null' ;;
    fetch)
        [[ -n "$REMOTE" ]] || fail "Usage: ./chains.sh fetch -Remote <dir>"
        engine '$Paths = Get-VaultPaths -VaultRoot $env:CHAINS_VAULT
Fetch-Chains -Paths $Paths -RemoteRoot $env:CHAINS_REMOTE | Out-Null' ;;
    verify)
        engine '
$Paths = Get-VaultPaths -VaultRoot $env:CHAINS_VAULT
if (-not (Test-Path $Paths.Dir)) { Write-Host "  [FAIL] Not a Chains. Run '"'"'init'"'"' first." -ForegroundColor Red; Exit 1 }
if (Test-SaveChain -Paths $Paths) { Exit 0 } else { Exit 1 }' ;;
    diff)
        ((${#RAWARGS[@]} >= 2)) || fail "Usage: ./chains.sh diff <commit-a> <commit-b>"
        engine '$Paths = Get-VaultPaths -VaultRoot $env:CHAINS_VAULT
Compare-SaveCommit -Paths $Paths -FromRef $env:CHAINS_A -ToRef $env:CHAINS_B' ;;
    restore)
        ((${#RAWARGS[@]} >= 1)) || fail "Usage: ./chains.sh restore <commit>"
        if [[ "$FORCE" != "1" ]]; then
            cprint "$C_YELLOW" "  [!] This overwrites current save files with commit ${RAWARGS[0]}."
            cprint "$C_GRAY"   "      A pre-restore backup commit is made first (skip with -NoBackup)."
            # PowerShell -notmatch is case-insensitive: y/Y/yes/YES all confirm.
            read -r -p "      Continue? [y/N]: " confirm
            if [[ ! "$confirm" =~ ^[Yy]([Ee][Ss])?$ ]]; then
                cprint "$C_GRAY" "  [i] Aborted."
                exit 0
            fi
        fi
        engine '$Paths = Get-VaultPaths -VaultRoot $env:CHAINS_VAULT
$nb = $env:CHAINS_NOBACKUP -eq "1"
Restore-SaveCommit -Paths $Paths -Ref $env:CHAINS_A -NoBackup:$nb | Out-Null' ;;
    *)
        show_usage; exit 0 ;;
esac
