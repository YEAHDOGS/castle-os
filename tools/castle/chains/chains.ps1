<#
.SYNOPSIS
    Chains -- "git for files" command line interface.
.DESCRIPTION
    Version-control your files: snapshot any watched directory, write a
    message about the moment, browse history, diff commits, and restore any
    point in time. Born as "git for save data" (emulator battery saves like
    SNES .srm and GBA .sav are still the default tracked patterns) and grown
    into general file versioning. Never lose a file again.
.EXAMPLE
    .\chains.ps1 init
    .\chains.ps1 watch -Known
    .\chains.ps1 commit -m "beat the Elite Four"
    .\chains.ps1 log -n 5 -Oneline
    .\chains.ps1 diff abc123 def456
    .\chains.ps1 restore abc123
    .\chains.ps1 verify
    .\chains.ps1 push -Remote "E:\chains-remote"
    .\chains.ps1 fetch -Remote "\\CASTLE\chains"
    .\chains.ps1 patterns -SetInclude "*.md;*.ps1"   # track docs, not saves
#>
param(
    [Parameter(Position = 0)]
    [string]$Command,

    [Parameter()]
    [string]$Path = ".",

    [Parameter()]
    [string]$Add,

    [Parameter()]
    [switch]$Known,

    [Parameter()]
    [string]$m,

    [Parameter()]
    [string]$Message,

    [Parameter()]
    [switch]$NoBackup,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [int]$n,

    [Parameter()]
    [switch]$Oneline,

    [Parameter()]
    [string]$Remote,

    [Parameter()]
    [string]$Include,

    [Parameter()]
    [string]$Exclude,

    [Parameter()]
    [string]$SetInclude,

    [Parameter()]
    [string]$SetExclude,

    [Parameter()]
    [switch]$Reset
)

$ModuleRoot = Join-Path $PSScriptRoot "modules"
. (Join-Path $ModuleRoot "vault.ps1")

$VaultRoot = (Resolve-Path $Path -ErrorAction SilentlyContinue)
if (-not $VaultRoot) {
    Write-Host "  [FAIL] Path does not exist: $Path" -ForegroundColor Red
    Exit 1
}
$VaultRoot = $VaultRoot.Path

function Show-Usage {
    Write-Host ""
    Write-Host "  Chains -- git for files" -ForegroundColor Cyan
    Write-Host "  ================================================================" -ForegroundColor DarkGray
    Write-Host "  .\chains.ps1 init                  Initialize a vault here" -ForegroundColor White
    Write-Host "  .\chains.ps1 watch -Known          Auto-watch emulator save dirs" -ForegroundColor White
    Write-Host "  .\chains.ps1 watch -Add <dir>      Watch an explicit directory" -ForegroundColor White
    Write-Host "  .\chains.ps1 commit -m ""msg""       Snapshot tracked files" -ForegroundColor White
    Write-Host "  .\chains.ps1 status                Diff working tree vs HEAD" -ForegroundColor White
    Write-Host "  .\chains.ps1 log [-n 10] [-Oneline]  History, newest first" -ForegroundColor White
    Write-Host "  .\chains.ps1 diff <a> <b>          Compare two commits" -ForegroundColor White
    Write-Host "  .\chains.ps1 restore <ref>         Restore a commit (auto-backs up first)" -ForegroundColor White
    Write-Host "  .\chains.ps1 verify                Check journal + blob integrity" -ForegroundColor White
    Write-Host "  .\chains.ps1 push -Remote <dir>    Push vault to a local remote" -ForegroundColor White
    Write-Host "  .\chains.ps1 fetch -Remote <dir>   Fetch from a local remote" -ForegroundColor White
    Write-Host "  .\chains.ps1 patterns              Show tracked file patterns" -ForegroundColor White
    Write-Host "  .\chains.ps1 patterns -SetInclude ""*.md;*.txt""  Track docs instead of saves" -ForegroundColor White
    Write-Host "  .\chains.ps1 patterns -Exclude ""*.tmp""          Ignore temp files" -ForegroundColor White
    Write-Host "  .\chains.ps1 patterns -Reset       Back to save-data defaults" -ForegroundColor White
    Write-Host ""
    Write-Host "  -Path <dir> selects the vault root (default: current directory)." -ForegroundColor DarkGray
    Write-Host ""
}

$CommitMessage = if ($m) { $m } elseif ($Message) { $Message } else { "" }

switch ($Command.ToLower()) {
    "init" {
        Initialize-Chains -Path $VaultRoot | Out-Null
    }
    "watch" {
        $Paths = Get-VaultPaths -VaultRoot $VaultRoot
        if (-not (Test-Path $Paths.Dir)) { Write-Host "  [FAIL] Not a Chains. Run 'init' first." -ForegroundColor Red; Exit 1 }
        if ($Known) {
            $Found = Get-KnownEmulatorSaveDir
            if ($Found.Count -eq 0) { Write-Host "  [i] No known emulator save dirs found on this machine." -ForegroundColor DarkGray }
            foreach ($k in $Found) {
                Write-Host "  [>] Found $($k.Emulator): $($k.Path)" -ForegroundColor Cyan
                Add-SaveWatchPath -Paths $Paths -WatchPath $k.Path | Out-Null
            }
        }
        elseif ($Add) {
            Add-SaveWatchPath -Paths $Paths -WatchPath $Add | Out-Null
        }
        else {
            Write-Host "  [FAIL] Specify -Known or -Add <dir>." -ForegroundColor Red
            Exit 1
        }
    }
    "commit" {
        $Paths = Get-VaultPaths -VaultRoot $VaultRoot
        New-SaveCommit -Paths $Paths -Message $CommitMessage | Out-Null
    }
    "status" {
        $Paths = Get-VaultPaths -VaultRoot $VaultRoot
        Get-SaveStatus -Paths $Paths
    }
    "log" {
        $Paths = Get-VaultPaths -VaultRoot $VaultRoot
        $Entries = @(Get-SaveLog -Paths $Paths -Count $n)
        if ($Entries.Count -eq 0) { Write-Host "  [i] No commits yet." -ForegroundColor DarkGray; break }
        Write-Host ""
        foreach ($e in $Entries) {
            $When = ([datetime]$e.When).ToLocalTime().ToString("yyyy-MM-dd HH:mm")
            $Delta = "+$($e.Added) ~$($e.Modified) -$($e.Deleted)"
            $SeqTag = if ($null -ne $e.Seq) { " #$($e.Seq)" } else { "" }
            if ($Oneline) {
                Write-Host "  $($e.Id)$SeqTag  $When  $Delta  $($e.Message)" -ForegroundColor Cyan
            }
            else {
                Write-Host "  $($e.Id)$SeqTag  $When  ($($e.Files) files, $Delta)" -ForegroundColor Cyan
                if ($e.Message) { Write-Host "      $($e.Message)" -ForegroundColor White }
            }
        }
        Write-Host ""
    }
    "push" {
        if (-not $Remote) { Write-Host "  [FAIL] Usage: .\chains.ps1 push -Remote <dir>" -ForegroundColor Red; Exit 1 }
        $Paths = Get-VaultPaths -VaultRoot $VaultRoot
        Push-Chains -Paths $Paths -RemoteRoot $Remote | Out-Null
    }
    "fetch" {
        if (-not $Remote) { Write-Host "  [FAIL] Usage: .\chains.ps1 fetch -Remote <dir>" -ForegroundColor Red; Exit 1 }
        $Paths = Get-VaultPaths -VaultRoot $VaultRoot
        Fetch-Chains -Paths $Paths -RemoteRoot $Remote | Out-Null
    }
    "verify" {
        $Paths = Get-VaultPaths -VaultRoot $VaultRoot
        if (-not (Test-Path $Paths.Dir)) { Write-Host "  [FAIL] Not a Chains. Run 'init' first." -ForegroundColor Red; Exit 1 }
        if (Test-SaveChain -Paths $Paths) { Exit 0 } else { Exit 1 }
    }
    "patterns" {
        $Paths = Get-VaultPaths -VaultRoot $VaultRoot
        if (-not (Test-Path $Paths.Dir)) { Write-Host "  [FAIL] Not a Chains. Run 'init' first." -ForegroundColor Red; Exit 1 }
        if ($PSBoundParameters.ContainsKey("Reset")) {
            Set-TrackedPatterns -Paths $Paths -Reset | Out-Null
        }
        elseif ($PSBoundParameters.ContainsKey("SetInclude") -or $PSBoundParameters.ContainsKey("SetExclude")) {
            Set-TrackedPatterns -Paths $Paths `
                -Include (Split-PatternList $SetInclude) `
                -Exclude (Split-PatternList $SetExclude) -Replace | Out-Null
        }
        elseif ($PSBoundParameters.ContainsKey("Include") -or $PSBoundParameters.ContainsKey("Exclude")) {
            Set-TrackedPatterns -Paths $Paths `
                -Include (Split-PatternList $Include) `
                -Exclude (Split-PatternList $Exclude) | Out-Null
        }
        else {
            Show-TrackedPatterns -Paths $Paths
        }
    }
    "diff" {
        # diff takes two positional refs: .\chains.ps1 diff <a> <b>
        # $Path was consumed as vault root, so read raw args instead.
        $RawArgs = @($args)
        if ($RawArgs.Count -lt 2) { Write-Host "  [FAIL] Usage: .\chains.ps1 diff <commit-a> <commit-b>" -ForegroundColor Red; Exit 1 }
        $Paths = Get-VaultPaths -VaultRoot $VaultRoot
        Compare-SaveCommit -Paths $Paths -FromRef $RawArgs[0] -ToRef $RawArgs[1]
    }
    "restore" {
        $RawArgs = @($args)
        if ($RawArgs.Count -lt 1) { Write-Host "  [FAIL] Usage: .\chains.ps1 restore <commit>" -ForegroundColor Red; Exit 1 }
        if (-not $Force) {
            Write-Host "  [!] This overwrites current save files with commit $($RawArgs[0])." -ForegroundColor Yellow
            Write-Host "      A pre-restore backup commit is made first (skip with -NoBackup)." -ForegroundColor DarkGray
            $Confirm = Read-Host "      Continue? [y/N]"
            if ($Confirm -notmatch "^y(es)?$") { Write-Host "  [i] Aborted." -ForegroundColor DarkGray; Exit 0 }
        }
        $Paths = Get-VaultPaths -VaultRoot $VaultRoot
        Restore-SaveCommit -Paths $Paths -Ref $RawArgs[0] -NoBackup:$NoBackup | Out-Null
    }
    default {
        Show-Usage
    }
}
