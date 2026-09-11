# ==============================================================================
# Chains -- "git for files" engine
# ==============================================================================
# Version control for files, born as "git for save data": snapshot any set
# of files -- battery saves (SNES .srm, GBA .sav, N64 .sra/.eep/.fla, PSX
# memory cards .mcr, DeSmuME NDS .dsv, BizHawk .SaveRAM) and save states by
# default -- write a message about the moment, browse history, diff commits,
# and restore any point in time.
# Snapshots are content-addressed by SHA256 and recorded in an append-only
# JSON-lines journal -- a tiny git for the files that matter to you.
#
# Vault layout (<vault>/.chains/):
#   config.json        { version, created, watchPaths: [...],
#                        includePatterns: [...], excludePatterns: [...] }
#   journal.jsonl      one JSON object per commit (the history)
#   snapshots/<sha>    full file bytes, deduped by content hash
#
# By default only save data is tracked -- never ROMs or firmware. A vault
# can opt into arbitrary files with the `patterns` command, which stores
# per-vault include/exclude globs in config.json.
# ==============================================================================

$Script:SavePatterns = @("*.srm", "*.sav", "*.state*", "*.sgm", "*.zst", "*.savestate", "*.mcr", "*.ps2", "*.gci", "*.ppst", "*.dsv", "*.SaveRAM", "*.sra", "*.eep", "*.fla", "*.vmi", "*.vms")

# Exclude list used when a vault has no per-vault excludePatterns configured.
# Empty on purpose: a fresh vault behaves exactly like Chains v1 (only the
# include patterns decide). Noise/ROM guards belong in per-vault excludes.
$Script:DefaultExcludePatterns = @()

function Get-VaultPaths {
    param([Parameter(Mandatory = $true)][string]$VaultRoot)
    $sv = Join-Path $VaultRoot ".chains"
    return @{
        Root      = $VaultRoot
        Dir       = $sv
        Config    = Join-Path $sv "config.json"
        Journal   = Join-Path $sv "journal.jsonl"
        Snapshots = Join-Path $sv "snapshots"
    }
}

function Read-VaultConfig {
    param([hashtable]$Paths)
    if (-not (Test-Path $Paths.Config)) { return $null }
    return (Get-Content $Paths.Config -Raw | ConvertFrom-Json)
}

function Write-VaultConfig {
    param([hashtable]$Paths, [object]$Config)
    # Depth 6: config -> remotePins -> pin entry -> ids array -> id strings
    # (nested remote pins need the headroom; shallow configs are unaffected).
    ($Config | ConvertTo-Json -Depth 6) | Set-Content $Paths.Config -Force
}

function Initialize-Chains {
    param([Parameter(Mandatory = $true)][string]$Path)
    $Paths = Get-VaultPaths -VaultRoot $Path
    if (Test-Path $Paths.Dir) {
        Write-Host "  [i] Chains already initialized at: $($Paths.Dir)" -ForegroundColor DarkGray
        return $Paths
    }
    New-Item -ItemType Directory -Path $Paths.Snapshots -Force | Out-Null
    "" | Set-Content $Paths.Journal -Force -NoNewline
    Write-VaultConfig -Paths $Paths -Config ([pscustomobject]@{
            version    = 1
            created    = (Get-Date).ToUniversalTime().ToString("o")
            watchPaths = @()
        })
    Write-Host "  [OK] Chains initialized at: $($Paths.Dir)" -ForegroundColor Green
    return $Paths
}

function Get-KnownEmulatorSaveDir {
    <#
    .SYNOPSIS
        Well-known emulator save locations that exist on this machine.
        Emulators not listed (or with custom paths) can be added explicitly
        via Add-SaveWatchPath -- this list is a convenience, not a limit.
    #>
    $IsWinOS = ($PSVersionTable.OS -like "*Windows*") -or ($IsWindows -eq $true)
    $Candidates = @()
    if ($IsWinOS) {
        $AppData = $env:APPDATA
        $Candidates += @{ Emulator = "RetroArch"; Path = (Join-Path $AppData (Join-Path "RetroArch" "saves")) }
        $Candidates += @{ Emulator = "mGBA"; Path = (Join-Path $AppData "mGBA") }
        $Candidates += @{ Emulator = "Snes9x"; Path = (Join-Path $AppData "Snes9x") }
    }
    else {
        $HomeDir = if ($env:HOME) { $env:HOME } else { "~" }
        $Candidates += @{ Emulator = "RetroArch"; Path = (Join-Path $HomeDir (Join-Path ".config" (Join-Path "retroarch" "saves"))) }
        $Candidates += @{ Emulator = "mGBA"; Path = (Join-Path $HomeDir (Join-Path ".config" "mgba")) }
        $Candidates += @{ Emulator = "Snes9x"; Path = (Join-Path $HomeDir (Join-Path ".config" "snes9x")) }
    }
    return @($Candidates | Where-Object { Test-Path $_.Path })
}

function Add-SaveWatchPath {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Paths,
        [Parameter(Mandatory = $true)][string]$WatchPath
    )
    $Full = (Resolve-Path $WatchPath -ErrorAction SilentlyContinue)
    if (-not $Full) {
        Write-Host "  [FAIL] Directory does not exist: $WatchPath" -ForegroundColor Red
        return $false
    }
    $FullPath = $Full.Path
    $Config = Read-VaultConfig -Paths $Paths
    if (-not $Config) { Write-Host "  [FAIL] Not a Chains. Run 'init' first." -ForegroundColor Red; return $false }
    # Normalize: an empty JSON array can round-trip as $null.
    $WatchList = @($Config.watchPaths)
    if ($WatchList -contains $FullPath) {
        Write-Host "  [i] Already watched: $FullPath" -ForegroundColor DarkGray
        return $true
    }
    $WatchList += $FullPath
    $Config.watchPaths = $WatchList
    Write-VaultConfig -Paths $Paths -Config $Config
    Write-Host "  [OK] Watching: $FullPath" -ForegroundColor Green
    return $true
}

# ==============================================================================
# Tracked-file patterns -- the "git for files" expansion
# ==============================================================================
# A vault tracks whichever files its include patterns match (PowerShell
# wildcards against the file name: "*.md", "*.srm", "*"). Exclude patterns
# win over include patterns. Both lists live in config.json so every vault
# can track something different; a vault without them behaves exactly like
# Chains v1 (save-data defaults), which keeps old vaults working untouched.

function Get-TrackedPatterns {
    <#
    .SYNOPSIS
        The effective include/exclude pattern lists for this vault: the
        per-vault config.json overrides when present, the save-data defaults
        ($Script:SavePatterns / $Script:DefaultExcludePatterns) otherwise.
    #>
    param([Parameter(Mandatory = $true)][hashtable]$Paths)
    $Include = @($Script:SavePatterns)
    $Exclude = @($Script:DefaultExcludePatterns)
    $Config = Read-VaultConfig -Paths $Paths
    if ($Config) {
        if ($Config.PSObject.Properties.Name -contains "includePatterns") { $Include = @($Config.includePatterns) }
        if ($Config.PSObject.Properties.Name -contains "excludePatterns") { $Exclude = @($Config.excludePatterns) }
    }
    return @{ Include = $Include; Exclude = $Exclude }
}

function Split-PatternList {
    <#
    .SYNOPSIS
        Splits a user-supplied glob list ("*.md; *.txt, *.ps1") into an array.
        Empty input yields an empty array (which means "match nothing" for
        include, "exclude nothing" for exclude).
    #>
    param([string]$List)
    if ([string]::IsNullOrWhiteSpace($List)) { return @() }
    return @($List -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
}

function Test-PatternListMatch {
    <#
    .SYNOPSIS
        True when $Name matches any glob in $Patterns. Case-insensitive on
        Windows, case-sensitive on Linux -- the same rule the filesystem
        itself uses (and the same rule Get-ChildItem -Filter follows).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [string[]]$Patterns = @()
    )
    $IsWinOS = ($PSVersionTable.OS -like "*Windows*") -or ($IsWindows -eq $true)
    foreach ($p in $Patterns) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        if ($IsWinOS) { if ($Name -like $p) { return $true } }
        else { if ($Name -clike $p) { return $true } }
    }
    return $false
}

function Show-TrackedPatterns {
    <#
    .SYNOPSIS
        Prints the vault's effective include/exclude pattern lists.
    #>
    param([Parameter(Mandatory = $true)][hashtable]$Paths)
    $Tracked = Get-TrackedPatterns -Paths $Paths
    $Inc = if ($Tracked.Include.Count -gt 0) { $Tracked.Include -join ", " } else { "(none -- nothing is tracked)" }
    $Exc = if ($Tracked.Exclude.Count -gt 0) { $Tracked.Exclude -join ", " } else { "(none)" }
    Write-Host "  include: $Inc" -ForegroundColor White
    Write-Host "  exclude: $Exc" -ForegroundColor DarkGray
}

function Set-TrackedPatterns {
    <#
    .SYNOPSIS
        Updates the vault's include/exclude pattern lists in config.json.
        -Include/-Exclude append globs; -Replace swaps the whole list;
        -Reset drops the overrides and restores the save-data defaults.
        Journal history is untouched -- this only changes what future scans
        pick up, like editing .gitignore.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Paths,
        [string[]]$Include = @(),
        [string[]]$Exclude = @(),
        [switch]$Replace,
        [switch]$Reset
    )
    $Config = Read-VaultConfig -Paths $Paths
    if (-not $Config) { Write-Host "  [FAIL] Not a Chains. Run 'init' first." -ForegroundColor Red; return $false }
    if ($Reset) {
        foreach ($Prop in @("includePatterns", "excludePatterns")) {
            if ($Config.PSObject.Properties.Name -contains $Prop) { $Config.PSObject.Properties.Remove($Prop) }
        }
        Write-Host "  [OK] Patterns reset to the save-data defaults." -ForegroundColor Green
    }
    else {
        if (-not $Replace -and $Include.Count -eq 0 -and $Exclude.Count -eq 0) {
            Write-Host "  [FAIL] Nothing to set: pass -Include and/or -Exclude globs." -ForegroundColor Red
            return $false
        }
        $Cur = Get-TrackedPatterns -Paths $Paths
        if ($Include.Count -gt 0) {
            $New = if ($Replace) { @($Include) } else { @($Cur.Include) + @($Include) }
            $Config | Add-Member -NotePropertyName "includePatterns" -NotePropertyValue @($New | Select-Object -Unique) -Force
        }
        if ($Exclude.Count -gt 0) {
            $New = if ($Replace) { @($Exclude) } else { @($Cur.Exclude) + @($Exclude) }
            $Config | Add-Member -NotePropertyName "excludePatterns" -NotePropertyValue @($New | Select-Object -Unique) -Force
        }
        Write-Host "  [OK] Patterns updated." -ForegroundColor Green
    }
    Write-VaultConfig -Paths $Paths -Config $Config
    Show-TrackedPatterns -Paths $Paths
    return $true
}

function Get-SaveWorkingTree {
    <#
    .SYNOPSIS
        Scans all watched paths for tracked files. Returns objects with:
        Key (watch-relative identity), FullPath, Sha256, Bytes.
        "Tracked" is decided by the vault's include/exclude patterns
        (Get-TrackedPatterns) -- by default the save-data globs, so an
        unconfigured vault behaves exactly like Chains v1. The .chains
        vault directory itself is never scanned, even when the vault root
        is a watched path. Files matching several include patterns are
        reported once.
    #>
    param([Parameter(Mandatory = $true)][hashtable]$Paths)
    $Config = Read-VaultConfig -Paths $Paths
    if (-not $Config) { return @() }
    $Tracked = Get-TrackedPatterns -Paths $Paths
    $Files = @()
    $Seen = @{}
    # The scan loop iterates $Script:SavePatterns in exactly this form --
    # pinned by tests/test-save-patterns.sh and by the doctor's pattern
    # extraction -- so the vault's effective include list is swapped in for
    # the duration of the scan and restored afterwards.
    $PatternBackup = $Script:SavePatterns
    $Script:SavePatterns = @($Tracked.Include)
    try {
        foreach ($Watch in $Config.watchPaths) {
            if (-not (Test-Path $Watch)) { continue }
            foreach ($Pattern in $Script:SavePatterns) {
                foreach ($f in (Get-ChildItem -Path $Watch -Filter $Pattern -File -Recurse -ErrorAction SilentlyContinue)) {
                    if ($Seen.ContainsKey($f.FullName)) { continue }
                    $Seen[$f.FullName] = $true
                    # Never ingest the vault itself (config, journal, blobs).
                    if (($f.FullName -split '[\\/]') -contains '.chains') { continue }
                    # Exclude patterns win over include patterns.
                    if (Test-PatternListMatch -Name $f.Name -Patterns $Tracked.Exclude) { continue }
                    $Rel = $f.FullName.Substring($Watch.Length).TrimStart([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
                    $Hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLower()
                    $Files += [pscustomobject]@{
                        Key      = "$Watch::$Rel"
                        FullPath = $f.FullName
                        Rel      = $Rel
                        Sha256   = $Hash
                        Bytes    = $f.Length
                    }
                }
            }
        }
    }
    finally {
        $Script:SavePatterns = $PatternBackup
    }
    return $Files
}

function Get-SaveJournal {
    param([Parameter(Mandatory = $true)][hashtable]$Paths)
    if (-not (Test-Path $Paths.Journal)) { return @() }
    $Entries = @()
    foreach ($Line in (Get-Content $Paths.Journal -ErrorAction SilentlyContinue)) {
        if ([string]::IsNullOrWhiteSpace($Line)) { continue }
        $Entries += ($Line | ConvertFrom-Json)
    }
    return $Entries
}

function Find-SaveCommit {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Paths,
        [Parameter(Mandatory = $true)][string]$Ref
    )
    $Journal = Get-SaveJournal -Paths $Paths
    if ($Journal.Count -eq 0) { return $null }
    if ($Ref -eq "HEAD") { return $Journal[-1] }
    $Matched = @($Journal | Where-Object { $_.id -eq $Ref -or $_.id.StartsWith($Ref) })
    if ($Matched.Count -eq 1) { return $Matched[0] }
    return $null  # none, or ambiguous prefix
}

function New-SaveCommitId {
    <#
    .SYNOPSIS
        Derives a 12-hex-char commit id from the parent commit id, timestamp,
        message, and file list. Including the parent id chains every commit
        to its predecessor: same-tick commits can never collide, a
        restore-then-recommit always yields a fresh id, and the journal is
        tamper-evident end to end.
    #>
    param(
        [string]$ParentId = "",
        [Parameter(Mandatory = $true)][string]$Timestamp,
        [string]$Message = "",
        [array]$FileList = @()
    )
    $TreePart = (($FileList | ForEach-Object { "$($_.key)=$($_.sha256)" } | Sort-Object) -join ",")
    $Seed = "$ParentId|$Timestamp|$Message|$TreePart"
    return ((Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($Seed))) -Algorithm SHA256).Hash.ToLower()).Substring(0, 12)
}

function New-SaveCommit {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Paths,
        [string]$Message = ""
    )
    $Config = Read-VaultConfig -Paths $Paths
    if (-not $Config) { Write-Host "  [FAIL] Not a Chains. Run 'init' first." -ForegroundColor Red; return $null }
    if (@($Config.watchPaths).Count -eq 0) {
        Write-Host "  [FAIL] No watched paths. Run 'watch' first." -ForegroundColor Red
        return $null
    }

    $Tree = Get-SaveWorkingTree -Paths $Paths
    $Journal = Get-SaveJournal -Paths $Paths
    $Head = if ($Journal.Count -gt 0) { $Journal[-1] } else { $null }

    # Build the file list for this commit; store any blobs we haven't seen.
    $FileList = @()
    $NewBlobs = 0
    foreach ($f in $Tree) {
        $BlobPath = Join-Path $Paths.Snapshots $f.Sha256
        if (-not (Test-Path $BlobPath)) {
            Copy-Item $f.FullPath $BlobPath -Force
            $NewBlobs++
        }
        $FileList += [pscustomobject]@{ key = $f.Key; rel = $f.Rel; sha256 = $f.Sha256; bytes = $f.Bytes }
    }

    # Nothing-to-commit check: same key->hash mapping as HEAD.
    if ($Head) {
        $HeadMap = @{}
        foreach ($hf in $Head.files) { $HeadMap[$hf.key] = $hf.sha256 }
        $Same = ($Tree.Count -eq $Head.files.Count)
        if ($Same) {
            foreach ($f in $Tree) {
                if ($HeadMap[$f.Key] -ne $f.Sha256) { $Same = $false; break }
            }
        }
        if ($Same) {
            Write-Host "  [i] Nothing to commit -- working tree matches $($Head.id)." -ForegroundColor DarkGray
            return $Head
        }
    }

    $Ts = (Get-Date).ToUniversalTime().ToString("o")
    $ParentId = if ($Head) { $Head.id } else { "" }
    $Id = New-SaveCommitId -ParentId $ParentId -Timestamp $Ts -Message $Message -FileList $FileList

    # Revision counter: the per-commit sequence number. This is what makes
    # the history a *chain* you can point at ("revision 14") instead of a
    # pile of timestamps. Journals written before this field existed keep
    # working -- readers treat a missing seq as unknown, and verify/merge
    # never depend on it (ids stay the sole integrity anchor).
    $MaxSeq = 0
    $HasSeq = $false
    foreach ($e in $Journal) {
        if ($e.PSObject.Properties.Name -contains "seq") {
            $HasSeq = $true
            if ($e.seq -gt $MaxSeq) { $MaxSeq = $e.seq }
        }
    }
    $Seq = if ($HasSeq) { $MaxSeq + 1 } else { $Journal.Count + 1 }

    # Snapshot of the patterns in effect: the audit trail for "what was
    # tracked when", like the custody chain recording its own scope.
    $Tracked = Get-TrackedPatterns -Paths $Paths

    $Entry = [pscustomobject]@{
        id       = $Id
        parent   = $ParentId
        seq      = $Seq
        ts       = $Ts
        message  = $Message
        patterns = [pscustomobject]@{ include = @($Tracked.Include); exclude = @($Tracked.Exclude) }
        files    = $FileList
    }
    ($Entry | ConvertTo-Json -Depth 5 -Compress) | Add-Content $Paths.Journal

    Write-Host "  [OK] Committed $Id (#$Seq) -- $($Tree.Count) file(s), $NewBlobs new blob(s)." -ForegroundColor Green
    if ($Message) { Write-Host "       ""$Message""" -ForegroundColor DarkGray }
    return $Entry
}

function Get-SaveStatus {
    param([Parameter(Mandatory = $true)][hashtable]$Paths)
    $Journal = Get-SaveJournal -Paths $Paths
    if ($Journal.Count -eq 0) {
        Write-Host "  [i] No commits yet." -ForegroundColor DarkGray
        return
    }
    $Head = $Journal[-1]
    $HeadMap = @{}
    foreach ($hf in $Head.files) { $HeadMap[$hf.key] = $hf }
    $Tree = Get-SaveWorkingTree -Paths $Paths
    $TreeMap = @{}
    foreach ($f in $Tree) { $TreeMap[$f.Key] = $f }

    $Changed = @()
    foreach ($Key in $TreeMap.Keys) {
        if (-not $HeadMap.ContainsKey($Key)) { $Changed += "  + added:    $($TreeMap[$Key].Rel)"; continue }
        if ($HeadMap[$Key].sha256 -ne $TreeMap[$Key].Sha256) { $Changed += "  ~ modified: $($TreeMap[$Key].Rel)" }
    }
    foreach ($Key in $HeadMap.Keys) {
        if (-not $TreeMap.ContainsKey($Key)) { $Changed += "  - deleted:  $($HeadMap[$Key].rel)" }
    }
    if ($Changed.Count -eq 0) {
        Write-Host "  [OK] Clean -- working tree matches $($Head.id)." -ForegroundColor Green
    }
    else {
        Write-Host "  [~] Changes vs $($Head.id):" -ForegroundColor Yellow
        $Changed | ForEach-Object { Write-Host $_ -ForegroundColor White }
    }
}

function Compare-SaveCommit {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Paths,
        [Parameter(Mandatory = $true)][string]$FromRef,
        [Parameter(Mandatory = $true)][string]$ToRef
    )
    $From = Find-SaveCommit -Paths $Paths -Ref $FromRef
    $To = Find-SaveCommit -Paths $Paths -Ref $ToRef
    if (-not $From) { Write-Host "  [FAIL] Unknown commit: $FromRef" -ForegroundColor Red; return }
    if (-not $To) { Write-Host "  [FAIL] Unknown commit: $ToRef" -ForegroundColor Red; return }

    $FromMap = @{}; foreach ($f in $From.files) { $FromMap[$f.key] = $f }
    $ToMap = @{}; foreach ($f in $To.files) { $ToMap[$f.key] = $f }

    Write-Host ""
    Write-Host "  diff $($From.id) -> $($To.id)" -ForegroundColor Cyan
    $Any = $false
    foreach ($Key in $ToMap.Keys) {
        if (-not $FromMap.ContainsKey($Key)) {
            Write-Host "  + $($ToMap[$Key].rel) (new, $($ToMap[$Key].bytes) bytes)" -ForegroundColor Green
            $Any = $true
        }
        elseif ($FromMap[$Key].sha256 -ne $ToMap[$Key].sha256) {
            $Delta = $ToMap[$Key].bytes - $FromMap[$Key].bytes
            $DeltaStr = if ($Delta -ge 0) { "+$Delta" } else { "$Delta" }
            $ByteDiff = Get-BlobByteDiff -Paths $Paths -ShaA $FromMap[$Key].sha256 -ShaB $ToMap[$Key].sha256
            Write-Host "  ~ $($ToMap[$Key].rel) (size $DeltaStr bytes$ByteDiff)" -ForegroundColor Yellow
            $Any = $true
        }
    }
    foreach ($Key in $FromMap.Keys) {
        if (-not $ToMap.ContainsKey($Key)) {
            Write-Host "  - $($FromMap[$Key].rel) (deleted)" -ForegroundColor Red
            $Any = $true
        }
    }
    if (-not $Any) { Write-Host "  (identical)" -ForegroundColor DarkGray }
    Write-Host ""
}

function Get-BlobByteDiff {
    param([hashtable]$Paths, [string]$ShaA, [string]$ShaB)
    # Byte-level diff summary for small binary saves; skipped for large files.
    $MaxBytes = 4MB
    $A = Join-Path $Paths.Snapshots $ShaA
    $B = Join-Path $Paths.Snapshots $ShaB
    if (-not (Test-Path $A) -or -not (Test-Path $B)) { return "" }
    if ((Get-Item $A).Length -gt $MaxBytes -or (Get-Item $B).Length -gt $MaxBytes) { return ", diff skipped (>4MB)" }
    $BytesA = [IO.File]::ReadAllBytes($A)
    $BytesB = [IO.File]::ReadAllBytes($B)
    $Len = [Math]::Max($BytesA.Length, $BytesB.Length)
    $Diff = 0
    for ($i = 0; $i -lt $Len; $i++) {
        $ba = if ($i -lt $BytesA.Length) { $BytesA[$i] } else { -1 }
        $bb = if ($i -lt $BytesB.Length) { $BytesB[$i] } else { -1 }
        if ($ba -ne $bb) { $Diff++ }
    }
    return ", $Diff of $Len bytes differ"
}

function Restore-SaveCommit {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Paths,
        [Parameter(Mandatory = $true)][string]$Ref,
        [switch]$NoBackup
    )
    $Commit = Find-SaveCommit -Paths $Paths -Ref $Ref
    if (-not $Commit) { Write-Host "  [FAIL] Unknown commit: $Ref" -ForegroundColor Red; return $false }

    if (-not $NoBackup) {
        Write-Host "  [i] Auto-committing current state as pre-restore backup..." -ForegroundColor DarkGray
        New-SaveCommit -Paths $Paths -Message "pre-restore auto-backup" | Out-Null
    }

    $Restored = 0
    foreach ($f in $Commit.files) {
        $Blob = Join-Path $Paths.Snapshots $f.sha256
        if (-not (Test-Path $Blob)) {
            Write-Host "  [FAIL] Missing blob for $($f.rel) -- vault is corrupt." -ForegroundColor Red
            continue
        }
        # Key format is "<watchdir>::<relative>"; recover the watch dir.
        $WatchDir = $f.key.Substring(0, $f.key.IndexOf("::"))
        $Dest = Join-Path $WatchDir $f.rel
        $DestDir = Split-Path $Dest -Parent
        if (-not (Test-Path $DestDir)) { New-Item -ItemType Directory -Path $DestDir -Force | Out-Null }
        Copy-Item $Blob $Dest -Force
        $Restored++
    }
    Write-Host "  [OK] Restored $Restored file(s) from commit $($Commit.id)." -ForegroundColor Green
    return $true
}

function Test-SaveChain {
    <#
    .SYNOPSIS
        Verifies the vault end to end. For every journal entry it checks the
        parent link, then re-derives the commit id from parent id, timestamp,
        message, and file list -- any edit to the journal breaks the chain.
        It also re-hashes every stored blob and compares it to the recorded
        SHA256, so silent corruption of snapshots is caught too. Returns
        $true only when the whole vault is intact.
    #>
    param([Parameter(Mandatory = $true)][hashtable]$Paths)
    $Journal = Get-SaveJournal -Paths $Paths
    if ($Journal.Count -eq 0) {
        Write-Host "  [i] No commits to verify." -ForegroundColor DarkGray
        return $true
    }
    $PrevId = ""
    $Legacy = 0
    foreach ($c in $Journal) {
        if ($c.PSObject.Properties.Name -contains "parent") {
            if ($c.parent -ne $PrevId) {
                Write-Host "  [FAIL] Commit $($c.id) has a broken parent link (expected '$PrevId')." -ForegroundColor Red
                return $false
            }
            $Recomputed = New-SaveCommitId -ParentId $PrevId -Timestamp $c.ts -Message $c.message -FileList @($c.files)
            if ($Recomputed -ne $c.id) {
                Write-Host "  [FAIL] Commit $($c.id) fails the integrity check -- journal entry was modified." -ForegroundColor Red
                return $false
            }
        }
        else {
            # Commits written before parent-chaining existed can't be
            # re-derived; their blobs can still be integrity-checked.
            $Legacy++
        }
        foreach ($f in @($c.files)) {
            $Blob = Join-Path $Paths.Snapshots $f.sha256
            if (-not (Test-Path $Blob)) {
                Write-Host "  [FAIL] Missing blob for $($f.rel) ($($f.sha256))." -ForegroundColor Red
                return $false
            }
            $Actual = (Get-FileHash -Path $Blob -Algorithm SHA256).Hash.ToLower()
            if ($Actual -ne $f.sha256) {
                Write-Host "  [FAIL] Blob for $($f.rel) no longer matches its recorded hash." -ForegroundColor Red
                return $false
            }
        }
        $PrevId = $c.id
    }
    $Note = if ($Legacy -gt 0) { " ($Legacy legacy pre-chain commit(s) checked by blob only)" } else { "" }
    Write-Host "  [OK] Chain intact: $($Journal.Count) commit(s), all blobs verified.$Note" -ForegroundColor Green
    return $true
}

# ==============================================================================
# Sync -- push/fetch chains through a remote store
# ==============================================================================
# The sync contract is documented in SYNC.md. The engine implements the
# LOCAL FILESYSTEM backend only: a directory on disk (USB stick, Castle LAN
# share, mounted cloud drive). No network code lives here -- default-deny:
# the engine never phones home, never touches a third-party host.
#
# Remote layout (<remote>/vaults/<vault-id>/):
#   journal.jsonl      union of all known commits for the vault
#   blobs/<sha256>     content-addressed blobs, deduped by hash
# ==============================================================================

function Get-ChainsVaultId {
    <#
    .SYNOPSIS
        Stable identity for this vault inside the sync namespace. A GUID
        minted at init, backfilled for vaults created before sync existed.
    #>
    param([Parameter(Mandatory = $true)][hashtable]$Paths)
    $Config = Read-VaultConfig -Paths $Paths
    if (-not $Config) { return $null }
    if (-not $Config.id) {
        $Config | Add-Member -NotePropertyName "id" -NotePropertyValue ([Guid]::NewGuid().ToString("N"))
        Write-VaultConfig -Paths $Paths -Config $Config
    }
    return $Config.id
}

function Resolve-SyncVaultId {
    <#
    .SYNOPSIS
        Which remote vault id to talk to. An explicit -VaultId wins and is
        remembered in the config (so the next bare `fetch` just works);
        otherwise the last-remembered id, else this vault's own id.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Paths,
        [string]$VaultId = ""
    )
    $Config = Read-VaultConfig -Paths $Paths
    if (-not $Config) { return $null }
    if ($VaultId) {
        $Config | Add-Member -NotePropertyName "syncVaultId" -NotePropertyValue $VaultId -Force
        Write-VaultConfig -Paths $Paths -Config $Config
        return $VaultId
    }
    if ($Config.syncVaultId) { return $Config.syncVaultId }
    return (Get-ChainsVaultId -Paths $Paths)
}

function Read-JournalFile {
    param([Parameter(Mandatory = $true)][string]$JournalPath)
    $Entries = @()
    foreach ($Line in (Get-Content $JournalPath -ErrorAction SilentlyContinue)) {
        if ([string]::IsNullOrWhiteSpace($Line)) { continue }
        $Entries += ($Line | ConvertFrom-Json)
    }
    return $Entries
}

function Merge-JournalFile {
    <#
    .SYNOPSIS
        Unions $Entries into the journal at $JournalPath, keyed by commit id.
        Existing order is preserved; new entries are appended in timestamp
        order (so verify's parent-before-child walk stays valid). The same id
        with different bytes is corruption, not a conflict -- ids are
        content-derived, so this is impossible without tampering. Returns the
        number of entries added, or $null on corruption.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$JournalPath,
        [array]$Entries = @()
    )
    $Known = @{}
    foreach ($e in (Read-JournalFile -JournalPath $JournalPath)) { $Known[$e.id] = $e }
    $NewOnes = @()
    foreach ($e in $Entries) {
        if ($Known.ContainsKey($e.id)) {
            $LocalJson = ($Known[$e.id] | ConvertTo-Json -Depth 5 -Compress)
            $RemoteJson = ($e | ConvertTo-Json -Depth 5 -Compress)
            if ($LocalJson -ne $RemoteJson) {
                Write-Host "  [FAIL] Commit $($e.id) collides with different content -- possible tampering. Sync aborted." -ForegroundColor Red
                return $null
            }
            continue
        }
        $Known[$e.id] = $e
        $NewOnes += $e
    }
    foreach ($e in ($NewOnes | Sort-Object { $_.ts }, { $_.id })) {
        ($_ | ConvertTo-Json -Depth 5 -Compress) | Add-Content $JournalPath
    }
    return $NewOnes.Count
}

function Get-SyncRemoteVaultPaths {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteRoot,
        [Parameter(Mandatory = $true)][string]$VaultId
    )
    $VaultDir = Join-Path (Join-Path $RemoteRoot "vaults") $VaultId
    return @{
        VaultDir = $VaultDir
        Journal  = Join-Path $VaultDir "journal.jsonl"
        Blobs    = Join-Path $VaultDir "blobs"
    }
}

# ==============================================================================
# Remote fingerprint pinning -- TOFU rollback/replay protection for sync
# ==============================================================================
# Blobs are hash-checked and same-id-different-bytes journal collisions abort
# the merge, but neither stops a *rollback*: a remote whose journal was
# replaced with an older copy (or swapped for a different vault's journal)
# would still "merge" cleanly and silently resurrect deleted history. The pin
# closes that hole: after every successful push/fetch, the vault records the
# set of commit ids it has seen on that remote root. The next sync requires
# every pinned id to still be present. Trust-on-first-use, like SSH host keys.

function Get-JournalFingerprint {
    <#
    .SYNOPSIS
        Compact content fingerprint of a journal: SHA256 over the sorted,
        deduplicated commit-id list. Order-independent, so two machines that
        merged the same entry set in different timestamp orders agree.
    #>
    param([array]$Entries = @())
    $Ids = @($Entries | ForEach-Object { $_.id } | Sort-Object -Unique)
    $Bytes = [Text.Encoding]::UTF8.GetBytes(($Ids -join "`n"))
    $Hash = [Security.Cryptography.SHA256]::Create().ComputeHash($Bytes)
    return ([BitConverter]::ToString($Hash)).Replace("-", "").ToLower()
}

function Get-PinKey {
    <#
    .SYNOPSIS
        Pin namespace: a remote root can host many vault ids, and one vault
        can sync with many remote roots, so the pin is keyed by both.
        ("|" is illegal in Windows paths, so it is a safe separator.)
    #>
    param(
        [Parameter(Mandatory = $true)][string]$RemoteRoot,
        [Parameter(Mandatory = $true)][string]$VaultId
    )
    return "$RemoteRoot|$VaultId"
}

function Get-RemotePins {
    <#
    .SYNOPSIS
        The pinned remote fingerprints from this vault's config, as a
        hashtable keyed by pin key (remote root + vault id). Empty when
        nothing is pinned yet.
    #>
    param([Parameter(Mandatory = $true)][hashtable]$Paths)
    $Config = Read-VaultConfig -Paths $Paths
    if (-not $Config -or -not $Config.remotePins) { return @{} }
    $Pins = @{}
    foreach ($p in $Config.remotePins.PSObject.Properties) { $Pins[$p.Name] = $p.Value }
    return $Pins
}

function Set-RemotePin {
    <#
    .SYNOPSIS
        Records (or refreshes) the fingerprint pin for a remote root + vault
        id after a successful push/fetch. Call only on the success path -- a
        failed sync must never move the pin.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Paths,
        [Parameter(Mandatory = $true)][string]$RemoteRoot,
        [Parameter(Mandatory = $true)][string]$VaultId,
        [array]$Entries = @()
    )
    $Config = Read-VaultConfig -Paths $Paths
    if (-not $Config) { return }
    $Pins = Get-RemotePins -Paths $Paths
    $Pins[(Get-PinKey -RemoteRoot $RemoteRoot -VaultId $VaultId)] = @{
        fingerprint = (Get-JournalFingerprint -Entries $Entries)
        ids         = @($Entries | ForEach-Object { $_.id } | Sort-Object -Unique)
        when        = (Get-Date).ToUniversalTime().ToString("o")
    }
    $Config | Add-Member -NotePropertyName "remotePins" -NotePropertyValue $Pins -Force
    Write-VaultConfig -Paths $Paths -Config $Config
}

function Test-RemotePin {
    <#
    .SYNOPSIS
        Verifies the remote journal still contains every commit id this vault
        has previously seen on this remote root + vault id. Missing ids mean
        the remote was rolled back, truncated, or swapped for a different
        vault -- the sync aborts before any local state changes. New ids
        appended after the pin are normal and allowed. First contact has no
        pin yet and is trusted (TOFU), then pinned on success.
        Returns $true when the remote is acceptable, $false on violation.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Paths,
        [Parameter(Mandatory = $true)][string]$RemoteRoot,
        [Parameter(Mandatory = $true)][string]$VaultId,
        [array]$RemoteEntries = @()
    )
    $Pins = Get-RemotePins -Paths $Paths
    $Key = Get-PinKey -RemoteRoot $RemoteRoot -VaultId $VaultId
    if (-not $Pins.ContainsKey($Key)) { return $true }
    $RemoteIds = @{}
    foreach ($e in $RemoteEntries) { $RemoteIds[$e.id] = $true }
    foreach ($id in @($Pins[$Key].ids)) {
        if (-not $RemoteIds.ContainsKey($id)) {
            Write-Host "  [FAIL] Remote journal is missing commit $id pinned on a previous sync -- possible rollback or replay. Sync aborted; local vault untouched." -ForegroundColor Red
            return $false
        }
    }
    return $true
}

function Push-Chains {
    <#
    .SYNOPSIS
        Uploads this vault's journal + blobs to a local filesystem remote.
        Idempotent: re-pushing transfers only what's missing. Returns a
        summary object, or $null on failure.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Paths,
        [Parameter(Mandatory = $true)][string]$RemoteRoot,
        [string]$VaultId = ""
    )
    if (-not (Test-Path $Paths.Dir)) { Write-Host "  [FAIL] Not a Chains. Run 'init' first." -ForegroundColor Red; return $null }
    $Id = Resolve-SyncVaultId -Paths $Paths -VaultId $VaultId
    if (-not $Id) { Write-Host "  [FAIL] Not a Chains. Run 'init' first." -ForegroundColor Red; return $null }
    $R = Get-SyncRemoteVaultPaths -RemoteRoot $RemoteRoot -VaultId $Id
    New-Item -ItemType Directory -Path $R.Blobs -Force | Out-Null
    if (-not (Test-Path $R.Journal)) { "" | Set-Content $R.Journal -Force -NoNewline }

    $LocalEntries = @(Get-SaveJournal -Paths $Paths)
    $RemoteEntries = @(Read-JournalFile -JournalPath $R.Journal)
    if (-not (Test-RemotePin -Paths $Paths -RemoteRoot $RemoteRoot -VaultId $Id -RemoteEntries $RemoteEntries)) { return $null }
    $Added = Merge-JournalFile -JournalPath $R.Journal -Entries $LocalEntries
    if ($null -eq $Added) { return $null }
    # Pin the remote as we just left it (now including our entries).
    Set-RemotePin -Paths $Paths -RemoteRoot $RemoteRoot -VaultId $Id -Entries @(Read-JournalFile -JournalPath $R.Journal)

    # Upload blobs the remote is missing. Blob names are content hashes, so
    # a name collision is an integrity violation, never a silent overwrite.
    $Pushed = 0
    foreach ($c in $LocalEntries) {
        foreach ($f in @($c.files)) {
            $Dest = Join-Path $R.Blobs $f.sha256
            if (-not (Test-Path $Dest)) {
                $Src = Join-Path $Paths.Snapshots $f.sha256
                if (-not (Test-Path $Src)) {
                    Write-Host "  [FAIL] Local blob missing for $($f.rel) -- run 'verify'." -ForegroundColor Red
                    return $null
                }
                Copy-Item $Src $Dest -Force
                $Pushed++
            }
        }
    }
    Write-Host "  [OK] Pushed to ${RemoteRoot}: $($LocalEntries.Count) commit(s), $Pushed new blob(s)." -ForegroundColor Green
    return [pscustomobject]@{ VaultId = $Id; EntriesAdded = $Added; BlobsPushed = $Pushed }
}

function Fetch-Chains {
    <#
    .SYNOPSIS
        Downloads the remote journal + missing blobs into this vault. Blobs
        are staged to a temp dir and SHA256-checked against the journal
        BEFORE the local journal is extended, so a tampered remote can never
        leave the vault pointing at bad bytes. Merge is id-keyed, so both
        histories survive. Returns a summary object, or $null on failure.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Paths,
        [Parameter(Mandatory = $true)][string]$RemoteRoot,
        [string]$VaultId = ""
    )
    if (-not (Test-Path $Paths.Dir)) { Write-Host "  [FAIL] Not a Chains. Run 'init' first." -ForegroundColor Red; return $null }
    $Id = Resolve-SyncVaultId -Paths $Paths -VaultId $VaultId
    if (-not $Id) { Write-Host "  [FAIL] Not a Chains. Run 'init' first." -ForegroundColor Red; return $null }
    $R = Get-SyncRemoteVaultPaths -RemoteRoot $RemoteRoot -VaultId $Id
    if (-not (Test-Path $R.Journal)) {
        Write-Host "  [i] Remote has no data for this vault yet -- push first." -ForegroundColor DarkGray
        return [pscustomobject]@{ VaultId = $Id; EntriesAdded = 0; BlobsFetched = 0 }
    }
    $RemoteEntries = @(Read-JournalFile -JournalPath $R.Journal)
    if (-not (Test-RemotePin -Paths $Paths -RemoteRoot $RemoteRoot -VaultId $Id -RemoteEntries $RemoteEntries)) { return $null }

    # Stage + hash-check every blob we don't have yet, before touching the journal.
    $KnownIds = @{}
    foreach ($e in (Get-SaveJournal -Paths $Paths)) { $KnownIds[$e.id] = $true }
    $Stage = Join-Path ([IO.Path]::GetTempPath()) ("chains-stage-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $Stage -Force | Out-Null
    $Staged = 0
    try {
        foreach ($c in $RemoteEntries) {
            if ($KnownIds.ContainsKey($c.id)) { continue }
            foreach ($f in @($c.files)) {
                $Local = Join-Path $Paths.Snapshots $f.sha256
                if (Test-Path $Local) { continue }
                $Src = Join-Path $R.Blobs $f.sha256
                if (-not (Test-Path $Src)) {
                    Write-Host "  [FAIL] Remote blob missing for $($f.rel) -- remote is corrupt." -ForegroundColor Red
                    return $null
                }
                $Tmp = Join-Path $Stage $f.sha256
                Copy-Item $Src $Tmp -Force
                $Actual = (Get-FileHash -Path $Tmp -Algorithm SHA256).Hash.ToLower()
                if ($Actual -ne $f.sha256) {
                    Write-Host "  [FAIL] Remote blob for $($f.rel) failed its hash check -- remote tampered." -ForegroundColor Red
                    return $null
                }
                $Staged++
            }
        }
    }
    finally {
        # Move verified blobs into the snapshot store, then drop the stage.
        if ($Staged -gt 0) {
            foreach ($b in (Get-ChildItem -Path $Stage -File -ErrorAction SilentlyContinue)) {
                Move-Item $b.FullName (Join-Path $Paths.Snapshots $b.Name) -Force
            }
        }
        Remove-Item -Recurse -Force $Stage -ErrorAction SilentlyContinue
    }

    $Added = Merge-JournalFile -JournalPath $Paths.Journal -Entries $RemoteEntries
    if ($null -eq $Added) { return $null }
    # Pin only on the success path -- a failed fetch must never move the pin.
    Set-RemotePin -Paths $Paths -RemoteRoot $RemoteRoot -VaultId $Id -Entries $RemoteEntries
    Write-Host "  [OK] Fetched from ${RemoteRoot}: $Added new commit(s), $Staged new blob(s)." -ForegroundColor Green
    return [pscustomobject]@{ VaultId = $Id; EntriesAdded = $Added; BlobsFetched = $Staged }
}

# ==============================================================================
# Log -- structured history for `chains log`
# ==============================================================================

function Get-SaveLog {
    <#
    .SYNOPSIS
        History newest-first as structured entries. Each entry carries the
        commit id, timestamp, message, file count, and a per-commit delta
        (added/modified/deleted) computed against its parent commit, so the
        log reads like a changelog instead of a bare id list.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Paths,
        [int]$Count = 0
    )
    $Journal = @(Get-SaveJournal -Paths $Paths)
    if ($Journal.Count -eq 0) { return @() }
    $ById = @{}
    foreach ($c in $Journal) { $ById[$c.id] = $c }
    $Ordered = @($Journal | Sort-Object { $_.ts } -Descending)
    if ($Count -gt 0) { $Ordered = @($Ordered | Select-Object -First $Count) }
    $Result = @()
    foreach ($c in $Ordered) {
        $Parent = $null
        if ($c.parent -and $ById.ContainsKey($c.parent)) { $Parent = $ById[$c.parent] }
        $ParentMap = @{}
        if ($Parent) { foreach ($f in @($Parent.files)) { $ParentMap[$f.key] = $f.sha256 } }
        $Added = 0; $Modified = 0; $Deleted = 0
        $CurKeys = @{}
        foreach ($f in @($c.files)) {
            $CurKeys[$f.key] = $true
            if (-not $ParentMap.ContainsKey($f.key)) { $Added++ }
            elseif ($ParentMap[$f.key] -ne $f.sha256) { $Modified++ }
        }
        if ($Parent) {
            foreach ($k in $ParentMap.Keys) { if (-not $CurKeys.ContainsKey($k)) { $Deleted++ } }
        }
        else {
            # Root commit (or legacy commit without a parent link): everything is new.
            $Added = @($c.files).Count
        }
        $Result += [pscustomobject]@{
            Id       = $c.id
            Seq      = $(if ($c.PSObject.Properties.Name -contains "seq") { $c.seq } else { $null })
            When     = $c.ts
            Message  = $c.message
            Files    = @($c.files).Count
            Added    = $Added
            Modified = $Modified
            Deleted  = $Deleted
        }
    }
    return $Result
}
