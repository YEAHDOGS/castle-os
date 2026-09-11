# PROVENANCE — vendored Chains engine

This directory is a **copy** (not a submodule) of the Chains file-versioning
engine, so Castle OS builds stay self-contained and reproducible.

- **Source repo:** `YEAHDOGS/chains`
- **Commit:** `4f3ed65c46b92e95f53aa362bf749fc7256adee8`
  ("Merge branch 'jack/chains-git-for-files' -- git-for-files expansion")
- **Vendored:** 2026-09-11 by the Castle OS build crew

## What was copied

| Path here | From chains repo |
|---|---|
| `chains.sh` | `chains.sh` — bash dispatcher CLI (init/watch/commit/status/log/diff/restore/verify/push/fetch/patterns) |
| `modules/vault.ps1` | `modules/vault.ps1` — the one canonical engine; `chains.sh` delegates every engine command to `pwsh` running this |
| `scripts/chains-doctor.sh` | `scripts/chains-doctor.sh` — read-only vault health check, no PowerShell needed |
| `scripts/chains-sync.sh` | `scripts/chains-sync.sh` — offline push/fetch through any directory remote, no PowerShell needed |
| `scripts/chains-sync-plan.sh` | `scripts/chains-sync-plan.sh` — read-only sync preview, no PowerShell needed |
| `chains.ps1` | `chains.ps1` — PowerShell dispatcher twin (same flags/commands as `chains.sh`); kept on Castle OS for pwsh-equipped machines and so the vendored pattern suites stay self-consistent |
| `tests/*.sh` | the bash regression suites (dispatcher, doctor, sync, sync-plan, journal schema, file patterns) |

Deliberately **not** copied: `docs/` (the upstream design docs), the Pester suite, and the format-specific tests tied to upstream docs. The upstream `SYNC.md` spec is summarized in the Castle OS README instead.

## How it lands on the live system

`build.sh` already stages all of `tools/castle/` into `/opt/castle` at
assemble time, so this directory ships as `/opt/castle/chains` with no build
changes. The `chains` wrapper in the live overlay
(`profile/airootfs/usr/local/bin/chains`) execs
`/opt/castle/chains/chains.sh`.

## Updating

To pull a newer chains engine: copy the same file set over this directory
from the chains repo at the new commit, update the commit line above, and
re-run the vendored suites (`bash tests/test-*.sh` from this directory).
