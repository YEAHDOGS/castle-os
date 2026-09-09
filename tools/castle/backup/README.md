# Backup intake (`backup/`)

Castle's receiving end for machine backups — the landing zone for
Phoenix's emergency runbook (image the infected laptop → back up data
to Castle → wipe and rebuild). See `docs/BACKUP-INTAKE.md` for the full
contract.

## Model

- Intake root: `~/.castle-backups/` (override with `--dir`).
- Layout: `machines/<machine>/images/` and `.../data/`; infected disk
  images go under `images/quarantine/` with a DO-NOT-MOUNT marker.
- Every intake is SHA-256 verified at write time and recorded in
  append-only `intake.jsonl`; `verify` re-hashes to catch bit-rot or
  tampering. A corrupt intake log is refused, never trusted.
- Quarantined images are never mounted, booted, or opened by Castle
  tooling — forensics happens on an isolated setup.

## Usage

```bash
python3 intake.py register --machine brando-laptop --kind disk-image \
  --label QUARANTINE-INFECTED-2026-09-09 --sha256 <64-hex> \
  --quarantine /path/to/image.img
python3 intake.py register --machine brando-laptop --kind data \
  --label DATA-2026-09-09 --sha256 <64-hex> /path/to/backup.zip
python3 intake.py verify               # exit 2 on drift
python3 intake.py list --machine brando-laptop
python3 intake.py retire --id <16-hex-id> --confirm-label <EXACT-LABEL>
#   destroys the intake file (2x CSPRNG overwrite + zero pass, fsync'd,
#   read-back sampled, then rename→truncate→unlink) and appends a
#   "retirement" record to intake.jsonl — fingerprints only, never
#   contents. Refuses: unknown id, already retired, confirmation not an
#   exact label match, file missing from disk, or file hash drifting
#   from the manifest (never destroy data you can't verify).
#   Quarantined images need --release-quarantine (forensics evidence).
```

## Security rules this module enforces

- Machine/label names strictly validated — no path traversal; staged
  destinations can never escape the intake root.
- Symlinks and non-regular files refused as sources; quarantine refused
  for `data` kind (only disk images).
- SHA-256 mismatch refused before anything is written; idempotent on
  machine+label+sha.
- Dirs 0700, files 0600; logs carry metadata only — never file bytes.

## Tests

```bash
python3 test_intake.py   # 28 fixture-based regression tests, temp dirs only
```
