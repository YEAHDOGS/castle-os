# Flamethrower — Tier 1 crypto-shredding key lifecycle

Implements FLAMETHROWER.md build-order steps 1–2: per-vault encryption key
lifecycle (generation → escrow → destruction ceremony → deletion
certificate). Stdlib Python only — no third-party crypto, no network.

## The idea

Every vault gets a random 256-bit data key. Deleting the key **is**
deleting the data: AES-256 ciphertext without its key is noise, on any
media (HDD, SSD, SD — crypto-shredding is media-independent). The
certificate labels everything honestly; it records *that* something
burned, never its contents.

## Usage

```bash
# one-time setup (keyring dir is 0700, key files 0600)
python3 keyring.py init

# create a vault key; --escrow keeps a family-recovery copy
python3 keyring.py create-vault mom --escrow
python3 keyring.py list

# destruction ceremony: dry-run is the DEFAULT
python3 keyring.py destroy-vault mom
# → lists exactly what would die; exits 2; nothing burned

# real burn needs TYPED confirmation (the vault name, not "y")
python3 keyring.py destroy-vault mom --yes mom
# → overwrites key bytes 3× (CSPRNG), fsync, unlink — keyring AND escrow
# → emits certificates/<uuid>.json

# verify a deletion certificate (fails on tampered/missing fields)
python3 keyring.py verify-cert certificates/<uuid>.json

# burn the whole keyring (typed: DESTROY-ALL)
python3 keyring.py destroy-master --yes DESTROY-ALL
```

## Safety interlocks (same DNA as the Phoenix nuke tool)

- Dry-run default; real run is the exception.
- Typed confirmation (vault name / `DESTROY-ALL`).
- Explicit target enumeration before the burn; no globs, no "older than X".
- Key bytes never touch stdout, logs, or certificates — certificates carry
  only a SHA-256 receipt proving *which* key died.

## Tests

```bash
python3 test_keyring.py   # 11 fixture-based regression tests, temp dirs only
```

## What's done (per FLAMETHROWER.md build order)

1–2. Tier 1 key lifecycle: generation, escrow, destruction ceremony,
   deletion certificates (keyring.py).
3. Media detection for Tier 2/3: `media.py` classifies HDD / SATA SSD /
   NVMe / USB+SD flash / virtual / unknown from sysfs, emits the Tier-2
   kill plan (`nvme format --ses=2`, ATA Secure Erase, nwipe-style,
   crypto-shred), and structurally refuses to bless a software-overwrite
   kill on anything but spinning rust. Read-only: it runs no destructive
   commands.
4. Tier 2 firmware-erase routines (`tier2.py`): NVMe Format SES=2 crypto
   erase (Sanitize fallback), ATA Secure Erase (enhanced when offered,
   frozen-state and unsupported-state refusals), and a stdlib HDD
   single-pass zero overwrite with read-back sample verification. Flash
   with no firmware erase is REFUSED (crypto-shred only) — the module
   never offers an overwrite fallback on flash. Dry-run default, typed
   serial confirmation, mounted-partition/root-device structural
   refusals, last-second serial re-verification, abort window, and a
   deletion certificate per burn (same envelope as the keyring certs).
5. Tier 3 file shredder with honest media labeling (`tier3.py`):
   explicit files only (no globs, no recursion). HDD targets get
   overwrite → read-back sample verify → random rename → truncate →
   unlink, a real kill on spinning rust. Flash/virtual/unknown targets
   run the same sequence as a labeled BEST EFFORT — the plan, dry-run,
   and certificate all say plainly that unmapped flash pages may retain
   data and point at Tier 1 crypto-shredding for guarantees. Typed
   basename confirmation, dry-run default, abort window, structural
   refusals (directories, dangling symlinks, duplicate inodes,
   keyring-root targets, unmappable devices), one deletion certificate
   per file. The certificate records THAT something burned, never its
   contents.

## What's next

6. Cross-burn audit log (`audit.py`, build-order step 6): every Tier 1/2/3
   burn appends one entry per certificate to `<root>/audit.jsonl` —
   timestamp, operator, tier, cert id, fingerprint, method, media,
   verification result. SHA-256 hash chain (`audit verify`) detects edits,
   deletions, and reordering. 22 regression tests.
7. Wire the keyring into the vault-per-user layout from
   FAMILY-DATA-VAULT.md.

## Tests

```bash
python3 test_keyring.py   # 11 fixture-based regression tests, temp dirs only
python3 test_media.py     # 14 classification tests, fake sysfs
python3 test_tier2.py     # 39 firmware-erase tests, fake sysfs/probes/runner
python3 test_tier3.py     # 32 file-shredder tests, fake sysfs/st_dev/stdin
python3 test_flamethrower.py  # 9 unified-CLI tests, fake sysfs/temp dirs
```
