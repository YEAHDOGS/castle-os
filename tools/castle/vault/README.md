# Family Data Vault — core (`vault.py`)

Implements FAMILY-DATA-VAULT.md build-order steps 1 (vault-per-user data
layout + age-tiered accounts) and 5 (guardian controls), wired into the
flamethrower Tier-1 keyring.

## The model

Every family member gets a **private vault** — nothing is shared unless
explicitly granted via the sharing ladder (vision build-order step 2,
implemented in this module too). Every vault gets a real random 256-bit
data key in the flamethrower keyring; deleting the key **is** deleting the
data (crypto-shredding, media-independent).

## Age tiers (a property of the account)

| | adult (18+) | child (<18) |
|---|---|---|
| Private vault + all subdirs | ✅ | ✅ |
| Share to member / family | ✅ | ✅ |
| **Share to world** | ✅ | ❌ refused |
| **Integrations** (POS push, API tokens) | ✅ | ❌ refused |
| Device approval | self | guardian approves (`--by <guardian>`) |
| Key escrow (family recovery) | optional | always on |
| **Guardian controls** (step 5) | immune — nobody touches an adult's account | guardian revokes child's devices/shares, approves graduation |

## Guardian controls (FAMILY-DATA-VAULT.md step 5)

Scoped power: a guardian can act only on their **own** children — never
on an adult. Dad can't touch Mom's devices or shares (no family-admin
backdoor). Every exercise is logged in `activity.jsonl`.

```bash
python3 vault.py revoke-device sally sally-phone --by mom   # lost phone
python3 vault.py guardian-revoke-share sally dad --by mom   # take back a bad share
python3 vault.py graduate sally --by mom                    # child -> adult, data comes with
```

Kids can't self-revoke devices (that would make approval theater), can't
share to the world, can't add integrations. Graduation flips the tier,
clears the guardian, and keeps data + escrow (family recovery keeps
working); the adult surface (world shares, integrations) unlocks after.

## Usage

```bash
python3 vault.py init
python3 vault.py create-user dad --tier adult
python3 vault.py create-user mom --tier adult
python3 vault.py create-user sally --tier child --guardian mom

python3 vault.py add-device sally sally-phone --by mom
python3 vault.py add-integration dad clover-pos

# secrets store: encrypted API keys/tokens per adult vault (0600 files,
# AES-256-CBC + HMAC-SHA256 via the user's own keyring data key).
# The value arrives via stdin or a 0600 file — never a CLI arg.
printf 'sk-live-...' | python3 vault.py add-secret dad alpaca-key
python3 vault.py get-secret dad alpaca-key        # stdout only, not logged
python3 vault.py list-secrets dad                 # names only, never values
printf 'sk-live-new' | python3 vault.py rotate-secret dad alpaca-key
python3 vault.py delete-secret dad alpaca-key --yes alpaca-key  # shredded

# sharing ladder: explicit, revocable, logged
python3 vault.py grant-share mom family
python3 vault.py grant-share mom dad
python3 vault.py revoke-share mom dad
python3 vault.py show-shares mom

# guardian controls (FAMILY-DATA-VAULT.md step 5): guardian acts only on
# their own children — never on an adult's account
python3 vault.py revoke-device sally sally-phone --by mom
python3 vault.py guardian-revoke-share sally dad --by mom
python3 vault.py graduate sally --by mom   # child -> adult, data comes with

# true deletion: dry-run default; typed confirmation burns
python3 vault.py delete-user sally          # lists what would die
python3 vault.py delete-user sally --yes sally   # key crypto-shredded, dirs wiped

python3 vault.py verify

# integrity: SHA-256 manifest + drift audit (FAMILY-DATA-VAULT step 6)
python3 vault.py manifest ~/family-vaults/mom --out mom-manifest.json
python3 vault.py audit ~/family-vaults/mom --manifest mom-manifest.json  # exit 0 = clean

# encrypted-at-rest sealing (FAMILY-DATA-VAULT step 7) — openssl only.
# Secret files must already be mode 0600; lock is dry-run by default.
python3 vault.py vault-init ~/family-vaults/mom --out mom.castle --passphrase-file ~/.castle-pw
python3 vault.py vault-lock ~/family-vaults/mom --out mom.castle --passphrase-file ~/.castle-pw
python3 vault.py vault-lock ~/family-vaults/mom --out mom.castle --passphrase-file ~/.castle-pw --yes mom  # burns plaintext
python3 vault.py vault-unlock mom.castle --out ~/restored-mom --passphrase-file ~/.castle-pw
```

```bash
python3 test_vault.py   # 26 fixture-based regression tests, temp dirs only
python3 test_secrets.py  # secrets store: encrypt-at-rest, adult gate, shred
python3 test_guardian.py  # 18 regression tests: guardian controls, graduation
python3 test_manifest.py  # 13 regression tests: manifest build/write/load + refusals
python3 test_verify.py    # 13 regression tests: ADDED/REMOVED/MODIFIED/UNCHANGED + CLI
python3 test_vault_lock.py  # 25 regression tests: init/lock/unlock, fail-closed refusals
```

Layout under the vault root (`--dir`, default `~/.castle-vault`), all
0700 dirs / 0600 files: `users.json`, `activity.jsonl`, `vaults/<user>/`
(inbox, documents, photos, receipts, shared), `keys/` (keyring root).

`activity.jsonl` is the append-only event log — who did what to which
vault, never key material or file bytes. (Deletions also get flamethrower
deletion certificates + the cross-burn audit log; the activity log
records *that* the burn happened.)

## Tests

```bash
python3 test_vault.py   # 26 fixture-based regression tests, temp dirs only
```

## Security rules this module enforces

- Name validation on every user/vault name (no path traversal).
- Child accounts: world-share and integrations refused, devices need
  guardian approval, keys always escrowed for family recovery.
- True deletion needs typed confirmation (the user name); dry-run is
  the default; revoking a non-existent share is a refusal, not a no-op.
- Key bytes never touch stdout, logs, certificates, or the activity log.
