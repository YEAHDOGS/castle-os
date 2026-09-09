# DOGS Token Authority (`castle/tokens/`)

The encrypted token system for the DOGS ecosystem. First consumer: DOGS ID
(`id.wearedogs.net`), replacing the forgeable `#dogs-verified=21` URL-hash
handshake with real encrypted bearer tokens.

The anti-JWT: claims are **encrypted**, not merely signed. Nothing readable
leaks onto the wire, and a token minted for one audience never verifies on
another.

## Envelope

```
dogs1.<b64u(header)>.<b64u(ciphertext)>.<b64u(tag)>
```

All segments are base64url, no padding. Max token length: 16384 chars
(anything longer is refused outright).

**header** (JSON, sorted keys, no whitespace):

```json
{"cipher":"aes-256-cbc","iter":100000,"kid":"k5e5b495f70ff","mac":"hmac-sha256","v":1}
```

| field   | meaning                                                        |
|---------|----------------------------------------------------------------|
| `v`     | envelope version, currently `1`                                |
| `kid`   | key id — selects the keyring key; validated `^[a-z][a-z0-9-]{1,31}$` before any path use |
| `cipher`| `aes-256-cbc` (GCM probed at runtime; this machine's openssl refuses AEAD) |
| `mac`   | `hmac-sha256`                                                  |
| `iter`  | PBKDF2 iterations for the `openssl enc -pbkdf2` step            |

**ciphertext**: raw output of
`openssl enc -e -aes-256-cbc -pbkdf2 -iter <iter> -pass file:<keyfile>`,
i.e. `b" Salted__" + salt(8) + ct`. b64u-encoded. A fresh random salt per
mint means identical claims produce different tokens (no linkability).

**tag**: `HMAC-SHA256(mac_key, "<b64u(header)>.<b64u(ciphertext)>")` over the
ASCII of the first two segments — the header is authenticated too. 32 bytes,
b64u-encoded.

## Key derivation (exact, for other implementations)

- `master` = the 32 raw bytes of `keys/<kid>.key` (256-bit CSPRNG).
- Encryption key/IV: OpenSSL's `enc -pbkdf2` derivation —
  `key || iv = PBKDF2-HMAC-SHA256(pass=master, salt, iter, 48)`;
  first 32 bytes = AES key, next 16 = IV. `salt` is the 8 bytes after the
  `Salted__` magic in the ciphertext blob.
- MAC key: `HMAC-SHA256(master, b"castle-tokens-mac-v1" || kid)` —
  domain-separated per key, computed in constant time.
- Iteration count is 100_000 (not 600_000): keyring keys are 256-bit random,
  not passwords, so iterations are domain separation + salt randomization,
  not brute-force armor. Keeps mint/verify around half a second.

## Claims (encrypted payload, JSON)

| claim     | type | meaning                                              |
|-----------|------|------------------------------------------------------|
| `iss`     | str  | issuer, e.g. `dogs-id`                               |
| `aud`     | str  | audience — the token ONLY verifies for this aud      |
| `sub`     | str  | subject, e.g. `visitor` or a user id                 |
| `iat`     | int  | issued-at (unix seconds)                             |
| `exp`     | int  | expiry (unix seconds); max ttl 86400 (24h)           |
| `jti`     | str  | unique token id, 32 lowercase hex chars              |
| `purpose` | str  | e.g. `age-verified-21`                               |

All string claims: printable ASCII, length-capped.

## Verify algorithm (fail closed, in order)

1. Envelope: 4 dot-separated parts, prefix `dogs1`, sane length.
2. Parse header; check `v`, cipher suite, `kid` format, sane `iter`.
3. Load key by `kid` (unknown kid → refuse; `kid` never reaches the
   filesystem unvalidated).
4. Recompute the tag; `compare_digest` — mismatch → refuse. **HMAC is
   always verified before decrypt.**
5. Decrypt; parse claims JSON.
6. `aud` must equal the expected audience exactly.
7. `now > exp + 300` → expired. `iat > now + 300` → issued in the future.
   (300s clock-skew leeway, documented here.)
8. `jti` in `revoked.jsonl` → refused.

## Rotation

`keys/<kid>.key` (0600, never symlinks) + `keys.json` metadata.
`rotate-keys` generates a new key and retires the rest: **old kids verify
but never mint**. `list-keys` shows kids + metadata — key bytes never leave
the keyring.

## Revocation

`revoked.jsonl` — one JSON object per line: `{"jti","exp","revoked_at",
"reason"}`. Checked on every verify. `revoke` accepts a bare `jti` or a
full token (jti+exp are extracted from the token, so it stays prunable;
a leaked token is revocable even after expiry). `prune-revoked` drops
entries whose `exp` is past the skew window; bare-jti entries (no `exp`)
are kept forever.

## Keyring layout

```
~/.castle-tokens/          (0700; override with --dir)
  keys/<kid>.key           (0600, 32 raw bytes)
  keys.json                (0600, kid metadata)
  revoked.jsonl            (0600)
```

## CLI

```bash
python3 tokens.py init
python3 tokens.py mint --iss dogs-id --aud weed.wearedogs.net \
    --sub visitor --purpose age-verified-21 --ttl 600
python3 tokens.py verify <token> --aud weed.wearedogs.net
python3 tokens.py revoke <jti-or-token> [--reason "..."]
python3 tokens.py rotate-keys
python3 tokens.py list-keys
python3 tokens.py prune-revoked
```

`mint` prints the token to stdout — tokens are bearer credentials, so treat
stdout like a password field. `verify` prints claims JSON, exit 0; any
failure prints `error: ...` to stderr, exit 1. Errors name the failure,
never key material.

## Security notes

- Key material never appears in argv, logs, or error messages. Keys arrive
  via `-pass file:` (openssl) and stdlib HMAC only.
- `kid` from a token is validated before any filesystem use (path-traversal
  safe); unknown kids fail closed.
- Tokens are bearer credentials: whoever holds one can use it until `exp`.
  Keep ttls short; revoke on leak.
- No `mlock`/RAM wiping — Python can't promise that; key bytes are
  `del`eted best-effort.

## For a future JS verifier (e.g. DOGS ID)

The format above is implementable with WebCrypto alone:
PBKDF2 (SHA-256) → AES-CBC decrypt → HMAC-SHA256 verify, all with
`crypto.subtle`. **But**: verification needs the keyring secret, so a pure
static site cannot verify tokens by itself — it needs a secret-holding
verify endpoint (Castle side). The spec here is for that endpoint's
implementation, in any language.
