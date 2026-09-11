#!/usr/bin/env bash
# =============================================================================
# Regression tests for the real sync path (scripts/chains-sync.sh).
#
# Builds fixture vaults + local-filesystem remotes in a temp dir and runs the
# actual push/fetch against them, asserting the SYNC.md contract:
#   - push seeds an empty remote (journal + blobs) and pins it
#   - fetch onto a second machine brings history + blobs, hash-verified, and
#     remembers the vault id (syncVaultId) so bare fetches just work
#   - re-push / re-fetch are idempotent (exit 0, nothing transferred)
#   - divergence merges both histories in timestamp order, both sides intact
#   - a rolled-back remote aborts (exit 2) before any state changes, pin unmoved
#   - a tampered remote blob aborts before the local journal is extended,
#     no staged files are left behind, pin unmoved
#   - same-id-different-bytes (corruption) aborts; remote untouched
#   - a missing local blob aborts a push before the remote journal changes
#   - a same-named-different-bytes remote blob aborts a push (integrity)
#   - a push whose blob transfer fails partway leaves the remote journal
#     untouched (blobs are transferred before the journal is rewritten)
#   - fetch from an empty remote is a clean no-op (exit 0)
#   - pin fingerprint matches the engine's format (fingerprint(ids sorted,
#     newline-joined, sha256); keyed "<remote>|<vault-id>") so the bash and
#     PowerShell twins share pins
#   - a vault that went through the real sync still verifies with
#     chains-doctor.sh
#
# Needs: bash, python3 (stdlib only), sha256sum. No network, no installs.
# Run from the repo root:  bash tests/test-sync.sh
# =============================================================================
set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SYNC="$REPO_ROOT/scripts/chains-sync.sh"
DOCTOR="$REPO_ROOT/scripts/chains-doctor.sh"

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

assert_eq() {  # assert_eq <expected> <actual> <label>
    if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (expected '$1', got '$2')"; fi
}

# --- fixture builders (same shape as test-sync-plan.sh) ----------------------

# mkvault <name> : creates $FIX/<name> with .chains/{config.json,journal.jsonl,snapshots/}
mkvault() {
    local v="$FIX/$1"
    mkdir -p "$v/.chains/snapshots"
    : > "$v/.chains/journal.jsonl"
    printf '%s' "$v"
}

# mkremote <name> : creates an empty remote root $FIX/<name> (no vaults dir yet)
mkremote() {
    local r="$FIX/$1"
    mkdir -p "$r"
    printf '%s' "$r"
}

write_config() {  # write_config <vault> <json>
    printf '%s' "$2" > "$1/.chains/config.json"
}

# mkblob <vault> <bytes-string> : writes content-addressed blob into vault snapshots, echoes sha256
mkblob() {
    local content="$2"
    local sha
    sha="$(printf '%s' "$content" | sha256sum | awk '{print $1}')"
    printf '%s' "$content" > "$1/.chains/snapshots/$sha"
    printf '%s' "$sha"
}

# mkentry <journal> <parent> <ts> <msg> <files-json> : appends an engine-style
# commit entry (id minted exactly like vault.ps1 New-SaveCommitId, with the
# engine's real field names so a synced vault verifies with the doctor) and
# echoes the id
mkentry() {
    python3 - "$1" "$2" "$3" "$4" "$5" <<'PY'
import hashlib, json, sys
journal, parent, ts, msg = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
files = json.loads(sys.argv[5])
tree = ",".join(sorted(("%s=%s" % (f["key"], f["sha256"]) for f in files), key=str.casefold))
cid = hashlib.sha256(("%s|%s|%s|%s" % (parent, ts, msg, tree)).encode("utf-8")).hexdigest()[:12]
entry = {"id": cid, "parent": parent, "ts": ts, "message": msg, "files": files}
open(journal, "a", encoding="utf-8").write(json.dumps(entry, separators=(",", ":")) + "\n")
print(cid)
PY
}

mkfiles() {  # mkfiles <watch> <sha>... : echoes a files[] JSON array for rels g0.srm, g1.srm, ...
    python3 - "$@" <<'PY'
import json, sys
watch, shas = sys.argv[1], sys.argv[2:]
print(json.dumps([
    {"key": "%s::g%d.srm" % (watch, i), "rel": "g%d.srm" % i, "sha256": s, "bytes": 8}
    for i, s in enumerate(shas)]))
PY
}

journal_ids() {  # journal_ids <journal> : sorted id list, one per line
    python3 - "$1" <<'PY'
import json, sys
print("\n".join(json.loads(l)["id"] for l in open(sys.argv[1], encoding="utf-8") if l.strip()))
PY
}

pin_fingerprint() {  # pin_fingerprint <vault> <remote> <vault-id> : fingerprint recorded in config
    python3 - "$1" "$2" "$3" <<'PY'
import json, sys
cfg = json.load(open("%s/.chains/config.json" % sys.argv[1], encoding="utf-8"))
print(cfg["remotePins"]["%s|%s" % (sys.argv[2], sys.argv[3])]["fingerprint"])
PY
}

expect_fingerprint() {  # expect_fingerprint <id...> : engine-format fingerprint of those ids
    python3 - "$@" <<'PY'
import hashlib, sys
print(hashlib.sha256("\n".join(sorted(sys.argv[1:])).encode("utf-8")).hexdigest())
PY
}

syncVaultId_of() {  # syncVaultId_of <vault> : remembered id or empty
    python3 - "$1" <<'PY'
import json, sys
cfg = json.load(open("%s/.chains/config.json" % sys.argv[1], encoding="utf-8"))
print(cfg.get("syncVaultId") or "")
PY
}

# --- suite -------------------------------------------------------------------

FIX="$(mktemp -d)"
trap 'rm -rf "$FIX"' EXIT

# Test 1: push seeds an empty remote.
VA="$(mkvault vaultA)"
write_config "$VA" '{"version":1,"id":"vault-aaaa"}'
R="$(mkremote remote1)"
SHA_A="$(mkblob "$VA" 'save-bytes-A')"
ID1="$(mkentry "$VA/.chains/journal.jsonl" "0" "2026-09-01T10:00:00Z" "beat the elite four" "$(mkfiles '/w' "$SHA_A")")"

out="$(bash "$SYNC" "$VA" "$R" --direction push 2>&1)"; code=$?
assert_exit 0 "$code" "push seeds empty remote"
assert_contains "$out" "1 new commit(s), 1 new blob(s)" "push reports what transferred"
assert_eq "$ID1" "$(journal_ids "$R/vaults/vault-aaaa/journal.jsonl")" "remote journal gained the entry"
[ -f "$R/vaults/vault-aaaa/blobs/$SHA_A" ] && pass "remote blob landed" || fail "remote blob landed"
assert_eq "$(expect_fingerprint "$ID1")" "$(pin_fingerprint "$VA" "$R" "vault-aaaa")" \
    "pin recorded in engine fingerprint format"

# Test 2: fetch onto a second machine (explicit --vault-id remembered).
VB="$(mkvault vaultB)"
write_config "$VB" '{"version":1,"id":"vault-bbbb"}'
out="$(bash "$SYNC" "$VB" "$R" --direction fetch --vault-id vault-aaaa 2>&1)"; code=$?
assert_exit 0 "$code" "fetch onto machine B"
assert_contains "$out" "1 new commit(s), 1 new blob(s)" "fetch reports what transferred"
assert_eq "$ID1" "$(journal_ids "$VB/.chains/journal.jsonl")" "B gained the history"
[ -f "$VB/.chains/snapshots/$SHA_A" ] && \
    [ "$(sha256sum < "$VB/.chains/snapshots/$SHA_A" | awk '{print $1}')" = "$SHA_A" ] && \
    pass "fetched blob verified by hash" || fail "fetched blob verified by hash"
assert_eq "vault-aaaa" "$(syncVaultId_of "$VB")" "vault id remembered in syncVaultId"
assert_eq "$(expect_fingerprint "$ID1")" "$(pin_fingerprint "$VB" "$R" "vault-aaaa")" "B pinned the remote"

# Test 3: idempotent re-push / re-fetch.
out="$(bash "$SYNC" "$VA" "$R" --direction push 2>&1)"; code=$?
assert_exit 0 "$code" "re-push idempotent"
assert_contains "$out" "0 new commit(s), 0 new blob(s)" "re-push transfers nothing"
out="$(bash "$SYNC" "$VB" "$R" 2>&1)"; code=$?   # bare fetch: direction defaults to fetch, id remembered
assert_exit 0 "$code" "re-fetch idempotent (bare, id remembered)"
assert_contains "$out" "0 new commit(s), 0 new blob(s)" "re-fetch transfers nothing"

# Test 4: divergence merges both histories in timestamp order.
SHA_B="$(mkblob "$VB" 'save-bytes-B')"
ID2="$(mkentry "$VB/.chains/journal.jsonl" "$ID1" "2026-09-02T10:00:00Z" "caught mewtwo" "$(mkfiles '/w' "$SHA_B")")"
out="$(bash "$SYNC" "$VB" "$R" --direction push 2>&1)"; code=$?
assert_exit 0 "$code" "diverged machine B pushes"
out="$(bash "$SYNC" "$VA" "$R" --direction fetch 2>&1)"; code=$?
assert_exit 0 "$code" "machine A fetches B's commit"
assert_contains "$out" "1 new commit(s), 1 new blob(s)" "fetch reports B's commit"
assert_eq "$ID1
$ID2" "$(journal_ids "$VA/.chains/journal.jsonl")" "A's journal has both commits in ts order"
assert_eq "$(journal_ids "$VB/.chains/journal.jsonl")" "$(journal_ids "$VA/.chains/journal.jsonl")" \
    "both machines agree on the id set"
[ "$(sha256sum < "$VA/.chains/snapshots/$SHA_B" | awk '{print $1}')" = "$SHA_B" ] && \
    pass "B's blob arrived intact on A" || fail "B's blob arrived intact on A"
assert_eq "$(expect_fingerprint "$ID1" "$ID2")" "$(pin_fingerprint "$VA" "$R" "vault-aaaa")" \
    "pin moved forward on success"
# The vault that went through the real sync still verifies with the doctor
# (warnings are fine in a fixture vault -- no save files live under /tmp --
# but there must be no integrity FAILs).
dout="$(bash "$DOCTOR" "$VA" 2>&1)"
if printf '%s' "$dout" | grep -q '^\s*\[FAIL\]'; then
    fail "synced vault has doctor FAILs"
    printf '%s\n' "$dout" | grep '^\s*\[FAIL\]' >&2
else
    pass "synced vault still verifies with chains-doctor.sh (no FAILs)"
fi

# Test 5: rolled-back remote aborts before any state change; pin unmoved.
cp "$R/vaults/vault-aaaa/journal.jsonl" "$FIX/journal-backup.jsonl"
python3 - "$R/vaults/vault-aaaa/journal.jsonl" <<'PY'   # rewind the remote to just ID1
import json, sys
lines = [l for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
open(sys.argv[1], "w", encoding="utf-8").write(lines[0])
PY
before_local="$(journal_ids "$VA/.chains/journal.jsonl")"
before_remote="$(journal_ids "$R/vaults/vault-aaaa/journal.jsonl")"
before_pin="$(pin_fingerprint "$VA" "$R" "vault-aaaa")"
out="$(bash "$SYNC" "$VA" "$R" --direction fetch 2>&1)"; code=$?
assert_exit 2 "$code" "rolled-back remote aborts"
assert_contains "$out" "possible rollback or replay" "rollback message"
assert_eq "$before_local" "$(journal_ids "$VA/.chains/journal.jsonl")" "local journal untouched by aborted fetch"
assert_eq "$before_remote" "$(journal_ids "$R/vaults/vault-aaaa/journal.jsonl")" "remote journal untouched by aborted fetch"
assert_eq "$before_pin" "$(pin_fingerprint "$VA" "$R" "vault-aaaa")" "pin unmoved by aborted fetch"
cp "$FIX/journal-backup.jsonl" "$R/vaults/vault-aaaa/journal.jsonl"   # restore the remote

# Test 6: tampered remote blob aborts before the local journal is extended.
SHA_C="$(mkblob "$VB" 'save-bytes-C')"
ID3="$(mkentry "$VB/.chains/journal.jsonl" "$ID2" "2026-09-03T10:00:00Z" "shiny hunt" "$(mkfiles '/w' "$SHA_C")")"
out="$(bash "$SYNC" "$VB" "$R" --direction push 2>&1)"; code=$?
assert_exit 0 "$code" "B pushes commit with blob C"
printf 'TAMPERED-TAMPERED' > "$R/vaults/vault-aaaa/blobs/$SHA_C"
before_local="$(journal_ids "$VA/.chains/journal.jsonl")"
before_pin="$(pin_fingerprint "$VA" "$R" "vault-aaaa")"
out="$(bash "$SYNC" "$VA" "$R" --direction fetch 2>&1)"; code=$?
assert_exit 2 "$code" "tampered remote blob aborts fetch"
assert_contains "$out" "failed its hash check" "tamper message"
assert_eq "$before_local" "$(journal_ids "$VA/.chains/journal.jsonl")" "local journal NOT extended on tampered fetch"
[ ! -f "$VA/.chains/snapshots/$SHA_C" ] && pass "tampered blob never entered snapshots" || fail "tampered blob never entered snapshots"
if ls -d /tmp/chains-stage-* >/dev/null 2>&1; then fail "no staged files left behind"; else pass "no staged files left behind"; fi
assert_eq "$before_pin" "$(pin_fingerprint "$VA" "$R" "vault-aaaa")" "pin unmoved by tampered fetch"
# repair the remote so later tests see a healthy one
printf 'save-bytes-C' > "$R/vaults/vault-aaaa/blobs/$SHA_C"

# Test 7: same-id-different-bytes aborts a push; remote untouched.
python3 - "$R/vaults/vault-aaaa/journal.jsonl" "$ID2" <<'PY'   # flip a byte in ID2's remote copy
import json, sys
lines = [l for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
for i, l in enumerate(lines):
    e = json.loads(l)
    if e["id"] == sys.argv[2]:
        e["message"] = "forged message"
        lines[i] = json.dumps(e, separators=(",", ":")) + "\n"
open(sys.argv[1], "w", encoding="utf-8").writelines(lines)
PY
before_remote="$(journal_ids "$R/vaults/vault-aaaa/journal.jsonl")"
out="$(bash "$SYNC" "$VA" "$R" --direction push 2>&1)"; code=$?
assert_exit 2 "$code" "same-id-different-bytes aborts push"
assert_contains "$out" "possible tampering" "collision message"
assert_eq "$before_remote" "$(journal_ids "$R/vaults/vault-aaaa/journal.jsonl")" "remote journal untouched on collision abort"
python3 - "$R/vaults/vault-aaaa/journal.jsonl" "$VB/.chains/journal.jsonl" "$ID2" <<'PY'   # restore remote copy
import json, sys
good = {json.loads(l)["id"]: l for l in open(sys.argv[2], encoding="utf-8") if l.strip()}
lines = [l for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
for i, l in enumerate(lines):
    if json.loads(l)["id"] == sys.argv[3]:
        lines[i] = good[sys.argv[3]]
open(sys.argv[1], "w", encoding="utf-8").writelines(lines)
PY

# Test 8: missing local blob aborts a push before the remote journal changes.
SHA_D="$(mkblob "$VA" 'save-bytes-D')"
ID4="$(mkentry "$VA/.chains/journal.jsonl" "$ID3" "2026-09-04T10:00:00Z" "hall of fame" "$(mkfiles '/w' "$SHA_D")")"
rm "$VA/.chains/snapshots/$SHA_D"
before_remote="$(journal_ids "$R/vaults/vault-aaaa/journal.jsonl")"
out="$(bash "$SYNC" "$VA" "$R" --direction push 2>&1)"; code=$?
assert_exit 2 "$code" "missing local blob aborts push"
assert_contains "$out" "local blob missing" "missing-blob message"
assert_eq "$before_remote" "$(journal_ids "$R/vaults/vault-aaaa/journal.jsonl")" "remote journal unchanged on missing-blob abort"
printf 'save-bytes-D' > "$VA/.chains/snapshots/$SHA_D"   # restore

# Test 9: existing-but-corrupt remote blob aborts a push (integrity, not silent skip).
printf 'wrong-bytes-under-right-name' > "$R/vaults/vault-aaaa/blobs/$SHA_D"
out="$(bash "$SYNC" "$VA" "$R" --direction push 2>&1)"; code=$?
assert_exit 2 "$code" "corrupt same-named remote blob aborts push"
assert_contains "$out" "different bytes" "integrity message"
printf 'save-bytes-D' > "$R/vaults/vault-aaaa/blobs/$SHA_D"   # restore

# Test 11: a push whose blob transfer fails partway must NOT leave the
# remote journal referencing blobs that never arrived (partial-state
# safety). Blobs are transferred before the remote journal is rewritten,
# so a failed push aborts with the journal exactly as it was.
SHA_E="$(mkblob "$VA" 'save-bytes-E')"
ID5="$(mkentry "$VA/.chains/journal.jsonl" "$ID4" "2026-09-05T10:00:00Z" "new run" "$(mkfiles '/w' "$SHA_E")")"
SHA_F="$(mkblob "$VA" 'save-bytes-F')"
ID6="$(mkentry "$VA/.chains/journal.jsonl" "$ID5" "2026-09-06T10:00:00Z" "another run" "$(mkfiles '/w' "$SHA_F")")"
# Break the remote blob store deterministically (a regular file where the
# blobs directory should be makes every blob copy fail, even as root --
# before any bytes can be transferred).
mv "$R/vaults/vault-aaaa/blobs" "$FIX/blobs-backup"
printf 'not-a-directory' > "$R/vaults/vault-aaaa/blobs"
before_remote="$(journal_ids "$R/vaults/vault-aaaa/journal.jsonl")"
out="$(bash "$SYNC" "$VA" "$R" --direction push 2>&1)"; code=$?
assert_exit 2 "$code" "push with failed blob transfer aborts cleanly"
assert_contains "$out" "remote journal left untouched" "partial-push message"
assert_eq "$before_remote" "$(journal_ids "$R/vaults/vault-aaaa/journal.jsonl")" \
    "remote journal NOT extended when blob transfer fails"
# Repair the remote and finish the push for real: 3 new commits (ID4-6);
# blob D was already on the remote so only E and F are new.
rm "$R/vaults/vault-aaaa/blobs"
mv "$FIX/blobs-backup" "$R/vaults/vault-aaaa/blobs"
out="$(bash "$SYNC" "$VA" "$R" --direction push 2>&1)"; code=$?
assert_exit 0 "$code" "push succeeds after remote repair"
assert_contains "$out" "3 new commit(s), 2 new blob(s)" "recovered push transfers what was missing"

# Test 12: fetch from an empty remote is a clean no-op.
R2="$(mkremote remote2)"
out="$(bash "$SYNC" "$VA" "$R2" --direction fetch 2>&1)"; code=$?
assert_exit 0 "$code" "fetch from empty remote is clean"
assert_contains "$out" "push first" "empty-remote message"

echo ""
echo "  $PASS passed, $FAIL failed."
[ "$FAIL" -eq 0 ]
