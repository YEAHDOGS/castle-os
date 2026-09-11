#!/usr/bin/env bash
# =============================================================================
# Regression tests for chains sync plan (scripts/chains-sync-plan.sh).
#
# Builds fixture vaults + local-filesystem remotes in a temp dir -- in-sync,
# push-needed, fetch-needed, rolled-back remote with a pin, same-id
# collision, missing local blob for a planned push, missing remote blob for
# a planned fetch, empty remote, first-contact (TOFU) remote -- plus a --json
# pass, runs the plan against each, and asserts exit codes (0 clean / 1
# warnings / 2 errors), key output markers, and the machine-readable schema.
# Also asserts the plan is strictly read-only: a hash of every fixture file
# must be identical before and after every run -- the plan never writes.
#
# Needs: bash, python3 (stdlib only), sha256sum. No network, no installs.
# Run from the repo root:  bash tests/test-sync-plan.sh
# =============================================================================
set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLAN="$REPO_ROOT/scripts/chains-sync-plan.sh"

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

# --- fixture builders --------------------------------------------------------

# mkvault <name> : creates $FIX/<name> with .chains/{config.json,journal.jsonl,snapshots/}
mkvault() {
    local v="$FIX/$1"
    mkdir -p "$v/.chains/snapshots"
    printf '%s' "$v"
}

# mkremote <name> <vault-id> : creates $FIX/<name>/vaults/<vault-id>/{journal.jsonl,blobs/}
mkremote() {
    local r="$FIX/$1"
    mkdir -p "$r/vaults/$2/blobs"
    : > "$r/vaults/$2/journal.jsonl"
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
# commit entry (id minted exactly like vault.ps1 New-SaveCommitId) and echoes the id
mkentry() {
    python3 - "$1" "$2" "$3" "$4" "$5" <<'PY'
import hashlib, json, sys
journal, parent, ts, msg = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
files = json.loads(sys.argv[5])
tree = ",".join(sorted(("%s=%s" % (f["key"], f["sha256"]) for f in files), key=str.casefold))
cid = hashlib.sha256(("%s|%s|%s|%s" % (parent, ts, msg, tree)).encode("utf-8")).hexdigest()[:12]
entry = {"id": cid, "parent": parent, "ts": ts, "msg": msg, "files": files}
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

# seed_remote <remote> <vault-id> <vault> : copies a vault's journal + blobs onto a remote
seed_remote() {
    cp "$3/.chains/journal.jsonl" "$1/vaults/$2/journal.jsonl"
    for b in "$3"/.chains/snapshots/*; do
        [ -f "$b" ] && cp "$b" "$1/vaults/$2/blobs/"
    done
}

# snapshot_fixture <dir> : sha256 of every file under <dir>, for the read-only assertion
snapshot_fixture() {
    ( cd "$1" && find . -type f -exec sha256sum {} + | sort )
}

# plan_readonly <vault> <remote> [args...] : runs the plan, fails the test if any
# fixture file changed; echoes the plan's stdout
plan_readonly() {
    local vault="$1" remote="$2"; shift 2
    local before after out code
    before="$(snapshot_fixture "$vault"; snapshot_fixture "$remote")"
    out="$(bash "$PLAN" "$vault" "$remote" "$@" 2>&1)"; code=$?
    after="$(snapshot_fixture "$vault"; snapshot_fixture "$remote")"
    if [ "$before" = "$after" ]; then
        echo "  [PASS] plan is read-only on ${vault##*/}/${remote##*/}" >&2
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] plan modified files in ${vault##*/} or ${remote##*/}" >&2
        FAIL=$((FAIL + 1))
    fi
    printf '%s' "$out"
    return "$code"
}

FIX="$(mktemp -d)"
trap 'rm -rf "$FIX"' EXIT

WATCH="/games/saves"
TS1="2026-09-09T10:00:00Z"
TS2="2026-09-09T11:00:00Z"
TS3="2026-09-09T11:30:00Z"

# --- base vault: two commits, id deadbeef ------------------------------------
BASE_VAULT_ID="deadbeefdeadbeef"
BV="$(mkvault base)"
write_config "$BV" "{\"id\":\"$BASE_VAULT_ID\",\"version\":1,\"watchPaths\":[\"$WATCH\"],\"remotePins\":{}}"
BS1="$(mkblob "$BV" 'save-one-content')"
BS2="$(mkblob "$BV" 'save-two-content')"
BID1="$(mkentry "$BV/.chains/journal.jsonl" "" "$TS1" "first" "$(mkfiles "$WATCH" "$BS1")")"
BID2="$(mkentry "$BV/.chains/journal.jsonl" "$BID1" "$TS2" "second" "$(mkfiles "$WATCH" "$BS2")")"

# --- fixture 1: in sync -------------------------------------------------------
V1="$(mkvault v-insync)"; R1="$(mkremote r-insync "$BASE_VAULT_ID")"
cp -r "$BV/." "$V1/"   # vault with two commits + blobs
seed_remote "$R1" "$BASE_VAULT_ID" "$V1"

OUT="$(plan_readonly "$V1" "$R1")"; CODE=$?
assert_exit 0 "$CODE" "in-sync vault"
assert_contains "$OUT" "already in sync" "in-sync plan reports nothing to transfer"

# --- fixture 2: push needed (local has commit 2, remote only commit 1) --------
V2="$(mkvault v-push)"; R2="$(mkremote r-push "$BASE_VAULT_ID")"
cp -r "$BV/." "$V2/"
# remote gets only the first commit + first blob
head -1 "$V2/.chains/journal.jsonl" > "$R2/vaults/$BASE_VAULT_ID/journal.jsonl"
cp "$V2/.chains/snapshots/$BS1" "$R2/vaults/$BASE_VAULT_ID/blobs/"

OUT="$(plan_readonly "$V2" "$R2" --direction push)"; CODE=$?
assert_exit 0 "$CODE" "push-needed vault"
assert_contains "$OUT" "+ commit $BID2" "push plan lists the missing commit"
assert_contains "$OUT" "1 new blob(s)" "push plan lists the missing blob"

# --- fixture 3: fetch needed (remote has extra commit 3) -----------------------
V3="$(mkvault v-fetch)"; R3="$(mkremote r-fetch "$BASE_VAULT_ID")"
cp -r "$BV/." "$V3/"
seed_remote "$R3" "$BASE_VAULT_ID" "$V3"
BS3_CONTENT='save-three-content'
BS3="$(printf '%s' "$BS3_CONTENT" | sha256sum | awk '{print $1}')"
printf '%s' "$BS3_CONTENT" > "$R3/vaults/$BASE_VAULT_ID/blobs/$BS3"
BID3="$(mkentry "$R3/vaults/$BASE_VAULT_ID/journal.jsonl" "$BID2" "$TS3" "other-machine" "$(mkfiles "$WATCH" "$BS3")")"

OUT="$(plan_readonly "$V3" "$R3" --direction fetch)"; CODE=$?
assert_exit 0 "$CODE" "fetch-needed vault"
assert_contains "$OUT" "+ commit $BID3" "fetch plan lists the remote-only commit"
assert_contains "$OUT" "1 new blob(s)" "fetch plan lists the missing blob"

# --- fixture 4: rolled-back remote with a pin ----------------------------------
V4="$(mkvault v-rollback)"; R4="$(mkremote r-rollback "$BASE_VAULT_ID")"
cp -r "$BV/." "$V4/"
seed_remote "$R4" "$BASE_VAULT_ID" "$V4"
# remote loses commit 2 (rollback); pin still records it
head -1 "$V4/.chains/journal.jsonl" > "$R4/vaults/$BASE_VAULT_ID/journal.jsonl"
rm -f "$R4/vaults/$BASE_VAULT_ID/blobs/$BS2"
python3 - "$V4/.chains/config.json" "$BID1" "$BID2" "$R4" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1], encoding="utf-8"))
cfg["remotePins"]["%s|%s" % (sys.argv[4], "deadbeefdeadbeef")] = {
    "fingerprint": "abc", "ids": [sys.argv[2], sys.argv[3]],
    "when": "2026-09-09T12:00:00Z"}
json.dump(cfg, open(sys.argv[1], "w", encoding="utf-8"))
PY

OUT="$(plan_readonly "$V4" "$R4")"; CODE=$?
assert_exit 2 "$CODE" "rolled-back remote with pin"
assert_contains "$OUT" "rollback" "plan flags the pin rollback violation"
assert_contains "$OUT" "a real sync would abort" "plan says a real sync would abort"

# --- fixture 5: same-id collision (tampered remote entry) ----------------------
V5="$(mkvault v-collide)"; R5="$(mkremote r-collide "$BASE_VAULT_ID")"
cp -r "$BV/." "$V5/"
seed_remote "$R5" "$BASE_VAULT_ID" "$V5"
python3 - "$R5/vaults/$BASE_VAULT_ID/journal.jsonl" "$BID1" <<'PY'
import json, sys
p, cid = sys.argv[1], sys.argv[2]
lines = open(p, encoding="utf-8").read().splitlines()
out = []
for ln in lines:
    e = json.loads(ln)
    if e["id"] == cid:
        e["msg"] = "rewritten-by-attacker"
    out.append(json.dumps(e, separators=(",", ":")))
open(p, "w", encoding="utf-8").write("\n".join(out) + "\n")
PY

OUT="$(plan_readonly "$V5" "$R5")"; CODE=$?
assert_exit 2 "$CODE" "tampered remote journal (collision)"
assert_contains "$OUT" "collides with different content" "plan flags the collision"

# --- fixture 6: local blob missing for a planned push --------------------------
V6="$(mkvault v-pushmissing)"; R6="$(mkremote r-pushmissing "$BASE_VAULT_ID")"
cp -r "$BV/." "$V6/"
head -1 "$V6/.chains/journal.jsonl" > "$R6/vaults/$BASE_VAULT_ID/journal.jsonl"
cp "$V6/.chains/snapshots/$BS1" "$R6/vaults/$BASE_VAULT_ID/blobs/"
rm -f "$V6/.chains/snapshots/$BS2"   # commit 2's blob vanished locally

OUT="$(plan_readonly "$V6" "$R6" --direction push)"; CODE=$?
assert_exit 2 "$CODE" "push with missing local blob"
assert_contains "$OUT" "local blob missing" "plan flags the missing local blob"

# --- fixture 7: remote blob missing for a planned fetch ------------------------
V7="$(mkvault v-fetchmissing)"; R7="$(mkremote r-fetchmissing "$BASE_VAULT_ID")"
cp -r "$BV/." "$V7/"
seed_remote "$R7" "$BASE_VAULT_ID" "$V7"
# remote journal gains commit 3 but its blob never landed
mkentry "$R7/vaults/$BASE_VAULT_ID/journal.jsonl" "$BID2" "$TS3" "ghost" "$(mkfiles "$WATCH" "$BS3")" >/dev/null

OUT="$(plan_readonly "$V7" "$R7" --direction fetch)"; CODE=$?
assert_exit 2 "$CODE" "fetch with missing remote blob"
assert_contains "$OUT" "remote blob missing" "plan flags the corrupt remote"

# --- fixture 8: empty remote ----------------------------------------------------
V8="$(mkvault v-nodata)"; R8="$FIX/r-nodata"; mkdir -p "$R8"
cp -r "$BV/." "$V8/"

OUT="$(plan_readonly "$V8" "$R8")"; CODE=$?
assert_exit 1 "$CODE" "empty remote"
assert_contains "$OUT" "push first" "plan tells the user to push first"
assert_contains "$OUT" "2 new blob(s)" "plan seeds both blobs on first push"

# --- fixture 9: first contact with existing remote data (TOFU) ------------------
V9="$(mkvault v-tofu)"; R9="$(mkremote r-tofu "$BASE_VAULT_ID")"
cp -r "$BV/." "$V9/"
seed_remote "$R9" "$BASE_VAULT_ID" "$V9"

OUT="$(plan_readonly "$V9" "$R9")"; CODE=$?
assert_exit 0 "$CODE" "first-contact remote (no pin)"
assert_contains "$OUT" "pin   : none" "plan shows no pin recorded yet"
assert_contains "$OUT" "TOFU" "plan notes first-contact trust"

# --- --json pass ---------------------------------------------------------------
OUT="$(plan_readonly "$V2" "$R2" --direction push --json)"; CODE=$?
assert_exit 0 "$CODE" "--json push plan"
if printf '%s' "$OUT" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["result"] == "healthy" and d["exit"] == 0, "verdict"
assert d["direction"] == "push", "direction"
assert len(d["push"]["entries"]) == 1, "push entries"
assert d["push"]["bytes"] > 0, "push bytes"
assert d["pin"] in ("none", "pinned"), "pin"
assert all(set(f) == {"severity", "message"} for f in d["findings"]), "findings schema"
print("ok")' >/dev/null 2>&1; then
    pass "--json push plan parses with valid schema"
else
    fail "--json push plan schema"
fi
assert_contains "$OUT" "\"result\": \"healthy\"" "--json carries the verdict"
if printf '%s' "$OUT" | head -1 | grep -q '^{'; then
    pass "--json emits a bare JSON document (no human lines)"
else
    fail "--json emits a bare JSON document (no human lines)"
fi

# --json on the rollback fixture mirrors the human verdict
OUT="$(plan_readonly "$V4" "$R4" --json)"; CODE=$?
assert_exit 2 "$CODE" "--json rollback fixture"
assert_contains "$OUT" "\"result\": \"errors\"" "--json carries the errors verdict"

# --- arg handling ----------------------------------------------------------------
bash "$PLAN" >/dev/null 2>&1; CODE=$?
assert_exit 2 "$CODE" "no args"
bash "$PLAN" "$V1" "$R1" --direction sideways >/dev/null 2>&1; CODE=$?
assert_exit 2 "$CODE" "bad --direction"

echo ""
echo "  $PASS passed, $FAIL failed."
[ "$FAIL" -eq 0 ]
