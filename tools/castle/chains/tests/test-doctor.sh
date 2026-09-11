#!/usr/bin/env bash
# =============================================================================
# Regression tests for chains doctor (scripts/chains-doctor.sh).
#
# Builds ten fixture vaults in a temp dir -- healthy, dangling parent ref,
# missing pins, stale sync, broken journal, working-tree drift, untracked
# saves, journal tampering, malformed pins, orphan snapshots -- plus a --json
# pass over the healthy/dangling/stale/drift/untracked/tampered fixtures,
# runs the doctor against each, and asserts the exit code (0 healthy /
# 1 warnings / 2 errors), the machine-readable report schema, plus key
# output markers.
# Also asserts the doctor is read-only WITHOUT --fix: a hash of every file
# in the fixture vault must be identical before and after the run. --fix is
# the one write path: the test asserts it repairs exactly the safe issues
# (malformed pins, orphan snapshots), always takes a pre-repair backup, and
# writes nothing when there is nothing repairable.
#
# Needs: bash, python3 (stdlib only), sha256sum. No network, no installs.
# Run from the repo root:  bash tests/test-doctor.sh
# =============================================================================
set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
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

# --- fixture builders --------------------------------------------------------

# mkvault <name> : creates $FIX/<name> with .chains/{config.json,journal.jsonl,snapshots/}
mkvault() {
    local v="$FIX/$1"
    mkdir -p "$v/.chains/snapshots"
    printf '%s' "$v"
}

# mkblob <vault> <bytes> : writes content-addressed blob, echoes sha256
mkblob() {
    local v="$1" content="$2"
    local sha
    sha="$(printf '%s' "$content" | sha256sum | awk '{print $1}')"
    printf '%s' "$content" > "$v/.chains/snapshots/$sha"
    printf '%s' "$sha"
}

# commit_entry <id> <parent> <ts> <msg> <files_json> : one journal.jsonl line
commit_entry() {
    python3 -c '
import json,sys
print(json.dumps({"id":sys.argv[1],"parent":sys.argv[2],"ts":sys.argv[3],
                  "message":sys.argv[4],"files":json.loads(sys.argv[5])}))' \
        "$1" "$2" "$3" "$4" "$5"
}

# mint_id <parent> <ts> <msg> <files_json> : engine-identical commit id.
# Mirrors vault.ps1 New-SaveCommitId: sha256("<parent>|<ts>|<msg>|
# <sorted key=sha256 list joined by ,>"), first 12 hex chars. PowerShell's
# Sort-Object is case-insensitive, hence the casefold sort key. Fixture
# ids must be engine-minted so the doctor's id re-derivation check treats
# honest fixtures as clean and only flags genuine tampering.
mint_id() {
    python3 -c '
import hashlib,json,sys
parent,ts,msg=sys.argv[1],sys.argv[2],sys.argv[3]
files=json.loads(sys.argv[4])
tree=",".join(sorted(("%s=%s"%(f["key"],f["sha256"]) for f in files),key=str.casefold))
print(hashlib.sha256(("%s|%s|%s|%s"%(parent,ts,msg,tree)).encode("utf-8")).hexdigest()[:12])' \
        "$1" "$2" "$3" "$4"
}

iso_now()     { python3 -c 'from datetime import datetime,timezone; print(datetime.now(timezone.utc).isoformat())'; }
iso_days_ago() { python3 -c 'from datetime import datetime,timezone,timedelta; print((datetime.now(timezone.utc)-timedelta(days=int(__import__("sys").argv[1]))).isoformat())' "$1"; }

write_config() {  # write_config <vault> <json>
    printf '%s' "$2" > "$1/.chains/config.json"
}

# snapshot_fixture <vault> : sha256 of every file, for the read-only assertion
snapshot_fixture() {
    ( cd "$1" && find .chains -type f -exec sha256sum {} + | sort )
}

FIX="$(mktemp -d)"
trap 'rm -rf "$FIX"' EXIT
export CHAINS_DOCTOR_MIN_FREE_MB=1  # fixtures live on small tmpfs; keep the disk check green

# --- fixture 1: healthy ------------------------------------------------------
V1="$(mkvault healthy)"
W1="$V1/saves"; mkdir -p "$W1"
printf 'SAVE-A' > "$W1/game.srm"
printf 'SAVE-B' > "$W1/game.sav"
SHA_A="$(mkblob "$V1" 'SAVE-A')"
SHA_B="$(mkblob "$V1" 'SAVE-B')"
write_config "$V1" "$(python3 - "$W1" "$(iso_now)" <<'PY'
import json,sys
print(json.dumps({"version":1,"created":sys.argv[2],"watchPaths":[sys.argv[1]],
  "remotePins":{"usb|vault-1":{"fingerprint":"abc","ids":["c1","c2"],"when":sys.argv[2]}}}))
PY
)"
FILES1="$(python3 - "$W1" "$SHA_A" "$SHA_B" <<'PY'
import json,sys
w=sys.argv[1]
print(json.dumps([
  {"key":w+"::game.srm","rel":"game.srm","sha256":sys.argv[2],"bytes":6},
  {"key":w+"::game.sav","rel":"game.sav","sha256":sys.argv[3],"bytes":6}]))
PY
)"
TS1A="$(iso_now)"; TS1B="$(iso_now)"
ID1A="$(mint_id "" "$TS1A" "first" "$FILES1")"
ID1B="$(mint_id "$ID1A" "$TS1B" "second" "$FILES1")"
commit_entry "$ID1A" "" "$TS1A" "first" "$FILES1" > "$V1/.chains/journal.jsonl"
commit_entry "$ID1B" "$ID1A" "$TS1B" "second" "$FILES1" >> "$V1/.chains/journal.jsonl"

# --- fixture 2: dangling parent ref -------------------------------------------
V2="$(mkvault dangling)"
SHA_C="$(mkblob "$V2" 'SAVE-C')"
write_config "$V2" '{"version":1,"created":"2026-09-01T00:00:00+00:00","watchPaths":[]}'
F2="$(python3 - "$SHA_C" <<'PY'
import json,sys
print(json.dumps([{"key":"w::x.srm","rel":"x.srm","sha256":sys.argv[1],"bytes":6}]))
PY
)"
TS2A="$(iso_now)"; TS2B="$(iso_now)"
ID2A="$(mint_id "" "$TS2A" "first" "$F2")"
# the bad entry's id is honestly derived FROM its bogus parent, so the only
# finding is the dangling ref -- not an id mismatch.
ID2B="$(mint_id "nope-not-a-real-parent" "$TS2B" "bad" "$F2")"
commit_entry "$ID2A" "" "$TS2A" "first" "$F2" > "$V2/.chains/journal.jsonl"
commit_entry "$ID2B" "nope-not-a-real-parent" "$TS2B" "bad" "$F2" >> "$V2/.chains/journal.jsonl"

# --- fixture 3: missing pins (synced vault, pins wiped) -----------------------
V3="$(mkvault missingpin)"
SHA_D="$(mkblob "$V3" 'SAVE-D')"
write_config "$V3" '{"version":1,"created":"2026-09-01T00:00:00+00:00","watchPaths":[],"syncVaultId":"vault-3"}'
F3="$(python3 - "$SHA_D" <<'PY'
import json,sys
print(json.dumps([{"key":"w::y.srm","rel":"y.srm","sha256":sys.argv[1],"bytes":6}]))
PY
)"
TS3="$(iso_now)"
ID3="$(mint_id "" "$TS3" "first" "$F3")"
commit_entry "$ID3" "" "$TS3" "first" "$F3" > "$V3/.chains/journal.jsonl"

# --- fixture 4: stale sync ----------------------------------------------------
V4="$(mkvault stale)"
SHA_E="$(mkblob "$V4" 'SAVE-E')"
write_config "$V4" "$(python3 - "$(iso_days_ago 30)" <<'PY'
import json,sys
when=sys.argv[1]
print(json.dumps({"version":1,"created":when,"watchPaths":[],
  "remotePins":{"usb|vault-4":{"fingerprint":"abc","ids":["a1b2c3d4e5f6"],"when":when}}}))
PY
)"
F4="$(python3 - "$SHA_E" <<'PY'
import json,sys
print(json.dumps([{"key":"w::z.srm","rel":"z.srm","sha256":sys.argv[1],"bytes":6}]))
PY
)"
TS4="$(iso_now)"
ID4="$(mint_id "" "$TS4" "first" "$F4")"
commit_entry "$ID4" "" "$TS4" "first" "$F4" > "$V4/.chains/journal.jsonl"

# --- fixture 5: broken journal line --------------------------------------------
V5="$(mkvault broken)"
write_config "$V5" '{"version":1,"created":"2026-09-01T00:00:00+00:00","watchPaths":[]}'
ID5="$(mint_id "" "" "" "[]")"
{ echo "{\"id\":\"$ID5\",\"parent\":\"\",\"files\":[]}"; echo 'this is not json{'; } > "$V5/.chains/journal.jsonl"

# --- fixture 6: working-tree drift (played but uncommitted) ------------------
V6="$(mkvault drift)"
W6="$V6/saves"; mkdir -p "$W6"
printf 'SAVE-F' > "$W6/game.srm"
printf 'SAVE-G' > "$W6/game.sav"
SHA_F="$(mkblob "$V6" 'SAVE-F')"
SHA_G="$(mkblob "$V6" 'SAVE-G')"
write_config "$V6" "$(python3 - "$W6" "$(iso_now)" <<'PY'
import json,sys
print(json.dumps({"version":1,"created":sys.argv[2],"watchPaths":[sys.argv[1]],
  "remotePins":{"usb|vault-6":{"fingerprint":"abc","ids":["c1","c2"],"when":sys.argv[2]}}}))
PY
)"
FILES6="$(python3 - "$W6" "$SHA_F" "$SHA_G" <<'PY'
import json,sys
w=sys.argv[1]
print(json.dumps([
  {"key":w+"::game.srm","rel":"game.srm","sha256":sys.argv[2],"bytes":6},
  {"key":w+"::game.sav","rel":"game.sav","sha256":sys.argv[3],"bytes":6}]))
PY
)"
TS6A="$(iso_now)"; TS6B="$(iso_now)"
ID6A="$(mint_id "" "$TS6A" "first" "$FILES6")"
ID6B="$(mint_id "$ID6A" "$TS6B" "second" "$FILES6")"
commit_entry "$ID6A" "" "$TS6A" "first" "$FILES6" > "$V6/.chains/journal.jsonl"
commit_entry "$ID6B" "$ID6A" "$TS6B" "second" "$FILES6" >> "$V6/.chains/journal.jsonl"
# ...then the player keeps playing: the live .srm no longer matches HEAD.
printf 'SAVE-F-PLAYED-ON' > "$W6/game.srm"

# --- fixture 7: untracked saves (played a new game, never committed) ----------
V7="$(mkvault untracked)"
W7="$V7/saves"; mkdir -p "$W7/sub"
printf 'SAVE-H' > "$W7/game.srm"
printf 'SAVE-NEW-GAME' > "$W7/newgame.srm"      # never committed, flat
printf 'SAVE-NEW-STATE' > "$W7/sub/secret.state"  # never committed, nested
SHA_H="$(mkblob "$V7" 'SAVE-H')"
write_config "$V7" "$(python3 - "$W7" "$(iso_now)" <<'PY'
import json,sys
print(json.dumps({"version":1,"created":sys.argv[2],"watchPaths":[sys.argv[1]],
  "remotePins":{"usb|vault-7":{"fingerprint":"abc","ids":["c1"],"when":sys.argv[2]}}}))
PY
)"
FILES7="$(python3 - "$W7" "$SHA_H" <<'PY'
import json,sys
w=sys.argv[1]
print(json.dumps([{"key":w+"::game.srm","rel":"game.srm","sha256":sys.argv[2],"bytes":6}]))
PY
)"
TS7="$(iso_now)"
ID7="$(mint_id "" "$TS7" "first" "$FILES7")"
commit_entry "$ID7" "" "$TS7" "first" "$FILES7" > "$V7/.chains/journal.jsonl"

# --- fixture 8: journal tampering (message edited after commit) ----------------
# The entry's id was minted honestly, then the message was rewritten by
# hand. Parent refs, id format, and blob hashes all still look intact --
# only the id re-derivation check catches the edit. Mirrors the Pester
# "detects journal tampering" case for `chains.ps1 verify`.
V8="$(mkvault tampered)"
W8="$V8/saves"; mkdir -p "$W8"
printf 'SAVE-T' > "$W8/game.srm"
SHA_T="$(mkblob "$V8" 'SAVE-T')"
write_config "$V8" '{"version":1,"created":"2026-09-01T00:00:00+00:00","watchPaths":[]}'
FT="$(python3 - "$W8" "$SHA_T" <<'PY'
import json,sys
w=sys.argv[1]
print(json.dumps([{"key":w+"::game.srm","rel":"game.srm","sha256":sys.argv[2],"bytes":6}]))
PY
)"
TS8="$(iso_now)"
ID8="$(mint_id "" "$TS8" "honest message" "$FT")"
commit_entry "$ID8" "" "$TS8" "honest message" "$FT" | \
  python3 -c 'import json,sys; e=json.loads(sys.stdin.read()); e["message"]="forged message"; print(json.dumps(e))' \
  > "$V8/.chains/journal.jsonl"

# --- fixture 9: malformed pins (auto-repairable by --fix) --------------------
# One good pin plus two malformed ones (a non-object, and an object with no
# pinned ids). The journal itself is honest and complete, so the ONLY
# failures are the pins -- --fix must remove exactly the bad entries and
# leave the good pin untouched.
V9="$(mkvault malformedpin)"
W9="$V9/saves"; mkdir -p "$W9"
printf 'SAVE-P' > "$W9/game.srm"
SHA_P="$(mkblob "$V9" 'SAVE-P')"
write_config "$V9" "$(python3 - "$(iso_now)" <<'PY'
import json,sys
when=sys.argv[1]
print(json.dumps({"version":1,"created":when,"watchPaths":[],"syncVaultId":"vault-9",
  "remotePins":{"usb|vault-9":{"fingerprint":"abc","ids":["c1"],"when":when},
                "bad|vault-9":"not-an-object",
                "noids|vault-9":{"fingerprint":"abc","when":when}}}))
PY
)"
F9="$(python3 - "$W9" "$SHA_P" <<'PY'
import json,sys
w=sys.argv[1]
print(json.dumps([{"key":w+"::game.srm","rel":"game.srm","sha256":sys.argv[2],"bytes":6}]))
PY
)"
TS9="$(iso_now)"
ID9="$(mint_id "" "$TS9" "first" "$F9")"
commit_entry "$ID9" "" "$TS9" "first" "$F9" > "$V9/.chains/journal.jsonl"

# --- fixture 10: orphan snapshot (auto-repairable by --fix) --------------------
# Healthy vault with an extra unreferenced blob on disk. --fix must MOVE it
# into the repair backup (recoverable) rather than delete it.
V10="$(mkvault orphansnap)"
W10="$V10/saves"; mkdir -p "$W10"
printf 'SAVE-Q' > "$W10/game.srm"
SHA_Q="$(mkblob "$V10" 'SAVE-Q')"
write_config "$V10" '{"version":1,"created":"2026-09-01T00:00:00+00:00","watchPaths":[]}'
F10="$(python3 - "$W10" "$SHA_Q" <<'PY'
import json,sys
w=sys.argv[1]
print(json.dumps([{"key":w+"::game.srm","rel":"game.srm","sha256":sys.argv[2],"bytes":6}]))
PY
)"
TS10="$(iso_now)"
ID10="$(mint_id "" "$TS10" "first" "$F10")"
commit_entry "$ID10" "" "$TS10" "first" "$F10" > "$V10/.chains/journal.jsonl"
printf 'ORPHAN-BYTES' > "$V10/.chains/snapshots/orphan0123456789"

# --- run the doctor ------------------------------------------------------------
echo ""
echo "  chains doctor regression tests"
echo "  ================================================================"

run_doctor() {  # run_doctor <vault> : sets OUT and CODE; asserts read-only
    local v="$1"
    local before after
    before="$(snapshot_fixture "$v")"
    OUT="$("$DOCTOR" "$v" 2>&1)"
    CODE=$?
    after="$(snapshot_fixture "$v")"
    if [ "$before" = "$after" ]; then
        pass "doctor is read-only on $(basename "$v")"
    else
        fail "doctor modified files in $(basename "$v")"
    fi
}

run_doctor "$V1"
assert_exit 0 "$CODE" "healthy vault"
assert_contains "$OUT" "vault is healthy" "healthy vault report"

run_doctor "$V2"
assert_exit 2 "$CODE" "dangling parent ref"
assert_contains "$OUT" "dangling parent ref" "dangling parent reported"

run_doctor "$V3"
assert_exit 1 "$CODE" "missing pins"
assert_contains "$OUT" "no pins are recorded" "missing pins reported"

run_doctor "$V4"
assert_exit 1 "$CODE" "stale sync"
assert_contains "$OUT" "older than" "stale sync reported"

run_doctor "$V5"
assert_exit 2 "$CODE" "broken journal line"
assert_contains "$OUT" "not valid JSON" "broken journal reported"

run_doctor "$V6"
assert_exit 1 "$CODE" "working-tree drift"
assert_contains "$OUT" "uncommitted changes" "drift reported"
assert_contains "$OUT" "game.srm" "drifted file named"

run_doctor "$V7"
assert_exit 1 "$CODE" "untracked saves"
assert_contains "$OUT" "not tracked in HEAD" "untracked saves reported"
assert_contains "$OUT" "newgame.srm" "untracked flat save named"
assert_contains "$OUT" "sub/secret.state" "untracked nested save named"

run_doctor "$V8"
assert_exit 2 "$CODE" "journal tampering"
assert_contains "$OUT" "fails the integrity check" "tamper reported"
assert_contains "$OUT" "id re-derivation mismatch" "tamper detail reported"

run_doctor "$V9"
assert_exit 2 "$CODE" "malformed pins"
assert_contains "$OUT" "pin 'bad|vault-9' is malformed" "non-object pin reported"
assert_contains "$OUT" "pin 'noids|vault-9' has no pinned commit ids" "no-ids pin reported"

run_doctor "$V10"
assert_exit 1 "$CODE" "orphan snapshot"
assert_contains "$OUT" "orphan snapshot" "orphan reported"
assert_contains "$OUT" "orphan0123456789" "orphan named"

# --- --fix: safe, reversible auto-repairs --------------------------------------
# Default runs stay read-only (asserted above for every fixture). --fix is
# the one write path: it repairs malformed pins + orphan snapshots, takes a
# pre-repair backup first, and writes nothing when nothing is repairable.

# --fix on the healthy vault: nothing to repair -> no backup, no writes.
OUT_FIX="$("$DOCTOR" --fix "$V1" 2>&1)"; CODE_FIX=$?
assert_exit 0 "$CODE_FIX" "--fix on healthy vault"
assert_contains "$OUT_FIX" "no auto-repairable issues found" "--fix finds nothing to repair"
if [ -d "$V1/.chains/repair-backups" ]; then fail "--fix on healthy vault creates no backup dir"; else pass "--fix on healthy vault creates no backup dir"; fi

# --fix on the tampered vault: tamper is NOT auto-repairable -> no writes.
BEFORE_T="$(snapshot_fixture "$V8")"
OUT_FIX_T="$("$DOCTOR" --fix "$V8" 2>&1)"; CODE_FIX_T=$?
AFTER_T="$(snapshot_fixture "$V8")"
assert_exit 2 "$CODE_FIX_T" "--fix on tampered vault keeps the error verdict"
assert_contains "$OUT_FIX_T" "no auto-repairable issues found" "--fix does not repair tampering"
if [ "$BEFORE_T" = "$AFTER_T" ] && [ ! -d "$V8/.chains/repair-backups" ]; then
    pass "--fix writes nothing on unrepairable vault"
else
    fail "--fix writes nothing on unrepairable vault"
fi

# --fix on the malformed-pins vault: bad pins removed, good pin kept.
OUT_FIX_P="$("$DOCTOR" --fix "$V9" 2>&1)"; CODE_FIX_P=$?
assert_exit 2 "$CODE_FIX_P" "--fix exit still reflects the pre-repair scan"
assert_contains "$OUT_FIX_P" "removed malformed remote pin 'bad|vault-9'" "--fix removes non-object pin"
assert_contains "$OUT_FIX_P" "removed malformed remote pin 'noids|vault-9'" "--fix removes no-ids pin"
assert_contains "$OUT_FIX_P" "repair backup:" "--fix reports the backup location"
BACKUP_P="$(find "$V9/.chains/repair-backups" -mindepth 1 -maxdepth 1 -type d | head -1)"
if [ -n "$BACKUP_P" ]; then pass "--fix created a timestamped repair backup"; else fail "--fix created a timestamped repair backup"; fi
# the backup is a true pre-repair snapshot: the original config still has the bad pins
if [ -n "$BACKUP_P" ] && grep -q 'bad|vault-9' "$BACKUP_P/config.json" && grep -q 'noids|vault-9' "$BACKUP_P/config.json"; then
    pass "backup holds the pre-repair config.json (reversible)"
else
    fail "backup holds the pre-repair config.json (reversible)"
fi
if [ -n "$BACKUP_P" ] && [ -f "$BACKUP_P/repairs.json" ] && grep -q '"kind": "pin"' "$BACKUP_P/repairs.json"; then
    pass "backup holds a repairs.json manifest"
else
    fail "backup holds a repairs.json manifest"
fi
# live config: good pin survives, bad pins gone, config still parses
PINS_LEFT="$(python3 -c 'import json,sys; print(" ".join(sorted(json.load(open(sys.argv[1]))["remotePins"])))' "$V9/.chains/config.json" 2>&1)"
if [ "$PINS_LEFT" = "usb|vault-9" ]; then pass "--fix kept only the good pin"; else fail "--fix kept only the good pin (got: $PINS_LEFT)"; fi
# re-run: the pin findings are gone, vault is clean
OUT_RERUN="$("$DOCTOR" "$V9" 2>&1)"; CODE_RERUN=$?
assert_exit 0 "$CODE_RERUN" "re-run after --fix is healthy"
assert_contains "$OUT_RERUN" "vault is healthy" "re-run confirms health"

# --fix on the orphan-snapshot vault: orphan moved into the backup, never deleted.
OUT_FIX_O="$("$DOCTOR" --fix "$V10" 2>&1)"; CODE_FIX_O=$?
assert_contains "$OUT_FIX_O" "moved orphan snapshot orphan0123456789 into the repair backup" "--fix moves the orphan"
BACKUP_O="$(find "$V10/.chains/repair-backups" -mindepth 1 -maxdepth 1 -type d | head -1)"
if [ -n "$BACKUP_O" ] && [ ! -f "$V10/.chains/snapshots/orphan0123456789" ] && \
   [ "$(cat "$BACKUP_O/orphans/orphan0123456789" 2>/dev/null)" = "ORPHAN-BYTES" ]; then
    pass "--fix moved the orphan (recoverable, not deleted)"
else
    fail "--fix moved the orphan (recoverable, not deleted)"
fi
# committed blobs are untouched; re-run no longer warns about the orphan
if [ -f "$V10/.chains/snapshots/$SHA_Q" ]; then pass "--fix left committed blobs in place"; else fail "--fix left committed blobs in place"; fi
OUT_RERUN_O="$("$DOCTOR" "$V10" 2>&1)"
if printf '%s' "$OUT_RERUN_O" | grep -q "orphan snapshot"; then
    fail "re-run no longer warns about the orphan"
else
    pass "re-run no longer warns about the orphan"
fi

# doctor must refuse a non-vault
OUT_BAD="$("$DOCTOR" "$FIX" 2>&1)"; CODE_BAD=$?
assert_exit 2 "$CODE_BAD" "non-vault rejected"

# --- --json: machine-readable report ------------------------------------------
run_doctor_json() {  # run_doctor_json <vault> : sets JOUT and JCODE; asserts read-only
    local v="$1"
    local before after
    before="$(snapshot_fixture "$v")"
    JOUT="$("$DOCTOR" --json "$v" 2>&1)"
    JCODE=$?
    after="$(snapshot_fixture "$v")"
    if [ "$before" = "$after" ]; then
        pass "--json is read-only on $(basename "$v")"
    else
        fail "--json modified files in $(basename "$v")"
    fi
}

json_field() {  # json_field <json> <expr> : prints the evaluated field
    python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print('"$2"')' "$1" 2>/dev/null
}

run_doctor_json "$V1"
assert_exit 0 "$JCODE" "--json on healthy vault"
# stdout must be exactly one JSON document (scriptable): no banner, no chatter.
if printf '%s' "$JOUT" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
    pass "--json emits a single valid JSON document"
else
    fail "--json emits a single valid JSON document"
fi
[ "$(json_field "$JOUT" 'd["result"]')" = "healthy" ] && pass "--json result=healthy" || fail "--json result=healthy"
[ "$(json_field "$JOUT" 'd["exit"]')" = "0" ] && pass "--json exit mirrors exit code" || fail "--json exit mirrors exit code"
[ "$(json_field "$JOUT" 'd["summary"]["commit_count"]')" = "2" ] && pass "--json summary commit_count" || fail "--json summary commit_count"
[ "$(json_field "$JOUT" 'd["summary"]["blob_count"]')" = "2" ] && pass "--json summary blob_count" || fail "--json summary blob_count"
[ "$(json_field "$JOUT" 'd["summary"]["pin_count"]')" = "1" ] && pass "--json summary pin_count" || fail "--json summary pin_count"
[ "$(json_field "$JOUT" 'd["summary"]["head"]')" = "$ID1B" ] && pass "--json summary head id" || fail "--json summary head id"
# every finding has severity + message, severity drawn from the known set
if python3 - "$JOUT" <<'PY' 2>/dev/null; then
import json,sys
d=json.loads(sys.argv[1])
assert isinstance(d["findings"], list) and d["findings"], "no findings"
for f in d["findings"]:
    assert set(f) >= {"severity","message"}, "finding missing keys"
    assert f["severity"] in {"ok","warn","fail","info"}, "bad severity"
PY
    pass "--json findings schema"
else
    fail "--json findings schema"
fi
# human-only text must not leak into --json output
if printf '%s' "$JOUT" | grep -qE '^\s*(\[OK\]|\[FAIL\]|\[~\]|\[i\]|chains doctor --)'; then
    fail "--json has no human-format lines"
else
    pass "--json has no human-format lines"
fi

run_doctor_json "$V2"
assert_exit 2 "$JCODE" "--json on error vault"
[ "$(json_field "$JOUT" 'd["result"]')" = "errors" ] && pass "--json result=errors" || fail "--json result=errors"
if printf '%s' "$JOUT" | grep -q '"severity": "fail"'; then
    pass "--json carries fail findings"
else
    fail "--json carries fail findings"
fi

run_doctor_json "$V4"
assert_exit 1 "$JCODE" "--json on warning vault"
[ "$(json_field "$JOUT" 'd["result"]')" = "warnings" ] && pass "--json result=warnings" || fail "--json result=warnings"

run_doctor_json "$V6"
assert_exit 1 "$JCODE" "--json on drift vault"
[ "$(json_field "$JOUT" 'd["result"]')" = "warnings" ] && pass "--json drift result=warnings" || fail "--json drift result=warnings"
if printf '%s' "$JOUT" | python3 -c '
import json,sys
d=json.loads(sys.stdin.read())
warns=[f for f in d["findings"] if f["severity"]=="warn" and "uncommitted changes" in f["message"]]
assert warns, "no drift finding in --json"'; then
    pass "--json carries the drift finding"
else
    fail "--json carries the drift finding"
fi

run_doctor_json "$V7"
assert_exit 1 "$JCODE" "--json on untracked-saves vault"
[ "$(json_field "$JOUT" 'd["result"]')" = "warnings" ] && pass "--json untracked result=warnings" || fail "--json untracked result=warnings"
if printf '%s' "$JOUT" | python3 -c '
import json,sys
d=json.loads(sys.stdin.read())
warns=[f for f in d["findings"] if f["severity"]=="warn" and "not tracked in HEAD" in f["message"]]
assert len(warns) == 2, "expected 2 untracked findings, got %d" % len(warns)
assert any("newgame.srm" in f["message"] for f in warns), "flat untracked save missing"
assert any("sub/secret.state" in f["message"] for f in warns), "nested untracked save missing"'; then
    pass "--json carries both untracked findings"
else
    fail "--json carries both untracked findings"
fi

run_doctor_json "$V8"
assert_exit 2 "$JCODE" "--json on tampered vault"
[ "$(json_field "$JOUT" 'd["result"]')" = "errors" ] && pass "--json tampered result=errors" || fail "--json tampered result=errors"
if printf '%s' "$JOUT" | python3 -c '
import json,sys
d=json.loads(sys.stdin.read())
fails=[f for f in d["findings"] if f["severity"]=="fail" and "integrity check" in f["message"]]
assert fails, "no tamper finding in --json"'; then
    pass "--json carries the tamper finding"
else
    fail "--json carries the tamper finding"
fi

echo ""
echo "  $PASS passed, $FAIL failed."
[ "$FAIL" -eq 0 ]
