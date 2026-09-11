#!/usr/bin/env bash
# =============================================================================
# chains sync plan -- read-only preview of what a push/fetch would transfer.
#
# Answers "what would sync do?" without doing it: shows the exact commit ids
# and blobs a push would upload / a fetch would download, the pin/rollback
# verdict a real sync would compute, and anything that would make the sync
# fail (missing blobs, a rolled-back remote, a tampered journal).
#
# READ-ONLY: this script never creates, modifies, or deletes anything inside
# (or outside) the vault or the remote -- the plan contract holds and the
# fixture suite asserts it. No network code, no installs; the local
# filesystem remote is the only backend this previews.
#
# Usage: bash scripts/chains-sync-plan.sh <vault-root> <remote-root>
#            [--direction push|fetch|both] [--json]
#
#   vault-root   Directory containing .chains/ (default: current dir).
#   remote-root  Root of the local-filesystem remote (<remote>/vaults/<vault-id>/).
#   --direction  Which side of the sync to plan: push (local->remote),
#                fetch (remote->local), or both (default: both).
#   --json       Machine-readable plan document on stdout, same verdicts.
#
# Exit codes: 0 = plan is clean (sync would succeed), 1 = warnings only
# (e.g. remote has no data for this vault yet -- push first), 2 = errors
# (a real sync would abort: pin rollback violation, same-id-different-bytes
# collision, missing blobs, unparseable journal).
# Needs: bash, python3 (stdlib only), sha256sum.
# =============================================================================
set -u

VAULT="."
REMOTE=""
DIRECTION="both"
JSON=0

usage() {
    echo "Usage: $(basename "$0") <vault-root> <remote-root> [--direction push|fetch|both] [--json]"
    echo ""
    echo "  vault-root   Directory containing .chains/ (default: current dir)."
    echo "  remote-root  Root of the local-filesystem remote."
    echo "  --direction  Plan a push, a fetch, or both (default: both)."
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --direction)
            [ $# -lt 2 ] && usage
            DIRECTION="$2"; shift 2 ;;
        --direction=*)
            DIRECTION="${1#--direction=}"; shift ;;
        --json)
            JSON=1; shift ;;
        --help|-h)
            usage ;;
        -*)
            echo "Unknown option: $1" >&2; usage ;;
        *)
            if [ "$VAULT" = "." ]; then VAULT="$1"; else REMOTE="$1"; fi
            shift ;;
    esac
done

[ -z "$REMOTE" ] && { echo "Missing <remote-root>." >&2; usage; }
case "$DIRECTION" in push|fetch|both) ;; *) echo "Bad --direction: $DIRECTION" >&2; usage ;; esac

export CHAINS_PLAN_VAULT="$VAULT"
export CHAINS_PLAN_REMOTE="$REMOTE"
export CHAINS_PLAN_DIRECTION="$DIRECTION"
export CHAINS_PLAN_JSON="$JSON"

python3 - <<'PY'
import json, os, sys
from datetime import datetime, timezone

vault   = os.environ["CHAINS_PLAN_VAULT"]
remote  = os.environ["CHAINS_PLAN_REMOTE"]
direction = os.environ["CHAINS_PLAN_DIRECTION"]
as_json = os.environ["CHAINS_PLAN_JSON"] == "1"

findings = []   # (severity, message)  severity: ok|warn|fail|info

def emit(sev, msg):
    findings.append({"severity": sev, "message": msg})

def human_bytes(n):
    for u in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or u == "GiB":
            return "%d %s" % (n, u) if u == "B" else "%.1f %s" % (n, u)
        n /= 1024.0

chains = os.path.join(vault, ".chains")
config_path  = os.path.join(chains, "config.json")
journal_path = os.path.join(chains, "journal.jsonl")
snaps_dir    = os.path.join(chains, "snapshots")

config = None
if os.path.isfile(config_path):
    try:
        config = json.load(open(config_path, encoding="utf-8"))
        if not isinstance(config, dict):
            emit("fail", "config.json is not a JSON object")
            config = None
    except Exception:
        emit("fail", "config.json is not valid JSON")
else:
    emit("fail", "config.json missing -- not a chains vault")

vault_id = None
if config is not None:
    vault_id = config.get("syncVaultId") or config.get("id")
    if not vault_id:
        emit("fail", "config.json has no vault id (need 'id' or 'syncVaultId')")

def read_journal(path, label, required=True):
    """Returns (entries, ok). A missing required journal is a fail finding;
    a missing optional (remote) journal means the remote has no data."""
    if not os.path.isfile(path):
        if required:
            emit("fail", "%s missing -- not a chains vault" % label)
            return ([], False)
        return ([], True)
    entries, ok = [], True
    try:
        with open(path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    emit("fail", "%s line %d is not valid JSON" % (label, lineno))
                    ok = False
                    continue
                if not isinstance(e, dict) or "id" not in e:
                    emit("fail", "%s line %d: entry without id" % (label, lineno))
                    ok = False
                    continue
                entries.append(e)
    except OSError as ex:
        emit("fail", "%s unreadable: %s" % (label, ex))
        return ([], False)
    seen = set()
    for e in entries:
        if e["id"] in seen:
            emit("fail", "%s: duplicate commit id %s" % (label, e["id"]))
            ok = False
        seen.add(e["id"])
    return (entries, ok)

local_entries, local_ok = ([], False)
remote_entries, remote_ok = ([], True)
remote_exists = False

if vault_id:
    local_entries, local_ok = read_journal(journal_path, "local journal", required=True)
    rdir = os.path.join(remote, "vaults", vault_id)
    rjournal = os.path.join(rdir, "journal.jsonl")
    rblobs   = os.path.join(rdir, "blobs")
    remote_exists = os.path.isdir(rdir) and os.path.isfile(rjournal)
    if remote_exists:
        remote_entries, remote_ok = read_journal(rjournal, "remote journal", required=True)
    else:
        if direction in ("fetch", "both"):
            emit("warn", "remote has no data for this vault yet -- push first")
        else:
            emit("info", "remote has no data for this vault yet -- this push would seed it")

def canon(e):
    return json.dumps(e, sort_keys=True, separators=(",", ":"))

local_by_id  = {e["id"]: e for e in local_entries}
remote_by_id = {e["id"]: e for e in remote_entries}

# ---- same-id-different-bytes is corruption, not a conflict (mirrors Merge-JournalFile)
collisions = 0
for cid in set(local_by_id) & set(remote_by_id):
    if canon(local_by_id[cid]) != canon(remote_by_id[cid]):
        emit("fail", "commit %s collides with different content on remote -- "
                     "possible tampering; a real sync would abort" % cid)
        collisions += 1

# ---- pin / rollback verdict (mirrors Test-RemotePin)
pin_state = "none"
if config is not None and vault_id:
    pins = config.get("remotePins")
    if isinstance(pins, dict):
        key = "%s|%s" % (remote, vault_id)
        pin = pins.get(key)
        if isinstance(pin, dict) and isinstance(pin.get("ids"), list):
            pin_state = "pinned"
            remote_ids = set(remote_by_id)
            missing = [i for i in pin["ids"] if i not in remote_ids]
            if missing and remote_exists:
                emit("fail", "remote journal is missing %d pinned commit id(s) from a "
                             "previous sync (e.g. %s) -- possible rollback or replay; "
                             "a real sync would abort before any state changes" %
                             (len(missing), missing[0]))
            elif not remote_exists:
                emit("warn", "pin exists for this remote but the remote has no data -- "
                             "a wiped/rebuilt remote must be re-trusted first (see SYNC.md)")
        elif pin is not None:
            emit("warn", "pin entry for this remote is malformed -- "
                         "`chains-doctor.sh --fix` repairs it; a real sync may re-pin")
    if pin_state == "none" and remote_exists:
        emit("info", "no pin for this remote yet -- first contact is trusted (TOFU), "
                     "then pinned on success (see SYNC.md)")

# ---- blob existence helpers
def blob_info(dirpath, sha):
    p = os.path.join(dirpath, sha)
    return os.path.getsize(p) if os.path.isfile(p) else None

push = {"entries": [], "blobs": [], "bytes": 0}
fetch = {"entries": [], "blobs": [], "bytes": 0}

def entry_label(e):
    return "%s (%s)" % (e["id"], e.get("msg") or e.get("message") or "?")

if vault_id and local_ok and remote_ok and collisions == 0:
    if direction in ("push", "both"):
        for e in local_entries:
            if e["id"] in remote_by_id:
                continue
            push["entries"].append(e)
            for f in (e.get("files") or []):
                sha = f.get("sha256")
                if not sha:
                    continue
                local_sz = blob_info(snaps_dir, sha)
                if local_sz is None:
                    emit("fail", "local blob missing for %s -- a real push would abort; run verify" %
                                 (f.get("rel") or sha))
                    continue
                if (not remote_exists) or blob_info(rblobs, sha) is None:
                    push["blobs"].append({"rel": f.get("rel"), "sha256": sha, "bytes": local_sz})
                    push["bytes"] += local_sz
    if direction in ("fetch", "both"):
        for e in remote_entries:
            if e["id"] in local_by_id:
                continue
            fetch["entries"].append(e)
            for f in (e.get("files") or []):
                sha = f.get("sha256")
                if not sha:
                    continue
                if blob_info(snaps_dir, sha) is None:
                    if remote_exists:
                        r_sz = blob_info(rblobs, sha)
                        if r_sz is None:
                            emit("fail", "remote blob missing for %s -- remote is corrupt; "
                                         "a real fetch would abort" % (f.get("rel") or sha))
                            continue
                        fetch["blobs"].append({"rel": f.get("rel"), "sha256": sha, "bytes": r_sz})
                        fetch["bytes"] += r_sz
                    # else: remote has no data at all -- the top-level warn already said it

errs  = sum(1 for f in findings if f["severity"] == "fail")
warns = sum(1 for f in findings if f["severity"] == "warn")
result = "errors" if errs else ("warnings" if warns else "healthy")
exit_code = 2 if errs else (1 if warns else 0)

if (not errs and not warns and not push["entries"] and not fetch["entries"]
        and local_ok and remote_ok):
    emit("info", "already in sync -- a real %s would transfer nothing" %
                 ("push" if direction == "push" else "fetch" if direction == "fetch" else "push/fetch"))

plan = {
    "vault": os.path.abspath(vault),
    "remote": remote,
    "vault_id": vault_id,
    "direction": direction,
    "result": result,
    "exit": exit_code,
    "errors": errs,
    "warnings": warns,
    "findings": findings,
    "pin": pin_state,
    "push": {
        "entries": [{"id": e["id"], "msg": e.get("msg") or e.get("message")} for e in push["entries"]],
        "blobs": push["blobs"],
        "bytes": push["bytes"],
    },
    "fetch": {
        "entries": [{"id": e["id"], "msg": e.get("msg") or e.get("message")} for e in fetch["entries"]],
        "blobs": fetch["blobs"],
        "bytes": fetch["bytes"],
    },
}

if as_json:
    print(json.dumps(plan, indent=2))
    sys.exit(exit_code)

def show_block(name, part):
    n_e = len(part["entries"])
    n_b = len(part["blobs"])
    if n_e == 0 and n_b == 0:
        print("  %s: nothing to transfer" % name)
        return
    print("  %s: %d new commit(s), %d new blob(s), %s total" %
          (name, n_e, n_b, human_bytes(part["bytes"])))
    for e in part["entries"]:
        print("    + commit %s (%s)" % (e["id"], e.get("msg") or e.get("message") or "?"))
    for b in part["blobs"]:
        print("    + blob %-64s %s  (%s)" % (b["sha256"], human_bytes(b["bytes"]), b["rel"] or "?"))

print("chains sync plan")
print("  vault : %s" % os.path.abspath(vault))
print("  remote: %s" % remote)
print("  pin   : %s" % pin_state)
if direction in ("push", "both"):
    show_block("push ", plan["push"])
if direction in ("fetch", "both"):
    show_block("fetch", plan["fetch"])
print("")
for f in findings:
    tag = {"ok": "OK", "warn": "WARN", "fail": "FAIL", "info": "i"}[f["severity"]]
    print("  [%s] %s" % (tag, f["message"]))
print("")
print("  result: %s (exit %d) -- read-only, no state was changed" % (result, exit_code))
sys.exit(exit_code)
PY
