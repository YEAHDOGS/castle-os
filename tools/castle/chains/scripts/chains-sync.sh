#!/usr/bin/env bash
# =============================================================================
# chains sync -- the actual push/fetch over the local-filesystem backend.
#
# This is the real sync path behind chains-sync-plan.sh's read-only preview:
# it implements the SYNC.md contract (local filesystem backend) and mirrors
# the PowerShell engine's Push-Chains / Fetch-Chains, Test-RemotePin,
# Set-RemotePin, Merge-JournalFile, and Resolve-SyncVaultId.
#
# Preconditions abort BEFORE any state changes (mirroring the plan's
# verdicts): TOFU pin rollback check, same-id-different-bytes collisions
# (tampering), missing blobs, unparseable journals.
#
# Safety order is deliberate and slightly stricter than the PowerShell
# original: every precondition is verified before the first write, journals
# are rewritten via temp-file + rename (never a partial append), push
# transfers blobs BEFORE rewriting the remote journal (so a failed push
# can never leave the journal referencing missing blobs), and the remote
# pin moves forward ONLY on the success path. Fetched blobs are staged
# to a temp dir and SHA256-checked against the journal BEFORE the local
# journal is extended, so a tampered remote can never leave the vault
# pointing at bad bytes. An aborted fetch leaves no staged files behind.
#
# Usage: bash scripts/chains-sync.sh <vault-root> <remote-root>
#            [--direction push|fetch] [--vault-id <id>]
#
#   --direction  push (local->remote) or fetch (remote->local, default).
#   --vault-id   Explicit remote vault id; wins and is remembered in the
#                vault's config as syncVaultId (so the next bare fetch just
#                works). Otherwise the remembered id, else this vault's id.
#
# Exit codes: 0 = sync succeeded (nothing-to-do included), 2 = aborted
# (rollback/pin violation, collision, missing or tampered blob, bad config).
# Needs: bash, python3 (stdlib only), sha256sum. No network code, no installs.
# =============================================================================
set -u

VAULT="."
REMOTE=""
DIRECTION="fetch"
EXPLICIT_VAULT_ID=""

usage() {
    echo "Usage: $(basename "$0") <vault-root> <remote-root> [--direction push|fetch] [--vault-id <id>]"
    echo ""
    echo "  vault-root   Directory containing .chains/ (default: current dir)."
    echo "  remote-root  Root of the local-filesystem remote."
    echo "  --direction  push (upload to remote) or fetch (download, default)."
    echo "  --vault-id   Explicit remote vault id; remembered in config."
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --direction)
            [ $# -lt 2 ] && usage
            DIRECTION="$2"; shift 2 ;;
        --direction=*)
            DIRECTION="${1#--direction=}"; shift ;;
        --vault-id)
            [ $# -lt 2 ] && usage
            EXPLICIT_VAULT_ID="$2"; shift 2 ;;
        --vault-id=*)
            EXPLICIT_VAULT_ID="${1#--vault-id=}"; shift ;;
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
case "$DIRECTION" in push|fetch) ;; *) echo "Bad --direction: $DIRECTION" >&2; usage ;; esac

export CHAINS_SYNC_VAULT="$VAULT"
export CHAINS_SYNC_REMOTE="$REMOTE"
export CHAINS_SYNC_DIRECTION="$DIRECTION"
export CHAINS_SYNC_VAULT_ID="$EXPLICIT_VAULT_ID"

python3 - <<'PY'
import json, os, shutil, sys, tempfile
from datetime import datetime, timezone

vault     = os.environ["CHAINS_SYNC_VAULT"]
remote    = os.environ["CHAINS_SYNC_REMOTE"]
direction = os.environ["CHAINS_SYNC_DIRECTION"]
explicit_vault_id = os.environ["CHAINS_SYNC_VAULT_ID"]

def die(msg):
    print("  [FAIL] %s -- sync aborted; nothing was changed" % msg)
    sys.exit(2)

def ok(msg):
    print("  [OK] %s" % msg)

def info(msg):
    print("  [i] %s" % msg)

chains       = os.path.join(vault, ".chains")
config_path  = os.path.join(chains, "config.json")
journal_path = os.path.join(chains, "journal.jsonl")
snaps_dir    = os.path.join(chains, "snapshots")

# ---- vault config -----------------------------------------------------------
config = None
if os.path.isfile(config_path):
    try:
        with open(config_path, encoding="utf-8") as fh:
            config = json.load(fh)
        if not isinstance(config, dict):
            die("config.json is not a JSON object")
    except Exception as ex:
        die("config.json is not valid JSON: %s" % ex)
else:
    die("config.json missing -- not a chains vault")

def save_config():
    # temp + rename so a crash never leaves a half-written config
    tmp = config_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, config_path)

# ---- resolve vault id (mirrors Resolve-SyncVaultId) -------------------------
if explicit_vault_id:
    config["syncVaultId"] = explicit_vault_id
    save_config()
    vault_id = explicit_vault_id
else:
    vault_id = config.get("syncVaultId") or config.get("id")
if not vault_id:
    die("config.json has no vault id (need 'id' or 'syncVaultId')")

rdir    = os.path.join(remote, "vaults", vault_id)
rjournal = os.path.join(rdir, "journal.jsonl")
rblobs   = os.path.join(rdir, "blobs")

# ---- journal readers (mirrors Read-JournalFile) -----------------------------
def read_journal(path, label, required):
    if not os.path.isfile(path):
        if required:
            die("%s missing -- not a chains vault" % label)
        return []
    entries = []
    try:
        with open(path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    die("%s line %d is not valid JSON" % (label, lineno))
                if not isinstance(e, dict) or "id" not in e:
                    die("%s line %d: entry without id" % (label, lineno))
                entries.append(e)
    except OSError as ex:
        die("%s unreadable: %s" % (label, ex))
    seen = set()
    for e in entries:
        if e["id"] in seen:
            die("%s: duplicate commit id %s" % (label, e["id"]))
    return entries

local_entries = read_journal(journal_path, "local journal", required=True)
remote_exists = os.path.isdir(rdir) and os.path.isfile(rjournal)
remote_entries = read_journal(rjournal, "remote journal", required=remote_exists) \
    if remote_exists else []

# ---- pin check (mirrors Test-RemotePin) -- abort before ANY write ------------
pin_key = "%s|%s" % (remote, vault_id)
pins = config.get("remotePins")
if isinstance(pins, dict) and isinstance(pins.get(pin_key), dict) \
        and isinstance(pins[pin_key].get("ids"), list):
    if not remote_exists:
        die("pin exists for this remote but the remote has no data -- a "
            "wiped/rebuilt remote must be re-trusted first (see SYNC.md)")
    remote_ids = set(e["id"] for e in remote_entries)
    for pid in pins[pin_key]["ids"]:
        if pid not in remote_ids:
            die("remote journal is missing commit %s pinned on a previous "
                "sync -- possible rollback or replay; sync aborted, vault "
                "and remote untouched" % pid)
else:
    if remote_exists:
        info("no pin for this remote yet -- first contact is trusted (TOFU), "
             "then pinned on success (see SYNC.md)")

# ---- same-id-different-bytes is corruption, not a conflict ------------------
def canon(e):
    return json.dumps(e, sort_keys=True, separators=(",", ":"))

local_by_id  = {e["id"]: e for e in local_entries}
remote_by_id = {e["id"]: e for e in remote_entries}
for cid in set(local_by_id) & set(remote_by_id):
    if canon(local_by_id[cid]) != canon(remote_by_id[cid]):
        die("commit %s collides with different content on remote -- "
            "possible tampering; sync aborted" % cid)

# ---- pin writer (mirrors Set-RemotePin) -- success path only -----------------
def fingerprint(entries):
    ids = sorted(set(e["id"] for e in entries))
    import hashlib
    return hashlib.sha256("\n".join(ids).encode("utf-8")).hexdigest()

def set_pin(entries):
    pins = config.get("remotePins")
    if not isinstance(pins, dict):
        pins = {}
        config["remotePins"] = pins
    pins[pin_key] = {
        "fingerprint": fingerprint(entries),
        "ids": sorted(set(e["id"] for e in entries)),
        "when": datetime.now(timezone.utc).isoformat(),
    }
    save_config()

# ---- merge helper (mirrors Merge-JournalFile) via temp + rename -------------
def merged_entries(base_entries, add_entries):
    known = {e["id"]: canon(e) for e in base_entries}
    new_ones = []
    for e in add_entries:
        if e["id"] in known:
            # collision was already ruled out above; skip known ids
            continue
        known[e["id"]] = canon(e)
        new_ones.append(e)
    new_ones.sort(key=lambda e: (e.get("ts") or "", e["id"]))
    return base_entries + new_ones, len(new_ones)

def write_journal_atomic(path, entries):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e, separators=(",", ":")) + "\n")
    os.replace(tmp, path)

def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def blobs_needed(entries, store_dir):
    """(sha -> rel) for blobs named by the entries but missing locally."""
    need = {}
    for e in entries:
        for f in (e.get("files") or []):
            sha = f.get("sha256")
            if not sha:
                continue
            if not os.path.isfile(os.path.join(store_dir, sha)):
                need[sha] = f.get("rel") or sha
    return need

# ---- push -------------------------------------------------------------------
if direction == "push":
    if not remote_exists:
        info("remote has no data for this vault yet -- this push seeds it")
        os.makedirs(rblobs, exist_ok=True)
        open(rjournal, "a").close()
        remote_entries = []

    # Precondition: every local blob a new entry names must exist locally.
    # Checked BEFORE the remote journal is touched.
    for e in local_entries:
        if e["id"] in remote_by_id:
            continue
        for f in (e.get("files") or []):
            sha = f.get("sha256")
            if sha and not os.path.isfile(os.path.join(snaps_dir, sha)):
                die("local blob missing for %s -- run verify" % (f.get("rel") or sha))

    # Blobs go to the remote BEFORE its journal is rewritten. A push that
    # dies mid-transfer (disk full, permissions, crash) therefore leaves the
    # remote journal describing exactly what is already there -- it can
    # never reference blobs that never arrived. Transfer errors abort
    # cleanly (exit 2) instead of propagating as tracebacks.
    new_ids = {e["id"] for e in local_entries if e["id"] not in remote_by_id}
    shas = []
    for e in local_entries:
        if e["id"] not in new_ids:
            continue
        for f in (e.get("files") or []):
            sha = f.get("sha256")
            if sha and sha not in shas:
                shas.append(sha)

    pushed = 0
    for sha in shas:
        dest = os.path.join(rblobs, sha)
        if os.path.isfile(dest):
            # A blob name is a content hash: an existing blob with
            # different bytes is an integrity violation, never skipped
            # silently.
            if sha256_file(dest) != sha:
                die("remote blob %s exists with different bytes -- remote "
                    "is corrupt; sync aborted" % sha)
            continue
        try:
            shutil.copy2(os.path.join(snaps_dir, sha), dest)
        except OSError as ex:
            die("could not write blob %s to remote: %s -- remote journal "
                "left untouched" % (sha, ex))
        pushed += 1

    new_journal, added = merged_entries(remote_entries, local_entries)
    write_journal_atomic(rjournal, new_journal)

    set_pin(new_journal)  # pin the remote as we just left it -- success only
    ok("pushed to %s: %d new commit(s), %d new blob(s); remote pinned"
       % (remote, added, pushed))
    sys.exit(0)

# ---- fetch ------------------------------------------------------------------
if not remote_exists:
    info("remote has no data for this vault yet -- push first")
    ok("fetch from %s: 0 new commit(s), 0 new blob(s)" % remote)
    sys.exit(0)

# Precondition: every remote blob a new entry names must exist on the remote.
for e in remote_entries:
    if e["id"] in local_by_id:
        continue
    for f in (e.get("files") or []):
        sha = f.get("sha256")
        if sha and not os.path.isfile(os.path.join(rblobs, sha)):
            die("remote blob missing for %s -- remote is corrupt"
                % (f.get("rel") or sha))

need = blobs_needed(remote_entries, snaps_dir)

# Stage + hash-check every needed blob BEFORE the local journal is extended.
stage = tempfile.mkdtemp(prefix="chains-stage-")
staged = []
try:
    for sha, rel in sorted(need.items()):
        tmp = os.path.join(stage, sha)
        shutil.copy2(os.path.join(rblobs, sha), tmp)
        if sha256_file(tmp) != sha:
            die("remote blob for %s failed its hash check -- remote tampered; "
                "local vault untouched" % rel)
        staged.append((tmp, sha))
except BaseException:
    # Failure path: the journal was never extended -- clean the stage and
    # re-raise so the original abort reason stands. Nothing verified moves.
    shutil.rmtree(stage, ignore_errors=True)
    raise

# Success path: every staged file was hash-checked; move them into the
# snapshot store, then drop the stage.
for tmp, sha in staged:
    dst = os.path.join(snaps_dir, sha)
    if os.path.isfile(dst):
        continue  # already arrived via a sibling entry -- never clobber
    os.replace(tmp, dst)
shutil.rmtree(stage, ignore_errors=True)

new_journal, added = merged_entries(local_entries, remote_entries)
write_journal_atomic(journal_path, new_journal)

set_pin(remote_entries)  # pin the remote we just read -- success only
ok("fetched from %s: %d new commit(s), %d new blob(s); remote pinned"
   % (remote, added, len(need)))
sys.exit(0)
PY
