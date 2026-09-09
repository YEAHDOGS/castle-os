#!/usr/bin/env python3
"""Castle family data vault core — FAMILY-DATA-VAULT.md build-order step 1.

Vault-per-user data layout + age-tiered accounts, wired into the
flamethrower Tier-1 keyring (FLAMETHROWER.md steps 1-2): every user vault
gets a real 256-bit data key; deleting the key IS deleting the data
(crypto-shredding), which is the honest deletion primitive for the
flamethrower.

The model (nuclear family, zero implicit trust):
  - Every member gets a private vault. Nothing is shared unless shared
    explicitly (the sharing ladder lands in step 2 of the vision doc;
    this module ships the private-vault foundation it builds on).
  - Age-tiered accounts: tier is a property of the account.
      * adult (18+): full vault, integrations, device self-approval.
      * child (<18): guardian approves new devices, escrowed key for
        family recovery, restricted surface (no integrations).
  - Key bytes never touch stdout, logs, certificates, or the activity
    log — only receipt hashes (see keyring.py).

Stdlib only. No network, no new hosts.

Layout (under <root>, all 0700/0600):
    users.json          account registry (0600)
    activity.jsonl      append-only event log — who did what, when (0600)
    vaults/<user>/      inbox documents photos receipts shared  (0700)
    keys/               flamethrower keyring root (one key per vault)

Usage:
    vault.py init [--dir PATH]
    vault.py create-user NAME [--tier adult|child] [--guardian NAME] [--dir PATH]
    vault.py list-users [--dir PATH]
    vault.py add-device USER DEVICE [--by NAME] [--dir PATH]
    vault.py add-integration USER NAME [--dir PATH]
    vault.py add-secret USER NAME [--secret-file FILE]   # stdin or 0600 file
    vault.py get-secret USER NAME                        # stdout, not logged
    vault.py list-secrets USER                           # names only
    vault.py rotate-secret USER NAME [--secret-file FILE]
    vault.py delete-secret USER NAME [--yes NAME]
    vault.py ingest-receipt FILE [--dir PATH]
    vault.py verify [--dir PATH]
    vault.py vault-init DIR --out FILE.castle --passphrase-file F
    vault.py vault-lock DIR --out FILE.castle --passphrase-file F [--yes NAME]
    vault.py vault-unlock FILE.castle --out DIR --passphrase-file F
"""

import argparse
import json
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "..", "flamethrower"))
import keyring  # noqa: E402  (Tier-1 crypto-shredding key lifecycle)

TIERS = ("adult", "child")
DEFAULT_DIR = os.path.expanduser("~/.castle-vault")
SUBDIRS = ("inbox", "documents", "photos", "receipts", "shared")
ACTIVITY_FILE = "activity.jsonl"


# ---------------------------------------------------------------------------
# plumbing
# ---------------------------------------------------------------------------

def _p(*parts):
    return os.path.join(*parts)


def _ts():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _atomic_write(path, obj, mode=0o600):
    tmp = path + ".tmp.%d" % os.getpid()
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def keyroot(root):
    return _p(root, "keys")


def _ensure_dirs(root):
    os.makedirs(root, mode=0o700, exist_ok=True)
    os.chmod(root, 0o700)
    os.makedirs(_p(root, "vaults"), mode=0o700, exist_ok=True)
    os.chmod(_p(root, "vaults"), 0o700)
    keyring.init(keyroot(root))
    users_path = _p(root, "users.json")
    if not os.path.exists(users_path):
        _atomic_write(users_path, {"version": 1, "users": {}})
    os.chmod(users_path, 0o600)
    act_path = _p(root, ACTIVITY_FILE)
    if not os.path.exists(act_path):
        open(act_path, "a").close()
    os.chmod(act_path, 0o600)
    return root


def _load_users(root):
    with open(_p(root, "users.json"), encoding="utf-8") as f:
        return json.load(f)


def _save_users(root, doc):
    _atomic_write(_p(root, "users.json"), doc)


def _activity(root, actor, action, detail=""):
    """Append one event to the activity log. Never records key material,
    file bytes, or passwords — only WHO did WHAT to WHICH vault."""
    line = {"ts": _ts(), "actor": actor, "action": action, "detail": detail}
    with open(_p(root, ACTIVITY_FILE), "a", encoding="utf-8") as f:
        f.write(json.dumps(line, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return line


def _require_user(users, name):
    if name not in users["users"]:
        raise ValueError("no such user: %s" % name)
    return users["users"][name]


# ---------------------------------------------------------------------------
# accounts: age tiers, guardians, devices, integrations
# ---------------------------------------------------------------------------

def create_user(root, name, tier="adult", guardian=None):
    """Create an account + private vault layout + flamethrower data key.

    A child's key is always escrowed (family recovery), and a child
    account needs an existing adult guardian. An adult account is the
    full vault.
    """
    _ensure_dirs(root)
    if not keyring._valid_name(name):
        raise ValueError("invalid user name: %r" % name)
    if tier not in TIERS:
        raise ValueError("tier must be adult|child, got %r" % tier)
    users = _load_users(root)
    if name in users["users"]:
        raise ValueError("user already exists: %s" % name)

    if tier == "child":
        if not guardian:
            raise ValueError("child account requires --guardian (an adult)")
        g = _require_user(users, guardian)
        if g["tier"] != "adult":
            raise ValueError("guardian must be an adult account: %s" % guardian)

    vdir = _p(root, "vaults", name)
    os.makedirs(vdir, mode=0o700, exist_ok=False)
    for sub in SUBDIRS:
        os.makedirs(_p(vdir, sub), mode=0o700)

    escrow = (tier == "child")
    keyring.create_vault(keyroot(root), name, escrow=escrow)

    users["users"][name] = {
        "name": name,
        "tier": tier,
        "guardian": guardian if tier == "child" else None,
        "devices": [],
        "integrations": [],
        "shares": [],
        "created": _ts(),
        "escrowed": escrow,
    }
    _save_users(root, users)
    _activity(root, name, "user.created",
              "tier=%s guardian=%s escrow=%s" % (tier, guardian, escrow))
    return "user %s created (tier=%s)" % (name, tier)


def add_device(root, user, device, by=None):
    """Register a device on an account. Under-18 accounts need their
    guardian's approval; adults approve their own devices."""
    _ensure_dirs(root)
    users = _load_users(root)
    rec = _require_user(users, user)
    if not device or not device.strip():
        raise ValueError("device name is required")
    if device in rec["devices"]:
        raise ValueError("device already registered: %s" % device)
    if rec["tier"] == "child":
        if by != rec["guardian"]:
            raise ValueError(
                "child device needs guardian approval: --by %s" % rec["guardian"])
    rec["devices"].append(device)
    _save_users(root, users)
    _activity(root, by or user, "device.added",
              "user=%s device=%s" % (user, device))
    return "device %s registered for %s (approved by %s)" % (
        device, user, by or user)


def add_integration(root, user, integration):
    """Add a third-party integration (POS push, email forward, API token).
    Restricted surface: under-18 accounts cannot add integrations."""
    _ensure_dirs(root)
    users = _load_users(root)
    rec = _require_user(users, user)
    if rec["tier"] != "adult":
        raise ValueError(
            "integrations are adult-only (child account: %s)" % user)
    if not integration or not integration.strip():
        raise ValueError("integration name is required")
    if integration in rec["integrations"]:
        raise ValueError("integration already added: %s" % integration)
    rec["integrations"].append(integration)
    _save_users(root, users)
    _activity(root, user, "integration.added", integration)
    return "integration %s added for %s" % (integration, user)


def list_users(root):
    _ensure_dirs(root)
    users = _load_users(root)
    return sorted(users["users"].values(), key=lambda r: r["name"])


# ---------------------------------------------------------------------------
# sharing ladder (vision build-order step 2): explicit, revocable, logged
# ---------------------------------------------------------------------------

SPECIAL_SCOPES = ("family", "world")


def grant_share(root, frm, to, by=None):
    """Grant an explicit share: frm's vault visible to `to`.

    `to` is one rung of the ladder: another member's name, "family", or
    "world". Every grant is explicit, stored on the granting account, and
    written to the activity log. Restrictions:
      - under-18 accounts cannot share to "world";
      - cannot share to yourself or to a non-existent member;
      - duplicate grants are refused (revoke first).
    """
    _ensure_dirs(root)
    users = _load_users(root)
    rec = _require_user(users, frm)
    actor = by or frm
    if to == frm:
        raise ValueError("cannot share to yourself")
    if to == "world" and rec["tier"] == "child":
        raise ValueError(
            "child accounts cannot share to the world: %s" % frm)
    if to not in SPECIAL_SCOPES and to not in users["users"]:
        raise ValueError("no such share target: %s" % to)
    if any(s["to"] == to for s in rec["shares"]):
        raise ValueError("share already granted: %s -> %s (revoke first)"
                         % (frm, to))
    grant = {"to": to, "by": actor, "ts": _ts()}
    rec["shares"].append(grant)
    _save_users(root, users)
    _activity(root, actor, "share.granted", "%s -> %s" % (frm, to))
    return "share granted: %s -> %s" % (frm, to)


def revoke_share(root, frm, to, by=None):
    """Revoke a previously granted share. Revoking a non-existent grant
    is a refusal, not a silent no-op."""
    _ensure_dirs(root)
    users = _load_users(root)
    rec = _require_user(users, frm)
    actor = by or frm
    before = len(rec["shares"])
    rec["shares"] = [s for s in rec["shares"] if s["to"] != to]
    if len(rec["shares"]) == before:
        raise ValueError("no such share to revoke: %s -> %s" % (frm, to))
    _save_users(root, users)
    _activity(root, actor, "share.revoked", "%s -> %s" % (frm, to))
    return "share revoked: %s -> %s" % (frm, to)


def show_shares(root, user):
    """Who can see this user's vault right now (default: nobody)."""
    _ensure_dirs(root)
    users = _load_users(root)
    rec = _require_user(users, user)
    return list(rec["shares"])


def activity_tail(root, n=20):
    """Last n activity log entries."""
    _ensure_dirs(root)
    lines = []
    with open(_p(root, ACTIVITY_FILE), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                lines.append(json.loads(line))
    return lines[-n:]


# ---------------------------------------------------------------------------
# true deletion: burn the vault's key (flamethrower Tier 1) and wipe the dirs
# ---------------------------------------------------------------------------

def delete_user(root, name, confirm=None):
    """Delete a user's vault: crypto-shred their data key (deleting the
    key IS deleting the data — irretrievable on any media), remove the
    vault dirs, and retire the account record.

    Dry-run is the default: it enumerates exactly what would die.
    The real burn needs TYPED confirmation (the user's name)."""
    _ensure_dirs(root)
    users = _load_users(root)
    rec = _require_user(users, name)

    targets = ["vault dir: %s" % _p(root, "vaults", name)]
    keyroot_dir = keyroot(root)
    for label, path in (("keyring", _p(keyroot_dir, "keys", name + ".key")),
                        ("escrow", _p(keyroot_dir, "escrow", name + ".key"))):
        if os.path.exists(path):
            targets.append("%s key copy: %s" % (label, path))

    if confirm != name:
        return {"dry_run": True, "would_destroy": targets,
                "hint": "re-run with --yes %s to burn" % name}

    burn = keyring.destroy_vault(keyroot_dir, name, confirm=name)
    # defense in depth: crypto-shred every secret ciphertext before the
    # tree wipe, so no secret file survives even if the rmtree below
    # were ever interrupted.
    sdir = _p(root, "vaults", name, "secrets")
    if os.path.isdir(sdir):
        for fn in sorted(os.listdir(sdir)):
            if fn.endswith(".secret"):
                full = _p(sdir, fn)
                if os.path.isfile(full) and not os.path.islink(full):
                    keyring._overwrite_and_unlink(full)
                    targets.append("secret ciphertext shredded: %s" % full)
    shutil.rmtree(_p(root, "vaults", name), ignore_errors=True)
    del users["users"][name]
    _save_users(root, users)
    _activity(root, name, "user.deleted",
              "crypto-shredded via keyring cert %s" % burn["cert_id"])
    return {"dry_run": False, "kills": targets,
            "certificate": burn["certificate"], "cert_id": burn["cert_id"]}


# ---------------------------------------------------------------------------
# verification
# ---------------------------------------------------------------------------

def verify(root):
    """Regression-friendly consistency check: perms, registry shape,
    every user has a vault dir + a keyring key, children are escrowed."""
    problems = []
    _ensure_dirs(root)

    def perm(path, want):
        try:
            return (os.stat(path).st_mode & 0o777) == want
        except FileNotFoundError:
            return False

    if not perm(root, 0o700):
        problems.append("root dir perms not 0700")
    for f in ("users.json", ACTIVITY_FILE):
        if not perm(_p(root, f), 0o600):
            problems.append("%s perms not 0600" % f)

    try:
        users = _load_users(root)
        records = users["users"]
    except Exception as e:  # noqa: BLE001 - verify reports, never crashes
        return ["users.json unreadable: %s" % e]

    vault_keys = set(n for n, _kid, _created, _esc
                    in keyring.list_vaults(keyroot(root)))
    for name, rec in records.items():
        if not keyring._valid_name(name):
            problems.append("invalid user name in registry: %r" % name)
        if rec.get("tier") not in TIERS:
            problems.append("bad tier for %s" % name)
        if rec["tier"] == "child":
            g = rec.get("guardian")
            if not g or g not in records or records[g]["tier"] != "adult":
                problems.append("child %s has no adult guardian" % name)
            if not rec.get("escrowed"):
                problems.append("child %s key not escrowed" % name)
        for sub in SUBDIRS:
            d = _p(root, "vaults", name, sub)
            if not os.path.isdir(d):
                problems.append("missing dir: vaults/%s/%s" % (name, sub))
            elif not perm(d, 0o700):
                problems.append("perms not 0700: vaults/%s/%s" % (name, sub))
        if name not in vault_keys:
            problems.append("no keyring key for user: %s" % name)
        for s in rec.get("shares", []):
            if s["to"] not in SPECIAL_SCOPES and s["to"] not in records:
                problems.append("share to unknown target: %s -> %s"
                                % (name, s["to"]))
        # secrets store: tight perms on the dir, the registry, and every
        # ciphertext file (checked only when the store exists)
        sdir = _p(root, "vaults", name, "secrets")
        if os.path.isdir(sdir):
            if not perm(sdir, 0o700):
                problems.append("perms not 0700: vaults/%s/secrets" % name)
            for fn in sorted(os.listdir(sdir)):
                full = _p(sdir, fn)
                if fn == "index.json" or fn.endswith(".secret"):
                    if not perm(full, 0o600):
                        problems.append("perms not 0600: vaults/%s/secrets/%s"
                                        % (name, fn))

    extra_keys = vault_keys - set(records)
    if extra_keys:
        problems.append("orphan keyring keys: %s" % sorted(extra_keys))
    return problems


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(prog="vault.py",
                                 description="Castle family data vault core")
    ap.add_argument("--dir", default=DEFAULT_DIR)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init")
    p = sub.add_parser("create-user")
    p.add_argument("name")
    p.add_argument("--tier", default="adult", choices=TIERS)
    p.add_argument("--guardian")
    sub.add_parser("list-users")
    p = sub.add_parser("add-device")
    p.add_argument("user"); p.add_argument("device"); p.add_argument("--by")
    p = sub.add_parser("add-integration")
    p.add_argument("user"); p.add_argument("integration")
    p = sub.add_parser("add-secret",
                       help="store an encrypted secret (API key/token) for "
                            "an adult user — reads from stdin or "
                            "--secret-file (never a CLI arg)")
    p.add_argument("user"); p.add_argument("name")
    p.add_argument("--secret-file", default=None,
                   help="file holding the secret (must be mode 0600)")
    p = sub.add_parser("get-secret",
                       help="print a secret to stdout (nothing is logged)")
    p.add_argument("user"); p.add_argument("name")
    p = sub.add_parser("list-secrets",
                       help="list a user's secret names (never values)")
    p.add_argument("user")
    p = sub.add_parser("rotate-secret",
                       help="replace a secret's value (fresh IV + "
                            "ciphertext, same name)")
    p.add_argument("user"); p.add_argument("name")
    p.add_argument("--secret-file", default=None,
                   help="file holding the new secret (must be mode 0600)")
    p = sub.add_parser("delete-secret",
                       help="crypto-shred a secret: typed confirmation "
                            "burns the ciphertext")
    p.add_argument("user"); p.add_argument("name"); p.add_argument("--yes")
    p = sub.add_parser("grant-share")
    p.add_argument("frm"); p.add_argument("to"); p.add_argument("--by")
    p = sub.add_parser("revoke-share")
    p.add_argument("frm"); p.add_argument("to"); p.add_argument("--by")
    p = sub.add_parser("revoke-device",
                       help="revoke a registered device: child needs their "
                            "guardian (--by), adults revoke their own "
                            "(FAMILY-DATA-VAULT step 5)")
    p.add_argument("user"); p.add_argument("device"); p.add_argument("--by")
    p = sub.add_parser("guardian-revoke-share",
                       help="a guardian revokes a share their child granted "
                            "(FAMILY-DATA-VAULT step 5)")
    p.add_argument("child"); p.add_argument("to")
    p.add_argument("--by", required=True, help="the child's guardian")
    p = sub.add_parser("graduate",
                       help="guardian-approved child -> adult graduation; "
                            "data comes with the account "
                            "(FAMILY-DATA-VAULT step 5)")
    p.add_argument("child"); p.add_argument("--by", required=True,
                                            help="the child's guardian")
    p = sub.add_parser("show-shares")
    p.add_argument("user")
    p = sub.add_parser("delete-user")
    p.add_argument("name"); p.add_argument("--yes")
    p = sub.add_parser("ingest-receipt",
                       help="ingest a forwarded email into the addressed "
                            "user's receipts vault (FAMILY-DATA-VAULT step 3)")
    p.add_argument("file", help="path to the raw RFC822 message")
    p = sub.add_parser("ingest-pos",
                       help="ingest a POS webhook JSON body into the "
                            "addressed user's receipts vault "
                            "(FAMILY-DATA-VAULT step 3)")
    p.add_argument("file", help="path to the JSON push body")
    p = sub.add_parser("ingest-scan",
                       help="ingest a scanned receipt image + OCR text into a "
                            "user's receipts vault (FAMILY-DATA-VAULT step 3)")
    p.add_argument("file", help="path to the scan image (JPEG/PNG/WebP)")
    p.add_argument("--ocr", required=True, help="path to the OCR text file")
    p.add_argument("--user", required=True, help="vault user to ingest into")
    p.add_argument("--merchant", default=None,
                   help="merchant name as stated (optional, high confidence)")
    p = sub.add_parser("activity")
    p.add_argument("--tail", type=int, default=20)
    p = sub.add_parser("tailnet-onboard",
                       help="start tailnet onboarding for a registered "
                            "device: prints the operator runbook "
                            "(FAMILY-DATA-VAULT step 4)")
    p.add_argument("user"); p.add_argument("device"); p.add_argument("--by")
    p = sub.add_parser("tailnet-claim",
                       help="mark a pending device active once it joined "
                            "the tailnet (100.64.0.0/10 only)")
    p.add_argument("user"); p.add_argument("device")
    p.add_argument("--ip", required=True,
                   help="the device's tailnet address, from the admin console")
    p = sub.add_parser("tailnet-status",
                       help="pending/active tailnet devices, registry-resolved")
    p = sub.add_parser("tailnet-drop",
                       help="purge a device's tailnet record "
                            "(after revoke-device, or to re-home)")
    p.add_argument("user"); p.add_argument("device"); p.add_argument("--by")
    p = sub.add_parser("tailnet-dns",
                       help="write the Pi-hole dnsmasq fragment naming the "
                            ".castle services (FAMILY-DATA-VAULT step 4)")
    p.add_argument("--castle-ip", required=True,
                   help="Castle's own tailnet address (100.64.0.0/10)")
    p.add_argument("--out", default=None,
                   help="where to write the fragment "
                        "(default: <root>/dnsmasq.d/10-castle.conf)")
    sub.add_parser("verify")
    p = sub.add_parser("manifest",
                       help="write a SHA-256 file manifest of a vault "
                            "directory (FAMILY-DATA-VAULT step 6)")
    p.add_argument("dir", help="vault directory to inventory")
    p.add_argument("--out", required=True,
                   help="where to write the manifest JSON (not inside the "
                        "tree it describes)")
    p.add_argument("--label", default=None,
                   help="root label recorded in the manifest")
    p = sub.add_parser("audit",
                       help="audit a vault directory against a manifest: "
                            "ADDED/REMOVED/MODIFIED/UNCHANGED "
                            "(FAMILY-DATA-VAULT step 6)")
    p.add_argument("dir", help="vault directory to re-scan")
    p.add_argument("--manifest", required=True,
                   help="manifest file written by the manifest command")
    p.add_argument("--json", action="store_true",
                   help="machine-readable output instead of the diff")

    def _secret_args(p):
        g = p.add_mutually_exclusive_group(required=True)
        g.add_argument("--passphrase-file",
                       help="file holding the passphrase (must be mode 0600)")
        g.add_argument("--keyfile",
                       help="file holding a 32-byte raw key "
                            "(must be mode 0600)")
        return p

    p = _secret_args(sub.add_parser(
        "vault-init",
        help="seal a vault directory into an encrypted .castle file "
             "(FAMILY-DATA-VAULT step 7); plaintext left untouched"))
    p.add_argument("dir", help="plaintext vault directory to seal")
    p.add_argument("--out", required=True,
                   help="where to write the locked .castle file")

    p = _secret_args(sub.add_parser(
        "vault-lock",
        help="seal a vault directory then burn the plaintext "
             "(dry-run unless --yes BASENAME)"))
    p.add_argument("dir", help="plaintext vault directory to seal and burn")
    p.add_argument("--out", required=True,
                   help="where to write the locked .castle file")
    p.add_argument("--yes", default=None,
                   help="typed confirmation: the directory's basename")

    p = _secret_args(sub.add_parser(
        "vault-unlock",
        help="open an encrypted .castle file into a directory"))
    p.add_argument("file", help="the locked .castle file")
    p.add_argument("--out", required=True,
                   help="empty (or new) directory to restore into")

    p = _secret_args(sub.add_parser(
        "backup",
        help="seal a user's vault into an encrypted backup on a backup "
             "target (FAMILY-DATA-VAULT step 8); dry-run unless --yes USER"))
    p.add_argument("user", help="vault user to back up")
    p.add_argument("--target-dir", required=True,
                   help="backup target directory (existing .castle files "
                        "are never overwritten)")
    p.add_argument("--yes", default=None,
                   help="typed confirmation: the username")
    p.add_argument("--chunks", action="store_true",
                   help="seal with the pure-stdlib chunked container "
                        "(castle-chunks/v1, per-chunk HMAC) instead of "
                        "the openssl-backed format")

    p = _secret_args(sub.add_parser(
        "backup-verify",
        help="prove an encrypted backup file restores bit-exact "
             "(nothing is extracted to disk)"))
    p.add_argument("file", help="the .castle backup file to verify")

    a = ap.parse_args(argv)
    try:
        if a.cmd == "init":
            _ensure_dirs(a.dir); print("vault root ready: %s" % a.dir)
        elif a.cmd == "create-user":
            print(create_user(a.dir, a.name, tier=a.tier, guardian=a.guardian))
        elif a.cmd == "list-users":
            for r in list_users(a.dir):
                print("%-12s tier=%-5s guardian=%-8s devices=%d shares=%d" % (
                    r["name"], r["tier"], r["guardian"] or "-",
                    len(r["devices"]), len(r["shares"])))
        elif a.cmd == "add-device":
            print(add_device(a.dir, a.user, a.device, by=a.by))
        elif a.cmd == "add-integration":
            print(add_integration(a.dir, a.user, a.integration))
        elif a.cmd in ("add-secret", "get-secret", "list-secrets",
                       "rotate-secret", "delete-secret"):
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import secretstore as _sec  # noqa: E402
            if a.cmd == "add-secret":
                print(_sec.add_secret(a.dir, a.user, a.name,
                                      _sec.read_secret_input(a.secret_file)))
            elif a.cmd == "get-secret":
                sys.stdout.buffer.write(
                    _sec.get_secret(a.dir, a.user, a.name))
                sys.stdout.buffer.flush()
            elif a.cmd == "list-secrets":
                names = _sec.list_secrets(a.dir, a.user)
                print("\n".join(names) if names else "(no secrets)")
            elif a.cmd == "rotate-secret":
                print(_sec.rotate_secret(a.dir, a.user, a.name,
                                         _sec.read_secret_input(
                                             a.secret_file)))
            elif a.cmd == "delete-secret":
                r = _sec.delete_secret(a.dir, a.user, a.name, confirm=a.yes)
                if r["dry_run"]:
                    print("DRY RUN — nothing burned. Would destroy:")
                    for t in r["would_destroy"]:
                        print("  " + t)
                    print(r["hint"])
                    return 2
                print("BURNED secret %s for %s — ciphertext crypto-shredded"
                      % (a.name, a.user))
        elif a.cmd == "grant-share":
            print(grant_share(a.dir, a.frm, a.to, by=a.by))
        elif a.cmd == "revoke-share":
            print(revoke_share(a.dir, a.frm, a.to, by=a.by))
        elif a.cmd == "revoke-device":
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import guardian as _gd  # noqa: E402
            print(_gd.revoke_device(a.dir, a.user, a.device, by=a.by))
        elif a.cmd == "guardian-revoke-share":
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import guardian as _gd  # noqa: E402
            print(_gd.guardian_revoke_share(a.dir, a.child, a.to, a.by))
        elif a.cmd == "graduate":
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import guardian as _gd  # noqa: E402
            print(_gd.graduate(a.dir, a.child, a.by))
        elif a.cmd == "show-shares":
            shares = show_shares(a.dir, a.user)
            print("shares from %s: %s" % (a.user,
                  ", ".join(s["to"] for s in shares) or "(none — private)"))
            for s in shares:
                print("  -> %-10s by=%s ts=%s" % (s["to"], s["by"], s["ts"]))
        elif a.cmd == "delete-user":
            r = delete_user(a.dir, a.name, confirm=a.yes)
            if r["dry_run"]:
                print("DRY RUN — nothing burned. Would destroy:")
                for t in r["would_destroy"]:
                    print("  " + t)
                print(r["hint"])
                return 2
            print("BURNED %s — crypto-shredded (cert %s)" % (a.name, r["cert_id"]))
            print("certificate: %s" % r["certificate"])
        elif a.cmd == "ingest-receipt":
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import receipts as _rcpt  # noqa: E402
            with open(a.file, "rb") as f:
                raw = f.read()
            user, _msg = _rcpt.resolve_recipient(a.dir, raw)
            r = _rcpt.ingest(a.dir, user, raw)
            print("receipt %s -> %s's vault (merchant=%s total=%s)" % (
                r["id"], user, r["merchant"], r["total"]))
        elif a.cmd == "ingest-pos":
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import poshook as _pos  # noqa: E402
            with open(a.file, "rb") as f:
                raw = f.read()
            user, _payload = _pos.resolve_recipient(a.dir, raw)
            r = _pos.ingest(a.dir, user, raw)
            print("pos receipt %s -> %s's vault (merchant=%s total=%s %s)" % (
                r["id"], user, r["merchant"], r["total"], r["currency"]))
        elif a.cmd == "ingest-scan":
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import scan as _scan  # noqa: E402
            with open(a.file, "rb") as f:
                img = f.read()
            with open(a.ocr, "r", encoding="utf-8") as f:
                ocr_text = f.read()
            r = _scan.ingest(a.dir, a.user, img, ocr_text,
                             filename=os.path.basename(a.file),
                             hint_merchant=a.merchant)
            print("scan %s -> %s's vault (merchant=%s total=%s)" % (
                r["id"], a.user, r["merchant"], r["total"]))
        elif a.cmd == "activity":
            for e in activity_tail(a.dir, a.tail):
                print("%s %-12s %-16s %s" % (e["ts"], e["actor"], e["action"], e["detail"]))
        elif a.cmd in ("tailnet-onboard", "tailnet-claim", "tailnet-status",
                       "tailnet-drop", "tailnet-dns"):
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import tailnet as _tn  # noqa: E402
            if a.cmd == "tailnet-onboard":
                r = _tn.onboard(a.dir, a.user, a.device, by=a.by)
                print("onboarding started: %s/%s is tailnet-pending" % (
                    r["user"], r["device"]))
                print()
                print("OPERATOR RUNBOOK (run this on the device):")
                print(r["runbook"])
            elif a.cmd == "tailnet-claim":
                r = _tn.claim(a.dir, a.user, a.device, a.ip)
                print("tailnet-active: %s/%s @ %s" % (
                    r["user"], r["device"], r["ip"]))
            elif a.cmd == "tailnet-status":
                rows = _tn.status(a.dir)
                if not rows:
                    print("(no tailnet devices)")
                for r in rows:
                    print("%-12s %-14s %-7s %s" % (
                        r["user"], r["device"], r["state"], r["ip"] or "-"))
            elif a.cmd == "tailnet-drop":
                print(_tn.drop(a.dir, a.user, a.device, by=a.by))
            elif a.cmd == "tailnet-dns":
                r = _tn.dns_refresh(a.dir, a.castle_ip, out=a.out)
                print("hosted DNS fragment written: %s" % r["out"])
                print("services: %s -> %s" % (
                    ", ".join(r["services"]), r["castle_ip"]))
                print("install: drop it into Pi-hole's dnsmasq.d, "
                      "then restart pihole-FTL (operator step)")
        elif a.cmd == "verify":
            problems = verify(a.dir)
            if problems:
                print("VERIFY FAILED:")
                for p in problems:
                    print("  - " + p)
                return 1
            print("verify: all green")
        elif a.cmd == "manifest":
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import manifest as _manifest  # noqa: E402
            doc = _manifest.write_manifest(a.dir, a.out, root_label=a.label)
            print("manifest written: %s (%d file(s), %d skipped)" % (
                a.out, len(doc["entries"]), len(doc["skipped"])))
        elif a.cmd == "audit":
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import verify as _va  # noqa: E402
            return _va.run_audit(a.dir, a.manifest, json_out=a.json)
        elif a.cmd in ("vault-init", "vault-lock", "vault-unlock"):
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import vault_lock as _vl  # noqa: E402
            try:
                if a.cmd == "vault-init":
                    h = _vl.vault_init(a.dir, a.out,
                                       passphrase_file=a.passphrase_file,
                                       keyfile=a.keyfile)
                    print("sealed %d file(s) -> %s (%s+%s)" % (
                        h["file_count"], a.out, h["cipher"], h["mac"]))
                elif a.cmd == "vault-lock":
                    r = _vl.vault_lock(a.dir, a.out,
                                       passphrase_file=a.passphrase_file,
                                       keyfile=a.keyfile, confirm=a.yes)
                    if r["dry_run"]:
                        print("DRY RUN — plaintext untouched.")
                        print("  sealed: %s" % r["sealed"])
                        print("  would burn: %s" % r["would_burn"])
                        print(r["hint"])
                        return 2
                    print("LOCKED %s — plaintext burned (cert manifest %s)" % (
                        r["sealed"], r["burn"]["manifest"]))
                else:
                    r = _vl.vault_unlock(a.file, a.out,
                                         passphrase_file=a.passphrase_file,
                                         keyfile=a.keyfile)
                    print("unlocked %d file(s) -> %s (all hashes verified)" % (
                        r["files"], r["unlocked"]))
            except _vl.VaultLockError as e:
                print("error: %s" % e, file=sys.stderr)
                return 1
        elif a.cmd == "backup":
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import backup as _bk  # noqa: E402
            try:
                r = _bk.create_backup(a.dir, a.user, a.target_dir,
                                      passphrase_file=a.passphrase_file,
                                      keyfile=a.keyfile, confirm=a.yes,
                                      chunks=a.chunks)
            except _bk.BackupError as e:
                print("refused: %s" % e)
                return 1
            if r["dry_run"]:
                print("DRY RUN — nothing written. Would back up:")
                print("  user:      %s" % r["user"])
                print("  vault dir: %s" % r["vault_dir"])
                print("  files:     %d (%d bytes)" % (r["file_count"],
                                                      r["total_bytes"]))
                print("  write to:  %s" % r["would_write"])
                print(r["hint"])
                return 2
            c = r["certificate"]
            print("BACKED UP %s -> %s (cert %s, %d files verified "
                  "bit-exact)" % (a.user, r["backup_file"], c["cert_id"],
                                  c["file_count"]))
        elif a.cmd == "backup-verify":
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import backup as _bk  # noqa: E402
            try:
                r = _bk.verify_backup(a.file,
                                      passphrase_file=a.passphrase_file,
                                      keyfile=a.keyfile)
            except _bk.BackupError as e:
                print("refused: %s" % e)
                return 1
            print("VERIFIED %s — %d file(s), %d bytes, HMAC + every "
                  "per-file SHA-256 match (sealed %s)" % (
                      r["backup_file"], r["file_count"], r["total_bytes"],
                      r["sealed_at"]))
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
