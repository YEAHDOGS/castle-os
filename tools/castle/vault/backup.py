#!/usr/bin/env python3
"""Castle encrypted backups — FAMILY-DATA-VAULT.md build-order step 8.

The vault-per-user layout (step 1) is plaintext on the family box, and
step 7 seals a vault into a locked ``.castle`` file. This module is the
missing middle: the *backup primitive*. A family's data home is worth
nothing without an encrypted off-box copy — this is the flow that puts
an encrypted, verified backup of one user's vault onto the backup
target (Castle's 10TB drive, an external disk, anything).

What it does, in order:
  1. Resolve the user's vault directory from the registry.
  2. Build a deterministic manifest (step 6) — the inventory the
     backup promises to preserve.
  3. Seal it with the step-7 lock (AES-256-CBC + encrypt-then-MAC,
     passphrase or raw keyfile) into ``<user>-<utc>.castle`` in the
     target directory. The live vault is NEVER touched or burned —
     a backup that destroys the original is a fire, not a backup.
  4. Prove the backup opens in the same run: re-read it, verify the
     HMAC, decrypt, check the tarball hash, then check every per-file
     SHA-256 in the header against the tarball members. A backup that
     hasn't been proven restorable is a rumor.
  5. Log one activity record (metadata only — user, file name, counts,
     hashes) and return a backup certificate.

Trust model (same DNA as the vault core and the flamethrower):
  - Dry-run is the default: the plan enumerates exactly what would be
    sealed and where it would land. The real backup needs TYPED
    confirmation (the username) — same interlock as vault-lock and
    flamethrower burns.
  - Refusals, never guesses: unknown user, missing/unusable target,
    a target that is or contains the vault being backed up (a backup
    written inside the tree it describes would corrupt the next one),
    the secret file living inside the vault or the target, an existing
    backup file at the chosen name (never silently overwrite a
    previous backup — a new timestamped name is minted instead).
  - The secret arrives via --passphrase-file / --keyfile only, with the
    same 0600 checks as the step-7 lock. It is never written to disk,
    never printed, never logged.
  - verify_backup re-proves an existing backup file restores
    bit-exact: HMAC, tarball hash, then every file's SHA-256 against
    the header inventory. Wrong passphrase or tampered file fails
    closed.

Stdlib + the openssl CLI (via vault_lock) only. No network, no new
hosts, no installs.

Usage (via vault.py):
    vault.py backup USER --target-dir DIR --passphrase-file F [--yes USER]
                 [--chunks]
    vault.py backup-verify FILE.castle --passphrase-file F
"""

import hashlib
import io
import json
import os
import tarfile
import time

import vault_lock
import chunkseal
import manifest as vault_manifest
import vault as vault_core


class BackupError(Exception):
    """Anything that makes a backup untrustworthy is a hard refusal."""


def _locked_call(fn, *args, **kwargs):
    """Run a vault_lock operation, translating its refusals into ours
    so callers (and the CLI) only ever see BackupError."""
    try:
        return fn(*args, **kwargs)
    except vault_lock.VaultLockError as e:
        raise BackupError(str(e))


def _chunk_call(fn, *args, **kwargs):
    """Same translation for the chunked container's typed errors."""
    try:
        return fn(*args, **kwargs)
    except chunkseal.ChunkSealError as e:
        raise BackupError(str(e))


def _ts_compact():
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def _require_real_dir(path, what):
    if os.path.islink(path):
        raise BackupError("%s is a symlink — refusing: %s" % (what, path))
    if not os.path.isdir(path):
        raise BackupError("%s is not a directory: %s" % (what, path))
    rp = os.path.realpath(path)
    if rp == os.sep:
        raise BackupError("refusing: %s is the filesystem root" % what)
    return rp


def _check_target(vdir, target):
    """The backup target must not be the vault, inside the vault, or
    contain the vault. A backup written into the tree it describes
    corrupts the next backup's manifest; a backup containing the vault
    is a recursion trap."""
    t = _require_real_dir(target, "backup target")
    if t == vdir:
        raise BackupError(
            "backup target IS the vault dir — refusing")
    if t.startswith(vdir + os.sep):
        raise BackupError(
            "backup target lives inside the vault being backed up — "
            "refusing (it would corrupt the next manifest)")
    if vdir.startswith(t + os.sep):
        raise BackupError(
            "backup target contains the vault being backed up — refusing")
    return t


def _check_secret(secret_path, vdir, target):
    sp = os.path.realpath(secret_path)
    for place, name in ((vdir, "the vault being backed up"),
                        (target, "the backup target")):
        if sp == place or sp.startswith(place + os.sep):
            raise BackupError(
                "secret file lives inside %s — refusing (the key would "
                "sit next to the data it protects)" % name)


def _resolve_vault_dir(root, user):
    core = vault_core
    core._ensure_dirs(root)
    users = core._load_users(root)
    if user not in users["users"]:
        raise BackupError("no such user: %s" % user)
    vdir = os.path.realpath(core._p(root, "vaults", user))
    if os.path.islink(core._p(root, "vaults", user)):
        raise BackupError("vault dir is a symlink — refusing")
    if not os.path.isdir(vdir):
        raise BackupError("vault dir missing for user %s: %s" % (user, vdir))
    return vdir


def plan_backup(root, user, target_dir, passphrase_file=None, keyfile=None):
    """Dry-run: enumerate what a backup would seal and where it would
    land. Changes nothing. Raises BackupError on any refusal."""
    if (passphrase_file is None) == (keyfile is None):
        raise BackupError("exactly one of passphrase-file / keyfile required")
    vdir = _resolve_vault_dir(root, user)
    target = _check_target(vdir, target_dir)
    secret_path = passphrase_file or keyfile
    _check_secret(secret_path, vdir, target)
    man = vault_manifest.build_manifest(vdir)
    if man["skipped"]:
        raise BackupError(
            "refusing to back up: non-regular files in vault: %s"
            % ", ".join(s["path"] for s in man["skipped"]))
    base = "%s-%s.castle" % (user, _ts_compact())
    out = os.path.join(target, base)
    n = 2
    while os.path.exists(out):
        out = os.path.join(target, "%s-%s-%d.castle"
                           % (user, _ts_compact(), n))
        n += 1
    return {
        "dry_run": True,
        "user": user,
        "vault_dir": vdir,
        "would_write": out,
        "file_count": len(man["entries"]),
        "total_bytes": sum(e["size"] for e in man["entries"]),
        "hint": "re-run with --yes %s to write the backup" % user,
    }


def _verify_tarball_bytes(header, tar_bytes):
    """Bit-exact restore proof: every member's SHA-256 must match the
    header inventory, and the member set must match exactly."""
    files = header.get("files") or {}
    buf = io.BytesIO(tar_bytes)
    seen = {}
    try:
        tf = tarfile.open(fileobj=buf, mode="r")
    except tarfile.TarError as e:
        raise BackupError("backup tarball unreadable: %s" % e)
    with tf:
        for m in tf.getmembers():
            if m.isdir():
                continue
            if not m.isfile():
                raise BackupError(
                    "backup contains non-regular member: %s" % m.name)
            fobj = tf.extractfile(m)
            if fobj is None:
                raise BackupError("cannot read member: %s" % m.name)
            h = hashlib.sha256()
            while True:
                chunk = fobj.read(65536)
                if not chunk:
                    break
                h.update(chunk)
            seen[m.name] = h.hexdigest()
    if set(seen) != set(files):
        raise BackupError(
            "backup inventory mismatch: header lists %d files, tarball "
            "holds %d" % (len(files), len(seen)))
    for name, digest in seen.items():
        if digest != files[name]["sha256"]:
            raise BackupError(
                "backup corrupt: %s hash mismatch after decrypt — refusing"
                % name)
    return len(seen)


def _prove_restorable(out_path, passphrase_file, keyfile):
    """Re-read the sealed backup and prove it opens with the same
    secret, bit-exact. Fail closed on anything wrong."""
    header, ct = _locked_call(vault_lock._read_locked, out_path)
    kind, secret = _locked_call(vault_lock._read_secret,
                                passphrase_file, keyfile)
    try:
        tar_bytes = _locked_call(vault_lock._open_ciphertext,
                                 header, ct, kind, secret)
    finally:
        del secret
    n = _verify_tarball_bytes(header, tar_bytes)
    del tar_bytes
    return header, n


def _prove_restorable_chunks(out_path, passphrase_file, keyfile):
    """Same proof for the chunked container: every chunk's HMAC is
    re-verified on open, then the tarball and per-file inventory."""
    fmt = _chunk_call(chunkseal.peek_format, out_path)
    if fmt != chunkseal.FORMAT:
        raise BackupError("not a chunked backup: %s" % out_path)
    kind, secret = _locked_call(vault_lock._read_secret,
                                passphrase_file, keyfile)
    try:
        header, payload = _chunk_call(chunkseal.open_file,
                                      out_path, (kind, secret))
    finally:
        del secret
    n = _verify_tarball_bytes(header, payload)
    del payload
    return header, n


def _seal_chunks(vdir, out_path, passphrase_file, keyfile):
    """Seal vdir's tarball into the chunked container. Returns the
    header dict. Non-destructive — the live vault is untouched."""
    kind, secret = _locked_call(vault_lock._read_secret,
                                passphrase_file, keyfile)
    _locked_call(vault_lock._check_secret_not_inside,
                 passphrase_file or keyfile, vdir)
    try:
        man = vault_manifest.build_manifest(vdir)
        files = {e["path"]: {"size": e["size"], "sha256": e["sha256"]}
                 for e in man["entries"]}
        if man["skipped"]:
            raise BackupError(
                "refusing to back up: non-regular files in vault: %s"
                % ", ".join(s["path"] for s in man["skipped"]))
        tar_bytes = _locked_call(vault_lock._build_tarball, vdir)
        header, body = _chunk_call(chunkseal.seal, tar_bytes,
                                   (kind, secret), files=files)
        _chunk_call(chunkseal._write_chunked, out_path, header, body)
    finally:
        del secret
    return header


def _backup_cert_id():
    return "bkp-" + __import__("secrets").token_hex(6)


def create_backup(root, user, target_dir, passphrase_file=None, keyfile=None,
                  confirm=None, chunks=False):
    """Seal a user's vault into an encrypted backup on the target dir.

    Dry-run is the default. The real backup needs typed confirmation
    (the username). ``chunks=True`` seals with the pure-stdlib chunked
    container (castle-chunks/v1, per-chunk HMAC) instead of the
    openssl-backed .castle format. Returns a dict with the plan or the
    backup certificate."""
    plan = plan_backup(root, user, target_dir, passphrase_file, keyfile)
    if confirm != user:
        return plan
    out = plan["would_write"]
    core = vault_core
    if chunks:
        # seal with the chunked container (non-destructive: the live
        # vault is NEVER burned — a backup that destroys the original
        # is a fire, not a backup)
        header = _seal_chunks(plan["vault_dir"], out,
                              passphrase_file, keyfile)
        header, verified = _prove_restorable_chunks(out, passphrase_file,
                                                    keyfile)
    else:
        # seal (non-destructive: vault_init never burns the plaintext —
        # a backup that destroys the original is a fire, not a backup)
        _locked_call(vault_lock.vault_init, plan["vault_dir"], out,
                     passphrase_file=passphrase_file, keyfile=keyfile)
        # prove it restores before calling it a backup
        header, verified = _prove_restorable(out, passphrase_file, keyfile)
    with open(out, "rb") as f:
        file_sha = hashlib.sha256(f.read()).hexdigest()
    if chunks:
        total = sum(e["size"] for e in header.get("files", {}).values())
    else:
        total = header.get("total_bytes")
    cert = {
        "cert_id": _backup_cert_id(),
        "user": user,
        "backup_file": out,
        "file_sha256": file_sha,
        "file_count": verified,
        "total_bytes": total,
        "container": header.get("format"),
        "cipher": header.get("cipher"),
        "mac": header.get("mac"),
        "sealed_at": header.get("created"),
    }
    core._activity(root, user, "backup",
                   "sealed %d files (%d bytes) -> %s (cert %s)"
                   % (cert["file_count"], cert["total_bytes"],
                      os.path.basename(out), cert["cert_id"]))
    return {"dry_run": False, "backup_file": out, "certificate": cert}


def verify_backup(locked_path, passphrase_file=None, keyfile=None):
    """Prove an existing backup file restores bit-exact with this
    secret. Nothing is extracted to disk. The container format is
    detected from the header (castle-vault/v1 vs castle-chunks/v1).
    Returns the verification report; raises BackupError on any
    failure."""
    if (passphrase_file is None) == (keyfile is None):
        raise BackupError("exactly one of passphrase-file / keyfile required")
    if not os.path.isfile(locked_path):
        raise BackupError("not a file: %s" % locked_path)
    fmt = _chunk_call(chunkseal.peek_format, locked_path)
    if fmt == chunkseal.FORMAT:
        header, n = _prove_restorable_chunks(locked_path, passphrase_file,
                                             keyfile)
        total = sum(e["size"] for e in header.get("files", {}).values())
    else:
        header, n = _prove_restorable(locked_path, passphrase_file, keyfile)
        total = header.get("total_bytes")
    with open(locked_path, "rb") as f:
        file_sha = hashlib.sha256(f.read()).hexdigest()
    return {
        "ok": True,
        "backup_file": os.path.realpath(locked_path),
        "file_sha256": file_sha,
        "file_count": n,
        "total_bytes": total,
        "container": header.get("format"),
        "cipher": header.get("cipher"),
        "mac": header.get("mac"),
        "sealed_at": header.get("created"),
    }


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def _secret_args(p):
        g = p.add_mutually_exclusive_group(required=True)
        g.add_argument("--passphrase-file")
        g.add_argument("--keyfile")
        return p

    p = _secret_args(sub.add_parser("backup"))
    p.add_argument("--root", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--target-dir", required=True)
    p.add_argument("--yes", default=None)
    p.add_argument("--chunks", action="store_true",
                   help="chunked container instead of openssl format")

    p = _secret_args(sub.add_parser("verify"))
    p.add_argument("file")

    a = ap.parse_args()
    try:
        if a.cmd == "backup":
            r = create_backup(a.root, a.user, a.target_dir,
                              passphrase_file=a.passphrase_file,
                              keyfile=a.keyfile, confirm=a.yes,
                              chunks=a.chunks)
            print(json.dumps(r, indent=2, sort_keys=True))
            raise SystemExit(2 if r["dry_run"] else 0)
        print(json.dumps(verify_backup(a.file,
                                       passphrase_file=a.passphrase_file,
                                       keyfile=a.keyfile),
                         indent=2, sort_keys=True))
    except BackupError as e:
        print("refused: %s" % e)
        raise SystemExit(1)
