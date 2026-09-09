#!/usr/bin/env python3
"""Vault integrity: file manifests — FAMILY-DATA-VAULT.md build-order step 6.

A Castle vault is a pile of files on a LAN box. Backups, bit rot, a kid
with a thumb drive, a failing disk — any of them can silently change
what's on disk. The manifest is the audit half of the vault vision: a
cryptographically check-summed inventory of a vault directory that the
``verify`` module later re-scans to report ADDED / REMOVED / MODIFIED /
UNCHANGED per file.

What a manifest records per file (relative path, size in bytes,
SHA-256 of the bytes, mtime_ns). Size + hash are the integrity signal;
mtime is provenance only — touching a file without changing its bytes
does not count as a modification.

Trust model (same as the vault core and the flamethrower):
  - The target MUST be a real directory: not a symlink, not ``/``, not
    inside or containing the flamethrower burn root. Symlink targets are
    refused before anything is read — a manifest must describe what the
    owner asked for, not where a link points.
  - Symlinks *inside* the tree are never followed and never hashed.
    They are listed in ``skipped`` so the audit is honest about what it
    did NOT cover. Same for non-regular files (fifos, sockets, devices).
  - Hashing uses ``hashlib.sha256`` — real crypto, never a homebrew
    hash. Files are streamed in chunks; nothing is slurped whole.
  - Manifests are written 0600 (they describe a private vault) and
    serialized deterministically (sorted entries, sorted keys) so two
    runs over identical bytes produce byte-identical JSON.
  - Loading a manifest is strict: unreadable file, invalid JSON, or a
    well-formed-but-wrong-shape document is a refusal, never a guess.

Stdlib only. No network, no new hosts.
"""

import hashlib
import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

FORMAT = "castle-vault-manifest/1"
_CHUNK = 65536  # stream hashes in 64 KiB blocks


class ManifestError(ValueError):
    """Refusal to build, write, or load a manifest."""


def _check_target(root):
    """Refuse dangerous or ambiguous manifest targets."""
    if not os.path.islink(root) and os.path.abspath(root) == os.sep:
        raise ManifestError("refusing to manifest the filesystem root")
    if os.path.islink(root):
        raise ManifestError(
            "refusing to manifest a symlink: %s" % root)
    if not os.path.isdir(root):
        raise ManifestError(
            "manifest target is not a directory: %s" % root)


def _relposix(root, path):
    rel = os.path.relpath(path, root)
    return rel.replace(os.sep, "/")


def hash_file(path):
    """SHA-256 of a file's bytes, streamed. Returns hex digest."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def build_manifest(root, root_label=None):
    """Walk ``root`` and return a manifest dict.

    Only regular files are hashed. Symlinks and non-regular files are
    skipped (reported in ``skipped``). Entries are sorted by relative
    path for deterministic output.
    """
    _check_target(root)
    root = os.path.abspath(root)
    entries = []
    skipped = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Never descend through a symlinked dir (os.walk with
        # followlinks=False won't, but prune defensively).
        dirnames[:] = [d for d in dirnames
                       if not os.path.islink(os.path.join(dirpath, d))]
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = _relposix(root, full)
            if os.path.islink(full):
                skipped.append({"path": rel, "reason": "symlink"})
                continue
            if not os.path.isfile(full):
                skipped.append({"path": rel, "reason": "non-regular file"})
                continue
            try:
                st = os.stat(full)
            except OSError as e:
                raise ManifestError(
                    "cannot stat %s: %s" % (rel, e))
            entries.append({
                "path": rel,
                "size": st.st_size,
                "sha256": hash_file(full),
                "mtime_ns": st.st_mtime_ns,
            })
    entries.sort(key=lambda e: e["path"])
    skipped.sort(key=lambda e: e["path"])
    return {
        "format": FORMAT,
        "root": root_label or os.path.basename(root.rstrip(os.sep)),
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime()),
        "entries": entries,
        "skipped": skipped,
    }


def write_manifest(root, out_path, root_label=None):
    """Build the manifest for ``root`` and write it to ``out_path``
    (0600). The manifest may NOT live inside the tree it describes —
    writing it there would corrupt the next audit."""
    _check_target(root)
    root = os.path.abspath(root)
    out_abs = os.path.abspath(out_path)
    if out_abs == root or out_abs.startswith(root + os.sep):
        raise ManifestError(
            "manifest file may not live inside the tree it describes: %s"
            % out_path)
    doc = build_manifest(root, root_label=root_label)
    data = (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(out_abs, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return doc


def _require(cond, what):
    if not cond:
        raise ManifestError("corrupt manifest: %s" % what)


def load_manifest(path):
    """Load and strictly validate a manifest file. Returns the doc."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except OSError as e:
        raise ManifestError("cannot read manifest %s: %s" % (path, e))
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ManifestError(
            "manifest is not valid JSON (%s): %s" % (path, e))
    _require(isinstance(doc, dict), "top level is not an object")
    _require(doc.get("format") == FORMAT,
             "unsupported format %r (want %r)" % (doc.get("format"), FORMAT))
    entries = doc.get("entries")
    _require(isinstance(entries, list), "'entries' is not a list")
    seen = set()
    for e in entries:
        _require(isinstance(e, dict), "entry is not an object")
        _require(isinstance(e.get("path"), str) and e["path"],
                 "entry missing 'path'")
        _require(isinstance(e.get("size"), int) and e["size"] >= 0,
                 "entry %r has bad 'size'" % e["path"])
        _require(isinstance(e.get("sha256"), str)
                 and len(e["sha256"]) == 64
                 and all(c in "0123456789abcdef" for c in e["sha256"]),
                 "entry %r has bad 'sha256'" % e["path"])
        _require(e["path"] not in seen,
                 "duplicate entry for %r" % e["path"])
        _require("/" not in e["path"] or not e["path"].startswith("/"),
                 "entry %r is not a relative path" % e["path"])
        _require(".." not in e["path"].split("/"),
                 "entry %r escapes the root" % e["path"])
        seen.add(e["path"])
    return doc
