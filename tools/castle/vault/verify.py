#!/usr/bin/env python3
"""Vault integrity: drift audits — FAMILY-DATA-VAULT.md build-order step 6.

Re-scans a vault directory against a manifest (``manifest.py``) and
classifies every file:

  - ADDED:     on disk, not in the manifest (new file since the snapshot)
  - REMOVED:   in the manifest, gone from disk
  - MODIFIED:  in both, but size or SHA-256 differs
  - UNCHANGED: in both, size and SHA-256 match (mtime drift alone is not
               a modification — only byte changes count)

``audit(root, manifest_doc)`` returns a result dict with the four lists
plus a ``clean`` flag. ``main()`` is the CLI used by ``vault.py audit``:
human-readable diff, exit code 0 when clean, non-zero otherwise.

The manifest's ``skipped`` list (symlinks, non-regular files) is
carried into the result so the report is honest about what it did NOT
cover. A file that appears on disk as a *new symlink* is reported in
``skipped_new``, not ADDED — the manifest builder never hashes
symlinks, so an audit must not claim a link is a new file.

Stdlib only. No network, no new hosts.
"""

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import manifest as _manifest  # noqa: E402


def audit(root, doc):
    """Compare the current state of ``root`` against a loaded manifest
    document. Returns a result dict; ``result['clean']`` is True when
    there is nothing to report."""
    new_doc = _manifest.build_manifest(root)
    old = {e["path"]: e for e in doc["entries"]}
    new = {e["path"]: e for e in new_doc["entries"]}
    added, removed, modified, unchanged = [], [], [], []
    for path in sorted(set(old) | set(new)):
        if path not in old:
            added.append(path)
        elif path not in new:
            removed.append(path)
        elif (old[path]["size"] != new[path]["size"]
              or old[path]["sha256"] != new[path]["sha256"]):
            modified.append(path)
        else:
            unchanged.append(path)
    skipped_old = {e["path"] for e in doc.get("skipped", [])}
    skipped_new = {e["path"] for e in new_doc.get("skipped", [])}
    skipped_new_only = sorted(skipped_new - skipped_old)
    clean = not (added or removed or modified or skipped_new_only)
    return {
        "root": new_doc["root"],
        "manifest_created": doc.get("created"),
        "added": added,
        "removed": removed,
        "modified": modified,
        "unchanged": unchanged,
        "skipped_new": skipped_new_only,
        "clean": clean,
    }


def format_result(result):
    """Human-readable diff. Returns the report string."""
    lines = ["audit of %s (manifest %s):" % (
        result["root"], result["manifest_created"] or "unknown")]
    def _sec(label, paths):
        lines.append("  %s (%d):" % (label, len(paths)))
        for p in paths:
            lines.append("    %s %s" % (
                {"ADDED": "+", "REMOVED": "-", "MODIFIED": "~",
                 "SKIPPED": "?"}.get(label, " "), p))
    if result["clean"]:
        lines.append("  clean — %d file(s) unchanged"
                     % len(result["unchanged"]))
    else:
        _sec("ADDED", result["added"])
        _sec("REMOVED", result["removed"])
        _sec("MODIFIED", result["modified"])
        _sec("SKIPPED", result["skipped_new"])
    return "\n".join(lines)


def audit_to_json(result):
    """Machine-readable form of the result (manifests may be diffed by
    tooling)."""
    return json.dumps(result, indent=2, sort_keys=True) + "\n"


def run_audit(root, manifest_path, json_out=False):
    """Load the manifest, audit, print, and return an exit code:
    0 when clean, 2 when differences were found."""
    doc = _manifest.load_manifest(manifest_path)
    result = audit(root, doc)
    if json_out:
        print(audit_to_json(result), end="")
    else:
        print(format_result(result))
    return 0 if result["clean"] else 2


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        description="audit a vault directory against a manifest")
    ap.add_argument("dir", help="vault directory to re-scan")
    ap.add_argument("--manifest", required=True,
                    help="manifest file written by the manifest builder")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable output instead of the diff")
    a = ap.parse_args(argv)
    try:
        return run_audit(a.dir, a.manifest, json_out=a.json)
    except _manifest.ManifestError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
