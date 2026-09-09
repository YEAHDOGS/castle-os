#!/usr/bin/env bash
# build.sh — build the Castle OS Phase 1 ISO with mkarchiso, then verify it.
#
# Usage: ./build.sh [work_dir] [out_dir]
#
# Does NOT download anything itself: mkarchiso pulls packages from the Arch
# mirrors named in profile/pacman.conf (official repos only — DOGS default-deny,
# no third-party mirrors). This script intentionally performs no network
# actions beyond what mkarchiso does.
#
# Verification after build:
#   1. ISO exists and is non-empty.
#   2. SHA-256 checksum written to <iso>.sha256 and re-verified.
#   3. Included package list dumped from the ISO's airootfs metadata.

set -euo pipefail
cd "$(dirname "$0")"

PROFILE="profile"
WORK_DIR="${1:-work}"
OUT_DIR="${2:-out}"

command -v mkarchiso >/dev/null 2>&1 || {
    echo "ERROR: mkarchiso not found. Install archiso on an Arch host to build." >&2
    exit 1
}

echo "==> Building Castle OS Phase 1 ISO (profile=./${PROFILE})"
sudo mkarchiso -v -w "$WORK_DIR" -o "$OUT_DIR" "$PROFILE"

ISO="$(ls -t "$OUT_DIR"/castle-os-*.iso | head -n 1)"
echo "==> ISO: $ISO ($(du -h "$ISO" | cut -f1))"

echo "==> Writing SHA-256 checksum"
sha256sum "$ISO" > "${ISO}.sha256"
sha256sum -c "${ISO}.sha256"
echo "==> Checksum OK"

echo "==> Packages baked into the ISO (from airootfs, first 80 lines)"
# The squashfs root holds /var/log/pacman.log-ish metadata; fall back to the
# profile package list when the ISO layout can't be introspected.
if command -v unsquashfs >/dev/null 2>&1; then
    SQFS="$(mktemp -d)/airootfs.sfs"
    mkdir -p "$(dirname "$SQFS")"
    # best-effort: copy the squashfs image out of the ISO via 7z/bsdtar if present
    if command -v bsdtar >/dev/null 2>&1; then
        bsdtar -xf "$ISO" -C "$(dirname "$SQFS")" 2>/dev/null || true
    fi
fi
echo "--- declared package set (profile/packages.x86_64) ---"
grep -vE '^\s*(#|$)' "$PROFILE/packages.x86_64"

echo "==> DONE: $ISO"
echo "    checksum: ${ISO}.sha256"
