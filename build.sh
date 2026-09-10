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
# Steps:
#   0. Pre-flight gate: ./verify.sh must pass (fail fast on scaffold drift).
#   1. mkarchiso build on profile/.
#   2. ISO sanity: exists, non-empty, above a gross minimum size.
#   3. Provenance file: <iso>.build-info.txt (date, git commit, profile
#      checksums, mkarchiso version) so any ISO can be traced back to source.
#   4. SHA-256 checksum written to <iso>.sha256 and re-verified.
#   5. Package listing: declared set from profile/packages.x86_64.
#
# mkarchiso is not a reproducible build; the .build-info.txt records what we
# can (exact profile inputs + builder version) so two ISOs can be compared.

set -euo pipefail
cd "$(dirname "$0")"

PROFILE="profile"
WORK_DIR="${1:-work}"
OUT_DIR="${2:-out}"

command -v mkarchiso >/dev/null 2>&1 || {
    echo "ERROR: mkarchiso not found. Install archiso on an Arch host to build." >&2
    exit 1
}

echo "==> Pre-flight: running ./verify.sh"
./verify.sh
echo "==> Pre-flight green"

echo "==> Building Castle OS Phase 1 ISO (profile=./${PROFILE})"
sudo mkarchiso -v -w "$WORK_DIR" -o "$OUT_DIR" "$PROFILE"

ISO="$(ls -t "$OUT_DIR"/castle-os-*.iso | head -n 1)"
echo "==> ISO: $ISO ($(du -h "$ISO" | cut -f1))"

# Sanity: non-empty and above a gross minimum (a real rescue ISO is hundreds
# of MB; anything under 10M means the build silently produced garbage).
[ -s "$ISO" ] || { echo "ERROR: ISO is empty: $ISO" >&2; exit 1; }
ISO_BYTES="$(stat -c%s "$ISO")"
[ "$ISO_BYTES" -ge 10485760 ] || {
    echo "ERROR: ISO suspiciously small (${ISO_BYTES} bytes): $ISO" >&2
    exit 1
}
echo "==> ISO sanity OK (${ISO_BYTES} bytes)"

# Provenance: tie this ISO back to exact source inputs.
INFO="${ISO%.iso}.build-info.txt"
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo 'not-a-git-repo')"
# NOTE: profiledef.sh cannot be sourced wholesale here — its file_permissions
# associative array needs mkarchiso's pre-declaration. Evaluate only the
# iso_version assignment line.
ISO_VERSION="$(eval "$(grep -E '^iso_version=' "$PROFILE/profiledef.sh")"; printf '%s' "$iso_version")"
MKARCHISO_VER="$(mkarchiso -V 2>/dev/null || mkarchiso --version 2>/dev/null || echo 'unknown')"
{
    echo "castle-os Phase 1 build provenance"
    echo "build_date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "git_commit=$GIT_COMMIT"
    echo "iso_version=$ISO_VERSION"
    echo "mkarchiso_version=$MKARCHISO_VER"
    echo "profiledef.sh_sha256=$(sha256sum "$PROFILE/profiledef.sh" | cut -d' ' -f1)"
    echo "packages.x86_64_sha256=$(sha256sum "$PROFILE/packages.x86_64" | cut -d' ' -f1)"
    echo "pacman.conf_sha256=$(sha256sum "$PROFILE/pacman.conf" | cut -d' ' -f1)"
} > "$INFO"
echo "==> Wrote provenance: $INFO"

echo "==> Writing SHA-256 checksum"
sha256sum "$ISO" > "${ISO}.sha256"
sha256sum -c "${ISO}.sha256"
echo "==> Checksum OK"

echo "==> Packages declared for the ISO (profile/packages.x86_64)"
grep -vE '^\s*(#|$)' "$PROFILE/packages.x86_64"

echo "==> DONE: $ISO"
echo "    checksum:   ${ISO}.sha256"
echo "    provenance: ${INFO}"
