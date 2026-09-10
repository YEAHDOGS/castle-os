#!/usr/bin/env bash
# verify.sh — assert the Castle OS Phase 1 archiso profile scaffold is intact.
# Run: ./verify.sh   (exit 0 = all green)
#
# Checks:
#   1. Every required profile file exists.
#   2. castle-mode refuses nuke (safety interlock present, no wipe code).
#   3. All shell scripts pass `bash -n`.
#   4. Boot entries reference a consistent castle.mode set.

set -euo pipefail
cd "$(dirname "$0")"

PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); echo "PASS: $1"; }
fail() { FAIL=$((FAIL+1)); echo "FAIL: $1"; }

# 1. required files -----------------------------------------------------------
REQUIRED=(
  profile/profiledef.sh
  profile/packages.x86_64
  profile/pacman.conf
  profile/airootfs/usr/local/bin/castle-mode
  profile/airootfs/usr/local/bin/castle-disks
  profile/airootfs/etc/motd
  profile/syslinux/syslinux.cfg
  profile/efiboot/loader/loader.conf
  profile/efiboot/loader/entries/castle-analyze.conf
  profile/efiboot/loader/entries/castle-backup.conf
  profile/efiboot/loader/entries/castle-nuke.conf
  profile/efiboot/loader/entries/castle-reinstall.conf
  build.sh
  verify.sh
  docs/CASTLE-OS-PHASE1.md
  README.md
)
for f in "${REQUIRED[@]}"; do
    [ -f "$f" ] && ok "exists: $f" || fail "missing: $f"
done

# 2. nuke safety interlock ----------------------------------------------------
# No destructive commands may exist anywhere in the live-system bin dir:
# enumeration is the only allowed disk interaction in Phase 1.
BIN="profile/airootfs/usr/local/bin"
if grep -q "REFUSED" "$BIN/castle-mode"; then
    ok "castle-mode refuses nuke (interlock present)"
else
    fail "castle-mode missing nuke refusal"
fi
if grep -vE '^\s*#' "$BIN"/castle-* | grep -qE 'dd\s+if=|mkfs\.|wipefs|shred'; then
    fail "destructive commands found in $BIN — not allowed in Phase 1"
else
    ok "no destructive commands in $BIN (enumeration only)"
fi

# 3. shell syntax --------------------------------------------------------------
for s in build.sh verify.sh profile/airootfs/usr/local/bin/castle-mode profile/airootfs/usr/local/bin/castle-disks; do
    if bash -n "$s"; then ok "bash -n: $s"; else fail "bash -n: $s"; fi
done
if bash -n profile/profiledef.sh; then
    ok "bash -n: profile/profiledef.sh"
else
    fail "bash -n: profile/profiledef.sh"
fi

# 5. profile hygiene -----------------------------------------------------------
# pacman.conf: official repos only — no hardcoded Server lines, mirrorlist
# includes only (DOGS default-deny, no third-party mirrors).
if grep -qE '^\s*Server\s*=' profile/pacman.conf; then
    fail "pacman.conf has hardcoded Server lines"
else
    ok "pacman.conf has no hardcoded Server lines"
fi
if grep -q '^\[core\]' profile/pacman.conf && grep -q '^\[extra\]' profile/pacman.conf; then
    ok "pacman.conf declares [core] and [extra]"
else
    fail "pacman.conf missing [core]/[extra] repos"
fi
# packages.x86_64: no duplicate entries.
DUPS="$(grep -vE '^\s*(#|$)' profile/packages.x86_64 | sort | uniq -d)"
if [ -z "$DUPS" ]; then
    ok "packages.x86_64 has no duplicate entries"
else
    fail "packages.x86_64 duplicates: $DUPS"
fi
# build.sh: checksum write + re-verify steps must be present.
if grep -q 'sha256sum' build.sh && grep -q 'sha256sum -c' build.sh; then
    ok "build.sh writes and re-verifies SHA-256 checksum"
else
    fail "build.sh missing SHA-256 write/verify steps"
fi
# build.sh: pre-flight verify.sh gate must be present.
if grep -q '\./verify\.sh' build.sh; then
    ok "build.sh runs ./verify.sh as a pre-flight gate"
else
    fail "build.sh missing pre-flight verify.sh gate"
fi
# syslinux has the GUI boot entry the docs promise.
if grep -q 'LABEL castle-gui' profile/syslinux/syslinux.cfg; then
    ok "syslinux defines the GUI boot entry"
else
    fail "syslinux missing castle-gui entry"
fi

# 4. boot entries agree on castle.mode values ----------------------------------
for mode in analyze backup nuke reinstall; do
    if grep -q "castle.mode=$mode" profile/efiboot/loader/entries/castle-"$mode".conf \
        && grep -q "castle.mode=$mode" profile/syslinux/syslinux.cfg; then
        ok "boot entries define castle.mode=$mode (uefi + bios)"
    else
        fail "boot entries inconsistent for castle.mode=$mode"
    fi
done

echo "----"
echo "verify: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
