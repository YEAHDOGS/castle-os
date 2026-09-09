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
if grep -q "REFUSED" profile/airootfs/usr/local/bin/castle-mode; then
    ok "castle-mode refuses nuke (interlock present)"
else
    fail "castle-mode missing nuke refusal"
fi
if grep -qE 'dd\s+if=|mkfs\.|wipefs|shred' profile/airootfs/usr/local/bin/castle-mode; then
    fail "castle-mode contains destructive commands — not allowed in Phase 1"
else
    ok "castle-mode contains no destructive commands"
fi

# 3. shell syntax --------------------------------------------------------------
for s in build.sh verify.sh profile/airootfs/usr/local/bin/castle-mode; do
    if bash -n "$s"; then ok "bash -n: $s"; else fail "bash -n: $s"; fi
done

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
