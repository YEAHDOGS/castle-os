#!/usr/bin/env bash
#
# build.sh — assemble the Castle archiso profile for a mode and build the ISO.
#
#   ./build.sh cli      build the headless ISO
#   ./build.sh gui      build the Wayland GUI ISO
#   ./build.sh verify   run every check that works without mkarchiso
#
# Needs a real Arch Linux machine/VM: mkarchiso requires pacman, root and
# loop devices. See docs/RUNBOOK.md. This script refuses to fake a build.
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE_SRC="$REPO_DIR/profile"
OUT_DIR="$REPO_DIR/out"

usage() {
    cat <<'EOF'
Usage: ./build.sh <cli|gui|verify>

  cli      assemble profile-cli and run mkarchiso (headless ISO)
  gui      assemble profile-gui and run mkarchiso (Wayland ISO)
  verify   run all offline checks (profile syntax, package sanity,
           shell syntax, python imports) — no mkarchiso needed
EOF
}

die() { echo "build.sh: ERROR: $*" >&2; exit 1; }

# pkg_names <fragment> — one clean package name per line: strips full-line
# comments, blank lines, trailing "# comment"s and surrounding whitespace.
# Arch package names never contain '#', so splitting there is safe.
pkg_names() {
    sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$1" | grep -vE '^$' || true
}

# ---------------------------------------------------------------------------
# verify: everything checkable without a real Arch box
# ---------------------------------------------------------------------------
cmd_verify() {
    local failures=0

    echo "==> bash syntax"
    for f in "$REPO_DIR/build.sh" \
             "$REPO_DIR/tools/castle-install" \
             "$REPO_DIR/profile/airootfs/usr/local/bin/castle" \
             "$REPO_DIR/profile/airootfs/root/.bash_profile" \
             "$REPO_DIR/profile/airootfs/root/.config/labwc/autostart" \
             "$REPO_DIR/profile/profiledef.sh"; do
        if [[ -f "$f" ]]; then
            bash -n "$f" && echo "  OK $f" || { echo "  FAIL $f"; failures=$((failures+1)); }
        fi
    done

    echo "==> profiledef.sh sources cleanly and defines required vars"
    # shellcheck disable=SC1090
    if ( source "$PROFILE_SRC/profiledef.sh" >/dev/null 2>&1 &&
         [[ -n "${iso_name:-}" && -n "${iso_label:-}" && -n "${install_dir:-}" &&
             -n "${pacman_conf:-}" && ${#buildmodes[@]} -gt 0 && ${#bootmodes[@]} -gt 0 ]] ); then
        # shellcheck disable=SC1090
        source "$PROFILE_SRC/profiledef.sh" >/dev/null 2>&1
        echo "  OK iso_name=$iso_name install_dir=$install_dir bootmodes=${bootmodes[*]}"
    else
        echo "  FAIL profiledef.sh missing required archiso variables"; failures=$((failures+1))
    fi

    echo "==> package fragments: format + official-repo existence"
    for frag in base cli gui; do
        local f="$PROFILE_SRC/packages.$frag.x86_64"
        [[ -f "$f" ]] || { echo "  FAIL missing $f"; failures=$((failures+1)); continue; }
        # no duplicates inside a fragment, no stray whitespace-only lines
        if grep -qE '^[[:space:]]*$' "$f"; then
            echo "  WARN $f contains blank lines (harmless, archiso skips them)"
        fi
        local dupes
        dupes=$(pkg_names "$f" | sort | uniq -d || true)
        if [[ -n "$dupes" ]]; then
            echo "  FAIL duplicate packages in $f: $dupes"; failures=$((failures+1))
        fi
        local bad=0
        while IFS= read -r pkg; do
            pkg="${pkg%%#*}"                    # strip trailing comments
            pkg="$(echo "$pkg" | tr -d '[:space:]')"
            [[ -z "$pkg" ]] && continue
            if ! curl -sf --max-time 20 \
                    "https://archlinux.org/packages/search/json/?name=${pkg}" \
                    | python3 -c "
import json, sys
names = {r['pkgname'] for r in json.load(sys.stdin)['results']}
sys.exit(0 if '${pkg}' in names else 1)
" >/dev/null 2>&1; then
                echo "  FAIL not in official Arch repos: $pkg"; bad=1
            fi
        done < "$f"
        [[ $bad -eq 0 ]] && echo "  OK packages.$frag.x86_64 ($(grep -vcE '^\s*(#|$)' "$f") packages)" \
            || failures=$((failures+1))
    done

    echo "==> cross-fragment duplicates"
    local all_dupes
    all_dupes=$( { for frag in "$PROFILE_SRC"/packages.*.x86_64; do pkg_names "$frag"; done; } | sort | uniq -d || true)
    if [[ -n "$all_dupes" ]]; then
        echo "  FAIL package listed in more than one fragment: $all_dupes"; failures=$((failures+1))
    else
        echo "  OK no package in two fragments"
    fi

    echo "==> vendored Castle python tools import cleanly"
    for tool in "$REPO_DIR"/tools/castle/*/*.py; do
        python3 -m py_compile "$tool" 2>/dev/null \
            && echo "  OK $(basename "$tool")" \
            || { echo "  FAIL py_compile $tool"; failures=$((failures+1)); }
    done

    echo "==> bootloader configs reference the castle install dir"
    grep -q "castle" "$PROFILE_SRC/efiboot/loader/entries/01-castle-cli.conf" \
        && grep -q "castle.mode=gui" "$PROFILE_SRC/efiboot/loader/entries/02-castle-gui.conf" \
        && grep -q "castle.mode=cli" "$PROFILE_SRC/syslinux/archiso_sys-linux.cfg" \
        && grep -q "castle.mode=gui" "$PROFILE_SRC/syslinux/archiso_sys-linux.cfg" \
        && echo "  OK mode entries present (BIOS + UEFI)" \
        || { echo "  FAIL mode entries missing/mismatched"; failures=$((failures+1)); }

    if [[ $failures -eq 0 ]]; then
        echo "VERIFY: all checks passed."
    else
        die "VERIFY: $failures check(s) failed."
    fi
}

# ---------------------------------------------------------------------------
# assemble: build out/profile-<mode>/ from profile/ + package fragments
# ---------------------------------------------------------------------------
cmd_assemble() {
    local mode="$1"
    [[ "$mode" == cli || "$mode" == gui ]] || die "mode must be cli or gui"
    local dest="$OUT_DIR/profile-$mode"
    rm -rf "$dest"
    mkdir -p "$OUT_DIR"
    # cp -a preserves ownership on a real build box; restricted containers
    # can't chown, so fall back to not preserving ownership there.
    cp -a "$PROFILE_SRC" "$dest" 2>/dev/null \
        || cp -a --no-preserve=ownership "$PROFILE_SRC" "$dest"
    # one package list per mode: base + mode extras (archiso reads packages.x86_64)
    {
        echo "# Castle OS $mode profile — assembled by build.sh, do not edit."
        echo "# Sources: packages.base.x86_64 + packages.$mode.x86_64"
        echo
        pkg_names "$PROFILE_SRC/packages.base.x86_64"
        pkg_names "$PROFILE_SRC/packages.$mode.x86_64"
    } > "$dest/packages.x86_64.new"
    rm -f "$dest"/packages.base.x86_64 "$dest"/packages.cli.x86_64 "$dest"/packages.gui.x86_64
    mv "$dest/packages.x86_64.new" "$dest/packages.x86_64"
    # stage Castle extras into the live overlay (kept out of profile/airootfs
    # so tools/ stays the single source of truth)
    mkdir -p "$dest/airootfs/opt" "$dest/airootfs/usr/local/bin" "$dest/airootfs/usr/share/castle-os"
    cpa() { cp -a "$@" 2>/dev/null || cp -a --no-preserve=ownership "$@"; }
    cpa "$REPO_DIR/tools/castle" "$dest/airootfs/opt/"
    cpa "$REPO_DIR/tools/castle-install" "$dest/airootfs/usr/local/bin/castle-install"
    cpa "$PROFILE_SRC"/packages.base.x86_64 "$PROFILE_SRC"/packages.cli.x86_64 \
        "$PROFILE_SRC"/packages.gui.x86_64 "$dest/airootfs/usr/share/castle-os/"
    chmod 755 "$dest/airootfs/usr/local/bin/castle-install"
    echo "assembled $dest ($(grep -vcE '^\s*(#|$)' "$dest/packages.x86_64") packages)"
}

cmd_build() {
    local mode="$1"
    command -v mkarchiso >/dev/null 2>&1 \
        || die "mkarchiso not found. This needs a real Arch box — see docs/RUNBOOK.md. Not faking it."
    [[ "$(id -u)" -eq 0 ]] \
        || die "mkarchiso needs root. Re-run with sudo (see docs/RUNBOOK.md)."
    cmd_assemble "$mode"
    mkarchiso -v -w "$OUT_DIR/work-$mode" -o "$OUT_DIR" "$OUT_DIR/profile-$mode"
    echo "ISO written to $OUT_DIR"
    ls -la "$OUT_DIR"/*.iso
}

case "${1:-}" in
    cli|gui)   cmd_build "$1" ;;
    verify)    cmd_verify ;;
    assemble)  cmd_assemble "${2:-cli}" ;;  # debugging aid: inspect the assembled profile
    *)         usage; exit 1 ;;
esac
