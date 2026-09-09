#!/usr/bin/env bash
# shellcheck disable=SC2034
# Castle OS archiso profile definition.
# Derived from archiso's releng profile; only the identity and the file
# permission list were changed.

iso_name="castle"
iso_label="CASTLE_$(date --date="@${SOURCE_DATE_EPOCH:-$(date +%s)}" +%Y%m)"
iso_publisher="DOGS <https://github.com/YEAHDOGS/castle-os>"
iso_application="Castle OS Live ISO"
iso_version="$(date --date="@${SOURCE_DATE_EPOCH:-$(date +%s)}" +%Y.%m.%d)"
install_dir="castle"
buildmodes=('iso')
bootmodes=('bios.syslinux'
           'uefi.systemd-boot')
pacman_conf="pacman.conf"
airootfs_image_type="squashfs"
airootfs_image_tool_options=('-comp' 'xz' '-Xbcj' 'x86,arm64' '-b' '1M' '-Xdict-size' '1M')
bootstrap_tarball_compression=('zstd' '-c' '-T0' '--auto-threads=logical' '--long' '-19')
# NOTE: the explicit declare -A keeps this sourceable even on bash builds
# with quirky subscript expansion (e.g. minimal container bashes);
# on stock Arch bash the compound assignment alone would suffice.
declare -A file_permissions
file_permissions=(
  ["/etc/shadow"]="0:0:400"
  ["/root"]="0:0:750"
  ["/root/.gnupg"]="0:0:700"
  ["/usr/local/bin/castle"]="0:0:755"
  ["/usr/local/bin/castle-install"]="0:0:755"
)
