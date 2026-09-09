# Castle OS — Phase 2 TODO

Everything deliberately left out of Phase 1. Nothing here is promised;
it's the honest backlog.

## Must happen before anyone flashes real hardware

- [ ] Build both ISOs on a real Arch box (`docs/RUNBOOK.md` §5 checklist)
- [ ] Boot BIOS + UEFI in QEMU, both modes
- [ ] `castle-install` full run against a blank virtual disk
- [ ] Decide: keep the simple installer or adopt `archinstall` as the engine

## Distribution plumbing (the "Clone Wars" part)

- [ ] Castle package repository (signed) + `pacman.conf` snippet
- [ ] Update channel: how installed systems get Castle updates
      (repo + timer? image-based A/B? — decision needed)
- [ ] Versioning / release process for ISOs

## Appliance roles (the actual vision)

- [ ] Router: nftables policy, DHCP/DNS (dnsmasq is installed; policy isn't),
      sane WAN/LAN defaults, web or TUI status
- [ ] NAS / private cloud: Samba shares, storage pooling, the 10TB-drive story
- [ ] Arcade: emulator set, controller support, kiosk launcher
- [ ] Headless-first admin: SSH hardening, web dashboard or TUI

## Castle integration

- [ ] Castle secrets vault + token system as first-class services
      (today they're CLI tools in /opt/castle)
- [ ] The Kotlin server/app — needs a JVM packaging story; was NOT
      force-fit into Phase 1 for exactly this reason
- [ ] QEMU/hypervisor bits from `clonewars/` (Windows-oriented today;
      needs a Linux-native rethink)
- [ ] DOGS ID gate integration for the local admin UI (when it exists)

## Polish

- [ ] Custom syslinux splash + systemd-boot theme
- [ ] Real wallpaper art (hook is already there: labwc `autostart`)
- [ ] Non-root daily user + privilege model (Phase 1 live session is root,
      like every Arch live medium — fine for install/rescue, not for daily use)
- [ ] Secure Boot story
- [ ] Accessibility boot entry (releng has one; dropped for size — reconsider)

## Out of scope on purpose

- ARM images (x86_64 only in Phase 1)
- Anything requiring the AUR at build time
