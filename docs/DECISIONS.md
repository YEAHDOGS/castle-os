# Castle OS — decisions (Phase 1)

## Wayland compositor: labwc (not sway)

Design spec: GUI mode runs on "a Wayland compositor". The two serious
lightweight candidates on Arch:

| | labwc | sway |
|---|---|---|
| Style | Stacking (Openbox-like) | Tiling (i3-like) |
| Config surface | Small (`rc.xml`, `autostart`) | Large (full i3-style config language) |
| Footprint | Tiny; few dependencies | Bigger; pulls more of the wlroots stack surface |
| Audience fit | Appliance/kiosk: user mostly needs a terminal + launcher | Power-user tiling workflow |

**Chosen: labwc.** Rationale:

1. Castle OS is an *appliance* first. The GUI exists so a human can do
   first-boot setup, check status, and open a terminal — not to be a daily
   driver. A stacking compositor with three keybinds (terminal, launcher,
   close) covers that with the least code and the least that can break.
2. Smaller config = fewer Phase 1 bugs we can't test (no Arch box yet).
3. wlroots-based, so the whole `swaybg`/`wofi`/`foot` ecosystem just works.

**Honest caveat:** this is reasoning, not benchmarking — neither compositor
has been run on Castle hardware yet. If labwc misbehaves in QEMU testing,
sway is the documented fallback (swap `labwc` for `sway` in
`profile/packages.gui.x86_64`, point `.bash_profile` at it, done — the
mode-selection plumbing doesn't care which compositor it execs).

## Two modes, one ISO

Both modes ship on one ISO, selected in the bootloader (BIOS + UEFI),
passed as `castle.mode=cli|gui` on the kernel command line. The package
lists are per-mode fragments (`packages.base` + `packages.cli|gui`),
assembled by `build.sh` — so the headless image never contains GUI
packages and vice versa. No runtime package surgery, no bloat.

**Default: headless CLI.** Castle's primary jobs (router, NAS, always-on
box) are headless; the default should match the appliance, not the demo.

## GUI session without a display manager

No GDM/SDDM/LightDM in Phase 1 — that's a whole service stack for one
autologin. Instead: systemd autologins root on tty1 (same as releng),
and root's `.bash_profile` execs `labwc` only when `castle.mode=gui`
is on the cmdline. One file, obvious behavior, trivially revertible.

## What's in the base package list

Deliberately small: kernel, firmware, networking (NetworkManager + iwd),
disk/boot tooling the installer needs, and the Castle Python runtime.
The *roles* (Samba shares, firewall policy, VPN gateway, arcade
emulators) are Phase 2 — a Phase 1 ISO that claims to be a router but
isn't configured as one would be dishonest. See PHASE2-TODO.md.

## Official repos only

Every package is verified against `archlinux.org`'s package API in
`build.sh verify`. No AUR helpers, no third-party mirrors, no binary
blobs from unfamiliar hosts. If it isn't in core/extra, it doesn't ship.

## Branding restraint

Text-mode bootloader theme (amber-on-black), `/etc/issue` + `/etc/motd`,
hostname `castle`. Custom splash art and wallpaper are Phase 2 —
a generated PNG committed blind, untested, would be worse than none.
