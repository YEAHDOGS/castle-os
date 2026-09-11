# Castle OS 🏰 - Work in Progress

Castle OS is Castle as its own Linux distribution: a flashable appliance based
directly on rolling **Arch Linux** that can act as a **router**, a **NAS /
private cloud**, and an **arcade**.

**Phase 1 (this repo):** a bootable live ISO with a simple disk installer.
Package repository and update channel are **Phase 2** (see
[docs/PHASE2-TODO.md](docs/PHASE2-TODO.md)) — deliberately not built here.

## Two modes

The ISO boots into one of two modes, selectable in the bootloader menu:

| Mode | What you get |
|---|---|
| **Headless CLI** (default) | Minimal console system. No GUI packages installed. This is the router / NAS / server personality. |
| **GUI (Wayland)** | [labwc](https://labwc.github.io) stacking Wayland compositor + `foot` terminal + `wofi` launcher. See [docs/DECISIONS.md](docs/DECISIONS.md) for why labwc. |

The choice is passed as `castle.mode=cli|gui` on the kernel command line.
On first login, root's shell starts the compositor automatically in GUI mode.

## Quick start (on a real Arch machine)

```bash
sudo pacman -S archiso
git clone https://github.com/YEAHDOGS/castle-os.git
cd castle-os
./build.sh cli      # headless ISO
./build.sh gui      # GUI ISO
# ISO lands in out/
```

Full reproduction steps, QEMU test command, and flashing instructions:
**[docs/RUNBOOK.md](docs/RUNBOOK.md)**.

## How to get the ISO

The ISOs are built automatically by the
[`build-iso`](https://github.com/YEAHDOGS/castle-os/actions/workflows/build-iso.yml)
workflow on every `master` push that touches the profile, tools, or build
script (and can be run manually via **Actions → build-iso → Run workflow**).

1. Go to **Actions → build-iso** and open the latest green run.
2. Download the `castle-os-iso` artifact — it contains both
   `castle-*-x86_64.iso` files (headless CLI and GUI Wayland).

Then flash per **[docs/RUNBOOK.md](docs/RUNBOOK.md)**. Nothing is deployed
anywhere by CI; the artifact ISOs are the deliverable.

## Layout

```
build.sh                 # assemble profile for a mode, run mkarchiso
profile/                 # archiso profile (based on releng)
  profiledef.sh          # ISO identity: name "castle", label CASTLE_*
  pacman.conf            # official Arch repos only (core + extra)
  packages.base.x86_64   # common packages
  packages.cli.x86_64    # headless extras
  packages.gui.x86_64    # Wayland extras
  syslinux/  efiboot/    # BIOS + UEFI boot menus (CLI / GUI entries)
  airootfs/              # live-system overlay: branding, autologin,
                         # labwc config, vendored Castle tools
tools/
  castle-install         # simple guided installer: live system -> disk
  castle/                # portable Castle Python tools (vault, tokens,
                         # backup intake, flamethrower) — stdlib only
docs/
  RUNBOOK.md             # exact build / test / flash commands
  DECISIONS.md           # labwc vs sway, defaults, trade-offs
  PHASE2-TODO.md         # everything deliberately left out
```

## Castle tools on the live system

`/opt/castle/` ships the portable Python tools from the Castle repo
(`vault`, `tokens`, `backup`, `flamethrower`) — all standard-library only, no
extra dependencies. The `castle` command lists and runs them. Anything with
undeclared or heavy dependencies (the Kotlin server/app, QEMU/Windows
hypervisor bits) is **not** force-fit — it's on the Phase 2 list.

## What was verified (without a real Arch box)

- `profiledef.sh` sources cleanly; all required archiso variables present.
- Package fragments: every package name checked against the official
  Arch package API (`archlinux.org`) — all exist in core/extra, no AUR,
  no third-party mirrors.
- `bash -n` clean on `build.sh`, `tools/castle-install`, `usr/local/bin/castle`.
- Vendored Python tools byte-identical to the Castle repo and importable
  (`py_compile` + import smoke test).
- Bootloader configs derived from current `releng` with the smallest
  possible diff (mode entries + branding only).

## What still needs a real Arch box

- Running `mkarchiso` end-to-end for both modes.
- Booting the ISO in QEMU (BIOS + UEFI) and checking both modes come up.
- Running `castle-install` against a blank virtual disk.
- Installing the produced system and confirming the Castle tools work there.

## License

MIT — see [LICENSE](LICENSE).
