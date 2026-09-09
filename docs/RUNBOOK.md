# Castle OS — build runbook (Phase 1)

Exact commands to reproduce the ISO. **You need a real Arch Linux
machine or VM.** `mkarchiso` requires pacman, root, and loop devices —
it cannot run in a container without them (verified: this profile was
authored in an Ubuntu container where `mknod` on loop devices is denied,
so no ISO was produced there — and none is claimed).

## 0. Prereqs (on the Arch box)

```bash
sudo pacman -Syu --needed archiso qemu-full
```

`archiso` pulls in everything mkarchiso needs. `qemu-full` is for testing.

## 1. Build

```bash
git clone https://github.com/YEAHDOGS/castle-os.git
cd castle-os

# offline checks first (no mkarchiso needed — also runs in CI/containers)
./build.sh verify

# headless ISO
sudo ./build.sh cli
# GUI ISO
sudo ./build.sh gui
```

Output: `out/castle-*.iso`. `build.sh` assembles `out/profile-<mode>/`
from `profile/` + the package fragments, then runs:

```bash
mkarchiso -v -w out/work-<mode> -o out/ out/profile-<mode>
```

To inspect the assembled profile without building: `./build.sh assemble cli`.

## 2. Test in QEMU

```bash
ISO=out/castle-2026.09.09-x86_64.iso   # actual filename from the build

# BIOS boot, headless mode
qemu-system-x86_64 -enable-kvm -m 4G -cdrom "$ISO" -boot d

# UEFI boot, GUI mode: create an OVMF drive once, then select
# "Castle OS (GUI Wayland)" in the boot menu
qemu-system-x86_64 -enable-kvm -m 4G \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/edk2-ovmf/x64/OVMF_CODE.4m.fd \
  -drive if=pflash,format=raw,file=/tmp/OVMF_VARS.4m.fd \
  -cdrom "$ISO" -boot d
```

Expected: syslinux menu (BIOS) or systemd-boot menu (UEFI) offering
**Castle OS (headless CLI)** and **Castle OS (GUI Wayland)**. CLI mode
drops to a root shell; GUI mode starts labwc with a terminal open.
On the live system, `castle --help` lists the bundled Castle tools.

## 3. Test the installer (blank virtual disk — never your real disk)

```bash
qemu-img create -f qcow2 /tmp/castle-test.qcow2 16G
qemu-system-x86_64 -enable-kvm -m 4G \
  -drive file=/tmp/castle-test.qcow2,format=qcow2 \
  -cdrom "$ISO" -boot d
# inside the VM:
castle-install --print-plan     # review first — touches nothing
castle-install --mode cli       # then for real on the VIRTUAL disk
```

## 4. Flash to USB

```bash
# TRIPLE-CHECK the device name. This destroys it.
lsblk -dno NAME,SIZE,MODEL
sudo dd if=out/castle-*.iso of=/dev/sdX bs=4M status=progress oflag=sync
```

Or use `usbimager` / balenaEtcher if you prefer a GUI.

## 5. What "done" looks like

- [ ] `./build.sh verify` green
- [ ] Both ISOs build with no mkarchiso errors
- [ ] BIOS boot: both menu entries work
- [ ] UEFI boot: both menu entries work
- [ ] GUI mode: labwc starts, `foot` opens, `Super+D` opens wofi
- [ ] CLI mode: no Wayland packages installed (`pacman -Q labwc` fails)
- [ ] `castle vault --help` works on the live system
- [ ] `castle-install --print-plan` reads sane; full install completes in a VM

## Troubleshooting

- `mkarchiso: command not found` → `sudo pacman -S archiso`.
- GPG/keyring errors during build → `sudo pacman -Sy archlinux-keyring`.
- Build must run as root; the work dir (`out/work-<mode>`) must be on a
  filesystem that supports what mkarchiso needs (ext4/xfs/btrfs, not vfat).
