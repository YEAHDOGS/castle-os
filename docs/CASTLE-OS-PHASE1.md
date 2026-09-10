# Castle OS — Phase 1 (archiso profile)

Castle OS ships in **two modes**:

| Mode | What it is | Phase 1 status |
|---|---|---|
| **Headless CLI-only** | Boots to a shell: analyze disks, back up data, nuke, reinstall. No graphics stack. | Scaffolded: `castle-mode` dispatcher, syslinux + systemd-boot entries for `castle.mode=analyze\|backup\|nuke\|reinstall` |
| **GUI on Wayland** | Same rescue system under `sway` (compositor) + `foot` (terminal) + `waybar`. | Scaffolded: packages included (`sway`, `foot`, `waybar`, `grim`, `wl-clipboard`, `xorg-xwayland`); boot into Analyze, then run `sway` |

This is the **Linux rescue leg** of the Phoenix multi-boot USB Swiss Army knife
(Phoenix WinPE for backup/reinstall + Linux rescue for nuke/clone/analyze with
a file manager + clean Windows ISO). The config GUI (Svelte + Tauri, Brando's
stack) writes an OS-agnostic config file that the bootable side reads
headlessly; every Phoenix PowerShell script gets a bash twin here.

## Phase 1 scope — slow and verified

- archiso profile only: no ISO build in CI here (slow, heavy). Build locally on
  an Arch host with `./build.sh` when needed.
- `analyze` works (read-only `lsblk` listing). `backup` / `reinstall` are
  declared placeholders — they exit non-zero and change nothing.
- **`nuke` explicitly refuses.** Nuke needs serious safety interlocks first:
  explicit disk enumeration + typed confirmation. Wiping the wrong disk must be
  structurally hard. No `dd`/`mkfs`/`wipefs`/`shred` in the live image until
  those interlocks exist and are reviewed.

## Building

```bash
./verify.sh     # scaffold self-check (fast, no network, no root)
./build.sh      # pre-flight verify, mkarchiso build, SHA-256 checksum
```

`build.sh` runs `mkarchiso` on `profile/`, then:
1. pre-flight: `./verify.sh` must pass, or the build aborts before touching
   mkarchiso,
2. ISO sanity: exists, non-empty, above a gross minimum size,
3. provenance: `<iso>.build-info.txt` records build date, git commit,
   `profiledef.sh`/`packages.x86_64`/`pacman.conf` checksums, and the
   mkarchiso version, so any ISO can be traced back to exact inputs
   (mkarchiso is not a reproducible build; this records what we can),
4. SHA-256 checksum written to `<iso>.sha256` and re-verified,
5. declared package set dumped from `profile/packages.x86_64`.

Package sources: official Arch repos only (`profile/pacman.conf`), per the DOGS
default-deny posture — no third-party mirrors, ever.

## Layout

```
profile/                      archiso profile
  profiledef.sh               ISO metadata (name, label, boot modes, perms)
  packages.x86_64             minimal rescue package set
  pacman.conf                 official-repos-only pacman config
  airootfs/                   live-system overlay
    usr/local/bin/castle-mode mode dispatcher (safe Phase 1 version)
    usr/local/bin/castle-disks read-only disk enumerator (nuke interlock step 1)
    etc/motd                  boot banner
  syslinux/syslinux.cfg       BIOS boot menu (5 entries)
  efiboot/loader/             UEFI systemd-boot entries (4 modes)
build.sh                      mkarchiso wrapper + verification
verify.sh                     scaffold self-check
```

## Next steps (post-Phase 1)

1. Emergency runbook: image infected drive → back up data to Castle → wipe →
   rebuild in one step.
2. `backup` implementation: enumerate disks, rsync to Castle share.
3. Nuke interlocks: disk enumeration is DONE (`castle-disks`, read-only);
   remaining: numbered-target selection + typed confirmation, then `nuke`.
4. Phoenix bash twins of the Windows-side PowerShell scripts.
