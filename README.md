# castle-os

Castle OS — the Linux rescue leg of the Phoenix multi-boot USB Swiss Army
knife. Ships headless CLI-only or GUI on a Wayland compositor.

Phase 1: archiso profile, slow and verified. See `docs/CASTLE-OS-PHASE1.md`.

Quick checks (no network, no root, no ISO build):

```bash
./verify.sh   # scaffold self-check
./build.sh    # full mkarchiso build (needs an Arch host)
```
