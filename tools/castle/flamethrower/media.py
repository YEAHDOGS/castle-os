#!/usr/bin/env python3
"""Flamethrower media detection — Tier 2/3 device honesty.

Implements FLAMETHROWER.md build-order step 3: know what you're burning.
Classification is READ-ONLY (sysfs reads only). It emits no destructive
commands for flash media — the module structurally refuses to bless a
software overwrite as a "kill" on anything that isn't spinning rust, the
same refusal the Phoenix nuke tool carries.

Categories (see docs/FLAMETHROWER.md "Why deletion is hard"):
  HDD          - rotational media: OS sector == physical sector.
                 Overwrite is a real kill.
  SATA_SSD     - NAND behind a SATA controller: wear leveling +
                 over-provisioning mean overwrites miss physical cells.
                 Kill = ATA Secure Erase (firmware) or crypto-shred.
  NVME         - NVMe flash. Kill = `nvme format --ses=2` (crypto erase)
                 or NVMe Sanitize. Overwrite is a polite fiction.
  FLASH_USB    - USB sticks, SD cards, eMMC: usually NO firmware erase.
                 Crypto-shred is the only real kill.
  VIRTUAL      - loop/nbd/dm/md/virtio/ram: no physical media to erase;
                 crypto-shred the guest data.
  UNKNOWN      - unrecognized: assume flash. Never assume HDD.

Stdlib only. No network, no new hosts. The sysfs root is injectable so
tests build a fake /sys tree and no test touches real hardware.

Usage:
    media.py identify /dev/sda /dev/nvme0n1 [--sysfs /sys]
    media.py kill-plan /dev/sda [--sysfs /sys]
"""

import argparse
import json
import os
import re
import sys

SYSFS = "/sys"


# ---------------------------------------------------------------------------
# types
# ---------------------------------------------------------------------------

HDD = "hdd"
SATA_SSD = "sata_ssd"
NVME = "nvme"
FLASH_USB = "flash_usb"
VIRTUAL = "virtual"
UNKNOWN = "unknown"

VIRTUAL_PREFIXES = ("loop", "nbd", "ram", "zram", "dm-", "md", "vd", "xvd")
PARTITION_TAIL = re.compile(r"^(?P<disk>.+?)(p?\d+)$")


class DeviceInfo:
    """Classification result for one block device."""

    def __init__(self, name, media, transport, removable, rotational,
                 model="", serial=""):
        self.name = name
        self.media = media
        self.transport = transport
        self.removable = removable
        self.rotational = rotational
        self.model = model
        self.serial = serial

    def as_dict(self):
        return {
            "device": "/dev/" + self.name,
            "media": self.media,
            "transport": self.transport,
            "removable": self.removable,
            "rotational": self.rotational,
            "model": self.model,
            "serial": self.serial,
            "recommended_kill": recommended_kill(self.media),
            "honest_label": honest_label(self.media),
        }


class Refusal(Exception):
    """Raised when asked to bless an overwrite kill on flash media."""


# ---------------------------------------------------------------------------
# sysfs plumbing (read-only)
# ---------------------------------------------------------------------------

def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except (OSError, IOError):
        return None


def _flag(path):
    return _read(path) == "1"


def _disk_names(sysfs):
    block = os.path.join(sysfs, "block")
    try:
        return sorted(os.listdir(block))
    except OSError:
        return []


def resolve_disk(name, sysfs=SYSFS):
    """Map a /dev name (whole disk or partition) to its whole-disk name.

    sda1 -> sda, nvme0n1p2 -> nvme0n1, mmcblk0p1 -> mmcblk0.
    Returns None when the name doesn't match any known disk.
    """
    name = os.path.basename(name)
    disks = _disk_names(sysfs)
    if name in disks:
        return name
    m = PARTITION_TAIL.match(name)
    if m and m.group("disk") in disks:
        return m.group("disk")
    # slow path: strip a trailing digit run for odd naming
    stripped = re.sub(r"\d+$", "", name)
    if stripped != name and stripped in disks:
        return stripped
    return None


def _transport(disk, sysfs):
    """Best-effort transport: usb / nvme / sata / virtual / unknown.

    Resolves the /sys/block/<disk> symlink and looks at the device path;
    USB devices pass through a usb* ancestor directory.
    """
    if disk.startswith("nvme"):
        return "nvme"
    for prefix in VIRTUAL_PREFIXES:
        if disk.startswith(prefix):
            return "virtual"
    link = os.path.join(sysfs, "block", disk)
    try:
        target = os.path.realpath(link)
    except OSError:
        target = ""
    parts = target.lower().split(os.sep)
    if any(p.startswith("usb") for p in parts):
        return "usb"
    if "mmc_host" in parts or disk.startswith("mmcblk"):
        return "mmc"
    if "nvme" in parts:
        return "nvme"
    return "sata" if "ata" in "".join(parts) else "unknown"


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------

def classify(name, sysfs=SYSFS):
    """Classify a block device (or partition) by media type. Read-only."""
    disk = resolve_disk(name, sysfs)
    if disk is None:
        return DeviceInfo(os.path.basename(name), UNKNOWN, "unknown",
                          False, False)

    base = os.path.join(sysfs, "block", disk)
    rotational = _flag(os.path.join(base, "queue", "rotational"))
    removable = _flag(os.path.join(base, "removable"))
    transport = _transport(disk, sysfs)
    model = _read(os.path.join(base, "device", "model")) or ""
    serial = _read(os.path.join(base, "device", "serial")) or ""

    for prefix in VIRTUAL_PREFIXES:
        if disk.startswith(prefix):
            media = VIRTUAL
            break
    else:
        if disk.startswith("nvme"):
            media = NVME
        elif transport in ("usb", "mmc") or removable or disk.startswith("mmcblk"):
            media = FLASH_USB
        elif rotational:
            media = HDD
        elif _read(os.path.join(base, "queue", "rotational")) == "0":
            media = SATA_SSD
        else:
            media = UNKNOWN

    return DeviceInfo(disk, media, transport, removable, rotational,
                      model=model, serial=serial)


def recommended_kill(media):
    """The real kill for this media, per FLAMETHROWER.md Tier 2."""
    return {
        HDD: "single-pass overwrite + verify (nwipe-style)",
        SATA_SSD: "ATA Secure Erase (firmware-level) — overwrite cannot "
                  "reach unmapped pages",
        NVME: "nvme format --ses=2 (crypto erase) or NVMe Sanitize — "
              "firmware erases every block including spares",
        FLASH_USB: "crypto-shred only — USB/SD flash rarely exposes a "
                   "firmware erase; overwrite is a polite fiction",
        VIRTUAL: "no physical media — crypto-shred the guest data",
        UNKNOWN: "assume flash: firmware erase if the drive offers one, "
                 "otherwise crypto-shred",
    }[media]


def honest_label(media):
    """Tier-3 honest labeling: what a file-overwrite actually achieves."""
    if media == HDD:
        return ("overwrite works: the OS writes sector 100, the head "
                "writes sector 100")
    return ("best effort only — flash wear leveling means overwrites miss "
            "physical cells; use crypto-shred for guarantees")


def assert_overwrite_kill_ok(info):
    """Enforce the Tier-2 refusal: never bless an overwrite kill on flash.

    Returns True for HDD. Raises Refusal for everything else.
    """
    if info.media == HDD:
        return True
    raise Refusal(
        "refusing to bless a software-overwrite kill on %s (%s): "
        "%s" % (info.name, info.media, recommended_kill(info.media)))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="flamethrower media detection")
    ap.add_argument("--sysfs", default=SYSFS, help="sysfs root (tests only)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_id = sub.add_parser("identify", help="classify block devices")
    p_id.add_argument("devices", nargs="+")

    p_kp = sub.add_parser("kill-plan", help="show the real kill for devices")
    p_kp.add_argument("devices", nargs="+")

    args = ap.parse_args(argv)
    out = []
    for dev in args.devices:
        info = classify(dev, args.sysfs)
        d = info.as_dict()
        if args.cmd == "kill-plan":
            try:
                assert_overwrite_kill_ok(info)
                d["overwrite_kill_allowed"] = True
            except Refusal as e:
                d["overwrite_kill_allowed"] = False
                d["refusal"] = str(e)
        out.append(d)
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
