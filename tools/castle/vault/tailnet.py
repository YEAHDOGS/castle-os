#!/usr/bin/env python3
"""Tailscale onboarding flow per device + hosted DNS names per service —
FAMILY-DATA-VAULT.md build-order step 4.

The vision: every family member's phone/laptop joins the Castle's tailnet,
so ``vault.castle`` / ``receipts.castle`` resolve anywhere on Earth via
the hosted DNS (Pi-hole) — no port forwarding, no dynamic-DNS hacks, no
exposing SMB to the open internet.

What this module owns (and what it deliberately does NOT):

  - It owns the *bookkeeping*: which of a user's registered devices are
    tailnet-pending vs tailnet-active, their tailnet IPs, and the
    dnsmasq address lines that point the service names at the Castle.
  - It does NOT touch the network. There is no ``tailscale`` subprocess
    call, no HTTP, no DNS query. The operator runs the generated
    ``tailscale up`` command on the device itself and reports the
    tailnet IP back with ``claim``. Zero network here means the flow
    works in a locked-down room and can't leak anything anywhere.
  - The Tailscale **auth key is never stored**. The onboard runbook
    tells the operator exactly where to generate an ephemeral,
    reusable auth key (Tailscale admin console) and paste it into the
    printed command. ``tailnet.json`` carries metadata only — no
    tokens, no keys, no passwords.

Trust model (same as the vault core):

  - Onboard only touches devices that are *registered* on the account
    (``vault.py add-device``). The guardian-approval rule for under-18
    accounts therefore already holds: a child's phone can't even reach
    the onboarding flow without the guardian's ``--by`` at registration.
  - ``claim`` accepts only 100.64.0.0/10 addresses (Tailscale's CGNAT
    range). Anything else — LAN, loopback, public — is refused rather
    than recorded. A recorded IP is metadata, not proof: the real
    proof is the operator seeing the device in the admin console.
  - Revoked devices don't linger: ``status`` and ``dns`` resolve the
    tailnet state against the live account registry, so a device
    removed with ``revoke-device`` drops out of the active set even
    before its tailnet record is purged with ``drop``.
  - Everything is 0600/0700; the activity log records who onboarded
    what to which device — never tokens.

Services get the DNS names the vision doc names: ``vault.castle``
(family vault UI) and ``receipts.castle`` (receipt ingestion
endpoint). The generated file is a dnsmasq fragment for Pi-hole's
``dnsmasq.d`` (e.g. ``address=/vault.castle/100.91.2.3``); the
operator installs it, so ``.castle`` stays off the public internet.

Usage (via vault.py):
    vault.py tailnet-onboard USER DEVICE [--by NAME]
    vault.py tailnet-claim USER DEVICE --ip 100.X.Y.Z
    vault.py tailnet-status
    vault.py tailnet-dns --castle-ip 100.X.Y.Z [--out FILE]

Stdlib only. No network, no new hosts.
"""

import ipaddress
import json
import os
import re
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import vault as _vault  # noqa: E402  (registry, perms, activity plumbing)

TAILNET_FILE = "tailnet.json"
DNS_SUBDIR = "dnsmasq.d"
DNS_FILENAME = "10-castle.conf"

# Tailscale's CGNAT range. The ONLY addresses claim/dns will record.
TAILNET_NET = ipaddress.ip_network("100.64.0.0/10")

# Hosted service names from the vision doc (FAMILY-DATA-VAULT.md):
# "vault.castle / receipts.castle resolve anywhere on Earth via the
# hosted DNS (Pi-hole)". Tailscale MagicDNS already names devices;
# Castle's own DNS fragment names the services.
SERVICES = {
    "vault.castle": "family vault web UI",
    "receipts.castle": "receipt ingestion endpoint",
}

STATES = ("pending", "active")

# Hostnames on the device side are operator-visible; keep them tame.
DEVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


def _ts():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _key(user, device):
    return "%s/%s" % (user, device)


def _state_path(root):
    return os.path.join(root, TAILNET_FILE)


def _load(root):
    """Load tailnet state (creates the file if missing)."""
    _vault._ensure_dirs(root)
    path = _state_path(root)
    if not os.path.exists(path):
        doc = {"version": 1, "devices": {}}
        _vault._atomic_write(path, doc)
        return doc
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict) or doc.get("version") != 1 \
            or not isinstance(doc.get("devices"), dict):
        raise ValueError("refused: tailnet state is corrupt — not migrating "
                         "an unreadable device map (%s)" % path)
    os.chmod(path, 0o600)
    return doc


def _save(root, doc):
    _vault._atomic_write(_state_path(root), doc)


def _check_tailnet_ip(value, what):
    """Refuse anything that isn't a Tailscale CGNAT address."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("refused: %s is required" % what)
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        raise ValueError("refused: %s is not an IP address: %r" % (what, value))
    if ip not in TAILNET_NET:
        raise ValueError("refused: %s %s is not a Tailscale tailnet address "
                         "(expected 100.64.0.0/10)" % (what, ip))
    return str(ip)


def _live_devices(root):
    """Devices currently registered on accounts (post-revocation truth)."""
    users = _vault._load_users(root)["users"]
    live = set()
    for name, rec in users.items():
        for dev in rec.get("devices", []):
            live.add(_key(name, dev))
    return live


def onboard(root, user, device, by=None):
    """Start tailnet onboarding for a registered device.

    Returns the operator runbook: the exact ``tailscale up`` command to
    run on the device. The auth key is pasted by the operator — never
    stored, never in state, never in logs.
    """
    _vault._ensure_dirs(root)
    users = _vault._load_users(root)
    _vault._require_user(users, user)
    if not device or not DEVICE_RE.match(device):
        raise ValueError("refused: device name must match [A-Za-z0-9._-] "
                         "(1-63 chars)")
    rec = users["users"][user]
    if device not in rec.get("devices", []):
        raise ValueError("refused: device %r is not registered on %s — "
                         "register it first with `add-device` (guardian "
                         "approval applies for child accounts)" % (device, user))
    doc = _load(root)
    key = _key(user, device)
    existing = doc["devices"].get(key)
    if existing is not None:
        raise ValueError("refused: %s is already tailnet-%s since %s" % (
            key, existing["state"], existing["ts"]))
    doc["devices"][key] = {"state": "pending", "ip": None,
                           "ts": _ts(), "by": by or user}
    _save(root, doc)
    _vault._activity(root, by or user, "tailnet.onboarded",
                     "user=%s device=%s" % (user, device))
    slug = re.sub(r"[^a-z0-9-]", "-", ("%s-%s" % (user, device)).lower())
    runbook = [
        "1. Generate an ephemeral auth key: Tailscale admin console -> "
        "Settings -> Keys -> Generate auth key (reusable, short expiry).",
        "2. On %r, run:" % device,
        "     sudo tailscale up --authkey <PASTE-AUTH-KEY> "
        "--hostname %s --accept-routes" % slug,
        "3. Verify the device appears in the Tailscale admin console, "
        "then report its 100.x address back:",
        "     vault.py tailnet-claim %s %s --ip 100.X.Y.Z" % (user, device),
        "The auth key is never stored by Castle — it lives only in the "
        "command you paste it into.",
    ]
    return {"user": user, "device": device, "state": "pending",
            "runbook": "\n".join(runbook)}


def claim(root, user, device, ip, by=None):
    """Mark a pending device active once it has joined the tailnet.

    Only 100.64.0.0/10 addresses are recorded. No network call is
    made to check the device — the operator's eyes on the admin
    console are the check; this records the metadata honestly.
    """
    _vault._ensure_dirs(root)
    users = _vault._load_users(root)
    _vault._require_user(users, user)
    if device not in users["users"][user].get("devices", []):
        raise ValueError("refused: device %r is not registered on %s — "
                         "a revoked device cannot be claimed" % (device, user))
    doc = _load(root)
    key = _key(user, device)
    rec = doc["devices"].get(key)
    if rec is None:
        raise ValueError("refused: %s has no tailnet onboarding — "
                         "run `tailnet-onboard` first" % key)
    if rec["state"] == "active":
        raise ValueError("refused: %s is already tailnet-active (%s) — "
                         "use `drop` + re-onboard to re-home it" % (
                             key, rec["ip"]))
    clean = _check_tailnet_ip(ip, "tailnet IP")
    rec["state"] = "active"
    rec["ip"] = clean
    rec["claimed_ts"] = _ts()
    rec["claimed_by"] = by or user
    _save(root, doc)
    _vault._activity(root, by or user, "tailnet.claimed",
                     "user=%s device=%s ip=%s" % (user, device, clean))
    return {"user": user, "device": device, "state": "active", "ip": clean}


def drop(root, user, device, by=None):
    """Purge a device's tailnet state (after revoke-device, or to
    re-home). Refuses unknown records instead of silently no-op'ing."""
    _vault._ensure_dirs(root)
    users = _vault._load_users(root)
    _vault._require_user(users, user)
    doc = _load(root)
    key = _key(user, device)
    if key not in doc["devices"]:
        raise ValueError("refused: %s has no tailnet record to drop" % key)
    del doc["devices"][key]
    _save(root, doc)
    _vault._activity(root, by or user, "tailnet.dropped",
                     "user=%s device=%s" % (user, device))
    return "dropped tailnet record for %s" % key


def status(root):
    """Live tailnet view: records resolved against the account registry,
    so revoked devices can't masquerade as active."""
    _vault._ensure_dirs(root)
    doc = _load(root)
    live = _live_devices(root)
    rows = []
    for key, rec in sorted(doc["devices"].items()):
        if key not in live:
            continue  # revoked from the registry — dead record
        user, device = key.split("/", 1)
        rows.append({"user": user, "device": device,
                     "state": rec["state"], "ip": rec.get("ip"),
                     "ts": rec["ts"]})
    return rows


def dns_refresh(root, castle_ip, out=None):
    """Write the hosted-DNS fragment for the service names.

    dnsmasq format for Pi-hole's ``dnsmasq.d``:
        address=/vault.castle/100.91.2.3

    The operator installs the fragment — Castle never reloads DNS
    itself (no privileged processes, no network).
    """
    _vault._ensure_dirs(root)
    clean = _check_tailnet_ip(castle_ip, "castle tailnet IP")
    if out is None:
        d = os.path.join(root, DNS_SUBDIR)
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)
        out = os.path.join(d, DNS_FILENAME)
    lines = ["# Castle hosted DNS — drop into Pi-hole dnsmasq.d, then "
             "restart pihole-FTL (operator step, Castle never does this)",
             "# generated %s" % _ts()]
    for name in sorted(SERVICES):
        lines.append("address=/%s/%s  # %s" % (name, clean, SERVICES[name]))
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(out, 0o600)
    _vault._activity(_vault._ensure_dirs(root), "castle", "tailnet.dns",
                     "services=%d castle_ip=%s out=%s" % (
                         len(SERVICES), clean, out))
    return {"out": out, "castle_ip": clean, "services": sorted(SERVICES)}
