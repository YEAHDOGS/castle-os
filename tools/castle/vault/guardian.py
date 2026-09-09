#!/usr/bin/env python3
"""Guardian controls for under-18 accounts (FAMILY-DATA-VAULT.md step 5).

The sharing ladder says: no "family admin sees everything" backdoor. So
guardian power is *scoped to that guardian's own children* and every
exercise of it is logged in activity.jsonl. What a guardian CAN do:

  - approve / revoke a child's devices (lost phone, rogue login);
  - revoke any share their child granted (Sam shared to the wrong
    person; Mom takes it back);
  - approve the child's graduation to a full adult account;
  - review the child's recent activity (supervision, not surveillance:
    metadata only — who did what to which vault).

What a guardian CANNOT do: touch an adult's account at all — not their
devices, not their shares. Dad cannot see (or revoke) Mom's shares.
If Dad needs something of Mom's, Mom shares it. That's the whole point.

Stdlib only. Run:  python3 guardian.py  (self-test is in test_guardian.py)
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vault  # noqa: E402


def _guardian_of(users, child):
    rec = vault._require_user(users, child)
    if rec["tier"] != "child":
        raise ValueError("%s is not a child account" % child)
    g = rec.get("guardian")
    if not g:
        raise ValueError("child %s has no guardian on record" % child)
    return rec, g


def _check_guardian(users, child, by):
    """Return the child record if `by` is that child's guardian, else refuse.

    Adults are immune: a guardian is never anyone's approver over an
    adult account — not even Dad's."""
    rec, g = _guardian_of(users, child)
    if by != g:
        raise ValueError(
            "not %s's guardian (guardian is %s)" % (child, g))
    return rec


def revoke_device(root, user, device, by=None):
    """Revoke a registered device (lost phone, rogue login).

    Child accounts: only the child's guardian may revoke. Adults revoke
    their own. Refusals, not silent no-ops: unknown devices and
    unauthorized actors are rejected loudly."""
    vault._ensure_dirs(root)
    users = vault._load_users(root)
    rec = vault._require_user(users, user)
    actor = by or user
    if device not in rec["devices"]:
        raise ValueError("device not registered: %s -> %s" % (user, device))
    if rec["tier"] == "child":
        _check_guardian(users, user, actor)
    elif actor != user:
        raise ValueError(
            "cannot revoke %s's device: adults manage their own devices"
            % user)
    rec["devices"].remove(device)
    vault._save_users(root, users)
    vault._activity(root, actor, "device.revoked",
                    "user=%s device=%s" % (user, device))
    return "device %s revoked for %s (by %s)" % (device, user, actor)


def guardian_revoke_share(root, child, to, guardian):
    """A guardian revokes a share their child granted.

    The override runs ONLY downward: child -> guardian only. An adult's
    shares can never be revoked by someone else — revoke_share stays the
    only tool there."""
    vault._ensure_dirs(root)
    users = vault._load_users(root)
    rec = _check_guardian(users, child, guardian)
    before = len(rec["shares"])
    rec["shares"] = [s for s in rec["shares"] if s["to"] != to]
    if len(rec["shares"]) == before:
        raise ValueError("no such share to revoke: %s -> %s" % (child, to))
    vault._save_users(root, users)
    vault._activity(root, guardian, "share.revoked.by_guardian",
                    "%s -> %s" % (child, to))
    return "guardian %s revoked share: %s -> %s" % (guardian, child, to)


def graduate(root, child, by):
    """Guardian-approved graduation: child account -> full adult account.

    Data comes with the account: vault dirs, devices, shares, and the
    escrowed key all survive (escrow stays on — family recovery keeps
    working; the graduate can rotate the key later via the keyring if
    they want a clean break). World shares and integrations, refused to
    children, unlock with the adult tier."""
    vault._ensure_dirs(root)
    users = vault._load_users(root)
    rec = _check_guardian(users, child, by)
    g = rec["guardian"]
    rec["tier"] = "adult"
    rec["guardian"] = None
    vault._save_users(root, users)
    vault._activity(root, by, "user.graduated",
                    "user=%s approved_by=%s escrow_kept=%s"
                    % (child, g, rec.get("escrowed")))
    return ("user %s graduated to adult (approved by %s); data, devices "
            "and escrow preserved" % (child, g))


def guardian_review(root, child, n=20):
    """Recent activity touching a child's account — for that child's
    guardian. Metadata only (who did what to which vault), same as the
    activity log itself; never key material, never file bytes."""
    vault._ensure_dirs(root)
    lines = vault.activity_tail(root, n=200)
    hits = [e for e in lines
            if e.get("actor") == child
            or ("user=%s" % child) in str(e.get("detail", ""))
            or e.get("detail", "").startswith("%s -> " % child)]
    return hits[-n:]


if __name__ == "__main__":
    print(__doc__.strip().splitlines()[0])
