#!/usr/bin/env python3
"""Receipt ingestion: POS webhook — FAMILY-DATA-VAULT.md build-order step 3.

The vision: POS systems (Clover and friends) push receipts straight to
your Castle — a webhook/API receiver per user vault, so a purchase at a
Clover terminal lands in *your* records, not just theirs.

This module is the receive side of that flow. It takes one JSON body (the
bytes a POS webhook would POST) and lands it in exactly one user's
``receipts/`` vault subdir, sharing the storage layout with email
ingestion (``rcpt-<date>-<hash>/receipt.json``, append-only
``index.jsonl``), so every downstream query works across both sources.

There is no network listener here on purpose: Castle is air-gap friendly
and "all code is a liability," so the HTTP surface (nginx/Tailscale
terminus) stays outside this module. What this module owns is the trust
boundary — addressing, validation, idempotency, tight perms — which is
the part that has to be right regardless of transport.

Trust model (same as the vault core and email ingestion):
  - Zero implicit trust: the payload names its user (``"user": "sam"``)
    and that name MUST match the vault being written to. A push naming
    sam never lands in sally's vault; an unaddressed, mis-addressed, or
    unknown-user payload is refused, not guessed at.
  - The account must have the ``pos-webhook`` integration registered.
    ``add-integration`` is adult-only, so child accounts cannot enable
    this surface.
  - Ingestion is idempotent: re-pushing the same payload (sha256 of the
    canonical JSON) or the same ``transaction_id`` is refused, so
    webhook retries never create dupes.
  - Money is a string like "7.75" — never a float. A float total (or any
    malformed money) is refused rather than rounded into the vault.
  - The activity log records metadata only (merchant, total,
    transaction id) — never the raw payload.

Stdlib only. No network, no new hosts.
"""

import hashlib
import json
import os
import re
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import vault as _vault  # noqa: E402  (registry, perms, activity plumbing)
import receipts as _receipts  # noqa: E402  (shared receipts/ layout)

INTEGRATION = "pos-webhook"
SOURCE = "pos-webhook"

# money as an exact decimal string: "7.75", "1234.00" — no floats, no
# commas, no currency symbols. Refuse anything else.
MONEY_RE = re.compile(r"^\d{1,9}\.\d{2}$")
CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
MAX_MERCHANT = 200
MAX_VENDOR = 64
MAX_ITEMS = 500
MAX_STR = 512


def _strict_str(value, name, max_len=MAX_STR):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("refused: %s must be a non-empty string" % name)
    value = value.strip()
    if len(value) > max_len:
        raise ValueError("refused: %s too long (%d > %d)" % (
            name, len(value), max_len))
    return value


def resolve_recipient(root, raw):
    """Which user is this POS push addressed to? Refuses anything that
    isn't JSON with a ``"user"`` field naming a known vault user — a
    receipt is never guessed into a vault."""
    _vault._ensure_dirs(root)
    users = _vault._load_users(root)["users"]
    try:
        payload = json.loads(raw)
    except (ValueError, TypeError):
        raise ValueError("refused: POS payload is not valid JSON")
    if not isinstance(payload, dict):
        raise ValueError("refused: POS payload must be a JSON object")
    user = payload.get("user")
    if not isinstance(user, str) or not user:
        raise ValueError("refused: POS payload has no \"user\" field")
    user = user.lower()
    if user not in users:
        raise ValueError("refused: no such user in POS payload: %s" % user)
    return user, payload


def _canonical(payload):
    """Canonical bytes for the idempotency hash (sorted keys, compact)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _validate(payload):
    """Return a normalized push record, or raise ValueError on any
    incomplete/invalid record. Incomplete records are refused, never
    guessed."""
    merchant = _strict_str(payload.get("merchant"), "merchant",
                           MAX_MERCHANT)
    total = payload.get("total")
    if not isinstance(total, str) or not MONEY_RE.match(total):
        raise ValueError("refused: total must be an exact decimal string "
                         "like \"7.75\" (got %r) — floats are never "
                         "rounded into the vault" % (total,))
    currency = payload.get("currency", "USD")
    if not isinstance(currency, str) or not CURRENCY_RE.match(currency):
        raise ValueError("refused: currency must be a 3-letter ISO code "
                         "(got %r)" % (currency,))

    vendor = payload.get("pos_vendor")
    if vendor is not None:
        vendor = _strict_str(vendor, "pos_vendor", MAX_VENDOR)

    txn = payload.get("transaction_id")
    if txn is not None:
        txn = _strict_str(txn, "transaction_id")

    occurred = payload.get("occurred_at")
    if occurred is not None:
        occurred = _strict_str(occurred, "occurred_at", 64)

    items = payload.get("items")
    if items is not None:
        if not isinstance(items, list) or len(items) > MAX_ITEMS:
            raise ValueError("refused: items must be a list of at most %d"
                             % MAX_ITEMS)
        for it in items:
            if not isinstance(it, dict):
                raise ValueError("refused: items must be objects")

    return {"merchant": merchant, "total": total, "currency": currency,
            "pos_vendor": vendor, "transaction_id": txn,
            "occurred_at": occurred, "items": items}


def ingest(root, user, raw):
    """Ingest one POS webhook JSON body into `user`'s receipts vault.

    Returns the stored receipt record. Raises ValueError on any refusal:
    unknown user, missing pos-webhook integration, payload addressed to
    a different user, invalid JSON, incomplete/invalid record, or a
    payload (or transaction_id) already ingested.
    """
    _vault._ensure_dirs(root)
    users = _vault._load_users(root)
    rec = _vault._require_user(users, user)
    if INTEGRATION not in rec["integrations"]:
        raise ValueError("refused: %s has no %r integration "
                         "(register it with add-integration first)" % (
                             user, INTEGRATION))
    if not raw or not raw.strip():
        raise ValueError("refused: empty payload")

    try:
        payload = json.loads(raw)
    except (ValueError, TypeError):
        raise ValueError("refused: POS payload is not valid JSON")
    if not isinstance(payload, dict):
        raise ValueError("refused: POS payload must be a JSON object")

    addressed = payload.get("user")
    if isinstance(addressed, str) and addressed.lower() != user.lower():
        raise ValueError("refused: payload addressed to %s, not %s — "
                         "a receipt never lands in the wrong vault" % (
                             addressed.lower(), user))

    push = _validate(payload)

    content_hash = hashlib.sha256(_canonical(payload)).hexdigest()
    seen_hashes = _receipts._index_hashes(root, user)
    if content_hash in seen_hashes:
        raise ValueError("refused: payload already ingested (content hash "
                         "dup)")
    if push["transaction_id"]:
        for e in _receipts.list_receipts(root, user):
            if e.get("transaction_id") == push["transaction_id"]:
                raise ValueError("refused: transaction_id %s already "
                                 "ingested" % push["transaction_id"])

    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    rid = "rcpt-%s-%s" % (time.strftime("%Y%m%d", time.gmtime()),
                          content_hash[:12])
    rdir = os.path.join(_receipts._receipt_dir(root, user), rid)
    os.makedirs(rdir, mode=0o700, exist_ok=False)
    os.chmod(rdir, 0o700)

    receipt = {
        "id": rid,
        "user": user,
        "source": SOURCE,
        "ingested_at": ts,
        "content_hash": content_hash,
        "merchant": push["merchant"],
        "merchant_confidence": "high",   # POS supplies it explicitly
        "total": push["total"],
        "total_confidence": "high",     # exact decimal, no extraction
        "currency": push["currency"],
        "pos_vendor": push["pos_vendor"],
        "transaction_id": push["transaction_id"],
        "occurred_at": push["occurred_at"],
        "items": push["items"],
        "attachments": [],
    }

    _vault._atomic_write(os.path.join(rdir, "receipt.json"), receipt)
    with open(os.path.join(rdir, "raw.json"), "w",
              encoding="utf-8") as f:   # 0600: the verbatim push
        f.write(_canonical(payload).decode("ascii"))
    os.chmod(os.path.join(rdir, "raw.json"), 0o600)

    index_entry = {"id": rid, "content_hash": content_hash,
                   "merchant": push["merchant"], "total": push["total"],
                   "currency": push["currency"], "source": SOURCE,
                   "transaction_id": push["transaction_id"],
                   "ingested_at": ts}
    with open(_receipts._index_path(root, user), "a",
              encoding="utf-8") as f:
        f.write(json.dumps(index_entry, sort_keys=True) + "\n")

    _vault._activity(root, user, "receipt.pos",
                     "id=%s merchant=%s total=%s %s txn=%s" % (
                         rid, push["merchant"], push["total"],
                         push["currency"], push["transaction_id"]))
    return receipt
