#!/usr/bin/env python3
"""Receipt ingestion: email forward — FAMILY-DATA-VAULT.md build-order step 3.

Forward receipts to ``receipts@<you>.castle``. This module ingests the raw
RFC822 message into the addressed user's ``receipts/`` vault subdir,
extracting a structured receipt record with honest extraction confidence.

The trust model from the vault core applies unchanged:
  - Zero implicit trust: a receipt lands in exactly ONE vault — the user
    named in the ``To:`` address (``receipts@<name>.castle``). An email
    addressed to sam never lands in sally's vault, and an unaddressed
    or mis-addressed message is refused, not guessed at.
  - The account must have the ``email-forward`` integration registered
    (``add-integration`` is already adult-only, so child accounts cannot
    enable this surface).
  - Ingestion is idempotent: re-forwarding the same message is refused
    (sha256 of the raw bytes), so retries never create dupes.
  - Both the parsed ``receipt.json`` and the original ``.eml`` are kept
    (0600, inside the user's own vault). The activity log records the
    event (merchant, total, message-id) but NEVER the email body or
    attachment bytes.

Stdlib only. No network, no new hosts.
"""

import email
import email.header
import email.policy
import email.utils
import hashlib
import json
import os
import re
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import vault as _vault  # noqa: E402  (registry, perms, activity plumbing)

INTEGRATION = "email-forward"
ADDRESS_RE = re.compile(
    r"^receipts@(?P<user>[a-z0-9][a-z0-9_-]{0,62}[a-z0-9])\.castle$", re.I)

# "Total $12.34", "Amount due: 12,34.56", "Charged: $5.00" — take the LAST
# match, totals live at the bottom of a receipt body.
TOTAL_RE = re.compile(
    r"(?im)\b(?:total|grand total|amount\s+due|balance\s+due|charged|paid)\b"
    r"[^\S\r\n]{0,3}[:\-]?[^\S\r\n]{0,3}\$?\s*([\d,]+\.\d{2})")
GENERIC_MONEY_RE = re.compile(r"\$?\s*([\d,]+\.\d{2})")


def _decode(hdr):
    """Decode a possibly RFC2047-encoded header to str."""
    if not hdr:
        return ""
    parts = email.header.decode_header(hdr)
    out = []
    for chunk, enc in parts:
        if isinstance(chunk, bytes):
            out.append(chunk.decode(enc or "utf-8", errors="replace"))
        else:
            out.append(chunk)
    return "".join(out).strip()


def _body_text(msg):
    """First text/plain part as str, or the body of a non-multipart msg."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                charset = part.get_content_charset() or "utf-8"
                return payload.decode(charset, errors="replace")
        return ""
    payload = msg.get_payload(decode=True)
    if payload is None:
        return str(msg.get_payload() or "")
    charset = msg.get_content_charset() or "utf-8"
    return payload.decode(charset, errors="replace")


def _extract_total(text):
    """(total_str, confidence). Last explicit 'Total $X.XX' match wins;
    falls back to the largest bare $X.XX amount at low confidence."""
    totals = TOTAL_RE.findall(text or "")
    if totals:
        return totals[-1], "high"
    money = [m.replace(",", "") for m in GENERIC_MONEY_RE.findall(text or "")]
    if money:
        return max(money, key=lambda m: float(m)), "low"
    return None, "none"


def _extract_merchant(from_hdr, subject):
    """Merchant guess from the From display name, with fallbacks."""
    name, _addr = email.utils.parseaddr(from_hdr or "")
    name = _decode(name).strip()
    if name:
        return name, "medium"
    m = re.search(r"(?i)receipt (?:from|for)\s+([^\n,;]+)", subject or "")
    if m:
        return m.group(1).strip(), "low"
    return (_decode(from_hdr).strip() or "unknown"), "low"


def _receipt_dir(root, user):
    return os.path.join(root, "vaults", user, "receipts")


def _index_path(root, user):
    return os.path.join(_receipt_dir(root, user), "index.jsonl")


def _index_hashes(root, user):
    hashes = set()
    p = _index_path(root, user)
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        hashes.add(json.loads(line)["content_hash"])
                    except (KeyError, ValueError):
                        continue
    return hashes


def resolve_recipient(root, raw):
    """Which user is this forwarded email addressed to? Refuses anything
    that isn't exactly ``receipts@<known-user>.castle`` in the To header —
    a receipt is never guessed into a vault."""
    _vault._ensure_dirs(root)
    users = _vault._load_users(root)["users"]
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    to = _decode(msg["To"])
    m = ADDRESS_RE.match(to)
    if not m:
        raise ValueError("refused: To header is not a receipts@<you>.castle "
                         "address (got %r)" % to[:80])
    user = m.group("user").lower()
    if user not in users:
        raise ValueError("refused: no such user in receipts address: %s"
                         % user)
    return user, msg


def ingest(root, user, raw):
    """Ingest one forwarded email's raw bytes into `user`'s receipts vault.

    Returns the stored receipt record. Raises ValueError on any refusal:
    unknown user, missing email-forward integration, mis-addressed mail,
    empty payload, or a message already ingested.
    """
    _vault._ensure_dirs(root)
    users = _vault._load_users(root)
    rec = _vault._require_user(users, user)
    if INTEGRATION not in rec["integrations"]:
        raise ValueError("refused: %s has no %r integration "
                         "(register it with add-integration first)" % (
                             user, INTEGRATION))
    if not raw or not raw.strip():
        raise ValueError("refused: empty message")

    msg = email.message_from_bytes(raw, policy=email.policy.default)
    to = _decode(msg["To"])
    if to:
        m = ADDRESS_RE.match(to)
        if not m:
            raise ValueError("refused: To header is not a "
                             "receipts@<you>.castle address (got %r)"
                             % to[:80])
        if m.group("user").lower() != user.lower():
            raise ValueError("refused: message addressed to %s, not %s — "
                             "a receipt never lands in the wrong vault" % (
                                 m.group("user").lower(), user))
    content_hash = hashlib.sha256(raw).hexdigest()
    if content_hash in _index_hashes(root, user):
        raise ValueError("refused: message already ingested (content hash "
                         "dup)")

    from_hdr = _decode(msg["From"])
    subject = _decode(msg["Subject"])
    message_id = _decode(msg["Message-ID"])
    body = _body_text(msg)
    total, total_conf = _extract_total(body)
    merchant, merchant_conf = _extract_merchant(from_hdr, subject)

    # attachments: kept as-is inside the user's own vault, 0600
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if not filename:
            continue
        filename = _decode(filename).replace("/", "_").replace("\\", "_")
        payload = part.get_payload(decode=True) or b""
        attachments.append({"name": filename, "bytes": len(payload),
                            "type": part.get_content_type()})

    date_hdr = _decode(msg["Date"])
    try:
        dt = email.utils.parsedate_to_datetime(date_hdr) if date_hdr else None
    except (TypeError, ValueError):
        dt = None
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    rid = "rcpt-%s-%s" % (time.strftime("%Y%m%d", time.gmtime()),
                          content_hash[:12])
    rdir = os.path.join(_receipt_dir(root, user), rid)
    os.makedirs(rdir, mode=0o700, exist_ok=False)
    os.chmod(rdir, 0o700)

    receipt = {
        "id": rid,
        "user": user,
        "ingested_at": ts,
        "message_id": message_id,
        "content_hash": content_hash,
        "from": from_hdr,
        "subject": subject,
        "email_date": dt.isoformat() if dt else None,
        "merchant": merchant,
        "merchant_confidence": merchant_conf,
        "total": total,
        "total_confidence": total_conf,
        "currency": "USD" if total and "$" in body else None,
        "attachments": [{"name": a["name"], "bytes": a["bytes"],
                         "type": a["type"]} for a in attachments],
        "body_snippet": body[:500],
    }

    # store attachments + original + parsed record, all 0600
    saved = []
    idx = 0
    for part in msg.walk():
        if part.is_multipart():
            continue
        if not part.get_filename():
            continue
        fname = _decode(part.get_filename()).replace("/", "_")
        apath = os.path.join(rdir, "att-%d-%s" % (idx, fname))
        with open(apath, "wb") as f:
            f.write(part.get_payload(decode=True) or b"")
        os.chmod(apath, 0o600)
        saved.append(os.path.basename(apath))
        idx += 1
    for i, a in enumerate(receipt["attachments"]):
        a["stored_as"] = saved[i] if i < len(saved) else None

    with open(os.path.join(rdir, "original.eml"), "wb") as f:
        f.write(raw)
    os.chmod(os.path.join(rdir, "original.eml"), 0o600)
    _vault._atomic_write(os.path.join(rdir, "receipt.json"), receipt)

    with open(_index_path(root, user), "a", encoding="utf-8") as f:
        f.write(json.dumps({"id": rid, "content_hash": content_hash,
                            "merchant": merchant, "total": total,
                            "ingested_at": ts}, sort_keys=True) + "\n")
    _vault._activity(root, user, "receipt.ingested",
                     "id=%s merchant=%s total=%s msg=%s" % (
                         rid, merchant, total, message_id[:60]))
    return receipt


def list_receipts(root, user):
    """Summaries of every receipt ingested into `user`'s vault."""
    _vault._ensure_dirs(root)
    _vault._require_user(_vault._load_users(root), user)
    out = []
    p = _index_path(root, user)
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
    return out


def get_receipt(root, user, rid):
    """Full receipt record (parsed + stored attachment names)."""
    _vault._ensure_dirs(root)
    _vault._require_user(_vault._load_users(root), user)
    if "/" in rid or "\\" in rid or ".." in rid or not rid:
        raise ValueError("invalid receipt id")
    p = os.path.join(_receipt_dir(root, user), rid, "receipt.json")
    if not os.path.isfile(p):
        raise ValueError("no such receipt: %s" % rid)
    with open(p, encoding="utf-8") as f:
        return json.load(f)
