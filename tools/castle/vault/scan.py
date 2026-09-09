#!/usr/bin/env python3
"""Receipt ingestion: scan/OCR — FAMILY-DATA-VAULT.md build-order step 3.

Photo a paper receipt, OCR it (on the phone, or anywhere — Castle does
not run the OCR engine itself), and this module lands the image plus its
extracted text as a structured receipt in the user's ``receipts/`` vault
subdir, sharing the storage layout with email and POS ingestion
(``rcpt-<date>-<hash>/receipt.json``, append-only ``index.jsonl`` with a
``source`` field), so every downstream query works across all sources.

Deliberate design choice: Castle never does the OCR. OCR engines change
fast and phones already do it well; what Castle owns is the trust
boundary — the image bytes are genuine, the text is honestly labeled
with extraction confidence, nothing lands in the wrong vault.

Trust model (same as the vault core, email, and POS ingestion):
  - Zero implicit trust: the caller names the user explicitly and the
    user MUST exist. A scan for sam never lands in sally's vault; an
    unknown user is refused, not guessed at.
  - The account must have the ``scan`` integration registered.
    ``add-integration`` is adult-only, so child accounts cannot enable
    this surface.
  - The image is validated by magic bytes (JPEG/PNG/WebP only) — a
    renamed text file or a 12-byte stub is refused, not stored.
  - OCR text must be non-empty: a scan without extracted text is not a
    receipt, and guessing merchant/total from nothing is exactly the
    kind of "helpful" behavior Castle refuses.
  - Ingestion is idempotent: re-scanning the same image + text
    (sha256) is refused, so double-taps never create dupes.
  - The filename is validated, not sanitized into place: any path
    separator or ``..`` is a refusal. Scans can never escape their
    receipt dir.
  - The activity log records metadata only (merchant, total,
    confidence) — never the image bytes or full OCR text.

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
import receipts as _receipts  # noqa: E402  (shared receipts/ layout + total regex)

INTEGRATION = "scan"
SOURCE = "scan"

# magic-byte sniffing: phones shoot JPEG, scanners emit PNG, WebP shows up
# from Android share sheets. Anything else is refused.
_MAGIC = [
    (b"\xff\xd8\xff", "jpg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"RIFF", "webp"),  # full check below: RIFF....WEBP
]
MIN_IMAGE_BYTES = 1024          # smaller than this is a stub, not a photo
MAX_IMAGE_BYTES = 50 * 1024 * 1024
MAX_OCR_CHARS = 100_000
MAX_MERCHANT = 200
_MERCHANT_LINE_RE = re.compile(r"^.{1,200}$")
_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def detect_image_kind(data):
    """Return 'jpg'/'png'/'webp', or None for anything unrecognized."""
    if not data:
        return None
    for magic, kind in _MAGIC:
        if not data.startswith(magic):
            continue
        if kind == "webp":
            if len(data) >= 12 and data[8:12] == b"WEBP":
                return "webp"
            return None
        return kind
    return None


def extract_from_ocr(ocr_text, hint_merchant=None):
    """Structured receipt from OCR text. Merchant is the first non-empty
    line (low confidence — receipt headers are noisy) unless the caller
    stated it explicitly (high confidence). Total uses the same honest
    extraction as email ingestion. Returns (merchant, merchant_conf,
    total, total_conf, currency)."""
    total, total_conf = _receipts._extract_total(ocr_text or "")
    if hint_merchant and hint_merchant.strip():
        return (hint_merchant.strip()[:MAX_MERCHANT], "high",
                total, total_conf, "USD" if total and "$" in ocr_text else None)
    first = ""
    for line in (ocr_text or "").splitlines():
        line = line.strip()
        if line:
            first = line
            break
    merchant = (first[:MAX_MERCHANT], "low") if first else ("unknown", "none")
    currency = "USD" if total and "$" in (ocr_text or "") else None
    return merchant[0], merchant[1], total, total_conf, currency


def _validate_filename(name):
    """Refuse anything that isn't a bare, harmless filename — scans can
    never escape their receipt dir via `..` or separators."""
    if not isinstance(name, str) or not _FILENAME_RE.match(name):
        raise ValueError("refused: unsafe scan filename %r — must be a "
                         "bare filename, no paths" % (name,)[:80])
    if ".." in name or "/" in name or "\\" in name:
        raise ValueError("refused: unsafe scan filename %r" % name[:80])
    return name


def ingest(root, user, image_bytes, ocr_text, filename=None,
           hint_merchant=None):
    """Ingest one scanned receipt image + its OCR text into `user`'s
    receipts vault. Returns the stored receipt record. Raises ValueError
    on any refusal: unknown user, missing scan integration, bad image
    bytes, empty OCR text, unsafe filename, or an already-ingested scan.
    """
    _vault._ensure_dirs(root)
    users = _vault._load_users(root)
    rec = _vault._require_user(users, user)
    if INTEGRATION not in rec["integrations"]:
        raise ValueError("refused: %s has no %r integration "
                         "(register it with add-integration first)" % (
                             user, INTEGRATION))
    if not image_bytes or len(image_bytes) < MIN_IMAGE_BYTES:
        raise ValueError("refused: image too small to be a scan "
                         "(%d bytes)" % (len(image_bytes or b"")))
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise ValueError("refused: image exceeds 50MB scan cap")
    kind = detect_image_kind(image_bytes)
    if kind is None:
        raise ValueError("refused: not a recognized scan image "
                         "(JPEG/PNG/WebP magic bytes required)")
    if not ocr_text or not ocr_text.strip():
        raise ValueError("refused: empty OCR text — a scan without "
                         "extracted text is not a receipt")
    if len(ocr_text) > MAX_OCR_CHARS:
        raise ValueError("refused: OCR text exceeds 100k char cap")
    if filename is None:
        filename = "scan.%s" % kind
    else:
        _validate_filename(filename)
        if not filename.lower().endswith("." + kind):
            raise ValueError("refused: filename extension .%s does not "
                             "match image kind %s" % (
                                 filename.rsplit(".", 1)[-1][:10], kind))

    content_hash = hashlib.sha256(
        image_bytes + b"\x00" + ocr_text.encode("utf-8")).hexdigest()
    if content_hash in _receipts._index_hashes(root, user):
        raise ValueError("refused: scan already ingested (content hash dup)")

    merchant, mconf, total, tconf, currency = extract_from_ocr(
        ocr_text, hint_merchant=hint_merchant)

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
        "image_filename": filename,
        "image_bytes": len(image_bytes),
        "image_kind": kind,
        "merchant": merchant,
        "merchant_confidence": mconf,
        "total": total,
        "total_confidence": tconf,
        "currency": currency,
        "ocr_chars": len(ocr_text),
        "attachments": [],
    }

    with open(os.path.join(rdir, filename), "wb") as f:  # 0600: the scan
        f.write(image_bytes)
    os.chmod(os.path.join(rdir, filename), 0o600)
    with open(os.path.join(rdir, "ocr.txt"), "w",
              encoding="utf-8") as f:                    # 0600: raw text
        f.write(ocr_text)
    os.chmod(os.path.join(rdir, "ocr.txt"), 0o600)
    _vault._atomic_write(os.path.join(rdir, "receipt.json"), receipt)

    index_entry = {"id": rid, "content_hash": content_hash,
                   "merchant": merchant, "total": total,
                   "currency": currency, "source": SOURCE,
                   "ingested_at": ts}
    with open(_receipts._index_path(root, user), "a",
              encoding="utf-8") as f:
        f.write(json.dumps(index_entry, sort_keys=True) + "\n")

    _vault._activity(root, user, "receipt.scan",
                     "id=%s merchant=%s total=%s mconf=%s tconf=%s" % (
                         rid, merchant, total, mconf, tconf))
    return receipt
