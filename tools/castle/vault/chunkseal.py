#!/usr/bin/env python3
"""Castle chunked encrypted backup container — castle-chunks/v1.

A pure-stdlib, chunked, authenticated-encryption container for backup
payloads. The existing ``.castle`` format (vault_lock.py) seals one
monolithic ciphertext behind the ``openssl`` CLI. This module is the
other lane: it splits the payload into fixed-size *chunks* and seals
each one independently, so tampering is detected *per chunk* and a
damaged chunk can be named exactly — which chunk failed, not just
"the file is bad".

Crypto construction (documented honestly — see docs/CRYPTO-NOTES.md):
  - Key derivation: scrypt (N=32768, r=8, p=1, 64-byte output),
    falling back to PBKDF2-HMAC-SHA256 (600k iterations) if scrypt is
    unavailable. The 64-byte master key is split into a 256-bit
    encryption key and a 256-bit MAC key. Params (algorithm, salt, and
    the scrypt/PBKDF2 parameters) are stored in the header so a
    future reader knows exactly what to redo.
  - Encryption: SHA-256 in counter mode (keystream block =
    SHA-256(enc_key || nonce || chunk_index || block_counter), XOR
    with plaintext). This is NOT AES — the stdlib has no AES and
    ``pip install`` is off the table (default-deny network). The
    production path is AES-256-GCM the day a real crypto library is
    on the machine; the header's ``cipher`` field names the suite so
    migration is mechanical.
  - Integrity: encrypt-then-MAC — HMAC-SHA256(mac_key, nonce ||
    chunk_index || ciphertext) per chunk, plus a SHA-256 of the whole
    plaintext payload. Wrong passphrase or any flipped byte fails
    closed with a typed ChunkSealError — never a traceback, never a
    half-decrypted chunk.

File layout (``<name>.castle`` — the header format id distinguishes it
from the vault_lock format):
    line 1: single-line JSON header (format id, kdf name + params,
            salt, nonce, chunk size, chunk count, per-chunk HMAC tags,
            payload SHA-256, optional file inventory, timestamp).
    rest:   per chunk: 4-byte big-endian length + raw ciphertext.

Usage:
    chunkseal.seal_file(src_path, out_path, secret, files=None)
    chunkseal.open_file(path, secret) -> (header, payload_bytes)
    chunkseal.verify_file(path, secret) -> header (raises on failure)

Stdlib only. No network, no subprocess, no installs.
"""

import hashlib
import hmac as hmac_std
import json
import os
import secrets
import struct
import time

FORMAT = "castle-chunks/v1"
CIPHER = "sha256-ctr-proto"
MAC = "hmac-sha256"
DEFAULT_CHUNK = 1 << 20          # 1 MiB chunks
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
PBKDF2_ITER = 600_000
_SECRET_LABEL = b"castle-chunks-mac-v1"


class ChunkSealError(Exception):
    """Anything that makes a chunked backup untrustworthy is a hard
    refusal — wrong passphrase, tampered chunk, malformed file."""


# ---------------------------------------------------------------------------
# key derivation — passphrase or raw 32-byte keyfile key
# ---------------------------------------------------------------------------

def derive_keys(secret, salt):
    """Derive (enc_key, mac_key, kdf_params) from secret + salt.

    ``secret`` is (kind, bytes) as returned by
    ``vault_lock._read_secret``: kind "passphrase" or "keyfile".
    Returns ((enc_key, mac_key), params_dict_for_header)."""
    kind, raw = secret
    if kind == "keyfile":
        enc_key = raw
        mac_key = hmac_std.new(raw, _SECRET_LABEL,
                               hashlib.sha256).digest()
        return (enc_key, mac_key), {"kdf": "raw-keyfile"}
    try:
        master = hashlib.scrypt(raw, salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                                p=SCRYPT_P, dklen=64)
        params = {"kdf": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R,
                  "p": SCRYPT_P, "dklen": 64}
    except (ValueError, MemoryError):
        # scrypt unavailable or memory-capped on this box: fail over
        # to PBKDF2 rather than failing the backup. The header records
        # which one ran, so the reader redoes exactly that.
        master = hashlib.pbkdf2_hmac("sha256", raw, salt,
                                     PBKDF2_ITER, dklen=64)
        params = {"kdf": "pbkdf2-sha256", "iterations": PBKDF2_ITER,
                  "dklen": 64}
    return (master[:32], master[32:]), params


def rederive_keys(secret, header):
    """Re-derive the key pair using the KDF params stored in the
    header. Refuses on unknown/unsupported KDF."""
    kind, raw = secret
    params = header.get("kdf")
    if not isinstance(params, dict) or "kdf" not in params:
        raise ChunkSealError("backup header missing KDF params — refusing")
    name = params["kdf"]
    salt = bytes.fromhex(header["salt"])
    if kind == "keyfile":
        if name != "raw-keyfile":
            raise ChunkSealError(
                "backup was sealed with a passphrase, not a keyfile — "
                "refusing")
        enc_key = raw
        mac_key = hmac_std.new(raw, _SECRET_LABEL,
                               hashlib.sha256).digest()
        return enc_key, mac_key
    if name == "scrypt":
        try:
            master = hashlib.scrypt(raw, salt=salt, n=params["n"],
                                    r=params["r"], p=params["p"],
                                    dklen=params["dklen"])
        except (ValueError, MemoryError, KeyError) as e:
            raise ChunkSealError(
                "cannot redo scrypt with stored params: %s" % e)
    elif name == "pbkdf2-sha256":
        try:
            master = hashlib.pbkdf2_hmac("sha256", raw, salt,
                                        params["iterations"],
                                        dklen=params["dklen"])
        except (ValueError, KeyError) as e:
            raise ChunkSealError(
                "cannot redo PBKDF2 with stored params: %s" % e)
    else:
        raise ChunkSealError("unsupported KDF in backup header: %r" % name)
    return master[:32], master[32:]


# ---------------------------------------------------------------------------
# stream cipher — SHA-256 counter mode (prototype, documented)
# ---------------------------------------------------------------------------

def _keystream(enc_key, nonce, chunk_idx, nbytes):
    """Keystream for one chunk: SHA-256(enc_key || nonce ||
    chunk_index || block_counter), concatenated."""
    out = bytearray()
    ctr = 0
    prefix = enc_key + nonce + struct.pack(">I", chunk_idx)
    while len(out) < nbytes:
        out += hashlib.sha256(prefix + struct.pack(">Q", ctr)).digest()
        ctr += 1
    return bytes(out[:nbytes])


def _xor(chunk, keystream):
    return bytes(a ^ b for a, b in zip(chunk, keystream))


# ---------------------------------------------------------------------------
# seal / open / verify
# ---------------------------------------------------------------------------

def seal(payload, secret, files=None, chunk_size=DEFAULT_CHUNK):
    """Encrypt payload bytes -> (header_dict, body_bytes).

    ``secret`` is (kind, bytes). ``files`` is an optional
    {path: {size, sha256}} inventory the reader can re-check.
    Raises ChunkSealError on bad input."""
    if not isinstance(payload, (bytes, bytearray)):
        raise ChunkSealError("payload must be bytes")
    if chunk_size < 64 or chunk_size > (1 << 28):
        raise ChunkSealError("chunk size out of range: %r" % chunk_size)
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    (enc_key, mac_key), kdf_params = derive_keys(secret, salt)
    chunks = [bytes(payload[i:i + chunk_size])
              for i in range(0, len(payload), chunk_size)] or [b""]
    tags, body = [], bytearray()
    for idx, pt in enumerate(chunks):
        ct = _xor(pt, _keystream(enc_key, nonce, idx, len(pt)))
        tag = hmac_std.new(mac_key,
                           nonce + struct.pack(">I", idx) + ct,
                           hashlib.sha256).hexdigest()
        tags.append(tag)
        body += struct.pack(">I", len(ct)) + ct
    header = {
        "format": FORMAT,
        "cipher": CIPHER,
        "mac": MAC,
        "kdf": kdf_params,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "chunk_size": chunk_size,
        "chunk_count": len(chunks),
        "chunk_tags": tags,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "payload_bytes": len(payload),
        "files": files or {},
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    return header, bytes(body)


def _parse_body(body):
    """Split the body into length-prefixed chunks. Malformed framing
    is a refusal, never a guess."""
    chunks, off = [], 0
    while off < len(body):
        if off + 4 > len(body):
            raise ChunkSealError(
                "backup body truncated (bad chunk framing) — refusing")
        (ln,) = struct.unpack(">I", body[off:off + 4])
        off += 4
        if off + ln > len(body):
            raise ChunkSealError(
                "backup body truncated (chunk overruns file) — refusing")
        chunks.append(body[off:off + ln])
        off += ln
    return chunks


def open_sealed(header, body, secret):
    """Verify every chunk's HMAC, then decrypt. Returns the payload
    bytes. Fail closed: any tag mismatch, count mismatch, or payload
    hash mismatch raises ChunkSealError."""
    if header.get("format") != FORMAT:
        raise ChunkSealError("not a castle-chunks backup (bad format id)")
    if header.get("cipher") != CIPHER or header.get("mac") != MAC:
        raise ChunkSealError(
            "unsupported suite in header: %r/%r"
            % (header.get("cipher"), header.get("mac")))
    enc_key, mac_key = rederive_keys(secret, header)
    nonce = bytes.fromhex(header["nonce"])
    chunks = _parse_body(body)
    if len(chunks) != header["chunk_count"]:
        raise ChunkSealError(
            "chunk count mismatch: header says %d, file holds %d — "
            "refusing" % (header["chunk_count"], len(chunks)))
    if len(header["chunk_tags"]) != len(chunks):
        raise ChunkSealError("header tag list does not match chunk count")
    pt_parts = []
    for idx, ct in enumerate(chunks):
        expect = header["chunk_tags"][idx]
        got = hmac_std.new(mac_key,
                           nonce + struct.pack(">I", idx) + ct,
                           hashlib.sha256).hexdigest()
        if not hmac_std.compare_digest(got, expect):
            raise ChunkSealError(
                "chunk %d HMAC mismatch — wrong passphrase or tampered "
                "chunk; refusing to decrypt" % idx)
        pt_parts.append(_xor(ct, _keystream(enc_key, nonce, idx, len(ct))))
    payload = b"".join(pt_parts)
    if hashlib.sha256(payload).hexdigest() != header["payload_sha256"]:
        raise ChunkSealError(
            "payload hash mismatch after decrypt — refusing")
    return payload


def _write_chunked(out_path, header, body):
    tmp = out_path + ".tmp.%d" % os.getpid()
    with open(tmp, "wb") as f:
        f.write((json.dumps(header, sort_keys=True) + "\n").encode("utf-8"))
        f.write(body)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, out_path)


def _read_chunked(path):
    with open(path, "rb") as f:
        raw = f.read()
    header_raw, sep, body = raw.partition(b"\n")
    if not sep:
        raise ChunkSealError("not a castle backup file (no header line)")
    try:
        header = json.loads(header_raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ChunkSealError("not a castle backup file (bad header)")
    if not isinstance(header, dict):
        raise ChunkSealError("not a castle backup file (bad header)")
    return header, body


def peek_format(path):
    """Read just the header's format id (no secret needed)."""
    header, _ = _read_chunked(path)
    return header.get("format")


def seal_file(src_path, out_path, secret, files=None,
              chunk_size=DEFAULT_CHUNK):
    """Seal the bytes of src_path into out_path. Returns the header."""
    with open(src_path, "rb") as f:
        payload = f.read()
    header, body = seal(payload, secret, files=files,
                        chunk_size=chunk_size)
    _write_chunked(out_path, header, body)
    return header


def open_file(path, secret):
    """Verify + decrypt path -> (header, payload)."""
    header, body = _read_chunked(path)
    return header, open_sealed(header, body, secret)


def verify_file(path, secret):
    """Prove the file opens cleanly. Returns the header; raises
    ChunkSealError on anything wrong. Nothing is written."""
    header, payload = open_file(path, secret)
    if header["payload_bytes"] != len(payload):
        raise ChunkSealError("payload length mismatch — refusing")
    return header


if __name__ == "__main__":
    import argparse
    import sys

    _HERE = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, _HERE)
    import vault_lock  # noqa: E402  (0600 secret checks, no chmod)

    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def _secret_args(p):
        g = p.add_mutually_exclusive_group(required=True)
        g.add_argument("--passphrase-file")
        g.add_argument("--keyfile")
        return p

    p = _secret_args(sub.add_parser("seal"))
    p.add_argument("src", help="file to seal")
    p.add_argument("--out", required=True)
    p.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK)

    p = _secret_args(sub.add_parser("verify"))
    p.add_argument("file", help="the sealed .castle-chunks file")

    a = ap.parse_args()
    try:
        secret = vault_lock._read_secret(a.passphrase_file, a.keyfile)
        try:
            if a.cmd == "seal":
                h = seal_file(a.src, a.out, secret,
                              chunk_size=a.chunk_size)
                print("sealed %s -> %s (%d chunks, kdf=%s)"
                      % (a.src, a.out, h["chunk_count"],
                         h["kdf"]["kdf"]))
            else:
                h = verify_file(a.file, secret)
                print("verified %s — %d chunk(s), %d bytes, all HMACs "
                      "match" % (a.file, h["chunk_count"],
                                 h["payload_bytes"]))
        finally:
            del secret
    except (ChunkSealError, vault_lock.VaultLockError) as e:
        # typed errors only: no traceback, ever
        print("refused: %s" % e)
        raise SystemExit(1)
