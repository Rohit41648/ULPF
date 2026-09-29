"""AES-256-GCM encryption and SHA-256 integrity verification.

RSA has been removed — key exchange is secured by HTTPS/TLS. The browser
fetches the shared AES key over TLS, encrypts payloads with AES-256-GCM,
and attaches a SHA-256 hash of the plaintext for tamper detection.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


BASE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_AES_KEY_PATH = BASE_DIR / "keys" / "aes_secret.key"


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _b64d(value: str) -> bytes:
    value = value.strip()
    value += "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value.encode("ascii"))


# ── AES key management ──────────────────────────────────────────────────

def load_aes_key(path: str | Path | None = None) -> bytes:
    """Load the 32-byte AES-256 key from the hex-encoded key file."""
    key_path = Path(path) if path else DEFAULT_AES_KEY_PATH
    if not key_path.exists():
        raise FileNotFoundError(
            f"AES key not found at {key_path}. "
            "Run backend/scripts/generate_crypto_keys.py first."
        )
    hex_key = key_path.read_text(encoding="utf-8").strip()
    return bytes.fromhex(hex_key)


def get_aes_key_hex(path: str | Path | None = None) -> str:
    """Return the AES key as a hex string (served to frontend over HTTPS)."""
    key_path = Path(path) if path else DEFAULT_AES_KEY_PATH
    if not key_path.exists():
        raise FileNotFoundError(
            f"AES key not found at {key_path}. "
            "Run backend/scripts/generate_crypto_keys.py first."
        )
    return key_path.read_text(encoding="utf-8").strip()


# ── SHA-256 integrity hashing ────────────────────────────────────────────

def compute_integrity_hash(data: bytes) -> str:
    """Compute a SHA-256 hex digest of the given bytes.

    This is the server-side counterpart of the browser's sha256Hex() function.
    Both sides hash the raw JSON plaintext (UTF-8 bytes) *before* it is
    encrypted by AES-GCM. If the hashes disagree after decryption, the data
    was tampered with in transit.
    """
    return hashlib.sha256(data).hexdigest()


def verify_integrity_hash(plaintext_bytes: bytes, expected_hash: str | None) -> dict[str, Any]:
    """Compare the hash of decrypted plaintext against the sender's hash.

    Returns a dict with:
      - integrity_verified: bool — True when the hashes match
      - integrity_hash_sent: str | None — the hash the sender attached
      - integrity_hash_computed: str — the hash the server recomputed
      - integrity_status: str — "VERIFIED" | "TAMPERED" | "NO_HASH"
    """
    computed = compute_integrity_hash(plaintext_bytes)

    if expected_hash is None:
        return {
            "integrity_verified": False,
            "integrity_hash_sent": None,
            "integrity_hash_computed": computed,
            "integrity_status": "NO_HASH",
        }

    verified = computed == expected_hash
    return {
        "integrity_verified": verified,
        "integrity_hash_sent": expected_hash,
        "integrity_hash_computed": computed,
        "integrity_status": "VERIFIED" if verified else "TAMPERED",
    }


# ── AES-256-GCM encryption/decryption ───────────────────────────────────

def aes_encrypt(plaintext: bytes, key: bytes) -> dict[str, str]:
    """Encrypt plaintext with AES-256-GCM using the shared key.

    Returns an envelope dict with: iv, ciphertext, integrity_hash.
    """
    iv = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(iv, plaintext, None)
    integrity_hash = compute_integrity_hash(plaintext)
    return {
        "version": 1,
        "algorithm": "A256GCM",
        "iv": _b64e(iv),
        "ciphertext": _b64e(ciphertext),
        "integrity_hash": integrity_hash,
    }


def aes_decrypt(envelope: dict[str, Any], key: bytes) -> tuple[dict[str, Any], bytes]:
    """Decrypt an AES-256-GCM envelope and return (parsed_json, raw_bytes)."""
    if envelope.get("algorithm") != "A256GCM":
        raise ValueError("Unsupported encryption algorithm.")

    iv = _b64d(envelope["iv"])
    ciphertext = _b64d(envelope["ciphertext"])
    plaintext_bytes = AESGCM(key).decrypt(iv, ciphertext, None)
    parsed = json.loads(plaintext_bytes.decode("utf-8"))
    return parsed, plaintext_bytes


def decrypt_and_verify(
    envelope: dict[str, Any],
    key_path: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Decrypt the envelope **and** verify the integrity hash in one step.

    Returns:
        (decrypted_payload, integrity_result)
    """
    key = load_aes_key(key_path)
    parsed, plaintext_bytes = aes_decrypt(envelope, key)
    integrity = verify_integrity_hash(plaintext_bytes, envelope.get("integrity_hash"))
    return parsed, integrity


def decrypt_with_config(envelope: dict[str, Any], key_path: str | None = None) -> dict[str, Any]:
    """Decrypt without integrity verification (backward compat)."""
    key = load_aes_key(key_path)
    parsed, _ = aes_decrypt(envelope, key)
    return parsed
