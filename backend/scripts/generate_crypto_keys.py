"""Generate a random AES-256 key for application-layer encryption.

Run once:  python -m scripts.generate_crypto_keys
The key is saved as a hex-encoded file. Transport security is handled by
HTTPS/TLS — this key is only for payload-level encryption.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
KEY_DIR = BASE_DIR / "keys"
AES_KEY_FILE = KEY_DIR / "aes_secret.key"

KEY_DIR.mkdir(parents=True, exist_ok=True)

if AES_KEY_FILE.exists():
    raise SystemExit(
        f"AES key already exists at {AES_KEY_FILE}. "
        "Delete the file only if you intentionally want to rotate the key."
    )

# 32 bytes = 256 bits for AES-256
key = os.urandom(32)
AES_KEY_FILE.write_text(key.hex(), encoding="utf-8")

try:
    AES_KEY_FILE.chmod(0o600)
except OSError:
    pass

print(f"Created AES-256 key: {AES_KEY_FILE}")
print("Keep this file secret. Transport is secured by HTTPS/TLS.")
