from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.core.config import settings
from app.security.crypto import get_aes_key_hex, DEFAULT_AES_KEY_PATH

router = APIRouter(prefix="/security", tags=["security"])


@router.get("/encryption-key")
def get_encryption_key() -> dict[str, str]:
    """Return the shared AES-256 key so clients can encrypt payloads.

    This endpoint MUST be served over HTTPS in production so that the key
    is protected by TLS during transit.
    """
    if not settings.ENCRYPTION_ENABLED:
        raise HTTPException(status_code=404, detail="Application-layer encryption is disabled.")
    path = settings.ENCRYPTION_KEY_PATH or str(DEFAULT_AES_KEY_PATH)
    try:
        key_hex = get_aes_key_hex(path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"algorithm": "A256GCM", "key_hex": key_hex}
