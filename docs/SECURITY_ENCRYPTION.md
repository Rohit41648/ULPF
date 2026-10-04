# ULPF application-layer encryption

ULPF now supports an optional browser-to-backend encryption layer for sensitive log payloads.

## Design

```text
Sender (browser)
    |
    | 1. Generate random AES-256 key + 96-bit IV
    | 2. Encrypt JSON payload with AES-256-GCM
    | 3. Encrypt only the AES key with receiver RSA-OAEP-3072 public key
    | 4. Send encrypted envelope
    v
Receiver (ULPF backend)
    |
    | 5. Use RSA private key to recover AES key
    | 6. AES-GCM decrypts + authenticates the payload
    | 7. Continue with normal ULPF processing / Gemini onboarding
```

The private key never goes to the browser. The browser receives only the public key.
A fresh AES key is generated for every payload, so the RSA key is used only to protect the
short-lived symmetric key.

## Local setup

From `backend/`:

```powershell
python -m pip install -r requirements.txt
python scripts/generate_crypto_keys.py
python -m uvicorn app.main:app --reload --env-file .env
```

This creates:

- `backend/keys/receiver_public.pem` — safe to distribute to senders
- `backend/keys/receiver_private.pem` — secret; never commit or share it

The `.gitignore` already excludes both PEM files.

## Secure endpoints

- `GET /api/v1/security/public-key` — returns the receiver public key
- `POST /api/v1/onboarding/analyze-secure` — decrypts onboarding input before AI/heuristic analysis
- `POST /api/v1/onboarding/create-parser-secure` — decrypts approved onboarding data before persistence
- `POST /api/v1/logs/secure-process` — decrypts log input before processing

The frontend onboarding and log-processing flows use these secure endpoints automatically.

## Important production note

This is **application-layer encryption** for the request body. It does not replace HTTPS/TLS.
For production deployment, use HTTPS as well, protect the private key with a secret-management
system or KMS/HSM, rotate keys, and authenticate/authorize senders.
