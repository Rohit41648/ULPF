from __future__ import annotations

import os


class Settings:
    """Reads config from environment variables (see .env.example).
    No secrets or credentials are hardcoded."""

    APP_NAME: str = "ULPF - Universal Log Pre-processing Framework"
    API_V1_PREFIX: str = "/api/v1"

    # Defaults to a local SQLite file so `uvicorn app.main:app` works with
    # zero setup; docker-compose overrides this to Postgres via env.
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./ulpf.db")

    MAX_UPLOAD_BYTES: int = int(os.getenv("MAX_UPLOAD_BYTES", str(256 * 1024)))  # 256 KB per log
    MAX_BATCH_BYTES: int = int(os.getenv("MAX_BATCH_BYTES", str(5 * 1024 * 1024)))  # 5 MB per uploaded file
    MAX_BATCH_LOGS: int = int(os.getenv("MAX_BATCH_LOGS", "10000"))

    # Optional: if set, the onboarding service can use an LLM provider for
    # more sophisticated field inference. The app must fully function
    # without this being set (heuristic fallback).
    LLM_API_KEY: str | None = os.getenv("LLM_API_KEY")
    LLM_PROVIDER: str | None = os.getenv("LLM_PROVIDER")  # e.g. "gemini"
    LLM_MODEL: str | None = os.getenv("LLM_MODEL", "gemini-3.6-flash")

    # Client-to-server application-layer encryption. Uses a shared AES-256
    # key — transport security (key exchange) is handled by HTTPS/TLS.
    ENCRYPTION_ENABLED: bool = os.getenv("ENCRYPTION_ENABLED", "true").lower() == "true"
    ENCRYPTION_KEY_PATH: str | None = os.getenv("ENCRYPTION_KEY_PATH")

    CORS_ORIGINS: list[str] = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")


settings = Settings()
