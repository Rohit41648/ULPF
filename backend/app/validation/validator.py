"""Validates a UniversalEvent before storage.

Runs after Pydantic's own type validation (which happens at construction
time) and adds domain-level checks: IPs, ports, required-field presence,
and timestamp sanity. Produces SUCCESS / WARNING / FAILED plus a list of
human-readable warnings — the raw log is preserved regardless of outcome.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from app.schemas.universal_event import UniversalEvent, ValidationResult


def _is_valid_ip(value: str | None) -> bool:
    if not value:
        return True  # absence is fine; malformed presence is not
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_valid_port(value: int | None) -> bool:
    if value is None:
        return True
    return 0 <= value <= 65535


def validate_event(event: UniversalEvent) -> ValidationResult:
    warnings: list[str] = []
    errors: list[str] = []

    if not _is_valid_ip(event.network.source_ip):
        errors.append(f"Invalid source_ip: {event.network.source_ip!r}")
    if not _is_valid_ip(event.network.destination_ip):
        errors.append(f"Invalid destination_ip: {event.network.destination_ip!r}")
    if not _is_valid_port(event.network.source_port):
        errors.append(f"Invalid source_port: {event.network.source_port!r}")
    if not _is_valid_port(event.network.destination_port):
        errors.append(f"Invalid destination_port: {event.network.destination_port!r}")

    if event.timestamp is None:
        warnings.append("Timestamp could not be extracted; ingestion time will be used for ordering.")
    elif event.timestamp.replace(tzinfo=None) > datetime.now(timezone.utc).replace(tzinfo=None):
        warnings.append("Event timestamp is in the future relative to ingestion time.")

    if not event.event.type:
        warnings.append("event.type could not be determined from the source log.")

    if event.parser.confidence is not None and event.parser.confidence < 0.6:
        warnings.append(f"Low parser confidence ({event.parser.confidence}); review recommended.")

    if errors:
        status = "FAILED"
    elif warnings:
        status = "WARNING"
    else:
        status = "SUCCESS"

    return ValidationResult(status=status, warnings=warnings, errors=errors)
