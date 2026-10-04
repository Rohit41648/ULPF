from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.schemas.universal_event import (
    UniversalEvent,
    SourceInfo,
    EventInfo,
    NetworkInfo,
    UserInfo,
    HttpInfo,
    HostInfo,
    ParserInfo,
    TraceabilityInfo,
)


FIELD_MAP = {
    "timestamp": "timestamp",

    "hostname": "host.hostname",

    "username": "user.username",

    "source_ip": "network.source_ip",
    "source_port": "network.source_port",

    "destination_ip": "network.destination_ip",
    "destination_port": "network.destination_port",

    "protocol": "network.protocol",

    "event_action": "event.action",
    "event_type": "event.type",
    "severity": "event.severity",

    "http_method": "http.method",
    "http_path": "http.path",
    "http_status_code": "http.status_code",
    "user_agent": "http.user_agent",
}


def _convert_value(field: str, value: Any) -> Any:

    if value is None:
        return None

    value = str(value).strip()

    if field in {
        "source_port",
        "destination_port",
        "http_status_code",
    }:
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    return value


def _parse_timestamp(value: Any) -> datetime | None:

    if not value:
        return None

    value = str(value).strip()

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%b %d %H:%M:%S",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue

    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def map_unknown_log_to_universal_event(
    raw_log: str,
    suggestions: list[Any],
    raw_log_id: str | None = None,
    parser_confidence: float | None = None,
) -> UniversalEvent:

    event_id = str(uuid4())

    if raw_log_id is None:
        raw_log_id = event_id

    timestamp = None

    source = SourceInfo(
        vendor="Unknown",
        product=None,
        format="custom",
    )

    event = EventInfo()
    network = NetworkInfo()
    user = UserInfo()
    http = HttpInfo()
    host = HostInfo()

    extensions: dict[str, Any] = {}

    # ---------------------------------------------------------
    # Read suggestions
    # ---------------------------------------------------------

    for suggestion in suggestions:

        if isinstance(suggestion, dict):
            field = suggestion.get("field")
            value = suggestion.get("value")

        else:
            field = getattr(suggestion, "field", None)
            value = getattr(suggestion, "value", None)

        if not field or value is None:
            continue

        value = _convert_value(field, value)

        # -----------------------------------------------------
        # Standard UniversalEvent fields
        # -----------------------------------------------------

        if field == "timestamp":

            parsed = _parse_timestamp(value)

            if parsed:
                timestamp = parsed

        elif field == "hostname":

            host.hostname = str(value)

        elif field == "username":

            user.username = str(value)

        elif field == "source_ip":

            network.source_ip = str(value)

        elif field == "source_port":

            network.source_port = value

        elif field == "destination_ip":

            network.destination_ip = str(value)

        elif field == "destination_port":

            network.destination_port = value

        elif field == "protocol":

            network.protocol = str(value)

        elif field == "event_action":

            event.action = str(value)

        elif field == "event_type":

            event.type = str(value)

        elif field == "severity":

            event.severity = str(value)

        elif field == "http_method":

            http.method = str(value)

        elif field == "http_path":

            http.path = str(value)

        elif field == "http_status_code":

            http.status_code = value

        elif field == "user_agent":

            http.user_agent = str(value)

        # -----------------------------------------------------
        # Unknown field → preserve it
        # -----------------------------------------------------

        else:

            extensions[field] = value

    # ---------------------------------------------------------
    # Current ingestion time
    # ---------------------------------------------------------

    ingested_at = datetime.now(timezone.utc)

    # ---------------------------------------------------------
    # Parser confidence
    # ---------------------------------------------------------

    if parser_confidence is None:

        confidences = []

        for suggestion in suggestions:

            if isinstance(suggestion, dict):
                confidence = suggestion.get("confidence")

            else:
                confidence = getattr(
                    suggestion,
                    "confidence",
                    None,
                )

            if confidence is not None:
                confidences.append(float(confidence))

        parser_confidence = (
            sum(confidences) / len(confidences)
            if confidences
            else 0.0
        )

    parser = ParserInfo(
        name="unknown_source_parser",
        version="1.0",
        confidence=round(
            min(max(parser_confidence, 0.0), 1.0),
            2,
        ),
    )

    traceability = TraceabilityInfo(
        raw_log_id=raw_log_id,
        parser_id=None,
        ingested_at=ingested_at,
    )

    # ---------------------------------------------------------
    # Build UniversalEvent
    # ---------------------------------------------------------

    return UniversalEvent(
        event_id=event_id,
        timestamp=timestamp,
        source=source,
        event=event,
        network=network,
        user=user,
        http=http,
        host=host,
        parser=parser,
        traceability=traceability,
        extensions=extensions,
    )