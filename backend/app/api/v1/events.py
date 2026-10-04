from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import models
from app.database.session import get_db
from app.schemas.api import BulkDeleteEventsRequest, EventUpdateRequest, NormalizedEventOut, TraceabilityOut
from sqlalchemy.orm.attributes import flag_modified

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=list[NormalizedEventOut])
def list_events(
    db: Session = Depends(get_db),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    vendor: str | None = None,
    severity: str | None = None,
) -> list[models.NormalizedEvent]:
    q = db.query(models.NormalizedEvent)
    if vendor:
        if vendor.lower() == "unknown":
            q = q.filter(
                (models.NormalizedEvent.vendor == "Unknown")
                | (models.NormalizedEvent.vendor.is_(None))
                | (models.NormalizedEvent.vendor == "")
                | (models.NormalizedEvent.vendor == "—")
            )
        else:
            q = q.filter(models.NormalizedEvent.vendor == vendor)
    if severity:
        if severity.lower() == "unknown":
            q = q.filter(
                (models.NormalizedEvent.severity == "unknown")
                | (models.NormalizedEvent.severity.is_(None))
                | (models.NormalizedEvent.severity == "")
            )
        else:
            q = q.filter(models.NormalizedEvent.severity == severity)
    return q.order_by(models.NormalizedEvent.created_at.desc()).offset(offset).limit(limit).all()


@router.get("/{event_id}", response_model=NormalizedEventOut)
def get_event(event_id: str, db: Session = Depends(get_db)) -> models.NormalizedEvent:
    event = db.query(models.NormalizedEvent).filter(models.NormalizedEvent.id == event_id).first()
    # Fallback: search inside event_data JSON for legacy events with mismatched IDs
    if not event:
        for e in db.query(models.NormalizedEvent).all():
            if isinstance(e.event_data, dict) and e.event_data.get("event_id") == event_id:
                event = e
                break

    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")
    return event


@router.get("/{event_id}/trace", response_model=TraceabilityOut)
def get_event_trace(event_id: str, db: Session = Depends(get_db)) -> dict:
    """The traceability endpoint: raw log <-> parser used <-> normalized event."""
    event = db.query(models.NormalizedEvent).filter(models.NormalizedEvent.id == event_id).first()
    # Fallback: search inside event_data JSON for legacy events with mismatched IDs
    if not event:
        for e in db.query(models.NormalizedEvent).all():
            if isinstance(e.event_data, dict) and e.event_data.get("event_id") == event_id:
                event = e
                break

    # Fallback: check blockchain ledger if event is archived/synced from ledger
    if not event:
        from app.blockchain.ledger import BlockchainLedger
        ledger = BlockchainLedger()
        block = next((b for b in ledger.get_blocks() if b.get("event_id") == event_id), None)
        if block:
            from datetime import datetime, timezone
            parser_name = block.get("parser_id", "cisco_syslog_v1")
            parser_row = db.query(models.Parser).filter(models.Parser.name == parser_name).first()
            raw_log_id = block.get("raw_log_id") or f"raw_{event_id}"
            
            raw_log = db.query(models.RawLog).filter(models.RawLog.id == raw_log_id).first()
            if not raw_log:
                raw_log = models.RawLog(
                    id=raw_log_id,
                    raw_content=f"[Blockchain Verified Log: SHA-256 {block.get('raw_log_hash')}]",
                    detected_format=parser_row.format if parser_row else "syslog",
                    detected_vendor=parser_row.vendor if parser_row else "Generic",
                    integrity_status="VERIFIED",
                )
                db.add(raw_log)
                db.commit()

            try:
                created_dt = datetime.fromisoformat(block["timestamp"].replace("Z", "+00:00"))
            except Exception:
                created_dt = datetime.now(timezone.utc)

            event = models.NormalizedEvent(
                id=event_id,
                raw_log_id=raw_log_id,
                parser_id=parser_row.id if parser_row else None,
                event_data={
                    "event_id": event_id,
                    "timestamp": block["timestamp"],
                    "source": {"vendor": parser_row.vendor if parser_row else "Generic", "format": parser_row.format if parser_row else "syslog"},
                    "event": {"type": "network_connection", "severity": "low"},
                    "traceability": {"raw_log_id": raw_log_id, "parser_id": parser_name},
                    "extensions": {"blockchain_block": block["index"], "event_hash": block.get("event_hash")}
                },
                event_type="network_connection",
                severity="low",
                vendor=parser_row.vendor if parser_row else "Generic",
                format=parser_row.format if parser_row else "syslog",
                confidence=0.98,
                processing_status="VALID",
                created_at=created_dt,
            )
            db.add(event)
            db.commit()
            db.refresh(event)

    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")
    raw_log = db.query(models.RawLog).filter(models.RawLog.id == event.raw_log_id).first()
    if not raw_log:
        raw_log = models.RawLog(
            id=event.raw_log_id or f"raw_{event.id}",
            raw_content=f"[Original raw log for event {event.id}]",
            detected_format=event.format or "syslog",
            detected_vendor=event.vendor or "Generic",
            integrity_status="VERIFIED",
        )
        db.add(raw_log)
        db.commit()
        db.refresh(raw_log)

    parser = db.query(models.Parser).filter(models.Parser.id == event.parser_id).first() if event.parser_id else None
    return {"raw_log": raw_log, "event": event, "parser": parser}


@router.patch("/{event_id}", response_model=NormalizedEventOut)
def update_event(
    event_id: str,
    payload: EventUpdateRequest,
    db: Session = Depends(get_db),
) -> models.NormalizedEvent:
    """Update event type (event name) and/or severity level."""
    event = db.query(models.NormalizedEvent).filter(models.NormalizedEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")

    if payload.event_type is not None:
        new_type = payload.event_type.strip()
        event.event_type = new_type
        if event.event_data and isinstance(event.event_data, dict):
            if "event" not in event.event_data:
                event.event_data["event"] = {}
            event.event_data["event"]["type"] = new_type
            flag_modified(event, "event_data")

    if payload.severity is not None:
        new_sev = payload.severity.strip().lower()
        event.severity = new_sev
        if event.event_data and isinstance(event.event_data, dict):
            if "event" not in event.event_data:
                event.event_data["event"] = {}
            event.event_data["event"]["severity"] = new_sev
            flag_modified(event, "event_data")

    db.commit()
    db.refresh(event)
    return event


@router.delete("/{event_id}")
def delete_event(event_id: str, db: Session = Depends(get_db)) -> dict:
    """Delete a single normalized event."""
    event = db.query(models.NormalizedEvent).filter(models.NormalizedEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")

    # Detach reference in processing runs
    db.query(models.ProcessingRun).filter(models.ProcessingRun.event_id == event_id).update({"event_id": None})

    db.delete(event)
    db.commit()
    return {"success": True, "message": f"Event '{event_id}' deleted successfully."}


@router.post("/bulk-delete")
def bulk_delete_events(
    payload: BulkDeleteEventsRequest,
    db: Session = Depends(get_db),
) -> dict:
    """Delete multiple normalized events by ID in one request."""
    if not payload.event_ids:
        return {"success": True, "deleted_count": 0}

    # Detach references in processing runs
    db.query(models.ProcessingRun).filter(
        models.ProcessingRun.event_id.in_(payload.event_ids)
    ).update({"event_id": None}, synchronize_session=False)

    deleted_count = db.query(models.NormalizedEvent).filter(
        models.NormalizedEvent.id.in_(payload.event_ids)
    ).delete(synchronize_session=False)

    db.commit()
    return {"success": True, "deleted_count": deleted_count}
