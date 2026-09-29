from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import models
from app.database.session import get_db
from app.schemas.api import NormalizedEventOut, TraceabilityOut

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
        q = q.filter(models.NormalizedEvent.vendor == vendor)
    if severity:
        q = q.filter(models.NormalizedEvent.severity == severity)
    return q.order_by(models.NormalizedEvent.created_at.desc()).offset(offset).limit(limit).all()


@router.get("/{event_id}", response_model=NormalizedEventOut)
def get_event(event_id: str, db: Session = Depends(get_db)) -> models.NormalizedEvent:
    event = db.query(models.NormalizedEvent).filter(models.NormalizedEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")
    return event


@router.get("/{event_id}/trace", response_model=TraceabilityOut)
def get_event_trace(event_id: str, db: Session = Depends(get_db)) -> dict:
    """The traceability endpoint: raw log <-> parser used <-> normalized event."""
    event = db.query(models.NormalizedEvent).filter(models.NormalizedEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")
    raw_log = db.query(models.RawLog).filter(models.RawLog.id == event.raw_log_id).first()
    parser = db.query(models.Parser).filter(models.Parser.id == event.parser_id).first() if event.parser_id else None
    return {"raw_log": raw_log, "event": event, "parser": parser}
