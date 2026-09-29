from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from app.database import models
from app.database.session import get_db

from app.blockchain.ledger import BlockchainLedger


router = APIRouter(
    prefix="/blockchain",
    tags=["Blockchain"]
)

ledger = BlockchainLedger()


@router.get("/status")
def blockchain_status():

    blocks = ledger.get_blocks()

    return {
        "blockchain": "ULPF Private Integrity Ledger",
        "valid": ledger.verify_chain(),
        "blocks": len(blocks),
        "algorithm": "SHA-256"
    }


@router.get("/blocks")
def get_blocks():

    return {
        "blocks": ledger.get_blocks()
    }
@router.get("/verify/{event_id}")
def verify_event(
    event_id: str,
    db: Session = Depends(get_db),
):
    # Find the normalized event using the UniversalEvent ID
    normalized_event = None

    all_events = db.query(models.NormalizedEvent).all()

    for candidate in all_events:
        if candidate.event_data.get("event_id") == event_id:
            normalized_event = candidate
            break

    if not normalized_event:
        raise HTTPException(
            status_code=404,
            detail=f"UniversalEvent '{event_id}' not found in database."
        )

    # Find the original raw log
    raw_log = (
        db.query(models.RawLog)
        .filter(models.RawLog.id == normalized_event.raw_log_id)
        .first()
    )

    if not raw_log:
        raise HTTPException(
            status_code=404,
            detail="Original raw log not found."
        )

    # Verify against blockchain
    result = ledger.verify_event(
        event_id=event_id,
        event_data=normalized_event.event_data,
        raw_log=raw_log.raw_content,
    )

    return result