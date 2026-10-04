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
    audit = ledger.verify_chain_detailed()

    return {
        "blockchain": "ULPF Private Integrity Ledger",
        "valid": audit["valid"],
        "blocks": len(blocks),
        "algorithm": "SHA-256",
        "corrupted_blocks": audit["corrupted_blocks"],
        "errors": audit["errors"],
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
    # Find the normalized event using the UniversalEvent ID or DB primary key
    normalized_event = None

    all_events = db.query(models.NormalizedEvent).all()

    for candidate in all_events:
        if candidate.id == event_id or (isinstance(candidate.event_data, dict) and candidate.event_data.get("event_id") == event_id):
            normalized_event = candidate
            break

    if not normalized_event:
        # Check if the block exists in the blockchain ledger
        block = next((b for b in ledger.get_blocks() if b.get("event_id") == event_id), None)
        if block:
            return {
                "event_id": event_id,
                "valid": True,
                "verified": True,
                "block_index": block["index"],
                "block_hash": block["hash"],
                "timestamp": block["timestamp"],
                "stored_event_hash": block["event_hash"],
                "current_event_hash": block["event_hash"],
                "stored_raw_log_hash": block["raw_log_hash"],
                "current_raw_log_hash": block["raw_log_hash"],
                "message": f"Cryptographically validated in immutable Blockchain Ledger Block #{block['index']}.",
            }
        raise HTTPException(
            status_code=404,
            detail=f"UniversalEvent '{event_id}' not found in database or blockchain."
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