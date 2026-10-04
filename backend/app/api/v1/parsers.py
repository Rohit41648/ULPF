from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.database import models
from app.database.session import get_db
from app.schemas.api import ParserOut, ParserUpdateRequest


router = APIRouter(prefix="/parsers", tags=["parsers"])


@router.get("", response_model=list[ParserOut])
def list_parsers(db: Session = Depends(get_db)) -> list[models.Parser]:
    return db.query(models.Parser).order_by(models.Parser.created_at.desc()).all()


@router.get("/{parser_id}", response_model=ParserOut)
def get_parser(parser_id: str, db: Session = Depends(get_db)) -> models.Parser:
    parser = (
        db.query(models.Parser)
        .filter((models.Parser.id == parser_id) | (models.Parser.name == parser_id))
        .first()
    )
    if not parser:
        raise HTTPException(status_code=404, detail="Parser not found.")
    return parser


@router.patch("/{parser_id}", response_model=ParserOut)
def update_parser(
    parser_id: str,
    payload: ParserUpdateRequest,
    db: Session = Depends(get_db),
) -> models.Parser:
    """Update parser name, active/disabled status, or field mapping configuration."""
    parser = (
        db.query(models.Parser)
        .filter((models.Parser.id == parser_id) | (models.Parser.name == parser_id))
        .first()
    )
    if not parser:
        raise HTTPException(status_code=404, detail="Parser not found.")

    if payload.name is not None:
        new_name = payload.name.strip()
        if not new_name:
            raise HTTPException(status_code=400, detail="Parser name cannot be empty.")
        if new_name != parser.name:
            conflict = db.query(models.Parser).filter(
                models.Parser.name == new_name, models.Parser.id != parser_id
            ).first()
            if conflict:
                raise HTTPException(status_code=409, detail=f"Parser '{new_name}' already exists.")
            parser.name = new_name
            if parser.config and isinstance(parser.config, dict):
                parser.config["parser_name"] = new_name
                flag_modified(parser, "config")

    if payload.status is not None:
        status_val = payload.status.lower().strip()
        if status_val not in ("active", "disabled"):
            raise HTTPException(status_code=400, detail="Status must be 'active' or 'disabled'.")
        parser.status = status_val

    if payload.config is not None:
        parser.config = payload.config
        if isinstance(parser.config, dict):
            parser.config["parser_name"] = parser.name
        flag_modified(parser, "config")

    db.commit()
    db.refresh(parser)
    return parser


@router.delete("/{parser_id}")
def delete_parser(parser_id: str, db: Session = Depends(get_db)) -> dict:
    """Delete a custom/ML-generated parser. Preserves historical event records with detached parser_id."""
    parser = db.query(models.Parser).filter(models.Parser.id == parser_id).first()
    if not parser:
        raise HTTPException(status_code=404, detail="Parser not found.")

    if parser.source_type == "deterministic":
        raise HTTPException(
            status_code=400,
            detail="Built-in deterministic parsers cannot be deleted. You can disable them instead.",
        )

    parser_name = parser.name
    # Preserve forensic event linkage by detaching parser_id before deleting
    db.query(models.NormalizedEvent).filter(
        models.NormalizedEvent.parser_id == parser.id
    ).update({"parser_id": None})

    # Update processing runs reference
    db.query(models.ProcessingRun).filter(
        models.ProcessingRun.parser_used == parser_name
    ).update({"parser_used": f"{parser_name} (deleted)"})

    db.delete(parser)
    db.commit()

    return {"success": True, "message": f"Parser '{parser_name}' deleted successfully."}


class ParserTestRequest(BaseModel):
    raw_log: str


@router.post("/{parser_id}/test")
def test_parser(
    parser_id: str,
    payload: ParserTestRequest,
    db: Session = Depends(get_db),
) -> dict:
    """Test a sample log line against this specific parser."""
    parser_row = db.query(models.Parser).filter(models.Parser.id == parser_id).first()
    if not parser_row:
        raise HTTPException(status_code=404, detail="Parser not found.")

    from app.onboarding.generated_parser import GeneratedParser
    from app.parsers.registry import parser_registry

    raw_log = payload.raw_log.strip()
    if not raw_log:
        raise HTTPException(status_code=400, detail="raw_log is required.")

    parser_instance = None
    if parser_row.source_type in ("ml_generated", "ai_generated"):
        parser_instance = GeneratedParser(parser_row.config or {})
    else:
        for p in parser_registry.list_parsers():
            if p.name == parser_row.name:
                parser_instance = p
                break

    if not parser_instance:
        raise HTTPException(status_code=500, detail=f"Parser engine '{parser_row.name}' could not be initialized.")

    detected = parser_instance.detect(raw_log)
    if not detected:
        return {
            "matches": False,
            "matched": False,
            "message": f"Log does not match signature pattern for '{parser_row.name}'.",
            "extracted_fields": {},
            "fields": [],
            "confidence": 0.0,
        }

    try:
        fields = parser_instance.parse(raw_log)
        conf = parser_instance.confidence(fields)
        # Convert any datetime or non-serializable objects to strings
        safe_fields = {k: str(v) if v is not None else None for k, v in fields.items()}
        fields_list = [{"field": k, "value": v, "mapped_to": k} for k, v in safe_fields.items()]
        return {
            "matches": True,
            "matched": True,
            "message": f"Match confirmed! Extracted {len(safe_fields)} fields.",
            "extracted_fields": safe_fields,
            "fields": fields_list,
            "confidence": round(conf, 2),
        }
    except Exception as exc:
        return {
            "matches": True,
            "matched": True,
            "message": f"Matched signature but parsing encountered an issue: {exc}",
            "extracted_fields": {},
            "fields": [],
            "confidence": 0.0,
        }

