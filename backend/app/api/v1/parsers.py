from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import models
from app.database.session import get_db
from app.schemas.api import ParserOut

router = APIRouter(prefix="/parsers", tags=["parsers"])


@router.get("", response_model=list[ParserOut])
def list_parsers(db: Session = Depends(get_db)) -> list[models.Parser]:
    return db.query(models.Parser).order_by(models.Parser.created_at.desc()).all()


@router.get("/{parser_id}", response_model=ParserOut)
def get_parser(parser_id: str, db: Session = Depends(get_db)) -> models.Parser:
    parser = db.query(models.Parser).filter(models.Parser.id == parser_id).first()
    if not parser:
        raise HTTPException(status_code=404, detail="Parser not found.")
    return parser
