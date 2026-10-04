"""Creates tables and seeds the `parsers` table from the in-memory
ParserRegistry so the Parser Registry UI has data on first boot."""
from __future__ import annotations

from app.database import models  # noqa: F401  (ensures models are registered on Base)
from app.database.session import Base, SessionLocal, engine
from app.parsers.registry import parser_registry


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    _seed_parsers()


def _seed_parsers() -> None:
    db = SessionLocal()
    try:
        existing = {p.name for p in db.query(models.Parser).all()}
        for parser in parser_registry.list_parsers():
            if parser.name in existing:
                continue
            fields_dict = {f: f for f in getattr(parser, "expected_fields", [])}
            db.add(
                models.Parser(
                    name=parser.name,
                    vendor=parser.vendor,
                    format=parser.format,
                    version=parser.version,
                    status="active",
                    source_type="deterministic",
                    config={
                        "parser_name": parser.name,
                        "format": parser.format,
                        "fields": fields_dict,
                    },
                )
            )
        db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized and parser registry seeded.")
