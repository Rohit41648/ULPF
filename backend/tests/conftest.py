import os

# A file-backed sqlite DB (not :memory:) so every connection created by
# SQLAlchemy's connection pool sees the same tables/data during a test.
_TEST_DB_PATH = os.path.join(os.path.dirname(__file__), "_test_ulpf.db")
if os.path.exists(_TEST_DB_PATH):
    os.remove(_TEST_DB_PATH)
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB_PATH}"

import pytest
from fastapi.testclient import TestClient

from app.database.init_db import init_db
from app.database.session import Base, SessionLocal, engine
from app.main import app


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    init_db()
    with TestClient(app) as c:
        yield c
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db_session():
    Base.metadata.drop_all(bind=engine)
    init_db()
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
