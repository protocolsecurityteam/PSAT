import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from db.models import Artifact, Job


@pytest.fixture()
def test_session_local(monkeypatch):
    """Otherwise fresh ``SessionLocal()`` calls hit the prod DATABASE_URL."""
    test_url = os.environ.get("TEST_DATABASE_URL")
    if not test_url:
        pytest.skip("TEST_DATABASE_URL not set")
    test_engine = create_engine(test_url)
    test_factory = sessionmaker(bind=test_engine, class_=Session, expire_on_commit=False)
    monkeypatch.setattr("workers.base.SessionLocal", test_factory)
    yield test_factory
    test_engine.dispose()


@pytest.fixture()
def clean_jobs(db_session):
    db_session.query(Artifact).delete()
    db_session.query(Job).delete()
    db_session.commit()
    yield db_session
    db_session.rollback()
    db_session.query(Artifact).delete()
    db_session.query(Job).delete()
    db_session.commit()


def _read_stage_errors(session, job_id):
    art = session.query(Artifact).filter(Artifact.job_id == job_id, Artifact.name == "stage_errors").one_or_none()
    if art is None or art.data is None:
        return None
    return art.data
