"""Payload schema goldens, stale limits, split publication, and heartbeat-quiet triggers."""

import gzip
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy import select, update

from db.models import CompanyPageRevision as Revision
from db.models import CompanyPageSnapshot as Page
from db.models import Contract, Job, JobStatus, TvlSnapshot
from services import company_pages as pages
from tests.aggregations.test_prepared_company_pages import prepared as prepared
from tests.aggregations.test_prepared_company_pages import request, source
from tests.conftest import DATABASE_URL, requires_postgres, run_alembic_upgrade
from tests.support.overview_builders import _add_job, _addr
from workers import company_pages as worker

pytestmark = requires_postgres

GOLDEN_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "company_pages"
# Entity-keyed maps (e.g. "ethereum::0x...") are data, not shape.
ADDRESS_KEY = re.compile(r"0x[0-9a-f]{40}")


def skeleton(value):
    if isinstance(value, dict):
        shape = {}
        for key in sorted(value):
            key_shape = "<address>" if ADDRESS_KEY.search(key) else key
            shape[key_shape] = _merge(shape.get(key_shape), skeleton(value[key]))
        return dict(sorted(shape.items()))
    if isinstance(value, list):
        merged = None
        for item in value:
            merged = _merge(merged, skeleton(item))
        return [] if merged is None else [merged]
    return type(value).__name__


def _merge(a, b):
    if a is None or a == b:
        return b
    if b is None:
        return a
    if isinstance(a, dict) and isinstance(b, dict):
        return {key: _merge(a.get(key), b.get(key)) for key in sorted(a.keys() | b.keys())}
    return "|".join(sorted(set(str(a).split("|")) | set(str(b).split("|"))))


def blob(session, section):
    column = pages.section_columns(section).blob
    return json.loads(gzip.decompress(session.execute(select(column)).scalar_one()))


@pytest.mark.parametrize("section", pages.SECTIONS)
def test_payload_skeleton_matches_golden_for_its_schema(prepared, section):
    session, _, factory = prepared
    assert worker.refresh_one(factory) == "prepared"
    actual = {"payload_schema": pages.PAYLOAD_SCHEMA[section], "skeleton": skeleton(blob(session, section))}
    path = GOLDEN_DIR / f"schema_{section}.json"
    if os.getenv("PSAT_UPDATE_SCHEMA_GOLDEN") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n")
    assert json.loads(path.read_text()) == actual, (
        f"The {section} payload shape changed. Bump PAYLOAD_SCHEMA[{section!r}] in services/company_pages.py, "
        "then regenerate the golden with: PSAT_UPDATE_SCHEMA_GOLDEN=1 uv run pytest -m 'not live' "
        "tests/aggregations/test_company_page_staleness.py::test_payload_skeleton_matches_golden_for_its_schema"
    )


def test_only_a_stale_section_past_the_limit_is_refused_and_logged_once(prepared, monkeypatch, caplog):
    session, protocol, factory = prepared
    assert worker.refresh_one(factory) == "prepared"
    monkeypatch.setenv("PSAT_COMPANY_STALE_MAX_S", "60")
    session.execute(update(Page).values(source_started_at=datetime.now(timezone.utc) - timedelta(seconds=61)))
    session.commit()
    with caplog.at_level(logging.ERROR, logger="services.company_pages"):
        # A fresh build never expires and is not rebuilt for age.
        assert source(session, protocol.name) == "prepared"
        assert worker.refresh_one(factory) == "idle"
        session.execute(update(Contract).values(contract_name="changed"))
        session.commit()
        response = pages.prepared_or_pending(session, request(), protocol.name)
    assert response.status_code == 503
    errors = [r for r in caplog.records if r.getMessage() == "Prepared company page exceeded stale limit"]
    assert len(errors) == 1
    assert (errors[0].company, errors[0].section) == (protocol.name, "overview")
    assert worker.refresh_one(factory) == "prepared"
    assert source(session, protocol.name) == "prepared"


def test_structural_failure_still_publishes_summary_and_keeps_structure(prepared, monkeypatch):
    session, protocol, factory = prepared
    assert worker.refresh_one(factory) == "prepared"
    structure = (blob(session, "overview"), blob(session, "functions"))
    session.add(TvlSnapshot(protocol_id=protocol.id, total_usd=123))
    session.execute(update(Contract).values(contract_name="changed"))
    session.commit()

    def timeout(*args):
        raise TimeoutError("canceling statement due to statement timeout")

    monkeypatch.setattr(worker, "build_functions_for_protocol", timeout)
    assert worker.refresh_one(factory) == "failed"
    session.expire_all()
    assert blob(session, "summary")["tvl"]["total_usd"] == 123
    assert source(session, protocol.name, "summary") == "prepared"
    assert (blob(session, "overview"), blob(session, "functions")) == structure
    assert source(session, protocol.name) == "prepared-stale"
    assert session.execute(select(Page.attempts)).scalar_one() == 1


def revisions(session):
    session.expire_all()
    return session.execute(select(Revision.key, Revision.token, Revision.changed_at).order_by(Revision.key)).all()


def test_heartbeat_touches_no_revision_but_completion_does(prepared):
    from db.queue.jobs import heartbeat_job

    session, protocol, _ = prepared
    lease = uuid4()
    address = _addr("heartbeat")
    job = _add_job(session, address=address, company="heartbeat-co", status=JobStatus.processing)
    session.execute(update(Job).where(Job.id == job.id).values(lease_id=lease))
    session.commit()
    before = revisions(session)
    heartbeat_job(session, job.id, lease_id=lease)
    assert revisions(session) == before
    session.execute(update(Job).where(Job.id == job.id).values(status=JobStatus.completed))
    session.commit()
    touched = {key for key, *_ in set(revisions(session)) - set(before)}
    assert {f"legacy:job:{job.id}", f"address:{address}"} <= touched


def test_migration_round_trip():
    from alembic.config import Config

    from alembic import command

    admin = sa.create_engine(DATABASE_URL, isolation_level="AUTOCOMMIT")
    name = f"psat_mig_pages_{os.getpid()}"
    with admin.connect() as conn:
        conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}"'))
        conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
    url = sa.engine.make_url(DATABASE_URL).set(database=name).render_as_string(hide_password=False)
    engine = sa.create_engine(url)
    try:
        run_alembic_upgrade(url)
        config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
        config.set_main_option("script_location", str(Path(__file__).resolve().parents[2] / "alembic"))
        config.set_main_option("sqlalchemy.url", url)

        def columns(table):
            return {c["name"] for c in sa.inspect(engine).get_columns(table)}

        command.downgrade(config, "e1c72a9d4b03")
        assert "version" in columns("company_page_snapshots")
        assert "changed_at" not in columns("company_page_revisions")
        run_alembic_upgrade(url)
        assert "version" not in columns("company_page_snapshots")
        assert {"schema_version", "functions_semantic_epoch", "summary_builder_digest"} <= columns(
            "company_page_snapshots"
        )
        with engine.connect() as conn:
            assert conn.execute(sa.text("SELECT psat_page_changed_at('absent')")).scalar() is None
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()
