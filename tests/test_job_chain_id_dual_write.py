"""M0.2 Item 1 — Job.chain_id dual-write + CHECK constraint.

Proves every enqueue path (all funnel through ``db.queue.create_job``) stamps a
first-class ``chain_id`` derived from ``request["chain"]`` via the canonical
registry, that address-less company/root jobs keep ``chain_id`` NULL, and that
the ``address IS NULL OR chain_id IS NOT NULL`` CHECK constraint holds.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from db.models import Job, JobStage, derive_job_chain_id
from db.queue import create_job

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")


def _can_connect() -> bool:
    if not DATABASE_URL:
        return False
    try:
        engine = create_engine(DATABASE_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


requires_postgres = pytest.mark.skipif(not _can_connect(), reason="PostgreSQL not available")


@pytest.fixture()
def session():
    engine = create_engine(DATABASE_URL)
    s = Session(engine, expire_on_commit=False)
    try:
        yield s
    finally:
        s.rollback()
        s.query(Job).delete()
        s.commit()
        s.close()
        engine.dispose()


ADDR = "0x" + "ab" * 20


# ---------------------------------------------------------------------------
# Pure derivation logic (no DB) — mirrors the migration backfill rules.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "chain_value,address,expected",
    [
        ("ethereum", ADDR, 1),
        ("mainnet", ADDR, 1),
        (None, ADDR, 1),  # absent chain → mainnet edge default
        ("", ADDR, 1),
        ("   ", ADDR, 1),
        ("base", ADDR, 8453),
        ("arbitrum", ADDR, 42161),
        ("arbitrum one", ADDR, 42161),  # loose alias via chain_by_name
        ("avax", ADDR, 43114),
        ("optimism", ADDR, 10),
        ("unknown", ADDR, 1),  # discovery sentinel → mainnet fallback
        ("nonsense-l2", ADDR, 1),  # unrecognized → mainnet fallback
        (12345, ADDR, 1),  # non-string → fallback (guarded by chain_by_name)
        # Address-less company/root jobs never carry a chain id.
        ("ethereum", None, None),
        (None, None, None),
        ("base", None, None),
    ],
)
def test_derive_chain_id(chain_value, address, expected):
    assert derive_job_chain_id(chain_value, address) == expected


# ---------------------------------------------------------------------------
# Dual-write through create_job (the single funnel for every enqueue path).
# ---------------------------------------------------------------------------


@requires_postgres
def test_create_job_mainnet_address_gets_chain_id_1(session):
    job = create_job(session, {"address": ADDR, "chain": "ethereum", "name": "eth"})
    assert job.chain_id == 1


@requires_postgres
def test_create_job_missing_chain_defaults_mainnet(session):
    job = create_job(session, {"address": ADDR, "name": "no-chain"})
    assert job.chain_id == 1


@requires_postgres
def test_create_job_base_address_gets_8453(session):
    job = create_job(session, {"address": ADDR, "chain": "base", "name": "base"})
    assert job.chain_id == 8453


@requires_postgres
def test_create_job_unknown_chain_falls_back_to_mainnet(session):
    job = create_job(session, {"address": ADDR, "chain": "unknown", "name": "unk"})
    assert job.chain_id == 1


@requires_postgres
def test_create_job_company_root_job_keeps_null(session):
    # No address = company/root job. chain_id stays NULL even if a chain leaks in.
    job = create_job(session, {"company": "acme", "name": "acme-root", "chain": "base"})
    assert job.address is None
    assert job.chain_id is None


@requires_postgres
def test_create_job_defillama_and_dapp_stages_dual_write(session):
    # The dapp-crawl / defillama enqueue paths pass a non-default initial_stage
    # but the same request dict; chain_id derivation is stage-independent.
    dapp = create_job(session, {"address": ADDR, "chain": "base"}, initial_stage=JobStage.dapp_crawl)
    assert dapp.chain_id == 8453
    dl = create_job(session, {"company": "acme"}, initial_stage=JobStage.defillama_scan)
    assert dl.chain_id is None


# ---------------------------------------------------------------------------
# Model-level insert default: direct Job() construction (bypassing create_job)
# still derives chain_id from its own request, so no path violates the CHECK.
# ---------------------------------------------------------------------------


@requires_postgres
def test_orm_default_derives_chain_id_for_direct_construction(session):
    job = Job(address=ADDR, request={"chain": "base"}, stage=JobStage.static)
    session.add(job)
    session.commit()
    assert job.chain_id == 8453


@requires_postgres
def test_orm_default_mainnet_when_request_has_no_chain(session):
    job = Job(address=ADDR, request={"address": ADDR}, stage=JobStage.static)
    session.add(job)
    session.commit()
    assert job.chain_id == 1


@requires_postgres
def test_orm_default_null_for_addressless_job(session):
    job = Job(address=None, company="acme", request={"company": "acme"}, stage=JobStage.discovery)
    session.add(job)
    session.commit()
    assert job.chain_id is None


# ---------------------------------------------------------------------------
# CHECK constraint at the DB level. Raw INSERT bypasses the ORM default so the
# constraint itself is exercised (the ORM default would otherwise fill it).
# ---------------------------------------------------------------------------


@requires_postgres
def test_check_constraint_rejects_address_without_chain_id(session):
    with pytest.raises(IntegrityError):
        session.execute(
            text(
                "INSERT INTO jobs (id, address, chain_id, status, stage) "
                "VALUES (gen_random_uuid(), :addr, NULL, 'queued', 'discovery')"
            ),
            {"addr": ADDR},
        )
        session.commit()
    session.rollback()


@requires_postgres
def test_check_constraint_allows_addressless_null_chain_id(session):
    session.execute(
        text(
            "INSERT INTO jobs (id, address, chain_id, status, stage) "
            "VALUES (gen_random_uuid(), NULL, NULL, 'queued', 'discovery')"
        )
    )
    session.commit()  # must not raise


@requires_postgres
def test_check_constraint_allows_address_with_chain_id(session):
    session.execute(
        text(
            "INSERT INTO jobs (id, address, chain_id, status, stage) "
            "VALUES (gen_random_uuid(), :addr, 8453, 'queued', 'discovery')"
        ),
        {"addr": ADDR},
    )
    session.commit()  # must not raise


# ---------------------------------------------------------------------------
# Migration backfill rules (pure, no DB) — loaded from the migration module.
# ---------------------------------------------------------------------------


def _load_migration():
    path = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "f3a9c1d47b02_add_chain_id_to_jobs.py"
    spec = importlib.util.spec_from_file_location("_mig_chain_id", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize(
    "raw,cid,reason",
    [
        (None, 1, "absent->mainnet"),
        ("", 1, "absent->mainnet"),
        ("ethereum", 1, "registry"),
        ("mainnet", 1, "registry"),
        ("base", 8453, "registry"),
        ("arbitrum", 42161, "registry"),
        ("unknown", 1, "unknown-sentinel->mainnet"),
        ("nonsense-l2", 1, "unrecognized->mainnet"),
    ],
)
def test_migration_backfill_rules(raw, cid, reason):
    mod = _load_migration()
    assert mod._resolve_chain_id(raw) == (cid, reason)
