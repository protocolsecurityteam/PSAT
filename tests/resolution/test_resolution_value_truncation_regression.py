"""Regression tests for the 2026-05-26 resolution stall (etherfi run).

Two bugs combined to freeze the whole pipeline:

1. TRIGGER — ``services.resolution.tracking._decode_controller_value`` returned
   the raw multi-word ABI blob for a struct getter that had no ``member_path``
   projection (AccountantWithRateProviders.``accountantState()``). That value is
   >66 chars, so the resolution worker's ``controller_values.value`` (VARCHAR(66))
   INSERT raised ``psycopg2 StringDataRightTruncation`` on ``session.commit()``.

2. AMPLIFIER — ``BaseWorker._execute_job``'s failure handler read
   ``job.retry_count`` (an expired ORM attribute) on the still-pending-rollback
   session *before* calling ``session.rollback()``. That lazy-load re-raised
   ``PendingRollbackError``, escaped the handler, and left the job in
   'processing'. Only the stale-job sweep recovered it (never bumping
   ``retry_count``), so every ~10 min the poison job was requeued, re-claimed and
   re-failed forever — zero forward progress for the run.

These pin both: the snapshot can never emit an unstorable value, and any
session-poisoning exception lands the job in ``failed_terminal`` instead of
stalling. The DB-backed tests hit real Postgres (the truncation only reproduces
against the live ``VARCHAR(66)`` constraint), so they're marked offline-safe via
``requires_postgres`` and keep artifacts inline (no object storage).
"""

from __future__ import annotations

import os

import pytest
from eth_abi.abi import encode
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from db.models import Artifact, Contract, ControllerValue, Job, JobDependency, JobStage, JobStatus
from db.queue import create_job
from schemas.control_tracking import ControlTrackingPlan
from services.resolution.tracking import (
    _CONTROLLER_VALUE_MAX_LEN,
    _decode_controller_value,
    build_control_snapshot,
    clear_classify_cache,
)
from tests.cache_helpers import requires_postgres
from workers.base import BaseWorker

_ADDR = "0x2222222222222222222222222222222222222222"
# A 3-word struct (address, uint96, bool) — the exact shape of AccountantState.
# 0x + 3*64 hex = 194 chars, well past VARCHAR(66).
_RAW_STRUCT = "0x" + encode(["address", "uint96", "bool"], [_ADDR, 123, False]).hex()


@pytest.fixture()
def test_session_local(monkeypatch):
    """Point ``workers.base.SessionLocal`` at the test DB so the handler's
    fresh-session helpers (``_persist_stage_errors``) don't hit prod."""
    test_url = os.environ.get("TEST_DATABASE_URL")
    if not test_url:
        pytest.skip("TEST_DATABASE_URL not set")
    test_engine = create_engine(test_url)
    test_factory = sessionmaker(bind=test_engine, class_=Session, expire_on_commit=False)
    monkeypatch.setattr("workers.base.SessionLocal", test_factory)
    yield test_factory
    test_engine.dispose()


@pytest.fixture()
def clean_db(db_session):
    """Nuke the tables these tests touch so assertions are deterministic.
    FK-safe order: children (controller_values, artifacts, job_dependencies)
    before parents (contracts, jobs)."""

    def _wipe():
        db_session.query(ControllerValue).delete()
        db_session.query(Artifact).delete()
        db_session.query(JobDependency).delete()
        db_session.query(Contract).delete()
        db_session.query(Job).delete()
        db_session.commit()

    _wipe()
    yield db_session
    db_session.rollback()
    _wipe()


def _read_stage_errors(session, job_id):
    art = session.query(Artifact).filter(Artifact.job_id == job_id, Artifact.name == "stage_errors").one_or_none()
    if art is None or art.data is None:
        return None
    return art.data


# ---------------------------------------------------------------------------
# Bug 1 (trigger), decode boundary — unit
# ---------------------------------------------------------------------------


def test_decode_controller_value_refuses_unstorable_struct_blob():
    """A struct getter with no ``member_path`` must not return a >66-char value
    — that's the raw blob that truncated controller_values.value in prod."""
    # No read_spec at all (the prod top-level ``accountantState`` controller).
    with pytest.raises(ValueError, match="exceeds storable width"):
        _decode_controller_value(_RAW_STRUCT, "state_variable", None)

    # A getter_call read_spec that is a struct but carries no member_path.
    struct_spec_no_projection = {
        "strategy": "getter_call",
        "target": "accountantState",
        "type": "Mock.AccountantState",
        "type_kind": "struct",
    }
    with pytest.raises(ValueError, match="exceeds storable width"):
        _decode_controller_value(_RAW_STRUCT, "state_variable", struct_spec_no_projection)  # pyright: ignore[reportArgumentType]


def test_decode_controller_value_storable_paths_unchanged():
    """The fix must not regress the storable paths: a left-padded address word,
    and a projected struct member (member_path) still decode to a 42-char addr."""
    word = "0x" + "00" * 12 + "ab" * 20
    assert _decode_controller_value(word, "state_variable", None) == "0x" + "ab" * 20
    assert len("0x" + "ab" * 20) <= _CONTROLLER_VALUE_MAX_LEN

    projected = {
        "member_path": ["payoutAddress"],
        "type": "address",
        "components": [
            {"name": "payoutAddress", "abi_type": "address"},
            {"name": "highwaterMark", "abi_type": "uint96"},
            {"name": "isPaused", "abi_type": "bool"},
        ],
    }
    assert _decode_controller_value(_RAW_STRUCT, "state_variable", projected) == _ADDR  # pyright: ignore[reportArgumentType]


# ---------------------------------------------------------------------------
# Bug 1 (trigger), end-to-end snapshot → real controller_values INSERT
# ---------------------------------------------------------------------------


def _struct_controller_plan() -> ControlTrackingPlan:
    contract_address = "0x1111111111111111111111111111111111111111"
    return {
        "schema_version": "0.1",
        "contract_address": contract_address,
        "contract_name": "AccountantWithRateProviders",
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": [
            {
                "controller_id": "state_variable:accountantState",
                "label": "accountantState",
                "source": "accountantState",
                "kind": "state_variable",
                # Struct getter, NO member_path — the spurious top-level
                # controller that produced the raw multi-word blob in prod.
                "read_spec": {
                    "strategy": "getter_call",
                    "target": "accountantState",
                    "type": "AccountantWithRateProviders.AccountantState",
                    "type_kind": "struct",
                },
                "tracking_mode": "state_only",
                "event_watch": None,
                "polling_fallback": {
                    "contract_address": contract_address,
                    "polling_sources": ["accountantState"],
                    "cadence": "state_only",
                    "notes": [],
                },
                "notes": [],
            }
        ],
    }


@requires_postgres
def test_struct_getter_snapshot_value_is_storable(clean_db, monkeypatch):
    """build_control_snapshot must not emit a value that overflows
    controller_values.value. Persisting the snapshot exactly as
    resolution_worker.process() does must NOT raise (pre-fix it raised
    StringDataRightTruncation; the worker session would then be poisoned).

    Discovery no longer emits a bare-struct controller (it has no single
    storable value), so a real plan never carries one. This pins the
    resolution-layer defense-in-depth: even if a bare-struct controller is
    handed to the snapshot directly, the value resolves to an honest ``None``."""
    clear_classify_cache()
    plan = _struct_controller_plan()

    def fake_rpc(_rpc_url, method, params, *, chain_id=None):
        if method == "eth_blockNumber":
            return "0x1801f29"  # 25_173_801 — arbitrary recent block
        if method == "eth_call":
            return _RAW_STRUCT
        if method == "eth_getCode":
            return "0x"
        raise AssertionError(f"Unexpected RPC call: {method} {params}")

    monkeypatch.setattr("services.resolution.tracking._rpc_request", fake_rpc)

    snapshot = build_control_snapshot(plan, "https://rpc.example")

    entry = snapshot["controller_values"]["state_variable:accountantState"]
    # The unstorable blob became an honest "couldn't resolve to one value".
    assert entry["value"] is None
    assert entry["resolved_type"] == "unknown"

    # Persist the snapshot the way workers/resolution_worker.py:~140-154 does.
    session = clean_db
    contract = Contract(address=plan["contract_address"], contract_name=plan["contract_name"])
    session.add(contract)
    session.flush()
    for cid, cv in snapshot["controller_values"].items():
        session.add(
            ControllerValue(
                contract_id=contract.id,
                controller_id=cid,
                value=cv.get("value"),
                resolved_type=cv.get("resolved_type"),
                source=cv.get("source"),
                block_number=snapshot.get("block_number"),
                details=cv.get("details"),
                observed_via=cv.get("observed_via"),
            )
        )
    session.commit()  # pre-fix: raises sqlalchemy.exc.DataError here

    stored = session.query(ControllerValue).filter(ControllerValue.contract_id == contract.id).one()
    assert stored.value is None


# ---------------------------------------------------------------------------
# Bug 2 (amplifier), handler must not stall on a poisoned session
# ---------------------------------------------------------------------------


class _SessionPoisoningWorker(BaseWorker):
    """``process()`` reproduces the prod failure shape: an expired ``job`` row
    (an intermediate flush expires it under the worker's session) plus a
    controller_values INSERT whose value overflows VARCHAR(66), which fails the
    flush and leaves the session in pending-rollback."""

    stage = JobStage.resolution
    next_stage = JobStage.policy
    poll_interval = 0.0

    def __init__(self, contract_id: int):
        super().__init__()
        self._contract_id = contract_id

    def process(self, session, job):
        session.expire(job)  # the prod traceback shows job.retry_count was expired
        session.add(
            ControllerValue(
                contract_id=self._contract_id,
                controller_id="state_variable:accountantState",
                value="0x" + "ab" * 65,  # 132 chars > VARCHAR(66)
                resolved_type="contract",
                source="accountantState",
                observed_via="eth_call",
            )
        )
        session.flush()  # psycopg2 StringDataRightTruncation -> sqlalchemy DataError


@requires_postgres
def test_execute_job_marks_terminal_on_session_poisoning_dataerror(clean_db, test_session_local):
    """A DataError that poisons the session lands the job in ``failed_terminal``
    — the handler must not re-raise (pre-fix: PendingRollbackError escaped
    ``_execute_job`` and the row was stranded in 'processing')."""
    session = clean_db
    contract = Contract(address="0x" + "11" * 20, contract_name="AccountantWithRateProviders")
    session.add(contract)
    session.commit()

    job_row = create_job(session, {"address": "0x" + "22" * 20, "name": "accountant-poison"})

    worker = _SessionPoisoningWorker(contract_id=contract.id)
    # Must return normally. Pre-fix this raised PendingRollbackError.
    worker._execute_job(session, job_row)

    session.expire_all()
    refreshed = session.get(Job, job_row.id)
    assert refreshed is not None
    assert refreshed.status == JobStatus.failed_terminal
    assert refreshed.status != JobStatus.processing  # never stranded
    assert refreshed.retry_count == 0  # terminal DataError consumes no retry slot
    assert refreshed.last_failure_kind == "terminal"
    assert refreshed.next_attempt_at is None
    assert refreshed.worker_id is None  # lease released
    assert refreshed.lease_id is None

    payload = _read_stage_errors(session, job_row.id)
    assert payload is not None
    assert any("DataError" in (e.get("exc_type") or "") for e in payload["errors"])
