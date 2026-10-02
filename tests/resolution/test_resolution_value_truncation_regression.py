"""The 2026-05-26 etherfi resolution stall.

``_decode_controller_value`` returned a raw multi-word struct blob that overflowed ``controller_values.value``
(VARCHAR(66)); the failure handler then read expired ``retry_count`` before rollback and left the job
processing, so the stale sweep requeued it forever. Needs real Postgres for the VARCHAR constraint.
"""

from __future__ import annotations

import pytest
from eth_abi.abi import encode

from db.models import Artifact, Contract, ControllerValue, Job, JobDependency, JobStage, JobStatus
from db.queue import create_job
from schemas.control_tracking import ControlTrackingPlan
from services.resolution.tracking import (
    build_control_snapshot,
    clear_classify_cache,
)
from tests.cache_helpers import requires_postgres
from tests.support.db_fixtures import (
    _read_stage_errors,
    test_session_local,  # noqa: F401  (fixture, registered by import)
)
from workers.base import BaseWorker

_ADDR = "0x2222222222222222222222222222222222222222"
# The AccountantState shape: 194 chars.
_RAW_STRUCT = "0x" + encode(["address", "uint96", "bool"], [_ADDR, 123, False]).hex()


@pytest.fixture()
def clean_db(db_session):

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
    """Discovery no longer emits a bare-struct controller; this is defense in depth."""
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
    assert entry["value"] is None
    assert entry["resolved_type"] == "unknown"

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


class _SessionPoisoningWorker(BaseWorker):
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
    session = clean_db
    contract = Contract(address="0x" + "11" * 20, contract_name="AccountantWithRateProviders")
    session.add(contract)
    session.commit()

    job_row = create_job(session, {"address": "0x" + "22" * 20, "name": "accountant-poison"})

    worker = _SessionPoisoningWorker(contract_id=contract.id)
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
