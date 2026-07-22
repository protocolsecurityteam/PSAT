"""Effects-stage foundations: enum placement, flag-dynamic transition, worker
scaffolding, and fail-forward semantics (EFFECTS_RESOLUTION_SPEC Phase 1).

The DB-backed cases mirror ``tests/test_baseworker_retry.py`` (real Postgres,
inline-JSONB artifacts, offline-safe). ``PSAT_EFFECTS_STAGE`` is asserted default-
off; the flag-off parity case reproduces the Phase-0 baseline artifact hashes.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.models import Artifact, Job, JobStage, JobStatus  # noqa: E402
from db.queue import create_job  # noqa: E402
from services.effects.config import effects_stage_enabled  # noqa: E402
from services.effects.exceptions import ForkRpcTimeoutError  # noqa: E402
from tests.cache_helpers import requires_postgres  # noqa: E402
from tests.test_policy_worker_integration import (  # noqa: E402
    TARGET_ADDRESS,
    _graph_with_nodes,
    _job,
    _minimal_contract_analysis,
    _minimal_snapshot,
)
from workers.effects_worker import EffectsWorker  # noqa: E402
from workers.policy_worker import PolicyWorker  # noqa: E402

# Phase-0 baseline (EFFECTS_RESOLUTION_SPEC, captured at HEAD 146edff): sha256 of
# ``json.dumps(payload, sort_keys=True, default=str)`` per stored policy artifact.
BASELINE_HASHES = {
    "effective_permissions": "1f4ded7e9220b252f9b976e728b89834abb9efb2dc50072b2792ce97e06a7e6c",
    "resolved_control_graph": "ae1197b205261339940fff4060d5530716627dd728ad99417396f33347964d29",
    "principal_labels": "4819eb558b145332ec3815cba846a43974b60138b0c8b446b1835d56494c8d89",
}


@pytest.fixture()
def test_session_local(monkeypatch):
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


# ---------------------------------------------------------------------------
# Enum placement / lifecycle ordering (inv. 11).
# ---------------------------------------------------------------------------


def test_effects_stage_between_policy_and_coverage():
    order = [s.value for s in JobStage]
    assert order.index("policy") < order.index("effects") < order.index("coverage")
    # Full progression is intact.
    assert order == [
        "discovery",
        "dapp_crawl",
        "defillama_scan",
        "selection",
        "static",
        "resolution",
        "policy",
        "effects",
        "coverage",
        "done",
    ]


def test_effects_worker_stage_attrs():
    assert EffectsWorker.stage == JobStage.effects
    assert EffectsWorker.next_stage == JobStage.coverage


# ---------------------------------------------------------------------------
# Flag-dynamic transition (§3a.4 / inv. 15).
# ---------------------------------------------------------------------------


def test_flag_defaults_off(monkeypatch):
    monkeypatch.delenv("PSAT_EFFECTS_STAGE", raising=False)
    assert effects_stage_enabled() is False


def test_policy_next_stage_flag_off_is_coverage(monkeypatch):
    monkeypatch.delenv("PSAT_EFFECTS_STAGE", raising=False)
    assert PolicyWorker().next_stage == JobStage.coverage


def test_policy_next_stage_flag_on_is_effects(monkeypatch):
    monkeypatch.setenv("PSAT_EFFECTS_STAGE", "1")
    assert PolicyWorker().next_stage == JobStage.effects


# ---------------------------------------------------------------------------
# Flag-off parity: the Phase-0 baseline fixture reruns byte-identical AND the
# policy transition stays coverage.
# ---------------------------------------------------------------------------


def _sha256_payload(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def test_flag_off_parity_baseline_artifact_hashes(monkeypatch):
    """The three policy artifacts hash byte-identical to the Phase-0 baseline
    with the flag off, and ``PolicyWorker.next_stage`` stays ``coverage`` — the
    effects work is provably inert flag-off."""
    monkeypatch.delenv("PSAT_EFFECTS_STAGE", raising=False)

    worker = PolicyWorker()
    assert worker.next_stage == JobStage.coverage

    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    contract_analysis = _minimal_contract_analysis()
    control_snapshot = _minimal_snapshot({"some_key:admin": {"value": "0xbbb"}})
    resolved_graph = _graph_with_nodes([])
    tracking_plan = {"schema_version": "0.1", "contract_address": TARGET_ADDRESS, "contract_name": "TestContract"}

    def fake_get_artifact(_session: Any, _job_id: Any, name: str) -> Any:
        return {
            "contract_analysis": contract_analysis,
            "control_snapshot": control_snapshot,
            "resolved_control_graph": resolved_graph,
            "control_tracking_plan": tracking_plan,
        }.get(name)

    store_calls: dict[str, Any] = {}

    def fake_store_artifact(_session, _job_id, name, data=None, text_data=None):
        store_calls[name] = data

    monkeypatch.setattr("workers.policy_worker.get_artifact", fake_get_artifact)
    monkeypatch.setattr("workers.policy_worker.store_artifact", fake_store_artifact)
    monkeypatch.setattr("workers.policy_worker._load_nested_artifacts", lambda *_a, **_kw: {})
    monkeypatch.setattr(
        "workers.policy_worker.build_effective_permissions",
        lambda *a, **kw: {"schema_version": "1", "functions": []},
    )
    monkeypatch.setattr(
        "workers.policy_worker.resolve_control_graph",
        lambda **kw: ({"nodes": [], "edges": [], "refreshed": True}, {}),
    )
    monkeypatch.setattr(
        "workers.policy_worker.build_principal_labels",
        lambda *a, **kw: {"principals": []},
    )

    worker.process(session, cast(Any, job))

    for name, expected in BASELINE_HASHES.items():
        assert name in store_calls, f"{name} not stored"
        assert _sha256_payload(store_calls[name]) == expected, f"{name} drifted from Phase-0 baseline"


# ---------------------------------------------------------------------------
# Worker behavior: inert pass-through + fail-forward (inv. 15).
# ---------------------------------------------------------------------------


class _FailingEffectsWorker(EffectsWorker):
    """Effects worker whose ``process()`` always raises — to drive the
    fail-forward path without a real harness."""

    poll_interval = 0.0

    def __init__(self, exc: BaseException) -> None:
        super().__init__()
        self._exc = exc

    def process(self, _session, _job):
        raise self._exc


@requires_postgres
def test_flag_on_zero_candidate_passthrough(clean_jobs, test_session_local):
    """The inert ``process()`` advances a job straight to ``coverage`` with no
    error (flag-on, zero candidates)."""
    session = clean_jobs
    job_row = create_job(session, {"address": "0xabc", "name": "effects-passthrough"})

    worker = EffectsWorker()
    worker._execute_job(session, job_row)

    session.expire_all()
    refreshed = session.get(Job, job_row.id)
    assert refreshed is not None
    assert refreshed.stage == JobStage.coverage
    assert refreshed.status == JobStatus.queued


@requires_postgres
def test_fail_forward_exhaustion_advances_never_terminal(clean_jobs, test_session_local, monkeypatch):
    """inv. 15: on retry exhaustion the effects stage advances to ``coverage``
    (fail-forward) and NEVER emits ``failed_terminal``."""
    monkeypatch.setenv("PSAT_JOB_MAX_RETRIES", "0")  # first failure = exhaustion

    session = clean_jobs
    job_row = create_job(session, {"address": "0xabc", "name": "effects-failforward"})

    worker = _FailingEffectsWorker(ForkRpcTimeoutError("fork RPC down"))
    worker._execute_job(session, job_row)

    session.expire_all()
    refreshed = session.get(Job, job_row.id)
    assert refreshed is not None
    assert refreshed.status != JobStatus.failed_terminal
    assert refreshed.status == JobStatus.queued
    assert refreshed.stage == JobStage.coverage


@requires_postgres
def test_fail_forward_on_terminal_kind_also_advances(clean_jobs, test_session_local):
    """A deterministically-terminal exception (ValueError) in the effects stage
    must also fail-forward — the stage never terminals a job whose upstream
    artifacts are already complete."""
    session = clean_jobs
    job_row = create_job(session, {"address": "0xabc", "name": "effects-terminal-kind"})

    worker = _FailingEffectsWorker(ValueError("bad candidate"))
    worker._execute_job(session, job_row)

    session.expire_all()
    refreshed = session.get(Job, job_row.id)
    assert refreshed is not None
    assert refreshed.status != JobStatus.failed_terminal
    assert refreshed.stage == JobStage.coverage
