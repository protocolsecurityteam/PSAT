"""A policy job whose analysis outgrows its budget ends ``resource_exhausted`` without taking its worker down.

Two real policy jobs share one worker process (K=2), each analysed in a budgeted child against a local JSON-RPC stub,
the only stub. The heavy job's child burns past the CPU budget and is killed: the job ends terminal and is not requeued,
and every function the resolver decides is published not determined with the reason. The sibling finishes normally, and
the worker keeps claiming.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from sqlalchemy import create_engine, select

from tests.conftest import DATABASE_URL, requires_postgres

pytestmark = requires_postgres

HEAVY = "0x" + "a1" * 20
LIGHT = "0x" + "b2" * 20
LATE = "0x" + "c3" * 20
HEAVY_FUNCTIONS = 2000
TREE_WIDTH = 8


class _JsonRpc(BaseHTTPRequestHandler):
    RESULTS = {
        "eth_chainId": "0x1",
        "eth_blockNumber": "0x1000",
        "eth_getCode": "0x",
        "eth_getBalance": "0x0",
        "eth_getStorageAt": "0x" + "0" * 64,
        "eth_call": "0x" + "0" * 64,
    }

    def do_POST(self) -> None:  # noqa: N802 — http.server's hook name
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
        calls = body if isinstance(body, list) else [body]
        replies = [
            {"jsonrpc": "2.0", "id": call.get("id"), "result": self.RESULTS.get(call.get("method"))} for call in calls
        ]
        payload = json.dumps(replies if isinstance(body, list) else replies[0]).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        return


@pytest.fixture
def rpc_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _JsonRpc)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def isolated(monkeypatch):
    """Children reach the test database through the environment their fork server starts with."""
    from db.models import SessionLocal
    from services.compute_isolation import shutdown_children

    monkeypatch.setenv("PSAT_COMPUTE_ISOLATION", "1")
    monkeypatch.setenv("DATABASE_URL", DATABASE_URL)
    monkeypatch.setenv("PSAT_POLICY_COMPUTE_CPU_S", "0.5")
    monkeypatch.setenv("PSAT_POLICY_JOB_CONCURRENCY", "2")
    monkeypatch.setenv("PSAT_EFFECTS_STAGE", "1")
    engine = create_engine(DATABASE_URL)
    previous = SessionLocal.kw["bind"]
    SessionLocal.configure(bind=engine)
    shutdown_children()
    yield
    shutdown_children()
    SessionLocal.configure(bind=previous)
    engine.dispose()


def _business_leaf(value: int) -> dict[str, Any]:
    return {
        "op": "LEAF",
        "leaf": {
            "kind": "equality",
            "authority_role": "business",
            "operator": "eq",
            "operands": [
                {"source": "parameter", "parameter_index": 0, "parameter_name": "x"},
                {"source": "constant", "value": str(value)},
            ],
            "parameter_indices": [0],
            "references_msg_sender": False,
            "expression": f"x == {value}",
            "basis": ["require"],
        },
    }


def _tree(seed: int) -> dict[str, Any]:
    return {
        "op": "AND",
        "children": [
            {
                "op": "OR",
                "children": [_business_leaf((seed * TREE_WIDTH + i) * TREE_WIDTH + j) for j in range(TREE_WIDTH)],
            }
            for i in range(TREE_WIDTH)
        ],
    }


def _seed_job(db_session, address: str, functions: int, rpc_url: str):
    from db.models import Contract, Job, JobStage, JobStatus
    from db.queue import store_artifact

    now = datetime.now(timezone.utc)
    job = Job(
        address=address,
        name=f"Contract{address[2:6]}",
        request={"address": address, "chain": "ethereum", "rpc_url": rpc_url},
        chain_id=1,
        status=JobStatus.queued,
        stage=JobStage.policy,
        created_at=now,
        updated_at=now,
    )
    db_session.add(job)
    db_session.flush()
    db_session.add(Contract(job_id=job.id, address=address, chain="ethereum", contract_name=job.name))
    signatures = [f"f{i}(uint256)" for i in range(functions)]
    artifacts = {
        "contract_analysis": {
            "schema_version": "0.1",
            "subject": {"address": address, "name": job.name},
            "analysis_status": {"static_analysis_completed": True, "errors": []},
        },
        "control_snapshot": {"schema_version": "0.1", "contract_address": address, "controller_values": {}},
        "resolved_control_graph": {"schema_version": "0.1", "nodes": [], "edges": []},
        "control_tracking_plan": {"schema_version": "0.1", "contract_address": address, "contract_name": job.name},
        "predicate_trees": {
            "schema_version": "semantic",
            "trees": {signature: _tree(i) for i, signature in enumerate(signatures)},
        },
        "effects": {"schema_version": "semantic", "functions": {}},
    }
    for name, data in artifacts.items():
        store_artifact(db_session, job.id, name, data=data)
    db_session.commit()
    return job.id, signatures


def _artifact(db_session, job_id: uuid.UUID, name: str) -> dict[str, Any]:
    from db.queue import get_artifact

    value = get_artifact(db_session, job_id, name)
    assert isinstance(value, dict)
    return value


def _rows(db_session, address: str) -> dict[str, Any]:
    from db.models import Contract, EffectiveFunction

    contract_id = db_session.execute(select(Contract.id).where(Contract.address == address)).scalar_one()
    return {
        row.abi_signature: row
        for row in db_session.execute(select(EffectiveFunction).where(EffectiveFunction.contract_id == contract_id))
        .scalars()
        .all()
    }


def test_an_overrun_job_ends_resource_exhausted_while_its_sibling_and_worker_carry_on(
    db_session, rpc_url, isolated, monkeypatch
):
    from db.models import Job, JobStage, JobStatus
    from workers.policy_worker import PolicyWorker

    monkeypatch.setattr("workers.base.signal.signal", lambda *_a: None)
    heavy_id, heavy_signatures = _seed_job(db_session, HEAVY, HEAVY_FUNCTIONS, rpc_url)
    light_id, light_signatures = _seed_job(db_session, LIGHT, 1, rpc_url)

    worker = PolicyWorker()
    worker.poll_interval = 0.1
    assert worker._job_concurrency == 2
    loop = threading.Thread(target=worker.run_loop, daemon=True)
    loop.start()
    try:

        def settled(job_id: uuid.UUID) -> Job | None:
            """The job once it has left the policy stage, by failing or by advancing."""
            db_session.expire_all()
            job = db_session.get(Job, job_id)
            if job is None or (job.status != JobStatus.failed_terminal and job.stage == JobStage.policy):
                return None
            return job

        deadline = time.monotonic() + 120
        while time.monotonic() < deadline and not (settled(heavy_id) and settled(light_id)):
            time.sleep(0.2)
        heavy = settled(heavy_id)
        light = settled(light_id)
        assert heavy is not None and light is not None

        assert heavy.status == JobStatus.failed_terminal
        assert heavy.last_failure_kind == "resource_exhausted"
        assert heavy.retry_count == 0 and heavy.next_attempt_at is None
        errors = _artifact(db_session, heavy_id, "stage_errors")["errors"]
        assert [e["exc_type"] for e in errors] == ["services.compute_isolation.ResourceExhausted"]
        assert "cpu budget" in errors[0]["message"]
        timing = _artifact(db_session, heavy_id, "stage_timing_policy")
        assert timing["status"] == "failed"
        assert timing["metrics"]["resource_exhausted"]["resource"] == "cpu"

        rows = _rows(db_session, HEAVY)
        assert set(rows) == set(heavy_signatures)
        for row in rows.values():
            assert row.status == "unsupported"
            assert row.authority_openness == "not_determined"
            assert row.authority_public is False
            assert row.capability_expr["unsupported_reason"] == "resource_exhausted"
        published = _artifact(db_session, heavy_id, "effective_permissions")
        assert {f["capability_expr"]["unsupported_reason"] for f in published["functions"]} == {"resource_exhausted"}

        assert light.status != JobStatus.failed_terminal
        assert light.stage == JobStage.effects
        light_rows = _rows(db_session, LIGHT)
        assert set(light_rows) == set(light_signatures)
        assert all((row.capability_expr or {}).get("unsupported_reason") is None for row in light_rows.values())
        light_timing = _artifact(db_session, light_id, "stage_timing_policy")
        assert light_timing["status"] == "success"
        assert light_timing["metrics"]["isolated_policy_semantic_cpu_s"] < 0.5

        # The worker survived the overrun and keeps claiming.
        assert loop.is_alive()
        late_id, _ = _seed_job(db_session, LATE, 1, rpc_url)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and settled(late_id) is None:
            time.sleep(0.2)
        late = settled(late_id)
        assert late is not None and late.stage == JobStage.effects

        db_session.expire_all()
        assert db_session.get(Job, heavy_id).status == JobStatus.failed_terminal
    finally:
        worker._running = False
        loop.join(timeout=30)
