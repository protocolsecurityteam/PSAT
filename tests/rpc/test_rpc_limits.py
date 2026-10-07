"""Admission is shared by independent workers; overload is not evidence of a revert."""

import json
import multiprocessing
import uuid
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
import requests
from sqlalchemy import delete
from sqlalchemy.orm import Session

from db.models import OpsKv
from services.clients import rpc
from services.clients import rpc_limits as limits
from services.clients.request_budget import RequestBudget, request_budget
from tests.conftest import requires_postgres


def response(payload, status=200, headers=None):
    r = requests.Response()
    r.status_code = status
    r._content = json.dumps(payload).encode()
    r.headers.update(headers or {})
    return r


def _process_reservation(url, database_url, output):
    from sqlalchemy import create_engine

    engine = create_engine(database_url)
    limits._session = lambda: Session(engine)
    try:
        output.put(limits._reserve(url, 1))
    finally:
        engine.dispose()


@pytest.fixture
def shared_gate(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_RPC_LIMITER_MODE", "postgres")
    monkeypatch.setattr(limits, "_session", lambda: Session(db_session.get_bind()))
    url = "https://" + uuid.uuid4().hex + ".example/main/evm/1"
    yield url
    db_session.execute(delete(OpsKv).where(OpsKv.key.like("rpc:%")))
    db_session.commit()


@requires_postgres
def test_concurrent_workers_share_one_burst_across_chains(shared_gate, monkeypatch):
    monkeypatch.setenv("PSAT_RPC_BURST", "3")
    monkeypatch.setenv("PSAT_RPC_RPS", "0.001")
    with ThreadPoolExecutor(max_workers=8) as pool:
        waits = list(pool.map(lambda i: limits._reserve(shared_gate.rsplit("/", 1)[0] + f"/{i + 1}", 1), range(8)))
    assert sum(wait == 0 for wait in waits) == 3
    assert all(wait == 0 or wait > 900 for wait in waits)


@requires_postgres
def test_separate_processes_do_not_multiply_the_allowance(shared_gate, db_session, monkeypatch):
    monkeypatch.setenv("PSAT_RPC_BURST", "2")
    monkeypatch.setenv("PSAT_RPC_RPS", "0.0001")
    database_url = db_session.get_bind().url.render_as_string(hide_password=False)
    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    processes = [
        context.Process(target=_process_reservation, args=(shared_gate, database_url, output)) for _ in range(4)
    ]
    try:
        for process in processes:
            process.start()
        waits = [output.get(timeout=20) for _ in processes]
        for process in processes:
            process.join(timeout=10)
            assert process.exitcode == 0
        assert sum(wait == 0 for wait in waits) == 2
    finally:
        for process in processes:
            if process.is_alive():
                process.kill()
                process.join(timeout=5)
        output.close()


@requires_postgres
def test_run_allowance_survives_new_worker_scope(shared_gate, monkeypatch):
    monkeypatch.setenv("PSAT_RPC_RUN_LIMIT", "3")
    run = str(uuid.uuid4())
    with limits.rpc_scope(run):
        assert limits._reserve(shared_gate, 2) == 0
    with limits.rpc_scope(run):
        with pytest.raises(limits.RpcBudgetExceeded, match="run allowance"):
            limits._reserve(shared_gate, 2)


@requires_postgres
def test_dependency_jobs_inherit_the_run_allowance_identity(db_session):
    from db.queue import create_job

    root = create_job(db_session, {"address": "0x" + "12" * 20, "chain": "ethereum"})
    assert root.request is not None
    assert root.request["root_job_id"] == str(root.id)
    with limits.rpc_scope(root.request["root_job_id"]):
        child = create_job(db_session, {"address": "0x" + "34" * 20, "chain": "ethereum"})
    assert child.request is not None
    assert child.request["root_job_id"] == str(root.id)


@requires_postgres
def test_retry_after_blocks_other_workers_without_another_wire_call(shared_gate, monkeypatch):
    sent = []

    def post(*args, **kwargs):
        sent.append(1)
        return response({}, 429, {"Retry-After": "120"})

    monkeypatch.setattr(rpc, "_get_session", lambda: SimpleNamespace(post=post))
    with pytest.raises(limits.RpcBackpressure):
        rpc.rpc_request(shared_gate, "eth_blockNumber", [], retries=10)
    with pytest.raises(limits.RpcBackpressure) as caught:
        rpc.rpc_request(shared_gate, "eth_blockNumber", [], retries=10)
    assert caught.value.retry_after > 115
    assert len(sent) == 1


def test_missing_admission_store_never_fails_open(monkeypatch):
    monkeypatch.setenv("PSAT_RPC_LIMITER_MODE", "postgres")
    monkeypatch.setattr(limits, "_session", lambda: (_ for _ in ()).throw(RuntimeError("offline DB")))
    monkeypatch.setattr(rpc, "_get_session", lambda: pytest.fail("wire must not be reached"))
    with pytest.raises(limits.RpcBackpressure, match="store unavailable"):
        rpc.rpc_request("https://rpc.example", "eth_blockNumber", [])


def test_batch_members_each_consume_budget_and_swallowed_exhaustion_fails_stage(monkeypatch):
    monkeypatch.setenv("PSAT_RPC_STAGE_LIMIT", "2")
    monkeypatch.setattr(rpc, "_get_session", lambda: pytest.fail("wire must not be reached"))
    with pytest.raises(limits.RpcBudgetExceeded):
        with limits.rpc_scope("one-stage"):
            results = rpc.rpc_batch_request_classified("https://rpc.example", [("eth_call", [{}, "latest"])] * 3)
            assert results == [(None, "transport")] * 3


def test_direct_completion_cannot_hide_exhausted_budget(monkeypatch):
    from unittest.mock import MagicMock

    from db.models import JobStage
    from db.queue import advance_job, complete_job
    from workers.retry_policy import classify

    monkeypatch.setenv("PSAT_RPC_STAGE_LIMIT", "0")
    session = MagicMock()
    with pytest.raises(limits.RpcBudgetExceeded):
        with limits.rpc_scope("exhausted"):
            with pytest.raises(limits.RpcBudgetExceeded):
                limits.admit("https://rpc.example", 1)
            with pytest.raises(limits.RpcBudgetExceeded):
                complete_job(session, uuid.uuid4())
            with pytest.raises(limits.RpcBudgetExceeded):
                advance_job(session, uuid.uuid4(), JobStage.coverage)
    assert not session.get.called
    assert classify(limits.RpcBudgetExceeded()) == "terminal"
    assert classify(limits.RpcBackpressure("cooldown")) == "transient"


def test_successful_batch_counts_calls_not_http_envelopes(monkeypatch):
    def post(*args, **kwargs):
        return response([{"id": item["id"], "result": "0x"} for item in kwargs["json"]])

    monkeypatch.setattr(rpc, "_get_session", lambda: SimpleNamespace(post=post))
    budget = RequestBudget(limit=5)
    with request_budget(budget):
        rpc.rpc_batch_request("https://rpc.example", [("eth_call", [{}, "latest"])] * 3)
    assert budget.attempts["rpc"] == 3


def test_wrapped_capacity_error_is_transport_without_revert_data(monkeypatch):
    error = {
        "code": -32000,
        "message": "upstreams exhausted",
        "data": {
            "code": "ErrUpstreamsExhausted",
            "cause": [{"code": "ErrEndpointCapacityExceeded"}],
            "data": "0xdeadbeef",
        },
    }
    monkeypatch.setattr(
        rpc, "_get_session", lambda: SimpleNamespace(post=lambda *a, **k: response([{"id": 0, "error": error}]))
    )
    assert rpc.rpc_batch_request_classified("https://rpc.example", [("eth_call", [{}, "latest"])]) == [
        (None, "transport")
    ]
    result = rpc.eth_call_batch("https://rpc.example", [{}])[0]
    assert not result.success and result.revert_data is None


def test_pinned_duplicate_probes_and_reverts_are_reused_but_callers_are_distinct(monkeypatch):
    sent = []

    def post(*args, **kwargs):
        sent.append(kwargs["json"])
        return response(
            [
                {"id": item["id"], "error": {"code": 3, "message": "execution reverted", "data": "0x12345678"}}
                for item in kwargs["json"]
            ]
        )

    monkeypatch.setattr(rpc, "_get_session", lambda: SimpleNamespace(post=post))
    with limits.rpc_scope("pinned-read"):
        calls = [{"from": "0x" + "11" * 20, "to": "0x" + "22" * 20, "data": "0x12345678"}]
        assert len(rpc.eth_call_batch("https://rpc.example", calls * 4, "0x64")) == 4
        rpc.eth_call_batch("https://rpc.example", calls, "0x64")
        rpc.eth_call_batch("https://rpc.example", [{**calls[0], "from": "0x" + "33" * 20}], "0x64")
        rpc.eth_call_batch("https://rpc.example", calls, "0x65")
    assert [len(batch) for batch in sent] == [1, 1, 1]


def test_large_pinned_replies_do_not_fill_the_stage_cache(monkeypatch):
    sent = []

    def post(*args, **kwargs):
        sent.append(1)
        return response({"id": 1, "result": "0x" + "aa" * 65536})

    monkeypatch.setattr(rpc, "_get_session", lambda: SimpleNamespace(post=post))
    with limits.rpc_scope("large-read") as scope:
        for _ in range(2):
            rpc.rpc_request("https://rpc.example", "eth_getCode", ["0x" + "11" * 20, "0x64"])
        assert scope.cache == {}
        assert scope.cache_bytes == 0
    assert len(sent) == 2


def test_moving_reads_and_capacity_errors_are_never_cached(monkeypatch):
    sent = []

    def post(*args, **kwargs):
        sent.append(1)
        return response({"id": 1, "result": "0x1"})

    monkeypatch.setattr(rpc, "_get_session", lambda: SimpleNamespace(post=post))
    with limits.rpc_scope("moving-read"):
        for _ in range(2):
            rpc.rpc_request("https://rpc.example", "eth_call", [{}, "latest"])
    assert len(sent) == 2


@requires_postgres
def test_hourly_allowance_schedules_retry_without_spending_next_run(shared_gate, monkeypatch):
    monkeypatch.setenv("PSAT_RPC_HOURLY_LIMIT", "1")
    assert limits._reserve(shared_gate, 1) == 0
    with pytest.raises(limits.RpcBackpressure) as error:
        limits._reserve(shared_gate, 1)
    assert 3500 < error.value.retry_after <= 3600


@pytest.mark.parametrize(
    "method",
    [
        "rpc_request",
        "rpc_batch_request",
        "rpc_batch_request_classified",
        "rpc_batch_request_with_status",
        "eth_call_batch",
    ],
)
def test_all_read_paths_keep_headers_and_pass_shared_admission(monkeypatch, method):
    sent = []
    admissions = []

    def post(*args, **kwargs):
        sent.append(kwargs)
        payload = kwargs["json"]
        if isinstance(payload, list):
            return response([{"id": item["id"], "result": "0x01"} for item in payload])
        return response({"id": payload["id"], "result": "0x01"})

    monkeypatch.setattr(rpc, "_get_session", lambda: SimpleNamespace(post=post))
    monkeypatch.setattr(rpc, "admit", lambda url, count: admissions.append(count))
    headers = {"X-Test-Trace": "read-path"}
    function = getattr(rpc, method)
    if method == "rpc_request":
        function("https://rpc.example", "eth_call", [{}, "latest"], headers=headers)
    elif method == "eth_call_batch":
        function("https://rpc.example", [{}], headers=headers)
    else:
        function("https://rpc.example", [("eth_call", [{}, "latest"])], headers=headers)
    assert admissions == [1]
    assert sent[0]["headers"]["X-Test-Trace"] == "read-path"


@requires_postgres
def test_waiting_batch_books_ahead_so_single_calls_cannot_starve_it(shared_gate, monkeypatch):
    monkeypatch.setenv("PSAT_RPC_BURST", "10")
    monkeypatch.setenv("PSAT_RPC_RPS", "1")
    assert limits._reserve(shared_gate, 10) == 0
    batch_wait = limits._reserve(shared_gate, 10, max_wait=30)
    assert 9 < batch_wait <= 10
    # A later single call queues behind the booked batch instead of taking the next refill.
    assert limits._reserve(shared_gate, 1) > batch_wait


@requires_postgres
def test_wait_beyond_deadline_books_nothing(shared_gate, monkeypatch):
    monkeypatch.setenv("PSAT_RPC_BURST", "10")
    monkeypatch.setenv("PSAT_RPC_RPS", "1")
    assert limits._reserve(shared_gate, 10) == 0
    assert limits._reserve(shared_gate, 10, max_wait=5) > 5
    assert limits._reserve(shared_gate, 1, max_wait=5) <= 1
