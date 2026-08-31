"""Query-count budgets for high-impact API hotspots (issues #1-6 in the perf review).

Seeds a realistic-shape protocol (50 contracts × 50 effective functions
each, control graph nodes/edges, balances, upgrade events, principal
labels), then asserts each hot endpoint answers with the expected payload
shape and stays under its SQL-statement budget, counted via the SQLAlchemy
``before_cursor_execute`` event.

Run:
    set -a; source .env; set +a
    uv run pytest tests/api/test_api_perf_benchmark.py -s -m "not live"

The ``-s`` flag is what surfaces the printed actual/budget table.
"""

from __future__ import annotations

import time
import uuid
from contextlib import contextmanager

import pytest
from sqlalchemy import event, text

from db.models import (
    AuditContractCoverage,
    AuditReport,
    Contract,
    ContractBalance,
    ContractSummary,
    ControlGraphEdge,
    ControlGraphNode,
    ControllerValue,
    EffectiveFunction,
    FunctionPrincipal,
    Job,
    JobStage,
    JobStatus,
    PrincipalLabel,
    Protocol,
    UpgradeEvent,
)
from db.queue import store_artifact
from tests.conftest import requires_postgres

PROTOCOL_NAME = "perftest"
N_CONTRACTS = 50
N_FUNCTIONS_PER_CONTRACT = 50
N_PRINCIPALS_PER_FUNCTION = 2
N_NODES_PER_CONTRACT = 6
N_EDGES_PER_CONTRACT = 8

# Stage names whose timings the worker fleet records as ``stage_timing_<name>``
# artifacts; ``done`` is the terminal sink so it never gets one.
_PERF_STAGE_TIMING_STAGES = (
    "discovery",
    "dapp_crawl",
    "defillama_scan",
    "selection",
    "static",
    "resolution",
    "policy",
    "coverage",
)


def _addr(seed: int) -> str:
    """Deterministic 0x-prefixed 20-byte address."""
    return "0x" + format(seed, "040x")


def _wipe_perf_data(session) -> None:
    """Remove rows the perf seed may have left behind on the shared test DB.

    The standard ``db_session`` fixture only cleans monitoring + protocol
    tables — Job/Contract rows from prior runs would skew SQL counts. Clean by
    Protocol name (cascades to AuditReport, Contract via SET NULL on
    contracts.protocol_id, Jobs via SET NULL on jobs.protocol_id) plus a sweep
    of the company-tagged jobs.

    Also wipes storage-keyed orphan jobs from sibling fixtures — their DB rows
    outlive MinIO teardown and would break /api/analyses once
    ``_scrub_storage_env`` strips the storage config.
    """
    session.execute(
        text("DELETE FROM artifacts WHERE job_id IN (SELECT id FROM jobs WHERE company = :c)"),
        {"c": PROTOCOL_NAME},
    )
    session.execute(
        text(
            "DELETE FROM contract_dependencies WHERE contract_id IN "
            "(SELECT id FROM contracts WHERE protocol_id IN "
            "(SELECT id FROM protocols WHERE name = :n))"
        ),
        {"n": PROTOCOL_NAME},
    )
    session.execute(
        text("DELETE FROM audit_contract_coverage WHERE protocol_id IN (SELECT id FROM protocols WHERE name = :n)"),
        {"n": PROTOCOL_NAME},
    )
    session.execute(
        text("DELETE FROM audit_reports WHERE protocol_id IN (SELECT id FROM protocols WHERE name = :n)"),
        {"n": PROTOCOL_NAME},
    )
    session.execute(
        text("DELETE FROM contracts WHERE protocol_id IN (SELECT id FROM protocols WHERE name = :n)"),
        {"n": PROTOCOL_NAME},
    )
    session.execute(text("DELETE FROM jobs WHERE company = :c"), {"c": PROTOCOL_NAME})
    session.execute(text("DELETE FROM protocols WHERE name = :n"), {"n": PROTOCOL_NAME})
    session.execute(text("DELETE FROM jobs WHERE id IN (SELECT job_id FROM artifacts WHERE storage_key IS NOT NULL)"))
    session.commit()


@pytest.fixture()
def seeded(db_session, storage_bucket):
    # storage_bucket wires ARTIFACT_STORAGE_* to minio so the artifacts
    # below land as storage_key rows (data NULL) — that's what
    # /api/analyses and /api/jobs/{job_id}/stage_timings hit in prod, so it
    # is the only configuration where the per-row fetch the query budgets
    # bound is on the real code path.
    _wipe_perf_data(db_session)

    protocol = Protocol(name=PROTOCOL_NAME, chains=["ethereum"])
    db_session.add(protocol)
    db_session.flush()

    jobs: list[Job] = []
    contracts: list[Contract] = []

    for i in range(N_CONTRACTS):
        addr = _addr(i + 1)
        job = Job(
            id=uuid.uuid4(),
            address=addr,
            company=PROTOCOL_NAME,
            name=f"perf_{i:03d}",
            status=JobStatus.completed,
            stage=JobStage.done,
            request={"chain": "ethereum"},
            protocol_id=protocol.id,
        )
        db_session.add(job)
        db_session.flush()
        jobs.append(job)

        contract = Contract(
            job_id=job.id,
            protocol_id=protocol.id,
            address=addr,
            chain="ethereum",
            contract_name=f"PerfContract_{i:03d}",
            source_verified=True,
            is_proxy=False,
            rank_score=float(N_CONTRACTS - i),
            discovery_sources=["seed"],
        )
        db_session.add(contract)
        db_session.flush()
        contracts.append(contract)

        db_session.add(
            ContractSummary(
                contract_id=contract.id,
                control_model="role",
                is_upgradeable=False,
                is_pausable=True,
                has_timelock=False,
                is_factory=False,
                source_verified=True,
                standards=["ERC20"],
            )
        )

        # Two balance rows per contract (native + one ERC20)
        db_session.add(
            ContractBalance(
                contract_id=contract.id,
                token_address=None,
                token_symbol="ETH",
                token_name="Ether",
                decimals=18,
                raw_balance="1000000000000000000",
                usd_value=2500.0,
                price_usd=2500.0,
            )
        )

        # Effective functions + principals
        ef_rows = []
        for f in range(N_FUNCTIONS_PER_CONTRACT):
            ef = EffectiveFunction(
                contract_id=contract.id,
                function_name=f"fn_{f:03d}",
                selector=f"0x{f:08x}",
                abi_signature=f"fn_{f:03d}(uint256,address)",
                authority_public=False,
                authority_roles=[],
            )
            db_session.add(ef)
            ef_rows.append(ef)
        db_session.flush()

        for ef in ef_rows:
            for p in range(N_PRINCIPALS_PER_FUNCTION):
                db_session.add(
                    FunctionPrincipal(
                        function_id=ef.id,
                        address=_addr(10000 + p * 100 + (i % 50)),
                        resolved_type="safe" if p == 0 else "eoa",
                        origin=f"controller_{p}",
                        principal_type="direct_owner" if p == 0 else "controller",
                        details={"k": "v"},
                    )
                )

        # Control graph (nodes + edges)
        for n in range(N_NODES_PER_CONTRACT):
            db_session.add(
                ControlGraphNode(
                    contract_id=contract.id,
                    address=_addr(20000 + n + i * 10),
                    node_type="contract" if n % 2 == 0 else "principal",
                    resolved_type="safe" if n % 3 == 0 else "eoa",
                    label=f"label_{n}",
                    contract_name=f"Ctl_{n}",
                    depth=n,
                    analysis_state=None,
                    details={},
                )
            )
        for e in range(N_EDGES_PER_CONTRACT):
            db_session.add(
                ControlGraphEdge(
                    contract_id=contract.id,
                    from_node_id=f"address:{_addr(20000 + (e % N_NODES_PER_CONTRACT) + i * 10)}",
                    to_node_id=f"address:{addr}",
                    relation="safe_owner" if e % 4 == 0 else "controller_value",
                    label=f"edge_{e}",
                    source_controller_id=f"src_{e}",
                    notes=[],
                )
            )

        # Controller values
        for cv_i in range(3):
            db_session.add(
                ControllerValue(
                    contract_id=contract.id,
                    controller_id=f"owner_{cv_i}",
                    value=_addr(30000 + cv_i),
                    resolved_type="safe",
                    source="storage",
                    block_number=1000 + cv_i,
                    details={},
                    observed_via="rpc",
                )
            )

        # Upgrade events
        db_session.add(
            UpgradeEvent(
                contract_id=contract.id,
                proxy_address=addr,
                old_impl=None,
                new_impl=_addr(40000 + i),
                block_number=1000 + i,
                tx_hash=f"0x{i:064x}",
            )
        )

        # Principal labels
        for pl in range(2):
            db_session.add(
                PrincipalLabel(
                    contract_id=contract.id,
                    address=_addr(50000 + pl + i * 10),
                    label=f"plabel_{pl}",
                    display_name=f"Display {pl}",
                    resolved_type="safe",
                    labels=["governance"],
                    confidence="high",
                    details={},
                    graph_context=[],
                )
            )

        # static_facts / contract_flags / dependencies via store_artifact
        # so each body lands in object storage (storage_key set, data NULL),
        # matching the prod layout that exposes the per-row GET hotspot.
        store_artifact(
            db_session,
            job.id,
            "static_facts",
            data={
                "subject": {"name": f"PerfContract_{i:03d}"},
                "summary": "perf summary",
            },
        )
        store_artifact(db_session, job.id, "contract_flags", data={"is_proxy": False})
        store_artifact(db_session, job.id, "dependencies", data={"deps": []})

    # Proxy + impl + audit + coverage rows so the audit_timeline benchmark
    # exercises the proxy/_current_status branch (where the unstaged
    # cov_rows-filter optimization lives).
    proxy_addr = _addr(900001)
    impl_addr = _addr(900002)
    proxy_job = Job(
        id=uuid.uuid4(),
        address=proxy_addr,
        company=PROTOCOL_NAME,
        name="perf_proxy",
        status=JobStatus.completed,
        stage=JobStage.done,
        request={"chain": "ethereum"},
        protocol_id=protocol.id,
    )
    impl_job = Job(
        id=uuid.uuid4(),
        address=impl_addr,
        company=PROTOCOL_NAME,
        name="perf_impl",
        status=JobStatus.completed,
        stage=JobStage.done,
        request={"chain": "ethereum", "proxy_address": proxy_addr},
        protocol_id=protocol.id,
    )
    db_session.add_all([proxy_job, impl_job])
    db_session.flush()

    proxy_contract = Contract(
        job_id=proxy_job.id,
        protocol_id=protocol.id,
        address=proxy_addr,
        chain="ethereum",
        contract_name="PerfProxy",
        is_proxy=True,
        proxy_type="UUPS",
        implementation=impl_addr,
        source_verified=True,
        discovery_sources=["seed"],
    )
    impl_contract = Contract(
        job_id=impl_job.id,
        protocol_id=protocol.id,
        address=impl_addr,
        chain="ethereum",
        contract_name="PerfImpl",
        is_proxy=False,
        source_verified=True,
        discovery_sources=["seed"],
    )
    db_session.add_all([proxy_contract, impl_contract])
    db_session.flush()

    db_session.add(
        UpgradeEvent(
            contract_id=proxy_contract.id,
            proxy_address=proxy_addr,
            old_impl=None,
            new_impl=impl_addr,
            block_number=1_000_000,
            tx_hash="0x" + "a" * 64,
        )
    )

    audit = AuditReport(
        protocol_id=protocol.id,
        url="https://example.com/audit.pdf",
        auditor="PerfAuditor",
        title="Perf Audit",
        date="2025-01-01",
        scope_extraction_status="success",
        scope_contracts=["PerfImpl"],
    )
    db_session.add(audit)
    db_session.flush()

    db_session.add(
        AuditContractCoverage(
            contract_id=impl_contract.id,
            audit_report_id=audit.id,
            protocol_id=protocol.id,
            matched_name="PerfImpl",
            match_type="direct",
            match_confidence="high",
            covered_from_block=1_000_000,
            covered_to_block=None,
        )
    )

    db_session.commit()

    # Stage timings on perf_000 so the /api/jobs/{id}/stage_timings benchmark
    # has eight storage-backed rows to fan out (one per stage that actually
    # ran; ``done`` is terminal and never gets a timing).
    timing_target = jobs[0]
    for stage in _PERF_STAGE_TIMING_STAGES:
        store_artifact(
            db_session,
            timing_target.id,
            f"stage_timing_{stage}",
            data={
                "schema_version": "2",
                "stage": stage,
                "started_at": "2025-01-01T00:00:00Z",
                "ended_at": "2025-01-01T00:00:01Z",
                "elapsed_s": 1.0,
                "worker_id": "perf-bench",
                "status": "ok",
            },
        )

    yield {
        "protocol": protocol,
        "jobs": jobs,
        "contracts": contracts,
        "proxy_contract_id": proxy_contract.id,
        "stage_timings_job_id": timing_target.id,
    }
    _wipe_perf_data(db_session)


class _QueryCounter:
    def __init__(self) -> None:
        self.count: int = 0
        self.elapsed_ms: float = 0.0

    def __call__(self, conn, cursor, statement, params, context, executemany):
        self.count += 1


@contextmanager
def _measure(engine):
    counter = _QueryCounter()
    event.listen(engine, "before_cursor_execute", counter)
    t0 = time.perf_counter()
    try:
        yield counter
    finally:
        counter.elapsed_ms = (time.perf_counter() - t0) * 1000
        event.remove(engine, "before_cursor_execute", counter)


# Post-perf actuals + ~3 slack. Tighten when you intentionally lower a count.
QUERY_BUDGETS = {
    # 25 -> 32 when the payload gained the scorer-computed ``reach`` block:
    # closure/condition/conferral plane loads + the signal population, a fixed
    # per-protocol count (no N+1).
    "company_overview": 35,
    "analyses": 5,
    "analysis_detail": 12,
    "list_jobs": 3,
    "audit_timeline": 10,
    "stage_timings": 3,
}


@requires_postgres
def test_query_count_budgets(seeded, api_client, db_session, monkeypatch, record_property):
    """Every hot endpoint must stay under its query budget, and must answer
    with the payload shape callers depend on — including the exact
    ``stage_timings`` key set, which is a wire-shape freeze."""
    from services.aggregations import contract_audit_timeline as _cat

    monkeypatch.setattr(_cat, "_bytecode_keccak_now_batch", lambda addrs, chain_id=1: {a.lower(): None for a in addrs})

    sample_run = "perf_000"
    proxy_contract_id = seeded["proxy_contract_id"]
    stage_timings_job_id = seeded["stage_timings_job_id"]
    cases = {
        "company_overview": lambda: api_client.get(f"/api/company/{PROTOCOL_NAME}"),
        "analyses": lambda: api_client.get("/api/analyses"),
        "analysis_detail": lambda: api_client.get(f"/api/analyses/{sample_run}"),
        "list_jobs": lambda: api_client.get("/api/jobs"),
        "audit_timeline": lambda: api_client.get(f"/api/contracts/{proxy_contract_id}/audit_timeline"),
        "stage_timings": lambda: api_client.get(f"/api/jobs/{stage_timings_job_id}/stage_timings"),
    }

    # Payload-shape sanity first: a wrong-shaped 200 makes the query counts
    # below meaningless, so shape gates the budget rather than the other way
    # round. Seed adds a proxy + impl pair on top of N_CONTRACTS regulars; the
    # proxy-merge pass in /api/analyses depends on artifact flags we
    # deliberately omit (the audit_timeline case only needs UpgradeEvent +
    # coverage), so just assert the listing carries at least the regulars.
    overview = api_client.get(f"/api/company/{PROTOCOL_NAME}").json()
    assert overview["contract_count"] >= N_CONTRACTS
    analyses = api_client.get("/api/analyses").json()
    assert len([a for a in analyses if a.get("company") == PROTOCOL_NAME]) >= N_CONTRACTS
    detail = api_client.get(f"/api/analyses/{sample_run}").json()
    assert detail["run_name"] == sample_run
    assert "permission_index" not in detail
    timeline = api_client.get(f"/api/contracts/{seeded['proxy_contract_id']}/audit_timeline").json()
    assert timeline["contract"]["is_proxy"] is True
    assert len(timeline["coverage"]) == 1
    jobs = api_client.get("/api/jobs").json()
    assert any(j.get("company") == PROTOCOL_NAME for j in jobs)
    timings = api_client.get(f"/api/jobs/{stage_timings_job_id}/stage_timings").json()
    assert set(timings["stage_timings"].keys()) == set(_PERF_STAGE_TIMING_STAGES)

    actuals: dict[str, int] = {}
    failures: list[str] = []
    for label, fn in cases.items():
        # Warm-up — don't measure planner/JIT cost.
        fn()
        db_session.commit()
        db_session.expire_all()
        with _measure(db_session.get_bind()) as counter:
            resp = fn()
        assert resp.status_code == 200, f"{label}: {resp.status_code} {resp.text[:200]}"
        actuals[label] = counter.count
        budget = QUERY_BUDGETS[label]
        if counter.count > budget:
            failures.append(f"{label}: {counter.count} queries exceeds budget {budget}")

    summary = "\n  ".join(f"{label}: {actuals[label]}/{QUERY_BUDGETS[label]} queries" for label in cases)
    print("\nQuery counts (actual / budget):\n  " + summary)
    record_property("query_counts", actuals)
    assert not failures, "Query-count regression:\n  " + "\n  ".join(failures) + "\n\nAll cases:\n  " + summary
