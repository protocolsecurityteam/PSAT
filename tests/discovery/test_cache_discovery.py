from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.cache_helpers import (
    ADDR_A,
    ADDR_B,
    _create_completed_job_with_static_data,
    db_session,  # noqa: F401
    requires_postgres,
)

# offline: stub the DefiLlama protocol-list fetch done during company resolution
pytestmark = [requires_postgres, pytest.mark.usefixtures("_stub_defillama_protocols")]

ADDR_C = "0x1111111111111111111111111111111111111111"


@pytest.fixture(autouse=True)
def _stub_membership_probe(monkeypatch):
    """Stub-the-wire: the gate intake's near-line probe never leaves the machine."""
    monkeypatch.setattr("services.discovery.membership_gate.probe", lambda session, contract: None)


def test_discovery_worker_cache_hit_skips_fetch(db_session, monkeypatch):
    from sqlalchemy import select

    from db.models import Contract
    from db.queue import create_job, get_source_files
    from workers.discovery import DiscoveryWorker

    _create_completed_job_with_static_data(db_session)

    new_job = create_job(db_session, {"address": ADDR_A})

    fetch_called = []
    monkeypatch.setattr(
        "workers.discovery.fetch",
        lambda addr: fetch_called.append(addr) or (_ for _ in ()).throw(AssertionError("fetch should not be called")),
    )

    worker = DiscoveryWorker()
    worker.update_detail = MagicMock()
    worker._process_address(db_session, new_job)

    assert fetch_called == []

    contract = db_session.execute(select(Contract).where(Contract.job_id == new_job.id)).scalar_one_or_none()
    assert contract is not None
    assert contract.contract_name == "TestContract"

    db_session.refresh(new_job)
    assert isinstance(new_job.request, dict)
    assert new_job.request.get("static_cached") is True
    assert new_job.request.get("cache_source_job_id") is not None

    sources = get_source_files(db_session, new_job.id)
    assert len(sources) == 2


def test_merge_inventory_new_and_previous():
    from services.discovery.inventory import merge_inventory as _merge_inventory

    prev = {
        "contracts": [
            {"address": ADDR_A, "name": "ContractA", "confidence": 0.9},
            {"address": ADDR_B, "name": "ContractB", "confidence": 0.7},
        ],
        "official_domain": "old.example.com",
        "pages_considered": [{"url": "https://old.example.com/page1"}],
        "sources": {"etherscan": True},
    }
    new = {
        "contracts": [
            {"address": ADDR_B, "name": "ContractB_v2", "confidence": 0.6},
            {"address": ADDR_C, "name": "ContractC", "confidence": 0.85},
        ],
        "official_domain": "new.example.com",
        "pages_considered": [{"url": "https://new.example.com/page2"}],
        "sources": {"tavily": True},
    }

    merged = _merge_inventory(prev, new)
    contracts_by_addr = {c["address"].lower(): c for c in merged["contracts"]}

    # A: only in prev, decayed 0.9 * 0.8 = 0.72.
    assert ADDR_A.lower() in contracts_by_addr
    assert abs(contracts_by_addr[ADDR_A.lower()]["confidence"] - 0.72) < 0.001

    # B: in both, the higher confidence is kept.
    assert ADDR_B.lower() in contracts_by_addr
    assert contracts_by_addr[ADDR_B.lower()]["confidence"] == 0.7
    assert contracts_by_addr[ADDR_B.lower()]["name"] == "ContractB_v2"  # new entry

    assert ADDR_C.lower() in contracts_by_addr
    assert contracts_by_addr[ADDR_C.lower()]["confidence"] == 0.85

    confs = [c["confidence"] for c in merged["contracts"]]
    assert confs == sorted(confs, reverse=True)

    assert merged["official_domain"] == "new.example.com"

    urls = {p["url"] for p in merged["pages_considered"]}
    assert urls == {"https://old.example.com/page1", "https://new.example.com/page2"}

    assert merged["sources"] == {"etherscan": True, "tavily": True}


def test_merge_inventory_confidence_decay_removes_stale():
    from services.discovery.inventory import merge_inventory as _merge_inventory

    confidence = 0.5
    prev = {
        "contracts": [{"address": ADDR_A, "name": "Stale", "confidence": confidence}],
    }
    for _ in range(10):
        new = {"contracts": []}  # never rediscovered
        prev = _merge_inventory(prev, new)

    assert len(prev["contracts"]) == 0


def test_merge_inventory_confidence_decay_gradual():
    from services.discovery.inventory import CONFIDENCE_DECAY as _CONFIDENCE_DECAY
    from services.discovery.inventory import merge_inventory as _merge_inventory

    prev = {
        "contracts": [{"address": ADDR_A, "name": "A", "confidence": 1.0}],
    }
    merged = _merge_inventory(prev, {"contracts": []})
    a = [c for c in merged["contracts"] if c["address"].lower() == ADDR_A.lower()][0]
    assert abs(a["confidence"] - _CONFIDENCE_DECAY) < 0.001

    merged2 = _merge_inventory(merged, {"contracts": []})
    a2 = [c for c in merged2["contracts"] if c["address"].lower() == ADDR_A.lower()][0]
    assert abs(a2["confidence"] - _CONFIDENCE_DECAY**2) < 0.001


def _make_company_job(session, company="TestProtocol", **extra):
    from db.queue import create_job

    req = {"company": company, "analyze_limit": 10}
    req.update(extra)
    job = create_job(session, req)
    job.company = company
    session.commit()
    return job


def _mock_inventory(contracts, **extra):
    inv = {"contracts": contracts, "official_domain": "example.com"}
    inv.update(extra)
    return inv


def test_first_run_no_previous_inventory(db_session, monkeypatch):
    from db.queue import get_artifact
    from workers.base import JobHandledDirectly
    from workers.discovery import DiscoveryWorker

    inventory = _mock_inventory(
        [
            {"address": ADDR_A, "name": "A", "confidence": 0.9},
        ]
    )
    monkeypatch.setattr(
        "services.discovery.run_discovery.run_discovery",
        lambda *a, **kw: {
            "audits": {"reports": [], "errors": [], "notes": []},
            "addresses": inventory,
            "meta": {"protocol": "TestProtocol", "estimated_cost_usd": 0.0},
        },
    )
    monkeypatch.setattr("workers.discovery.search_protocol_inventory", lambda *a, **kw: inventory)

    job = _make_company_job(db_session)

    worker = DiscoveryWorker()
    worker.update_detail = MagicMock()
    monkeypatch.setattr(worker, "_spawn_parallel_discovery", lambda *a, **kw: None)

    with pytest.raises(JobHandledDirectly):
        worker._process_company(db_session, job)

    stored = get_artifact(db_session, job.id, "contract_inventory")
    assert isinstance(stored, dict)
    assert len(stored["contracts"]) == 1
    assert stored["contracts"][0]["address"] == ADDR_A


def test_rerun_merges_with_previous_inventory(db_session, monkeypatch):
    from db.models import JobStage, JobStatus
    from db.queue import create_job, get_artifact, store_artifact
    from workers.base import JobHandledDirectly
    from workers.discovery import DiscoveryWorker

    prev_job = create_job(db_session, {"company": "TestProtocol"})
    prev_job.company = "TestProtocol"
    prev_job.status = JobStatus.completed
    prev_job.stage = JobStage.done
    db_session.commit()

    prev_inventory = _mock_inventory(
        [
            {"address": ADDR_A, "name": "A", "confidence": 0.9},
            {"address": ADDR_B, "name": "B", "confidence": 0.7},
        ]
    )
    store_artifact(db_session, prev_job.id, "contract_inventory", data=prev_inventory)

    new_inventory = _mock_inventory(
        [
            {"address": ADDR_B, "name": "B_v2", "confidence": 0.6},
            {"address": ADDR_C, "name": "C", "confidence": 0.85},
        ]
    )
    monkeypatch.setattr(
        "services.discovery.run_discovery.run_discovery",
        lambda *a, **kw: {
            "audits": {"reports": [], "errors": [], "notes": []},
            "addresses": new_inventory,
            "meta": {"protocol": "TestProtocol", "estimated_cost_usd": 0.0},
        },
    )
    monkeypatch.setattr("workers.discovery.search_protocol_inventory", lambda *a, **kw: new_inventory)

    job = _make_company_job(db_session)

    worker = DiscoveryWorker()
    worker.update_detail = MagicMock()
    monkeypatch.setattr(worker, "_spawn_parallel_discovery", lambda *a, **kw: None)

    with pytest.raises(JobHandledDirectly):
        worker._process_company(db_session, job)

    stored = get_artifact(db_session, job.id, "contract_inventory")
    assert isinstance(stored, dict)
    contracts_by_addr = {c["address"].lower(): c for c in stored["contracts"]}

    assert ADDR_A.lower() in contracts_by_addr
    assert abs(contracts_by_addr[ADDR_A.lower()]["confidence"] - 0.72) < 0.001

    assert ADDR_B.lower() in contracts_by_addr
    assert contracts_by_addr[ADDR_B.lower()]["confidence"] == 0.7

    assert ADDR_C.lower() in contracts_by_addr
    assert contracts_by_addr[ADDR_C.lower()]["confidence"] == 0.85


# Child-job dedup and confidence filtering live in tests/discovery/test_selection_worker.py.


@pytest.mark.parametrize(
    ("name", "proxy_fields", "lookups", "expected"),
    [
        pytest.param("Regular", {"is_proxy": False}, (ADDR_A,), False, id="non_proxy"),
        pytest.param(
            "Proxy",
            {"is_proxy": True, "proxy_type": "eip1967"},
            (ADDR_A.lower(), ADDR_A.upper()),
            True,
            id="proxy_case_insensitive",
        ),
    ],
)
def test_is_known_proxy(db_session, name, proxy_fields, lookups, expected):
    from db.models import Contract
    from db.queue import create_job, is_known_proxy

    assert is_known_proxy(db_session, ADDR_A) is False

    job = create_job(db_session, {"address": ADDR_A})
    db_session.add(
        Contract(
            job_id=job.id,
            address=ADDR_A,
            contract_name=name,
            compiler_version="v0.8.24",
            language="solidity",
            evm_version="shanghai",
            optimization=True,
            optimization_runs=200,
            source_format="flat",
            source_file_count=1,
            remappings=[],
            **proxy_fields,
        )
    )
    db_session.commit()

    for lookup in lookups:
        assert is_known_proxy(db_session, lookup) is expected
