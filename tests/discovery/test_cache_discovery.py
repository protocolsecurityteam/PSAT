from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tests.cache_helpers import (
    ADDR_A,
    ADDR_B,
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
