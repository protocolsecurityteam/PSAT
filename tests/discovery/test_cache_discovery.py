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
        "sources": {"s1": "https://old.example.com/page1"},
    }
    new = {
        "contracts": [
            {"address": ADDR_B, "name": "ContractB_v2", "confidence": 0.6},
            {"address": ADDR_C, "name": "ContractC", "confidence": 0.85},
        ],
        "official_domain": "new.example.com",
        "pages_considered": [{"url": "https://new.example.com/page2"}],
        "sources": {"s1": "https://new.example.com/page2"},
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

    assert sorted(merged["sources"].values()) == ["https://new.example.com/page2", "https://old.example.com/page1"]
    assert merged["sources"]["s1"] == "https://new.example.com/page2"


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


def test_merge_expands_legacy_grouped_entries_and_rekeys_sources():
    from services.discovery.inventory import merge_inventory

    prev = {
        "contracts": [
            {
                "name": "Vault",
                "chains": ["ethereum"],
                "confidence": 0.9,
                "source": ["ai_inventory"],
                "source_ids": ["s1", "s2"],
                "deployments": [
                    {"address": ADDR_A, "chains": ["ethereum"]},
                    {"address": ADDR_B, "chains": ["ethereum"], "source_ids": ["s2"]},
                ],
            },
        ],
        "sources": {"s1": "https://old.example.com/contracts", "s2": "https://etherscan.io/address/" + ADDR_B},
    }
    new = {
        "contracts": [
            {"address": ADDR_C, "name": "C", "confidence": 0.85, "source_ids": ["s1"]},
        ],
        "sources": {"s1": "https://new.example.com/contracts"},
        "dropped": {"deployer_expansion_over_limit": 2},
    }

    merged = merge_inventory(prev, new)
    by_addr = {c["address"]: c for c in merged["contracts"]}

    assert len(merged["contracts"]) == 3
    assert set(by_addr) == {ADDR_A.lower(), ADDR_B.lower(), ADDR_C.lower()}
    assert all("deployments" not in c for c in merged["contracts"])
    sources = merged["sources"]
    assert [sources[s] for s in by_addr[ADDR_C.lower()]["source_ids"]] == ["https://new.example.com/contracts"]
    # The legacy group's explorer link names B, so A keeps only the shared page.
    assert [sources[s] for s in by_addr[ADDR_A.lower()]["source_ids"]] == ["https://old.example.com/contracts"]
    assert [sources[s] for s in by_addr[ADDR_B.lower()]["source_ids"]] == ["https://etherscan.io/address/" + ADDR_B]
    assert merged["dropped"] == {"deployer_expansion_over_limit": 2}


def test_company_discovery_persists_every_listed_deployment(db_session, monkeypatch):
    from sqlalchemy import select

    from db.models import Contract
    from db.queue import get_artifact
    from workers.base import JobHandledDirectly
    from workers.discovery import DiscoveryWorker

    same_chain = [f"0x{0xA00 + i:040x}" for i in range(2)]
    other_chain = f"0x{0xB00:040x}"
    inventory = _mock_inventory(
        [
            {
                "name": "HashConsensus",
                "chains": ["ethereum", "base"],
                "confidence": 1.0,
                "source": ["ai_inventory"],
                "source_ids": ["s1"],
                "deployments": [
                    {"address": same_chain[0], "chains": ["ethereum"]},
                    {"address": same_chain[1], "chains": ["ethereum"], "source_ids": ["s2"]},
                    {"address": other_chain, "chains": ["base"]},
                    {"chains": ["ethereum"]},
                ],
            },
            {
                "name": "Solo",
                "address": ADDR_C,
                "chains": ["ethereum", "base"],
                "confidence": 0.8,
                "source": ["ai_inventory"],
                "source_ids": ["s1"],
            },
        ],
        sources={"s1": "https://docs.example.com/contracts", "s2": "https://app.safe.global/home?safe=eth:" + ADDR_C},
        dropped={"deployer_expansion_over_limit": 4},
    )
    monkeypatch.setattr(
        "services.discovery.run_discovery.run_discovery",
        lambda *a, **kw: {
            "audits": {"reports": [], "errors": [], "notes": []},
            "addresses": inventory,
            "meta": {"protocol": "GroupedProtocol", "estimated_cost_usd": 0.0},
        },
    )
    job = _make_company_job(db_session, company="GroupedProtocol")
    worker = DiscoveryWorker()
    worker.update_detail = MagicMock()
    monkeypatch.setattr(worker, "_spawn_parallel_discovery", lambda *a, **kw: None)

    with pytest.raises(JobHandledDirectly):
        worker._process_company(db_session, job)

    rows = {
        (r.address, r.chain): r
        for r in db_session.execute(
            select(Contract).where(Contract.address.in_([*same_chain, other_chain, ADDR_C.lower()]))
        ).scalars()
    }
    assert set(rows) == {
        (same_chain[0], "ethereum"),
        (same_chain[1], "ethereum"),
        (other_chain, "base"),
        (ADDR_C.lower(), "ethereum"),
        (ADDR_C.lower(), "base"),
    }
    assert rows[(same_chain[0], "ethereum")].contract_name == "HashConsensus"
    assert rows[(same_chain[0], "ethereum")].discovery_url == "https://docs.example.com/contracts"
    assert rows[(same_chain[1], "ethereum")].discovery_url == "https://app.safe.global/home?safe=eth:" + ADDR_C

    summary = get_artifact(db_session, job.id, "discovery_summary")
    assert isinstance(summary, dict)
    assert summary["inventory_entries"] == 2
    assert summary["discovered_count"] == 5
    assert summary["dropped"] == {"deployer_expansion_over_limit": 4, "no_address": 1}


def test_merge_keeps_one_address_on_two_chains():
    from services.discovery.inventory import CONFIDENCE_FLOOR, merge_inventory

    prev = {
        "contracts": [
            {"address": ADDR_A, "chains": ["ethereum"], "confidence": 0.9, "source": ["ai_inventory"]},
            {"address": ADDR_B, "chains": ["ethereum"], "confidence": CONFIDENCE_FLOOR, "source": ["ai_inventory"]},
            {"name": "Empty", "chains": ["ethereum"], "deployments": []},
        ],
    }
    new = {
        "contracts": [
            {"address": ADDR_A, "chains": ["arbitrum"], "confidence": 1.0, "source": ["exa_deep_research"]},
        ],
    }

    merged = merge_inventory(prev, new)

    assert sorted((c["address"], c["chain"]) for c in merged["contracts"]) == [
        (ADDR_A.lower(), "arbitrum"),
        (ADDR_A.lower(), "ethereum"),
    ]
    assert merged["dropped"] == {"no_address": 1, "stale_below_confidence_floor": 1}
