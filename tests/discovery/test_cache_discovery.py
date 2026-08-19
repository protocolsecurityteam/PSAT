"""Tests for discovery worker cache hit/miss and company mode."""

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

# Extra addresses used in inventory merge / dedup tests
ADDR_C = "0x1111111111111111111111111111111111111111"


# ---------------------------------------------------------------------------
# Discovery worker cache hit
# ---------------------------------------------------------------------------


def test_discovery_worker_cache_hit_skips_fetch(db_session, monkeypatch):
    """When cache exists, discovery skips fetch() and copies data instead."""
    from sqlalchemy import select

    from db.models import Contract
    from db.queue import create_job, get_source_files
    from workers.discovery import DiscoveryWorker

    # Create completed job as cache source
    _create_completed_job_with_static_data(db_session)

    # Create new job for the same address
    new_job = create_job(db_session, {"address": ADDR_A})

    fetch_called = []
    monkeypatch.setattr(
        "workers.discovery.fetch",
        lambda addr: fetch_called.append(addr) or (_ for _ in ()).throw(AssertionError("fetch should not be called")),
    )

    worker = DiscoveryWorker()
    worker.update_detail = MagicMock()
    worker._process_address(db_session, new_job)

    # fetch() was NOT called
    assert fetch_called == []

    # Data was copied
    contract = db_session.execute(select(Contract).where(Contract.job_id == new_job.id)).scalar_one_or_none()
    assert contract is not None
    assert contract.contract_name == "TestContract"

    # Explicit cache flag was set on the job request
    db_session.refresh(new_job)
    assert isinstance(new_job.request, dict)
    assert new_job.request.get("static_cached") is True
    assert new_job.request.get("cache_source_job_id") is not None

    sources = get_source_files(db_session, new_job.id)
    assert len(sources) == 2


# ---------------------------------------------------------------------------
# Discovery worker cache miss
# ---------------------------------------------------------------------------


def test_discovery_worker_cache_miss_runs_fetch(db_session, monkeypatch):
    """New address with no cached job runs fetch() normally."""
    from db.queue import create_job
    from workers.discovery import DiscoveryWorker

    new_job = create_job(db_session, {"address": ADDR_B})

    fetch_called = []

    def mock_fetch(addr, *, chain_id=1):
        fetch_called.append(addr)
        return {
            "ContractName": "NewContract",
            "SourceCode": "contract NewContract {}",
            "CompilerVersion": "v0.8.24",
            "OptimizationUsed": "1",
            "Runs": "200",
            "EVMVersion": "shanghai",
            "LicenseType": "MIT",
        }

    monkeypatch.setattr("workers.discovery.fetch", mock_fetch)
    monkeypatch.setattr("workers.discovery.parse_sources", lambda r: {"src/New.sol": "contract NewContract {}"})
    monkeypatch.setattr("workers.discovery.parse_remappings", lambda r: [])
    monkeypatch.setattr("workers.discovery.is_vyper_result", lambda r: False)
    monkeypatch.setattr("workers.discovery._batch_get_creators", lambda addrs: {})

    worker = DiscoveryWorker()
    worker.update_detail = MagicMock()
    worker._process_address(db_session, new_job)

    assert fetch_called == [ADDR_B]


# ---------------------------------------------------------------------------
# Company-mode jobs are unaffected
# ---------------------------------------------------------------------------


def test_company_mode_unaffected(db_session, monkeypatch):
    """Company-mode jobs (no address) go through _process_company, not cache."""
    from db.queue import create_job
    from workers.discovery import DiscoveryWorker

    job = create_job(db_session, {"company": "TestProtocol"})
    job.company = "TestProtocol"
    db_session.commit()

    company_called = []
    monkeypatch.setattr(
        DiscoveryWorker,
        "_process_company",
        lambda self, session, job: company_called.append(True),
    )

    worker = DiscoveryWorker()
    worker.process(db_session, job)

    assert company_called == [True]


# ---------------------------------------------------------------------------
# _merge_inventory unit tests
# ---------------------------------------------------------------------------


def test_merge_inventory_new_and_previous():
    """Previous has A, B. New has B, C. Merged has all three with correct handling."""
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

    # A: only in prev, decayed 0.9 * 0.8 = 0.72
    assert ADDR_A.lower() in contracts_by_addr
    assert abs(contracts_by_addr[ADDR_A.lower()]["confidence"] - 0.72) < 0.001

    # B: in both, new entry used but higher confidence kept (0.7 > 0.6)
    assert ADDR_B.lower() in contracts_by_addr
    assert contracts_by_addr[ADDR_B.lower()]["confidence"] == 0.7
    assert contracts_by_addr[ADDR_B.lower()]["name"] == "ContractB_v2"  # new entry

    # C: only in new, as-is
    assert ADDR_C.lower() in contracts_by_addr
    assert contracts_by_addr[ADDR_C.lower()]["confidence"] == 0.85

    # Sorted by confidence descending
    confs = [c["confidence"] for c in merged["contracts"]]
    assert confs == sorted(confs, reverse=True)

    # official_domain: prefer new
    assert merged["official_domain"] == "new.example.com"

    # pages_considered: union by URL
    urls = {p["url"] for p in merged["pages_considered"]}
    assert urls == {"https://old.example.com/page1", "https://new.example.com/page2"}

    # sources: merged
    assert merged["sources"] == {"etherscan": True, "tavily": True}


def test_merge_inventory_confidence_decay_removes_stale():
    """After enough misses, a contract drops below the floor and is removed."""
    from services.discovery.inventory import merge_inventory as _merge_inventory

    # Start with confidence 0.5, decay 5 times
    confidence = 0.5
    prev = {
        "contracts": [{"address": ADDR_A, "name": "Stale", "confidence": confidence}],
    }
    for _ in range(10):
        new = {"contracts": []}  # never rediscovered
        prev = _merge_inventory(prev, new)

    # After enough decays it should be empty
    assert len(prev["contracts"]) == 0


def test_merge_inventory_confidence_decay_gradual():
    """Each missed run decays confidence by the decay factor."""
    from services.discovery.inventory import CONFIDENCE_DECAY as _CONFIDENCE_DECAY
    from services.discovery.inventory import merge_inventory as _merge_inventory

    prev = {
        "contracts": [{"address": ADDR_A, "name": "A", "confidence": 1.0}],
    }
    # One miss
    merged = _merge_inventory(prev, {"contracts": []})
    a = [c for c in merged["contracts"] if c["address"].lower() == ADDR_A.lower()][0]
    assert abs(a["confidence"] - _CONFIDENCE_DECAY) < 0.001

    # Second miss
    merged2 = _merge_inventory(merged, {"contracts": []})
    a2 = [c for c in merged2["contracts"] if c["address"].lower() == ADDR_A.lower()][0]
    assert abs(a2["confidence"] - _CONFIDENCE_DECAY**2) < 0.001


def test_merge_inventory_rediscovered_keeps_higher_confidence():
    """Contract in both inventories keeps the higher confidence."""
    from services.discovery.inventory import merge_inventory as _merge_inventory

    prev = {
        "contracts": [{"address": ADDR_A, "name": "A", "confidence": 0.95}],
    }
    # New search finds it with lower confidence
    new = {
        "contracts": [{"address": ADDR_A, "name": "A_new", "confidence": 0.6}],
    }
    merged = _merge_inventory(prev, new)
    a = merged["contracts"][0]
    assert a["confidence"] == 0.95  # kept prev (higher)
    assert a["name"] == "A_new"  # but uses new entry data

    # Reverse: new has higher confidence
    prev2 = {
        "contracts": [{"address": ADDR_A, "name": "A", "confidence": 0.4}],
    }
    new2 = {
        "contracts": [{"address": ADDR_A, "name": "A_new", "confidence": 0.9}],
    }
    merged2 = _merge_inventory(prev2, new2)
    assert merged2["contracts"][0]["confidence"] == 0.9


# ---------------------------------------------------------------------------
# Company-mode integration tests (inventory caching + child job dedup)
# ---------------------------------------------------------------------------


def _make_company_job(session, company="TestProtocol", **extra):
    """Create a company-mode job."""
    from db.queue import create_job

    req = {"company": company, "analyze_limit": 10}
    req.update(extra)
    job = create_job(session, req)
    job.company = company
    session.commit()
    return job


def _mock_inventory(contracts, **extra):
    """Build a fake inventory dict."""
    inv = {"contracts": contracts, "official_domain": "example.com"}
    inv.update(extra)
    return inv


def test_first_run_no_previous_inventory(db_session, monkeypatch):
    """First run with no prior company job stores inventory normally."""
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
    """Re-run merges previous inventory (decays old, keeps rediscovered)."""
    from db.models import JobStage, JobStatus
    from db.queue import create_job, get_artifact, store_artifact
    from workers.base import JobHandledDirectly
    from workers.discovery import DiscoveryWorker

    # Create a completed previous company job with inventory
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

    # New search only finds B and C
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

    # A: decayed from 0.9 → 0.72
    assert ADDR_A.lower() in contracts_by_addr
    assert abs(contracts_by_addr[ADDR_A.lower()]["confidence"] - 0.72) < 0.001

    # B: in both, higher confidence kept (0.7)
    assert ADDR_B.lower() in contracts_by_addr
    assert contracts_by_addr[ADDR_B.lower()]["confidence"] == 0.7

    # C: new
    assert ADDR_C.lower() in contracts_by_addr
    assert contracts_by_addr[ADDR_C.lower()]["confidence"] == 0.85


# ---------------------------------------------------------------------------
# Child-job dedup and confidence-threshold filtering used to be tested here
# against DiscoveryWorker._process_company. That logic now lives in the
# SelectionWorker, where it runs once over the unified contract set; see
# tests/test_selection_worker.py for the equivalent coverage.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# is_known_proxy unit tests
# ---------------------------------------------------------------------------


def test_is_known_proxy_true(db_session):
    """Contract with is_proxy=True returns True."""
    from db.models import Contract
    from db.queue import create_job, is_known_proxy

    job = create_job(db_session, {"address": ADDR_A})
    db_session.add(
        Contract(
            job_id=job.id,
            address=ADDR_A,
            contract_name="Proxy",
            compiler_version="v0.8.24",
            language="solidity",
            evm_version="shanghai",
            optimization=True,
            optimization_runs=200,
            source_format="flat",
            source_file_count=1,
            remappings=[],
            is_proxy=True,
            proxy_type="eip1967",
        )
    )
    db_session.commit()

    assert is_known_proxy(db_session, ADDR_A) is True


def test_is_known_proxy_false(db_session):
    """Contract with is_proxy=False returns False. No contract at all returns False."""
    from db.models import Contract
    from db.queue import create_job, is_known_proxy

    # No contract at all
    assert is_known_proxy(db_session, ADDR_A) is False

    # Contract with is_proxy=False
    job = create_job(db_session, {"address": ADDR_A})
    db_session.add(
        Contract(
            job_id=job.id,
            address=ADDR_A,
            contract_name="Regular",
            compiler_version="v0.8.24",
            language="solidity",
            evm_version="shanghai",
            optimization=True,
            optimization_runs=200,
            source_format="flat",
            source_file_count=1,
            remappings=[],
            is_proxy=False,
        )
    )
    db_session.commit()

    assert is_known_proxy(db_session, ADDR_A) is False


def test_is_known_proxy_case_insensitive(db_session):
    """Checksummed vs lowercase match."""
    from db.models import Contract
    from db.queue import create_job, is_known_proxy

    job = create_job(db_session, {"address": ADDR_A})
    db_session.add(
        Contract(
            job_id=job.id,
            address=ADDR_A,
            contract_name="Proxy",
            compiler_version="v0.8.24",
            language="solidity",
            evm_version="shanghai",
            optimization=True,
            optimization_runs=200,
            source_format="flat",
            source_file_count=1,
            remappings=[],
            is_proxy=True,
            proxy_type="eip1967",
        )
    )
    db_session.commit()

    # Query with lowercase version of checksummed address
    assert is_known_proxy(db_session, ADDR_A.lower()) is True
    # Query with uppercase
    assert is_known_proxy(db_session, ADDR_A.upper()) is True


# ---------------------------------------------------------------------------
# Company-mode proxy dedup used to live here against DiscoveryWorker.
# The logic now runs in SelectionWorker — see
# tests/test_selection_worker.py::test_existing_non_proxy_job_skips_address
# and ::test_proxy_with_existing_job_is_re_queued for the replacement
# coverage.
# ---------------------------------------------------------------------------
