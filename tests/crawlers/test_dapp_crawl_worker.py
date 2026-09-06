"""Tests for DAppCrawlWorker — process() code paths.

Child-job creation and ``analyze_limit`` enforcement moved to the
``SelectionWorker``; end-to-end child queueing is covered there and in
``test_dapp_crawl_worker_integration``. This file keeps the
worker-local responsibilities: request validation, crawler parameter
plumbing, protocol derivation, artifact storage, and interaction
persistence.
"""

from __future__ import annotations

import importlib
import sys
import uuid
from types import ModuleType, SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

from tests.attempt_helpers import claimed_call
from workers.base import JobHandledDirectly

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ADDR_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ADDR_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


@pytest.fixture
def dapp_worker_module(monkeypatch: pytest.MonkeyPatch):
    """Import the worker with a scoped Playwright stub.

    The crawler stack imports Playwright at module import time.  Load the worker
    under a temporary stub so the test stays isolated and does not leave fake
    modules behind for the rest of the suite.
    """
    pw = ModuleType("playwright")
    pw_async = ModuleType("playwright.async_api")
    pw_async.async_playwright = MagicMock()  # pyright: ignore[reportAttributeAccessIssue]
    pw_async.BrowserContext = MagicMock()  # pyright: ignore[reportAttributeAccessIssue]
    pw_async.Page = MagicMock()  # pyright: ignore[reportAttributeAccessIssue]
    monkeypatch.setitem(sys.modules, "playwright", pw)
    monkeypatch.setitem(sys.modules, "playwright.async_api", pw_async)

    for module_name in (
        "workers.dapp_crawl_worker",
        "services.crawlers.dapp.crawl",
        "services.crawlers.dapp.browser",
    ):
        sys.modules.pop(module_name, None)

    module = importlib.import_module("workers.dapp_crawl_worker")
    yield module

    for module_name in (
        "workers.dapp_crawl_worker",
        "services.crawlers.dapp.crawl",
        "services.crawlers.dapp.browser",
    ):
        sys.modules.pop(module_name, None)


def _job(**overrides: Any) -> SimpleNamespace:
    """Create a minimal fake job with sensible defaults."""
    payload: dict[str, Any] = {
        "id": uuid.uuid4(),
        "name": None,
        "company": None,
        "protocol_id": None,
        "request": {
            "dapp_urls": ["https://example.com"],
        },
    }
    payload.update(overrides)
    return SimpleNamespace(**payload)


def _patch_worker_deps(
    monkeypatch: pytest.MonkeyPatch,
    worker_module: Any,
    *,
    crawl_result=None,
):
    """Patch all external deps of DAppCrawlWorker.process().

    Returns a dict of spy lists so tests can inspect calls.
    """
    if crawl_result is None:
        crawl_result = {"addresses": [], "interaction_count": 0}

    store_calls: list[tuple[str, Any]] = []
    complete_calls: list[tuple] = []
    protocol_calls: list[tuple[str, str | None]] = []

    monkeypatch.setattr(worker_module, "crawl_dapp", lambda urls, chain_id=1, wait=10, progress=None: crawl_result)

    def fake_get_or_create_protocol(session, name, official_domain=None, canonical_slug=None, aliases=None):
        protocol_calls.append((name, official_domain))
        return SimpleNamespace(id=1, name=name, official_domain=official_domain, canonical_slug=canonical_slug)

    monkeypatch.setattr(worker_module, "get_or_create_protocol", fake_get_or_create_protocol)
    # Worker now resolves the hostname to a canonical DefiLlama slug before
    # upserting the Protocol row; stub the network call away.
    monkeypatch.setattr(
        worker_module,
        "resolve_protocol",
        lambda name: {"slug": None, "url": None, "name": None, "chains": [], "all_slugs": [], "all_names": []},
    )
    monkeypatch.setattr(
        worker_module.DAppCrawlWorker,
        "update_detail",
        lambda self, session, job, detail: None,
    )

    def fake_store_artifact(session, job_id, name, data=None, text_data=None):
        store_calls.append((name, data))

    monkeypatch.setattr(worker_module, "store_artifact", fake_store_artifact)

    def fake_complete_job(session, job_id, detail="", **_routing):
        complete_calls.append((job_id, detail))

    monkeypatch.setattr(worker_module, "complete_job", fake_complete_job)

    return {
        "store_calls": store_calls,
        "complete_calls": complete_calls,
        "protocol_calls": protocol_calls,
    }


def _session_no_existing_contracts() -> MagicMock:
    """A MagicMock session whose Contract lookups always return None."""
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    return session


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMissingDappUrls:
    """process() raises ValueError when dapp_urls is absent or empty."""

    def test_missing_key(self, dapp_worker_module):
        worker = dapp_worker_module.DAppCrawlWorker()
        session = MagicMock()
        job = _job(request={})

        with pytest.raises(ValueError, match="missing dapp_urls"):
            claimed_call(worker.process, session, cast(Any, job))

    def test_empty_list(self, dapp_worker_module):
        worker = dapp_worker_module.DAppCrawlWorker()
        session = MagicMock()
        job = _job(request={"dapp_urls": []})

        with pytest.raises(ValueError, match="missing dapp_urls"):
            claimed_call(worker.process, session, cast(Any, job))

    def test_request_is_none(self, dapp_worker_module):
        worker = dapp_worker_module.DAppCrawlWorker()
        session = MagicMock()
        job = _job(request=None)

        with pytest.raises(ValueError, match="missing dapp_urls"):
            claimed_call(worker.process, session, cast(Any, job))


class TestHappyPath:
    """Crawl finds addresses, stores artifacts, completes. No child jobs here."""

    def test_stores_artifacts_and_completes(self, monkeypatch, dapp_worker_module):
        crawl_result = {
            "addresses": [ADDR_A, ADDR_B],
            "interaction_count": 5,
        }
        spies = _patch_worker_deps(monkeypatch, dapp_worker_module, crawl_result=crawl_result)
        session = _session_no_existing_contracts()
        job = _job()

        worker = dapp_worker_module.DAppCrawlWorker()
        with pytest.raises(JobHandledDirectly):
            claimed_call(worker.process, session, cast(Any, job))

        stored_names = [name for name, _ in spies["store_calls"]]
        assert "dapp_crawl_results" in stored_names
        assert "discovery_summary" in stored_names

        crawl_artifact = next(d for n, d in spies["store_calls"] if n == "dapp_crawl_results")
        assert crawl_artifact["addresses_found"] == 2
        assert crawl_artifact["interaction_count"] == 5

        summary = next(d for n, d in spies["store_calls"] if n == "discovery_summary")
        assert summary["discovered_count"] == 2
        assert "analyzed_count" not in summary
        assert "child_jobs" not in summary

        assert len(spies["complete_calls"]) == 1


class TestJobName:
    """Job name is set when missing, but not overwritten when already present."""

    def test_name_set_when_missing(self, monkeypatch, dapp_worker_module):
        crawl_result = {"addresses": [], "interaction_count": 0}
        _patch_worker_deps(monkeypatch, dapp_worker_module, crawl_result=crawl_result)
        session = _session_no_existing_contracts()
        job = _job(name=None, request={"dapp_urls": ["https://a.com", "https://b.com"]})

        worker = dapp_worker_module.DAppCrawlWorker()
        with pytest.raises(JobHandledDirectly):
            claimed_call(worker.process, session, cast(Any, job))

        assert job.name == "DApp crawl (2 URLs)"
        session.commit.assert_called()

    def test_name_not_overwritten(self, monkeypatch, dapp_worker_module):
        crawl_result = {"addresses": [], "interaction_count": 0}
        _patch_worker_deps(monkeypatch, dapp_worker_module, crawl_result=crawl_result)
        session = _session_no_existing_contracts()
        job = _job(name="My Custom Name")

        worker = dapp_worker_module.DAppCrawlWorker()
        with pytest.raises(JobHandledDirectly):
            claimed_call(worker.process, session, cast(Any, job))

        assert job.name == "My Custom Name"


class TestCrawlParameters:
    """chain_id and wait are read from request and passed to crawl_dapp."""

    def test_custom_chain_id_and_wait(self, monkeypatch, dapp_worker_module):
        captured: dict[str, Any] = {}

        def fake_crawl(urls, chain_id=1, wait=10, progress=None):
            captured["chain_id"] = chain_id
            captured["wait"] = wait
            return {"addresses": [], "interaction_count": 0}

        _patch_worker_deps(monkeypatch, dapp_worker_module)
        # Re-patch crawl_dapp since _patch_worker_deps installed its own stub
        monkeypatch.setattr(dapp_worker_module, "crawl_dapp", fake_crawl)

        session = _session_no_existing_contracts()
        job = _job(request={"dapp_urls": ["https://x.com"], "chain_id": 137, "wait": 20})

        worker = dapp_worker_module.DAppCrawlWorker()
        with pytest.raises(JobHandledDirectly):
            claimed_call(worker.process, session, cast(Any, job))

        assert captured["chain_id"] == 137
        assert captured["wait"] == 20

    def test_missing_wait_uses_default(self, monkeypatch, dapp_worker_module):
        captured: dict[str, Any] = {}

        def fake_crawl(urls, chain_id=1, wait=10, progress=None):
            captured["wait"] = wait
            return {"addresses": [], "interaction_count": 0}

        _patch_worker_deps(monkeypatch, dapp_worker_module)
        monkeypatch.setattr(dapp_worker_module, "crawl_dapp", fake_crawl)

        session = _session_no_existing_contracts()
        job = _job(request={"dapp_urls": ["https://x.com"]})

        worker = dapp_worker_module.DAppCrawlWorker()
        with pytest.raises(JobHandledDirectly):
            claimed_call(worker.process, session, cast(Any, job))

        assert captured["wait"] == 10


class TestProtocolCreation:
    """Protocol row is created / looked up from URL hostname when company is absent."""

    def test_hostname_derived_when_no_company(self, monkeypatch, dapp_worker_module):
        crawl_result = {"addresses": [], "interaction_count": 0}
        spies = _patch_worker_deps(monkeypatch, dapp_worker_module, crawl_result=crawl_result)
        session = _session_no_existing_contracts()
        job = _job(request={"dapp_urls": ["https://ether.fi/stake"]})

        worker = dapp_worker_module.DAppCrawlWorker()
        with pytest.raises(JobHandledDirectly):
            claimed_call(worker.process, session, cast(Any, job))

        assert spies["protocol_calls"] == [("ether.fi", "ether.fi")]
        assert job.protocol_id == 1
        assert job.company == "ether.fi"

    def test_www_stripped_from_hostname(self, monkeypatch, dapp_worker_module):
        crawl_result = {"addresses": [], "interaction_count": 0}
        spies = _patch_worker_deps(monkeypatch, dapp_worker_module, crawl_result=crawl_result)
        session = _session_no_existing_contracts()
        job = _job(request={"dapp_urls": ["https://www.uniswap.org"]})

        worker = dapp_worker_module.DAppCrawlWorker()
        with pytest.raises(JobHandledDirectly):
            claimed_call(worker.process, session, cast(Any, job))

        assert spies["protocol_calls"] == [("uniswap.org", "uniswap.org")]

    def test_company_prefers_over_hostname(self, monkeypatch, dapp_worker_module):
        crawl_result = {"addresses": [], "interaction_count": 0}
        spies = _patch_worker_deps(monkeypatch, dapp_worker_module, crawl_result=crawl_result)
        session = _session_no_existing_contracts()
        job = _job(company="Ether.fi", request={"dapp_urls": ["https://stake.ether.fi"]})

        worker = dapp_worker_module.DAppCrawlWorker()
        with pytest.raises(JobHandledDirectly):
            claimed_call(worker.process, session, cast(Any, job))

        assert spies["protocol_calls"] == [("Ether.fi", "stake.ether.fi")]
        assert job.company == "Ether.fi"


class TestInteractionPersistence:
    def test_interactions_written_to_session(self, monkeypatch, dapp_worker_module):
        crawl_result = {
            "addresses": [ADDR_A],
            "interaction_count": 2,
            "interactions": [
                {
                    "type": "sendTransaction",
                    "url": "https://ether.fi/stake",
                    "timestamp": 1700000000000,
                    "to": ADDR_A.upper(),
                    "value": "0x0",
                    "data": "0xabcdef01",
                    "method_selector": "0xabcdef01",
                    "is_permit": False,
                },
                {
                    "type": "personal_sign",
                    "url": "https://ether.fi/",
                    "timestamp": 1700000001000,
                    "to": None,
                    "message": "sign in",
                    "is_permit": False,
                },
            ],
        }
        _patch_worker_deps(monkeypatch, dapp_worker_module, crawl_result=crawl_result)
        session = _session_no_existing_contracts()
        job = _job()

        worker = dapp_worker_module.DAppCrawlWorker()
        with pytest.raises(JobHandledDirectly):
            claimed_call(worker.process, session, cast(Any, job))

        added = [call.args[0] for call in session.add.call_args_list]
        interactions = [row for row in added if type(row).__name__ == "DAppInteraction"]
        assert len(interactions) == 2
        types = {row.type for row in interactions}
        assert types == {"sendTransaction", "personal_sign"}
        send_row = next(row for row in interactions if row.type == "sendTransaction")
        assert send_row.to_address == ADDR_A.lower()
        assert send_row.method_selector == "0xabcdef01"
