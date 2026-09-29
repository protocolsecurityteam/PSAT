"""Tests for DAppCrawlWorker.process() code paths.

Child-job creation and ``analyze_limit`` moved to ``SelectionWorker`` (covered there and in
``test_dapp_crawl_worker_integration``); this file keeps worker-local concerns: validation, crawler params,
protocol derivation, artifact storage, interaction persistence.
"""

from __future__ import annotations

import importlib
import sys
import uuid
from types import ModuleType, SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

from workers.base import JobHandledDirectly

ADDR_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ADDR_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


@pytest.fixture
def dapp_worker_module(monkeypatch: pytest.MonkeyPatch):
    """Import the worker under a temporary Playwright stub (the crawler imports it at module load) so no fake
    modules leak into the rest of the suite."""
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

    def fake_complete_job(session, job_id, detail=""):
        complete_calls.append((job_id, detail))

    monkeypatch.setattr(worker_module, "complete_job", fake_complete_job)

    return {
        "store_calls": store_calls,
        "complete_calls": complete_calls,
        "protocol_calls": protocol_calls,
    }


def _session_no_existing_contracts() -> MagicMock:
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    return session


class TestMissingDappUrls:
    @pytest.mark.parametrize(
        "request_payload",
        [
            pytest.param({}, id="missing-key"),
            pytest.param({"dapp_urls": []}, id="empty-list"),
            pytest.param(None, id="request-is-none"),
        ],
    )
    def test_missing_dapp_urls_raises(self, dapp_worker_module, request_payload):
        worker = dapp_worker_module.DAppCrawlWorker()
        session = MagicMock()
        job = _job(request=request_payload)

        with pytest.raises(ValueError, match="missing dapp_urls"):
            worker.process(session, cast(Any, job))


class TestJobName:
    def test_name_not_overwritten(self, monkeypatch, dapp_worker_module):
        crawl_result = {"addresses": [], "interaction_count": 0}
        _patch_worker_deps(monkeypatch, dapp_worker_module, crawl_result=crawl_result)
        session = _session_no_existing_contracts()
        job = _job(name="My Custom Name")

        worker = dapp_worker_module.DAppCrawlWorker()
        with pytest.raises(JobHandledDirectly):
            worker.process(session, cast(Any, job))

        assert job.name == "My Custom Name"


class TestProtocolCreation:
    @pytest.mark.parametrize(
        "job_overrides, expected_call, expected_company",
        [
            pytest.param(
                {"request": {"dapp_urls": ["https://ether.fi/stake"]}},
                ("ether.fi", "ether.fi"),
                "ether.fi",
                id="hostname-derived-when-no-company",
            ),
            pytest.param(
                {"request": {"dapp_urls": ["https://www.uniswap.org"]}},
                ("uniswap.org", "uniswap.org"),
                "uniswap.org",
                id="www-stripped-from-hostname",
            ),
            pytest.param(
                {"company": "Ether.fi", "request": {"dapp_urls": ["https://stake.ether.fi"]}},
                ("Ether.fi", "stake.ether.fi"),
                "Ether.fi",
                id="company-preferred-over-hostname",
            ),
        ],
    )
    def test_protocol_name_derivation(
        self, monkeypatch, dapp_worker_module, job_overrides, expected_call, expected_company
    ):
        crawl_result = {"addresses": [], "interaction_count": 0}
        spies = _patch_worker_deps(monkeypatch, dapp_worker_module, crawl_result=crawl_result)
        session = _session_no_existing_contracts()
        job = _job(**job_overrides)

        worker = dapp_worker_module.DAppCrawlWorker()
        with pytest.raises(JobHandledDirectly):
            worker.process(session, cast(Any, job))

        assert spies["protocol_calls"] == [expected_call]
        assert job.protocol_id == 1
        assert job.company == expected_company
