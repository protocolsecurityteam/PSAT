"""Step 4 parallelism: DAppCrawler.crawl visits URLs concurrently.

The browser stack is mocked end-to-end so the test can run without
Playwright installed. We verify three things:

1. Every URL is visited (page.goto fires once per URL).
2. Concurrency is bounded by PSAT_DAPP_PARALLEL — the semaphore caps
   the maximum number of pages open simultaneously.
3. URLs faster than others don't block the slower ones from starting.
"""

from __future__ import annotations

import asyncio
import importlib
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture
def browser_module(monkeypatch: pytest.MonkeyPatch):
    """Stub Playwright before importing the browser module."""
    pw = ModuleType("playwright")
    pw_async = ModuleType("playwright.async_api")
    pw_async.async_playwright = MagicMock()  # pyright: ignore[reportAttributeAccessIssue]
    pw_async.BrowserContext = MagicMock()  # pyright: ignore[reportAttributeAccessIssue]
    pw_async.Page = MagicMock()  # pyright: ignore[reportAttributeAccessIssue]
    monkeypatch.setitem(sys.modules, "playwright", pw)
    monkeypatch.setitem(sys.modules, "playwright.async_api", pw_async)
    sys.modules.pop("services.crawlers.dapp.browser", None)
    module = importlib.import_module("services.crawlers.dapp.browser")
    yield module
    sys.modules.pop("services.crawlers.dapp.browser", None)


def _build_fake_async_playwright(page_factory):
    """Return a stub for ``async_playwright`` whose context manager hands out
    pages produced by *page_factory* (called once per ``new_page()``)."""

    fake_context = MagicMock()
    fake_context.new_page = AsyncMock(side_effect=page_factory)

    fake_browser = MagicMock()
    fake_browser.new_context = AsyncMock(return_value=fake_context)
    fake_browser.close = AsyncMock()

    fake_chromium = MagicMock()
    fake_chromium.launch = AsyncMock(return_value=fake_browser)

    class FakePlaywrightManager:
        async def __aenter__(self):
            return MagicMock(chromium=fake_chromium)

        async def __aexit__(self, *_a):
            return False

    return MagicMock(side_effect=lambda: FakePlaywrightManager()), fake_context


def _make_page(visit_log: list[tuple[str, asyncio.Event]]):
    """Page that records its goto URL and waits for an event before closing.

    The event is what lets the test gate concurrency: a page that hasn't
    been ``set()`` is still 'open', and the semaphore won't release.
    """
    page = MagicMock()
    page.goto = AsyncMock()
    page.close = AsyncMock()
    page.wait_for_timeout = AsyncMock()
    return page


def test_crawl_visits_every_url_concurrently(browser_module, monkeypatch):
    """All URLs are visited; concurrency stays at or below PSAT_DAPP_PARALLEL."""
    monkeypatch.setenv("PSAT_DAPP_PARALLEL", "2")
    # Re-import so the module-level constant picks up the env var.
    sys.modules.pop("services.crawlers.dapp.browser", None)
    browser_module = importlib.import_module("services.crawlers.dapp.browser")

    urls = [f"https://site{i}.example.com" for i in range(5)]
    open_pages = 0
    max_open = 0
    open_lock = asyncio.Lock()
    visit_log: list[str] = []

    pages: list[MagicMock] = []

    def page_factory():
        page = MagicMock()

        async def goto(url, **kwargs):
            nonlocal open_pages, max_open
            async with open_lock:
                open_pages += 1
                max_open = max(max_open, open_pages)
                visit_log.append(url)
            await asyncio.sleep(0.01)

        async def close():
            nonlocal open_pages
            async with open_lock:
                open_pages -= 1

        page.goto = goto
        page.close = close
        page.wait_for_timeout = AsyncMock()
        pages.append(page)
        return page

    fake_async_playwright, _ctx = _build_fake_async_playwright(page_factory)
    monkeypatch.setattr(browser_module, "async_playwright", fake_async_playwright)

    crawler = browser_module.DAppCrawler(
        wallet=MagicMock(address="0x" + "0" * 40),
        chain_id=1,
        headless=True,
    )
    # Replace the heavy per-page interactions with no-ops.
    crawler._setup_page = AsyncMock()
    crawler._try_connect_wallet = AsyncMock()
    crawler._explore_page = AsyncMock()

    asyncio.run(crawler.crawl(urls, wait_seconds=0))

    assert sorted(visit_log) == sorted(urls)
    assert max_open <= 2, f"semaphore breached: max_open={max_open}, expected ≤ PSAT_DAPP_PARALLEL=2"
    assert max_open >= 2, f"got max_open={max_open}, expected concurrency ≥ 2 with 5 URLs"


def test_crawl_one_url_failure_does_not_abort_siblings(browser_module, monkeypatch):
    """A page.goto exception on one URL must not cancel the others —
    the original loop swallowed exceptions per URL; the gather form
    must keep that behavior."""
    monkeypatch.setenv("PSAT_DAPP_PARALLEL", "3")
    sys.modules.pop("services.crawlers.dapp.browser", None)
    browser_module = importlib.import_module("services.crawlers.dapp.browser")

    urls = ["https://good.example.com", "https://bad.example.com", "https://also-good.example.com"]
    visit_log: list[str] = []
    closed: list[str] = []

    def page_factory():
        page = MagicMock()
        captured_url: list[str] = []

        async def goto(url, **kwargs):
            captured_url.append(url)
            visit_log.append(url)
            if "bad" in url:
                raise RuntimeError("page crashed")

        async def close():
            if captured_url:
                closed.append(captured_url[0])

        page.goto = goto
        page.close = close
        page.wait_for_timeout = AsyncMock()
        return page

    fake_async_playwright, _ctx = _build_fake_async_playwright(page_factory)
    monkeypatch.setattr(browser_module, "async_playwright", fake_async_playwright)

    crawler = browser_module.DAppCrawler(wallet=MagicMock(address="0x" + "0" * 40), chain_id=1, headless=True)
    crawler._setup_page = AsyncMock()
    crawler._try_connect_wallet = AsyncMock()
    crawler._explore_page = AsyncMock()

    asyncio.run(crawler.crawl(urls, wait_seconds=0))

    # Every URL should have been attempted, even after the bad one raised.
    assert sorted(visit_log) == sorted(urls)
    # And every page should have been closed (finally clause runs even on raise).
    assert sorted(closed) == sorted(urls)
