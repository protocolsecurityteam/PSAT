"""Caching: re-running an address/company should reuse cached static data."""

from __future__ import annotations

from typing import Any

import pytest

from tests.live.conftest import LiveClient

COMPANY_NAME = "etherfi"
COMPANY_LIMIT = 2


def test_first_run_completes(analyzed_weth):
    assert analyzed_weth["status"] == "completed"


def test_first_run_has_artifacts(analyzed_weth, live_client: LiveClient):
    analysis = live_client.artifact(analyzed_weth["name"], "assessment")
    assert isinstance(analysis, dict)
    assert analysis.get("schema_version") == "assessment/1"


def test_second_run_uses_cache(analyzed_weth, cached_weth, live_client: LiveClient):
    req2 = cached_weth.get("request") or {}
    assert req2.get("static_cached") is True, f"second WETH run did not hit cache: request={req2}"
    # Don't pin cache_source_job_id: a warm preview DB may reuse an earlier session's WETH job.
    source_id = req2.get("cache_source_job_id")
    assert source_id, f"static_cached=True but no cache_source_job_id on request={req2}"
    source = live_client.job(source_id)
    assert source["status"] == "completed", (
        f"cache source job {source_id} has status={source['status']!r}, expected completed"
    )
    assert (source.get("address") or "").lower() == (analyzed_weth.get("address") or "").lower(), (
        f"cache source {source_id} is for a different address ({source.get('address')}) "
        f"than the second run ({analyzed_weth.get('address')})"
    )

    a1 = live_client.artifact(analyzed_weth["name"], "assessment")
    a2 = live_client.artifact(cached_weth["name"], "assessment")
    assert isinstance(a1, dict) and isinstance(a2, dict)
    assert a1["contract"]["name"] == a2["contract"]["name"]


def test_second_run_completed_faster(analyzed_weth, cached_weth, live_client: LiveClient):
    t1 = live_client.job_duration_seconds(analyzed_weth)
    t2 = live_client.job_duration_seconds(cached_weth)
    # Below 30s fixed overhead dominates and the assertion flaps.
    if t1 > 30:
        assert t2 < t1, f"Second run ({t2:.1f}s) should be faster than first ({t1:.1f}s)"


@pytest.fixture(scope="module")
def company_first_run(live_client: LiveClient) -> dict[str, Any]:
    parent = live_client.submit_company_and_wait(COMPANY_NAME, limit=COMPANY_LIMIT)
    assert parent["status"] == "completed", f"Company run 1 failed: {parent.get('error')}"
    return parent


@pytest.fixture(scope="module")
def company_first_children(company_first_run, live_client: LiveClient) -> list[dict[str, Any]]:
    children = live_client.poll_children_until_done(company_first_run["job_id"])
    assert children, "Expected at least one child job"
    completed = [c for c in children if c["status"] == "completed"]
    assert completed, f"No completed children; statuses: {[c['status'] for c in children]}"
    return children


@pytest.fixture(scope="module")
def company_first_inventory(company_first_run, live_client: LiveClient) -> dict[str, Any] | None:
    art = live_client.artifact(company_first_run["name"], "contract_inventory")
    return art if isinstance(art, dict) else None


@pytest.fixture(scope="module")
def company_second_run(company_first_run, live_client: LiveClient) -> dict[str, Any]:
    parent = live_client.submit_company_and_wait(COMPANY_NAME, limit=COMPANY_LIMIT)
    assert parent["status"] == "completed", f"Company run 2 failed: {parent.get('error')}"
    return parent


def test_first_company_run_completes(company_first_run):
    assert company_first_run["status"] == "completed"


def test_first_company_run_has_children(company_first_children):
    assert any(c["status"] == "completed" for c in company_first_children)


def test_first_company_run_has_inventory(company_first_inventory, company_first_children):
    # contract_inventory is the dapp_crawl artifact; if Tavily can't pick a domain it's empty.
    # Discovery may still have succeeded via DefiLlama → fall back to children with addresses.
    inventory_contracts = (company_first_inventory or {}).get("contracts") or []
    child_addrs = [c for c in company_first_children if c.get("address")]
    assert inventory_contracts or child_addrs, (
        "Discovery produced no contracts via either contract_inventory (dapp_crawl) "
        "or analysis children (defillama/selection)"
    )


def test_second_company_run_deduplicates(
    company_first_children,
    company_second_run,
    live_client: LiveClient,
):
    # find_existing_job_for_address skips failed jobs so Run 2 can retry; only count completed.
    child_addrs1 = {
        c["address"].lower() for c in company_first_children if c.get("address") and c["status"] == "completed"
    }
    children2 = live_client.poll_children_until_done(company_second_run["job_id"])
    child_addrs2 = {c["address"].lower() for c in children2 if c.get("address")}

    # Proxies are re-queued every run for upgrade checks — only non-proxy dups are a cache miss.
    all_jobs = live_client.jobs()
    proxy_addrs = {(j.get("address") or "").lower() for j in all_jobs if j.get("is_proxy")}
    non_proxy_dup = (child_addrs1 & child_addrs2) - proxy_addrs
    if non_proxy_dup:
        lines = []
        for addr in sorted(non_proxy_dup):
            r1 = [c for c in company_first_children if (c.get("address") or "").lower() == addr]
            r2 = [c for c in children2 if (c.get("address") or "").lower() == addr]
            hits = [j for j in all_jobs if (j.get("address") or "").lower() == addr]
            is_proxy_flags = sorted({bool(j.get("is_proxy")) for j in hits})
            lines.append(
                f"  {addr}: r1_jobs={[c['job_id'] for c in r1]} "
                f"r2_jobs={[c['job_id'] for c in r2]} "
                f"all_is_proxy_flags={is_proxy_flags}"
            )
        raise AssertionError("Run 2 re-spawned jobs for already-analyzed non-proxy addresses:\n" + "\n".join(lines))


def test_second_company_run_inventory_merged(
    company_first_inventory,
    company_second_run,
    live_client: LiveClient,
):
    inventory2 = live_client.artifact(company_second_run["name"], "contract_inventory")
    if not isinstance(inventory2, dict):
        pytest.skip("Could not fetch inventory for run 2")
    contracts2 = inventory2.get("contracts", []) or []

    inventory1 = company_first_inventory if isinstance(company_first_inventory, dict) else None
    contracts1 = (inventory1 or {}).get("contracts") or []

    # Empty inventories on either side mean dapp_crawl/Tavily flaked; the cascade still
    # ran via DefiLlama. Skip the merge comparison rather than fail on a discovery flake.
    if not contracts1 or not contracts2:
        pytest.skip(
            f"contract_inventory empty on at least one run "
            f"(run1={len(contracts1)}, run2={len(contracts2)}); skipping merge comparison"
        )

    addrs1 = {c.get("address", "").lower() for c in contracts1 if c.get("address")}
    addrs2 = {c.get("address", "").lower() for c in contracts2 if c.get("address")}
    # Discovery (Tavily / DefiLlama / DApp crawl) isn't deterministic; assert overlap, not superset.
    overlap = len(addrs1 & addrs2)
    union = len(addrs1 | addrs2)
    jaccard = overlap / union if union else 1.0
    assert jaccard >= 0.85, (
        f"Run 1 and Run 2 inventories diverge too much: "
        f"run1={len(addrs1)}, run2={len(addrs2)}, overlap={overlap}, "
        f"union={union}, jaccard={jaccard:.2f} (required >= 0.85)"
    )
