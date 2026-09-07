"""Analyses list + detail endpoints — shape checks for frontend-critical fields."""

from __future__ import annotations

from tests.live.conftest import WETH_ADDRESS, LiveClient


def test_analyses_list_includes_weth(analyzed_weth, live_client: LiveClient):
    entries = live_client.analyses()
    assert isinstance(entries, list)
    run_names = {e.get("run_name") for e in entries}
    assert analyzed_weth["name"] in run_names, (
        f"WETH run {analyzed_weth['name']} missing from /api/analyses (got {len(entries)} entries)"
    )


def test_analyses_list_entry_shape(analyzed_weth, live_client: LiveClient):
    entries = live_client.analyses()
    entry = next((e for e in entries if e.get("run_name") == analyzed_weth["name"]), None)
    assert entry is not None
    for key in ("run_name", "job_id", "address", "available_artifacts"):
        assert key in entry, f"analyses list entry missing '{key}'"
    assert isinstance(entry["available_artifacts"], list)


def test_analysis_detail_roundtrip(analyzed_weth, live_client: LiveClient):
    detail = live_client.analysis_detail(analyzed_weth["name"])
    assert detail["run_name"] == analyzed_weth["name"]
    assert detail["job_id"] == analyzed_weth["job_id"]
    assert (detail.get("address") or "").lower() == WETH_ADDRESS.lower()
    assert isinstance(detail.get("available_artifacts"), list)


def test_analysis_detail_inlines_assessment(analyzed_weth, live_client: LiveClient):
    detail = live_client.analysis_detail(analyzed_weth["name"])
    assert isinstance(detail.get("assessment"), dict)
    via_artifact = live_client.artifact(analyzed_weth["name"], "assessment")
    assert isinstance(via_artifact, dict)
    assert detail["assessment"]["contract"]["name"] == via_artifact["contract"]["name"]


def test_analysis_detail_contract_id_is_usable(analyzed_weth, live_client: LiveClient):
    detail = live_client.analysis_detail(analyzed_weth["name"])
    contract_id = detail.get("contract_id")
    assert isinstance(contract_id, int), (
        f"contract_id must be int so audit_timeline etc. can look it up, got {type(contract_id).__name__}"
    )
