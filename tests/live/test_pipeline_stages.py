"""Single-contract pipeline output: WETH reaches ``done`` with one Assessment."""

from __future__ import annotations

from tests.live.conftest import LiveClient


def test_pipeline_reaches_done_stage(analyzed_weth):
    assert analyzed_weth["status"] == "completed"
    assert analyzed_weth["stage"] == "done"


def test_assessment_artifact(analyzed_weth, live_client: LiveClient):
    art = live_client.artifact(analyzed_weth["name"], "assessment")
    assert isinstance(art, dict)
    assert "schema_version" not in art
    for table in (
        "subjects",
        "evidence",
        "claims",
        "analyses",
        "corrections",
        "contexts",
        "implementations",
        "payloads",
    ):
        assert isinstance(art.get(table), list), f"Assessment table {table!r} missing"
    subject_ids = {row["id"] for row in art["subjects"]}
    assert art["view"]["subject"] in subject_ids
    assert art["claims"], "completed WETH analysis should publish canonical claims"
    assert art["evidence"], "completed WETH analysis should publish canonical evidence"


def test_contract_flags_artifact(analyzed_weth, live_client: LiveClient):
    art = live_client.artifact(analyzed_weth["name"], "contract_flags")
    assert isinstance(art, dict)
    assert "is_proxy" in art, "contract_flags.is_proxy missing"


def test_dependencies_artifact(analyzed_weth, live_client: LiveClient):
    art = live_client.artifact(analyzed_weth["name"], "dependencies")
    assert isinstance(art, dict)
    assert "dependencies" in art


def test_retired_analysis_artifacts_are_not_emitted(analyzed_weth, live_client: LiveClient):
    for name in (
        "static_facts",
        "observation_plan",
        "observation_batch",
        "resolution_graph",
        "permission_index",
        "principal_labels",
    ):
        assert live_client.artifact(analyzed_weth["name"], name) is None
