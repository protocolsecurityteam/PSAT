"""Single-contract pipeline output: WETH reaches ``done`` and emits the expected per-stage artifacts."""

from __future__ import annotations

import pytest

from tests.live.conftest import LiveClient


def test_pipeline_reaches_done_stage(analyzed_weth):
    assert analyzed_weth["status"] == "completed"
    assert analyzed_weth["stage"] == "done"


def test_contract_analysis_artifact(analyzed_weth, live_client: LiveClient):
    art = live_client.artifact(analyzed_weth["job_id"], "contract_analysis")
    assert isinstance(art, dict)
    subject = art.get("subject")
    assert isinstance(subject, dict) and subject.get("name"), "contract_analysis.subject.name missing"
    assert "summary" in art, "contract_analysis.summary missing"


def test_contract_flags_artifact(analyzed_weth, live_client: LiveClient):
    art = live_client.artifact(analyzed_weth["job_id"], "contract_flags")
    assert isinstance(art, dict)
    assert "is_proxy" in art, "contract_flags.is_proxy missing"


def test_dependencies_artifact(analyzed_weth, live_client: LiveClient):
    art = live_client.artifact(analyzed_weth["job_id"], "dependencies")
    assert isinstance(art, dict)
    assert "dependencies" in art


def test_control_tracking_plan_artifact(analyzed_weth, live_client: LiveClient):
    # WETH has no guarded controls; plan can be empty but the artifact must still exist.
    art = live_client.artifact(analyzed_weth["job_id"], "control_tracking_plan")
    assert isinstance(art, dict), "control_tracking_plan artifact should exist"


@pytest.mark.parametrize(
    "artifact_name",
    ["control_snapshot", "effective_permissions", "principal_labels"],
)
def test_unconditionally_emitted_artifacts(analyzed_weth, live_client: LiveClient, artifact_name: str):
    # resolution_worker.py:97 + policy_worker.py:213/283 emit these unconditionally.
    art = live_client.artifact(analyzed_weth["job_id"], artifact_name)
    assert art is not None, f"{artifact_name} artifact was not emitted"
    assert isinstance(art, (dict, list)), f"{artifact_name} should be structured JSON"
