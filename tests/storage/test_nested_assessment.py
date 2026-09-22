"""Recursive Assessment publication preserves omitted prior sections."""

from __future__ import annotations

from db.assessment import load_assessment
from db.nested_artifacts import store_bundle
from db.queue import create_job
from tests.conftest import requires_postgres


@requires_postgres
def test_staged_recursive_bundle_update_preserves_omitted_sections(db_session) -> None:
    job = create_job(db_session, {"address": "0x" + "a" * 40, "chain": "ethereum"})
    child = "0x" + "b" * 40
    other = "0x" + "c" * 40
    analysis = {"subject": {"address": child}}
    plan = {"contract_address": child, "tracked_controllers": []}
    snapshot = {"controller_values": {"owner": {"value": "0x" + "d" * 40}}}
    permissions = {"functions": [{"function": "old()"}]}

    store_bundle(
        db_session,
        job.id,
        {
            child: {
                "analysis": analysis,
                "tracking_plan": plan,
                "snapshot": snapshot,
                "effective_permissions": permissions,
            },
            other: {
                "analysis": {"subject": {"address": other}},
                "tracking_plan": {"contract_address": other},
                "snapshot": {"controller_values": {}},
            },
        },
    )

    replacement_permissions = {"functions": [{"function": "new()"}]}
    store_bundle(db_session, job.id, {child.upper(): {"effective_permissions": replacement_permissions}})

    assessment = load_assessment(db_session, job.id)
    assert assessment is not None
    recursive = assessment.get("recursive")
    assert recursive is not None
    updated = recursive[child]
    assert updated.get("contract_analysis") == analysis
    assert updated.get("control_tracking_plan") == plan
    assert updated.get("control_snapshot") == snapshot
    assert updated.get("effective_permissions") == replacement_permissions
    assert recursive[other].get("control_snapshot") == {"controller_values": {}}
