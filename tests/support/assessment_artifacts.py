"""Test helpers for the Assessment-only analytical artifact boundary."""

from __future__ import annotations

from typing import Any

from db.queue import store_artifact
from tests.support.policy_builders import _assessment, _minimal_static_facts


def store_test_assessment(
    session: Any,
    job_id: Any,
    *,
    address: str,
    name: str = "T",
    chain_id: int = 1,
    static_facts: dict | None = None,
    predicate_trees: dict | None = None,
    effects: dict | None = None,
) -> None:
    store_artifact(
        session,
        job_id,
        "assessment",
        data=_assessment(
            static_facts=static_facts or _minimal_static_facts(address=address, name=name),
            predicate_trees=predicate_trees,
            effects=effects,
            chain_id=chain_id,
        ),
    )


__all__ = ["store_test_assessment"]


def store_test_observations(
    session: Any, job_id: Any, controllers: dict, *, deployment_address: str | None = None
) -> None:
    """Add controller observations to an existing canonical fixture document."""
    from db.queue import get_artifact
    from db.queue.typed import load_assessment
    from services.assessment import control_graph, static_inputs
    from tests.support.policy_builders import _minimal_snapshot

    current = load_assessment(get_artifact, session, job_id)
    if current is None:
        return
    facts, trees, effects = static_inputs(current)
    values = {key: {"value": value} if isinstance(value, str) else value for key, value in controllers.items()}
    assessment = _assessment(
        static_facts=facts,
        predicate_trees=trees,
        effects=effects,
        snapshot=_minimal_snapshot(values),
        graph=control_graph(current),
        chain_id=current["contract"]["chain_id"],
    )
    assessment["contract"]["deployment_address"] = deployment_address or current["contract"]["deployment_address"]
    store_artifact(session, job_id, "assessment", data=assessment)
