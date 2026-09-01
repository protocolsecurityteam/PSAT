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
