"""Materialization predicates for inlined cross-contract results."""

from __future__ import annotations

import logging
from typing import Any

from ..capabilities import (
    CapabilityExpr,
)

logger = logging.getLogger(__name__)


def _public_without_root_cofinites(cap: CapabilityExpr) -> bool:
    """Would the resolved capability's projected writer surface be public with
    every root-subject ``cofinite_blacklist`` node counterfactually removed?

    A cofinite can only arise from a ``negate()`` exclusion arm (which needs
    falsy polarity — impossible on the guard's truthy path) or the
    deny-by-exception emission (which needs surviving caller taint plus a
    proven proceed-relation). Neither is a laundered un-gated allowlist, so a
    surface that is public ONLY because of a cofinite is legitimately public
    and must be spared; public via any other kind (a taint-lost opaque leaf
    folding to ``conditional_universal``) is the fail-open the guard closes."""
    from services.policy.capability_surface import project_capability_surface
    from services.resolution.capability_resolver import capability_to_dict

    def strip(node: dict[str, Any]) -> dict[str, Any]:
        if node.get("kind") == "cofinite_blacklist" and node.get("subject", "root") == "root":
            return {"kind": "unsupported", "unsupported_reason": "cofinite_counterfactual", "confidence": "check_only"}
        children = node.get("children")
        if isinstance(children, list):
            node = {**node, "children": [strip(c) if isinstance(c, dict) else c for c in children]}
        return node

    counterfactual = strip(capability_to_dict(cap))
    return project_capability_surface(counterfactual).authority_public


def _inline_result_needs_materialization(cap: CapabilityExpr) -> bool:
    if cap.kind == "finite_set":
        return not cap.members and cap.membership_quality != "exact"
    if cap.kind in {"external_check_only", "unsupported"}:
        return True
    if cap.kind == "conditional_universal":
        return _conditional_result_needs_materialization(cap)
    if cap.kind == "OR":
        return _or_result_needs_materialization(cap)
    return False


def _conditional_result_needs_materialization(cap: CapabilityExpr) -> bool:
    for condition in cap.conditions:
        description = condition.description or ""
        if description.startswith("return "):
            return True
    return False


def _or_result_needs_materialization(cap: CapabilityExpr) -> bool:
    saw_materializable = False
    for child in cap.children:
        if child.kind == "finite_set":
            if child.members:
                return False
            if child.membership_quality != "exact":
                saw_materializable = True
            continue
        if child.kind in {"external_check_only", "unsupported"}:
            saw_materializable = True
            continue
        if child.kind == "conditional_universal" and _conditional_result_needs_materialization(child):
            saw_materializable = True
            continue
        return False
    return saw_materializable


def _materialize_external_check_from_candidates(
    *,
    session: Any,
    outer_ctx: Any,
    chain_id: int,
    registry_addr: str,
    callee_selector: str | None,
    call_args: list[dict[str, Any]],
) -> CapabilityExpr | None:
    from services.resolution.external_check_materializer import materialize_external_check_from_events

    try:
        return materialize_external_check_from_events(
            session=session,
            rpc_url=getattr(outer_ctx, "rpc_url", None),
            chain_id=chain_id,
            checker_address=registry_addr,
            checker_selector=callee_selector,
            call_args=call_args,
            block=getattr(outer_ctx, "block", None),
        )
    except Exception:
        return None
