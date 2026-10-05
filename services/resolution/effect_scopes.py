"""Resolve site predicates with the same adapters and pinned context as their entry point."""

from __future__ import annotations

from typing import cast

from services.static.contract_analysis_pipeline.predicate_types import PredicateTree

from .capabilities import CapabilityExpr, Condition, union
from .predicate_evaluator import evaluate_tree_with_registry


def resolve_effect_scopes(sites, registry, ctx, base_cap=None, all_scopes=None):
    from services.policy.capability_surface import capability_surface_openness, project_capability_surface

    from .capability_resolver import capability_to_dict

    if all_scopes is not None:
        ctx.meta["effect_predicates"] = {
            site["id"]: site["predicate"] for group in all_scopes.values() for site in group
        }
    records = []
    body_caps = []
    for site in sites:
        cap = (
            evaluate_tree_with_registry(site["predicate"], registry, ctx)
            if "predicate" in site
            else CapabilityExpr.unsupported("missing_effect_predicate")
        )
        record = {k: site[k] for k in ("id", "kind", "target", "sink_ids", "origin")}
        record["capability"] = capability_to_dict(cap)
        records.append(record)
        if site.get("origin") == "body":
            body_caps.append(cap)
    if not body_caps:
        return None, records
    if base_cap is not None:
        from services.policy.effect_authority import authority_identity

        identity = authority_identity(capability_to_dict(base_cap))
        if all(authority_identity(capability_to_dict(c)) == identity for c in body_caps):
            return base_cap, records
    # Function openness is existential over effects; per-site records retain the independent restrictions.
    if any(
        capability_surface_openness(capability_to_dict(c), project_capability_surface(capability_to_dict(c))) == "open"
        for c in body_caps
    ):
        aggregate = CapabilityExpr.conditional_universal(Condition(kind="business", description="public effect path"))
    else:
        aggregate = body_caps[0]
        for cap in body_caps[1:]:
            aggregate = union(aggregate, cap)
    return aggregate, records


def resolve_state_authority(descriptor, ctx):
    from dataclasses import replace

    from services.static.contract_analysis_pipeline.structural_evidence import _unbind_writer_parameters

    from .adapters import CallFrame
    from .capabilities import ExternalCheck

    outer = getattr(ctx.adapter, "_outer_ctx", None)
    registry = getattr(ctx.adapter, "_registry", None)
    fallback = CapabilityExpr.external_check_only(
        ExternalCheck(
            target_address=ctx.contract_address,
            target_call_selector=None,
            extra={"basis": ["caller_tainted_authority_unresolved", "state_dependency_unresolved"]},
        )
    )
    if outer is None or registry is None:
        return fallback
    predicates = outer.meta.get("effect_predicates") or {}
    stack = outer.meta.setdefault("writer_scope_stack", set())
    memo = outer.meta.setdefault("writer_scope_capabilities", {})
    capabilities = []
    for scope_id in descriptor.get("writer_scope_ids") or []:
        if scope_id in stack or len(stack) >= 8 or scope_id not in predicates:
            outer.meta["writer_scope_refusals"] = outer.meta.get("writer_scope_refusals", 0) + 1
            return fallback
        if scope_id in memo:
            capabilities.append(memo[scope_id])
            continue
        stack.add(scope_id)
        refusals_before = outer.meta.get("writer_scope_refusals", 0)
        try:
            function = scope_id.split("/", 1)[0]
            child = replace(
                outer,
                call_frame=CallFrame.root(
                    contract_address=outer.contract_address, function_signature=function, function_selector=None
                ),
            )
            predicate = cast(PredicateTree, _unbind_writer_parameters(predicates[scope_id]))
            capability = evaluate_tree_with_registry(predicate, registry, child)
            # Memoizing a refusal reached through a cycle could make an unrelated anchored path order-dependent.
            if (
                capability.kind != "external_check_only"
                and outer.meta.get("writer_scope_refusals", 0) == refusals_before
            ):
                memo[scope_id] = capability
            capabilities.append(capability)
        finally:
            stack.remove(scope_id)
    if not capabilities:
        return fallback
    result = capabilities[0]
    for capability in capabilities[1:]:
        result = union(result, capability)
    return result
