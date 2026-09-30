"""``flow.out`` / ``flow.in``: value leaves or enters the contract.

ERC-20 callee selectors are standard_exact; native and low-level value moves are idiom_structural.
"""

from __future__ import annotations

from typing import Any

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from . import _facts


def _bare_sink_callee(sink: dict[str, Any]) -> str | None:
    target = sink.get("target")
    if not isinstance(target, str) or "." not in target:
        return None
    name = target.rsplit(".", 1)[-1].strip()
    return name or None


def _carries(sink: dict[str, Any], flows: list[dict[str, Any]]) -> bool:
    """Whether this body sink carries one of *flows*.

    Direct flows match on their own selector. A ``value_router`` flow's selector belongs to the callee's inner transfer,
    so its carrier is named by ``router_ops``; matching on the selector would let an unrelated same-selector sink lend
    it a receiver. No ``router_ops`` matches nothing.
    """
    selector = sink.get("selector")
    for flow in flows:
        if flow.get("direction") != "value_router":
            if (selector is not None and selector == flow.get("selector")) or _is_value_call(sink):
                return True
            continue
        for op in flow.get("router_ops") or []:
            if not isinstance(op, dict):
                continue
            op_selector = op.get("selector")
            if isinstance(op_selector, str) and op_selector and selector == op_selector:
                return True
            # The callee name travels with the selector because interface-typed params change the declared hash.
            op_name = op.get("callee")
            if isinstance(op_name, str) and op_name and _bare_sink_callee(sink) == op_name:
                return True
    return False


def _flow_evidence(ctx: ClaimContext, function: str, direction: str) -> ClaimEvidence | None:
    flows = [f for f in _facts.value_flows(ctx, function) if f.get("direction") == direction]
    if not flows:
        return None

    sinks = [s for s in _facts.body_sinks(ctx, function) if s.get("kind") == "external_call" and _carries(s, flows)]
    sink_ids = [s["id"] for s in sinks]
    # Keyed by sink id: one flow can span sinks with different receivers. Only sinks ``_carries`` accepted, so routed
    # claims can't adopt a direct sink's receiver. Missing map leaves the key absent.
    sink_receivers = {s["id"]: s["receiver"] for s in sinks if s.get("receiver")}
    exact = any(f.get("kind") == "callee_erc20_selector" for f in flows)
    witness: dict[str, Any] = {
        "kind": "value_flow",
        "direction": direction,
        "flows": [_flow_entry(ctx, function, f) for f in flows],
        "sink_ids": sorted(set(sink_ids)),
    }
    if sink_receivers:
        witness["sink_receivers"] = sink_receivers
    return ClaimEvidence(tier="standard_exact" if exact else "idiom_structural", witness=witness)


def _flow_entry(ctx: ClaimContext, function: str, f: dict[str, Any]) -> dict[str, Any]:
    """Project a value-flow fact into the witness: ``target_kind`` and ``amount_kind`` (each ``{kind, tier}``),
    omitted when unclassified.

    ``target_kinds``/``amount_kinds`` appear only where sites disagree: the scalar reads ``several`` when all sites
    resolved (the list is complete; take the worst) or ``indeterminate`` when some didn't (the list is partial).
    """
    entry: dict[str, Any] = {
        "kind": f.get("kind"),
        "selector": f.get("selector"),
        "from_is_self": f.get("from_is_self"),
    }
    if f.get("target_kind"):
        entry["target_kind"] = f["target_kind"]
        if f.get("target_kinds"):
            entry["target_kinds"] = f["target_kinds"]
    if f.get("amount_kind"):
        entry["amount_kind"] = f["amount_kind"]
        if f.get("amount_kinds"):
            entry["amount_kinds"] = f["amount_kinds"]
    if f.get("target_param_index") is not None:
        entry["target_param_index"] = f["target_param_index"]
    if f.get("amount_param_index") is not None:
        entry["amount_param_index"] = f["amount_param_index"]
    # A ``param`` destination means the caller names it; whether freely is the mandatory-gate question, and only
    # ``unconstrained_proven`` licenses the theft-shaped reading.
    if isinstance(f.get("target_kind"), dict) and f["target_kind"].get("kind") == "param":
        entry["target_constraint"] = _facts.param_constraint(ctx, function, f.get("target_param_index"))
    # Self-service witness, only where the amount is read from storage; absent elsewhere (fail-closed).
    if isinstance(f.get("amount_kind"), dict) and f["amount_kind"].get("kind") == "bounded_by_storage":
        entry["amount_record_constraint"] = _facts.amount_record_constraint(ctx, function, f)
        entry["self_service_payout"] = _facts.self_service_payout(ctx, function, f)
    # The same question for a ``param`` amount.
    if (
        f.get("amount_param_index") is not None
        and isinstance(f.get("amount_kind"), dict)
        and f["amount_kind"].get("kind") == "param"
    ):
        entry["amount_constraint"] = _facts.param_constraint(ctx, function, f.get("amount_param_index"))
    # The ops carrying a routed move, so the persisted witness matches ``_facts.effect_sink_identities``. ``callee`` is
    # an intra-unit name, not an on-chain target. Missing or empty leaves the key absent (fail-closed).
    if f.get("router_ops"):
        entry["router_ops"] = f["router_ops"]
    return entry


def _is_value_call(sink: dict[str, Any]) -> bool:
    return sink.get("selector") is None and str(sink.get("target") or "").endswith(".call")


@claim_matcher(
    claim_id="flow.out",
    sentence="sends value out of the contract",
    legacy_projection="asset_send",
    consumer_family="flow",
)
def flow_out(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    return _flow_evidence(ctx, function, "out")


@claim_matcher(
    claim_id="flow.in",
    sentence="pulls value into the contract",
    legacy_projection="asset_pull",
    consumer_family="flow",
)
def flow_in(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    return _flow_evidence(ctx, function, "in")


@claim_matcher(
    claim_id="value_router",
    sentence="routes value through a contract it calls",
    legacy_projection=None,
    consumer_family="flow",
)
def value_router(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    """A function that calls an in-unit contract whose body moves value (a Teller into a BoringVault); the
    destination and amount are resolved back to the entry's parameters.
    """
    return _flow_evidence(ctx, function, "value_router")
