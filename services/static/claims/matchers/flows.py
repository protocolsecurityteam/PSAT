"""``flow.out`` / ``flow.in`` — value leaves or enters the contract.

Thin claims over the hardened value-flow facts: ERC-20 callee selectors with the
``from == address(this)`` direction correction, native ``transfer``/``send``
sinks, and low-level ``call{value:}``. A callee selector proves the mechanism
exactly (``standard_exact``); a native/low-level move is structural
(``idiom_structural``). Guard-origin flows are excluded by the fact layer.
"""

from __future__ import annotations

from typing import Any

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from . import _facts


def _flow_evidence(ctx: ClaimContext, function: str, direction: str) -> ClaimEvidence | None:
    flows = [f for f in _facts.value_flows(ctx, function) if f.get("direction") == direction]
    if not flows:
        return None

    selectors = {f.get("selector") for f in flows if f.get("selector")}
    sink_ids = [
        s["id"]
        for s in _facts.body_sinks(ctx, function)
        if s.get("kind") == "external_call" and (s.get("selector") in selectors or _is_value_call(s))
    ]
    exact = any(f.get("kind") == "callee_erc20_selector" for f in flows)
    return ClaimEvidence(
        tier="standard_exact" if exact else "idiom_structural",
        witness={
            "kind": "value_flow",
            "direction": direction,
            "flows": [_flow_entry(f) for f in flows],
            "sink_ids": sorted(set(sink_ids)),
        },
    )


def _flow_entry(f: dict[str, Any]) -> dict[str, Any]:
    """Project a value-flow fact into the witness. ``target_kind`` (where funds
    go) and ``amount_kind`` (how much can leave) — each ``{kind, tier}`` — carry
    the theft-vs-routing discriminators when the fact layer classified them;
    omitted when absent so a consumer never reads a guessed value.

    ``target_kinds``/``amount_kinds`` accompany them only where the contributing
    IR sites disagreed and the fold therefore reads ``indeterminate``: the list
    names each site's own classification so a reader sees "two destinations, both
    resolved" instead of just "unknown". The scalar keeps its exact meaning — a
    consumer reading only it is unaffected."""
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
    """A function that itself neither holds nor sends value but CALLS an in-unit
    contract whose body moves it (a Teller forwarding into a BoringVault). The
    fact layer tags such moves ``direction: "value_router"`` and carries the
    destination/amount witness resolved back through the call to the entry's own
    parameters — so a caller-chosen router destination is provable when it is one."""
    return _flow_evidence(ctx, function, "value_router")
