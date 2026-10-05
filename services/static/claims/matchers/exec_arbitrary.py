"""``exec.arbitrary``: forwards caller-supplied target and calldata.

Three paths: Safe exec entries and OZ timelock ``execute``/``executeBatch`` (standard_exact), and the ``manage`` idiom,
a body call with a parameter-tainted destination and calldata (idiom_structural). A plain ``transfer`` has no arbitrary
calldata.

Not minted when every candidate call's destination is proven to be a state variable: that proves the caller doesn't
choose it. ``param`` and ``not_determined`` destinations still mint.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from . import _facts
from ._gates import (
    SAFE_EXEC_SELECTORS,
    TIMELOCK_EXECUTE_SELECTORS,
    is_oz_timelock_gate,
    is_safe_gate,
)
from ._taint import _slither_function, arbitrary_exec_taint


def _destination_constraint(ctx: ClaimContext, function: str, destination_param: str | None) -> dict[str, object]:
    """Three-state mandatory-gate verdict for the destination parameter; an unbound name is ``not_determined``."""
    index = None
    if destination_param:
        slither_fn = _slither_function(ctx, function)
        for position, parameter in enumerate(getattr(slither_fn, "parameters", None) or []):
            if getattr(parameter, "name", None) == destination_param:
                index = position
                break
    return _facts.param_constraint(ctx, function, index, mode="external_call")


def _body_external_call_sink_ids(ctx: ClaimContext, function: str) -> list[str]:
    return [
        str(sink["id"])
        for sink in ctx.sinks(function)
        if sink.get("kind") == "external_call" and sink.get("origin") == "body" and sink.get("id")
    ]


@claim_matcher(
    claim_id="exec.arbitrary",
    sentence="forwards a caller-supplied target and calldata (arbitrary execution)",
    legacy_projection="arbitrary_external_call",
    consumer_family="exec",
)
def exec_arbitrary(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    selector = ctx.canonical_selector(function)
    sink_ids = _body_external_call_sink_ids(ctx, function)

    if selector in SAFE_EXEC_SELECTORS and is_safe_gate(ctx):
        # execTransaction's target is committed by the owners' signatures. Module-exec entries only allowlist the
        # caller, so their verdict comes from the gate walk on ``to`` (index 0 on every Safe exec entry).
        constraint = _facts.standard_destination_commitment(ctx, function)
        if constraint is None:
            constraint = _facts.param_constraint(ctx, function, 0, mode="external_call")
        return ClaimEvidence(
            tier="standard_exact",
            witness={
                "kind": "selector+gate",
                "standard": "safe",
                "selector": selector,
                "sink_ids": sink_ids,
                "destination_constraint": constraint,
            },
        )
    if selector in TIMELOCK_EXECUTE_SELECTORS and is_oz_timelock_gate(ctx):
        return ClaimEvidence(
            tier="standard_exact",
            witness={
                "kind": "selector+gate",
                "standard": "oz_timelock",
                "selector": selector,
                "sink_ids": sink_ids,
                # The timelock execute path re-derives ``hashOperation(target, ...)``, so the target is committed. Same
                # helper as the flow witness so the two can't disagree.
                "destination_constraint": _facts.standard_destination_commitment(ctx, function),
            },
        )

    if not sink_ids:
        return None
    taint = arbitrary_exec_taint(ctx, function)
    if taint is None:
        sites = [
            s
            for s in ctx.effect_record(function).get("effect_scopes", [])
            if s.get("forwarded_parameters") and s.get("origin") == "body" and s.get("kind") == "external_call"
        ]
        if not sites:
            return None
        fn = _slither_function(ctx, function)
        if fn is None:
            return None
        forwarded = sites[0]["forwarded_parameters"]
        taint = {
            "destination_kind": "param",
            "calldata_kind": "param",
            "destination_param": fn.parameters[forwarded["destination"]].name,
            "calldata_param": fn.parameters[forwarded["payload"]].name,
            "destination_basis": "bound_effect_site",
            "calldata_basis": "bound_effect_site",
            "source_sites": [{"declaration": s["declaration"], "node": s["node"]} for s in sites],
        }
    if taint["destination_kind"] == "state_var":
        # Every candidate op's destination is storage-held (``LRTSquaredAdmin.rebalance``: address params are arguments
        # to a fixed call, not destinations). The witness would contradict the claim.
        return None
    witness = {
        "kind": "param_taint",
        "source_sites": taint.get("source_sites", []),
        "sink_ids": sink_ids,
        # ``*_param`` is only non-null when ``*_kind`` is ``param``; the kind separates the three states.
        "destination_param": taint["destination_param"],
        "destination_kind": taint["destination_kind"],
        "destination_basis": taint["destination_basis"],
        "calldata_param": taint["calldata_param"],
        "calldata_kind": taint["calldata_kind"],
        "calldata_basis": taint["calldata_basis"],
    }
    # Only where a destination parameter exists; absence reads as ``not_determined``.
    if taint["destination_kind"] == "param":
        witness["destination_constraint"] = _destination_constraint(ctx, function, taint["destination_param"])
    return ClaimEvidence(tier="idiom_structural", witness=witness)
