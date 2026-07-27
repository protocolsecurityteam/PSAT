"""``exec.arbitrary`` — forwards caller-supplied target and calldata.

Resurrects the dead ``arbitrary_external_call`` label (0 producers; the 0.95
severity and ``_manager`` principal-tag consumers had nothing to key on). Three
evidence paths, gate-open because they span unrelated contract shapes:

* Safe ``execTransaction`` / module-exec entries (Safe gate) — standard_exact.
* OZ timelock ``execute`` / ``executeBatch`` (oz_timelock gate) — standard_exact;
  these also carry ``timelock.execute``.
* The ``manage`` idiom — a body-origin call forwarding a parameter-tainted
  destination and calldata (BoringVault.manage) — idiom_structural.

A plain ``transfer(address,uint256)`` value send has an address-tainted
destination but no arbitrary calldata, so no path fires.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from ._gates import (
    SAFE_EXEC_SELECTORS,
    TIMELOCK_EXECUTE_SELECTORS,
    is_oz_timelock_gate,
    is_safe_gate,
)
from ._taint import arbitrary_exec_taint


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
        return ClaimEvidence(
            tier="standard_exact",
            witness={"kind": "selector+gate", "standard": "safe", "selector": selector, "sink_ids": sink_ids},
        )
    if selector in TIMELOCK_EXECUTE_SELECTORS and is_oz_timelock_gate(ctx):
        return ClaimEvidence(
            tier="standard_exact",
            witness={"kind": "selector+gate", "standard": "oz_timelock", "selector": selector, "sink_ids": sink_ids},
        )

    # Idiom tier: prove arbitrariness by taint, anchored to a real body call sink.
    if not sink_ids:
        return None
    taint = arbitrary_exec_taint(ctx, function)
    if taint is None:
        return None
    return ClaimEvidence(
        tier="idiom_structural",
        witness={
            "kind": "param_taint",
            "sink_ids": sink_ids,
            # ``*_param`` names a binding only when the matching ``*_kind`` is
            # ``param``; ``state_var`` / ``call_argument`` are proven absences and
            # ``not_determined`` is an open question. All three publish a null
            # name, so the kind is the only thing that separates them.
            "destination_param": taint["destination_param"],
            "destination_kind": taint["destination_kind"],
            "destination_basis": taint["destination_basis"],
            "calldata_param": taint["calldata_param"],
            "calldata_kind": taint["calldata_kind"],
            "calldata_basis": taint["calldata_basis"],
        },
    )
