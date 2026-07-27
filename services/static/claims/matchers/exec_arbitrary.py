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
from . import _facts
from ._gates import (
    SAFE_EXEC_SELECTORS,
    TIMELOCK_EXECUTE_SELECTORS,
    is_oz_timelock_gate,
    is_safe_gate,
)
from ._taint import _slither_function, arbitrary_exec_taint


def _destination_constraint(ctx: ClaimContext, function: str, destination_param: str | None) -> dict[str, object]:
    """The three-state mandatory-gate verdict for the destination parameter.

    The claim's sentence asserts the caller chooses the target; whether a
    mandatory revert gate pins that choice (an allowlist, a hash commitment) is
    the A3 narrowing. The name is resolved to its ABI index against the
    function's own parameter list — a name the taint layer could not bind
    (``None``) is ``not_determined`` by construction."""
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
        return ClaimEvidence(
            tier="standard_exact",
            witness={
                "kind": "selector+gate",
                "standard": "safe",
                "selector": selector,
                "sink_ids": sink_ids,
                # The standard itself is the constraint proof: execTransaction's
                # target is committed under the owners' threshold signatures.
                "destination_constraint": {
                    "state": "constrained",
                    "guard": "signature_witness",
                    "binding": "standard_gate",
                },
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
                # The gate proved the OZ TimelockController shape, whose execute
                # path re-derives ``hashOperation(target, …)`` and requires the
                # operation ready: the target is hash-committed by the standard.
                "destination_constraint": {
                    "state": "constrained",
                    "guard": "hash_commitment",
                    "binding": "standard_gate",
                },
            },
        )

    # Idiom tier: prove arbitrariness by taint, anchored to a real body call sink.
    if not sink_ids:
        return None
    taint = arbitrary_exec_taint(ctx, function)
    if taint is None:
        return None
    witness = {
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
    }
    # A3 narrowing: attached only where a destination parameter exists to ask
    # about. Absence of the field reads as ``not_determined`` downstream — never
    # as a proof in either direction.
    if taint["destination_kind"] == "param":
        witness["destination_constraint"] = _destination_constraint(ctx, function, taint["destination_param"])
    return ClaimEvidence(tier="idiom_structural", witness=witness)
