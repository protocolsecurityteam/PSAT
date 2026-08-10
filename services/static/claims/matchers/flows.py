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


def _bare_sink_callee(sink: dict[str, Any]) -> str | None:
    """The called method's bare name off a sink target (``vault.exit`` → ``exit``)."""
    target = sink.get("target")
    if not isinstance(target, str) or "." not in target:
        return None
    name = target.rsplit(".", 1)[-1].strip()
    return name or None


def _carries(sink: dict[str, Any], flows: list[dict[str, Any]]) -> bool:
    """Does this body sink CARRY one of *flows*?

    Two identity regimes meet here, and reading a routed flow with the direct
    one's rule is what over-attributed. For an ``out``/``in`` flow the move
    happens at a call in THIS body, so the flow's own selector names the sink
    exactly. For a ``value_router`` flow the selector belongs to the CALLEE's
    inner transfer — a selector this body may not call at all — so matching on
    it means any same-selector DIRECT sink in the entry (a ``token.transfer``
    beside a ``vault.exit``) is read as the carrier of the routed move and
    lends the routed claim ITS receiver. The carrier of a routed move is named
    by ``router_ops``, the producer's own record of the call its walk crossed;
    that is the identity :func:`_facts.effect_sink_identities` already joins on
    in process, so the persisted witness now reads the same way.

    A routed flow with no recorded ``router_ops`` names no carrier, so it
    matches nothing: the join is not determined and the key goes absent rather
    than being filled from the bare selector.
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
            # The name travels beside the selector because an interface-typed
            # parameter makes the DECLARED signature hash to a different one;
            # it is the join that survives that, and ``effect_sink_identities``
            # accepts either half for the same reason.
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
    # Keyed BY SINK ID, not listed per flow: one flow key can cover two sinks
    # with the same selector and different receivers (two different tokens moved
    # by one function), and a bare list gives the consumer no way to say which
    # receiver belongs to which move. Only sinks ``_carries`` accepted are in
    # here, so a routed claim can no longer adopt a direct sink's receiver.
    # Guarded the ``router_ops`` way — a missing or empty map leaves the key
    # absent, and absence fails every downstream precondition rather than
    # licensing one.
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
    """Project a value-flow fact into the witness. ``target_kind`` (where funds
    go) and ``amount_kind`` (how much can leave) — each ``{kind, tier}`` — carry
    the theft-vs-routing discriminators when the fact layer classified them;
    omitted when absent so a consumer never reads a guessed value.

    ``target_kinds``/``amount_kinds`` accompany them only where the contributing
    IR sites disagreed, which is exactly where the scalar stops naming one kind:
    it reads ``several`` when every site is itself resolved (the list is the
    COMPLETE set of what the function does — read it and take the WORST, and note
    that these are not alternatives: the sites may be branches or may all execute
    in one call) and ``indeterminate`` when some site is not (the list is a
    partial explanation, not a closed set). The scalar keeps its exact meaning
    either way — a consumer reading only it never over-reads, it just learns
    less."""
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
    # A3+A4 narrowing: a ``param`` destination proves the caller NAMES the
    # destination; whether they can name it FREELY is a separate three-state
    # question answered by the mandatory-gate analysis, and only
    # ``unconstrained_proven`` licenses the caller-chosen (theft-shaped)
    # reading downstream. Attached only where the destination question exists
    # (folded kind ``param``), so no consumer reads a guessed value elsewhere.
    if isinstance(f.get("target_kind"), dict) and f["target_kind"].get("kind") == "param":
        entry["target_constraint"] = _facts.param_constraint(ctx, function, f.get("target_param_index"))
    # The self-service witness and its W1-only substrate, attached only where the
    # amount is read out of storage — the one place the "is this cell the
    # caller's own" question is even asked. Guarded (key ABSENT off this path),
    # so no consumer reads a guessed value on a flow whose amount is a different
    # kind; absence is fail-closed everywhere downstream.
    if isinstance(f.get("amount_kind"), dict) and f["amount_kind"].get("kind") == "bounded_by_storage":
        entry["amount_record_constraint"] = _facts.amount_record_constraint(ctx, function, f)
        entry["self_service_payout"] = _facts.self_service_payout(ctx, function, f)
    # SS-R3: the same caller-names-it question for a ``param`` amount, so a later
    # param-amount shape has the substrate. Moves nothing on today's corpus.
    if (
        f.get("amount_param_index") is not None
        and isinstance(f.get("amount_kind"), dict)
        and f["amount_kind"].get("kind") == "param"
    ):
        entry["amount_constraint"] = _facts.param_constraint(ctx, function, f.get("amount_param_index"))
    # The identity of the op(s) carrying a routed move, so a consumer holding
    # only the persisted witness reads what ``_facts.effect_sink_identities``
    # reads in process. ``callee`` is an INTRA-UNIT AST name, never a resolved
    # on-chain target: an interface-typed parameter makes the declared signature
    # hash to a different selector, which is why the name travels beside it.
    # Guarded, so a missing record and ``[]`` alike leave the key ABSENT and the
    # existing fail-closed reading holds — a routed flow with no recorded op
    # makes nothing transparent, its router leaf blocks, and the mandatory gate
    # falls to ``not_determined``. No consumer can read ``[]`` as "no router".
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
    """A function that itself neither holds nor sends value but CALLS an in-unit
    contract whose body moves it (a Teller forwarding into a BoringVault). The
    fact layer tags such moves ``direction: "value_router"`` and carries the
    destination/amount witness resolved back through the call to the entry's own
    parameters — so a caller-chosen router destination is provable when it is one."""
    return _flow_evidence(ctx, function, "value_router")
