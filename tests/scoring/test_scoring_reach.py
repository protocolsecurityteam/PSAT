"""Surface reach document on hand-built planes.

The walk's proven hops are ``reached``, unestablished ones are ``frontier`` entries with the scorer's reason token, and
nothing is inferred from an edge's existence.
"""

from __future__ import annotations

from typing import Any

from services.scoring import constants as K
from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring import reach as R
from services.scoring.schema import (
    FunctionSignal,
    PrincipalRef,
    entity_key,
    not_determined_signal_defaults,
)
from services.static.claims import claim_ids_of_class
from utils.scoring_status import VALUE_STATE_PROVEN_REACH

SAFE = "0x" + "2" * 40
ANCHOR = "0x" + "a" * 40
VAULT = "0x" + "b" * 40
DEEP = "0x" + "c" * 40
ZERO = "0x" + "0" * 40
KEY_SAFE = entity_key("ethereum", SAFE)
KEY_ANCHOR = entity_key("ethereum", ANCHOR)
KEY_VAULT = entity_key("ethereum", VAULT)
KEY_DEEP = entity_key("ethereum", DEEP)
KEY_ZERO = entity_key("ethereum", ZERO)


def edge(principal: str, anchor: str, *, relation: str | None = "controller_value", label: str | None = "owner"):
    return P.ControlEdge(
        principal=principal,
        anchor=anchor,
        relation=relation,
        scope=P.parse_edge_scope(label, relation) if relation else P.EdgeScope(P.SCOPE_NOT_DETERMINED),
        witness=P.EDGE_WITNESS_CONTROL_GRAPH if relation else P.EDGE_WITNESS_ADMIN_COLUMN,
    )


class _StubConferral(P.ConferralPlane):
    def __init__(self, rewrites=(), role_functions=None):
        super().__init__(role_functions=dict(role_functions or {}))
        self._rewrites = frozenset(rewrites)

    def grant_for(self, capability, function_id, *, entity=None, selector=None):
        return P.GateGrant(capability, self._rewrites, True, "stub(test)", self)


def reach_signal(claim_id: str, *keys: str, principal: str = SAFE) -> FunctionSignal:
    fields: dict[str, Any] = not_determined_signal_defaults()
    fields.update(
        job_id=None,
        protocol_id=1,
        contract_id=1,
        chain="ethereum",
        deployment_address="0x" + "d" * 40,
        function_name="f",
        claim_id=claim_id,
        selector="0xdeadbeef",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", principal),),
        value_state=VALUE_STATE_PROVEN_REACH,
        value_entity_keys=tuple(sorted(keys)),
        value_basis="acting_entity",
    )
    return FunctionSignal(**fields)


def compute(closure, *, conditions=None, conferral=None, signals=()):
    by_principal: dict[str, list[FunctionSignal]] = {}
    for signal in signals:
        for ref in signal.principal_refs:
            by_principal.setdefault(ref.key, []).append(signal)
    return R.entity_reach(
        KEY_SAFE,
        closure,
        conditions or P.ConditionPlane(),
        conferral or _StubConferral(),
        by_principal,
    )


def test_reached_beats_frontier():
    """Same rule as the fold's gap filter."""
    closure = P.ControlClosure(edges=(edge(KEY_SAFE, KEY_ANCHOR), edge(KEY_ANCHOR, KEY_VAULT)))
    signal = reach_signal("upgrade.implementation", KEY_ANCHOR)
    record = compute(closure, signals=(signal,))
    assert record["reached"][KEY_VAULT] == {"hop": 2, "basis": R.BASIS_WALKED_HOP}
    assert record["frontier"] == []


def test_signal_walk_parity_with_the_fold_closure():
    closure = P.ControlClosure(
        edges=(edge(KEY_ANCHOR, KEY_VAULT, label="owner"), edge(KEY_ANCHOR, KEY_DEEP, label="hook"))
    )
    conditions = P.ConditionPlane()
    conferral = _StubConferral(rewrites=("owner",))
    grant = conferral.grant_for("ownership.transfer", None)

    seen, gaps, _licensed, _hops = FOLD._closure({KEY_ANCHOR}, closure, conditions, grant=grant)

    signal = reach_signal("ownership.transfer", KEY_ANCHOR)
    record = compute(closure, conditions=conditions, conferral=conferral, signals=(signal,))

    assert set(record["reached"]) <= seen
    fold_refusals = {(gap["caller"], gap["destination"], gap["reason"]) for gap in gaps}
    surface_frontier = {(e["from"], e["to"], e["reason"]) for e in record["frontier"]}
    assert fold_refusals <= surface_frontier
    assert record["reached"][KEY_VAULT] == {"hop": 2, "basis": R.BASIS_WALKED_HOP}
    assert KEY_DEEP not in record["reached"]


PROXY = "0x" + "e" * 40
KEY_PROXY = entity_key("ethereum", PROXY)


def test_seed_standpoint_carries_the_walk_the_fold_ran_from_it():
    """The finding row names the seed as the walk's origin, so hops are numbered from the standpoint, not the
    principal.
    """
    closure = P.ControlClosure(
        edges=(edge(KEY_ANCHOR, KEY_VAULT, label="owner"), edge(KEY_VAULT, KEY_DEEP, label="owner"))
    )
    signal = reach_signal("ownership.transfer", KEY_ANCHOR)
    record = R.entity_reach(
        KEY_ANCHOR,
        closure,
        P.ConditionPlane(),
        _StubConferral(rewrites=("owner",)),
        {},
        None,
        {KEY_ANCHOR: (signal,)},
    )
    # The entity's own edge ties with the walk at hop 1; what's pinned is the walked continuation past it.
    assert record["reached"][KEY_VAULT]["hop"] == 1
    assert record["reached"][KEY_DEEP] == {"hop": 2, "basis": R.BASIS_WALKED_HOP}
    assert record["parents"] == {KEY_VAULT: KEY_ANCHOR, KEY_DEEP: KEY_VAULT}

    hook = P.ControlClosure(edges=(edge(KEY_ANCHOR, KEY_VAULT, label="owner"), edge(KEY_VAULT, KEY_DEEP, label="hook")))
    record = R.entity_reach(
        KEY_ANCHOR,
        hook,
        P.ConditionPlane(),
        _StubConferral(rewrites=("owner",)),
        {},
        None,
        {KEY_ANCHOR: (signal,)},
    )
    (entry,) = record["frontier"]
    assert (entry["from"], entry["to"], entry["reason"]) == (KEY_VAULT, KEY_DEEP, R.HOP_REFUSED_CONFERRAL)


def test_hop_relaxes_to_the_parents_route_it_publishes():
    """The chip's hop number can never exceed its lit route length."""
    closure = P.ControlClosure(
        edges=(edge(KEY_SAFE, KEY_ANCHOR, relation=None), edge(KEY_ANCHOR, KEY_VAULT), edge(KEY_VAULT, KEY_DEEP))
    )
    # flow.out is non-transitive, so DEEP's hop-3 admission must relax along parents.
    signal = reach_signal("flow.out", KEY_VAULT)
    record = compute(closure, signals=(signal,))
    assert record["reached"][KEY_VAULT] == {"hop": 1, "basis": R.BASIS_SIGNAL_SEED}
    assert record["parents"][KEY_VAULT] == KEY_SAFE
    assert record["reached"][KEY_DEEP]["hop"] == 2
    assert record["parents"][KEY_DEEP] == KEY_VAULT


def test_merge_reach_min_hop_and_reached_beats_frontier():
    first = {
        KEY_SAFE: {
            "reached": {KEY_VAULT: {"hop": 3, "basis": R.BASIS_WALKED_HOP}},
            "parents": {KEY_VAULT: KEY_ANCHOR},
            "frontier": [
                {"from": KEY_ANCHOR, "to": KEY_DEEP, "reason": R.AUTHORITY_EXERCISE_NOT_WITNESSED, "basis": "b"}
            ],
        }
    }
    second = {
        KEY_SAFE: {
            "reached": {
                KEY_VAULT: {"hop": 2, "basis": R.BASIS_WALKED_HOP},
                KEY_DEEP: {"hop": 1, "basis": R.BASIS_SIGNAL_SEED},
            },
            "parents": {KEY_VAULT: KEY_ANCHOR, KEY_DEEP: KEY_SAFE},
            "frontier": [],
        }
    }
    merged = R.merge_reach([first, second])
    assert merged[KEY_SAFE]["reached"][KEY_VAULT] == {"hop": 2, "basis": R.BASIS_WALKED_HOP}
    assert merged[KEY_SAFE]["frontier"] == []


def test_reach_classes_are_drawn_from_the_grant_vocabulary():
    assert K.CODE_CONTROL_CAPABILITIES == claim_ids_of_class("control.code")
    assert K.GATE_CONTROL_CAPABILITIES < claim_ids_of_class("control.gate")
