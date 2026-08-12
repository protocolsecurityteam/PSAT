"""The surface reach document: the scorer's own hop verdicts, three states.

Hand-built planes, no database. Every case pins one arm of the unification:
what the walk proves is ``reached``, what it could not establish is a
``frontier`` entry carrying the scorer's own reason token, and what neither
holds is absent — never defaulted, never inferred from an edge's existence.
"""

from __future__ import annotations

from typing import Any

from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring import reach as R
from services.scoring.schema import (
    FunctionSignal,
    PrincipalRef,
    entity_key,
    not_determined_signal_defaults,
)
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
    """A closure edge; ``relation=None`` is the admin/beacon column witness."""
    return P.ControlEdge(
        principal=principal,
        anchor=anchor,
        relation=relation,
        scope=P.parse_edge_scope(label, relation) if relation else P.EdgeScope(P.SCOPE_NOT_DETERMINED),
        witness=P.EDGE_WITNESS_CONTROL_GRAPH if relation else P.EDGE_WITNESS_ADMIN_COLUMN,
    )


def pinned_conditions(destination: str) -> P.ConditionPlane:
    """Every analysed function of ``destination`` pins its caller to itself."""
    plane = P.ConditionPlane()
    plane.by_entity = {
        destination: (P.DestinationFunction(1, "guarded", ("msg.sender == address(this)",), analysed=True),)
    }
    plane.provenance = {"stub": True}
    return plane


class _StubConferral(P.ConferralPlane):
    """Grants stipulated per test — the stub signals carry no persisted function."""

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


def test_hop_verdict_is_the_folds_single_implementation():
    assert FOLD._hop_bound is R.hop_bound
    assert (FOLD.HOP_REFUSED_SCOPE, FOLD.HOP_REFUSED_CONFERRAL, FOLD.HOP_REFUSED_CONDITION) == (
        R.HOP_REFUSED_SCOPE,
        R.HOP_REFUSED_CONFERRAL,
        R.HOP_REFUSED_CONDITION,
    )


def test_admin_column_edge_expands_as_code_control():
    """Holding the admin slot is upgrade power: the walk continues past the
    anchor with no conferral question, hop-numbered from the anchor."""
    closure = P.ControlClosure(
        edges=(edge(KEY_SAFE, KEY_ANCHOR, relation=None), edge(KEY_ANCHOR, KEY_VAULT), edge(KEY_VAULT, KEY_DEEP))
    )
    record = compute(closure)
    assert record["reached"] == {
        KEY_ANCHOR: {"hop": 1, "basis": R.BASIS_CLOSURE_EDGE},
        KEY_VAULT: {"hop": 2, "basis": R.BASIS_WALKED_HOP},
        KEY_DEEP: {"hop": 3, "basis": R.BASIS_WALKED_HOP},
    }
    assert record["parents"] == {KEY_ANCHOR: KEY_SAFE, KEY_VAULT: KEY_ANCHOR, KEY_DEEP: KEY_VAULT}
    assert record["frontier"] == []


def test_stored_authority_does_not_expand_and_publishes_the_gap():
    """Being the stored owner of the anchor witnesses hop 1 and nothing past
    it: the anchor's own onward edges become frontier entries, not reach."""
    closure = P.ControlClosure(edges=(edge(KEY_SAFE, KEY_ANCHOR), edge(KEY_ANCHOR, KEY_VAULT)))
    record = compute(closure)
    assert record["reached"] == {KEY_ANCHOR: {"hop": 1, "basis": R.BASIS_CLOSURE_EDGE}}
    assert record["frontier"] == [
        {
            "from": KEY_ANCHOR,
            "to": KEY_VAULT,
            "reason": R.AUTHORITY_EXERCISE_NOT_WITNESSED,
            "basis": "no witness of what exercising this stored authority reaches",
        }
    ]


def test_gate_walk_refused_by_conferral_carries_the_scorer_token():
    closure = P.ControlClosure(edges=(edge(KEY_ANCHOR, KEY_VAULT, label="hook"),))
    signal = reach_signal("ownership.transfer", KEY_ANCHOR)
    record = compute(closure, conferral=_StubConferral(rewrites=("owner",)), signals=(signal,))
    assert record["reached"] == {KEY_ANCHOR: {"hop": 1, "basis": R.BASIS_SIGNAL_SEED}}
    (entry,) = record["frontier"]
    assert (entry["from"], entry["to"], entry["reason"]) == (KEY_ANCHOR, KEY_VAULT, R.HOP_REFUSED_CONFERRAL)
    assert entry["basis"]


def test_code_walk_condition_refused_hop_carries_the_scorer_token():
    closure = P.ControlClosure(edges=(edge(KEY_ANCHOR, KEY_VAULT),))
    signal = reach_signal("upgrade.implementation", KEY_ANCHOR)
    record = compute(closure, conditions=pinned_conditions(KEY_VAULT), signals=(signal,))
    assert KEY_VAULT not in record["reached"]
    (entry,) = record["frontier"]
    assert (entry["from"], entry["to"], entry["reason"]) == (KEY_ANCHOR, KEY_VAULT, R.HOP_REFUSED_CONDITION)


def test_reached_beats_frontier():
    """A destination another source reaches anyway was withheld from nothing —
    same rule as the fold's gap filter."""
    closure = P.ControlClosure(edges=(edge(KEY_SAFE, KEY_ANCHOR), edge(KEY_ANCHOR, KEY_VAULT)))
    signal = reach_signal("upgrade.implementation", KEY_ANCHOR)
    record = compute(closure, signals=(signal,))
    assert record["reached"][KEY_VAULT] == {"hop": 2, "basis": R.BASIS_WALKED_HOP}
    assert record["frontier"] == []


def test_zero_address_is_refused_as_seed_and_as_hop():
    closure = P.ControlClosure(edges=(edge(KEY_SAFE, KEY_ZERO, relation=None), edge(KEY_ANCHOR, KEY_ZERO)))
    signal = reach_signal("upgrade.implementation", KEY_ZERO, KEY_ANCHOR)
    record = compute(closure, signals=(signal,))
    assert record["reached"] == {KEY_ANCHOR: {"hop": 1, "basis": R.BASIS_SIGNAL_SEED}}
    assert record["frontier"] == []


def test_non_transitive_capability_seeds_only_no_frontier():
    """Non-transitivity is a proven boundary, not a gap: no expansion and no
    frontier entry for the seed's onward edges."""
    closure = P.ControlClosure(edges=(edge(KEY_ANCHOR, KEY_VAULT),))
    signal = reach_signal("flow.out", KEY_ANCHOR)
    record = compute(closure, signals=(signal,))
    assert record["reached"] == {KEY_ANCHOR: {"hop": 1, "basis": R.BASIS_SIGNAL_SEED}}
    assert record["frontier"] == []


def test_signal_walk_parity_with_the_fold_closure():
    """The reach document never claims what the fold's walk does not, and every
    hop the fold refuses appears on the frontier — same planes, same grant."""
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
    # Positive arms of the same parity: the walked destination is claimed, at
    # the walk's own hop, and the refused one is not.
    assert record["reached"][KEY_VAULT] == {"hop": 2, "basis": R.BASIS_WALKED_HOP}
    assert KEY_DEEP not in record["reached"]


PROXY = "0x" + "e" * 40
KEY_PROXY = entity_key("ethereum", PROXY)


def test_reached_keys_fold_onto_the_proxy():
    """The walk speaks in raw anchors; everything PUBLISHES at the canonical
    key — the fold's own rule — or a consumer keying nodes by the proxy would
    silently miss every destination that folds."""
    alias = {KEY_VAULT: KEY_PROXY}
    closure = P.ControlClosure(
        edges=(edge(KEY_SAFE, KEY_ANCHOR, relation=None), edge(KEY_ANCHOR, KEY_VAULT), edge(KEY_VAULT, KEY_DEEP))
    )
    record = R.entity_reach(
        KEY_SAFE, closure, P.ConditionPlane(), _StubConferral(), {}, lambda key: alias.get(key, key)
    )
    assert KEY_VAULT not in record["reached"]
    assert record["reached"][KEY_PROXY] == {"hop": 2, "basis": R.BASIS_WALKED_HOP}
    assert record["parents"][KEY_PROXY] == KEY_ANCHOR
    # The onward hop's caller folds too: DEEP's parent is the proxy, not the impl.
    assert record["parents"][KEY_DEEP] == KEY_PROXY


def test_frontier_endpoints_fold_and_a_self_fold_is_dropped():
    """A frontier destination publishes canonically; a refusal folding onto its
    own caller withheld nothing (the destination is the caller's alias)."""
    alias = {KEY_VAULT: KEY_PROXY}
    closure = P.ControlClosure(edges=(edge(KEY_SAFE, KEY_ANCHOR), edge(KEY_ANCHOR, KEY_VAULT)))
    record = R.entity_reach(
        KEY_SAFE, closure, P.ConditionPlane(), _StubConferral(), {}, lambda key: alias.get(key, key)
    )
    (entry,) = record["frontier"]
    assert (entry["from"], entry["to"]) == (KEY_ANCHOR, KEY_PROXY)

    self_alias = {KEY_VAULT: KEY_ANCHOR}
    record = R.entity_reach(
        KEY_SAFE, closure, P.ConditionPlane(), _StubConferral(), {}, lambda key: self_alias.get(key, key)
    )
    assert record["frontier"] == []


def test_hop_relaxes_to_the_parents_route_it_publishes():
    """A seed re-admitting an intermediate at hop 1 shortens its descendants'
    counts to the route ``parents`` draws — the chip's number can never exceed
    the length of its own lit route."""
    closure = P.ControlClosure(
        edges=(edge(KEY_SAFE, KEY_ANCHOR, relation=None), edge(KEY_ANCHOR, KEY_VAULT), edge(KEY_VAULT, KEY_DEEP))
    )
    # flow.out is non-transitive: it seeds VAULT at hop 1 and walks nothing, so
    # DEEP's hop-3 admission from the code walk must relax along parents.
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
