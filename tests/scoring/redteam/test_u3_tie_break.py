from __future__ import annotations

import itertools
from typing import Any

from services.scoring import fold as FOLD
from services.scoring import planes as P
from tests.support.scoring_builders import (
    COMPOSED_SELECTOR,
    KEY_C,
    KEY_PROXY,
    KEY_T,
    KEY_V,
    TIE_CALLING_SELECTOR,
    TIE_SELECTOR,
    _acl_plane,
    _composing_case,
    _composing_principals,
    _composing_signals,
    _gate_row,
    _tied_case,
    _tied_signals,
    fold,  # noqa: F401  (fold fixture, registered by import)
)
from utils import execution_record as EX


def test_u3_a_tied_composed_figure_publishes_the_weakest_witness_state(fold):
    """Taking the first offered would mint ``proven_exact`` from iteration order while an equal candidate supports
    only a floor.
    """
    document = fold(_tied_signals(), principals=_composing_principals(), **_tied_case())
    row = _gate_row(document)
    entry = next(e for e in row["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    assert row["value_at_stake_usd"] == 1_000_000.0
    assert entry["published_usd"] == 1_000_000.0
    assert entry["selector"] == TIE_SELECTOR
    assert entry["destination_function"] == "manage"
    assert entry["flow_out_witness"]["state"] == "proven_floor"


def test_u3_the_published_chain_is_the_chosen_candidates_own(fold):
    """``act_as_chain`` is indexed against the function that admitted the selector, so the chain must come from the
    winning candidate.
    """
    document = fold(_tied_signals(), principals=_composing_principals(), **_tied_case())
    entry = next(e for e in _gate_row(document)["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    (step,) = entry["act_as_chain"]
    assert step["selector"] == entry["selector"]
    assert step["calling_function"] == "manageVaultWithMerkleVerification"
    assert step["calling_selector"] == TIE_CALLING_SELECTOR
    assert (step["receiver_variable"], step["receiver_block"]) == ("vaultPtr", 25_659_227)
    assert "vaultPtr" in step["basis"] and "bulkWithdraw" not in step["basis"]


def test_u3_the_tie_is_disclosed_and_names_every_candidate(fold):
    """An arbitrary rule is admissible only if disclosed; ``null`` where it decided nothing, never absent."""
    document = fold(_tied_signals(), principals=_composing_principals(), **_tied_case())
    entry = next(e for e in _gate_row(document)["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    tie = entry["composed_selector_tie"]
    assert tie["tied_at_usd"] == 1_000_000.0
    assert tie["candidates"] == [
        {
            "selector": TIE_SELECTOR,
            "destination_function": "manage",
            "witness_state": "proven_floor",
            "witnessed_usd": 1_000_000.0,
            "chosen": True,
        },
        {
            "selector": COMPOSED_SELECTOR,
            "destination_function": "exit",
            "witness_state": "proven_exact",
            "witnessed_usd": 1_000_000.0,
            "chosen": False,
        },
    ]
    assert "weakest witness state" in tie["chosen_by"] and "lowest selector" in tie["chosen_by"]
    assert "not by evidence" in tie["reading"]

    single = fold(_composing_signals(), principals=_composing_principals(), **_composing_case())
    assert _gate_row(single)["reach_composed_magnitudes"][0]["composed_selector_tie"] is None


def test_u3_a_candidate_that_loses_on_dollars_is_not_a_tie(fold):
    document = fold(_tied_signals(tie_usd=400_000.0), principals=_composing_principals(), **_tied_case())
    entry = next(e for e in _gate_row(document)["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    assert entry["published_usd"] == 1_000_000.0
    assert entry["selector"] == COMPOSED_SELECTOR
    assert entry["flow_out_witness"]["state"] == "proven_exact"
    assert entry["composed_selector_tie"] is None


def _candidate(
    *,
    selector: str = COMPOSED_SELECTOR,
    function: str = "exit",
    state: str = "proven_exact",
    usd: float = 1_000_000.0,
    witnessed_usd: float | None = None,
    steps: tuple[tuple[str, str, str, str, str, int | None], ...] = (
        (KEY_C, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 1),
    ),
) -> Any:
    """``steps`` are ``(caller, destination, selector, calling_selector, receiver_variable, receiver_block)``;
    destination is the raw anchor, since a proxy and its impl share an entity.
    """
    chain = tuple(
        P.ActAsStep(
            caller=caller,
            destination=destination,
            selector=step_selector,
            calling_function=f"call_{calling_selector}",
            calling_function_openness="restricted",
            calling_selector=calling_selector,
            receiver_variable=variable,
            receiver_observed_via="eth_call",
            receiver_block=block,
        )
        for caller, destination, step_selector, calling_selector, variable, block in steps
    )
    return FOLD._ComposedMagnitude(
        entity=KEY_V,
        selector=selector,
        function=function,
        witness_state=state,
        witnessed_usd=usd if witnessed_usd is None else witnessed_usd,
        usd=usd,
        sheet_usd=None,
        chain=chain,
        predicates=P.DestinationPredicates(P.PREDICATES_FUNCTION_NOT_LOCATED, None, None, None, None, 0),
        execution=EX.not_determined(EX.REASON_NOT_PERSISTED),
    )


def _identity(entry: Any) -> tuple[Any, ...]:
    """Compared via ``as_json`` so the assertion can't pass on a hand-picked subset of fields."""
    return (
        entry.usd,
        entry.selector,
        entry.function,
        entry.witness_state,
        tuple(tuple(sorted((k, repr(v)) for k, v in s.as_json().items())) for s in entry.chain),
    )


def test_u3_no_permutation_of_the_candidates_moves_a_dollar():
    """Composition order: the order is not evidence.

    8: each pool is tied up to exactly one ordering component, and every permutation must select the same entry.
    """
    pools: dict[str, tuple[list[Any], Any]] = {}

    pools["published_usd"] = (
        [_candidate(usd=900_000.0, selector="0x0a0a0a0a"), _candidate(usd=1_000_000.0)],
        _candidate(usd=1_000_000.0),
    )
    pools["witness_state"] = (
        [_candidate(state="proven_exact"), _candidate(state="proven_floor", selector=TIE_SELECTOR)],
        _candidate(state="proven_floor", selector=TIE_SELECTOR),
    )
    pools["selector"] = (
        [_candidate(selector=TIE_SELECTOR), _candidate(selector=COMPOSED_SELECTOR)],
        _candidate(selector=COMPOSED_SELECTOR),
    )
    pools["destination_function"] = (
        [_candidate(function="manage"), _candidate(function="exit")],
        _candidate(function="exit"),
    )
    # 5. the same call site reached under two different entry functions of the caller.
    pools["calling_selector_chain"] = (
        [
            _candidate(steps=((KEY_C, KEY_V, COMPOSED_SELECTOR, "0xbbbb0002", "vault", 1),)),
            _candidate(steps=((KEY_C, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 1),)),
        ],
        _candidate(steps=((KEY_C, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 1),)),
    )
    # 6. two callers whose calling functions share a selector; the lowest caller wins.
    pools["chain_identity"] = (
        [
            _candidate(steps=((KEY_C, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 11),)),
            _candidate(steps=((KEY_T, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vaultPtr", 22),)),
        ],
        _candidate(steps=((KEY_T, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vaultPtr", 22),)),
    )
    # 7. the proxy fold: two raw anchors of one entity, differing only in the step's destination, which is why the key
    # reads the step's whole published identity.
    pools["proxy_folded_destination"] = (
        [
            _candidate(steps=((KEY_C, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 1),)),
            _candidate(steps=((KEY_C, KEY_PROXY, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 1),)),
        ],
        _candidate(steps=((KEY_C, KEY_PROXY, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 1),)),
    )

    for name, (pool, winner) in pools.items():
        # Otherwise the case isn't testing the component it claims to.
        keys = {FOLD._composed_order(c) for c in pool}
        assert len(keys) == len(pool), name
        expected_ties = sum(1 for c in pool if c.usd == winner.usd) - 1
        selected = [FOLD._select_composed(list(order)) for order in itertools.permutations(pool)]
        assert {_identity(entry) for entry in selected} == {_identity(winner)}, name
        assert {len(entry.tied_with) for entry in selected} == {expected_ties}, name


def test_u3_an_unrankable_witness_state_can_never_win_a_tie():
    """Ranking an unknown state as weakest would be fail-open, so it loses every tie."""
    unknown = _candidate(state="not_determined", selector="0x0a0a0a0a")
    for known in (_candidate(state="proven_floor"), _candidate(state="proven_exact")):
        pool = [unknown, known]
        for order in itertools.permutations(pool):
            chosen = FOLD._select_composed(list(order))
            assert chosen.witness_state == known.witness_state
            assert chosen.selector == known.selector
    alone = FOLD._select_composed([unknown])
    assert alone.witness_state == "not_determined" and alone.tied_with == ()


AUTH_GUARD = "require(bool,string)(isAuthorized(msg.sender,msg.sig),UNAUTHORIZED)"
TRANSFER_POSTCONDITION = "require(bool,string)(success,TRANSFER_FAILED)"
SSA_MARKER = "safeTransfer(...)"
VAULT_PREDICATES = (AUTH_GUARD, TRANSFER_POSTCONDITION, SSA_MARKER)


def _predicate_plane() -> P.ConditionPlane:
    plane = P.ConditionPlane()
    plane.by_entity = {
        KEY_V: (
            P.DestinationFunction(
                function_id=4242,
                name="exit",
                caller_pinned_to_self=(),
                analysed=True,
                selector=COMPOSED_SELECTOR,
                predicates=VAULT_PREDICATES,
                predicate_entries_stored=len(VAULT_PREDICATES),
            ),
        )
    }
    plane.provenance = {"stub": True}
    return plane


def test_u3_a_composed_entry_publishes_the_destinations_own_predicates(fold):
    """The entry carries the destination's predicate texts verbatim so the "unread" disclosure is falsifiable."""
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        **_composing_case(conditions=_predicate_plane()),
    )
    entry = _gate_row(document)["reach_composed_magnitudes"][0]
    block = entry["destination_predicates"]
    assert block["source"] == "effective_functions.conditions"
    assert block["state"] == P.PREDICATES_EXTRACTED
    assert block["function_id"] == 4242
    assert block["count"] == 3 and block["entries_stored"] == 3
    assert block["descriptions"] == list(VAULT_PREDICATES)
    # Nothing is filtered by kind, which is why the block can't be read as unmet conditions.
    assert AUTH_GUARD in block["descriptions"] and SSA_MARKER in block["descriptions"]
    assert block["evaluated"] is False
    for fragment in ("WITHOUT POLARITY", "EVALUATES", "authorization guard"):
        assert fragment in block["reading"], fragment
    assert "caller_holding_precondition" not in block["reading"]
    assert "bound_kind" not in block


def test_u3_the_predicates_ride_on_both_act_as_witness_shapes(fold):
    shapes = {
        P.ACT_AS_WITNESS_CALLER_STATE_VARIABLE: _composing_case(conditions=_predicate_plane()),
        P.ACT_AS_WITNESS_DESTINATION_ACL: _composing_case(act_as=_acl_plane(), conditions=_predicate_plane()),
    }
    for kind, case in shapes.items():
        document = fold(_composing_signals(), principals=_composing_principals(), **case)
        entry = _gate_row(document)["reach_composed_magnitudes"][0]
        assert {step["witness_kind"] for step in entry["act_as_chain"]} == {kind}, kind
        assert entry["destination_predicates"]["descriptions"] == list(VAULT_PREDICATES), kind


def test_u3_the_predicate_lookup_keeps_its_three_states():
    """Found-nothing, never-extracted and no-such-function are different facts; collapsing them would publish a
    coverage gap as absence of guards.
    """
    plane = P.ConditionPlane()
    plane.by_entity = {
        KEY_V: (
            P.DestinationFunction(1, "exit", (), True, COMPOSED_SELECTOR, VAULT_PREDICATES, 3),
            P.DestinationFunction(2, "manage", (), True, TIE_SELECTOR, (), 0),
            P.DestinationFunction(3, "sweep", (), False, "0x0a0a0a0a", (), 0),
            P.DestinationFunction(4, "unnamed", (), True, None, ("x == 1",), 1),
        )
    }
    extracted = plane.predicates(KEY_V, COMPOSED_SELECTOR)
    assert extracted.state == P.PREDICATES_EXTRACTED
    assert extracted.descriptions == VAULT_PREDICATES and extracted.functions_matching == 1

    empty = plane.predicates(KEY_V, TIE_SELECTOR)
    assert empty.state == P.PREDICATES_EXTRACTED and empty.descriptions == ()

    unextracted = plane.predicates(KEY_V, "0x0a0a0a0a")
    assert unextracted.state == P.PREDICATES_COLUMN_HOLDS_NO_ARRAY
    assert unextracted.descriptions is None and unextracted.entries_stored is None

    for missing in ("0xdeadbeef", ""):
        absent = plane.predicates(KEY_V, missing)
        assert absent.state == P.PREDICATES_FUNCTION_NOT_LOCATED, missing
        assert (absent.function_id, absent.descriptions) == (None, None), missing
    assert plane.predicates(KEY_V, "0x00000000").state == P.PREDICATES_FUNCTION_NOT_LOCATED
    assert plane.predicates("ethereum::0xnothing", COMPOSED_SELECTOR).state == P.PREDICATES_FUNCTION_NOT_LOCATED


def test_u3_the_predicate_texts_are_read_verbatim_from_the_stored_array():
    """``kind`` is not read (everything is labelled ``business``), and a text-less entry raises ``entries_stored``
    instead of disappearing.
    """
    texts, entries = P._stored_predicates(
        [
            {"kind": "business", "description": AUTH_GUARD},
            {"kind": "business", "description": AUTH_GUARD},
            {"kind": "reentrancy", "description": "$._status == ENTERED"},
            {"kind": "business"},
            "not an object",
        ]
    )
    assert texts == (AUTH_GUARD, AUTH_GUARD, "$._status == ENTERED")
    assert entries == 5
    assert P._stored_predicates(None) == ((), 0)
    assert P._stored_predicates("[]") == ((), 0)
