from __future__ import annotations

from typing import Any

from services.scoring import fold as FOLD
from services.scoring import planes as P
from tests.support.scoring_builders import (
    COMPOSED_SELECTOR,
    KEY_C,
    KEY_V,
    TIE_SELECTOR,
    _composing_case,
    _composing_principals,
    _composing_signals,
    _gate_row,
    _tied_case,
    _tied_signals,
    fold,  # noqa: F401  (fold fixture, registered by import)
)
from utils import execution_record as EX


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
