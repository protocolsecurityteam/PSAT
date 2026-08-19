"""U3 — the composed-candidate tie-break, and the destination's own predicates.

One of the twenty sections of the former ``test_scoring_redteam.py``.
"""

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
    """Two independent calls at one figure: the state published claims the least.

    Both selectors are licensed, both carry a ``flow.out`` witness, and both
    witnesses are the same number. The dollars are therefore not in question and
    the SELECTOR is: whichever candidate wins names the published
    ``witness_state``. Taking the first one offered mints ``proven_exact`` out of
    iteration order while an equally-witnessed candidate at the identical figure
    supports only a floor.
    """
    document = fold(_tied_signals(), principals=_composing_principals(), **_tied_case())
    row = _gate_row(document)
    entry = next(e for e in row["reach_composed_magnitudes"] if e["entity"] == KEY_V)
    assert row["value_at_stake_usd"] == 1_000_000.0
    assert entry["published_usd"] == 1_000_000.0
    # The weaker state wins the tie, although its selector sorts LAST and its
    # candidate is offered second.
    assert entry["selector"] == TIE_SELECTOR
    assert entry["destination_function"] == "manage"
    assert entry["flow_out_witness"]["state"] == "proven_floor"


def test_u3_the_published_chain_is_the_chosen_candidates_own(fold):
    """The whole candidate is selected, never a field of it.

    ``act_as_chain`` is hard-indexed against the function that admitted the
    published selector. A tie-break that changed the selector and left the chain
    behind would publish a path that ends at a different function from the one
    named beside it — with the calling function, the pointer and the block of
    the candidate that lost.
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
    """An arbitrary rule is only admissible if the document says it ran.

    ``composed_selector_tie`` lists both candidates with the figure and the
    state each supports, marks which one was published, and states the rule.
    Where nothing was decided by the rule it is ``null`` — the proven "one
    candidate" — and never an absent field.
    """
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

    # One candidate: the rule decided nothing, and that is a published fact.
    single = fold(_composing_signals(), principals=_composing_principals(), **_composing_case())
    assert _gate_row(single)["reach_composed_magnitudes"][0]["composed_selector_tie"] is None


def test_u3_a_candidate_that_loses_on_dollars_is_not_a_tie(fold):
    """The figure is still a MAX: the larger call wins outright and is not tied.

    Two selectors at one entity are two independent calls, so the row publishes
    the best of them. A resolved comparison must not be spelled as a tie —
    ``composed_selector_tie`` names candidates the EVIDENCE could not separate.
    """
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
    """One composed candidate, every ordering input settable.

    ``steps`` is ``(caller, destination, selector, calling_selector,
    receiver_variable, receiver_block)`` per hop. The DESTINATION is the raw
    anchor the walk landed on, which is not the entity: a proxy and its
    implementation fold to one entity under two anchors, so two candidates can
    carry the same ``entity`` and different step destinations.
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
    """Everything the published entry is rendered from, chain included.

    The chain is compared through ``as_json`` — the step's whole PUBLISHED
    identity — so this assertion cannot pass by agreeing on a hand-picked subset
    of the fields a reader is shown.
    """
    return (
        entry.usd,
        entry.selector,
        entry.function,
        entry.witness_state,
        tuple(tuple(sorted((k, repr(v)) for k, v in s.as_json().items())) for s in entry.chain),
    )


def test_u3_no_permutation_of_the_candidates_moves_a_dollar():
    """inv. 8 at the composition level: the order is not evidence.

    Seven pools, each tied through the ordering key and separated at exactly ONE
    component, so every component is the deciding one somewhere. Every ordering
    of every pool must select the same entry — same figure, same selector, same
    CHAIN, compared through the step's whole published identity — or some
    published field is a statement about the order the fold happened to build
    the candidates in.
    """
    pools: dict[str, tuple[list[Any], Any]] = {}

    # 1. dollars: the larger call wins outright and is not a tie.
    pools["published_usd"] = (
        [_candidate(usd=900_000.0, selector="0x0a0a0a0a"), _candidate(usd=1_000_000.0)],
        _candidate(usd=1_000_000.0),
    )
    # 2. witness state: the weakest of the tied candidates.
    pools["witness_state"] = (
        [_candidate(state="proven_exact"), _candidate(state="proven_floor", selector=TIE_SELECTOR)],
        _candidate(state="proven_floor", selector=TIE_SELECTOR),
    )
    # 3. selector: lowest, once the state cannot separate them.
    pools["selector"] = (
        [_candidate(selector=TIE_SELECTOR), _candidate(selector=COMPOSED_SELECTOR)],
        _candidate(selector=COMPOSED_SELECTOR),
    )
    # 4. destination function: lowest, once the selector cannot.
    pools["destination_function"] = (
        [_candidate(function="manage"), _candidate(function="exit")],
        _candidate(function="exit"),
    )
    # 5. the chain's calling selectors — the same call site reached under two
    #    different entry functions of the caller.
    pools["calling_selector_chain"] = (
        [
            _candidate(steps=((KEY_C, KEY_V, COMPOSED_SELECTOR, "0xbbbb0002", "vault", 1),)),
            _candidate(steps=((KEY_C, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 1),)),
        ],
        _candidate(steps=((KEY_C, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 1),)),
    )
    # 6. the chain's own IDENTITY: two different callers whose calling functions
    #    share a selector. Tied through every component above — only the caller,
    #    the pointer and the block differ, and all three are published. The
    #    lowest caller wins: KEY_T is 0x7777..., KEY_C is 0xaaaa....
    pools["chain_identity"] = (
        [
            _candidate(steps=((KEY_C, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 11),)),
            _candidate(steps=((KEY_T, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vaultPtr", 22),)),
        ],
        _candidate(steps=((KEY_T, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vaultPtr", 22),)),
    )
    # 7. THE PROXY FOLD. One entity, two raw anchors — an implementation folded
    #    onto its proxy is one entity under two of them — so two candidates
    #    agree on the caller, the selector, the calling selector, the pointer
    #    and the block, and differ only in the step's own ``destination`` and
    #    the basis rendered from it. Both are published; neither is in a
    #    hand-written list of "the fields that identify a step", which is why
    #    the key reads the step's whole published identity instead.
    pools["proxy_folded_destination"] = (
        [
            _candidate(steps=((KEY_C, KEY_V, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 1),)),
            _candidate(steps=((KEY_C, KEY_PROXY, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 1),)),
        ],
        # KEY_PROXY sorts below KEY_V, and the basis names it first.
        _candidate(steps=((KEY_C, KEY_PROXY, COMPOSED_SELECTOR, "0xaaaa0001", "vault", 1),)),
    )

    for name, (pool, winner) in pools.items():
        # Every pool must really be tied THROUGH the earlier components, or the
        # case is not testing the component it claims to.
        keys = {FOLD._composed_order(c) for c in pool}
        assert len(keys) == len(pool), name
        expected_ties = sum(1 for c in pool if c.usd == winner.usd) - 1
        selected = [FOLD._select_composed(list(order)) for order in itertools.permutations(pool)]
        assert {_identity(entry) for entry in selected} == {_identity(winner)}, name
        assert {len(entry.tied_with) for entry in selected} == {expected_ties}, name


def test_u3_an_unrankable_witness_state_can_never_win_a_tie():
    """A state the claim map does not know must not be PREFERRED to one it does.

    Ranking an unknown state with the weakest would be the fail-open: "we cannot
    tell what this claims" would beat a state proven to claim little, and an
    unrankable string would be published over a witness. It loses every tie, so
    it reaches the document only where it is the sole candidate — where nothing
    was compared and it is the only thing there is to publish.
    """
    unknown = _candidate(state="not_determined", selector="0x0a0a0a0a")
    for known in (_candidate(state="proven_floor"), _candidate(state="proven_exact")):
        pool = [unknown, known]
        for order in itertools.permutations(pool):
            chosen = FOLD._select_composed(list(order))
            assert chosen.witness_state == known.witness_state
            assert chosen.selector == known.selector
    # Sole candidate: published as it stands, and disclosed as no tie at all.
    alone = FOLD._select_composed([unknown])
    assert alone.witness_state == "not_determined" and alone.tied_with == ()


# --- destination_predicates (B2) -------------------------------------------


AUTH_GUARD = "require(bool,string)(isAuthorized(msg.sender,msg.sig),UNAUTHORIZED)"
TRANSFER_POSTCONDITION = "require(bool,string)(success,TRANSFER_FAILED)"
SSA_MARKER = "safeTransfer(...)"
VAULT_PREDICATES = (AUTH_GUARD, TRANSFER_POSTCONDITION, SSA_MARKER)


def _predicate_plane() -> P.ConditionPlane:
    """The vault's ``exit``, with its stored condition texts and its selector."""
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
    """The ceiling claim points at the evidence it was NOT made against.

    The shipped disclosure asserts the destination's own argument semantics went
    unread. Without a pointer that assertion is unfalsifiable by the reader, so
    the entry carries the texts verbatim, in stored order, from the canonical
    column — and says in the same object that it evaluated none of them.
    """
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
    # Verbatim and in STORED order — not sorted, not deduped, not filtered.
    assert block["descriptions"] == list(VAULT_PREDICATES)
    # Nothing is filtered out by kind: the authorization guard this step's own
    # witness proves satisfied, a transfer post-condition and an SSA call marker
    # all stay, which is why the block is not readable as unmet conditions.
    assert AUTH_GUARD in block["descriptions"] and SSA_MARKER in block["descriptions"]
    assert block["evaluated"] is False
    for fragment in ("WITHOUT POLARITY", "EVALUATES", "authorization guard"):
        assert fragment in block["reading"], fragment
    # The reading's clause (4) pointed at caller_holding_precondition, which is
    # cut — a dangling cross-reference is a claim that a field exists.
    assert "caller_holding_precondition" not in block["reading"]
    assert "bound_kind" not in block


def test_u3_the_predicates_ride_on_both_act_as_witness_shapes(fold):
    """The disclosure is a DESTINATION fact and does not depend on how it was reached.

    An ACL-admitted step and a state-variable step publish the same destination
    function's predicates — the block describes the callee's body, not the
    witness that got there.
    """
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
    """ "No predicate was stored" is three different facts and each keeps its name.

    An extraction that ran and found nothing is a read; a column holding no
    array is an extraction that never ran; and no function under that selector
    is a join that missed. Collapsing any two would publish a coverage gap as a
    proven absence of guards.
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

    # Extracted and EMPTY: a read that found no predicate, not a missing read.
    empty = plane.predicates(KEY_V, TIE_SELECTOR)
    assert empty.state == P.PREDICATES_EXTRACTED and empty.descriptions == ()

    unextracted = plane.predicates(KEY_V, "0x0a0a0a0a")
    assert unextracted.state == P.PREDICATES_COLUMN_HOLDS_NO_ARRAY
    assert unextracted.descriptions is None and unextracted.entries_stored is None

    for missing in ("0xdeadbeef", ""):
        absent = plane.predicates(KEY_V, missing)
        assert absent.state == P.PREDICATES_FUNCTION_NOT_LOCATED, missing
        assert (absent.function_id, absent.descriptions) == (None, None), missing
    # A function whose own selector was never extracted matches nothing: four
    # bytes nobody recorded do not name a function.
    assert plane.predicates(KEY_V, "0x00000000").state == P.PREDICATES_FUNCTION_NOT_LOCATED
    assert plane.predicates("ethereum::0xnothing", COMPOSED_SELECTOR).state == P.PREDICATES_FUNCTION_NOT_LOCATED


def test_u3_the_predicate_texts_are_read_verbatim_from_the_stored_array():
    """The canonical column, unfiltered — and an entry with no text is counted.

    ``kind`` is not read (the extractor labels everything ``business``), nothing
    is deduped or reordered, and an entry carrying no string ``description``
    raises ``entries_stored`` above the text count instead of disappearing.
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
    # A column holding no array is an extraction that never ran.
    assert P._stored_predicates(None) == ((), 0)
    assert P._stored_predicates("[]") == ((), 0)
