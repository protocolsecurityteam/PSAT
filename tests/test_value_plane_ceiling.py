"""The sheet ceiling resolver: what a node's own balance sheet bounds.

``planes.ceiling_for`` answers the value-side half of the code-control ceiling
rule — is this node's sheet determined, is its asset list whole, and is its key
one two proxies share — and the corpus cannot exercise it. Protocol 1 carries no
ambiguous alias and no airdrop-determined sheet (nothing has yet measured a
delivery), so two of the eight reasons have zero carriers there and the
unregistered-sheet-state guard has none anywhere. Every reason is therefore
pinned here over hand-built planes instead.

The one that matters most is ``proven_empty``. A sheet whose every quantity is
witnessed zero is an EARNED NEGATIVE — the ceiling is provably $0 — and both of
the obvious admission tests get it wrong in opposite directions: ``total() is
not None`` admits it without recording that the $0 was proven, and
``sheet_state() == SHEET_PRICED`` refuses it and publishes not_determined where
a proven zero exists. The resolver has to admit it under its own token, and the
tests below fail if either shortcut is ever substituted.
"""

from __future__ import annotations

import pytest

from services.scoring import planes as P

KEY = "ethereum::0x" + "a" * 40
OTHER = "ethereum::0x" + "b" * 40


def _plane(
    *,
    per_asset: dict[str, dict[str, float]] | None = None,
    per_asset_state: dict[str, dict[str, str]] | None = None,
    alias: dict[str, str] | None = None,
    alias_ambiguous: set[str] | None = None,
    asset_set_truncated: set[str] | None = None,
    asset_set_proven_complete: dict[str, dict] | None = None,
    asset_set_accounts_unscanned: dict[str, list[str]] | None = None,
    typed_receipts_unresolved: dict[str, list[dict]] | None = None,
    unpriced_positions: dict[str, list[dict]] | None = None,
    asset_disposition: dict[str, dict[str, dict]] | None = None,
) -> P.ValuePlane:
    plane = P.ValuePlane()
    plane.per_asset = per_asset or {}
    plane.per_asset_state = per_asset_state or {}
    plane.alias = alias or {}
    plane.alias_ambiguous = alias_ambiguous or set()
    plane.asset_set_truncated = asset_set_truncated or set()
    plane.asset_set_proven_complete = asset_set_proven_complete or {}
    plane.asset_set_accounts_unscanned = asset_set_accounts_unscanned or {}
    plane.typed_receipts_unresolved = typed_receipts_unresolved or {}
    plane.unpriced_positions = unpriced_positions or {}
    plane.asset_disposition = asset_disposition or {}
    plane.contract_entities = set(plane.per_asset) | set(plane.per_asset_state)
    return plane


def _priced() -> P.ValuePlane:
    return _plane(
        per_asset={KEY: {"weth": 3_000_000.0, "usdc": 1.5}},
        per_asset_state={KEY: {"weth": P.ASSET_PRICED, "usdc": P.ASSET_PRICED}},
    )


# The completeness witness a proven-empty sheet cannot be published without: the
# chain's own transfer history, read to a named block. Every builder that wants
# an empty sheet has to carry it, which is the point — a plane that never scanned
# answers ``unpriced`` and not $0.
SCANNED = {
    "source": "chain_log_sweep",
    # Both figures, as the plane publishes them: a sheet is whole only where
    # every account it folds was scanned, so the denominator travels with the
    # numerator.
    "accounts_scanned": 1,
    "accounts_folded": 1,
    "accounts": ["0x" + "a" * 40],
    "swept_from_block": 0,
    "swept_through_block": 21_000_000,
    "basis": ["chain scan of blocks 0-21000000 over Transfer/TransferSingle/TransferBatch"],
}


def _proven_empty() -> P.ValuePlane:
    return _plane(
        per_asset_state={KEY: {"weth": P.ASSET_PROVEN_ZERO}},
        asset_set_proven_complete={KEY: SCANNED},
    )


def _below_resolution() -> P.ValuePlane:
    return _plane(per_asset_state={KEY: {"weth": P.ASSET_BELOW_RESOLUTION}})


def _unpriced() -> P.ValuePlane:
    return _plane(per_asset_state={KEY: {"weth": P.ASSET_UNPRICED}})


def _no_rows() -> P.ValuePlane:
    return _plane()


def _ambiguous() -> P.ValuePlane:
    """An implementation two proxies share, holding a priced balance of its own.

    Priced on purpose: the ambiguity must refuse a sheet that would otherwise
    have admitted, or the conjunct is only ever exercised where it changes
    nothing.
    """
    return _plane(
        per_asset={KEY: {"weth": 3_000_000.0}},
        per_asset_state={KEY: {"weth": P.ASSET_PRICED}},
        alias_ambiguous={KEY},
    )


def _truncated() -> P.ValuePlane:
    """A PRICED sheet whose asset list was read at the endpoint's page cap.

    Priced on purpose, for the reason ``_ambiguous`` is: the truncation must
    refuse a sheet that would otherwise have admitted, or the conjunct is only
    ever exercised where it changes nothing.
    """
    return _plane(
        per_asset={KEY: {"weth": 3_000_000.0}},
        per_asset_state={KEY: {"weth": P.ASSET_PRICED}},
        asset_set_truncated={KEY},
    )


# The carrier record a disposed reading is published from — the delivery
# evidence's own stored fields, not a sentence written here.
DELIVERED = {
    "shape": "fan_out_all",
    "fan_out_threshold_k": 25,
    "min_fan_out": 199,
    "delivery_count": 1,
    "scanned_from_block": 0,
    "measured_through_block": 21_000_000,
    "accounts": ["0x" + "a" * 40],
    "basis": ["delivery receipts read over blocks 0-21000000; every delivery fanned out to >= 25 recipients"],
}


def _airdrop_determined() -> P.ValuePlane:
    """A sheet whose only reading arrived as a mass distribution.

    The claim is DELIVERY SHAPE: this says how the holding arrived and never
    that it is worth nothing — real tokens have been measured arriving this way.
    """
    return _plane(
        per_asset_state={KEY: {"junk": P.ASSET_AIRDROP_DELIVERED}},
        asset_disposition={KEY: {"junk": DELIVERED}},
    )


ALL_SHAPES = {
    "priced": (_priced, 3_000_001.5, P.CEILING_ADMITTED),
    "proven_empty": (_proven_empty, 0.0, P.CEILING_PROVEN_EMPTY),
    "airdrop_determined": (_airdrop_determined, 0.0, P.CEILING_AIRDROP_DETERMINED),
    "below_resolution": (_below_resolution, None, P.CEILING_BELOW_RESOLUTION),
    "unpriced": (_unpriced, None, P.CEILING_UNPRICED),
    "asset_list_truncated": (_truncated, None, P.CEILING_ASSET_LIST_TRUNCATED),
    "no_rows": (_no_rows, None, P.CEILING_NO_ROWS),
    "alias_ambiguous": (_ambiguous, None, P.CEILING_ALIAS_AMBIGUOUS),
}


@pytest.mark.parametrize("shape", sorted(ALL_SHAPES))
def test_every_sheet_shape_answers_under_its_own_reason(shape: str):
    build, expected_usd, expected_reason = ALL_SHAPES[shape]
    usd, reason = P.ceiling_for(build(), KEY)
    assert (usd, reason) == (expected_usd, expected_reason)


def test_the_eight_shapes_cover_the_whole_vocabulary():
    """No reason may ship without a case: an unexercised token is a claim."""
    assert {reason for _, _, reason in ALL_SHAPES.values()} == set(P.CEILING_REASONS)


@pytest.mark.parametrize("shape", sorted(ALL_SHAPES))
def test_a_number_is_returned_on_exactly_the_admitting_reasons(shape: str):
    """``usd is not None`` and the reason token must never disagree.

    The caller is allowed to branch on either. If a refusal ever carried a
    figure, a not_determined magnitude would be published as a bound; if an
    admit ever carried ``None``, a proven $0 ceiling would vanish into the
    fallthrough.
    """
    build, _, _ = ALL_SHAPES[shape]
    usd, reason = P.ceiling_for(build(), KEY)
    assert reason in P.CEILING_REASONS
    assert (usd is not None) == (reason in P.CEILING_ADMITTING_REASONS)


def test_a_proven_empty_sheet_admits_a_zero_rather_than_refusing():
    """The earned negative, stated as the two shortcuts that get it wrong."""
    plane = _proven_empty()
    assert plane.sheet_state(KEY) == P.SHEET_PROVEN_EMPTY
    assert plane.sheet_state(KEY) != P.SHEET_PRICED
    assert plane.total(KEY) == 0.0

    usd, reason = P.ceiling_for(plane, KEY)
    assert usd == 0.0
    assert reason == P.CEILING_PROVEN_EMPTY
    assert reason in P.CEILING_ADMITTING_REASONS
    assert reason != P.CEILING_ADMITTED


def test_the_three_undetermined_sheets_refuse_under_three_different_reasons():
    """Dust, unpriced and never-observed are three gaps, not one."""
    answers = {
        P.ceiling_for(_below_resolution(), KEY),
        P.ceiling_for(_unpriced(), KEY),
        P.ceiling_for(_no_rows(), KEY),
    }
    assert answers == {
        (None, P.CEILING_BELOW_RESOLUTION),
        (None, P.CEILING_UNPRICED),
        (None, P.CEILING_NO_ROWS),
    }


def test_an_ambiguous_implementation_refuses_however_the_key_was_folded():
    """The refusal survives the caller's canonicalisation.

    An implementation two proxies share is aliased onto nothing, so
    ``canonical()`` is the identity on it and folding first cannot launder the
    ambiguity away. The caller passes a canonical key; this is why that is safe.
    """
    plane = _ambiguous()
    assert plane.canonical(KEY) == KEY
    assert P.ceiling_for(plane, KEY) == (None, P.CEILING_ALIAS_AMBIGUOUS)
    assert P.ceiling_for(plane, plane.canonical(KEY)) == (None, P.CEILING_ALIAS_AMBIGUOUS)


def test_the_ceiling_is_read_at_the_canonical_key():
    """An implementation's ceiling is the proxy's sheet, counted once."""
    plane = _plane(
        per_asset={OTHER: {"weth": 12.0}},
        per_asset_state={OTHER: {"weth": P.ASSET_PRICED}},
        alias={KEY: OTHER},
    )
    assert P.ceiling_for(plane, KEY) == (12.0, P.CEILING_ADMITTED)
    assert P.ceiling_for(plane, OTHER) == (12.0, P.CEILING_ADMITTED)


def test_a_truncated_asset_list_refuses_the_sheet_that_would_otherwise_admit():
    """A page-capped list is a FLOOR over the holdings, never an at-most.

    The state cannot carry this: the same rows read whole and read cut off both
    answer ``priced``, so the truncation has to refuse ahead of the state or a
    prefix of an asset list gets published as a bound on the whole of it.
    """
    plane = _truncated()
    assert plane.sheet_state(KEY) == P.SHEET_PRICED
    assert plane.total(KEY) == 3_000_000.0

    usd, reason = P.ceiling_for(plane, KEY)
    assert (usd, reason) == (None, P.CEILING_ASSET_LIST_TRUNCATED)
    assert reason not in P.CEILING_ADMITTING_REASONS


def test_a_truncated_list_refuses_a_proven_empty_sheet_too():
    """The earned negative is earned over the list that was READ.

    "Every asset on this sheet is witnessed zero" is not "this entity holds
    nothing" when the sheet stops at entry 100 — so the $0 admit is refused for
    the same reason the priced one is, and under the same token.
    """
    plane = _plane(
        per_asset_state={KEY: {"weth": P.ASSET_PROVEN_ZERO}},
        asset_set_proven_complete={KEY: SCANNED},
        asset_set_truncated={KEY},
    )
    assert plane.sheet_state(KEY) == P.SHEET_PROVEN_EMPTY
    assert P.ceiling_for(plane, KEY) == (None, P.CEILING_ASSET_LIST_TRUNCATED)


def test_truncation_is_read_at_the_canonical_key_in_both_directions():
    """One sheet, so one truncation: it cannot be laundered by which key is asked.

    The proxy and its implementation are the one entity whose rows are folded
    together, and a capped read of that entity truncates the list whichever key
    the caller arrives with.
    """
    plane = _plane(
        per_asset={OTHER: {"weth": 12.0}},
        per_asset_state={OTHER: {"weth": P.ASSET_PRICED}},
        alias={KEY: OTHER},
        asset_set_truncated={OTHER},
    )
    assert plane.asset_set_is_truncated(KEY) and plane.asset_set_is_truncated(OTHER)
    assert P.ceiling_for(plane, KEY) == (None, P.CEILING_ASSET_LIST_TRUNCATED)
    assert P.ceiling_for(plane, OTHER) == (None, P.CEILING_ASSET_LIST_TRUNCATED)


def test_an_untruncated_sheet_is_not_thereby_claimed_complete():
    """Absence from the set is the absence of a witness, in one direction only.

    A page shorter than the cap proves this read was not cut off and never that
    the index behind it is whole, so the plane carries the truncated case alone
    and the ceiling that admits beside it rests on the sheet's own state — the
    same admission it rested on before this conjunct existed.
    """
    plane = _priced()
    assert plane.asset_set_truncated == set()
    assert plane.asset_set_is_truncated(KEY) is False
    assert P.ceiling_for(plane, KEY) == (3_000_001.5, P.CEILING_ADMITTED)


def test_an_unregistered_sheet_state_raises_instead_of_refusing_under_a_borrowed_reason(
    monkeypatch: pytest.MonkeyPatch,
):
    """A sixth sheet state must not inherit a fifth state's disclosure.

    ``_CEILING_REFUSALS`` is read without a default for this reason: a ``.get``
    fallback would publish "no rows were ever observed" about a fact nobody has
    classified, and the refusal tokens are the pipeline work list.
    """
    monkeypatch.setattr(P.ValuePlane, "sheet_state", lambda self, key: "sheet_state_nobody_registered")
    with pytest.raises(ValueError, match="no registered ceiling reason"):
        P.ceiling_for(_no_rows(), KEY)


def test_the_resolver_answers_the_value_conjuncts_only():
    """It never sees a capability, so it can never have checked one.

    Guards the docstring's contract by construction: the signature carries a
    plane and a key and nothing else, so a caller cannot read an admitted
    ceiling as "code control was proven here".
    """
    import inspect

    assert list(inspect.signature(P.ceiling_for).parameters) == ["plane", "key"]


# --- the empty claim's own conjuncts ----------------------------------------
# ``proven_empty`` is the only state on this plane that publishes a NUMBER out of
# an absence, so it is the one with a set conjunct beside its quantity conjunct.
# Each refusal below is a different missing witness, closed by different work.


def test_the_quantities_alone_do_not_publish_an_empty_sheet():
    """Zeros over a list nobody established say nothing about the entity.

    The reading is unchanged — the quantity IS witnessed zero — and the sheet
    still refuses, because "every asset is zero" is a claim about a set, and the
    set is what the scan supplies. The refusal publishes ``unpriced``: something
    was observed here and no number covers it, which is the fail-closed
    direction and never a $0.
    """
    plane = _plane(per_asset_state={KEY: {"weth": P.ASSET_PROVEN_ZERO}})
    assert plane.per_asset_state[KEY]["weth"] == P.ASSET_PROVEN_ZERO
    assert plane.proven_empty_refusal(KEY) == P.EMPTY_REFUSED_ASSET_SET_NOT_PROVEN_COMPLETE
    assert plane.sheet_state(KEY) == P.SHEET_UNPRICED
    assert plane.total(KEY) is None
    assert P.ceiling_for(plane, KEY) == (None, P.CEILING_UNPRICED)

    plane.asset_set_proven_complete[KEY] = SCANNED
    assert plane.proven_empty_refusal(KEY) is None
    assert plane.sheet_state(KEY) == P.SHEET_PROVEN_EMPTY
    assert plane.total(KEY) == 0.0
    assert P.ceiling_for(plane, KEY) == (0.0, P.CEILING_PROVEN_EMPTY)


def test_completeness_is_read_at_the_canonical_key_like_every_other_sheet_question():
    """One sheet, one asset list: the fold decides where the witness applies."""
    plane = _plane(
        per_asset_state={OTHER: {"weth": P.ASSET_PROVEN_ZERO}},
        alias={KEY: OTHER},
        asset_set_proven_complete={OTHER: SCANNED},
    )
    assert plane.asset_set_is_proven_complete(KEY) is True
    assert plane.sheet_state(KEY) == plane.sheet_state(OTHER) == P.SHEET_PROVEN_EMPTY
    assert P.ceiling_for(plane, KEY) == (0.0, P.CEILING_PROVEN_EMPTY)


@pytest.mark.parametrize(
    "entry,resolved",
    [
        ({"address": "0x1", "kind": "typed", "quantity_readable": True, "quantity": "0"}, True),
        ({"address": "0x1", "kind": "typed", "quantity_readable": True, "quantity": "1"}, False),
        ({"address": "0x1", "kind": "typed", "quantity_readable": False, "quantity": None}, False),
        ({"address": "0x1", "kind": "typed", "quantity_readable": True, "quantity": None}, False),
        ({"address": "0x1", "kind": "typed", "quantity_readable": "yes", "quantity": "0"}, False),
        ({"address": "0x1"}, False),
        ("not a record", False),
        # A quantity SUMMED OVER TOKEN IDS is an all-quantifier over an inventory,
        # so it says nothing at all unless the record also says the inventory is
        # whole. A per-id zero over a prefix of the ids is the shape that would
        # publish "holds nothing" over ids nobody read.
        (
            {
                "address": "0x1",
                "kind": "typed",
                "quantity_readable": True,
                "quantity": "0",
                "quantity_basis": "balance_of_batch_per_id",
                "ids_complete": True,
            },
            True,
        ),
        (
            {
                "address": "0x1",
                "kind": "typed",
                "quantity_readable": True,
                "quantity": "0",
                "quantity_basis": "balance_of_batch_per_id",
                "ids_complete": False,
            },
            False,
        ),
        (
            {
                "address": "0x1",
                "kind": "typed",
                "quantity_readable": True,
                "quantity": "0",
                "quantity_basis": "owner_of_per_id",
            },
            False,
        ),
        (
            {
                "address": "0x1",
                "kind": "typed",
                "quantity_readable": True,
                "quantity": "0",
                "quantity_basis": "balance_of_account_id_per_id",
                "ids_complete": "yes",
            },
            False,
        ),
        # An ADDRESS-level read covers the holder's whole position, so no
        # inventory stands behind it and none is asked for.
        (
            {
                "address": "0x1",
                "kind": "typed",
                "quantity_readable": True,
                "quantity": "0",
                "quantity_basis": "balance_of_address",
                "ids_complete": False,
            },
            True,
        ),
    ],
)
def test_only_a_readable_zero_resolves_a_typed_receipt(entry, resolved: bool):
    """An ERC-721/1155 arrival is immutable; whether it is still HELD is not.

    Exactly one shape closes it — the holding read back and read back zero. An
    unreadable ``balanceOf`` (ERC-1155 has none taking an address alone) is
    not_determined, a readable non-zero count is a held item, and a malformed
    record is evidence nobody can read. None of the three may stand behind
    "holds nothing", and a truthy-but-not-``True`` flag is not a witness either.
    """
    assert P.typed_receipt_is_resolved(entry) is resolved


def test_an_unresolved_typed_receipt_refuses_the_empty_sheet_and_publishes_unpriced():
    """ "Holds nothing" is false while a typed token may still be held.

    The count is not a value either — ``balanceOf`` on a 721 answers a number of
    ITEMS — so the entity publishes ``unpriced`` rather than a dollar figure in
    either direction.
    """
    unreadable = {"address": "0xnft", "kind": "typed", "quantity_readable": False, "quantity": None}
    plane = _plane(
        per_asset_state={KEY: {"weth": P.ASSET_PROVEN_ZERO}},
        asset_set_proven_complete={KEY: SCANNED},
        typed_receipts_unresolved={KEY: [unreadable]},
    )
    assert plane.unresolved_typed_receipts(KEY) == [unreadable]
    assert plane.proven_empty_refusal(KEY) == P.EMPTY_REFUSED_TYPED_RECEIPT_UNRESOLVED
    assert plane.sheet_state(KEY) == P.SHEET_UNPRICED
    assert plane.total(KEY) is None
    assert P.ceiling_for(plane, KEY) == (None, P.CEILING_UNPRICED)


def test_a_typed_receipt_with_no_fungible_reading_is_not_no_rows():
    """``no_rows`` says nothing was observed, and a receipt IS an observation.

    Left as ``no_rows`` the entity would refuse its ceiling under "no balance was
    ever observed", which sends the operator to the wrong pipeline: the balance
    WAS observed and the typed holding is the part nobody answered.
    """
    plane = _plane(
        asset_set_proven_complete={KEY: SCANNED},
        typed_receipts_unresolved={KEY: [{"address": "0xnft", "quantity_readable": False, "quantity": None}]},
    )
    assert plane.per_asset_state.get(KEY) is None
    assert plane.sheet_state(KEY) == P.SHEET_UNPRICED
    assert P.ceiling_for(plane, KEY) == (None, P.CEILING_UNPRICED)


def test_an_unpriced_restaking_position_refuses_the_empty_sheet():
    """The cross-plane gate: a $0 here would contradict a plane in the same document.

    The restaking plane carries quantities with no USD column at this node, so
    the priced sheet being all zeros is a fact about the priced sheet and not
    about the node. Publishing the $0 would also let the fold bound a magnitude
    at zero over holdings nobody priced.
    """
    plane = _plane(
        per_asset_state={KEY: {"weth": P.ASSET_PROVEN_ZERO}},
        asset_set_proven_complete={KEY: SCANNED},
        unpriced_positions={KEY: [{"asset": "eigenlayer_beacon_shares_wei", "quantity_wei": 3e19}]},
    )
    assert plane.proven_empty_refusal(KEY) == P.EMPTY_REFUSED_UNPRICED_POSITIONS
    assert plane.sheet_state(KEY) == P.SHEET_UNPRICED
    assert P.ceiling_for(plane, KEY) == (None, P.CEILING_UNPRICED)


def test_every_refusal_token_has_a_case_and_they_do_not_collapse():
    """The refusals are the work list, so an unexercised token is a claim."""
    seen = set()
    for refusal, plane in (
        (P.EMPTY_REFUSED_ASSET_SET_NOT_PROVEN_COMPLETE, _plane(per_asset_state={KEY: {"w": P.ASSET_PROVEN_ZERO}})),
        (
            P.EMPTY_REFUSED_UNSCANNED_ACCOUNT,
            _plane(
                per_asset_state={KEY: {"w": P.ASSET_PROVEN_ZERO}},
                asset_set_accounts_unscanned={KEY: ["0x" + "c" * 40]},
            ),
        ),
        (
            P.EMPTY_REFUSED_TYPED_RECEIPT_UNRESOLVED,
            _plane(
                per_asset_state={KEY: {"w": P.ASSET_PROVEN_ZERO}},
                asset_set_proven_complete={KEY: SCANNED},
                typed_receipts_unresolved={KEY: [{"address": "0xnft"}]},
            ),
        ),
        (
            P.EMPTY_REFUSED_UNPRICED_POSITIONS,
            _plane(
                per_asset_state={KEY: {"w": P.ASSET_PROVEN_ZERO}},
                asset_set_proven_complete={KEY: SCANNED},
                unpriced_positions={KEY: [{"asset": "shares", "quantity_wei": 1.0}]},
            ),
        ),
    ):
        assert plane.proven_empty_refusal(KEY) == refusal
        seen.add(refusal)
    assert seen == set(P.EMPTY_REFUSALS)


def test_the_native_fact_consumer_reads_the_same_answer_from_either_witness():
    """§1 D3's non-disturbance rule, asserted rather than assumed.

    ``native_value_state`` is ``native_fact``'s existing consumer and feeds the
    fold's native-only reach branch. A proven zero reaches it two ways — the
    fetch record's status for an absent row, and a stored zero-quantity row now
    that the producer writes one — and both must answer the same determined 0.0
    under the same label, or the branch's answer would depend on which writer
    got there first.
    """
    from_fact = _plane()
    from_fact.native_fact = {KEY: "proven_zero_at_block_21000000"}
    from_row = _plane(
        per_asset={KEY: {P.NATIVE_ASSET: 0.0}},
        per_asset_state={KEY: {P.NATIVE_ASSET: P.ASSET_PROVEN_ZERO}},
        asset_set_proven_complete={KEY: SCANNED},
    )
    for plane in (from_fact, from_row):
        answer = P.native_value_state(plane, KEY)
        assert (answer.is_determined, answer.state, answer.value) == (True, "proven_zero", 0.0)

    # A nonzero holding keeps the plain label, and a fetch record that proves
    # nothing keeps not_determined — neither moves.
    held = _plane(per_asset={KEY: {P.NATIVE_ASSET: 12.5}}, per_asset_state={KEY: {P.NATIVE_ASSET: P.ASSET_PRICED}})
    assert P.native_value_state(held, KEY).state == "proven"
    blank = _plane()
    blank.native_fact = {KEY: "not_determined"}
    assert P.native_value_state(blank, KEY).is_determined is False


def test_an_account_of_the_sheet_nobody_scanned_refuses_it_under_its_own_token():
    """A scan that covered one of two addresses did not cover the sheet.

    The two refusals are different work: "nobody has scanned this entity" waits
    on the escalation reaching it at all, while "one folded account was never
    read at its own address" is closed by one producer cycle over a named list —
    so the addresses are published and the token is its own.
    """
    plane = _plane(
        per_asset_state={KEY: {"weth": P.ASSET_PROVEN_ZERO}},
        asset_set_accounts_unscanned={KEY: ["0x" + "c" * 40]},
    )
    assert plane.asset_set_is_proven_complete(KEY) is False
    assert plane.proven_empty_refusal(KEY) == P.EMPTY_REFUSED_UNSCANNED_ACCOUNT
    assert plane.sheet_state(KEY) == P.SHEET_UNPRICED
    assert plane.total(KEY) is None
    assert P.ceiling_for(plane, KEY) == (None, P.CEILING_UNPRICED)

    # Scanned at last: the same sheet, the same readings, and now an admit.
    plane.asset_set_accounts_unscanned.clear()
    plane.asset_set_proven_complete[KEY] = SCANNED
    assert plane.proven_empty_refusal(KEY) is None
    assert P.ceiling_for(plane, KEY) == (0.0, P.CEILING_PROVEN_EMPTY)


def test_the_typed_cause_is_named_ahead_of_the_completeness_it_caused():
    """The published token has to aim a reader at the pipeline that closes it.

    A producer withholds the scan's completeness BECAUSE a typed receipt had no
    readable holding, so a sheet carrying both is refused for the receipt. Saying
    "nobody scanned this" there points at a scan that ran.
    """
    plane = _plane(
        per_asset_state={KEY: {"weth": P.ASSET_PROVEN_ZERO}},
        typed_receipts_unresolved={KEY: [{"address": "0xnft", "quantity_readable": False, "quantity": None}]},
    )
    assert plane.asset_set_is_proven_complete(KEY) is False
    assert plane.proven_empty_refusal(KEY) == P.EMPTY_REFUSED_TYPED_RECEIPT_UNRESOLVED
