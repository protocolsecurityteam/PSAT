"""``planes.ceiling_for`` is pinned over hand-built planes because the corpus can't exercise every reason.

``proven_empty`` is an earned $0 that both obvious tests get wrong: ``total() is not None`` admits it unlabelled and
``sheet_state() == SHEET_PRICED`` refuses it.
"""

from __future__ import annotations

import pytest

from services.scoring import planes as P

KEY = "ethereum::0x" + "a" * 40


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


# A plane that never scanned answers ``unpriced``, not $0.
SCANNED = {
    "source": "chain_log_sweep",
    "accounts_scanned": 1,
    "accounts_folded": 1,
    "accounts": ["0x" + "a" * 40],
    "swept_from_block": 0,
    "swept_through_block": 21_000_000,
    "basis": ["chain scan of blocks 0-21000000 over Transfer/TransferSingle/TransferBatch"],
}


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


# ``proven_empty`` is the only state that publishes a number from an absence, so it has a set conjunct too.


def test_the_quantities_alone_do_not_publish_an_empty_sheet():
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
        # A per-id zero over a prefix of the ids would publish "holds nothing" over ids nobody read.
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
    """Only a holding read back as zero closes a typed receipt; ERC-1155 has no address-only ``balanceOf``."""
    assert P.typed_receipt_is_resolved(entry) is resolved


def test_a_typed_receipt_with_no_fungible_reading_is_not_no_rows():
    """``no_rows`` would send the operator to the wrong pipeline."""
    plane = _plane(
        asset_set_proven_complete={KEY: SCANNED},
        typed_receipts_unresolved={KEY: [{"address": "0xnft", "quantity_readable": False, "quantity": None}]},
    )
    assert plane.per_asset_state.get(KEY) is None
    assert plane.sheet_state(KEY) == P.SHEET_UNPRICED
    assert P.ceiling_for(plane, KEY) == (None, P.CEILING_UNPRICED)


def test_an_unpriced_restaking_position_refuses_the_empty_sheet():
    """The restaking plane has no USD column here, so a $0 would contradict it and bound a magnitude over unpriced
    holdings.
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
    """The native fact consumer preserves the answer across both witness shapes.

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

    held = _plane(per_asset={KEY: {P.NATIVE_ASSET: 12.5}}, per_asset_state={KEY: {P.NATIVE_ASSET: P.ASSET_PRICED}})
    assert P.native_value_state(held, KEY).state == "proven"
    blank = _plane()
    blank.native_fact = {KEY: "not_determined"}
    assert P.native_value_state(blank, KEY).is_determined is False
