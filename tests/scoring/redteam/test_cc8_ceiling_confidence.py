"""CC8: a sheet ceiling is a third way to answer reach magnitude, beside a witness on the call and a composed
destination witness.
"""

from __future__ import annotations

from typing import Any

from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.schema import FunctionSignal, PrincipalRef, entity_key
from tests.support.scoring_builders import (
    EOA,
    KEY_C,
    KEY_V,
    OWNERS,
    SAFE,
    VAULT,
    _cc_row,
    facts,
    fold,  # noqa: F401  (fold fixture, registered by import)
    proven,
    reaches,
    sig,
    value_plane,
)


def _magnitude(document) -> dict[str, Any]:
    return document.model_parameters["confidence_detail"]["reach_magnitude_signals"]


def _ceiling_signal(**over: Any) -> FunctionSignal:
    """Overrides are merged so a case can move the signal without colliding with the default keyword."""
    base: dict[str, Any] = {
        "authority_openness": "restricted",
        "principal_state": "enumerated",
        "principal_refs": (PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    }
    return sig(**{**base, **over})


def test_cc8_a_sheet_ceiling_answers_the_reach_magnitude_question(fold):
    """Counted apart from the other two paths so a consumer can subtract the one that only bounds."""
    document = fold(
        [_ceiling_signal()],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}}),
    )
    census = _magnitude(document)
    assert census["magnitude_sheet_ceiling"] == 1
    assert census["sheet_ceiling_by_capability"] == {"upgrade.implementation": 1}
    assert census["by_capability"]["upgrade.implementation"] == [1, 1]
    assert census["magnitude_witnessed"] == 1
    assert census["magnitude_composed"] == 0
    assert document.model_parameters["confidence_detail"]["reach_magnitude_witnessed_pct"] > 0.0
    assert _cc_row(document)["entities_priced_from_a_sheet_ceiling"] == [KEY_C]


def test_cc8_a_refused_sheet_ceiling_is_not_credited(fold):
    """Crediting a refused sheet would answer with a number no row publishes."""
    plane = value_plane({}, contracts=(KEY_C,), per_asset_state={KEY_C: {}})
    assert plane.sheet_state(KEY_C) == P.SHEET_NO_ROWS
    document = fold([_ceiling_signal()], principals={1: facts(1, EOA, "eoa")}, value=plane)
    census = _magnitude(document)
    assert census["magnitude_sheet_ceiling"] == 0
    assert census["sheet_ceiling_by_capability"] == {}
    assert census["by_capability"]["upgrade.implementation"] == [0, 1]
    assert _cc_row(document)["entities_priced_from_a_sheet_ceiling"] == []


def test_cc8_gate_control_over_a_priced_node_earns_no_ceiling_credit(fold):
    """The vault's own code still stands, so the row earns no ceiling and the term must not credit one."""
    signal = _ceiling_signal(claim_id="authority.replace", function_name="setAuthority", selector="0x11112222")
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}}),
    )
    census = _magnitude(document)
    assert census["magnitude_sheet_ceiling"] == 0
    assert census["by_capability"]["authority.replace"] == [0, 1]
    assert _cc_row(document, "authority.replace")["entities_priced_from_a_sheet_ceiling"] == []


def test_cc8_a_ceiling_credit_is_not_vacuous_credit(fold):
    """The vacuous share exists for codeless entities answered with no witness; a ceiling was observed, so it moves
    the witnessed term.
    """
    # Only the capability differs, so the ceiling credit is the single moving part.
    eoa_key = entity_key("ethereum", EOA)

    def _document(**over: Any):
        return fold(
            [_ceiling_signal(**over)],
            principals={1: facts(1, EOA, "eoa")},
            value=value_plane(
                {KEY_C: {"usdc": 5_000_000.0}},
                contracts=(KEY_C, eoa_key),
                per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}},
            ),
            eoas={eoa_key},
        )

    with_ceiling = _document()
    without = _document(claim_id="authority.replace", function_name="setAuthority", selector="0x11112222")
    ceiling_detail = with_ceiling.model_parameters["confidence_detail"]
    plain_detail = without.model_parameters["confidence_detail"]
    assert _magnitude(with_ceiling)["magnitude_sheet_ceiling"] == 1
    assert _magnitude(without)["magnitude_sheet_ceiling"] == 0
    assert ceiling_detail["reach_magnitude_vacuous_credit_pct"] > 0.0
    assert ceiling_detail["reach_magnitude_vacuous_credit_pct"] == plain_detail["reach_magnitude_vacuous_credit_pct"]
    assert ceiling_detail["reach_magnitude_witnessed_pct"] > plain_detail["reach_magnitude_witnessed_pct"]
    assert (
        ceiling_detail["reach_magnitude_witnessed_pct"] - ceiling_detail["reach_magnitude_vacuous_credit_pct"]
        > plain_detail["reach_magnitude_witnessed_pct"] - plain_detail["reach_magnitude_vacuous_credit_pct"]
    )
    assert ceiling_detail["reach_magnitude_ceiling_pct"] == plain_detail["reach_magnitude_ceiling_pct"]


def test_cc8_every_credited_ceiling_has_a_carrier_in_the_published_document(fold):
    """The two revocations aren't constructible here (a code-control candidate can tie but never beat the node's own
    sheet), so this checks the invariant they guard: no credit outruns the rows.
    """
    priced = _ceiling_signal()
    unpriced = _ceiling_signal(
        deployment_address=VAULT,
        function_name="upgradeToVault",
        selector="0x55556666",
        **reaches(KEY_V),
    )
    plane = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        contracts=(KEY_C, KEY_V),
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}, KEY_V: {}},
    )
    document = fold([priced, unpriced], principals={1: facts(1, EOA, "eoa")}, value=plane)
    census = _magnitude(document)
    carriers = {
        entity
        for row in (*document.findings, *(s for f in document.findings for s in f["subsumed_capabilities"]))
        for entity in (row.get("entities_priced_from_a_sheet_ceiling") or [])
    }
    assert carriers == {KEY_C}
    assert census["magnitude_sheet_ceiling"] == 1
    assert census["by_capability"]["upgrade.implementation"] == [1, 2]


def test_cc8_the_document_rolls_the_ceiling_population_up_with_its_dollars(fold):
    """These dollars are absent from ``exposure_usd``, so this block is the only place a reader sees what was bounded
    but not charged.
    """
    priced = _ceiling_signal()
    refused = _ceiling_signal(
        deployment_address=VAULT,
        function_name="upgradeToVault",
        selector="0x55556666",
        **reaches(KEY_V),
    )
    plane = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        contracts=(KEY_C, KEY_V),
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}, KEY_V: {}},
    )
    block = fold([priced, refused], principals={1: facts(1, EOA, "eoa")}, value=plane).provenance["sheet_ceilings"]
    assert block["entities_priced_from_a_sheet_ceiling"] == 1
    assert block["ceiling_usd_over_distinct_entities"] == 5_000_000.0
    assert block["entities_by_capability"] == {"upgrade.implementation": 1}
    assert block["entities_in_more_than_one_capability"] == 0
    # An absent reason would conflate "didn't fire" with "not in the model".
    assert block["entities_by_ceiling_reason"] == {
        P.CEILING_ADMITTED: 1,
        P.CEILING_PROVEN_EMPTY: 0,
        P.CEILING_AIRDROP_DETERMINED: 0,
    }
    assert block["calls_refused_by_reason"] == {
        P.CEILING_NO_ROWS: 1,
        P.CEILING_BELOW_RESOLUTION: 0,
        P.CEILING_UNPRICED: 0,
        P.CEILING_ASSET_LIST_TRUNCATED: 0,
        P.CEILING_ALIAS_AMBIGUOUS: 0,
    }
    assert set(block["calls_refused_by_reason"]) == set(FOLD.CEILING_REFUSAL_REASONS)
    assert block["entities_by_bound_direction"] == {FOLD.BOUND_DIRECTION_NOT_DETERMINED: 0, "ceiling": 1}
    assert block["entities_publishing_more_than_one_figure"] == []
    assert block["entities_withheld_on_sheet_reconciliation"] == 0
    assert block["signals_credited_in_confidence"] == 1
    assert block["signals_credited_by_capability"] == {"upgrade.implementation": 1}
    assert "must never be rendered as dollars at risk" in block["reading"]


def test_cc8_one_sheet_read_by_two_rows_is_counted_once_in_the_rollup(fold):
    """Summing over rows would double the money; the agreement is checked and published as a count."""
    first = _ceiling_signal()
    second = _ceiling_signal(
        function_name="upgradeToAndCall",
        selector="0x77778888",
        principal_refs=(PrincipalRef(2, "ethereum", SAFE),),
    )
    document = fold(
        [first, second],
        principals={1: facts(1, EOA, "eoa"), 2: facts(2, SAFE, "safe", owners=OWNERS, threshold=3)},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}}),
    )
    block = document.provenance["sheet_ceilings"]
    assert block["rows_publishing_a_sheet_ceiling"]["findings"] == 2
    assert block["entities_priced_from_a_sheet_ceiling"] == 1
    assert block["ceiling_usd_over_distinct_entities"] == 5_000_000.0
    assert block["entities_publishing_more_than_one_figure"] == []
    assert block["signals_credited_in_confidence"] == 2


def test_cc8_one_node_under_two_code_control_capabilities_counts_once_in_the_population(fold):
    """Dollars are deduped but the capability breakdown is not."""
    upgrade = _ceiling_signal()
    execute = _ceiling_signal(claim_id="exec.arbitrary", function_name="execute", selector="0x33334444")
    document = fold(
        [upgrade, execute],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}}),
    )
    block = document.provenance["sheet_ceilings"]
    assert block["entities_by_capability"] == {"exec.arbitrary": 1, "upgrade.implementation": 1}
    assert sum(block["entities_by_capability"].values()) == 2
    assert block["entities_priced_from_a_sheet_ceiling"] == 1
    assert block["entities_in_more_than_one_capability"] == 1
    assert block["ceiling_usd_over_distinct_entities"] == 5_000_000.0
    assert "sums past the distinct-entity count" in block["reading"]
