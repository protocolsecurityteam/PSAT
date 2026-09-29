"""The confidence side of the ceiling (CC8).

The reach-magnitude term credited a signal on two paths: a witness on its own call, or a
composed destination witness. A sheet ceiling is a THIRD answer (a proven bound from a balance
observation); leaving it uncredited would report as open a question the document answers. These
cases pin what is credited, what is not, and that the credit is not the vacuous kind.

One of the twenty sections of the former ``test_scoring_redteam.py``.
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
    """Code control at ``C``, proven for an EOA, reaching ``C`` itself.

    Overrides are MERGED (not splatted after the defaults) so a case can move the signal
    without the keyword colliding with the default it replaces.
    """
    base: dict[str, Any] = {
        "authority_openness": "restricted",
        "principal_state": "enumerated",
        "principal_refs": (PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    }
    return sig(**{**base, **over})


def test_cc8_a_sheet_ceiling_answers_the_reach_magnitude_question(fold):
    """The third credit path, counted under its own name.

    The signal has no magnitude witness and composes nothing (code control names no destination
    function), so it was counted as open while the row beside it published a banded figure. The
    credit is counted APART from the other two: they are proofs of different strengths, and a
    consumer sizing what was MEASURED must be able to subtract the one that only bounds.
    """
    document = fold(
        [_ceiling_signal()],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}}),
    )
    census = _magnitude(document)
    assert census["magnitude_sheet_ceiling"] == 1
    assert census["sheet_ceiling_by_capability"] == {"upgrade.implementation": 1}
    # Counted as ANSWERED in the term's own census, and by neither older path.
    assert census["by_capability"]["upgrade.implementation"] == [1, 1]
    assert census["magnitude_witnessed"] == 1
    assert census["magnitude_composed"] == 0
    assert document.model_parameters["confidence_detail"]["reach_magnitude_witnessed_pct"] > 0.0
    assert _cc_row(document)["entities_priced_from_a_sheet_ceiling"] == [KEY_C]


def test_cc8_a_refused_sheet_ceiling_is_not_credited(fold):
    """No ceiling, no credit (anti-regression for "reached money, so answered").

    Same code control over the same key; only the SHEET differs. Nothing was observed at the
    node, so nothing bounds the move; crediting it would answer with a number no row publishes.
    """
    plane = value_plane({}, contracts=(KEY_C,), per_asset_state={KEY_C: {}})
    assert plane.sheet_state(KEY_C) == P.SHEET_NO_ROWS
    document = fold([_ceiling_signal()], principals={1: facts(1, EOA, "eoa")}, value=plane)
    census = _magnitude(document)
    assert census["magnitude_sheet_ceiling"] == 0
    assert census["sheet_ceiling_by_capability"] == {}
    assert census["by_capability"]["upgrade.implementation"] == [0, 1]
    assert _cc_row(document)["entities_priced_from_a_sheet_ceiling"] == []


def test_cc8_gate_control_over_a_priced_node_earns_no_ceiling_credit(fold):
    """CC2's anti-regression, one level up.

    The node is priced and the reach proven, but the capability is not code control, so the
    vault's own share math, caps and caller conditions still stand unexamined. The row earns no
    ceiling and the term must not credit one (a credit the row cannot show has no carrier).
    """
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
    """It carries a witness (the balance observation), so the vacuous share stays put.

    ``reach_magnitude_vacuous_credit_pct`` exists because a proven-codeless entity answers this
    term with NO magnitude witness, and the headline alone would let a perimeter of EOAs read as
    answered. A sheet ceiling is the opposite: answered because something was OBSERVED, so it
    must move the witnessed term and leave the vacuous share where it was.
    """
    # The two documents differ ONLY in the capability, so perimeter, denominator and the codeless
    # entity's weight are identical and the ceiling credit is the single moving part (varying the
    # SHEET would move the entity's band and the denominator underneath the comparison).
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
    # The term's HEADROOM is a different quantity (one field apart by name) that neither case moves.
    assert ceiling_detail["reach_magnitude_ceiling_pct"] == plain_detail["reach_magnitude_ceiling_pct"]


def test_cc8_every_credited_ceiling_has_a_carrier_in_the_published_document(fold):
    """The S4 population rule, over a document carrying both answers.

    The credited set is the fold's OWN per-entity standing set: signals whose sheet ceiling is
    the figure a row publishes at that entity. Its two revocations (a ceiling a larger
    contribution displaces; one per-key sheet reconciliation withdraws) are not constructible
    here: every alternative candidate is ``min(held, magnitude)`` against the node's own sheet
    (``fold._entity_contribution``), so a code-control candidate can TIE but never beat it, and a
    tie keeps the credit. What is testable is the invariant they guard: no credit outruns the rows.
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
    """Step 4's provenance block, derived from the rows and nothing else.

    These dollars are deliberately absent from ``exposure_usd``, so a reader of the grade
    figures cannot see how much the model bounded and declined to charge. Every count is taken
    off the published rows, refusals counted by the reason the SHEET gave.
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
    # Named zeros over the closed vocabularies: an absent reason would read the same as "rule did
    # not fire here" and "rule not in the model", and only the first is a fact about the protocol.
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
    """Dollars per distinct ENTITY, because a sheet ceiling is a fact about a node.

    Two principals with code control over one node publish the SAME sheet number; summing over
    rows would double the money. The agreement is checked, not assumed (a disagreement would
    mean per-key reconciliation let two figures stand) and published as a count.
    """
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
    # Two signals, one sheet: the two meters count different things and both are published.
    assert block["signals_credited_in_confidence"] == 2


def test_cc8_one_node_under_two_code_control_capabilities_counts_once_in_the_population(fold):
    """The capability breakdown counts MEMBERSHIPS; the population counts entities.

    A node reached by two code-control capabilities sits in two buckets but is one entity with
    one sheet. Dollars are deduped and the breakdown is not, so the document says so with a
    count, not a caveat.
    """
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
