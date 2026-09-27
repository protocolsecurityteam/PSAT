"""The confidence side of the ceiling (CC8).

The reach-magnitude term asks "was this reach's magnitude answered", and it
credited a signal on exactly two paths: a witness on its own call, or a
composed destination witness. A sheet ceiling is a THIRD answer — a proven
bound, from a balance observation — and leaving it uncredited would report a
question as open that the document answers on its own page. The cases below
pin what is credited, what is not, and that the credit is not the vacuous kind.

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

    The overrides are MERGED rather than splatted after the defaults so a case
    can move the signal to another deployment or another reach without the
    keyword colliding with the default it means to replace.
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

    The signal carries no magnitude witness of its own and composes nothing —
    code control names no destination function — so before this path it was
    counted as an open question while the row beside it published a banded
    figure. The term now credits it, and the credit is counted APART from the
    other two: the three answers are three different proofs of three different
    strengths, and a consumer sizing what the pipeline MEASURED has to be able to
    subtract the one that only bounds.
    """
    document = fold(
        [_ceiling_signal()],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}}),
    )
    census = _magnitude(document)
    assert census["magnitude_sheet_ceiling"] == 1
    assert census["sheet_ceiling_by_capability"] == {"upgrade.implementation": 1}
    # Counted as ANSWERED in the term's own census, and by neither of the two
    # older paths.
    assert census["by_capability"]["upgrade.implementation"] == [1, 1]
    assert census["magnitude_witnessed"] == 1
    assert census["magnitude_composed"] == 0
    assert document.model_parameters["confidence_detail"]["reach_magnitude_witnessed_pct"] > 0.0
    # And it has a carrier: the row publishes the figure the credit is for.
    assert _cc_row(document)["entities_priced_from_a_sheet_ceiling"] == [KEY_C]


def test_cc8_a_refused_sheet_ceiling_is_not_credited(fold):
    """No ceiling, no credit. The anti-regression for "reached money, so answered".

    The capability is the same code control over the same key; only the SHEET
    differs. Nothing was observed at the node, so nothing bounds the move, and
    the magnitude question is exactly as open as it was — crediting it here would
    answer it with a number no row publishes, which is the whole failure mode the
    credit population was scoped to avoid.
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

    The node is priced and the reach is proven; the capability is not code
    control, so the vault's own share math, caps and caller conditions are all
    still standing and none of them has been examined. The row earns no ceiling
    and the term must not credit one either — the two surfaces answer the same
    question and a credit the row cannot show is a credit with no carrier.
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
    """It carries a witness — the balance observation — so the vacuous share stays put.

    ``reach_magnitude_vacuous_credit_pct`` exists because a proven-codeless
    entity answers this term with no magnitude witness AT ALL, and publishing the
    headline alone would let a perimeter full of EOAs read as answered magnitude.
    A sheet ceiling is the opposite case: the question is answered because
    something was OBSERVED. So the ceiling has to move the witnessed term while
    leaving the vacuous share exactly where it was, and the two figures are read
    together here because subtracting one from the other is what a consumer does.
    """
    # The two documents differ ONLY in the capability, so the perimeter, the
    # denominator and the codeless entity's weight are identical in both and the
    # ceiling credit is the single moving part. Varying the SHEET instead would
    # move the entity's own band and change the denominator underneath the
    # comparison.
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
    # The witness-backed share is what moved.
    assert (
        ceiling_detail["reach_magnitude_witnessed_pct"] - ceiling_detail["reach_magnitude_vacuous_credit_pct"]
        > plain_detail["reach_magnitude_witnessed_pct"] - plain_detail["reach_magnitude_vacuous_credit_pct"]
    )
    # And the term's HEADROOM is a different quantity that neither case moves:
    # the name collision is one field apart and they must not track each other.
    assert ceiling_detail["reach_magnitude_ceiling_pct"] == plain_detail["reach_magnitude_ceiling_pct"]


def test_cc8_every_credited_ceiling_has_a_carrier_in_the_published_document(fold):
    """The S4 population rule, over a document that carries both answers.

    The credited set is the fold's OWN per-entity standing set: the signals whose
    sheet ceiling is the figure a row actually publishes at that entity. That
    rule has two revocations built into it — a ceiling a larger contribution
    displaces, and one the per-key sheet reconciliation withdraws — and neither
    is constructible from this fixture, for a reason worth recording rather than
    working around. Every alternative candidate at the controlled node is
    ``min(held, magnitude)`` against that node's own sheet (``fold._entity_contribution``),
    so a code-control candidate can TIE the sheet and can never beat it, and a
    tie keeps the credit because each tied call did prove the published figure.
    The revocations are guards against a branch that does not exist yet; what is
    testable today is the invariant they exist to hold, which is that no credit
    outruns the rows.
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
    # One credit, and the entity it names is one a row publishes.
    assert census["magnitude_sheet_ceiling"] == 1
    assert census["by_capability"]["upgrade.implementation"] == [1, 2]


def test_cc8_the_document_rolls_the_ceiling_population_up_with_its_dollars(fold):
    """Step 4's provenance block, derived from the rows and from nothing else.

    These dollars are the one class of published magnitude deliberately absent
    from ``exposure_usd``, so a consumer reading only the grade figures has no
    way to see how much the model bounded from above and then declined to charge.
    The block is the place that says so, and every count in it is taken off what
    the rows published — including the refusals, which are counted by the reason
    the SHEET gave rather than rolled into one number.
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
    # Named zeros over the closed vocabularies: a reason absent from the map
    # would read identically as "this rule did not fire here" and "this rule is
    # not in the model", and only the first is a fact about the protocol.
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
    # The confidence pass's own count, not a second derivation of it.
    assert block["signals_credited_in_confidence"] == 1
    assert block["signals_credited_by_capability"] == {"upgrade.implementation": 1}
    assert "must never be rendered as dollars at risk" in block["reading"]


def test_cc8_one_sheet_read_by_two_rows_is_counted_once_in_the_rollup(fold):
    """Dollars per distinct ENTITY, because a sheet ceiling is a fact about a node.

    Two principals with code control over the same node both publish that node's
    sheet, and they publish the SAME number because it is the same sheet.
    Summing over rows would report twice the money that exists. The agreement is
    checked rather than assumed — a disagreement would mean the per-key
    reconciliation let two figures stand under one claim — and it is published as
    a count so a corpus where it happens says so.
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
    # Two signals, one sheet: the two meters count different things and both are
    # published, so neither is read as the other.
    assert block["signals_credited_in_confidence"] == 2


def test_cc8_one_node_under_two_code_control_capabilities_counts_once_in_the_population(fold):
    """The capability breakdown counts MEMBERSHIPS and the population counts entities.

    A node reached by two code-control capabilities is priced from its own sheet
    under both, so it sits in two buckets while being one entity holding one
    sheet. The dollars are deduped and the breakdown is not — they answer
    different questions — and a reader summing the buckets would over-count the
    population unless the document says so. It says so with a count, not with a
    caveat.
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
    # Two memberships, one entity, one sheet's worth of dollars.
    assert sum(block["entities_by_capability"].values()) == 2
    assert block["entities_priced_from_a_sheet_ceiling"] == 1
    assert block["entities_in_more_than_one_capability"] == 1
    assert block["ceiling_usd_over_distinct_entities"] == 5_000_000.0
    assert "sums past the distinct-entity count" in block["reading"]
