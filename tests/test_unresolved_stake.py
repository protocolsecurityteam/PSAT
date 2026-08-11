"""The unresolved-stake ceiling: the at-most behind a finding's unanswered
questions, and the partial_proof stamp that admits a row to the levers rollup.

The figure reuses ``planes.ceiling_for`` so a sheet refused there (truncated,
unpriced, no rows) is refused here under the same token, and it never enters
lambda or exposure — the corpus's own numbers are pinned unchanged elsewhere.
"""

from __future__ import annotations

from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.schema import PrincipalRef
from tests.test_scoring_redteam import (
    EOA,
    KEY_C,
    KEY_V,
    facts,
    fold,  # noqa: F401
    proven,
    reaches,
    sig,
    value_plane,
)

REACHED = KEY_V
BEHIND = "ethereum::0x" + "7" * 40
SIZED = KEY_C

_EMPTY_WITHHELD = {"entities": 0, "entity_keys": [], "hops": 0}


def _und(*entities: str) -> list[dict[str, str]]:
    return [{"entity": e, "function": "f", "why": "reach_magnitude_not_witnessed(not_determined)"} for e in entities]


def _withheld(*entities: str) -> dict[str, object]:
    return {"entities": len(entities), "entity_keys": list(entities), "hops": 1}


def test_reached_and_behind_split_and_sum():
    plane = value_plane({REACHED: {"weth": 1_000_000.0}, BEHIND: {"usdc": 250_000.0}})
    stake = FOLD._unresolved_stake(
        _und(REACHED),
        _withheld(BEHIND),
        set(),
        plane,
        hops_not_determined=[{"reason": "gate_does_not_confer_this_scope"}],
    )
    assert stake["ceiling_usd"] == 1_250_000.0
    assert stake["entities_total"] == 2
    reached = stake["by_basis"]["reached_unwitnessed"]
    behind = stake["by_basis"]["behind_unestablished_hops"]
    assert reached["ceiling_usd"] == 1_000_000.0
    assert behind["ceiling_usd"] == 250_000.0
    # The closing witness is on the entry: the why-token class per entity for
    # reached, the hop's own refusal reason for the subtree behind it.
    assert reached["missing_witnesses"] == {"reach_magnitude_not_witnessed": 1}
    assert behind["missing_witnesses"] == {"gate_does_not_confer_this_scope": 1}
    # Itemized per entity, so a consumer sees WHICH addresses hold the ceiling.
    assert reached["entities_itemized"] == [
        {
            "entity": REACHED,
            "ceiling_usd": 1_000_000.0,
            "refusal": None,
            "missing": ["reach_magnitude_not_witnessed"],
        }
    ]
    assert behind["entities_itemized"] == [{"entity": BEHIND, "ceiling_usd": 250_000.0, "refusal": None}]
    # An unestablished hop is an earlier missing link than a magnitude: the
    # frontier is the furthest-back unanswered question.
    assert stake["proof_frontier"] == "reach"


def test_sized_entities_are_excluded_and_reached_takes_precedence():
    plane = value_plane({REACHED: {"weth": 1_000_000.0}, SIZED: {"usdc": 9_000_000.0}})
    stake = FOLD._unresolved_stake(_und(REACHED, SIZED), _withheld(REACHED), {SIZED}, plane)
    # SIZED already carries a published figure on the row; REACHED appears once,
    # under the stronger basis, not again behind the hop.
    assert stake["entities_total"] == 1
    assert set(stake["by_basis"]) == {"reached_unwitnessed"}


def test_a_refused_sheet_is_a_counted_refusal_never_a_zero():
    plane = value_plane({}, contracts=(REACHED,))
    stake = FOLD._unresolved_stake(_und(REACHED), _EMPTY_WITHHELD, set(), plane)
    assert stake["ceiling_usd"] is None
    assert stake["entities_total"] == 1
    basis = stake["by_basis"]["reached_unwitnessed"]
    assert basis["ceiling_usd"] is None
    assert basis["entities_refused_by_reason"] == {P.CEILING_NO_ROWS: 1}


def test_a_proven_empty_sheet_contributes_an_earned_zero():
    from tests.test_scoring_redteam import SCANNED

    plane = value_plane(
        per_asset_state={REACHED: {"weth": P.ASSET_PROVEN_ZERO}},
        asset_set_proven_complete={REACHED: SCANNED},
    )
    stake = FOLD._unresolved_stake(_und(REACHED), _EMPTY_WITHHELD, set(), plane)
    assert stake["ceiling_usd"] == 0.0
    assert stake["by_basis"]["reached_unwitnessed"]["entities_contributing"] == 1


def test_an_implementation_alias_cannot_recount_its_sized_proxy():
    impl = "ethereum::0x" + "8" * 40
    impl2 = "ethereum::0x" + "9" * 40
    plane = value_plane({SIZED: {"weth": 9_000_000.0}}, alias={impl: SIZED, impl2: SIZED})
    # The proxy's figure is already published on the row; both impl keys fold
    # onto it and must vanish rather than draw its sheet back out as unresolved.
    stake = FOLD._unresolved_stake(_und(impl, impl2), _EMPTY_WITHHELD, {SIZED}, plane)
    assert stake == {"ceiling_usd": None, "entities_total": 0, "proof_frontier": None, "by_basis": {}}
    # Unsized: two impls of one proxy are ONE pot, counted and summed once.
    stake = FOLD._unresolved_stake(_und(impl, impl2), _EMPTY_WITHHELD, set(), plane)
    assert stake["entities_total"] == 1
    assert stake["ceiling_usd"] == 9_000_000.0


def test_no_unresolved_entities_is_the_earned_fully_determined_state():
    plane = value_plane({})
    stake = FOLD._unresolved_stake([], _EMPTY_WITHHELD, set(), plane)
    assert stake == {"ceiling_usd": None, "entities_total": 0, "proof_frontier": None, "by_basis": {}}


def test_levers_rank_on_the_points_ceiling_then_dollars():
    def row(unit: str, points: float | None, ceiling: float | None, total: int) -> dict:
        return {
            "partial_proof": True,
            "principal_unit": unit,
            "principal": f"EOA {unit}",
            "capability": "authority.replace",
            "chain": "ethereum",
            "unresolved_stake": {
                "points_ceiling": points,
                "ceiling_usd": ceiling,
                "entities_total": total,
                "proof_frontier": "magnitude",
                "by_basis": {},
            },
        }

    # An almost-proven EOA over modest dollars outranks a weaker-proven row
    # over MORE dollars: the proven half's weight is in the rank.
    eoa_small = row("u1", 20.25, 2_000_000.0, 1)
    safe_big = row("u2", 6.3, 29_000_000.0, 62)
    unbounded = row("u3", None, None, 21)
    done = {**row("u4", None, None, 0), "partial_proof": False}
    rollup = FOLD._unresolved_levers([safe_big, eoa_small, unbounded, done])
    assert [e["principal_unit"] for e in rollup["levers"]] == ["u1", "u2", "u3"]
    assert rollup["findings_admitted"] == 3
    assert rollup["findings_fully_determined"] == 1
    # No lambda figure rides along: the grade is joined, never republished here.
    assert all("net_points_lambda" not in e for e in rollup["levers"])


def test_the_fold_stamps_the_row_and_publishes_the_rollup(fold):  # noqa: F811
    signal = sig(
        claim_id="authority.replace",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(0.75),
        **reaches(REACHED),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({REACHED: {"weth": 2_000_000.0}}),
    )
    finding = document.findings[0]
    # Gate control with no magnitude witness: the reached sheet is not charged,
    # so the entity is unresolved and its own sheet is the at-most.
    assert finding["partial_proof"] is True
    assert finding["unresolved_stake"]["ceiling_usd"] == 2_000_000.0
    assert finding["unresolved_stake"]["proof_frontier"] == "magnitude"
    # The at-most in points: proven severity (0.75) x proven weakness (EOA 0.9)
    # x the $2M ceiling's band (0.5) x the scale — derived, not minted.
    assert finding["unresolved_stake"]["points_ceiling"] == round(60.0 * 0.75 * 0.9 * 0.5, 4)
    levers = document.provenance["unresolved_levers"]
    assert levers["findings_admitted"] >= 1
    assert levers["levers"][0]["ceiling_usd"] == 2_000_000.0
    assert levers["levers"][0]["points_ceiling"] == finding["unresolved_stake"]["points_ceiling"]
    assert levers["levers"][0]["principal_unit"] == finding["principal_unit"]
