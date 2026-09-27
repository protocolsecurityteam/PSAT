"""Wallet totals cannot earn confidence credit for capability magnitude."""

from __future__ import annotations

from services.scoring.schema import PrincipalRef
from tests.support.scoring_builders import (
    EOA,
    KEY_C,
    facts,
    fold,  # noqa: F401 -- pytest fixture
    proven,
    reaches,
    sig,
    value_plane,
)


def test_priced_holdings_do_not_answer_the_magnitude_question(fold):
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    for dollars in (None, 5_000_000.0):
        plane = value_plane({KEY_C: {"token": dollars}} if dollars else {}, contracts=(KEY_C,))
        document = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane)
        census = document.model_parameters["confidence_detail"]["reach_magnitude_signals"]
        assert census["magnitude_sheet_ceiling"] == 0
        assert census["sheet_ceiling_by_capability"] == {}
        assert census["by_capability"]["upgrade.implementation"] == [0, 1]
        provenance = document.provenance["sheet_ceilings"]
        assert provenance["entities_priced_from_a_sheet_ceiling"] == (1 if dollars else 0)
        assert provenance["signals_credited_in_confidence"] == 0
        assert provenance["entities_by_capability"] == ({"upgrade.implementation": 1} if dollars else {})
