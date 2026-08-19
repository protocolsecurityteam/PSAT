"""Confidence perimeter admission rules.

One of the twenty sections of the former ``test_scoring_redteam.py``.
"""

from __future__ import annotations

from services.scoring.schema import PrincipalRef, entity_key
from tests.support.scoring_builders import (
    EOA,
    KEY_C,
    KEY_IMPL,
    KEY_PROXY,
    OWNERS,
    PROXY,
    SAFE,
    facts,
    fold,  # noqa: F401  (fold fixture, registered by import)
    magnitude,
    proven,
    reaches,
    sig,
    value_plane,
)


def test_perimeter_folds_an_implementation_onto_its_proxy(fold):
    """An impl row is the proxy's entity: admitting both hands the impl a second
    copy of the proxy's value band that no signal could ever answer."""
    signal = sig(
        deployment_address=PROXY,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        gates=magnitude(1_000_000_000.0),
        **proven(1.0),
        **reaches(KEY_PROXY),
    )
    document = fold(
        [signal],
        principals={1: facts(1, SAFE, "safe", owners=OWNERS, threshold=2)},
        value=value_plane(
            {KEY_PROXY: {"usdc": 1_000_000_000.0}},
            contracts=(KEY_PROXY, KEY_IMPL),
            alias={KEY_IMPL: KEY_PROXY},
        ),
    )
    detail = document.model_parameters["confidence_detail"]
    assert detail["implementation_entities_folded"] == 1
    assert detail["perimeter_entities"] == 1
    assert detail["reachability_answered_pct"] == 100.0
    assert detail["capability_scored_pct"] == 100.0
    assert detail["value_priced_pct"] == 100.0
    assert document.confidence_pct == 100.0


def test_zero_address_is_not_a_perimeter_entity(fold):
    """A renounced-ownership 0x0 in the closure is a burn sentinel, not an
    entity whose capabilities could ever be assessed."""
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        gates=magnitude(50_000_000.0),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, SAFE, "safe", owners=OWNERS, threshold=2)},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}, contracts=(KEY_C,)),
        closure={KEY_C: {entity_key("ethereum", "0x" + "0" * 40)}},
    )
    detail = document.model_parameters["confidence_detail"]
    assert detail["zero_address_entities_excluded"] == 1
    assert detail["perimeter_entities"] == 1
    assert document.confidence_pct == 100.0


def test_a_proven_codeless_eoa_answers_vacuously(fold):
    """With no code there are no functions: the capability question collapses
    into the closure's reach answer — but only on the earned getCode witness,
    and never for the pricing term."""
    key_eoa = entity_key("ethereum", EOA)
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        gates=magnitude(50_000_000.0),
        **proven(1.0),
        **reaches(KEY_C),
    )
    kwargs: dict = dict(
        principals={1: facts(1, SAFE, "safe", owners=OWNERS, threshold=2)},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}, contracts=(KEY_C,)),
        closure={key_eoa: {KEY_C}},
    )

    unproven = fold([signal], **kwargs)
    witnessed = fold([signal], **kwargs, eoas={key_eoa})

    unproven_detail = unproven.model_parameters["confidence_detail"]
    assert unproven_detail["proven_codeless_answered"] == 0
    assert unproven_detail["capability_scored_pct"] < 100.0

    detail = witnessed.model_parameters["confidence_detail"]
    assert detail["proven_codeless_answered"] == 1
    assert detail["reachability_answered_pct"] == 100.0
    assert detail["capability_scored_pct"] == 100.0
    # Holding value is a question code-lessness does not answer: the unpriced
    # EOA still charges the pricing term, and the headline stays the minimum.
    assert detail["value_priced_pct"] < 100.0
    assert witnessed.confidence_pct == detail["value_priced_pct"]

    # With the EOA's holdings priced, pricing no longer binds, and the earned
    # witness is exactly what separates a full answer from a charged gap.
    priced_kwargs = dict(
        kwargs,
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}, key_eoa: {"usdc": 1_000.0}}, contracts=(KEY_C,)),
    )
    assert fold([signal], **priced_kwargs).confidence_pct < 100.0
    assert fold([signal], **priced_kwargs, eoas={key_eoa}).confidence_pct == 100.0
