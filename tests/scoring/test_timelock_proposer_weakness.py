"""A timelock is priced by its weakest proven proposer-executor, whatever its type, and a Safe behind it keeps only
the k/n credit its own protection verdict allows.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from services.scoring import constants as K
from services.scoring.schema import PrincipalRef, entity_key
from tests.support.scoring_builders import (
    EOA,
    KEY_V,
    OWNERS,
    SAFE,
    TIMELOCK,
    VAULT,
    facts,
    fold,  # noqa: F401  (fold fixture, registered by import)
    magnitude,
    proven,
    reaches,
    sig,
    value_plane,
)

TWO_DAYS = 172800.0
KEY_TIMELOCK = entity_key("ethereum", TIMELOCK)
KEY_SAFE = entity_key("ethereum", SAFE)
KEY_EOA = entity_key("ethereum", EOA)
OTHER = "0x" + "4" * 40


def _population(timelock_refs):
    signals = [
        sig(
            claim_id=claim,
            function_name=claim.split(".")[1],
            deployment_address=TIMELOCK,
            contract_id=2,
            selector=selector,
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=timelock_refs,
        )
        for claim, selector in (("timelock.schedule", "0x01d5062a"), ("timelock.execute", "0x134008d3"))
    ]
    signals.append(
        sig(
            function_name="upgradeTo",
            deployment_address=VAULT,
            contract_id=3,
            selector="0x3659cfe6",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(2, "ethereum", TIMELOCK),),
            gates=magnitude(100_000_000.0),
            **proven(1.0),
            **reaches(KEY_V),
        )
    )
    return signals


def _principals(over=None):
    principals = {
        1: facts(1, SAFE, "safe", owners=OWNERS, threshold=3),
        2: facts(2, TIMELOCK, "timelock", delay=TWO_DAYS),
        3: facts(3, EOA, "eoa"),
    }
    principals.update(over or {})
    return principals


def _run(fold, refs, principals=None):
    document = fold(
        _population(refs),
        principals=principals or _principals(),
        value=value_plane({KEY_V: {"usdc": 100_000_000.0}}, contracts=(KEY_V, KEY_TIMELOCK)),
    )
    (finding,) = [f for f in document.findings if f["capability"].startswith("upgrade")]
    return document, finding


SAFE_REF = PrincipalRef(1, "ethereum", SAFE)
EOA_REF = PrincipalRef(3, "ethereum", EOA)


def test_safe_only_proposer_is_unchanged(fold):
    document, finding = _run(fold, (SAFE_REF,))
    assert finding["principal_unit"] == KEY_SAFE
    assert finding["weakness"] == 0.136
    assert document.grade_lambda == 92.656
    assert document.provenance["principal_units"]["timelock_collapses"][KEY_TIMELOCK]["proposer_k_of_n"] == "3/4"


def test_an_eoa_beside_the_safe_is_the_weakest_path(fold):
    discount = K.delay_discount(TWO_DAYS)
    assert discount is not None
    safe_only, _ = _run(fold, (SAFE_REF,))
    document, finding = _run(fold, (SAFE_REF, EOA_REF))

    assert finding["principal_unit"] == KEY_EOA
    assert finding["weakness"] == round(K.WEAKNESS_EOA * discount, 4)
    assert "via EOA" in str(finding["weakest_gate"])
    assert document.grade_lambda is not None and safe_only.grade_lambda is not None
    assert document.grade_lambda < safe_only.grade_lambda
    collapse = document.provenance["principal_units"]["timelock_collapses"][KEY_TIMELOCK]
    assert collapse["proposer_kind"] == "eoa" and collapse["proposer_k_of_n"] == "not_applicable"


def test_an_eoa_only_proposer_is_priced_as_an_eoa_not_as_not_determined(fold):
    discount = K.delay_discount(TWO_DAYS)
    assert discount is not None
    document, finding = _run(fold, (EOA_REF,))
    assert finding["weakness"] == round(K.WEAKNESS_EOA * discount, 4)
    assert "not_determined" not in str(finding["weakest_gate"])
    assert KEY_TIMELOCK in document.provenance["principal_units"]["timelock_collapses"]


@pytest.mark.parametrize(
    "unpriced",
    [
        pytest.param(facts(4, OTHER, "contract"), id="contract"),
        pytest.param(facts(4, OTHER, "unknown"), id="unknown-type"),
        pytest.param(facts(4, OTHER, "safe"), id="safe-owners-unread"),
    ],
)
def test_a_proposer_whose_weakness_is_unproven_makes_the_timelock_not_determined(fold, unpriced):
    other_ref = PrincipalRef(4, "ethereum", OTHER)
    document, finding = _run(fold, (SAFE_REF, other_ref), principals=_principals({4: unpriced}))

    assert finding["principal_unit"] == KEY_TIMELOCK
    assert finding["weakness"] == K.WEAKNESS_TIMELOCK_UNDETERMINED
    assert "proposer not_determined" in str(finding["weakest_gate"])
    assert any(n.startswith("timelock_proposer_weakness_not_determined:") for n in finding["witness_notes"])
    units = document.provenance["principal_units"]
    assert KEY_TIMELOCK not in units["timelock_collapses"]
    assert units["timelock_proposers_not_determined"][KEY_TIMELOCK]["principals"] == [entity_key("ethereum", OTHER)]


def test_a_proposer_with_no_readable_row_makes_the_timelock_not_determined(fold):
    missing_ref = PrincipalRef(9, "ethereum", OTHER)
    _, finding = _run(fold, (SAFE_REF, missing_ref))
    assert finding["weakness"] == K.WEAKNESS_TIMELOCK_UNDETERMINED


def test_a_safe_with_a_proven_module_loses_its_credit_behind_a_timelock(fold):
    discount = K.delay_discount(TWO_DAYS)
    assert discount is not None
    withheld = replace(
        facts(1, SAFE, "safe", owners=OWNERS, threshold=3),
        protection_credit_withheld=True,
        protection_basis="module_set_enumerated_non_empty(proven module)",
    )
    _, finding = _run(fold, (SAFE_REF,), principals=_principals({1: withheld}))

    assert finding["weakness"] == round(K.WEAKNESS_SAFE_UNCREDITED * discount, 4)
    assert "safe_kn_credit_withheld:module_set_enumerated_non_empty(proven module)" in finding["witness_notes"]


def test_a_safe_with_its_module_set_proven_empty_keeps_full_credit_behind_a_timelock(fold):
    proven_empty = replace(
        facts(1, SAFE, "safe", owners=OWNERS, threshold=3),
        protection_basis="module_set_proven_empty@123",
    )
    _, finding = _run(fold, (SAFE_REF,), principals=_principals({1: proven_empty}))
    assert finding["weakness"] == 0.136
    assert not any(n.startswith("safe_kn_credit_withheld") for n in finding["witness_notes"])


@pytest.mark.parametrize("five_of_six_address", ["0x" + "1" * 40, "0x" + "f" * 40])
def test_equal_weakness_safes_keep_the_smaller_k_of_n_as_the_published_proposer(fold, five_of_six_address):
    six_owners = tuple("0x" + c * 40 for c in "abcdef")
    principals = _principals({5: facts(5, five_of_six_address, "safe", owners=six_owners, threshold=5)})
    refs = (SAFE_REF, PrincipalRef(5, "ethereum", five_of_six_address))
    document, finding = _run(fold, refs, principals=principals)

    assert finding["principal_unit"] == KEY_SAFE
    assert "via 3/4" in str(finding["weakest_gate"])
    assert document.provenance["principal_units"]["timelock_collapses"][KEY_TIMELOCK]["proposer_k_of_n"] == "3/4"


@pytest.mark.parametrize(
    ("delay", "discounted"), [pytest.param(TWO_DAYS, True, id="2d"), pytest.param(0.0, False, id="0d")]
)
def test_an_unpriced_proposer_never_makes_a_proven_eoa_path_read_safer(fold, delay, discounted):
    discount = K.delay_discount(delay) if discounted else 1.0
    assert discount is not None
    principals = _principals({2: facts(2, TIMELOCK, "timelock", delay=delay), 4: facts(4, OTHER, "contract")})
    document, finding = _run(fold, (EOA_REF, PrincipalRef(4, "ethereum", OTHER)), principals=principals)
    eoa_only, eoa_finding = _run(fold, (EOA_REF,), principals=principals)

    expected = round(K.WEAKNESS_EOA * discount, 4)
    assert finding["weakness"] == expected == eoa_finding["weakness"]
    assert finding["principal_unit"] == KEY_TIMELOCK
    assert "proposer not_determined" in str(finding["weakest_gate"])
    assert f"proven_proposer_floor=EOA:{expected}" in finding["witness_notes"]
    assert document.provenance["principal_units"]["timelock_proposers_not_determined"][KEY_TIMELOCK]
    assert document.grade_lambda == eoa_only.grade_lambda


def test_an_unread_delay_never_prices_a_proven_eoa_proposer_below_an_eoa(fold):
    principals = _principals({2: facts(2, TIMELOCK, "timelock")})
    _, finding = _run(fold, (EOA_REF,), principals=principals)
    assert finding["weakness"] == K.WEAKNESS_EOA
    assert "timelock(delay not_determined)" in str(finding["weakest_gate"])


def test_a_stronger_proven_proposer_leaves_the_undetermined_rung_as_it_was(fold):
    principals = _principals({4: facts(4, OTHER, "contract")})
    _, finding = _run(fold, (SAFE_REF, PrincipalRef(4, "ethereum", OTHER)), principals=principals)
    assert finding["weakness"] == K.WEAKNESS_TIMELOCK_UNDETERMINED
    assert not any(n.startswith("proven_proposer_floor") for n in finding["witness_notes"])
