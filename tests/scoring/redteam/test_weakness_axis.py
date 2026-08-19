"""Weakness axis.

One of the twenty sections of the former ``test_scoring_redteam.py``.
"""

from __future__ import annotations

from services.scoring import planes as P
from services.scoring.constants import (
    FREEZE_CAPABILITY_PROVEN,
    FREEZE_KEYSET_RECOVERABLE,
    FREEZE_SUSTAINABLE,
    WEAKNESS_SAFE_SINGLE_SIGNER,
    WEAKNESS_SAFE_SUPERMAJORITY,
    WEAKNESS_SAFE_UNCREDITED,
    WEAKNESS_TIMELOCK_UNDETERMINED,
    delay_discount,
)
from services.scoring.schema import FunctionSignal, PrincipalRef, Tri, entity_key
from tests.support.scoring_builders import (
    EOA,
    KEY_C,
    KEY_V,
    OWNERS,
    SAFE,
    SAFE2,
    TIMELOCK,
    VAULT,
    C,
    _pause_document,
    facts,
    fold,  # noqa: F401  (fold fixture, registered by import)
    pause_sig,
    proven,
    reaches,
    sig,
    value_plane,
)


def test_f3_unread_owner_set_is_not_a_k_of_k_safe(fold):
    """n backfilled from k publishes the strongest rung out of an absent witness."""
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, SAFE, "safe", threshold=2)},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["weakness"] == WEAKNESS_SAFE_UNCREDITED
    assert "2/2" not in finding["principal"] and "2/2" not in str(finding["weakest_gate"])
    assert any("safe_owner_set_not_determined" in note for note in finding["witness_notes"])


def test_f3_proven_owner_set_still_earns_its_rung(fold):
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, SAFE, "safe", owners=OWNERS, threshold=3)},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}),
    )
    assert document.findings[0]["weakness"] == WEAKNESS_SAFE_SUPERMAJORITY
    assert document.findings[0]["weakest_gate"] == "Safe 3/4"


def test_f2_an_unread_pauser_key_set_moves_severity_in_neither_direction(fold):
    """The freezing key set was never read, so independence is uncomputable.

    Nothing may move on that: not the recoverable credit (which would need proven
    independence) and not the sustainable component (which would need proven
    dependence). The question is published instead.
    """
    document = _pause_document(
        fold,
        facts(1, SAFE, "safe", threshold=1),  # owner set never resolved
        facts(2, SAFE2, "safe", owners=OWNERS, threshold=2),
    )
    finding = document.findings[0]
    assert not any("keyset_independent" in note for note in finding["witness_notes"])
    assert finding["severity_proven"] == FREEZE_CAPABILITY_PROVEN
    # The single-signer cliff is not waived on the strength of a non-witness.
    assert finding["weakness"] == WEAKNESS_SAFE_UNCREDITED
    assert "freeze_recovery_independence_not_determined" in {w["kind"] for w in document.warnings}
    assert "freeze_recovery_independence_not_determined" in finding["severity_basis"]


def test_f2_every_undetermined_recovery_arm_lands_on_the_same_rung(fold):
    """No recovery claim, an unresolved recovery principal and an unread key set."""
    pauser = facts(1, SAFE, "safe", owners=OWNERS, threshold=2)
    arms = [
        _pause_document(fold, pauser, None),
        _pause_document(fold, pauser, facts(2, SAFE2, "contract")),
        _pause_document(fold, facts(1, SAFE, "safe", threshold=2), facts(2, SAFE2, "safe", owners=OWNERS, threshold=2)),
    ]
    assert {document.findings[0]["severity_proven"] for document in arms} == {FREEZE_CAPABILITY_PROVEN}


def test_f2_proven_dependence_adds_the_sustainable_component(fold):
    """The only witness that raises the freeze rung is a PROVEN dependent key set."""
    shared = ("0x" + "1" * 40, "0x" + "2" * 40, "0x" + "3" * 40)
    document = _pause_document(
        fold,
        facts(1, SAFE, "safe", owners=shared, threshold=1),
        facts(2, SAFE2, "safe", owners=shared, threshold=2),
    )
    finding = document.findings[0]
    assert finding["severity_proven"] == FREEZE_SUSTAINABLE
    # And the single-signer cliff stands, because independence was refuted.
    assert finding["weakness"] == WEAKNESS_SAFE_SINGLE_SIGNER
    assert "freeze_keyset_not_independent" in finding["severity_basis"]


def test_f2_an_eoa_pauser_is_its_own_key_set(fold):
    """The address fallback is admissible exactly where the principal IS a key."""
    recovery = [{"function_principal_id": 2, "chain": "ethereum", "address": SAFE2}]
    signal = pause_sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates={"freeze_recovery_principals": Tri.proven("enumerated", recovery).to_json()},
        **proven(FREEZE_KEYSET_RECOVERABLE, ("freeze_capability_proven",)),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa"), 2: facts(2, SAFE2, "safe", owners=OWNERS, threshold=2)},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}),
    )
    finding = document.findings[0]
    assert any(note.startswith("keyset_independent") for note in finding["witness_notes"])
    assert finding["severity_proven"] == FREEZE_KEYSET_RECOVERABLE


def test_w3_a_proven_zero_delay_is_not_an_unread_one(fold):
    assert delay_discount(0) == 1.0
    assert delay_discount(None) is None
    assert delay_discount(-1) is None

    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", TIMELOCK),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    zero = fold(
        [signal],
        principals={1: facts(1, TIMELOCK, "timelock", delay=0.0)},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}),
    ).findings[0]
    unread = fold(
        [signal],
        principals={1: facts(1, TIMELOCK, "timelock")},
        value=value_plane({KEY_C: {"usdc": 50_000_000.0}}),
    ).findings[0]

    assert "0d" in str(zero["weakest_gate"])
    assert any("proven_zero" in note for note in zero["witness_notes"])
    assert "not_determined" in str(unread["weakest_gate"])
    assert unread["weakness"] == WEAKNESS_TIMELOCK_UNDETERMINED


def _timelock_population(include_execute: bool) -> list[FunctionSignal]:
    claims = ["timelock.schedule"] + (["timelock.execute"] if include_execute else [])
    population = [
        sig(
            claim_id=claim,
            function_name=claim.split(".")[1],
            deployment_address=TIMELOCK,
            contract_id=2,
            selector=f"0x0000000{index}",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        )
        for index, claim in enumerate(claims)
    ]
    population.append(
        sig(
            function_name="upgradeToC",
            deployment_address=VAULT,
            contract_id=3,
            selector="0x3659cfe6",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(2, "ethereum", TIMELOCK),),
            **proven(1.0),
            **reaches(KEY_V),
        )
    )
    population.append(
        sig(
            function_name="upgradeToD",
            deployment_address=C,
            contract_id=4,
            selector="0x3659cfe7",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
            **proven(1.0),
            **reaches(KEY_C),
        )
    )
    return population


def test_f8_propose_only_does_not_collapse_a_timelock(fold):
    """The collapse asserts the Safe can ACT AS the timelock: both halves or none."""
    principals = {
        1: facts(1, SAFE, "safe", owners=OWNERS, threshold=2),
        2: facts(2, TIMELOCK, "timelock", delay=172800.0),
    }
    plane = value_plane({KEY_V: {"usdc": 100_000_000.0}, KEY_C: {"usdc": 10_000_000.0}})

    propose_only = fold(_timelock_population(include_execute=False), principals=principals, value=plane)
    both = fold(_timelock_population(include_execute=True), principals=principals, value=plane)

    propose_units = {f["principal_unit"] for f in propose_only.findings}
    assert entity_key("ethereum", TIMELOCK) in propose_units
    timelock_row = next(f for f in propose_only.findings if f["principal_unit"] == entity_key("ethereum", TIMELOCK))
    assert timelock_row["weakness"] == WEAKNESS_TIMELOCK_UNDETERMINED

    # With both halves proven the collapse runs, and the delayed value is still
    # charged at the DISCOUNTED weakness rather than the Safe's direct one.
    collapsed = [
        f for f in both.findings + both.provenance["subsumed_rows"] if f["capability"] == "upgrade.implementation"
    ]
    assert {f["principal_unit"] for f in collapsed} == {entity_key("ethereum", SAFE)}
    weaknesses = sorted(f["weakness"] for f in collapsed)
    assert len(weaknesses) == 2 and weaknesses[0] < weaknesses[1]
    assert both.provenance["principal_units"]["timelock_collapses"]


def test_w4_an_unread_proposer_threshold_cannot_rank_as_the_strongest(fold):
    """inv.5 takes the WEAKEST path, and unread must not win by construction."""
    population = _timelock_population(include_execute=True)
    principals = {
        1: facts(1, SAFE, "safe", owners=OWNERS),  # threshold never read
        2: facts(2, TIMELOCK, "timelock", delay=172800.0),
    }
    document = fold(population, principals=principals, value=value_plane({KEY_V: {"usdc": 100_000_000.0}}))
    rows = document.findings + document.provenance["subsumed_rows"]
    timelock_rows = [f for f in rows if "timelock" in str(f["weakest_gate"])]
    assert timelock_rows, "the timelock row should still be published"
    assert "k not_determined" in str(timelock_rows[0]["weakest_gate"])
    # Uncredited quorum × the proven delay discount — never a fabricated n/n.
    assert timelock_rows[0]["weakness"] == round(WEAKNESS_SAFE_UNCREDITED * (delay_discount(172800) or 1.0), 4)


def test_w6_an_unreadable_module_set_leaves_the_kn_credit_standing():
    """§7.1: only a PROVEN module or guard withholds the demotion."""
    proven_empty = {
        "module_set": [],
        "module_set_basis": "storage_linked_list_terminated",
        "guard": "proven_zero",
        "protection_is_upper_bound": "not_determined",
    }
    unreadable = {"module_set_basis": "not_determined", "protection_is_upper_bound": "not_determined"}
    proven_module = {**proven_empty, "protection_is_upper_bound": True}
    enumerated = {"module_set": ["0x" + "9" * 40], "module_set_basis": "storage_linked_list_terminated"}
    guarded = {**proven_empty, "guard": "proven_address"}

    assert P._safe_protection_verdict({"safe_protection": proven_empty})[0] is False
    assert P._safe_protection_verdict({"safe_protection": unreadable})[0] is False
    assert P._safe_protection_verdict({})[0] is False
    assert P._safe_protection_verdict({"safe_protection": proven_module})[0] is True
    assert P._safe_protection_verdict({"safe_protection": enumerated})[0] is True
    assert P._safe_protection_verdict({"safe_protection": guarded})[0] is True
