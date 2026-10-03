"""The worker-side labeling (call site 1) is in ``test_effects_worker_integration``."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from services.effects import claims_bridge
from services.effects.config import (
    EFFECT_CLASS_AUTHORITY_CHANGE,
    EFFECT_CLASS_CODE_UPGRADE,
    EFFECT_CLASS_FREEZE_PAUSE,
    EFFECT_CLASS_SUPPLY,
    EFFECT_CLASS_VALUE_OUT,
    TIER_CALL,
    TIER_FORK,
    TIER_HISTORICAL,
    VERDICT_PROVEN,
    VERDICT_UNKNOWN,
)
from services.static.claims.types import Claim
from utils import claim_ids as C


def _static(claim_id: str, tier: str = "standard_exact", **witness: Any) -> Claim:
    return {"claim_id": claim_id, "tier": tier, "witness": witness}  # pyright: ignore[reportReturnType]


def _verdict(
    effect_class: str,
    *,
    verdict: str = VERDICT_PROVEN,
    tier: str = TIER_CALL,
    witness: dict[str, Any] | None = None,
    observed_residue: dict[str, Any] | None = None,
    current_check_passed: bool | None = None,
    behavior_hash: str = "bh",
    vid: int = 1,
) -> Any:
    return SimpleNamespace(
        id=vid,
        effect_class=effect_class,
        verdict=verdict,
        tier=tier,
        behavior_hash=behavior_hash,
        current_check_passed=current_check_passed,
        witness=witness,
        observed_residue=observed_residue,
    )


def test_value_out_projects_the_measured_reach_discriminator():
    residue = {
        "observed_reach_value_usd": 55_200_000.0,
        "observed_reach_holders": ["0x" + "55" * 20],
        "reach_determined": True,
    }
    claim = claims_bridge.verdict_to_claim(
        _verdict(EFFECT_CLASS_VALUE_OUT, witness={"value_moved": True}, observed_residue=residue)
    )
    assert claim is not None
    assert claim["witness"]["observed"]["reach_determined"] is True


def test_freeze_pause_indefinite_latch_fields_survive_as_none():
    # None + None is the indefinite latch, and must be carried, never defaulted.
    witness = {
        "latch_flip": True,
        "observed_blast_radius": ["freeze(uint256)"],
        "auto_expiry": None,
        "duration_bound_seconds": None,
    }
    claim = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_FREEZE_PAUSE, tier=TIER_FORK, witness=witness))
    assert claim is not None
    observed = claim["witness"]["observed"]
    assert observed["observed_blast_radius"] == ["freeze(uint256)"]
    assert observed["auto_expiry"] is None
    assert observed["duration_bound_seconds"] is None


def test_a_duration_bound_never_reaches_the_scorer_without_its_fork_qualifier():
    """``duration_bound_seconds`` is a static read that becomes a mitigation only with the fork cross-check, so the
    qualifier and source must travel with it.
    """
    for expiry in (True, False, None):
        witness = {
            "latch_flip": True,
            "observed_blast_radius": ["freeze(uint256)"],
            "auto_expiry": expiry,
            "duration_bound_seconds": 3600,
            "duration_bound_source": "guard_constant",
        }
        claim = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_FREEZE_PAUSE, tier=TIER_FORK, witness=witness))
        assert claim is not None
        observed = claim["witness"]["observed"]
        assert observed["duration_bound_seconds"] == 3600
        assert "auto_expiry" in observed and observed["auto_expiry"] is expiry
        assert observed["duration_bound_source"] == "guard_constant"


def test_authority_change_maps_to_registered_authority_grant():
    # No existing id is honest for a mechanism-agnostic gate-open.
    claim = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_AUTHORITY_CHANGE, witness={"gate_mutation": True}))
    assert claim is not None and claim["claim_id"] == C.AUTHORITY_GRANT
    from services.static.claims.registry import is_registered, legacy_projections

    assert is_registered(C.AUTHORITY_GRANT)
    assert legacy_projections()[C.AUTHORITY_GRANT] == "authority_update"


def test_unknown_verdict_mints_nothing():
    assert claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_VALUE_OUT, verdict=VERDICT_UNKNOWN)) is None


def test_historical_with_passed_current_check_mints():
    v = _verdict(EFFECT_CLASS_CODE_UPGRADE, tier=TIER_HISTORICAL, current_check_passed=True)
    claim = claims_bridge.verdict_to_claim(v)
    assert claim is not None and claim["claim_id"] == "upgrade.implementation"
    assert claim["witness"]["observed"]["current_check_passed"] is True


def test_historical_with_null_current_check_mints_nothing():
    v = _verdict(EFFECT_CLASS_CODE_UPGRADE, tier=TIER_HISTORICAL, current_check_passed=None)
    assert claims_bridge.verdict_to_claim(v) is None


from db.models import Contract, EffectiveFunction, EffectVerdict  # noqa: E402
from services.policy.effective_permissions_writer import write_effective_function_rows  # noqa: E402
from tests.conftest import requires_postgres  # noqa: E402

_SELECTOR = "0x40c10f19"
_DEPLOY = "0x" + "ab" * 20


def _fn_record() -> dict[str, Any]:
    # A wholesale replace would blank the observed label.
    return {
        "function": "mint(address,uint256)",
        "abi_signature": "mint(address,uint256)",
        "selector": _SELECTOR,
        "effect_labels": [],
        "effect_targets": [],
        "action_summary": "stub",
        "authority_public": False,
        "authority_roles": [],
        "claims": [],
    }


def _cleanup(session, contract_id):
    session.query(Contract).filter(Contract.id == contract_id).delete()
    session.commit()


# Verdicts are keyed on deployment coordinates; a policy rewrite must never destroy them, and function_id relinks.


def _seed_with_real_verdict(session):
    """The witness points at a real verdict id, so the dangle assertion is exact."""
    contract = Contract(address=_DEPLOY, chain="ethereum", is_proxy=False)
    session.add(contract)
    session.flush()
    ef = EffectiveFunction(
        contract_id=contract.id,
        deployment_address=_DEPLOY,
        function_name="mint",
        selector=_SELECTOR,
        abi_signature="mint(address,uint256)",
        effect_labels=["mint"],
        claims=[],
        authority_public=False,
    )
    session.add(ef)
    session.flush()
    verdict = EffectVerdict(
        function_id=ef.id,
        chain_id=1,
        contract_address=_DEPLOY,
        selector=_SELECTOR,
        effect_class=EFFECT_CLASS_SUPPLY,
        behavior_hash="bh",
        verdict=VERDICT_PROVEN,
        tier=TIER_CALL,
        witness={"supply_delta_sign": "mint"},
    )
    session.add(verdict)
    session.flush()
    observed = _verdict(EFFECT_CLASS_SUPPLY, witness={"supply_delta_sign": "mint"}, vid=verdict.id)
    ef.claims = [claims_bridge.verdict_to_claim(observed)]
    session.commit()
    return contract.id, verdict.id


def _purge_verdicts(session):
    session.query(EffectVerdict).delete()
    session.commit()


@requires_postgres
def test_policy_rewrite_keeps_verdict_row_and_relinks(db_session):
    contract_id, verdict_id = _seed_with_real_verdict(db_session)
    write_effective_function_rows(
        db_session,
        contract_id=contract_id,
        function_records=[_fn_record()],
        capability_by_function=None,
        deployment_address=_DEPLOY,
    )
    db_session.commit()
    db_session.expire_all()
    verdict = db_session.query(EffectVerdict).filter(EffectVerdict.id == verdict_id).one_or_none()
    assert verdict is not None
    ef = db_session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == contract_id).one()
    assert verdict.function_id == ef.id
    for claim in ef.claims or []:
        if claim.get("tier") == "behavioral_observed":
            vid = (claim.get("witness") or {}).get("effect_verdict_id")
            assert vid is not None
            assert db_session.query(EffectVerdict).filter(EffectVerdict.id == vid).count() == 1
    _purge_verdicts(db_session)


def _static_flow_out() -> Claim:
    return {
        "claim_id": "flow.out",
        "tier": "standard_exact",
        "witness": {
            "kind": "value_flow",
            "direction": "out",
            "sink_ids": ["sink-1"],
            "flows": [
                {
                    "selector": "0xd0c407e1",
                    "from_is_self": True,
                    "target_kind": {"kind": "immutable", "tier": "dispositive_ast"},
                    "amount_kind": {"kind": "param", "tier": "dispositive_ast"},
                    "amount_param_index": 1,
                }
            ],
        },
    }


def _damaged_observed_flow_out() -> Claim:
    """19 preview-DB rows look exactly like this."""
    return {
        "claim_id": "flow.out",
        "tier": "behavioral_observed",
        "witness": {
            "effect_class": EFFECT_CLASS_VALUE_OUT,
            "effect_verdict_id": 1,
            "verdict_tier": TIER_CALL,
            "behavior_hash": "bh",
        },
    }


def _executed() -> Any:
    return _verdict(EFFECT_CLASS_VALUE_OUT, witness={"observation": "executed", "value_moved": True})


def test_a_damaged_row_is_repaired_by_the_next_policy_rerun():
    """Policy runs before effects, so the stripped claim must neither become its own donor nor outrank its
    replacement, or damaged rows stay damaged.
    """
    prior = [_static_flow_out(), _damaged_observed_flow_out()]
    result = claims_bridge.merge_into_function(prior, [], [_executed()])
    assert result is not None
    claims, _labels = result
    flow_out = [c for c in claims if c["claim_id"] == "flow.out"]
    assert len(flow_out) == 1
    witness = flow_out[0]["witness"]
    assert witness["flows"][0]["target_kind"] == {"kind": "immutable", "tier": "dispositive_ast"}
    assert witness["sink_ids"] == ["sink-1"]
    assert witness["effect_verdict_id"] == 1


def test_superseding_a_static_claim_keeps_the_tier_membership_admits_on():
    """Membership admits an observed claim only on the static tier it superseded; dropping the stamp would revoke
    standing members after the next effects run."""
    from services.discovery.membership_gate.readers import _function_grants_control

    merged = claims_bridge.merge_observed_claims(
        [_static("pause.set", "idiom_structural", kind="pause_latch")], [_verdict(EFFECT_CLASS_FREEZE_PAUSE)]
    )

    assert [(c["claim_id"], c["tier"]) for c in merged] == [("pause.set", "behavioral_observed")]
    assert merged[0]["witness"]["static_tier"] == "idiom_structural"
    assert _function_grants_control(merged)
