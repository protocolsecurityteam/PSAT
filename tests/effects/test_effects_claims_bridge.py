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
from services.static.claims.registry import resolve_claim_precedence
from services.static.claims.types import Claim


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


def test_code_upgrade_maps_to_upgrade_implementation():
    claim = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_CODE_UPGRADE))
    assert claim is not None
    assert claim["claim_id"] == "upgrade.implementation"
    assert claim["tier"] == "behavioral_observed"
    assert claim["witness"]["effect_verdict_id"] == 1
    assert claim["witness"]["verdict_tier"] == TIER_CALL
    assert "transcript" not in claim["witness"]


def test_value_out_maps_to_flow_out():
    claim = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_VALUE_OUT))
    assert claim is not None and claim["claim_id"] == "flow.out"


def test_supply_sign_selects_mint_or_burn():
    mint = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_SUPPLY, witness={"supply_delta_sign": "mint"}))
    burn = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_SUPPLY, witness={"supply_delta_sign": "burn"}))
    assert mint is not None and mint["claim_id"] == "supply.mint"
    assert burn is not None and burn["claim_id"] == "supply.burn"
    assert mint["witness"]["observed"]["supply_delta_sign"] == "mint"


def test_supply_mint_projects_backing_into_observed_witness():
    # So a backed conversion reads apart from a dilutive mint.
    backing = {"inflow_observed": False, "minted": True, "inflow_transfers": 0, "mint_transfers": 1}
    claim = claims_bridge.verdict_to_claim(
        _verdict(EFFECT_CLASS_SUPPLY, witness={"supply_delta_sign": "mint", "backing": backing})
    )
    assert claim is not None and claim["claim_id"] == "supply.mint"
    assert claim["witness"]["observed"]["backing"] == backing


def test_supply_without_sign_fails_closed():
    # No observed sign, so the delta shape can't be named.
    assert claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_SUPPLY, witness={})) is None
    assert claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_SUPPLY, witness=None)) is None


def test_freeze_pause_maps_to_pause_set_only():
    # The pause recipe only witnesses a freeze, never an unpause.
    claim = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_FREEZE_PAUSE, tier=TIER_FORK))
    assert claim is not None and claim["claim_id"] == "pause.set"


def test_value_out_projects_reach_into_observed_witness():
    # Reach is read from ``observed_residue``, never the witness.
    residue = {
        "observed_reach_value_usd": 55_200_000.0,
        "observed_reach_holders": ["0x" + "55" * 20],
    }
    claim = claims_bridge.verdict_to_claim(
        _verdict(EFFECT_CLASS_VALUE_OUT, witness={"value_moved": True}, observed_residue=residue)
    )
    assert claim is not None and claim["claim_id"] == "flow.out"
    observed = claim["witness"]["observed"]
    assert observed["observed_reach_value_usd"] == 55_200_000.0
    assert observed["observed_reach_holders"] == ["0x" + "55" * 20]


def test_value_out_projects_reach_indeterminate_floor():
    """``reach_determined: False`` is the discriminator; both keys must be allowlisted or they drop silently."""
    residue = {
        "observed_reach_floor_usd": 221_000_000.0,
        "reach_indeterminate": True,
        "reach_determined": False,
    }
    claim = claims_bridge.verdict_to_claim(
        _verdict(EFFECT_CLASS_VALUE_OUT, witness={"value_moved": True}, observed_residue=residue)
    )
    assert claim is not None
    observed = claim["witness"]["observed"]
    assert observed["reach_indeterminate"] is True
    assert observed["reach_determined"] is False
    assert observed["observed_reach_floor_usd"] == 221_000_000.0
    assert "observed_reach_value_usd" not in observed


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


def test_the_observed_destination_answer_reaches_the_claim(a6=True):
    """No claim carried ``destination_shape``, so approve-then-pull rows published $472M of reach with no destination
    statement.
    """
    witness = {"value_moved": True, "destination_shape": "unknown", "shape_proved_by": "none"}
    claim = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_VALUE_OUT, witness=witness))
    assert claim is not None
    observed = claim["witness"]["observed"]
    assert observed["destination_shape"] == "unknown"
    assert observed["shape_proved_by"] == "none"

    proven_witness = {"value_moved": True, "destination_shape": "caller_arbitrary", "shape_proved_by": "simulation"}
    proven_claim = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_VALUE_OUT, witness=proven_witness))
    assert proven_claim is not None
    assert proven_claim["witness"]["observed"]["destination_shape"] == "caller_arbitrary"
    assert proven_claim["witness"]["observed"]["shape_proved_by"] == "simulation"


def test_the_sentinel_subject_travels_with_the_answer():
    """The scorer's exec join refuses a shape with no subject, which left 15 proven witnesses unread."""
    witness = {
        "value_moved": True,
        "destination_shape": "caller_arbitrary",
        "shape_proved_by": "simulation",
        "sentinel_param": "data",
    }
    claim = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_VALUE_OUT, witness=witness))
    assert claim is not None
    assert claim["witness"]["observed"]["sentinel_param"] == "data"

    bare = claims_bridge.verdict_to_claim(
        _verdict(EFFECT_CLASS_VALUE_OUT, witness={k: v for k, v in witness.items() if k != "sentinel_param"})
    )
    assert bare is not None
    assert "sentinel_param" not in bare["witness"]["observed"]


def test_reach_is_never_read_off_the_cacheable_witness():
    # Witness-borne reach came from the cross-deployment cache and must not project.
    contaminated = {
        "value_moved": True,
        "observed_reach_value_usd": 5_000_000.0,
        "observed_reach_holders": ["0x" + "aa" * 20],
        "reach_indeterminate": True,
    }
    claim = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_VALUE_OUT, witness=contaminated))
    assert claim is not None
    observed = claim["witness"].get("observed", {})
    assert "observed_reach_value_usd" not in observed
    assert "observed_reach_holders" not in observed
    assert "reach_indeterminate" not in observed


def test_freeze_pause_projects_severity_fields_verdict318_shape():
    # Verdict 318's shape: the scorer needs all three to tell a $3.4B/30-day freeze from a harmless one.
    witness = {
        "latch_flip": True,
        "pause_effective": True,
        "auto_expiry": True,
        "scored_denominator": ["mintShares(address,uint256)", "transfer(address,uint256)", "unpauseUntil()"],
        "pre_pause_succeeding": ["mintShares(address,uint256)", "transfer(address,uint256)"],
        "observed_blast_radius": ["mintShares(address,uint256)", "transfer(address,uint256)"],
        "duration_bound_seconds": 2592000,
    }
    claim = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_FREEZE_PAUSE, tier=TIER_FORK, witness=witness))
    assert claim is not None and claim["claim_id"] == "pause.set"
    observed = claim["witness"]["observed"]
    assert observed["observed_blast_radius"] == ["mintShares(address,uint256)", "transfer(address,uint256)"]
    assert observed["auto_expiry"] is True
    assert observed["duration_bound_seconds"] == 2592000
    assert observed["pause_effective"] is True


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


def test_no_blast_verdict_mints_no_behavioral_claim():
    # An absent blast radius is an unproven lower bound, so no claim.
    witness = {"observed_blast_radius": [], "scored_denominator": ["a()", "b()"]}
    claim = claims_bridge.verdict_to_claim(
        _verdict(EFFECT_CLASS_FREEZE_PAUSE, verdict=VERDICT_UNKNOWN, tier=TIER_FORK, witness=witness)
    )
    assert claim is None


def test_authority_change_maps_to_registered_authority_grant():
    # No existing id is honest for a mechanism-agnostic gate-open.
    claim = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_AUTHORITY_CHANGE, witness={"gate_mutation": True}))
    assert claim is not None and claim["claim_id"] == claims_bridge.AUTHORITY_GRANT
    from services.static.claims.registry import is_registered, legacy_projections

    assert is_registered(claims_bridge.AUTHORITY_GRANT)
    assert legacy_projections()[claims_bridge.AUTHORITY_GRANT] == "authority_update"


def test_unknown_verdict_mints_nothing():
    assert claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_VALUE_OUT, verdict=VERDICT_UNKNOWN)) is None


def test_historical_with_failed_current_check_mints_nothing():
    # Tier-0 proves past capability; a failed current check would overclaim.
    v = _verdict(EFFECT_CLASS_CODE_UPGRADE, tier=TIER_HISTORICAL, current_check_passed=False)
    assert claims_bridge.verdict_to_claim(v) is None


def test_historical_with_passed_current_check_mints():
    v = _verdict(EFFECT_CLASS_CODE_UPGRADE, tier=TIER_HISTORICAL, current_check_passed=True)
    claim = claims_bridge.verdict_to_claim(v)
    assert claim is not None and claim["claim_id"] == "upgrade.implementation"
    assert claim["witness"]["observed"]["current_check_passed"] is True


def test_historical_with_null_current_check_mints_nothing():
    v = _verdict(EFFECT_CLASS_CODE_UPGRADE, tier=TIER_HISTORICAL, current_check_passed=None)
    assert claims_bridge.verdict_to_claim(v) is None


def test_double_merge_is_a_noop():
    verdicts = [_verdict(EFFECT_CLASS_VALUE_OUT)]
    once = claims_bridge.merge_observed_claims([], verdicts)
    twice = claims_bridge.merge_observed_claims(once, verdicts)
    assert once == twice
    assert [c["claim_id"] for c in once] == ["flow.out"]


def test_behavioral_observed_supersedes_static_same_id():
    static = _static("flow.out", "idiom_structural", static=True)
    merged = claims_bridge.merge_observed_claims([static], [_verdict(EFFECT_CLASS_VALUE_OUT)])
    flow = [c for c in merged if c["claim_id"] == "flow.out"]
    assert len(flow) == 1
    assert flow[0]["tier"] == "behavioral_observed"  # observed (rank 4) beats idiom (rank 2)


def test_distinct_sibling_claims_are_both_kept():
    static_burn = _static("supply.burn", "idiom_structural")
    merged = claims_bridge.merge_observed_claims(
        [static_burn], [_verdict(EFFECT_CLASS_SUPPLY, witness={"supply_delta_sign": "mint"})]
    )
    ids = sorted(c["claim_id"] for c in merged)
    assert ids == ["supply.burn", "supply.mint"]


def test_reproject_effect_labels_stays_in_sync():
    merged = claims_bridge.merge_observed_claims([], [_verdict(EFFECT_CLASS_VALUE_OUT)])
    labels = claims_bridge.reproject_effect_labels(["some_prior_label"], merged)
    assert "asset_send" in labels
    assert "some_prior_label" in labels


def test_merge_into_function_identity_when_no_verdict_mints():
    assert (
        claims_bridge.merge_into_function([], [], [_verdict(EFFECT_CLASS_VALUE_OUT, verdict=VERDICT_UNKNOWN)]) is None
    )


def test_merge_into_function_returns_claims_and_labels():
    result = claims_bridge.merge_into_function(
        [], ["prior"], [_verdict(EFFECT_CLASS_SUPPLY, witness={"supply_delta_sign": "mint"})]
    )
    assert result is not None
    claims, labels = result
    assert [c["claim_id"] for c in claims] == ["supply.mint"]
    assert "mint" in labels and "prior" in labels


def test_merge_preserves_unrelated_static_claims():
    static = _static("ownership.transfer")
    merged = claims_bridge.merge_observed_claims([static], [_verdict(EFFECT_CLASS_VALUE_OUT)])
    assert merged == resolve_claim_precedence(
        [static, *claims_bridge.claims_from_verdicts([_verdict(EFFECT_CLASS_VALUE_OUT)])]
    )
    assert any(c["claim_id"] == "ownership.transfer" for c in merged)


from db.models import Contract, EffectiveFunction, EffectVerdict  # noqa: E402
from services.policy.effective_permissions_writer import write_effective_function_rows  # noqa: E402
from tests.conftest import requires_postgres  # noqa: E402

_SELECTOR = "0x40c10f19"
_DEPLOY = "0x" + "ab" * 20


def _seed_contract_with_observed_function(session, *, with_verdict: bool):
    contract = Contract(address=_DEPLOY, chain="ethereum", is_proxy=False)
    session.add(contract)
    session.flush()
    observed = claims_bridge.verdict_to_claim(
        _verdict(EFFECT_CLASS_SUPPLY, witness={"supply_delta_sign": "mint"}, vid=1)
    )
    ef = EffectiveFunction(
        contract_id=contract.id,
        deployment_address=_DEPLOY,
        function_name="mint",
        selector=_SELECTOR,
        abi_signature="mint(address,uint256)",
        effect_labels=["mint"],
        claims=[observed],
        authority_public=False,
    )
    session.add(ef)
    session.flush()
    if with_verdict:
        session.add(
            EffectVerdict(
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
        )
    session.commit()
    return contract.id


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


@requires_postgres
def test_policy_rewrite_preserves_observed_claims_from_verdicts(db_session):
    contract_id = _seed_contract_with_observed_function(db_session, with_verdict=True)
    write_effective_function_rows(
        db_session,
        contract_id=contract_id,
        function_records=[_fn_record()],
        capability_by_function=None,
        deployment_address=_DEPLOY,
    )
    db_session.commit()
    ef = db_session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == contract_id).one()
    ids = [c["claim_id"] for c in (ef.claims or [])]
    assert "supply.mint" in ids
    assert any(c["tier"] == "behavioral_observed" for c in ef.claims)
    assert "mint" in (ef.effect_labels or [])


@requires_postgres
def test_policy_rewrite_preserves_observed_claims_without_surviving_verdict(db_session):
    """Repeated policy-only re-runs never blank the labels, even after the verdict was cascade-deleted."""
    contract_id = _seed_contract_with_observed_function(db_session, with_verdict=False)
    write_effective_function_rows(
        db_session,
        contract_id=contract_id,
        function_records=[_fn_record()],
        capability_by_function=None,
        deployment_address=_DEPLOY,
    )
    db_session.commit()
    ef = db_session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == contract_id).one()
    ids = [c["claim_id"] for c in (ef.claims or [])]
    assert "supply.mint" in ids
    assert "mint" in (ef.effect_labels or [])


@requires_postgres
def test_policy_rewrite_leaves_claimless_functions_byte_identical(db_session):
    contract = Contract(address="0x" + "cd" * 20, chain="ethereum", is_proxy=False)
    db_session.add(contract)
    db_session.flush()
    cid = contract.id
    db_session.commit()
    write_effective_function_rows(
        db_session,
        contract_id=cid,
        function_records=[dict(_fn_record(), effect_labels=["some_label"])],
        capability_by_function=None,
        deployment_address="0x" + "cd" * 20,
    )
    db_session.commit()
    ef = db_session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == cid).one()
    assert (ef.claims or []) == []
    assert ef.effect_labels == ["some_label"]
    _cleanup(db_session, cid)


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


@requires_postgres
def test_row_delete_without_recreate_nulls_function_id(db_session):
    contract_id, verdict_id = _seed_with_real_verdict(db_session)
    write_effective_function_rows(
        db_session,
        contract_id=contract_id,
        function_records=[],
        capability_by_function=None,
        deployment_address=_DEPLOY,
    )
    db_session.commit()
    db_session.expire_all()
    verdict = db_session.query(EffectVerdict).filter(EffectVerdict.id == verdict_id).one_or_none()
    assert verdict is not None
    assert verdict.function_id is None
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


def test_an_observed_flow_claim_keeps_the_static_destination_and_amount():
    """A fork observation proves value moved, not where or how much; replacing the witness wholesale made the
    executed ``redeem*`` lose its lattice.
    """
    merged = claims_bridge.merge_observed_claims(
        [_static_flow_out()],
        [_verdict(EFFECT_CLASS_VALUE_OUT, witness={"observation": "executed", "value_moved": True})],
    )
    flow_out = next(c for c in merged if c["claim_id"] == "flow.out")
    witness = flow_out["witness"]

    assert flow_out["tier"] == "behavioral_observed"
    assert witness["direction"] == "out"
    assert witness["flows"][0]["target_kind"] == {"kind": "immutable", "tier": "dispositive_ast"}
    assert witness["flows"][0]["amount_param_index"] == 1
    assert witness["effect_verdict_id"] == 1


def test_carrying_the_static_witness_forward_is_idempotent():
    verdicts = [_verdict(EFFECT_CLASS_VALUE_OUT, witness={"observation": "executed", "value_moved": True})]
    once = claims_bridge.merge_observed_claims([_static_flow_out()], verdicts)
    twice = claims_bridge.merge_observed_claims(once, verdicts)
    assert once == twice


def test_an_observed_claim_with_no_static_counterpart_is_unchanged():
    merged = claims_bridge.merge_observed_claims(
        [], [_verdict(EFFECT_CLASS_VALUE_OUT, witness={"observation": "executed", "value_moved": True})]
    )
    witness = next(c for c in merged if c["claim_id"] == "flow.out")["witness"]
    assert "flows" not in witness
    assert witness["effect_verdict_id"] == 1


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


def test_merge_into_function_keeps_the_static_lattice():
    """``merge_into_function`` is the only path that mints observed claims in production."""
    result = claims_bridge.merge_into_function([_static_flow_out()], [], [_executed()])
    assert result is not None
    claims, _labels = result
    flow_out = next(c for c in claims if c["claim_id"] == "flow.out")
    assert flow_out["tier"] == "behavioral_observed"
    assert flow_out["witness"]["flows"][0]["target_kind"] == {"kind": "immutable", "tier": "dispositive_ast"}
    assert flow_out["witness"]["direction"] == "out"


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


def test_repairing_a_damaged_row_is_idempotent():
    """The second pass is where a naive donor rule re-stamps ``static_tier``."""
    verdicts = [_executed()]
    once = claims_bridge.merge_observed_claims([_static_flow_out(), _damaged_observed_flow_out()], verdicts)
    twice = claims_bridge.merge_observed_claims(once, verdicts)
    thrice = claims_bridge.merge_observed_claims(twice, verdicts)
    assert once == twice == thrice
    assert next(c for c in once if c["claim_id"] == "flow.out")["witness"]["static_tier"] == "standard_exact"


def test_a_pause_claim_keeps_its_flags_and_polarity():
    """The erasure was never flow-specific."""
    static: Claim = {
        "claim_id": "pause.set",
        "tier": "idiom_structural",
        "witness": {"kind": "pause", "flags": ["deposit", "withdraw"], "polarity": "set"},
    }
    merged = claims_bridge.merge_observed_claims([static], [_verdict(EFFECT_CLASS_FREEZE_PAUSE)])
    witness = next(c for c in merged if c["claim_id"] == "pause.set")["witness"]
    assert witness["flags"] == ["deposit", "withdraw"]
    assert witness["polarity"] == "set"
    assert witness["static_tier"] == "idiom_structural"


def test_a_supply_claim_keeps_its_supply_and_selector():
    static: Claim = {
        "claim_id": "supply.mint",
        "tier": "standard_exact",
        "witness": {"kind": "supply", "supply": "increase", "selector": "0x40c10f19"},
    }
    merged = claims_bridge.merge_observed_claims(
        [static], [_verdict(EFFECT_CLASS_SUPPLY, witness={"supply_delta_sign": "mint"})]
    )
    witness = next(c for c in merged if c["claim_id"] == "supply.mint")["witness"]
    assert witness["supply"] == "increase"
    assert witness["selector"] == "0x40c10f19"
    assert witness["static_tier"] == "standard_exact"


def test_a_policy_derived_donor_is_stamped_as_such():
    """The scorer discounts on ``static_tier``, so the stamp must be the donor's tier, not the claim's."""
    static: Claim = {
        "claim_id": "flow.out",
        "tier": "policy_derived",
        "witness": {
            "kind": "value_flow",
            "callee": "0x" + "cd" * 20,
            "sink_id": "sink-9",
            "source_tier": "standard_exact",
        },
    }
    merged = claims_bridge.merge_observed_claims([static], [_executed()])
    witness = next(c for c in merged if c["claim_id"] == "flow.out")["witness"]
    assert witness["static_tier"] == "policy_derived"
    assert witness["sink_id"] == "sink-9"
    assert witness["callee"] == "0x" + "cd" * 20
    assert witness["source_tier"] == "standard_exact"


def test_no_static_donor_stamps_no_provenance():
    merged = claims_bridge.merge_observed_claims([], [_executed()])
    witness = next(c for c in merged if c["claim_id"] == "flow.out")["witness"]
    assert "flows" not in witness
    assert "static_tier" not in witness


@requires_postgres
def test_destination_shape_survives_the_writer_onto_the_function_row(db_session):
    """The scorer reads these off ``EffectiveFunction.claims``, and the adverse and non-observation answers are
    different facts.
    """
    for shape, proved_by, address in (
        ("caller_arbitrary", "simulation", "0x" + "d1" * 20),
        ("unknown", "none", "0x" + "d2" * 20),
    ):
        contract = Contract(address=address, chain="ethereum", is_proxy=False)
        db_session.add(contract)
        db_session.flush()
        ef = EffectiveFunction(
            contract_id=contract.id,
            deployment_address=address,
            function_name="manage",
            selector="0xf6e715d0",
            abi_signature="manage(address,bytes,uint256)",
            effect_labels=[],
            claims=[],
            authority_public=False,
        )
        db_session.add(ef)
        db_session.flush()
        db_session.add(
            EffectVerdict(
                function_id=ef.id,
                chain_id=1,
                contract_address=address,
                selector="0xf6e715d0",
                effect_class=EFFECT_CLASS_VALUE_OUT,
                behavior_hash="bh",
                verdict=VERDICT_PROVEN,
                tier=TIER_CALL,
                witness={
                    "value_moved": True,
                    "observation": "executed",
                    "destination_shape": shape,
                    "shape_proved_by": proved_by,
                },
            )
        )
        db_session.commit()

        write_effective_function_rows(
            db_session,
            contract_id=contract.id,
            function_records=[
                {
                    "function": "manage(address,bytes,uint256)",
                    "abi_signature": "manage(address,bytes,uint256)",
                    "selector": "0xf6e715d0",
                    "effect_labels": [],
                    "effect_targets": [],
                    "action_summary": "stub",
                    "authority_public": False,
                    "authority_roles": [],
                    "claims": [],
                }
            ],
            capability_by_function=None,
            deployment_address=address,
        )
        db_session.commit()
        db_session.expire_all()

        row = db_session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == contract.id).one()
        flow_out = next(c for c in (row.claims or []) if c["claim_id"] == "flow.out")
        observed = flow_out["witness"]["observed"]
        assert observed["destination_shape"] == shape
        assert observed["shape_proved_by"] == proved_by
        _purge_verdicts(db_session)
        _cleanup(db_session, contract.id)
