"""Effects → claims bridge (EFFECTS_RESOLUTION_SPEC §5.2).

Pure-mapping honesty per effect class, the two §8 fail-closed directions,
idempotent double-merge, behavioral_observed precedence over a static claim, and
legacy effect_labels re-projection staying in sync. The DB-backed writer
regression (call site 2 preserves observed claims across a policy rewrite) and
the end-to-end worker labeling (call site 1) live in
``test_effective_permissions_semantic``-style / ``test_effects_worker_integration``
files respectively; this file owns the bridge's own contract.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.effects import claims_bridge  # noqa: E402
from services.effects.config import (  # noqa: E402
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
from services.static.claims.registry import resolve_claim_precedence  # noqa: E402
from services.static.claims.types import Claim  # noqa: E402


def _static(claim_id: str, tier: str = "standard_exact", **witness: Any) -> Claim:
    return {"claim_id": claim_id, "tier": tier, "witness": witness}  # type: ignore[typeddict-item]


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


# ---------------------------------------------------------------------------
# Mapping honesty, per class
# ---------------------------------------------------------------------------


def test_code_upgrade_maps_to_upgrade_implementation():
    claim = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_CODE_UPGRADE))
    assert claim is not None
    assert claim["claim_id"] == "upgrade.implementation"
    assert claim["tier"] == "behavioral_observed"
    # Witness is a pointer, never a transcript.
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
    # §5a: the fork mint-backing object must reach claim.witness["observed"] so the
    # scorer/frontend can tell a backed conversion from an unbacked (dilutive) mint.
    backing = {"inflow_observed": False, "minted": True, "inflow_transfers": 0, "mint_transfers": 1}
    claim = claims_bridge.verdict_to_claim(
        _verdict(EFFECT_CLASS_SUPPLY, witness={"supply_delta_sign": "mint", "backing": backing})
    )
    assert claim is not None and claim["claim_id"] == "supply.mint"
    assert claim["witness"]["observed"]["backing"] == backing


def test_supply_without_sign_fails_closed():
    # No observed sign ⇒ the recipe proved a delta shape we cannot name; withhold.
    assert claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_SUPPLY, witness={})) is None
    assert claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_SUPPLY, witness=None)) is None


def test_freeze_pause_maps_to_pause_set_only():
    # The pause recipe only ever witnesses a freeze — there is no unpause
    # direction — so a proven freeze_pause is always pause.set, never pause.unset.
    claim = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_FREEZE_PAUSE, tier=TIER_FORK))
    assert claim is not None and claim["claim_id"] == "pause.set"


def test_value_out_projects_reach_into_observed_witness():
    # §5b: the fork downstream-reach fields ride the flow.out claim witness — read
    # from the per-deployment ``observed_residue`` column, never the witness.
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
    # §5b floor: reach_indeterminate + floored value both survive projection so the
    # scorer sees "downstream reach not witnessed, floored to own balance".
    residue = {"observed_reach_value_usd": 221_000_000.0, "reach_indeterminate": True}
    claim = claims_bridge.verdict_to_claim(
        _verdict(EFFECT_CLASS_VALUE_OUT, witness={"value_moved": True}, observed_residue=residue)
    )
    assert claim is not None
    observed = claim["witness"]["observed"]
    assert observed["reach_indeterminate"] is True
    assert observed["observed_reach_value_usd"] == 221_000_000.0


def test_reach_is_never_read_off_the_cacheable_witness():
    # The plane leak this fix closes: while reach sat on ``witness`` it was
    # written to the CROSS-DEPLOYMENT behavioral cache and re-published as another
    # deployment's observation on every hit. Witness-borne reach values are the
    # contaminated shape and must not project.
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
    # §1 A2: the fork pause recipe records observed_blast_radius / auto_expiry /
    # duration_bound_seconds on the verdict witness (verdict 318's real shape); the
    # projection must carry all three into claim.witness["observed"] so the scorer
    # can tell a $3.4B/30-day freeze from a harmless one.
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
    # duration None + auto_expiry None = indefinite latch = most severe; the
    # projection must carry the None values through (present, not dropped) so the
    # scorer sees "indefinite", never an absent-field default.
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


def test_no_blast_verdict_mints_no_behavioral_claim():
    # The 58/65 no-blast verdicts take the fork unknown path — they must mint NO
    # behavioral claim (absent blast radius is an unproven lower bound, not a proven
    # "no freeze"). A verdict==unknown never mints regardless of its witness fields.
    witness = {"observed_blast_radius": [], "scored_denominator": ["a()", "b()"]}
    claim = claims_bridge.verdict_to_claim(
        _verdict(EFFECT_CLASS_FREEZE_PAUSE, verdict=VERDICT_UNKNOWN, tier=TIER_FORK, witness=witness)
    )
    assert claim is None


def test_freeze_fields_absent_for_non_freeze_class():
    # The added keep keys are a no-op for other classes: a value_out verdict whose
    # witness happens to lack them projects no freeze fields (dict-comp keeps only
    # present keys).
    claim = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_VALUE_OUT, witness={"value_moved": True}))
    assert claim is not None
    observed = claim["witness"].get("observed", {})
    assert "observed_blast_radius" not in observed
    assert "auto_expiry" not in observed
    assert "duration_bound_seconds" not in observed


def test_authority_change_maps_to_registered_authority_grant():
    # None of roles.grant / authority.replace / authorized_caller.rotate is honest
    # for a mechanism-agnostic gate-open; the bridge mints its own registered id.
    claim = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_AUTHORITY_CHANGE, witness={"gate_mutation": True}))
    assert claim is not None and claim["claim_id"] == claims_bridge.AUTHORITY_GRANT
    # Registered, so it can be rendered / projected like any static claim.
    from services.static.claims.registry import is_registered, legacy_projections

    assert is_registered(claims_bridge.AUTHORITY_GRANT)
    assert legacy_projections()[claims_bridge.AUTHORITY_GRANT] == "authority_update"


# ---------------------------------------------------------------------------
# §8 fail-closed
# ---------------------------------------------------------------------------


def test_unknown_verdict_mints_nothing():
    assert claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_VALUE_OUT, verdict=VERDICT_UNKNOWN)) is None


def test_historical_with_failed_current_check_mints_nothing():
    # Tier-0 historical proves PAST capability; a failed current check means a
    # present-tense label would overclaim (inv. 13) ⇒ withhold.
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


# ---------------------------------------------------------------------------
# Merge: idempotency, precedence, re-projection
# ---------------------------------------------------------------------------


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
    # flow.out projects the legacy "asset_send"; prior labels are preserved (union).
    assert "asset_send" in labels
    assert "some_prior_label" in labels


def test_merge_into_function_identity_when_no_verdict_mints():
    # No mintable verdict ⇒ None, so the caller leaves the row byte-identical.
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


# ---------------------------------------------------------------------------
# Call site 2 (DB): a policy rewrite of the rows preserves observed claims.
# ---------------------------------------------------------------------------

from db.models import Contract, EffectiveFunction, EffectVerdict  # noqa: E402
from services.policy.effective_permissions_writer import write_effective_function_rows  # noqa: E402
from tests.conftest import requires_postgres  # noqa: E402

_SELECTOR = "0x40c10f19"
_DEPLOY = "0x" + "ab" * 20


def _seed_contract_with_observed_function(session, *, with_verdict: bool):
    """A contract whose one effective_function already carries a
    behavioral_observed claim (as call site 1 would have written), optionally with
    the backing proven effect_verdict still present."""
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
    # A fresh policy write for the same function — no claims of its own (the
    # regression is that the wholesale replace would blank the observed label).
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
    """Call site 2, verdict path: proven effect_verdicts survive the capture and
    re-merge onto the re-created row."""
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
    """Call site 2, durable path: even when the proven verdict was already cascade-
    deleted by an earlier replace, the observed claims on the outgoing rows are
    carried forward — so repeated policy-only re-runs never blank the labels."""
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
    """No observed state ⇒ the row is written exactly as the records say (no
    spurious claims/labels from the bridge)."""
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


# ---------------------------------------------------------------------------
# Row replace vs effect_verdicts: verdicts are durable state-plane residue keyed
# on deployment coordinates — a policy rewrite must never destroy them, and the
# function_id convenience join relinks to the re-created row.
# ---------------------------------------------------------------------------


def _seed_with_real_verdict(session):
    """A contract whose effective_function has a proven verdict row and an
    observed claim whose witness points at that REAL verdict id (as call site 1
    writes it) — so the dangle assertion below is exact."""
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
    """The row replace must not delete the deployment's verdicts; the surviving
    row relinks to the re-created function row and no carried observed claim's
    witness may point at a dead verdict."""
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
    """A function dropped from the new surface keeps its verdict rows (identity =
    deployment coordinates) with the convenience join nulled, not cascaded away."""
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
