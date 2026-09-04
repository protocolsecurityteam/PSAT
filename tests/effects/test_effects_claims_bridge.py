"""Effects → claims bridge.

Pure-mapping honesty per effect class, the two fail-closed directions,
idempotent double-merge, and behavioral_observed precedence over a static claim.
The DB-backed writer regression (call site 2 preserves observed claims across a policy rewrite) and
the end-to-end worker labeling (call site 1) live in
``test_permission_index_semantic``-style / ``test_effects_worker_integration``
files respectively; this file owns the bridge's own contract.
"""

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
from services.static.claims.types import EffectMatch


def _static(claim_id: str, tier: str = "standard_exact", **witness: Any) -> EffectMatch:
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
    # Backing: the fork mint-backing object must reach claim.witness["observed"] so the
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
    # Downstream reach: the fork reach fields ride the flow.out claim witness — read
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
    """Reach floor: the not-measured state survives projection whole, so a scorer sees
    "downstream reach not witnessed; the acting contract's own balance is a floor".

    ``observed_reach_value_usd`` is ABSENT on such a row (the producer no
    longer publishes the floor under the key that means measured reach), and
    ``reach_determined: False`` is the discriminator. Both new keys must be in the
    projection allowlist or they are silently dropped one layer before the consumer.
    """
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
    """NO claim in the database carried ``destination_shape`` or
    ``shape_proved_by``: the fork proved ``caller_arbitrary`` on 35 rows and a consumer
    had never seen it, while the two approve-then-pull rows published $472M of reach
    with no destination statement at all (their transfer sink lives in the callee, so
    the static matcher emitted nothing to carry forward).

    Unconditional, not scoped to those two rows: the class is 7 functions — 2 manifest,
    5 latent — and each new successful probe converts a latent one, so a fix keyed on
    "the 2 rows" would be wrong the next time coverage improves."""
    witness = {"value_moved": True, "destination_shape": "unknown", "shape_proved_by": "none"}
    claim = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_VALUE_OUT, witness=witness))
    assert claim is not None
    observed = claim["witness"]["observed"]
    assert observed["destination_shape"] == "unknown"
    assert observed["shape_proved_by"] == "none"

    # ...and the proven-adverse answer travels identically.
    proven_witness = {"value_moved": True, "destination_shape": "caller_arbitrary", "shape_proved_by": "simulation"}
    proven_claim = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_VALUE_OUT, witness=proven_witness))
    assert proven_claim is not None
    assert proven_claim["witness"]["observed"]["destination_shape"] == "caller_arbitrary"
    assert proven_claim["witness"]["observed"]["shape_proved_by"] == "simulation"


def test_the_sentinel_subject_travels_with_the_answer():
    """A shape with no stated subject is a proof about an unnamed parameter. The
    scorer's exec join (``distill._fork_caller_arbitrary_param``) refuses one, so
    dropping the name here is what left 15 already-proven fork witnesses unread."""
    witness = {
        "value_moved": True,
        "destination_shape": "caller_arbitrary",
        "shape_proved_by": "simulation",
        "sentinel_param": "data",
    }
    claim = claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_VALUE_OUT, witness=witness))
    assert claim is not None
    assert claim["witness"]["observed"]["sentinel_param"] == "data"

    # Absent stays absent — never a null, never a default.
    bare = claims_bridge.verdict_to_claim(
        _verdict(EFFECT_CLASS_VALUE_OUT, witness={k: v for k, v in witness.items() if k != "sentinel_param"})
    )
    assert bare is not None
    assert "sentinel_param" not in bare["witness"]["observed"]


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
    # The fork pause recipe records observed_blast_radius / auto_expiry /
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


def test_a_duration_bound_never_reaches_the_scorer_without_its_fork_qualifier():
    """The duration-bound CONTAINMENT PIN, scorer half.

    ``duration_bound_seconds`` is a STATIC read of a guard constant and the fork
    cross-check (warp ``bound + 1`` and re-probe) is the only thing that turns it into
    a mitigation: the documented contract is "trust it as a severity REDUCER ONLY when
    ``auto_expiry is True``". That containment is what keeps a fabricated constant —
    the harvest published lead times and cooldown offsets as freeze windows until it
    was narrowed — from ever scoring as a shorter freeze.

    So the pin is on the PAIRING: whenever the projection forwards a bound it must
    also forward the qualifier the witness recorded, in every one of its three states,
    and it must forward ``duration_bound_source`` so ``None`` stays two facts. A future
    edit that trims the keep-list to the number alone would leave a consumer unable to
    apply the rule and unable to tell that it could not."""
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
        # Present, not defaulted: the key must exist even when its value is None.
        assert "auto_expiry" in observed and observed["auto_expiry"] is expiry
        assert observed["duration_bound_source"] == "guard_constant"


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
    from services.static.claims.registry import is_registered

    assert is_registered(claims_bridge.AUTHORITY_GRANT)


# ---------------------------------------------------------------------------
# Fail-closed
# ---------------------------------------------------------------------------


def test_unknown_verdict_mints_nothing():
    assert claims_bridge.verdict_to_claim(_verdict(EFFECT_CLASS_VALUE_OUT, verdict=VERDICT_UNKNOWN)) is None


def test_historical_with_failed_current_check_mints_nothing():
    # Tier-0 historical proves PAST capability; a failed current check means a
    # present-tense label would overclaim ⇒ withhold.
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


# ---------------------------------------------------------------------------
# Call site 2 (DB): a policy rewrite of the rows preserves observed claims.
# ---------------------------------------------------------------------------

from db.models import Contract, EffectiveFunction, EffectVerdict  # noqa: E402
from services.policy.permission_index_writer import write_permission_rows  # noqa: E402
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
        "authority_public": False,
        "authority_roles": [],
        "claims": [],
    }


@requires_postgres
def test_policy_rewrite_relinks_verdict_without_recreating_claims(db_session):
    """Verdict facts survive, but claims come only from the Assessment projection."""
    contract_id = _seed_contract_with_observed_function(db_session, with_verdict=True)
    write_permission_rows(
        db_session,
        contract_id=contract_id,
        function_records=[_fn_record()],
        deployment_address=_DEPLOY,
    )
    db_session.commit()
    ef = db_session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == contract_id).one()
    assert (ef.claims or []) == []
    verdict = db_session.query(EffectVerdict).filter(EffectVerdict.function_id == ef.id).one()
    assert verdict.effect_class == EFFECT_CLASS_SUPPLY


@requires_postgres
def test_policy_rewrite_retracts_outgoing_claims_not_in_assessment_projection(db_session):
    contract_id = _seed_contract_with_observed_function(db_session, with_verdict=False)
    write_permission_rows(
        db_session,
        contract_id=contract_id,
        function_records=[_fn_record()],
        deployment_address=_DEPLOY,
    )
    db_session.commit()
    ef = db_session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == contract_id).one()
    assert (ef.claims or []) == []


@requires_postgres
def test_policy_rewrite_leaves_claimless_functions_byte_identical(db_session):
    """No observed state ⇒ the row is written exactly as the records say (no
    spurious claims/labels from the bridge)."""
    contract = Contract(address="0x" + "cd" * 20, chain="ethereum", is_proxy=False)
    db_session.add(contract)
    db_session.flush()
    cid = contract.id
    db_session.commit()
    write_permission_rows(
        db_session,
        contract_id=cid,
        function_records=[_fn_record()],
        deployment_address="0x" + "cd" * 20,
    )
    db_session.commit()
    ef = db_session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == cid).one()
    assert (ef.claims or []) == []
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
    row relinks to the re-created function row without minting relational claims."""
    contract_id, verdict_id = _seed_with_real_verdict(db_session)
    write_permission_rows(
        db_session,
        contract_id=contract_id,
        function_records=[_fn_record()],
        deployment_address=_DEPLOY,
    )
    db_session.commit()
    db_session.expire_all()
    verdict = db_session.query(EffectVerdict).filter(EffectVerdict.id == verdict_id).one_or_none()
    assert verdict is not None
    ef = db_session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == contract_id).one()
    assert verdict.function_id == ef.id
    assert (ef.claims or []) == []
    _purge_verdicts(db_session)


@requires_postgres
def test_row_delete_without_recreate_nulls_function_id(db_session):
    """A function dropped from the new surface keeps its verdict rows (identity =
    deployment coordinates) with the convenience join nulled, not cascaded away."""
    contract_id, verdict_id = _seed_with_real_verdict(db_session)
    write_permission_rows(
        db_session,
        contract_id=contract_id,
        function_records=[],
        deployment_address=_DEPLOY,
    )
    db_session.commit()
    db_session.expire_all()
    verdict = db_session.query(EffectVerdict).filter(EffectVerdict.id == verdict_id).one_or_none()
    assert verdict is not None
    assert verdict.function_id is None
    _purge_verdicts(db_session)


# ---------------------------------------------------------------------------
# Precedence must not cost the function its static lattice
# ---------------------------------------------------------------------------


def _static_flow_out() -> EffectMatch:
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


# ---------------------------------------------------------------------------
# ...and the repair must reach the seam the effects worker actually calls,
# on rows that are ALREADY damaged.
# ---------------------------------------------------------------------------


def _damaged_observed_flow_out() -> EffectMatch:
    """A ``flow.out`` claim as the bug left it on disk: the observed pointer, and
    nothing else. 19 rows in the preview DB look exactly like this."""
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


@requires_postgres
def test_destination_shape_survives_the_writer_onto_the_function_row(db_session):
    """End of the forwarding chain. ``destination_shape`` / ``shape_proved_by`` are
    the fork's answer to "where can this outflow go", and the scorer reads them off
    ``EffectiveFunction.claims`` — so the Assessment projection reaching the
    row writer must retain both fields, for the adverse
    answer and for the ``('unknown', 'none')`` non-observation alike (they are
    different facts and the consumer must keep telling them apart)."""
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

        write_permission_rows(
            db_session,
            contract_id=contract.id,
            function_records=[
                {
                    "function": "manage(address,bytes,uint256)",
                    "abi_signature": "manage(address,bytes,uint256)",
                    "selector": "0xf6e715d0",
                    "authority_public": False,
                    "authority_roles": [],
                    "claims": [
                        {
                            "claim_id": "flow.out",
                            "tier": "behavioral_observed",
                            "witness": {"observed": {"destination_shape": shape, "shape_proved_by": proved_by}},
                        }
                    ],
                }
            ],
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
