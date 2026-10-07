from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from services.static.claims import (
    CONSUMER_REFERENCED_CLAIM_IDS,
    GRANT_CLASSES,
    Claim,
    ClaimContext,
    ClaimEvidence,
    RegistryEntry,
    attach_claims_to_effects,
    build_claims,
    claim_ids_of_class,
    discover,
    emit_claim,
    grant_class_of,
    is_registered,
    register,
    registry,
    resolve_claim_precedence,
    single_contract_static_tier,
)
from services.static.claims.registry import _REGISTRY
from utils.claim_ids import ALL_CLAIM_IDS


@pytest.fixture(autouse=True)
def _registered_matchers():
    discover()


def _facts(*, with_creation: bool = True) -> dict:
    deploy_sinks = (
        [
            {
                "id": "deploy():sink0:contract_creation:Child",
                "function": "deploy()",
                "kind": "contract_creation",
                "target": "Child",
                "selector": None,
            }
        ]
        if with_creation
        else []
    )
    return {
        "schema_version": "semantic",
        "contract_name": "Factory",
        "functions": {
            "deploy()": {
                "function": "deploy()",
                "selector": "0x775c300c",
                "sinks": deploy_sinks,
                "effect_labels": ["contract_deployment"] if with_creation else [],
            },
            "ping()": {
                "function": "ping()",
                "selector": "0x5c36b186",
                "sinks": [
                    {
                        "id": "ping():sink0:state_write:counter",
                        "function": "ping()",
                        "kind": "state_write",
                        "target": "counter",
                        "selector": None,
                    }
                ],
                "effect_labels": [],
            },
        },
    }


def test_emit_claim_valid_copies_witness():
    witness = {"kind": "sink", "sink_ids": ["a"]}
    claim = emit_claim("contract_deployment", "standard_exact", witness)
    assert claim == {
        "claim_id": "contract_deployment",
        "tier": "standard_exact",
        "witness": {"kind": "sink", "sink_ids": ["a"]},
    }
    witness["kind"] = "mutated"
    assert claim["witness"]["kind"] == "sink"  # emit_claim copied the witness


@pytest.mark.parametrize(
    ("claim_id", "tier", "match"),
    [
        pytest.param("nope.not_a_claim", "standard_exact", "unregistered claim_id", id="unregistered_id"),
        pytest.param("contract_deployment", "guess", "invalid claim tier", id="non_literal_tier"),
    ],
)
def test_emit_claim_rejects_invalid_input(claim_id, tier, match):
    with pytest.raises(ValueError, match=match):
        emit_claim(claim_id, tier, {})


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda e: {**e, "claim_id": ""}, "non-empty"),
        (lambda e: {**e, "sentence": "  "}, "written sentence"),
        (lambda e: {**e, "consumer_family": "nonsense"}, "consumer_family"),
        (lambda e: {**e, "grant_class": "control"}, "grant_class"),
        (lambda e: {**e, "grant_class": None}, "grant_class"),
        (lambda e: {**e, "gate": "not-callable"}, "callables"),
    ],
)
def test_register_enforces_entry_contract(mutate, match):
    base = dict(
        claim_id="test.contract_check",
        sentence="a sentence",
        gate=lambda _ctx: True,
        trigger=lambda _ctx, _fn: None,
        legacy_projection=None,
        consumer_family="control_plane",
        grant_class="control.gate",
    )
    with pytest.raises((ValueError, TypeError), match=match):
        register(RegistryEntry(**mutate(base)))
    assert not is_registered("test.contract_check")


def test_register_rejects_duplicate():
    entry = RegistryEntry(
        claim_id="test.dup_claim",
        sentence="dup",
        gate=lambda _ctx: True,
        trigger=lambda _ctx, _fn: None,
        legacy_projection=None,
        consumer_family="control_plane",
        grant_class="control.gate",
    )
    register(entry)
    try:
        with pytest.raises(ValueError, match="duplicate"):
            register(entry)
    finally:
        _REGISTRY.pop("test.dup_claim", None)


def test_claim_context_accessors():
    trees = {
        "trees": {"deploy()": {"op": "LEAF", "leaf": {"authority_role": "caller_authority"}}},
        "canonical_signatures": {"deploy()": "deploy()"},
    }
    ctx = ClaimContext(contract=None, effects=_facts(), predicate_trees=trees)
    assert ctx.function_signatures() == ["deploy()", "ping()"]
    assert ctx.function_names() == {"deploy", "ping"}
    assert ctx.sink_ids("deploy()", "contract_creation") == ["deploy():sink0:contract_creation:Child"]
    assert ctx.sink_ids("ping()", "contract_creation") == []
    assert ctx.effect_labels("deploy()") == ["contract_deployment"]
    assert ctx.selector("deploy()") == "0x775c300c"
    assert ctx.canonical_signature("deploy()") == "deploy()"
    assert ctx.predicate_tree("deploy()") is not None
    assert ctx.effect_record("ping()")["function"] == "ping()"
    assert ctx.contract_name == "Factory"


def test_claim_context_tolerates_degraded_effects():
    ctx = ClaimContext(contract=None, effects={"schema_version": "semantic", "error": "boom"}, predicate_trees=None)
    assert ctx.function_signatures() == []
    assert ctx.sinks("anything()") == []
    assert ctx.effect_labels("anything()") == []
    assert ctx.selector("anything()") is None
    assert ctx.canonical_signature("anything()") is None


def test_build_claims_emits_contract_deployment_only_for_creation_sink():
    artifact = build_claims(None, _facts(), {})
    assert artifact["schema_version"] == "claims/1"
    assert artifact["contract_name"] == "Factory"
    deploy_claims = artifact["functions"]["deploy()"]
    assert len(deploy_claims) == 1
    assert deploy_claims[0]["claim_id"] == "contract_deployment"
    assert deploy_claims[0]["tier"] == "standard_exact"
    assert deploy_claims[0]["witness"]["sink_ids"] == ["deploy():sink0:contract_creation:Child"]
    assert artifact["functions"]["ping()"] == []


def test_build_claims_on_degraded_effects_is_empty():
    artifact = build_claims(None, {"schema_version": "semantic", "error": "boom"}, None)
    assert artifact["functions"] == {}


def test_attach_claims_merges_onto_effects_records():
    effects = _facts()
    artifact = build_claims(None, effects, {})
    attach_claims_to_effects(effects, artifact)
    assert effects["functions"]["deploy()"]["claims"][0]["claim_id"] == "contract_deployment"
    assert effects["functions"]["ping()"]["claims"] == []


def test_attach_claims_tolerates_degraded_effects():
    attach_claims_to_effects({"schema_version": "semantic", "error": "boom"}, {"functions": {}})
    attach_claims_to_effects(None, {"functions": {}})


@pytest.mark.parametrize("failure_at", [0, 1, 2])
def test_build_claims_isolates_a_failing_matcher(failure_at, monkeypatch):
    from utils.logging import degraded_errors_var

    visited = []

    def _boom(_ctx: ClaimContext, fn: str) -> ClaimEvidence | None:
        visited.append(fn)
        if len(visited) - 1 == failure_at:
            raise RuntimeError("matcher blew up")
        return ClaimEvidence(tier="idiom_structural", witness={"function": fn})

    entry = RegistryEntry(
        claim_id="test.raising_matcher",
        sentence="always explodes",
        gate=lambda _ctx: True,
        trigger=_boom,
        legacy_projection=None,
        consumer_family="control_plane",
        grant_class="control.gate",
    )
    effects = _facts()
    effects["functions"]["last()"] = {"sinks": [], "effect_labels": []}
    errors: list = []
    token = degraded_errors_var.set(errors)
    register(entry)
    monkeypatch.setattr("services.static.claims.builder.registry", lambda: {entry.claim_id: entry, **registry()})
    try:
        artifact = build_claims(None, effects, {})
    finally:
        _REGISTRY.pop("test.raising_matcher", None)
        degraded_errors_var.reset(token)
    assert artifact["functions"]["deploy()"][0]["claim_id"] == "contract_deployment"
    assert len(visited) == failure_at + 1
    assert all(c["claim_id"] != entry.claim_id for claims in artifact["functions"].values() for c in claims)
    assert len(errors) == 1
    assert errors[0].context["claim_id"] == entry.claim_id
    assert any(entry.claim_id in message for message in artifact.get("errors", []))


def test_consumer_referenced_ids_are_subset_of_registry():
    build_claims(None, _facts(with_creation=False), {})  # ensure discovery ran
    assert CONSUMER_REFERENCED_CLAIM_IDS <= set(registry())


_CONTROL_GATE = (
    "ownership.transfer ownership.renounce ownership.accept roles.grant roles.revoke roles.configure authority.replace "
    "authority.grant authorized_caller.rotate callee_pointer.rotate proxy.admin_change safe.signer_mgmt "
    "safe.module_mgmt safe.set_guard timelock.schedule timelock.execute timelock.cancel timelock.set_delay "
    "lz_oapp.set_peer lz_oapp.set_delegate"
)
# The owner-ruled class of every claim. A new registration must be classed here deliberately.
_RULED_GRANT_CLASSES = {
    **dict.fromkeys(_CONTROL_GATE.split(), "control.gate"),
    **dict.fromkeys(("upgrade.implementation", "exec.arbitrary", "delegatecall.execute"), "control.code"),
    **dict.fromkeys(("pause.set", "pause.unset"), "control.pause"),
    "transfer_policy.configure": "control.config",
    **dict.fromkeys(("flow.out", "supply.mint", "supply.burn"), "control.funds"),
    **dict.fromkeys(("flow.in", "value_router", "contract_deployment"), "operational"),
    **dict.fromkeys(
        ("erc20.approve", "erc20.transfer", "erc20.transfer_from", "weth.deposit", "weth.withdraw", "gov.delegate"),
        "user",
    ),
    "rate_limit.consume": "fact",
}


def test_every_registered_claim_has_a_valid_grant_class():
    every_id = claim_ids_of_class(*GRANT_CLASSES)
    assert every_id == set(registry())
    assert all(registry()[claim_id].grant_class in GRANT_CLASSES for claim_id in every_id)


def test_grant_classes_match_the_ruled_table():
    assert {claim_id: grant_class_of(claim_id) for claim_id in claim_ids_of_class(*GRANT_CLASSES)} == (
        _RULED_GRANT_CLASSES
    )
    assert not claim_ids_of_class("exemption"), "exemption is reserved until a producer proves a bypassed check"


def test_claim_id_constants_name_exactly_the_registered_ids():
    assert ALL_CLAIM_IDS == claim_ids_of_class(*GRANT_CLASSES)


def test_class_lookups_fail_closed():
    assert grant_class_of("not.a.claim") is None
    with pytest.raises(ValueError, match="unknown grant_class"):
        claim_ids_of_class("control")


def test_class_lookups_load_no_slither():
    """The membership gate and the monitor's scorer look classes up in processes that never analyze."""
    code = (
        "import sys; from services.static.claims import claim_ids_of_class; claim_ids_of_class('control.code'); "
        "assert 'slither' not in sys.modules"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]


@pytest.mark.parametrize(
    ("claim", "expected"),
    [
        ({"tier": "standard_exact", "witness": {}}, "standard_exact"),
        ({"tier": "idiom_structural", "witness": {}}, "idiom_structural"),
        ({"tier": "policy_derived", "witness": {}}, None),
        ({"tier": "policy_derived", "witness": {"static_tier": "standard_exact"}}, None),
        ({"tier": "behavioral_observed", "witness": {"effect_verdict_id": 1}}, None),
        ({"tier": "behavioral_observed", "witness": {"static_tier": "idiom_structural"}}, "idiom_structural"),
        ({"tier": "behavioral_observed", "witness": {"static_tier": "policy_derived"}}, None),
        ({"tier": "behavioral_observed", "witness": None}, None),
    ],
)
def test_single_contract_static_tier(claim, expected):
    assert single_contract_static_tier(claim) == expected


_GOLDEN_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "label_corpus" / "golden.json"

# Ids the reduced corpus doesn't exercise, with their validation basis. Remove ids when the corpus produces them.
_SAFE_EXEMPTION = (
    "no Safe in the label corpus; canonical variants and authentication-removed twins "
    "were checked manually for PR #245."
)
_AUTH_MATCHERS_EXEMPTION = "no compiled corpus positive; covered by test_claims_auth_matchers (synthetic facts)."
_UPGRADE_EXEC_EXEMPTION = (
    "no compiled corpus positive; covered by test_claims_upgrade_exec_matchers (small synthetic .sol fixtures)."
)
CORPUS_EXEMPT_CLAIM_IDS = {
    "contract_deployment": (
        "no contract factory in the label corpus; covered by this file's synthetic "
        "factory and test_claims_pipeline_integration (compiled upgrade_factory_uups.sol)."
    ),
    "authorized_caller.rotate": _AUTH_MATCHERS_EXEMPTION,
    "ownership.accept": _AUTH_MATCHERS_EXEMPTION,
    "roles.grant": _AUTH_MATCHERS_EXEMPTION,
    "roles.revoke": _AUTH_MATCHERS_EXEMPTION,
    "gov.delegate": (
        "no Comp-style voting token in the reduced corpus; the gate is facts-only, "
        "covered by test_claims_behavior_families::test_gov_delegate_positive_writes_delegates_and_checkpoints."
    ),
    "proxy.admin_change": _UPGRADE_EXEC_EXEMPTION,
    "upgrade.implementation": (
        "no proxy/impl pair in the reduced corpus; covered by test_claims_upgrade_exec_matchers "
        "(uups_eeth_upgrade.sol / proxy_shell_wbeth.sol) and test_claims_pipeline_integration."
    ),
    "timelock.schedule": _UPGRADE_EXEC_EXEMPTION,
    "timelock.execute": _UPGRADE_EXEC_EXEMPTION,
    "timelock.cancel": _UPGRADE_EXEC_EXEMPTION,
    "timelock.set_delay": _UPGRADE_EXEC_EXEMPTION,
    "safe.signer_mgmt": _SAFE_EXEMPTION,
    "safe.module_mgmt": _SAFE_EXEMPTION,
    "safe.set_guard": _SAFE_EXEMPTION,
    # cast_wrapped_pull.sol's execBatch is a direct executor, so the golden produces exec.arbitrary.
    "transfer_policy.configure": (
        "policy-tier claim: minted only downstream from sibling facts, so the "
        "single-contract static corpus never produces it; covered by "
        "test_cross_contract_effects and test_cross_contract_policy_claims."
    ),
    "authority.grant": (
        "behavioral_observed claim: minted only by the effects claims bridge from a "
        "proven authority-change verdict, never by the static pass (gate/trigger "
        "inert); covered by test_effects_claims_bridge."
    ),
}


def _golden_produced_claim_ids() -> set[str]:
    golden = json.loads(_GOLDEN_PATH.read_text())
    return {
        claim["claim_id"]
        for contract in golden.get("contracts", [])
        for function in contract.get("functions", [])
        for claim in function.get("claims", [])
    }


def test_every_registry_id_is_produced_by_the_corpus_or_exempt():
    """A dead claim is a build failure rather than silent rot."""
    build_claims(None, _facts(with_creation=False), {})  # ensure discovery ran
    registry_ids = set(registry())
    produced = _golden_produced_claim_ids()
    exempt = set(CORPUS_EXEMPT_CLAIM_IDS)

    uncovered = registry_ids - produced - exempt
    assert not uncovered, (
        f"registry claim ids neither produced by the frozen corpus nor exempt: {sorted(uncovered)}. "
        "Add a corpus fixture that produces them (regenerate the golden), or a documented "
        "CORPUS_EXEMPT_CLAIM_IDS entry naming the fixture that covers them."
    )
    stale = exempt & produced
    assert not stale, f"CORPUS_EXEMPT_CLAIM_IDS names ids the corpus now produces: {sorted(stale)}. Remove them."
    assert exempt <= registry_ids, f"exemptions for unregistered ids: {sorted(exempt - registry_ids)}"


def test_precedence_keeps_strongest_tier_of_the_same_claim():
    claims: list[Claim] = [
        {"claim_id": "upgrade.implementation", "tier": "idiom_structural", "witness": {"w": 1}},
        {"claim_id": "upgrade.implementation", "tier": "standard_exact", "witness": {"w": 2}},
        {"claim_id": "upgrade.implementation", "tier": "policy_derived", "witness": {"w": 3}},
    ]
    resolved = resolve_claim_precedence(claims)
    assert len(resolved) == 1
    assert resolved[0]["tier"] == "standard_exact"
    assert resolved[0]["witness"] == {"w": 2}  # the surviving witness is the strong one


def test_precedence_preserves_distinct_sibling_claims_in_one_family():
    claims: list[Claim] = [
        {"claim_id": "pause.unset", "tier": "idiom_structural", "witness": {}},
        {"claim_id": "pause.set", "tier": "standard_exact", "witness": {}},
        {"claim_id": "flow.out", "tier": "idiom_structural", "witness": {}},
    ]
    resolved = resolve_claim_precedence(claims)
    assert [c["claim_id"] for c in resolved] == ["flow.out", "pause.set", "pause.unset"]


def test_precedence_output_is_deterministically_sorted():
    claims: list[Claim] = [
        {"claim_id": "supply.mint", "tier": "standard_exact", "witness": {}},
        {"claim_id": "authority.replace", "tier": "standard_exact", "witness": {}},
    ]
    resolved = resolve_claim_precedence(claims)
    assert [c["claim_id"] for c in resolved] == ["authority.replace", "supply.mint"]


# The canonical ABI selector is what the cross-contract join keys on.


def _sweep_effects() -> dict:
    return {
        "contract_name": "AssetRecovery",
        "functions": {
            # The interface-typed keccak (0x38541c00) is not the dispatched selector (0x0aeef8c8).
            "sweepTo(IERC20,address,uint256)": {"selector": "0x38541c00", "sinks": []},
            "sweep(address)": {"selector": "0x01681a62", "sinks": []},
            # Hashing the rendered name would manufacture one.
            "receive()": {"selector": "", "sinks": []},
            "fallback()": {"selector": "", "sinks": []},
        },
    }


_SWEEP_TREES = {"canonical_signatures": {"sweepTo(IERC20,address,uint256)": "sweepTo(address,address,uint256)"}}


def test_build_claims_records_the_canonical_abi_selector():
    artifact = build_claims(None, _sweep_effects(), _SWEEP_TREES)
    assert "abi_selectors" in artifact
    selectors = artifact.get("abi_selectors") or {}
    assert selectors["sweepTo(IERC20,address,uint256)"] == "0x0aeef8c8"
    assert selectors["sweep(address)"] == "0x01681a62"


def test_build_claims_never_fabricates_a_selector():
    """Absence is the not-determined state; a consumer must fall back."""
    artifact = build_claims(None, _sweep_effects(), {})  # no canonical map
    assert "abi_selectors" in artifact
    selectors = artifact.get("abi_selectors") or {}
    assert "receive()" not in selectors
    assert "fallback()" not in selectors
    assert "sweepTo(IERC20,address,uint256)" not in selectors
    assert selectors["sweep(address)"] == "0x01681a62"


def test_attach_stamps_abi_selector_beside_the_declared_one():
    effects = _sweep_effects()
    artifact = build_claims(None, effects, _SWEEP_TREES)
    attach_claims_to_effects(effects, artifact)
    record = effects["functions"]["sweepTo(IERC20,address,uint256)"]
    assert record["abi_selector"] == "0x0aeef8c8"
    assert record["selector"] == "0x38541c00"  # the declared form stays
    assert "abi_selector" not in effects["functions"]["receive()"]
    assert "abi_selector" not in effects["functions"]["fallback()"]


def test_attach_tolerates_an_artifact_without_the_selector_map():
    effects = _sweep_effects()
    artifact = build_claims(None, effects, _SWEEP_TREES)
    del artifact["abi_selectors"]
    attach_claims_to_effects(effects, artifact)
    assert all("abi_selector" not in rec for rec in effects["functions"].values())
