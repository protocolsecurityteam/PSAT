"""Registry-side tests for the Plane-1 claims subsystem.

Drives the real production classes — ``build_claims``, ``ClaimContext``, the
registry, ``emit_claim``, and the shipped ``contract_deployment`` matcher — over
the documented Plane-0 facts interface (an ``effects``-shaped dict is input
data, not a faked collaborator). No Slither/DB, so these run in every offline
suite.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# Importing the policy-site module registers its policy-tier claim
# (``transfer_policy.configure``) so the registry invariants below see it
# deterministically regardless of test order.
import services.effects.claims_bridge
import services.static.cross_contract  # noqa: F401
from services.static.claims import (
    CONSUMER_REFERENCED_CLAIM_IDS,
    Claim,
    ClaimContext,
    ClaimEvidence,
    RegistryEntry,
    attach_claims_to_effects,
    build_claims,
    emit_claim,
    is_registered,
    legacy_projections,
    register,
    registry,
    resolve_claim_precedence,
)
from services.static.claims.registry import _REGISTRY


def _facts(*, with_creation: bool = True) -> dict:
    """An ``effects``-shaped facts artifact: a factory fn (creation sink) and a
    plain state-writing fn (no sink of interest)."""
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


# ---------------------------------------------------------------------------
# Registry + emit_claim (the anti-creep contract)
# ---------------------------------------------------------------------------


def test_registry_populated_by_autodiscovery():
    build_claims(None, _facts(with_creation=False), {})  # forces discover()
    assert is_registered("contract_deployment")
    entry = registry()["contract_deployment"]
    assert entry.sentence.strip()
    assert entry.legacy_projection == "contract_deployment"
    assert entry.consumer_family == "exec"
    assert legacy_projections()["contract_deployment"] == "contract_deployment"


def test_registry_view_is_read_only():
    view = registry()
    with pytest.raises(TypeError):
        view["x"] = object()  # pyright: ignore[reportIndexIssue]


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


def test_emit_claim_rejects_unregistered_id():
    with pytest.raises(ValueError, match="unregistered claim_id"):
        emit_claim("nope.not_a_claim", "standard_exact", {})


def test_emit_claim_rejects_non_literal_tier():
    with pytest.raises(ValueError, match="invalid claim tier"):
        emit_claim("contract_deployment", "guess", {})  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda e: {**e, "claim_id": ""}, "non-empty"),
        (lambda e: {**e, "sentence": "  "}, "written sentence"),
        (lambda e: {**e, "consumer_family": "nonsense"}, "consumer_family"),
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
    )
    register(entry)
    try:
        with pytest.raises(ValueError, match="duplicate"):
            register(entry)
    finally:
        _REGISTRY.pop("test.dup_claim", None)


# ---------------------------------------------------------------------------
# ClaimContext (tolerant facts view)
# ---------------------------------------------------------------------------


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
    assert ctx.selector("anything()") == ""
    assert ctx.canonical_signature("anything()") is None


# ---------------------------------------------------------------------------
# build_claims / attach_claims_to_effects
# ---------------------------------------------------------------------------


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


def test_build_claims_empty_when_no_matcher_fires():
    artifact = build_claims(None, _facts(with_creation=False), {})
    assert all(claims == [] for claims in artifact["functions"].values())


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
    # Must not raise on an errored artifact with no functions dict.
    attach_claims_to_effects({"schema_version": "semantic", "error": "boom"}, {"functions": {}})
    attach_claims_to_effects(None, {"functions": {}})


def test_build_claims_isolates_a_failing_matcher():
    """A matcher that raises forfeits only its own claims; the shipped
    contract_deployment matcher still fires."""

    def _boom(_ctx: ClaimContext, _fn: str) -> ClaimEvidence | None:
        raise RuntimeError("matcher blew up")

    entry = RegistryEntry(
        claim_id="test.raising_matcher",
        sentence="always explodes",
        gate=lambda _ctx: True,
        trigger=_boom,
        legacy_projection=None,
        consumer_family="control_plane",
    )
    register(entry)
    try:
        artifact = build_claims(None, _facts(), {})
    finally:
        _REGISTRY.pop("test.raising_matcher", None)
    assert artifact["functions"]["deploy()"][0]["claim_id"] == "contract_deployment"
    assert all(c["claim_id"] != "test.raising_matcher" for c in artifact["functions"]["deploy()"])


# ---------------------------------------------------------------------------
# Consumer-coverage invariant (registry-side)
# ---------------------------------------------------------------------------


def test_consumer_referenced_ids_are_subset_of_registry():
    build_claims(None, _facts(with_creation=False), {})  # ensure discovery ran
    assert CONSUMER_REFERENCED_CLAIM_IDS <= set(registry())


# The produced-side half of the coverage invariant: registry ids must
# appear in the frozen-corpus fixture output or carry a documented exemption.
_GOLDEN_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "label_corpus" / "golden.json"

# Registry claim ids the reduced corpus does not exercise, each mapped to the
# test that DOES cover it (positive + negative). Keep this minimal and honest: an
# id that starts producing on the corpus must be removed here (the test fails
# otherwise). The five-contract corpus deliberately compiles only a handful of
# real sources, so the auth / upgrade / exec / timelock / safe families are
# covered by the synthetic-facts and small-fixture matcher suites instead.
_SAFE_EXEMPTION = "no Gnosis Safe in the label corpus; covered by test_claims_upgrade_exec_matchers (safe_wallet.sol)."
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
    # exec.arbitrary is produced by the corpus: cast_wrapped_pull.sol's execBatch is
    # a DIRECT targets[i].call(data[i]) executor (a true executor, not a
    # fixed-destination library forwarder), so it mints the claim in the golden.
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
    """Produced-side coverage invariant: every registered claim can be minted —
    it appears in the frozen-corpus golden or carries a documented exemption
    pointing at the fixture that produces it. This is what makes a dead claim a
    build failure rather than silent rot."""
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


# ---------------------------------------------------------------------------
# Per-function precedence/dedup rule (standard_exact beats idiom_structural)
# ---------------------------------------------------------------------------


def test_precedence_keeps_strongest_tier_of_the_same_claim():
    """Two witnesses for the SAME claim on one function collapse to the strongest
    tier — a standard proof supersedes a structural idiom / policy derivation."""
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
    """Sibling operations in a namespace are different sentences, never collapsed:
    pause.set and pause.unset both survive even at different tiers."""
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


# ---------------------------------------------------------------------------
# The canonical ABI selector is computed at build time and stamped at
# attach time — the value the cross-contract join keys on.
# ---------------------------------------------------------------------------


def _sweep_effects() -> dict:
    return {
        "contract_name": "AssetRecovery",
        "functions": {
            # Declared signature carries an interface-typed param: its keccak
            # (0x38541c00) is NOT the dispatched selector (0x0aeef8c8).
            "sweepTo(IERC20,address,uint256)": {"selector": "0x38541c00", "sinks": []},
            # Elementary signature: canonical == declared.
            "sweep(address)": {"selector": "0x01681a62", "sinks": []},
            # No selector by construction; hashing the rendered name would
            # manufacture one.
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
    """Three not-determined shapes, all OMITTED from the map (absence is the
    not-determined state — a consumer must fall back, never infer):
    fallback/receive (no selector exists), and a user-typed signature with no
    canonical mapping and no Slither subject to lower it."""
    artifact = build_claims(None, _sweep_effects(), {})  # no canonical map
    assert "abi_selectors" in artifact
    selectors = artifact.get("abi_selectors") or {}
    assert "receive()" not in selectors
    assert "fallback()" not in selectors
    assert "sweepTo(IERC20,address,uint256)" not in selectors
    # The elementary signature is still lowerable from its own text.
    assert selectors["sweep(address)"] == "0x01681a62"


def test_attach_stamps_abi_selector_beside_the_declared_one():
    effects = _sweep_effects()
    artifact = build_claims(None, effects, _SWEEP_TREES)
    attach_claims_to_effects(effects, artifact)
    record = effects["functions"]["sweepTo(IERC20,address,uint256)"]
    assert record["abi_selector"] == "0x0aeef8c8"
    assert record["selector"] == "0x38541c00"  # the declared form stays
    # Not-determined stays ABSENT, never null and never fabricated.
    assert "abi_selector" not in effects["functions"]["receive()"]
    assert "abi_selector" not in effects["functions"]["fallback()"]


def test_attach_tolerates_an_artifact_without_the_selector_map():
    """Claims artifacts minted before ``abi_selectors`` existed attach exactly
    as before — key absent on every record."""
    effects = _sweep_effects()
    artifact = build_claims(None, effects, _SWEEP_TREES)
    del artifact["abi_selectors"]
    attach_claims_to_effects(effects, artifact)
    assert all("abi_selector" not in rec for rec in effects["functions"].values())
