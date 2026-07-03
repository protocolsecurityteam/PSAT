"""Registry-side tests for the Plane-1 claims subsystem.

Drives the real production classes — ``build_claims``, ``ClaimContext``, the
registry, ``emit_claim``, and the shipped ``contract_deployment`` matcher — over
the documented Plane-0 facts interface (an ``effects``-shaped dict is input
data, not a faked collaborator). No Slither/DB, so these run in every offline
suite.
"""

from __future__ import annotations

import pytest

from services.static.claims import (
    CONSUMER_REFERENCED_CLAIM_IDS,
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
        view["x"] = object()  # type: ignore[index]


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
        emit_claim("contract_deployment", "guess", {})  # type: ignore[arg-type]


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
    assert ctx.has_functions("deploy", "ping")
    assert not ctx.has_functions("deploy", "missing")
    assert ctx.has_signature("deploy()")
    assert ctx.has_sink("deploy()", "contract_creation")
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
