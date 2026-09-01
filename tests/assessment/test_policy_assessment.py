"""Policy produces capability claims, never failure-shaped claims."""

from __future__ import annotations

from typing import Any

from pydantic import TypeAdapter

from schemas.assessment import Assessment
from services.assessment import add_policy, build_static_assessment, project_permission_index


def _base() -> Assessment:
    effects = {
        "schema_version": "semantic-2",
        "claims_schema_version": "claims/1",
        "contract_name": "Vault",
        "functions": {
            "pause()": {
                "function": "pause()",
                "selector": "0x8456cb59",
                "abi_signature": "pause()",
                "state_changing": True,
                "state_writes": [{"var": "paused", "declared_type": "bool"}],
                "claims": [
                    {
                        "claim_id": "pause.set",
                        "tier": "idiom_structural",
                        "witness": {
                            "kind": "pause_flag",
                            "flags": [{"var": "paused", "member": None}],
                            "polarity": "set",
                            "affected_functions": ["withdraw()"],
                        },
                    }
                ],
            },
            "withdraw()": {
                "function": "withdraw()",
                "selector": "0x3ccfd60b",
                "abi_signature": "withdraw()",
                "state_changing": True,
                "state_writes": [],
                "claims": [],
            },
        },
        "claim_analyses": {
            "pause.set": {
                "detector": "pause.set",
                "status": "completed",
                "targets_total": 2,
                "targets_completed": 2,
                "omissions": [],
            }
        },
        "claim_diagnostics": [],
    }
    return build_static_assessment(
        chain_id=1,
        address="0x1111111111111111111111111111111111111111",
        contract_name="Vault",
        code_hash=None,
        source_hash="0xsource",
        static_facts={"controller_tracking": []},
        effects=effects,
        predicate_trees={
            "schema_version": "semantic",
            "trees": {
                "withdraw()": {
                    "op": "LEAF",
                    "leaf": {
                        "operator": "falsy",
                        "operands": [{"source": "state_variable", "state_variable_name": "paused"}],
                    },
                }
            },
        },
    )


def _permission(**overrides: object) -> dict:
    return {
        "schema_version": "1",
        "functions": [
            {
                "function": "pause()",
                "abi_signature": "pause()",
                "authority_public": False,
                "authority_openness": "restricted",
                "direct_owner": None,
                "authority_roles": [],
                "controllers": [],
                **overrides,
            }
        ],
    }


def test_public_authority_produces_a_capability_claim() -> None:
    assessment = add_policy(
        _base(),
        _permission(authority_public=True, authority_openness="open"),
        chain_id=1,
    )
    TypeAdapter(Assessment).validate_python(assessment)

    capabilities = [
        claim for claim in assessment["claims"].values() if claim["proposition"]["kind"] == "authority_capability"
    ]
    assert len(capabilities) == 1
    proposition = capabilities[0]["proposition"]
    assert proposition["kind"] == "authority_capability"
    assert proposition.get("authority") == {"kind": "public"}
    assert proposition.get("effect", {}).get("kind") == "pause.set"
    assert len(capabilities[0]["claims"]) == 1


def test_unresolved_authority_is_an_omission_not_a_claim() -> None:
    assessment = add_policy(
        _base(),
        _permission(authority_openness="not_determined", authority_roles=None),
        chain_id=1,
    )

    assert not any(claim["proposition"]["kind"] == "authority_capability" for claim in assessment["claims"].values())
    receipt = assessment["analyses"][-1]
    assert receipt["status"] == "failed"
    assert receipt["omissions"][0]["reason"] == "role_principals_not_determined"


def test_permission_claims_are_projected_from_the_assessment() -> None:
    assessment = _base()
    projected = project_permission_index(assessment, _permission())
    claims = projected["functions"][0]["claims"]
    assert [claim["claim_id"] for claim in claims] == ["pause.set"]
    assert claims[0]["witness"]["flags"] == [{"var": "paused", "member": None}]
    assert claims[0]["witness"]["evidence_ids"]


def test_policy_refresh_retracts_a_superseded_public_capability() -> None:
    public = add_policy(
        _base(),
        _permission(authority_public=True, authority_openness="open"),
        chain_id=1,
    )
    refreshed = add_policy(
        public,
        _permission(authority_public=False, authority_openness="restricted", status="resolved_empty"),
        chain_id=1,
    )

    assert not any(claim["proposition"]["kind"] == "authority_capability" for claim in refreshed["claims"].values())
    assert not any(evidence["producer"] == "policy.capability" for evidence in refreshed["evidence"].values())


def _capability_authority(permission: dict) -> Any:
    assessment = add_policy(_base(), permission, chain_id=1)
    capability = next(
        claim for claim in assessment["claims"].values() if claim["proposition"]["kind"] == "authority_capability"
    )
    proposition = capability["proposition"]
    assert proposition["kind"] == "authority_capability"
    authority = proposition.get("authority")
    assert authority is not None
    return authority


def test_conditional_public_authority_keeps_its_condition() -> None:
    expression = {
        "kind": "conditional_universal",
        "conditions": [{"kind": "time", "description": "after cooldown"}],
    }
    authority = _capability_authority(
        _permission(
            authority_public=True,
            authority_openness="open",
            capability_expr=expression,
            conditions=expression["conditions"],
        )
    )

    assert authority == {
        "kind": "expression",
        "expression": expression,
        "conditions": expression["conditions"],
    }


def test_threshold_authority_keeps_threshold_semantics() -> None:
    expression = {
        "kind": "threshold_group",
        "threshold": {
            "m": 2,
            "signers": [
                "0x2222222222222222222222222222222222222222",
                "0x3333333333333333333333333333333333333333",
            ],
        },
    }
    authority = _capability_authority(_permission(capability_expr=expression))
    assert authority["kind"] == "expression"
    assert authority["expression"] == expression


def test_irreducible_all_authority_keeps_composite_semantics() -> None:
    expression = {
        "kind": "AND",
        "children": [
            {"kind": "finite_set", "members": ["0x2222222222222222222222222222222222222222"]},
            {
                "kind": "threshold_group",
                "threshold": {"m": 2, "signers": ["0x3", "0x4", "0x5"]},
            },
        ],
    }
    authority = _capability_authority(_permission(capability_expr=expression))
    assert authority == {"kind": "expression", "expression": expression, "conditions": []}
