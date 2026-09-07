"""Policy produces capability claims, never failure-shaped claims."""

from __future__ import annotations

from typing import Any

from pydantic import TypeAdapter

from schemas.assessment import Assessment
from services.assessment import (
    add_policy,
    build_static_assessment,
    function_authority_claims,
    project_permission_index,
)
from services.resolution.capabilities import CapabilityExpr, intersect
from services.resolution.capability_resolver import capability_to_dict


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
    row = {
        "function": "pause()",
        "abi_signature": "pause()",
        "authority_public": False,
        "authority_openness": "restricted",
        "direct_owner": None,
        "authority_roles": [],
        "controllers": [],
        **overrides,
    }
    if "capability_expr" not in row:
        members = [p["address"] for grant in row["controllers"] for p in grant.get("principals", [])]
        trace = []
        if row["direct_owner"]:
            members.append(row["direct_owner"]["address"])
        for grant in row["authority_roles"] or []:
            role_members = [p["address"] for p in grant["principals"]]
            members.extend(role_members)
            trace.append(
                {
                    "step": "solmate_roles_authority",
                    "roles": [grant["role"]],
                    "role_members": {str(grant["role"]): role_members},
                }
            )
        if row["authority_public"]:
            cap = {"kind": "conditional_universal"}
        elif members or row.get("status") == "resolved_empty":
            cap = {"kind": "finite_set", "members": members, "membership_quality": "exact", "trace": trace}
        else:
            cap = {
                "kind": "unsupported",
                "unsupported_reason": (
                    "role_principals_not_determined" if row["authority_roles"] is None else "authority_not_determined"
                ),
            }
        row["capability_expr"] = cap
    return {"schema_version": "1", "functions": [row]}


def test_role_trace_cannot_restore_a_caller_removed_by_intersection() -> None:
    alice, bob = "0x" + "2" * 40, "0x" + "3" * 40
    role = CapabilityExpr.finite_set(
        [alice, bob],
        trace=[
            {
                "step": "solmate_roles_authority",
                "roles": [8],
                "role_members": {"8": [alice, bob]},
            }
        ],
    )
    capability = capability_to_dict(intersect(role, CapabilityExpr.finite_set([alice])))
    result = add_policy(_base(), _permission(capability_expr=capability), chain_id=1)
    authority = function_authority_claims(result)[0]["proposition"].get("authority")
    assert authority == {"kind": "role", "role": "8", "entities": [f"1:{alice}"]}


def test_rejected_function_cannot_escape_into_permission_rows() -> None:
    result = add_policy(
        _base(),
        _permission(
            function="invented()",
            abi_signature="invented()",
            capability_expr={"kind": "conditional_universal"},
        ),
        chain_id=1,
    )
    assert project_permission_index(result)["functions"] == []


def test_permission_projection_round_trips_without_original_resolver_output() -> None:
    import json

    result = add_policy(_base(), _permission(authority_public=True, authority_openness="open"), chain_id=1)
    assert project_permission_index(json.loads(json.dumps(result))) == project_permission_index(result)


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
    inputs = [assessment["claims"][key]["proposition"]["kind"] for key in capabilities[0]["claims"]]
    assert inputs == ["function_authority", "function_effect"]


def test_policy_records_call_authority_without_a_classified_effect() -> None:
    assessment = add_policy(
        _base(),
        _permission(
            function="withdraw()",
            abi_signature="withdraw()",
            selector="0x3ccfd60b",
            authority_public=True,
            authority_openness="open",
        ),
        chain_id=1,
    )

    authority_claims = [
        claim for claim in assessment["claims"].values() if claim["proposition"]["kind"] == "function_authority"
    ]
    assert len(authority_claims) == 1
    assert authority_claims[0]["proposition"].get("function") == "withdraw()"
    assert authority_claims[0]["proposition"].get("authority") == {"kind": "public"}
    assert not any(
        claim["proposition"]["kind"] == "authority_capability" and claim["proposition"].get("function") == "withdraw()"
        for claim in assessment["claims"].values()
    )


def test_policy_uses_source_signature_when_abi_signature_differs() -> None:
    assessment = _base()
    assessment["functions"]["pause(Authority)"] = assessment["functions"].pop("pause()")
    for evidence in assessment["evidence"].values():
        if evidence["subject_kind"] == "function" and evidence["subject"] == "pause()":
            evidence["subject"] = "pause(Authority)"
    for claim in assessment["claims"].values():
        if claim["proposition"].get("function") == "pause()":
            claim["proposition"]["function"] = "pause(Authority)"

    enriched = add_policy(
        assessment,
        _permission(
            function="pause(Authority)",
            abi_signature="pause(address)",
            selector="0x8456cb59",
            authority_public=True,
            authority_openness="open",
        ),
        chain_id=1,
    )

    receipt = next(item for item in enriched["analyses"] if item["detector"] == "policy.capabilities")
    assert receipt["status"] == "completed"
    assert receipt["omissions"] == []
    assert any(
        claim["proposition"]["kind"] == "function_authority"
        and claim["proposition"].get("function") == "pause(Authority)"
        for claim in enriched["claims"].values()
    )


def test_policy_falls_back_to_a_unique_selector_and_refuses_a_collision() -> None:
    base = _base()
    unique = add_policy(
        base,
        _permission(
            function="pause(address)",
            abi_signature="pause(address)",
            selector="0x8456cb59",
            authority_public=True,
            authority_openness="open",
        ),
        chain_id=1,
    )
    assert any(
        claim["proposition"]["kind"] == "function_authority" and claim["proposition"].get("function") == "pause()"
        for claim in unique["claims"].values()
    )

    collision = _base()
    collision["functions"]["otherPause()"] = {
        "abi_signature": "otherPause()",
        "selector": "0x8456cb59",
        "state_changing": True,
    }
    refused = add_policy(
        collision,
        _permission(
            function="pause(address)",
            abi_signature="pause(address)",
            selector="0x8456cb59",
            authority_public=True,
            authority_openness="open",
        ),
        chain_id=1,
    )
    receipt = next(item for item in refused["analyses"] if item["detector"] == "policy.capabilities")
    assert receipt["status"] == "failed"
    assert receipt["omissions"][0]["reason"] == "policy_function_not_in_contract:ambiguous_selector:0x8456cb59"


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
    assessment = add_policy(_base(), _permission(authority_public=True), chain_id=1)
    projected = project_permission_index(assessment)
    claims = projected["functions"][0]["claims"]
    assert [claim["claim_id"] for claim in claims] == ["pause.set"]
    assert claims[0]["witness"]["flags"] == [{"var": "paused", "member": None}]
    assert claims[0]["witness"]["evidence_ids"]


def test_permission_authority_is_projected_from_assessment_evidence() -> None:
    assessment = add_policy(
        _base(),
        _permission(authority_public=True, authority_openness="open"),
        chain_id=1,
    )
    projected = project_permission_index(assessment)
    function = projected["functions"][0]

    assert function["authority_public"] is True
    assert function["authority_openness"] == "open"
    assert function.get("status") is None


def test_resolved_empty_permission_keeps_projection_evidence_without_a_claim() -> None:
    assessment = add_policy(
        _base(),
        _permission(status="resolved_empty", authority_roles=[]),
        chain_id=1,
    )

    assert not function_authority_claims(assessment)
    evidence = [item for item in assessment["evidence"].values() if item["producer"] == "policy.capability"]
    assert len(evidence) == 1
    projected = project_permission_index(assessment)
    assert projected["functions"][0]["status"] == "resolved_empty"
    assert projected["functions"][0]["authority_public"] is False


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
    assert not any(claim["proposition"]["kind"] == "function_authority" for claim in refreshed["claims"].values())
    evidence = [item for item in refreshed["evidence"].values() if item["producer"] == "policy.capability"]
    assert len(evidence) == 1
    observation = evidence[0]["observation"]
    assert isinstance(observation, dict)
    assert observation["status"] == "resolved_empty"


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

    assert authority == {"kind": "public", "conditions": expression["conditions"]}


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
            {
                "kind": "finite_set",
                "members": ["0x2222222222222222222222222222222222222222"],
                "membership_quality": "exact",
            },
            {
                "kind": "threshold_group",
                "threshold": {"m": 2, "signers": ["0x3", "0x4", "0x5"]},
            },
        ],
    }
    authority = _capability_authority(_permission(capability_expr=expression))
    assert authority["kind"] == "all"
    children = authority.get("children")
    assert children is not None
    assert children[0] == {"kind": "entity", "entity": "1:0x2222222222222222222222222222222222222222"}
    assert children[1] == {
        "kind": "expression",
        "expression": expression["children"][1],
        "conditions": [],
    }
