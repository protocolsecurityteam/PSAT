import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.policy.effective_permissions import build_effective_permissions


def _effect(
    signature: str,
    *,
    targets: list[str] | None = None,
    labels: list[str] | None = None,
    claims: list[dict] | None = None,
    summary: str = "Performs a contract action.",
    sink_kind: str = "state_write",
) -> dict:
    return {
        signature: {
            "effect_targets": targets or [],
            "effect_labels": labels or [],
            "claims": claims or [],
            "action_summary": summary,
            "sinks": [{"kind": sink_kind, "target": (targets or ["state"])[0]}],
        }
    }


def _claim(claim_id: str, tier: str = "idiom_structural") -> dict:
    return {"claim_id": claim_id, "tier": tier, "witness": {}}


def _effects(*records: dict) -> dict:
    functions: dict = {}
    for record in records:
        functions.update(record)
    return {"schema_version": "semantic", "functions": functions}


def _finite_cap(*members: str) -> dict:
    return {
        "kind": "finite_set",
        "members": list(members),
        "membership_quality": "exact",
        "confidence": "enumerable",
    }


def _state_var_tree(*names: str) -> dict:
    return {
        "op": "LEAF",
        "leaf": {
            "kind": "equality",
            "operator": "eq",
            "authority_role": "caller_authority",
            "operands": [{"source": "msg_sender"}]
            + [{"source": "state_variable", "state_variable_name": name} for name in names],
            "references_msg_sender": True,
            "parameter_indices": [],
            "expression": "caller matches state variable",
            "basis": [],
        },
    }


def _predicate_trees(**trees: dict) -> dict:
    return {"schema_version": "semantic", "trees": trees}


def test_build_effective_permissions_uses_semantic_artifacts_over_static_summary():
    target_analysis = {
        "subject": {
            "address": "0x1111111111111111111111111111111111111111",
            "name": "Target",
        },
        "semantic_control": {
            "semantic_functions": [
                {
                    "function": "summaryPause()",
                    "controller_refs": ["owner"],
                    "effect_targets": ["summary"],
                    "effect_labels": ["summary"],
                    "action_summary": "Static summary record.",
                }
            ]
        },
    }
    effects = _effects(_effect("pause()", targets=["paused"], labels=["pause_toggle"], summary="Pauses the contract."))
    capability_resolver_output = {
        "pause()": _finite_cap("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    }

    payload = build_effective_permissions(
        target_analysis,
        capability_resolver_output=capability_resolver_output,
        effects=effects,
    )

    assert [fn["function"] for fn in payload["functions"]] == ["pause()"]
    pause = payload["functions"][0]
    assert pause["effect_labels"] == ["pause_toggle"]
    assert pause["effect_targets"] == ["paused"]
    assert pause.get("capability_expr") == capability_resolver_output["pause()"]


def test_build_effective_permissions_does_not_use_static_summary_without_semantic_artifacts():
    target_analysis = {
        "subject": {
            "address": "0x1111111111111111111111111111111111111111",
            "name": "Target",
        },
        "semantic_control": {
            "semantic_functions": [
                {
                    "function": "pause()",
                    "controller_refs": ["owner"],
                    "effect_targets": ["paused"],
                    "effect_labels": ["pause_toggle"],
                    "action_summary": "Static summary record.",
                }
            ]
        },
    }

    payload = build_effective_permissions(target_analysis)

    assert payload["functions"] == []


def test_build_effective_permissions_marks_effect_only_semantic_functions_public_when_resolver_is_empty():
    target_analysis = {
        "subject": {
            "address": "0x1111111111111111111111111111111111111111",
            "name": "Target",
        },
        "semantic_control": {"semantic_functions": []},
    }
    effects = _effects(
        _effect(
            "getImplementation()",
            targets=["_IMPLEMENTATION_SLOT.getAddressSlot"],
            labels=["external_contract_call"],
            summary="Calls an external contract from the contract context.",
            sink_kind="external_call",
        )
    )

    payload = build_effective_permissions(target_analysis, capability_resolver_output={}, effects=effects)

    fn = payload["functions"][0]
    assert fn["function"] == "getImplementation()"
    assert fn.get("status") == "public"
    assert fn["authority_public"] is True
    cap = fn.get("capability_expr")
    assert isinstance(cap, dict)
    assert cap["kind"] == "conditional_universal"
    assert cap["conditions"] == []


def test_build_effective_permissions_marks_effect_only_semantic_functions_unsupported_when_resolver_is_missing():
    target_analysis = {
        "subject": {
            "address": "0x1111111111111111111111111111111111111111",
            "name": "Target",
        },
        "semantic_control": {"semantic_functions": []},
    }
    effects = _effects(_effect("upgradeTo(address)", targets=["implementation"], labels=["implementation_update"]))

    payload = build_effective_permissions(target_analysis, effects=effects)

    fn = payload["functions"][0]
    assert fn["function"] == "upgradeTo(address)"
    assert fn.get("status") == "unsupported"
    assert fn["authority_public"] is False
    assert fn.get("capability_expr", {}).get("unsupported_reason") == "missing_semantic_capability_resolver_output"


def test_build_effective_permissions_marks_exact_empty_principal_set_resolved_empty():
    target_analysis = {
        "subject": {
            "address": "0x1111111111111111111111111111111111111111",
            "name": "Target",
        },
        "semantic_control": {"semantic_functions": []},
    }
    cap = _finite_cap()

    payload = build_effective_permissions(
        target_analysis,
        capability_resolver_output={"recover(address)": cap},
        effects=_effects(_effect("recover(address)", labels=["asset_send"])),
    )

    fn = payload["functions"][0]
    assert fn["function"] == "recover(address)"
    assert fn.get("status") == "resolved_empty"
    assert fn["authority_public"] is False
    assert fn.get("capability_expr") == cap


def test_build_effective_permissions_keeps_lower_bound_empty_as_unresolved_gap():
    target_analysis = {
        "subject": {
            "address": "0x1111111111111111111111111111111111111111",
            "name": "Target",
        },
        "semantic_control": {"semantic_functions": []},
    }
    cap = {
        "kind": "finite_set",
        "members": [],
        "membership_quality": "lower_bound",
        "confidence": "partial",
    }

    payload = build_effective_permissions(
        target_analysis,
        capability_resolver_output={"recover(address)": cap},
        effects=_effects(_effect("recover(address)", labels=["asset_send"])),
    )

    fn = payload["functions"][0]
    assert fn.get("status") is None
    assert fn.get("capability_expr") == cap


def test_build_effective_permissions_uses_semantic_capabilities_for_principals():
    target_analysis = {
        "subject": {
            "address": "0x1111111111111111111111111111111111111111",
            "name": "Target",
        },
        "semantic_control": {
            "semantic_functions": [
                {
                    "function": "manage(address,bytes,uint256)",
                    "controller_refs": ["authority", "owner"],
                    "effect_targets": ["target.functionCallWithValue"],
                    "effect_labels": ["arbitrary_external_call"],
                    "action_summary": "Executes arbitrary external calldata from the contract.",
                },
                {
                    "function": "setBeforeTransferHook(address)",
                    "controller_refs": ["authority", "owner"],
                    "effect_targets": ["hook"],
                    "effect_labels": ["hook_update"],
                    "action_summary": "Updates hook configuration that can affect later contract behavior.",
                },
            ]
        },
    }
    target_snapshot = {
        "contract_name": "Target",
        "controller_values": {
            "external_contract:authority": {
                "value": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "resolved_type": "contract",
                "details": {"address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            },
            "state_variable:owner": {
                "value": "0x0000000000000000000000000000000000000000",
                "resolved_type": "zero",
                "details": {"address": "0x0000000000000000000000000000000000000000"},
            },
        },
    }
    authority_snapshot = {
        "contract_name": "RolesAuthority",
        "controller_values": {
            "state_variable:owner": {
                "value": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "resolved_type": "safe",
                "details": {
                    "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "owners": [
                        "0x1111111111111111111111111111111111111111",
                        "0x2222222222222222222222222222222222222222",
                    ],
                    "threshold": 2,
                },
            }
        },
    }
    payload = build_effective_permissions(
        target_analysis,
        target_snapshot=target_snapshot,
        authority_snapshot=authority_snapshot,
        capability_resolver_output={
            "manage(address,bytes,uint256)": _finite_cap("0xcccccccccccccccccccccccccccccccccccccccc"),
            "setBeforeTransferHook(address)": _finite_cap("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        },
        effects=_effects(
            _effect(
                "manage(address,bytes,uint256)",
                targets=["target.functionCallWithValue"],
                labels=["arbitrary_external_call"],
                claims=[_claim("exec.arbitrary", tier="standard_exact")],
                summary="Executes arbitrary external calldata from the contract.",
                sink_kind="external_call",
            ),
            _effect(
                "setBeforeTransferHook(address)",
                targets=["hook"],
                labels=["hook_update"],
                claims=[_claim("callee_pointer.rotate")],
                summary="Updates hook configuration that can affect later contract behavior.",
            ),
        ),
    )

    assert payload["authority_contract"] is None
    assert payload["principal_resolution"]["status"] == "complete"
    functions: dict[str, Any] = {item["function"]: item for item in payload["functions"]}

    manage = functions["manage(address,bytes,uint256)"]
    assert manage["selector"] == "0xf6e715d0"
    assert manage["effect_labels"] == ["arbitrary_external_call"]
    # The Plane-1 claim provenance rides through to the payload alongside the
    # legacy projection, so a consumer can key off the typed claim id.
    assert [c["claim_id"] for c in manage["claims"]] == ["exec.arbitrary"]
    assert manage["action_summary"] == "Executes arbitrary external calldata from the contract."
    assert manage["authority_roles"] == []
    manage_cap = manage.get("capability_expr")
    assert isinstance(manage_cap, dict)
    assert manage_cap["members"] == ["0xcccccccccccccccccccccccccccccccccccccccc"]
    hook = functions["setBeforeTransferHook(address)"]
    assert hook["selector"] == "0x8929565f"
    assert hook["effect_targets"] == ["hook"]
    # ``hook_update`` is now the legacy projection of the ``callee_pointer.rotate``
    # claim; both are carried.
    assert hook["effect_labels"] == ["hook_update"]
    assert [c["claim_id"] for c in hook["claims"]] == ["callee_pointer.rotate"]
    assert hook["authority_roles"] == []
    hook_cap = hook.get("capability_expr")
    assert isinstance(hook_cap, dict)
    assert hook_cap["members"] == ["0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]


def test_build_effective_permissions_projects_mixed_public_or_capability():
    target_analysis = {
        "subject": {
            "address": "0x1111111111111111111111111111111111111111",
            "name": "Target",
        },
        "semantic_control": {"semantic_functions": []},
    }
    cap = {
        "kind": "OR",
        "children": [
            _finite_cap("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            {
                "kind": "conditional_universal",
                "conditions": [{"kind": "business", "description": "public capability enabled"}],
                "membership_quality": "exact",
                "confidence": "enumerable",
            },
        ],
        "membership_quality": "exact",
        "confidence": "enumerable",
    }

    payload = build_effective_permissions(
        target_analysis,
        capability_resolver_output={"send(bytes,address)": cap},
        effects=_effects(_effect("send(bytes,address)", labels=["asset_send"])),
    )

    fn = payload["functions"][0]
    assert fn["function"] == "send(bytes,address)"
    assert fn["authority_public"] is True
    assert fn.get("status") == "public"
    assert fn.get("conditions") == [{"kind": "business", "description": "public capability enabled"}]
    assert fn.get("capability_expr") == cap


def test_build_effective_permissions_with_authority_snapshot():
    target_analysis = {
        "subject": {
            "address": "0x1111111111111111111111111111111111111111",
            "name": "Target",
        },
        "semantic_control": {
            "semantic_functions": [
                {
                    "function": "manage(address,bytes,uint256)",
                    "controller_refs": ["authority"],
                    "effect_targets": ["target.functionCallWithValue"],
                    "effect_labels": ["arbitrary_external_call"],
                    "action_summary": "Executes arbitrary external calldata from the contract.",
                }
            ]
        },
    }
    target_snapshot = {
        "contract_name": "Target",
        "controller_values": {
            "external_contract:authority": {
                "value": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "resolved_type": "contract",
                "details": {"address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            }
        },
    }
    authority_snapshot = {"contract_name": "Authority", "controller_values": {}}
    payload = build_effective_permissions(
        target_analysis,
        target_snapshot=target_snapshot,
        authority_snapshot=authority_snapshot,
        capability_resolver_output={
            "manage(address,bytes,uint256)": _finite_cap("0xcccccccccccccccccccccccccccccccccccccccc"),
        },
        effects=_effects(
            _effect(
                "manage(address,bytes,uint256)",
                targets=["target.functionCallWithValue"],
                labels=["arbitrary_external_call"],
                summary="Executes arbitrary external calldata from the contract.",
                sink_kind="external_call",
            )
        ),
    )

    assert payload["contract_name"] == "Target"
    assert payload["authority_contract"] is None
    assert payload["principal_resolution"]["status"] == "complete"
    assert payload["functions"][0]["effect_labels"] == ["arbitrary_external_call"]


def test_build_effective_permissions_handles_vyper_dynarray_signatures():
    target_analysis = {
        "subject": {
            "address": "0x1111111111111111111111111111111111111111",
            "name": "GateSeal",
        },
        "semantic_control": {
            "semantic_functions": [
                {
                    "function": "seal(DynArray[address,MAX_SEALABLES])",
                    "controller_refs": ["SEALING_COMMITTEE"],
                    "effect_targets": [],
                    "effect_labels": ["external_contract_call", "pause_toggle"],
                    "action_summary": "Calls an external contract from the contract context.",
                }
            ]
        },
    }
    target_snapshot = {
        "contract_name": "GateSeal",
        "controller_values": {
            "state_variable:SEALING_COMMITTEE": {
                "source": "SEALING_COMMITTEE",
                "value": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "resolved_type": "safe",
                "details": {
                    "address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "owners": ["0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
                    "threshold": 1,
                },
            }
        },
    }

    payload = build_effective_permissions(
        target_analysis,
        target_snapshot=target_snapshot,
        predicate_trees=_predicate_trees(
            **{"seal(DynArray[address,MAX_SEALABLES])": _state_var_tree("SEALING_COMMITTEE")}
        ),
        capability_resolver_output={
            "seal(DynArray[address,MAX_SEALABLES])": _finite_cap("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        },
        effects=_effects(
            _effect(
                "seal(DynArray[address,MAX_SEALABLES])",
                labels=["external_contract_call", "pause_toggle"],
                summary="Calls an external contract from the contract context.",
                sink_kind="external_call",
            )
        ),
    )
    function = payload["functions"][0]

    assert function["function"] == "seal(DynArray[address,MAX_SEALABLES])"
    assert function["selector"].startswith("0x")
    assert len(function["selector"]) == 10
    assert function["controllers"] == [
        {
            "controller_id": "state_variable:SEALING_COMMITTEE",
            "label": "SEALING_COMMITTEE",
            "source": "SEALING_COMMITTEE",
            "kind": "state_variable",
            "principals": [
                {
                    "address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "resolved_type": "safe",
                    "details": {
                        "address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "owners": ["0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
                        "threshold": 1,
                    },
                    "source_contract": "GateSeal",
                    "source_controller_id": "state_variable:SEALING_COMMITTEE",
                }
            ],
            "notes": [],
        }
    ]


def test_build_effective_permissions_does_not_infer_controller_from_effect_target_names():
    target_analysis = {
        "subject": {
            "address": "0x1111111111111111111111111111111111111111",
            "name": "EtherFiAdmin",
        },
        "semantic_control": {
            "semantic_functions": [
                {
                    "function": "upgradeTo(address)",
                    "controller_refs": ["_authorizeUpgrade", "role"],
                    "effect_targets": ["roleRegistry.onlyProtocolUpgrader", "target"],
                    "effect_labels": ["delegatecall_execution", "implementation_update"],
                    "action_summary": "Calls an external contract from the contract context.",
                }
            ]
        },
    }
    target_snapshot = {
        "contract_name": "EtherFiAdmin",
        "controller_values": {
            "external_contract:roleRegistry": {
                "source": "roleRegistry",
                "value": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "resolved_type": "contract",
                "details": {
                    "address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                },
            },
            "state_variable:roleRegistry": {
                "source": "roleRegistry",
                "value": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "resolved_type": "contract",
                "details": {
                    "address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                },
            },
        },
    }

    payload = build_effective_permissions(
        target_analysis,
        target_snapshot=target_snapshot,
        predicate_trees=_predicate_trees(**{"upgradeTo(address)": _state_var_tree("_authorizeUpgrade", "role")}),
        capability_resolver_output={"upgradeTo(address)": _finite_cap("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
        effects=_effects(
            _effect(
                "upgradeTo(address)",
                targets=["roleRegistry.onlyProtocolUpgrader", "target"],
                labels=["delegatecall_execution", "implementation_update"],
                summary="Calls an external contract from the contract context.",
                sink_kind="delegatecall",
            )
        ),
    )
    function = payload["functions"][0]

    assert function["controllers"] == []


def test_build_effective_permissions_includes_generic_controller_grants():
    target_analysis = {
        "subject": {
            "address": "0x1111111111111111111111111111111111111111",
            "name": "Target",
        },
        "semantic_control": {
            "semantic_functions": [
                {
                    "function": "pause()",
                    "controller_refs": ["governance"],
                    "effect_targets": ["paused"],
                    "effect_labels": ["pause_toggle"],
                    "action_summary": "Pauses the contract.",
                }
            ]
        },
    }
    target_snapshot = {
        "contract_name": "Target",
        "controller_values": {
            "state_variable:governance": {
                "source": "governance",
                "value": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "resolved_type": "eoa",
                "details": {"address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            }
        },
    }

    payload = build_effective_permissions(
        target_analysis,
        target_snapshot=target_snapshot,
        predicate_trees=_predicate_trees(**{"pause()": _state_var_tree("governance")}),
        capability_resolver_output={"pause()": _finite_cap("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
        effects=_effects(
            _effect("pause()", targets=["paused"], labels=["pause_toggle"], summary="Pauses the contract.")
        ),
    )

    pause = payload["functions"][0]
    assert pause["controllers"] == [
        {
            "controller_id": "state_variable:governance",
            "label": "governance",
            "source": "governance",
            "kind": "state_variable",
            "principals": [
                {
                    "address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "resolved_type": "eoa",
                    "details": {"address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                    "source_contract": "Target",
                    "source_controller_id": "state_variable:governance",
                }
            ],
            "notes": [],
        }
    ]


def test_build_effective_permissions_uses_resolved_role_principals_and_skips_non_auth_contracts():
    target_analysis = {
        "subject": {
            "address": "0x1111111111111111111111111111111111111111",
            "name": "Target",
        },
        "semantic_control": {
            "semantic_functions": [
                {
                    "function": "pause()",
                    "controller_refs": ["PAUSE_ROLE", "LIDO"],
                    "effect_targets": ["paused"],
                    "effect_labels": ["pause_toggle"],
                    "action_summary": "Pauses the contract.",
                }
            ]
        },
    }
    target_snapshot = {
        "contract_name": "Target",
        "controller_values": {
            "role_identifier:PAUSE_ROLE": {
                "source": "PAUSE_ROLE",
                "value": "0x" + "11" * 32,
                "resolved_type": "unknown",
                "details": {
                    "resolved_principals": [
                        {
                            "address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "resolved_type": "eoa",
                            "details": {"address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                        }
                    ],
                },
            },
            "external_contract:LIDO": {
                "source": "LIDO",
                "value": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "resolved_type": "contract",
                "details": {"address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
            },
        },
    }

    payload = build_effective_permissions(
        target_analysis,
        target_snapshot=target_snapshot,
        predicate_trees=_predicate_trees(**{"pause()": _state_var_tree("PAUSE_ROLE", "LIDO")}),
        capability_resolver_output={"pause()": _finite_cap("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
        effects=_effects(
            _effect("pause()", targets=["paused"], labels=["pause_toggle"], summary="Pauses the contract.")
        ),
    )

    pause = payload["functions"][0]
    assert pause["controllers"] == [
        {
            "controller_id": "role_identifier:PAUSE_ROLE",
            "label": "PAUSE_ROLE",
            "source": "PAUSE_ROLE",
            "kind": "role_identifier",
            "principals": [
                {
                    "address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "resolved_type": "eoa",
                    "details": {"address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                    "source_controller_id": "role_identifier:PAUSE_ROLE",
                }
            ],
            "notes": [],
        }
    ]


def _public_default_target() -> dict:
    return {
        "subject": {
            "address": "0x1111111111111111111111111111111111111111",
            "name": "Target",
        },
        "semantic_control": {"semantic_functions": []},
    }


def _external_call_effect() -> dict:
    # A sensitive-sink, tree-less, capability-less entry point: the exact
    # population the resolver-ran branch would otherwise default to public.
    return _effects(
        _effect(
            "sweep(address)",
            targets=["token.transfer"],
            labels=["external_contract_call"],
            summary="Calls an external contract from the contract context.",
            sink_kind="external_call",
        )
    )


def test_guard_extraction_uncertain_marker_absent_defaults_public():
    """Control: with no ``guard_extraction_uncertain`` marker, a tree-less
    sensitive-sink entry point still defaults to public when the resolver
    ran — the historical behavior the marker must NOT change wholesale."""
    payload = build_effective_permissions(
        _public_default_target(),
        capability_resolver_output={},
        effects=_external_call_effect(),
        predicate_trees={"schema_version": "semantic", "trees": {}},
    )
    fn = next(f for f in payload["functions"] if f["function"] == "sweep(address)")
    assert fn.get("status") == "public"
    assert fn["authority_public"] is True


def test_guard_extraction_uncertain_marker_flips_only_marked_to_unsupported():
    """Fail-closed policy gate: when the static stage flags a tree-less sig as
    a caller-authority guard it could not lower (``guard_extraction_uncertain``),
    the policy resolves it ``unsupported`` instead of public — closing the
    fail-open default for that signature only. Carries the explicit reason and
    drops ``authority_public`` (never projected permissionless)."""
    payload = build_effective_permissions(
        _public_default_target(),
        capability_resolver_output={},
        effects=_external_call_effect(),
        predicate_trees={
            "schema_version": "semantic",
            "trees": {},
            "guard_extraction_uncertain": ["sweep(address)"],
        },
    )
    fn = next(f for f in payload["functions"] if f["function"] == "sweep(address)")
    assert fn.get("status") == "unsupported"
    assert fn.get("authority_public") is not True
    assert fn.get("capability_expr", {}).get("unsupported_reason") == "guard_extraction_uncertain"
