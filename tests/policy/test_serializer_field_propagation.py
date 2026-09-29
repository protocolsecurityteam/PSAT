"""Pin field propagation through the serializers.

``FunctionPrincipal.principal_type`` must survive ``_function_principal_payload`` and
``_serialize_effective_functions``; ``signature_witness`` principals get a dedicated
bucket; ``capability_expr`` / ``conditions`` / ``status`` reach the per-function dict;
``_safe_role_int`` returns ``None`` for non-int identifiers instead of raising.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest


def _ef_namespace(**overrides: Any) -> SimpleNamespace:
    base = {
        "abi_signature": "doThing()",
        "function_name": "doThing",
        "selector": "0xdeadbeef",
        "effect_labels": [],
        "effect_targets": [],
        "action_summary": "stub",
        "authority_public": False,
        "authority_roles": [],
        "capability_expr": None,
        "conditions": None,
        "status": None,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _fp_namespace(**overrides: Any) -> SimpleNamespace:
    base = {
        "address": "0x" + "1" * 40,
        "resolved_type": "eoa",
        "origin": "controller",
        "principal_type": "controller",
        "details": {},
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_signature_witness_bucket_in_company_function_entry() -> None:
    """``signature_witness`` principals route to a dedicated bucket so the UI can render
    'anyone with a valid signature from <signer>' apart from set-membership controllers."""
    from services.governance.principals import _build_company_function_entry

    ef = _ef_namespace(abi_signature="permit(address,uint256,bytes)")
    principals = [
        _fp_namespace(
            address="0x" + "a" * 40,
            resolved_type="eoa",
            origin="ecrecover_signer",
            principal_type="signature_witness",
            details={"signer_source": "predicate_evaluator"},
        ),
        _fp_namespace(
            address="0x" + "b" * 40,
            resolved_type="eoa",
            origin="owner_slot",
            principal_type="direct_owner",
        ),
    ]

    result = _build_company_function_entry(cast(Any, ef), cast(Any, principals))

    assert "signature_witnesses" in result
    assert len(result["signature_witnesses"]) == 1
    sig = result["signature_witnesses"][0]
    assert sig["address"] == "0x" + "a" * 40
    assert sig["principal_type"] == "signature_witness"
    assert sig["details"] == {"signer_source": "predicate_evaluator"}
    for controller in result["controllers"]:
        assert all(p["principal_type"] != "signature_witness" for p in controller["principals"])
    assert result["direct_owner"]["address"] == "0x" + "b" * 40


def test_signature_witness_in_serialize_effective_functions() -> None:
    """The analysis-detail serializer also buckets signature_witness and surfaces principal_type."""
    from services.aggregations.analysis_detail import _serialize_effective_functions

    ef = _ef_namespace(abi_signature="permit(address,uint256,bytes)")
    ef.principals = [
        _fp_namespace(
            address="0x" + "a" * 40,
            resolved_type="eoa",
            origin="ecrecover_signer",
            principal_type="signature_witness",
        ),
        _fp_namespace(
            address="0x" + "c" * 40,
            resolved_type="contract",
            origin="role_registry",
            principal_type="controller",
        ),
    ]

    out = _serialize_effective_functions(cast(Any, [ef]))

    assert len(out) == 1
    fn = out[0]
    assert "signature_witnesses" in fn
    assert len(fn["signature_witnesses"]) == 1
    assert fn["signature_witnesses"][0]["principal_type"] == "signature_witness"
    assert any(
        p["principal_type"] == "controller" and p["address"] == "0x" + "c" * 40
        for ctrl in fn["controllers"]
        for p in ctrl["principals"]
    )


def _company_entry(ef: SimpleNamespace) -> dict:
    from services.governance.principals import _build_company_function_entry

    return _build_company_function_entry(cast(Any, ef), [])


def _analysis_detail_entry(ef: SimpleNamespace) -> dict:
    from services.aggregations.analysis_detail import _serialize_effective_functions

    ef.principals = []
    out = _serialize_effective_functions(cast(Any, [ef]))
    assert len(out) == 1
    return out[0]


@pytest.mark.parametrize(
    ("serialize", "cap_expr", "conditions", "status"),
    [
        # Reaches the company payload's per-function entry verbatim.
        pytest.param(
            _company_entry,
            {
                "kind": "finite_set",
                "members": ["0x" + "1" * 40],
                "confidence": "enumerable",
                "quality": "exact",
            },
            [{"kind": "time", "description": "after 2026-01-01"}],
            "public",
            id="company_serializer",
        ),
        # Reaches the ``/api/analyses/{run}`` payload via ``_serialize_effective_functions``.
        pytest.param(
            _analysis_detail_entry,
            {"kind": "unsupported", "reason": "external_check_only_unresolved"},
            [],
            "unsupported",
            id="analysis_detail_serializer",
        ),
    ],
)
def test_capability_expr_propagates_through_serializer(serialize, cap_expr, conditions, status) -> None:
    ef = _ef_namespace(capability_expr=cap_expr, conditions=conditions, status=status)

    fn = serialize(ef)

    assert fn["capability_expr"] == cap_expr
    assert fn["conditions"] == conditions
    assert fn["status"] == status


def test_safe_role_int_handles_string_and_dict_without_crashing() -> None:
    """A direct ``int(role_grant["role"])`` crashes on role-name strings and
    Condition mappings; ``_safe_role_int`` must return ``None`` for non-int, never raise."""
    from services.policy.principal_enrichment import _safe_role_int as _safe_role_int_pe
    from services.resolution.recursive import _safe_role_int as _safe_role_int_rr

    for safe_role_int in (_safe_role_int_pe, _safe_role_int_rr):
        # Happy path — int passes through.
        assert safe_role_int(0) == 0
        assert safe_role_int(7) == 7
        # Numeric string also works for persisted numeric role identifiers.
        assert safe_role_int("3") == 3
        # Non-numeric string returns None — caller decides skip/log.
        assert safe_role_int("PAUSER_ROLE") is None
        # Condition-mapping returns None instead of TypeError.
        assert safe_role_int({"kind": "time", "description": "x"}) is None
        # None / missing returns None.
        assert safe_role_int(None) is None
        # Lists also return None.
        assert safe_role_int([1, 2, 3]) is None


def test_principal_enrichment_skips_non_int_role_without_crashing() -> None:
    """Non-int role grants are swallowed, landing on the ``role_<label>`` controller bucket."""
    from services.policy.principal_enrichment import _collect_permissions

    eff_perms = {
        "contract_name": "T",
        "contract_address": "0x" + "1" * 40,
        "functions": [
            {
                "function": "doThing()",
                "effect_labels": ["pause_toggle"],
                "authority_public": False,
                "direct_owner": None,
                "controllers": [],
                # Role grant carrying a role-name string instead of an int.
                "authority_roles": [
                    {
                        "role": "PAUSER_ROLE",
                        "principals": [
                            {
                                "address": "0x" + "a" * 40,
                                "resolved_type": "eoa",
                                "details": {},
                            }
                        ],
                    }
                ],
            }
        ],
    }

    by_address, label_hints = _collect_permissions(eff_perms)
    addr = "0x" + "a" * 40
    assert addr in by_address
    perm = by_address[addr][0]
    # Non-int role is None on the typed permission; the identifier survives on the controller string.
    assert perm["role"] is None
    assert perm.get("controller") == "role_PAUSER_ROLE"


def test_recursive_role_principals_skips_non_int_role_without_crashing() -> None:
    """The recursive resolver's role accumulator (``set[int]``) can't hold a non-int
    role; the helper must skip those grants rather than crash."""
    from services.resolution.recursive import _role_principals_from_effective_permissions

    eff_perms = {
        "functions": [
            {
                "function": "doThing()",
                "authority_roles": [
                    {
                        "role": "PAUSER_ROLE",
                        "principals": [
                            {
                                "address": "0x" + "a" * 40,
                                "resolved_type": "eoa",
                                "details": {},
                            }
                        ],
                    },
                    # Mixed case: also accept a real int role.
                    {
                        "role": 7,
                        "principals": [
                            {
                                "address": "0x" + "b" * 40,
                                "resolved_type": "safe",
                                "details": {"threshold": 2},
                            }
                        ],
                    },
                ],
                "controllers": [],
            }
        ]
    }

    out = _role_principals_from_effective_permissions(eff_perms)
    addrs = {p["address"]: p for p in out}
    # The non-int grant was skipped (no other source for its principal).
    assert "0x" + "a" * 40 not in addrs
    # The int role grant produced its principal with role=7.
    assert "0x" + "b" * 40 in addrs
    assert addrs["0x" + "b" * 40]["roles"] == [7]
