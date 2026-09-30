
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
    """The UI renders "anyone with a valid signature from <signer>" apart from set membership."""
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
    """Role names and Condition mappings crash a bare ``int()``."""
    from services.policy.principal_enrichment import _safe_role_int as _safe_role_int_pe
    from services.resolution.recursive import _safe_role_int as _safe_role_int_rr

    for safe_role_int in (_safe_role_int_pe, _safe_role_int_rr):
        assert safe_role_int(0) == 0
        assert safe_role_int(7) == 7
        assert safe_role_int("3") == 3
        assert safe_role_int("PAUSER_ROLE") is None
        assert safe_role_int({"kind": "time", "description": "x"}) is None
        assert safe_role_int(None) is None
        assert safe_role_int([1, 2, 3]) is None


def test_principal_enrichment_skips_non_int_role_without_crashing() -> None:
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
    assert perm["role"] is None
    assert perm.get("controller") == "role_PAUSER_ROLE"


def test_recursive_role_principals_skips_non_int_role_without_crashing() -> None:
    """The resolver's role accumulator is ``set[int]``."""
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
    assert "0x" + "a" * 40 not in addrs
    assert "0x" + "b" * 40 in addrs
    assert addrs["0x" + "b" * 40]["roles"] == [7]
