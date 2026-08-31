"""Pin field propagation through the serializers.

Verifies that:
  - ``FunctionPrincipal.principal_type`` survives both serializers
    (``services/governance/principals._function_principal_payload``
    and ``services/aggregations/analysis_detail._serialize_effective_functions``).
  - ``signature_witness`` principals reach the payload via a dedicated
    bucket on the per-function dict.
  - The ``EffectiveFunction`` columns ``capability_expr`` /
    ``conditions`` / ``status`` reach the per-function dict from both
    serializers.
  - ``_safe_role_int`` falls back to ``None`` for non-int identifiers
    rather than forcing every role identifier through ``int(...)``.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast


def _ef_namespace(**overrides: Any) -> SimpleNamespace:
    base = {
        "abi_signature": "doThing()",
        "function_name": "doThing",
        "selector": "0xdeadbeef",
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
    """``signature_witness`` principals route to a dedicated bucket so
    the company-overview UI can render 'anyone with a valid signature
    from <signer>' without conflating with set-membership controllers."""
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
    # The signature_witness must NOT also appear in controllers.
    for controller in result["controllers"]:
        assert all(p["principal_type"] != "signature_witness" for p in controller["principals"])
    # direct_owner still resolves correctly.
    assert result["direct_owner"]["address"] == "0x" + "b" * 40


def test_capability_expr_propagates_through_company_serializer() -> None:
    """``EffectiveFunction.capability_expr`` reaches the company
    payload's per-function entry verbatim."""
    from services.governance.principals import _build_company_function_entry

    cap_expr = {
        "kind": "finite_set",
        "members": ["0x" + "1" * 40],
        "confidence": "enumerable",
        "quality": "exact",
    }
    conditions = [{"kind": "time", "description": "after 2026-01-01"}]
    ef = _ef_namespace(capability_expr=cap_expr, conditions=conditions, status="public")

    result = _build_company_function_entry(cast(Any, ef), [])

    assert result["capability_expr"] == cap_expr
    assert result["conditions"] == conditions
    assert result["status"] == "public"


def test_safe_role_int_handles_string_and_dict_without_crashing() -> None:
    """A direct ``int(role_grant["role"])`` cast crashes on the
    string role-name and Condition-mapping shapes. ``_safe_role_int``
    must coerce ints, return ``None`` for non-int, and never raise."""
    from services.policy.principal_index import _safe_role_int as _safe_role_int_pe
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


def test_principal_index_skips_non_int_role_without_crashing() -> None:
    """The principal-enrichment path swallows non-int role grants
    instead of crashing, dropping
    unrecognized shapes onto the ``role_<label>`` controller bucket."""
    from services.policy.principal_index import _collect_permissions

    eff_perms = {
        "contract_name": "T",
        "contract_address": "0x" + "1" * 40,
        "functions": [
            {
                "function": "doThing()",
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

    # Must not raise.
    by_address, label_hints = _collect_permissions(eff_perms)
    addr = "0x" + "a" * 40
    assert addr in by_address
    perm = by_address[addr][0]
    # Non-int role surfaced as None on the typed permission, with the
    # original identifier preserved on the controller string.
    assert perm["role"] is None
    assert perm.get("controller") == "role_PAUSER_ROLE"


def test_recursive_role_principals_skips_non_int_role_without_crashing() -> None:
    """The recursive resolver's role-principal accumulator (``set[int]``)
    cannot hold a non-int role; the helper must skip those grants
    rather than crash."""
    from services.resolution.recursive import _role_principals_from_permission_index

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

    out = _role_principals_from_permission_index(eff_perms)
    addrs = {p["address"]: p for p in out}
    # The non-int role grant was skipped — its principal didn't make it
    # into the accumulator (it had no other source).
    assert "0x" + "a" * 40 not in addrs
    # The int role grant produced its principal with role=7.
    assert "0x" + "b" * 40 in addrs
    assert addrs["0x" + "b" * 40]["roles"] == [7]
