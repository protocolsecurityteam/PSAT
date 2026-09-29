"""Unit tests for ``probe_membership``.

Uses a stub AdapterRegistry returning a pre-baked CapabilityExpr so tests focus on the
probe's leaf-selection + membership-resolution logic, not adapter behavior.
"""

from __future__ import annotations

from services.resolution.adapters import AdapterRegistry, EvaluationContext
from services.resolution.capabilities import CapabilityExpr, ExternalCheck
from services.resolution.probe import probe_membership

# ---------------------------------------------------------------------------
# Stub registry. Subclasses AdapterRegistry because the production probe signatures
# type-narrow to it (no Protocol carve-out needed).
# ---------------------------------------------------------------------------


class _StubRegistry(AdapterRegistry):
    def __init__(self, cap: CapabilityExpr | None = None):
        super().__init__()
        self.cap = cap or CapabilityExpr.unsupported("no_cap_set")
        self.calls: list[tuple[dict, EvaluationContext]] = []

    def enumerate(self, descriptor, ctx):
        self.calls.append((descriptor, ctx))
        return self.cap


# Tree fixtures


def _membership_leaf(role: str = "caller_authority") -> dict:
    return {
        "kind": "membership",
        "operator": "truthy",
        "authority_role": role,
        "operands": [{"source": "msg_sender"}],
        "set_descriptor": {
            "kind": "mapping_membership",
            "key_sources": [{"source": "msg_sender"}],
            "storage_var": "_blacklist",
        },
        "references_msg_sender": True,
        "parameter_indices": [],
        "expression": "...",
        "basis": [],
    }


def _equality_leaf() -> dict:
    return {
        "kind": "equality",
        "operator": "eq",
        "authority_role": "caller_authority",
        "operands": [{"source": "msg_sender"}, {"source": "state_variable"}],
        "references_msg_sender": True,
        "parameter_indices": [],
        "expression": "msg.sender == owner",
        "basis": [],
    }


def _leaf_node(leaf: dict) -> dict:
    return {"op": "LEAF", "leaf": leaf}


def _and_node(*children: dict) -> dict:
    return {"op": "AND", "children": list(children)}


# Leaf selection


def test_predicate_index_out_of_range():
    tree = _leaf_node(_membership_leaf())
    res = probe_membership(
        tree,
        predicate_index=5,
        member="0x" + "11" * 20,
        registry=_StubRegistry(),
        ctx=EvaluationContext(chain_id=1),
    )
    assert res["result"] == "unknown"
    assert res["reason"] == "leaf_index_out_of_range"
    assert res["leaf_count"] == 1


def test_non_membership_leaf_returns_unknown():
    tree = _leaf_node(_equality_leaf())
    res = probe_membership(
        tree,
        predicate_index=0,
        member="0x" + "11" * 20,
        registry=_StubRegistry(),
        ctx=EvaluationContext(chain_id=1),
    )
    assert res["result"] == "unknown"
    assert res["reason"] == "non_membership_leaf"
    assert res["leaf_kind"] == "equality"


def test_index_picks_leaf_by_dfs_order():
    """Leaves are indexed via DFS (index 0 = leftmost); pinned so the order doesn't drift."""
    left = _membership_leaf("caller_authority")
    right = _equality_leaf()
    tree = _and_node(_leaf_node(left), _leaf_node(right))

    reg = _StubRegistry(CapabilityExpr.finite_set(["0x" + "11" * 20]))
    res0 = probe_membership(
        tree, predicate_index=0, member="0x" + "11" * 20, registry=reg, ctx=EvaluationContext(chain_id=1)
    )
    assert res0["result"] == "yes"
    assert res0["leaf_kind"] == "membership"

    res1 = probe_membership(
        tree, predicate_index=1, member="0x" + "11" * 20, registry=reg, ctx=EvaluationContext(chain_id=1)
    )
    assert res1["leaf_kind"] == "equality"
    assert res1["reason"] == "non_membership_leaf"


# CapabilityExpr resolution


def test_finite_set_exact_yes():
    addr = "0x" + "11" * 20
    reg = _StubRegistry(CapabilityExpr.finite_set([addr], quality="exact"))
    res = probe_membership(
        _leaf_node(_membership_leaf()),
        predicate_index=0,
        member=addr,
        registry=reg,
        ctx=EvaluationContext(chain_id=1),
    )
    assert res["result"] == "yes"
    assert res["reason"] == "finite_set_exact"
    assert res["membership_quality"] == "exact"


def test_finite_set_exact_no():
    reg = _StubRegistry(CapabilityExpr.finite_set(["0x" + "11" * 20], quality="exact"))
    res = probe_membership(
        _leaf_node(_membership_leaf()),
        predicate_index=0,
        member="0x" + "22" * 20,
        registry=reg,
        ctx=EvaluationContext(chain_id=1),
    )
    assert res["result"] == "no"
    assert res["reason"] == "finite_set_exact"


def test_finite_set_lower_bound_absent_is_unknown():
    """Lower bound = known members only; an absent member is unknown, not no."""
    reg = _StubRegistry(CapabilityExpr.finite_set(["0x" + "11" * 20], quality="lower_bound"))
    res = probe_membership(
        _leaf_node(_membership_leaf()),
        predicate_index=0,
        member="0x" + "22" * 20,
        registry=reg,
        ctx=EvaluationContext(chain_id=1),
    )
    assert res["result"] == "unknown"
    assert res["reason"] == "lower_bound_absent"


def test_finite_set_upper_bound_absent_is_no():
    """Upper bound = at most these: absent is a definitive no; presence is uncertain (state may have evicted)."""
    reg = _StubRegistry(CapabilityExpr.finite_set(["0x" + "11" * 20], quality="upper_bound"))
    absent = "0x" + "22" * 20
    res_absent = probe_membership(
        _leaf_node(_membership_leaf()),
        predicate_index=0,
        member=absent,
        registry=reg,
        ctx=EvaluationContext(chain_id=1),
    )
    assert res_absent["result"] == "no"

    res_present = probe_membership(
        _leaf_node(_membership_leaf()),
        predicate_index=0,
        member="0x" + "11" * 20,
        registry=reg,
        ctx=EvaluationContext(chain_id=1),
    )
    assert res_present["result"] == "unknown"
    assert res_present["reason"] == "upper_bound_present"


def test_threshold_group_signer_yes():
    reg = _StubRegistry(CapabilityExpr.threshold_group(2, ["0x" + "11" * 20, "0x" + "22" * 20, "0x" + "33" * 20]))
    yes = probe_membership(
        _leaf_node(_membership_leaf()),
        predicate_index=0,
        member="0x" + "22" * 20,
        registry=reg,
        ctx=EvaluationContext(chain_id=1),
    )
    assert yes["result"] == "yes"
    assert yes["reason"] == "threshold_group_signer"

    no = probe_membership(
        _leaf_node(_membership_leaf()),
        predicate_index=0,
        member="0x" + "44" * 20,
        registry=reg,
        ctx=EvaluationContext(chain_id=1),
    )
    assert no["result"] == "no"


def test_cofinite_blacklist_excluded_no():
    reg = _StubRegistry(CapabilityExpr.cofinite_blacklist(["0x" + "11" * 20]))
    res = probe_membership(
        _leaf_node(_membership_leaf()),
        predicate_index=0,
        member="0x" + "11" * 20,
        registry=reg,
        ctx=EvaluationContext(chain_id=1),
    )
    assert res["result"] == "no"
    assert res["reason"] == "cofinite_blacklisted"


def test_cofinite_blacklist_not_listed_yes():
    reg = _StubRegistry(CapabilityExpr.cofinite_blacklist(["0x" + "11" * 20]))
    res = probe_membership(
        _leaf_node(_membership_leaf()),
        predicate_index=0,
        member="0x" + "22" * 20,
        registry=reg,
        ctx=EvaluationContext(chain_id=1),
    )
    assert res["result"] == "yes"


def test_external_check_only_surfaces_probe_descriptor():
    """``external_check_only`` can't be answered offline; the probe returns target + selector for the caller."""
    check = ExternalCheck(
        target_address="0x" + "ee" * 20,
        target_call_selector="0xb7009613",  # canCall
        extra={"abi": "dsauth"},
    )
    reg = _StubRegistry(CapabilityExpr.external_check_only(check))
    res = probe_membership(
        _leaf_node(_membership_leaf()),
        predicate_index=0,
        member="0x" + "11" * 20,
        registry=reg,
        ctx=EvaluationContext(chain_id=1),
    )
    assert res["result"] == "unknown"
    assert res["reason"] == "external_check_only"
    assert res["probe_target"] == "0x" + "ee" * 20
    assert res["probe_selector"] == "0xb7009613"


def test_unsupported_capability_passes_reason_through():
    reg = _StubRegistry(CapabilityExpr.unsupported("no_adapter"))
    res = probe_membership(
        _leaf_node(_membership_leaf()),
        predicate_index=0,
        member="0x" + "11" * 20,
        registry=reg,
        ctx=EvaluationContext(chain_id=1),
    )
    assert res["result"] == "unknown"
    assert res["reason"] == "capability_unsupported"
    assert res["capability_unsupported_reason"] == "no_adapter"


# Composite (AND / OR) via constructed CapabilityExpr


def _composite(kind: str, *children: CapabilityExpr) -> CapabilityExpr:
    return CapabilityExpr(kind=kind, children=list(children))  # pyright: ignore[reportArgumentType]


def test_and_all_yes_returns_yes():
    addr = "0x" + "11" * 20
    cap = _composite(
        "AND",
        CapabilityExpr.finite_set([addr], quality="exact"),
        CapabilityExpr.finite_set([addr], quality="exact"),
    )
    reg = _StubRegistry(cap)
    res = probe_membership(
        _leaf_node(_membership_leaf()),
        predicate_index=0,
        member=addr,
        registry=reg,
        ctx=EvaluationContext(chain_id=1),
    )
    assert res["result"] == "yes"
    assert res["reason"] == "and_all_yes"


def test_and_one_no_returns_no():
    addr = "0x" + "11" * 20
    cap = _composite(
        "AND",
        CapabilityExpr.finite_set([addr], quality="exact"),
        CapabilityExpr.finite_set(["0x" + "ff" * 20], quality="exact"),
    )
    reg = _StubRegistry(cap)
    res = probe_membership(
        _leaf_node(_membership_leaf()),
        predicate_index=0,
        member=addr,
        registry=reg,
        ctx=EvaluationContext(chain_id=1),
    )
    assert res["result"] == "no"
    assert res["reason"] == "and_any_no"


def test_or_any_yes_returns_yes():
    addr = "0x" + "11" * 20
    cap = _composite(
        "OR",
        CapabilityExpr.finite_set(["0x" + "ff" * 20], quality="exact"),
        CapabilityExpr.finite_set([addr], quality="exact"),
    )
    reg = _StubRegistry(cap)
    res = probe_membership(
        _leaf_node(_membership_leaf()),
        predicate_index=0,
        member=addr,
        registry=reg,
        ctx=EvaluationContext(chain_id=1),
    )
    assert res["result"] == "yes"
    assert res["reason"] == "or_any_yes"


def test_or_all_no_returns_no():
    addr = "0x" + "11" * 20
    cap = _composite(
        "OR",
        CapabilityExpr.finite_set(["0x" + "ff" * 20], quality="exact"),
        CapabilityExpr.finite_set(["0x" + "ee" * 20], quality="exact"),
    )
    reg = _StubRegistry(cap)
    res = probe_membership(
        _leaf_node(_membership_leaf()),
        predicate_index=0,
        member=addr,
        registry=reg,
        ctx=EvaluationContext(chain_id=1),
    )
    assert res["result"] == "no"
    assert res["reason"] == "or_all_no"


def _signature_auth_leaf(signer_state_var: str = "trustedSigner") -> dict:
    return {
        "kind": "signature_auth",
        "operator": "eq",
        "authority_role": "caller_authority",
        "operands": [
            {"source": "signature_recovery"},
            {"source": "state_variable", "state_variable_name": signer_state_var},
        ],
        "references_msg_sender": False,
        "parameter_indices": [],
        "expression": "ecrecover(...) == trustedSigner",
        "basis": [],
    }


# probe_signature


def test_probe_signature_returns_unknown_for_non_signature_leaf():
    """Reason is non_signature_leaf, distinct from the membership probe's non_membership_leaf."""
    from services.resolution.probe import probe_signature

    tree = _leaf_node(_membership_leaf())
    res = probe_signature(
        tree,
        predicate_index=0,
        recovered_signer="0x" + "11" * 20,
        registry=_StubRegistry(),
        ctx=EvaluationContext(chain_id=1),
    )
    assert res["result"] == "unknown"
    assert res["reason"] == "non_signature_leaf"
    assert res["leaf_kind"] == "membership"


def test_probe_signature_index_out_of_range():
    from services.resolution.probe import probe_signature

    tree = _leaf_node(_signature_auth_leaf())
    res = probe_signature(
        tree,
        predicate_index=5,
        recovered_signer="0x" + "11" * 20,
        registry=_StubRegistry(),
        ctx=EvaluationContext(chain_id=1),
    )
    assert res["result"] == "unknown"
    assert res["reason"] == "leaf_index_out_of_range"


def test_probe_signature_real_evaluator_for_state_var_signer():
    """A state-var signer yields a signature_witness wrapping a lower_bound finite_set placeholder.

    Pinned as the predicate-evaluator / probe integration point: a regression on either
    side breaks the EIP-1271 / ecrecover client flow."""
    from services.resolution.adapters import AdapterRegistry
    from services.resolution.probe import probe_signature

    tree = _leaf_node(_signature_auth_leaf())
    res = probe_signature(
        tree,
        predicate_index=0,
        recovered_signer="0x" + "ee" * 20,
        registry=AdapterRegistry(),
        ctx=EvaluationContext(chain_id=1, contract_address="0x" + "ab" * 20),
    )
    assert res["leaf_kind"] == "signature_auth"
    assert res["capability_kind"] == "signature_witness"
    # unknown until a backend resolves the signer (lower_bound + absent), or a clean no if the placeholder was
    # empty exact.
    assert res["result"] in ("yes", "no", "unknown")


def test_or_with_unknown_returns_unknown():
    addr = "0x" + "11" * 20
    cap = _composite(
        "OR",
        CapabilityExpr.finite_set([addr], quality="lower_bound"),  # absent -> unknown
        CapabilityExpr.finite_set(["0x" + "ee" * 20], quality="exact"),  # absent -> no
    )
    reg = _StubRegistry(cap)
    res = probe_membership(
        _leaf_node(_membership_leaf()),
        predicate_index=0,
        member="0x" + "22" * 20,
        registry=reg,
        ctx=EvaluationContext(chain_id=1),
    )
    assert res["result"] == "unknown"
    assert res["reason"] == "or_some_unknown"
