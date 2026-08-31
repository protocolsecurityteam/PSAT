"""The caller-taint earned-public default (PSAT_AUTHORITY_EARNED_PUBLIC).

End-to-end conformance for the structural rule that replaces positive
authority recognition: a caller-tainted gate that matches no known
permissionless shape fails CLOSED (external_check_only), and "public" is
earned by either no caller gate at all or a permissionless shape. Every
exclusion shape is tested in BOTH polarities (the authority variant gates,
the permissionless variant stays open), with the canary shapes pinned.

Real compiled contracts (the `_compile` + `_build_pipeline` pattern) —
dict-leaf fakes hide provenance bugs; they are used only for the pure
shape-classifier unit tests at the bottom.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.resolution.capabilities import CapabilityExpr  # noqa: E402
from services.resolution.capability_resolver import capability_to_dict  # noqa: E402
from services.resolution.permissionless_shapes import (  # noqa: E402
    is_permissionless_caller_shape,
    leaf_is_caller_tainted,
)
from services.resolution.predicate_evaluator import (  # noqa: E402
    EvaluationContext,
    evaluate_tree,
)
from services.static.static_analysis.predicates import (  # noqa: E402
    build_predicate_tree,
)
from services.static.static_analysis.reentrancy_pause import (  # noqa: E402
    apply_reentrancy_pause_pass,
)
from services.static.static_analysis.writer_gate import (  # noqa: E402
    apply_writer_gate_pass,
)


@pytest.fixture
def earned_public(monkeypatch):
    monkeypatch.setenv("PSAT_AUTHORITY_EARNED_PUBLIC", "1")


@pytest.fixture
def legacy_path(monkeypatch):
    """The kill-switch side: the flag defaults ON, so the legacy E3/E4
    behavior must be requested explicitly."""
    monkeypatch.setenv("PSAT_AUTHORITY_EARNED_PUBLIC", "0")


def _compile(tmp_path: Path, source: str) -> Slither:
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    return Slither(str(f))


def _build_pipeline(contract):
    trees = {}
    for fn in contract.functions:
        if fn.is_constructor:
            continue
        trees[fn.full_name] = build_predicate_tree(fn)
    apply_writer_gate_pass(contract, trees)
    apply_reentrancy_pause_pass(contract, trees)
    return trees


def _cap_for(sl, full_name: str):
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    return evaluate_tree(trees[full_name])


# ---------------------------------------------------------------------------
# External bool calls: view ACL gates; effectful value movement stays open.
# ---------------------------------------------------------------------------


# The ACL target is derived through an external-call chain (the Aragon/Lido
# shape: kernel().acl().canPerform). A direct state-var/immutable target
# classifies delegated_authority and was already gated pre-flag; the chained
# target traces to ``computed`` → legacy ``business`` → the fail-open.
_EXTERNAL_ACL = """
    pragma solidity ^0.8.19;
    interface IACL { function canPerform(address who, bytes32 role) external view returns (bool); }
    interface IKernel { function acl() external view returns (IACL); }
    contract C {
        IKernel immutable kernel;
        constructor(IKernel k) { kernel = k; }
        function f() external {
            require(IACL(kernel.acl()).canPerform(msg.sender, keccak256("ROLE")), "no perm");
        }
    }
"""


def test_view_external_acl_gates_under_flag(tmp_path, earned_public):
    """The Lido class: a view bool call gated on the caller is an external
    ACL — gated, principals unknown."""
    cap = _cap_for(_compile(tmp_path, _EXTERNAL_ACL), "f()")
    assert cap.kind == "external_check_only", f"view caller ACL must gate, got {cap.kind}"


def test_view_external_acl_opens_without_flag(tmp_path, legacy_path):
    """Documents the legacy fail-open this refactor exists to fix (and pins
    the kill-switch rollback behavior)."""
    cap = _cap_for(_compile(tmp_path, _EXTERNAL_ACL), "f()")
    assert cap.kind == "conditional_universal"


def test_value_movement_transfer_from_stays_open(tmp_path, earned_public):
    """Canary: ``require(token.transferFrom(msg.sender, …))`` taints from
    the caller but is permissionless — the callee is effectful (non-view),
    the structural value-movement discriminator. Same chained-target shape
    as the ACL test, differing ONLY in callee mutability."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IERC20 { function transferFrom(address f, address t, uint256 a) external returns (bool); }
        interface IRegistry { function token() external view returns (IERC20); }
        contract C {
            IRegistry immutable registry;
            constructor(IRegistry r) { registry = r; }
            function deposit(uint256 amount) external {
                require(IERC20(registry.token()).transferFrom(msg.sender, address(this), amount), "transfer failed");
            }
        }
    """,
    )
    cap = _cap_for(sl, "deposit(uint256)")
    assert cap.kind == "conditional_universal", f"value movement must stay open, got {cap.kind}"


def test_state_var_target_transfer_from_opens_under_flag(tmp_path):
    """A state-var/immutable-target ``require(token.transferFrom(msg.sender,
    …))`` is a value-movement call, not a gate (the corpus labels every such
    row public: EarlyAdopterPool claim/withdraw token transfers). It used to
    classify delegated_authority and resolve GATED on the legacy path — a
    measured false-gate the earned-public flag opened. Since the classifier
    itself applies the gate-shape discriminator (Wave 5 B2: an effectful
    callee with a msg.sender funds-subject argument never earns
    delegated_authority), the row is open on BOTH paths — the flag no longer
    changes this class."""
    src = """
        pragma solidity ^0.8.19;
        interface IERC20 { function transferFrom(address f, address t, uint256 a) external returns (bool); }
        contract C {
            IERC20 immutable token;
            constructor(IERC20 t) { token = t; }
            function deposit(uint256 amount) external {
                require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
            }
        }
    """
    import os

    prior = os.environ.get("PSAT_AUTHORITY_EARNED_PUBLIC")
    os.environ["PSAT_AUTHORITY_EARNED_PUBLIC"] = "0"
    try:
        off = _cap_for(_compile(tmp_path, src), "deposit(uint256)")
        on_dir = tmp_path / "on"
        on_dir.mkdir()
        os.environ["PSAT_AUTHORITY_EARNED_PUBLIC"] = "1"
        on = _cap_for(_compile(on_dir, src), "deposit(uint256)")
    finally:
        if prior is None:
            os.environ.pop("PSAT_AUTHORITY_EARNED_PUBLIC", None)
        else:
            os.environ["PSAT_AUTHORITY_EARNED_PUBLIC"] = prior
    assert off.kind == "conditional_universal"
    assert on.kind == "conditional_universal"


def test_effectful_library_membership_consume_stays_gated(tmp_path, earned_public):
    """``require(pendingAdmins.remove(msg.sender))`` — an effectful LIBRARY
    call that manipulates the contract's OWN storage (no external calls in
    its body): only existing members of a contract-curated set pass
    (PermissionController.acceptAdmin). The value-movement exclusion must
    not open it. The fixture mirrors OZ EnumerableSet's two-level
    ``remove → _remove`` shape, which lifts as an ``external_bool`` leaf
    with ``nonview_library`` mutability — exactly the corpus shape. (A
    single-level library body inlines fully into a folded ``ne`` value
    comparison instead — a separate, documented extraction ceiling.)"""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        library AddressSet {
            struct Set { bytes32[] values; mapping(bytes32 => uint256) positions; }
            function _remove(Set storage set, bytes32 value) private returns (bool) {
                uint256 position = set.positions[value];
                if (position == 0) return false;
                uint256 valueIndex = position - 1;
                uint256 lastIndex = set.values.length - 1;
                if (valueIndex != lastIndex) {
                    bytes32 lastValue = set.values[lastIndex];
                    set.values[valueIndex] = lastValue;
                    set.positions[lastValue] = position;
                }
                set.values.pop();
                delete set.positions[value];
                return true;
            }
            function remove(Set storage set, address value) internal returns (bool) {
                return _remove(set, bytes32(uint256(uint160(value))));
            }
        }
        contract C {
            using AddressSet for AddressSet.Set;
            AddressSet.Set private pendingAdmins;
            function acceptAdmin() external {
                require(pendingAdmins.remove(msg.sender), "not pending");
            }
        }
    """,
    )
    cap = _cap_for(sl, "acceptAdmin()")
    assert cap.kind == "external_check_only", f"library membership-consume must stay gated, got {cap.kind}"


def test_wrapper_library_value_movement_stays_open(tmp_path, earned_public):
    """The other library polarity: a WRAPPER library whose body reaches an
    external call (OZ SafeERC20's library → internal → low-level call) moves
    another contract's assets exactly like a direct ``transferFrom`` —
    ``nonview``, permissionless, open. This is the shape behind the
    LiquidityPool/Liquifier/RewardsCoordinator corpus rows."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IERC20 { function transferFrom(address f, address t, uint256 a) external returns (bool); }
        library SafeERC20 {
            function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
                _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
            }
            function _callOptionalReturn(IERC20 token, bytes memory data) private {
                (bool success, bytes memory returndata) = address(token).call(data);
                require(success, "SafeERC20: low-level call failed");
                if (returndata.length > 0) {
                    require(abi.decode(returndata, (bool)), "SafeERC20: operation failed");
                }
            }
        }
        contract C {
            using SafeERC20 for IERC20;
            IERC20 immutable token;
            constructor(IERC20 t) { token = t; }
            function deposit(uint256 amount) external {
                token.safeTransferFrom(msg.sender, address(this), amount);
            }
        }
    """,
    )
    cap = _cap_for(sl, "deposit(uint256)")
    assert cap.kind == "conditional_universal", f"wrapper-library value movement must stay open, got {cap.kind}"


def test_assembly_wrapper_library_value_movement_stays_open(tmp_path, earned_public):
    """Solmate's SafeTransferLib makes the external call in inline assembly —
    Slither lifts the Yul ``call`` as a SolidityCall builtin, with no
    LowLevelCall IR at all. The external-reach walk must still see it
    (the BoringVault canary)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        library SafeTransferLib {
            function safeTransferFrom(address token, address from, address to, uint256 amount) internal {
                bool success;
                assembly {
                    let freeMemoryPointer := mload(0x40)
                    mstore(freeMemoryPointer, 0x23b872dd00000000000000000000000000000000000000000000000000000000)
                    mstore(add(freeMemoryPointer, 4), from)
                    mstore(add(freeMemoryPointer, 36), to)
                    mstore(add(freeMemoryPointer, 68), amount)
                    success := and(
                        or(and(eq(mload(0), 1), gt(returndatasize(), 31)), iszero(returndatasize())),
                        call(gas(), token, 0, freeMemoryPointer, 100, 0, 32)
                    )
                }
                require(success, "TRANSFER_FROM_FAILED");
            }
        }
        contract C {
            address immutable token;
            constructor(address t) { token = t; }
            function deposit(uint256 amount) external {
                SafeTransferLib.safeTransferFrom(token, msg.sender, address(this), amount);
            }
        }
    """,
    )
    cap = _cap_for(sl, "deposit(uint256)")
    assert cap.kind == "conditional_universal", f"assembly wrapper value movement must stay open, got {cap.kind}"


def test_void_call_with_merkle_witness_gates_under_flag(tmp_path, earned_public):
    """MembershipManager.wrapEthForEap: a VOID statement call (the gate is
    the callee's entire revert surface) consuming the caller plus a
    bytes32[] hash-path witness — merkle membership against a
    contract-committed snapshot root. An allowlist the caller cannot
    self-admit into; the value-movement exclusion must not open it."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IMembershipNFT {
            function processDepositFromEapUser(
                address user, uint256 snapshotEthAmount, uint256 points, bytes32[] calldata merkleProof
            ) external;
        }
        contract C {
            IMembershipNFT immutable nft;
            constructor(IMembershipNFT n) { nft = n; }
            function wrapForEap(uint256 amount, uint256 points, bytes32[] calldata proof) external payable {
                nft.processDepositFromEapUser(msg.sender, amount, points, proof);
            }
        }
    """,
    )
    cap = _cap_for(sl, "wrapForEap(uint256,uint256,bytes32[])")
    assert cap.kind == "external_check_only", f"void merkle-witness call must gate, got {cap.kind}"


def test_void_self_keyed_registration_stays_open_under_flag(tmp_path, earned_public):
    """DelegationManager.registerAsOperator: a VOID external call passing
    the caller and scalars — the callee records state for the caller's own
    key. Witness-free void calls stay permissionless (gating this would
    also re-gate the beforeTransfer denylist hook shape)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IAllocationManager {
            function setAllocationDelay(address operator, uint32 delay) external;
        }
        contract C {
            IAllocationManager immutable allocationManager;
            constructor(IAllocationManager m) { allocationManager = m; }
            function registerAsOperator(uint32 allocationDelay) external {
                allocationManager.setAllocationDelay(msg.sender, allocationDelay);
            }
        }
    """,
    )
    cap = _cap_for(sl, "registerAsOperator(uint32)")
    assert cap.kind == "conditional_universal", f"witness-free void self-keyed call must stay open, got {cap.kind}"


# ---------------------------------------------------------------------------
# Membership polarity: allowlist gates, denylist/claim-once stay open.
# ---------------------------------------------------------------------------


def test_caller_allowlist_membership_gates_under_flag(tmp_path, earned_public):
    """E4 conformance under the general rule (the bespoke arm is bypassed
    when the flag is on)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) public allowed;
            function f() external view {
                require(allowed[msg.sender]);
            }
        }
    """,
    )
    cap = _cap_for(sl, "f()")
    assert cap.kind == "external_check_only"
    assert cap.check is not None
    assert "caller_keyed_membership_allowlist" in (cap.check.extra.get("basis") or [])


def test_claim_once_denylist_stays_open_under_flag(tmp_path, earned_public):
    """Canary: falsy claim-once — the default-state caller is allowed."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) registered;
            function claim() external {
                require(!registered[msg.sender]);
                registered[msg.sender] = true;
            }
        }
    """,
    )
    cap = _cap_for(sl, "claim()")
    assert cap.kind == "conditional_universal", f"claim-once must stay open, got {cap.kind}"


# ---------------------------------------------------------------------------
# Comparisons: quantity thresholds open; equality-to-computed gates.
# ---------------------------------------------------------------------------


def test_balance_threshold_stays_open_under_flag(tmp_path, earned_public):
    """``balances[msg.sender] >= amount`` — the caller keys its own value;
    a quantity threshold, not membership in a curated set."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => uint256) public balances;
            function withdraw(uint256 amount) external {
                require(balances[msg.sender] >= amount, "insufficient");
                balances[msg.sender] -= amount;
            }
        }
    """,
    )
    cap = _cap_for(sl, "withdraw(uint256)")
    assert cap.kind == "conditional_universal", f"balance threshold must stay open, got {cap.kind}"


def test_caller_equals_untyped_computed_stays_open(tmp_path, earned_public):
    """``msg.sender == <untyped computed value>`` stays open: cross-contract
    inlining folds caller-keyed mapping reads to ``msg.sender == <scalar>``
    (``!hasPod(msg.sender)`` → ``msg.sender == 0``), so a caller equality
    whose other side is not plausibly address-typed is a folded value
    comparison on the caller's own data, not an identity authorization.
    Gating these manufactured false-gates on createPod/delegateTo/
    deregisterOperatorFromAVS (measured on the corpus)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function f(uint256 salt) external view {
                require(msg.sender == address(uint160(uint256(keccak256(abi.encode(salt))))), "no");
            }
        }
    """,
    )
    cap = _cap_for(sl, "f(uint256)")
    assert cap.kind == "conditional_universal", f"untyped computed equality must stay open, got {cap.kind}"


# ---------------------------------------------------------------------------
# Self-service equality canaries stay open with the flag on.
# ---------------------------------------------------------------------------


def test_renounce_style_self_service_stays_open_under_flag(tmp_path, earned_public):
    """Canary: ``account == msg.sender`` (renounceRole) — self-service."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) member;
            function renounce(address account) external {
                require(account == msg.sender, "can only renounce own");
                member[account] = false;
            }
        }
    """,
    )
    cap = _cap_for(sl, "renounce(address)")
    assert cap.kind == "conditional_universal", f"self-service equality must stay open, got {cap.kind}"
    assert any(c.kind == "self_service" for c in cap.conditions)


# ---------------------------------------------------------------------------
# Pure shape-classifier unit tests (dict leaves are fine for algebra-only).
# ---------------------------------------------------------------------------


def _leaf(**kw) -> Any:
    leaf = {
        "kind": "equality",
        "operator": "eq",
        "authority_role": "business",
        "operands": [],
        "references_msg_sender": False,
        "parameter_indices": [],
        "expression": "",
        "basis": [],
    }
    leaf.update(kw)
    return leaf


def test_taint_reads_operands_and_descriptor_keys():
    assert leaf_is_caller_tainted(_leaf(operands=[{"source": "msg_sender"}, {"source": "constant"}]))
    assert leaf_is_caller_tainted(
        _leaf(kind="membership", operator="truthy", set_descriptor={"key_sources": [{"source": "tx_origin"}]})
    )
    assert not leaf_is_caller_tainted(_leaf(operands=[{"source": "state_variable"}, {"source": "parameter"}]))


def test_exclusion_polarity_is_permissionless():
    assert is_permissionless_caller_shape(_leaf(operator="falsy", kind="membership"))
    assert is_permissionless_caller_shape(_leaf(operator="ne", operands=[{"source": "msg_sender"}]))


def test_self_comparison_and_signature_self_auth_are_permissionless():
    # msg.sender == tx.origin / msg.sender == ecrecover(...): every operand
    # caller-derived — uniform self-auth, not a curated set.
    assert is_permissionless_caller_shape(_leaf(operands=[{"source": "msg_sender"}, {"source": "tx_origin"}]))
    assert is_permissionless_caller_shape(_leaf(operands=[{"source": "msg_sender"}, {"source": "signature_recovery"}]))


def test_caller_vs_parameter_is_permissionless_but_state_var_is_not():
    assert is_permissionless_caller_shape(
        _leaf(operands=[{"source": "msg_sender"}, {"source": "parameter", "parameter_index": 0}])
    )
    assert not is_permissionless_caller_shape(
        _leaf(operands=[{"source": "msg_sender"}, {"source": "state_variable", "state_variable_name": "owner"}])
    )


def test_caller_vs_non_address_scalar_is_permissionless():
    # The inlining fold: ``!hasPod(msg.sender)`` / ``!isDelegated(msg.sender)``
    # collapse to ``msg.sender == 0 (uint256)`` — a folded claim-once, not an
    # identity test. An explicit address literal stays an authority.
    assert is_permissionless_caller_shape(
        _leaf(
            operands=[{"source": "msg_sender"}, {"source": "constant", "constant_value": "0", "value_type": "uint256"}]
        )
    )
    assert is_permissionless_caller_shape(
        _leaf(operands=[{"source": "msg_sender"}, {"source": "computed", "computed_kind": "member.REGISTERED"}])
    )
    assert not is_permissionless_caller_shape(
        _leaf(
            operands=[
                {"source": "msg_sender"},
                {"source": "constant", "constant_value": "0x" + "ab" * 20, "value_type": "address"},
            ]
        )
    )


def test_comparison_threshold_permissionless_but_time_allowlist_not():
    threshold = _leaf(kind="comparison", operator="gte", operands=[{"source": "computed"}, {"source": "parameter"}])
    assert is_permissionless_caller_shape(threshold)
    time_allowlist = _leaf(
        kind="comparison",
        operator="gte",
        operands=[
            {"source": "msg_sender"},
            {"source": "block_context", "block_context_kind": "timestamp"},
        ],
    )
    assert not is_permissionless_caller_shape(time_allowlist)


def test_external_bool_mutability_discriminates():
    view_acl = _leaf(kind="external_bool", operator="truthy", callee_state_mutability="view")
    assert not is_permissionless_caller_shape(view_acl)
    effectful = _leaf(kind="external_bool", operator="truthy", callee_state_mutability="nonview")
    assert is_permissionless_caller_shape(effectful)
    # Absent mutability (pre-flag trees): must not manufacture a false-gate
    # on the value-movement canary.
    legacy = _leaf(kind="external_bool", operator="truthy")
    assert is_permissionless_caller_shape(legacy)


def test_truthy_caller_membership_is_not_permissionless():
    leaf = _leaf(
        kind="membership",
        operator="truthy",
        set_descriptor={"key_sources": [{"source": "msg_sender"}]},
    )
    assert not is_permissionless_caller_shape(leaf)


def test_caller_keyed_bool_flag_fold_is_not_permissionless():
    # ``validatorSpawner[msg.sender].registered`` folds to a single-operand
    # truthy equality leaf — an allowlist, unlike the binary self-comparison.
    assert not is_permissionless_caller_shape(_leaf(operator="truthy", operands=[{"source": "msg_sender"}]))


# ---------------------------------------------------------------------------
# Projection: an unresolved ROOT-caller authorization AND-ed with public
# side-conditions gates the function (earned-public); bound-subject checks
# and resolved-empty ceilings keep the legacy side-condition fold.
# ---------------------------------------------------------------------------

from services.policy.capability_surface import project_capability_surface  # noqa: E402


def _and_dict(*children):
    return {"kind": "AND", "children": list(children)}


_PUBLIC = {"kind": "conditional_universal", "conditions": [{"kind": "business", "description": "whenNotPaused"}]}
# An unresolved CALLER gate (the earned-public default's fail-closed verdict)
# carries a caller-gate basis tag — only these block a sibling public path.
_ROOT_CHECK = {
    "kind": "external_check_only",
    "check": {
        "target_address": None,
        "target_call_selector": None,
        "extra": {"basis": ["caller_tainted_authority_unresolved"]},
    },
}
_BOUND_CHECK = {**_ROOT_CHECK, "subject": "bound"}
# A targeted downstream-call probe (the un-inlined Veda teller→vault check, a
# descriptor probe awaiting an adapter): basis is gate provenance, not a
# caller-gate tag — never a blocker.
_PROBE_CHECK = {
    "kind": "external_check_only",
    "check": {
        "target_address": "0x" + "cd" * 20,
        "target_call_selector": "0x61a3bcc8",
        "extra": {"basis": ["if-revert via successor NodeType.EXPRESSION"]},
    },
}
_EMPTY_LOWER = {"kind": "finite_set", "members": [], "membership_quality": "lower_bound", "confidence": "partial"}
_EMPTY_EXACT = {"kind": "finite_set", "members": [], "membership_quality": "exact", "confidence": "enumerable"}
_OWNER_SET = {
    "kind": "finite_set",
    "members": ["0x" + "ab" * 20],
    "membership_quality": "exact",
    "confidence": "enumerable",
}


def test_root_check_blocks_public_path_under_flag(earned_public):
    surface = project_capability_surface(_and_dict(_PUBLIC, _ROOT_CHECK))
    assert not surface.authority_public
    assert surface.residual


def test_root_check_folds_as_side_condition_without_flag(legacy_path):
    surface = project_capability_surface(_and_dict(_PUBLIC, _ROOT_CHECK))
    assert surface.authority_public


def test_bound_check_never_blocks_public_path(earned_public):
    """The Veda contract: an inlined downstream call's auth is a runtime
    side-condition, not an end-user restriction (and the cofinite/denylist
    public path must survive it)."""
    surface = project_capability_surface(_and_dict(_PUBLIC, _BOUND_CHECK))
    assert surface.authority_public


def test_untagged_probe_check_never_blocks_public_path(earned_public):
    """A targeted probe without a caller-gate basis tag (the UN-inlined
    teller→vault ``requiresAuth``, root subject by default) keeps the legacy
    side-condition fold: an adapter-earned public capability
    (PublicCapabilityUpdated) AND-ed with it must surface public
    (test_veda_principal_dimension pins the end-to-end shape)."""
    surface = project_capability_surface(_and_dict(_PUBLIC, _PROBE_CHECK))
    assert surface.authority_public


def test_unread_owner_equality_blocks_public_path_under_flag(earned_public):
    """``msg.sender == owner`` whose value wasn't read used to vanish in
    projection, letting a sibling public path open the function
    (WithdrawRequestNFT.seizeInvalidRequest)."""
    surface = project_capability_surface(_and_dict(_PUBLIC, _EMPTY_LOWER))
    assert not surface.authority_public


def test_resolved_empty_is_not_a_blocker(earned_public):
    surface = project_capability_surface(_and_dict(_PUBLIC, _EMPTY_EXACT))
    assert surface.authority_public


def test_principal_rows_survive_root_check_under_flag(earned_public):
    """Rows are already gated — the blocker folds onto them as a condition,
    exactly the legacy behavior (no caller-drop regression)."""
    surface = project_capability_surface(_and_dict(_OWNER_SET, _ROOT_CHECK))
    assert not surface.authority_public
    assert [r["address"] for r in surface.principal_rows] == ["0x" + "ab" * 20]


def test_or_blocks_only_when_every_disjunct_blocks(earned_public):
    blocked = project_capability_surface(_and_dict(_PUBLIC, {"kind": "OR", "children": [_ROOT_CHECK, _EMPTY_LOWER]}))
    assert not blocked.authority_public
    open_or = project_capability_surface(_and_dict(_PUBLIC, {"kind": "OR", "children": [_ROOT_CHECK, dict(_PUBLIC)]}))
    assert open_or.authority_public


def test_eth_send_success_check_stays_open(tmp_path, earned_public):
    """``(bool sent,) = msg.sender.call{value: amt}(""); require(sent)`` —
    the bool folds to a caller-sourced operand but is an effectful-call
    result: refunding the caller is value movement, not an allowlist
    (AuctionManager.cancelBid / UnwrapTokenV1ETH.claimWithdraw)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => uint256) public refunds;
            function claimRefund() external {
                uint256 amount = refunds[msg.sender];
                refunds[msg.sender] = 0;
                (bool sent, ) = msg.sender.call{value: amount}("");
                require(sent, "Failed to send Ether");
            }
        }
    """,
    )
    cap = _cap_for(sl, "claimRefund()")
    assert cap.kind == "conditional_universal", f"send-success check must stay open, got {cap.kind}"


def test_caller_equals_param_keyed_view_lookup_stays_open(tmp_path, earned_public):
    """``msg.sender == ownerOf(tokenId)`` — the caller matches a value keyed
    by its own argument: self-service-or-appointed (the ERC721
    transfer/claim family), not a fixed authority."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(uint256 => address) private _owners;
            function ownerOf(uint256 tokenId) public view returns (address) {
                return _owners[tokenId];
            }
            function burn(uint256 tokenId) external {
                require(msg.sender == ownerOf(tokenId), "not owner");
                delete _owners[tokenId];
            }
        }
    """,
    )
    cap = _cap_for(sl, "burn(uint256)")
    assert cap.kind == "conditional_universal", f"param-keyed view lookup must stay open, got {cap.kind}"
    assert any(c.kind == "self_service" for c in cap.conditions)


def test_caller_equals_nullary_getter_stays_gated(tmp_path, earned_public):
    """The fixed-authority sibling: ``msg.sender == owner()`` (nullary getter)
    keeps the gated resolution path."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address private _owner;
            function owner() public view returns (address) {
                return _owner;
            }
            function adminOp() external view {
                require(msg.sender == owner(), "not owner");
            }
        }
    """,
    )
    cap = _cap_for(sl, "adminOp()")
    assert cap.kind == "finite_set" and not cap.members and cap.membership_quality == "lower_bound"


# ---------------------------------------------------------------------------
# #111 / #112 — admin-curated caller-keyed THRESHOLD: promote + fail-closed.
#
# ``tier[msg.sender] >= K`` written only by an ``onlyOwner`` setter is an
# admin-curated authority — a caller cannot self-acquire the level — so the
# writer-gate promotes it from ``business`` to ``caller_authority`` (Part A),
# and the comparison branch enumerates it instead of re-opening to public via
# the role-blind permissionless-shape rule (Part B). A populated holder set
# (warm) or an authoritative empty (``exact`` = provably nobody now, #112) is
# honored; any cold / unsupported / no-adapter result fails CLOSED to an
# ``external_check_only`` carrying a ``CALLER_GATE_BASIS_TAGS`` tag (#111),
# never ``conditional_universal`` public.
#
# The discriminator's safe side: a self-acquirable ``points[msg.sender] >= K``
# written only by a self-keyed ``+=`` stays ``business`` and keeps opening to
# public when cold — the blanket "empty caller-keyed comparison => closed"
# alternative would wrongly gate this self-service threshold.
# ---------------------------------------------------------------------------

_ADMIN_CURATED_THRESHOLD = """
    pragma solidity ^0.8.19;
    contract C {
        address public owner;
        bool public open;
        mapping(address => uint256) public tier;
        constructor() { owner = msg.sender; }
        function setTier(address a, uint256 t) external {
            require(msg.sender == owner, "only owner");
            tier[a] = t;
        }
        function gated() external {
            require(open, "closed");
            require(tier[msg.sender] >= 2, "tier too low");
        }
    }
"""

_SELF_SERVICE_THRESHOLD = """
    pragma solidity ^0.8.19;
    contract C {
        bool public open;
        mapping(address => uint256) public points;
        function earn() external { points[msg.sender] += 1; }
        function gated() external {
            require(open, "closed");
            require(points[msg.sender] >= 5, "need points");
        }
    }
"""


class _StubAdapter:
    """Returns its configured capability for any descriptor — models the
    production adapter outcomes (warm holders / authoritative-empty) without
    smuggling in the routing decision the evaluator under test must make. A
    ``None`` adapter falls back to ``_NullAdapter`` (the cold / no-adapter
    state)."""

    def __init__(self, cap: Any) -> None:
        self._cap = cap

    def enumerate(self, descriptor: Any, contract_address: Any) -> Any:
        return self._cap


def _gate_comparison_subtree(tree: dict) -> Any:
    for child in tree.get("children") or []:
        leaf = child.get("leaf") or {}
        if leaf.get("kind") == "comparison":
            return child
    raise AssertionError("gate tree has no comparison leaf")


def _threshold_caps(sl, full_name: str, adapter: Any = None):
    """REAL pipeline: build_predicate_tree + writer_gate + evaluate. Returns
    (gate_leaf_role, gate_leaf_cap, end_to_end_surface). The gate-leaf cap is
    the comparison subtree alone; the surface is the whole ``gated()`` tree
    (the caller gate AND-ed with the public ``require(open)`` sibling — the
    end-to-end path the projection blocker must suppress)."""
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    tree = trees[full_name]
    gate_subtree = _gate_comparison_subtree(tree)
    role = (gate_subtree.get("leaf") or {}).get("authority_role")
    ctx = EvaluationContext(contract_address="0x" + "11" * 20, adapter=adapter)
    gate_cap = evaluate_tree(gate_subtree, ctx)
    surface = project_capability_surface(capability_to_dict(evaluate_tree(tree, ctx)))
    return role, gate_cap, surface


def test_admin_curated_threshold_promotes_to_caller_authority(tmp_path, earned_public):
    """Part A (writer-gate discriminator): an ``onlyOwner``-curated
    ``tier[msg.sender] >= K`` is not self-acquirable, so it promotes from
    ``business`` to ``caller_authority``."""
    role, _cap, _surface = _threshold_caps(_compile(tmp_path, _ADMIN_CURATED_THRESHOLD), "gated()")
    assert role == "caller_authority"


def test_admin_curated_threshold_cold_fails_closed(tmp_path, earned_public):
    """#111: a promoted authority threshold whose enumeration is cold /
    no-adapter must GATE — ``external_check_only`` carrying a caller-gate basis
    tag — never the ``conditional_universal`` public default. Revert-proof for
    BOTH the static promotion (Part A) and the comparison-branch re-open drop
    (Part B): reverting either re-opens the gate and fails this assertion."""
    sl = _compile(tmp_path, _ADMIN_CURATED_THRESHOLD)
    role, gate_cap, surface = _threshold_caps(sl, "gated()", adapter=None)
    assert role == "caller_authority"
    assert gate_cap.kind == "external_check_only", f"cold admin threshold must gate, got {gate_cap.kind}"
    basis = capability_to_dict(gate_cap)["check"]["extra"]["basis"]
    assert basis == ["caller_tainted_authority_unresolved"]
    # end-to-end: the sibling ``require(open)`` public path is suppressed.
    assert not surface.authority_public


def test_admin_curated_threshold_exact_empty_is_resolved_not_public(tmp_path, earned_public):
    """#112: an authoritative ``finite_set([], exact)`` (provably nobody now)
    is honored as resolved-empty, never coerced to public."""
    sl = _compile(tmp_path, _ADMIN_CURATED_THRESHOLD)
    empty_exact = CapabilityExpr.finite_set([], quality="exact", confidence="enumerable")
    role, gate_cap, surface = _threshold_caps(sl, "gated()", adapter=_StubAdapter(empty_exact))
    assert role == "caller_authority"
    assert gate_cap.kind == "finite_set"
    assert gate_cap.members == []
    assert gate_cap.membership_quality == "exact"
    assert not surface.authority_public


def test_admin_curated_threshold_warm_enumerates_restricted_holders(tmp_path, earned_public):
    """Warm: the populated holder set is honored (restricted callers), gated —
    the polarity the cold/empty cells must agree with, not invert from."""
    sl = _compile(tmp_path, _ADMIN_CURATED_THRESHOLD)
    holders = ["0x" + "aa" * 20, "0x" + "bb" * 20]
    warm = CapabilityExpr.finite_set(holders, quality="lower_bound", confidence="partial")
    _role, gate_cap, surface = _threshold_caps(sl, "gated()", adapter=_StubAdapter(warm))
    assert gate_cap.kind == "finite_set"
    assert gate_cap.members == holders
    assert not surface.authority_public


def test_self_service_threshold_stays_public_when_cold(tmp_path, earned_public):
    """The discriminator's safe side (no over-gate): a self-acquirable
    ``points[msg.sender] >= K`` written only by a self-keyed ``+=`` stays
    ``business`` and keeps opening to public when cold. The blanket
    "empty caller-keyed comparison => closed" alternative would wrongly gate
    this — guards against that over-gate regression."""
    sl = _compile(tmp_path, _SELF_SERVICE_THRESHOLD)
    role, gate_cap, surface = _threshold_caps(sl, "gated()", adapter=None)
    assert role == "business"
    assert gate_cap.kind == "conditional_universal", f"self-service threshold must stay open, got {gate_cap.kind}"
    assert surface.authority_public


# ---------------------------------------------------------------------------
# The Solady EnumerableRoles shape: an assembly-backed,
# named-return role read the static lifter cannot lower, after which the
# caller taint was hashed into ``callee_args_digest`` and a hardcoded
# ``authority_role="business"`` default published the gate as PUBLIC.
# (The "callee parameter binding" hypothesis is REFUTED — the binding
# works; the loss is downstream of it.)
# ---------------------------------------------------------------------------

_SOLADY_SELF_GATE = """
    pragma solidity ^0.8.19;
    contract C {
        uint256 public constant UPGRADE_TIMELOCK_ROLE_ID = 1;
        function hasRole(address holder, uint256 role) public view returns (bool result) {
            assembly {
                mstore(0x00, holder)
                mstore(0x20, role)
                result := iszero(iszero(sload(keccak256(0x00, 0x40))))
            }
        }
        function hasRole2(bytes32 role, address account) public view returns (bool) {
            return hasRole(account, uint256(role));
        }
        function onlyUpgradeTimelock(address account) public view {
            if (!hasRole2(bytes32(UPGRADE_TIMELOCK_ROLE_ID), account)) revert();
        }
        function f() external {
            _authorizeUpgrade();
        }
        function _authorizeUpgrade() internal view {
            onlyUpgradeTimelock(msg.sender);
        }
    }
"""

_SOLADY_MODIFIER_GATE = """
    pragma solidity ^0.8.19;
    contract C {
        function hasRole(address holder, uint256 role) internal view returns (bool result) {
            assembly {
                mstore(0x00, holder)
                mstore(0x20, role)
                result := iszero(iszero(sload(keccak256(0x00, 0x40))))
            }
        }
        modifier onlyTL() {
            if (!hasRole(msg.sender, 1)) revert();
            _;
        }
        function f() external onlyTL {}
    }
"""


def _leaves(tree):
    if not isinstance(tree, dict):
        return []
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        return [leaf] if leaf else []
    out = []
    for child in tree.get("children") or []:
        out.extend(_leaves(child))
    return out


def test_solady_self_gate_emits_probeable_descriptor_and_gates(tmp_path, earned_public):
    """Part A: the un-lowerable gate lives in a public single-address-param view
    ON the analyzed contract, so it is emitted as the same ``external_set``
    shape the identical gate takes when it is an EXTERNAL call (weETH's
    modifier) — handing it to the role-store adapter that already answers it
    correctly for every other contract. It must NOT read as public."""
    sl = _compile(tmp_path, _SOLADY_SELF_GATE)
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    leaves = _leaves(trees["f()"])
    gate = next(leaf for leaf in leaves if leaf.get("set_descriptor"))
    descriptor = gate["set_descriptor"]
    assert descriptor["kind"] == "external_set"
    assert descriptor["callee_signature"] == "onlyUpgradeTimelock(address)"
    # The authority is the analyzed deployment itself (the self-gate case), and
    # the caller is the descriptor's key so the adapter probes the real gate.
    assert descriptor["authority_contract"]["address_source"] == {"source": "self_address"}
    assert descriptor["key_sources"] == [{"source": "msg_sender"}]
    assert gate["authority_role"] == "delegated_authority"
    assert leaf_is_caller_tainted(gate) is True
    assert is_permissionless_caller_shape(gate) is False

    cap = evaluate_tree(trees["f()"])
    assert cap.kind != "conditional_universal", "the unlowered-role fail-open"
    assert capability_to_dict(cap)["kind"] != "conditional_universal"


def _tree_verdict(tree):
    dd = capability_to_dict(evaluate_tree(tree))
    return dd.get("kind")


def test_self_gate_checker_own_entry_point_stays_public(tmp_path, earned_public):
    """The un-hedged direction of Part A: the CHECKER's own entry point
    constrains its ARGUMENT, not its caller — anyone may call
    ``onlyUpgradeTimelock(anyAddress)``. Its own tree must stay
    ``conditional_universal`` (public) with no fabricated caller witness: no
    self-gate descriptor keyed on ``msg_sender``, no ``msg_sender`` in any
    operand's ``derived_from``, even though ``_authorizeUpgrade`` elsewhere in
    the contract calls it with ``msg.sender``. (The round-1 regression: the
    entry-parameter Phi unioned the call-site argument into the checker's own
    frame, so the verdict for a function was decided by what an unrelated
    function does.)"""
    sl = _compile(tmp_path, _SOLADY_SELF_GATE)
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    checker = trees["onlyUpgradeTimelock(address)"]
    assert _tree_verdict(checker) == "conditional_universal"
    for leaf in _leaves(checker):
        descriptor = leaf.get("set_descriptor") or {}
        assert descriptor.get("key_sources") != [{"source": "msg_sender"}]
        assert leaf.get("references_msg_sender") is not True
        for op in leaf.get("operands") or []:
            origins = [o.get("source") for o in (op.get("derived_from") or [])]
            assert "msg_sender" not in origins
    # The hedged direction is unchanged: reached THROUGH a call that binds the
    # parameter to msg.sender, the same gate still gates.
    assert _tree_verdict(trees["f()"]) != "conditional_universal"


_SIBLING_CHECKERS = """
    pragma solidity ^0.8.19;
    contract C {
        uint256 public constant ROLE_A = 1;
        uint256 public constant ROLE_B = 2;
        function hasRole(address holder, uint256 role) public view returns (bool result) {
            assembly {
                mstore(0x00, holder)
                mstore(0x20, role)
                result := iszero(iszero(sload(keccak256(0x00, 0x40))))
            }
        }
        function onlyA(address account) public view { if (!hasRole(account, ROLE_A)) revert(); }
        function onlyB(address account) public view { if (!hasRole(account, ROLE_B)) revert(); }
        function guarded() external { onlyA(msg.sender); }
    }
"""


def test_sibling_checkers_get_the_same_verdict_regardless_of_callers(tmp_path, earned_public):
    """Byte-identical checkers must not diverge because only one of them is
    ever called with ``msg.sender`` — the cid-568 falsification
    (onlyUpgradeTimelock flipped while its eight identical siblings stayed
    public). Frame purity: each checker's own frame sees its parameter as a
    parameter, and each ``hasRole`` sub-frame sees only ITS call site's role
    constant, not the union of every sibling's."""
    sl = _compile(tmp_path, _SIBLING_CHECKERS)
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    assert _tree_verdict(trees["onlyA(address)"]) == "conditional_universal"
    assert _tree_verdict(trees["onlyB(address)"]) == "conditional_universal"
    # The caller that binds msg.sender still gates.
    assert _tree_verdict(trees["guarded()"]) != "conditional_universal"
    # Frame purity of the sub-frame: onlyA's leaf never carries onlyB's role
    # constant (the cross-call-site union listed every sibling's constant).
    for leaf in _leaves(trees["onlyA(address)"]):
        for op in leaf.get("operands") or []:
            names = {o.get("state_variable_name") for o in (op.get("derived_from") or [])}
            assert "ROLE_B" not in names


def test_solady_modifier_gate_caller_taint_survives_the_digest(tmp_path, earned_public):
    """Part B: the gate is in a MODIFIER (not a probe-able view), so no
    descriptor is possible — but the caller was passed as an ARGUMENT of the
    un-lowerable read, and ``derived_from`` now carries that. The bare-bool
    leaf is therefore caller-tainted and, because the comparison it performs
    was never lowered, is never classified permissionless."""
    sl = _compile(tmp_path, _SOLADY_MODIFIER_GATE)
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    gate = next(leaf for leaf in _leaves(trees["f()"]) if leaf.get("operator") in ("truthy", "falsy"))
    origins = [o.get("source") for o in (gate["operands"][0].get("derived_from") or [])]
    assert "msg_sender" in origins
    assert leaf_is_caller_tainted(gate) is True
    assert is_permissionless_caller_shape(gate) is False
    assert evaluate_tree(trees["f()"]).kind != "conditional_universal"


def test_collapsed_caller_taint_does_not_fire_on_value_bounds_or_signature_checks():
    """The over-fire guard, and the reason the rule is shape-narrow.
    ``derived_from`` is TRANSITIVE, so any value computed from a
    caller-parameterized call carries the caller's origin. Measured on the
    88-contract corpus, the broad form tainted 25 leaves of which 23 were
    false. Each shape below is one of those false positives and must stay
    untainted by the collapsed rule."""
    from typing import cast

    from services.resolution.permissionless_shapes import leaf_caller_taint_is_collapsed as _collapsed
    from services.static.static_analysis.predicate_types import LeafPredicate

    def leaf_caller_taint_is_collapsed(leaf: dict) -> bool:
        return _collapsed(cast(LeafPredicate, leaf))

    caller_origin = [{"source": "msg_sender"}]
    computed = {"source": "computed", "computed_kind": "binary", "derived_from": caller_origin}

    # ``sharesBridged > type(uint96).max`` / ``shares < minimumMint`` — value bounds.
    assert not leaf_caller_taint_is_collapsed({"kind": "comparison", "operator": "lte", "operands": [computed]})
    # ``require(addr != address(0), "Create2: Failed on deploy")`` — a deploy check.
    assert not leaf_caller_taint_is_collapsed({"kind": "equality", "operator": "ne", "operands": [computed]})
    # ``require(signer.isValidSignatureNow(...))`` — self-auth, an ``eq`` equality.
    assert not leaf_caller_taint_is_collapsed({"kind": "equality", "operator": "eq", "operands": [computed]})
    # The Veda ``enter(...)`` vault call — external_bool carries its own
    # mutability, which the value-movement canary rule governs.
    assert not leaf_caller_taint_is_collapsed({"kind": "external_bool", "operator": "truthy", "operands": [computed]})
    # A two-operand comparison is a readable shape, classified on that shape.
    assert not leaf_caller_taint_is_collapsed(
        {"kind": "equality", "operator": "truthy", "operands": [computed, {"source": "state_variable"}]}
    )
    # An external_call operand: mutability unknown at operand level.
    assert not leaf_caller_taint_is_collapsed(
        {
            "kind": "equality",
            "operator": "truthy",
            "operands": [{"source": "external_call", "derived_from": caller_origin}],
        }
    )
    # ...and the shape that DOES fire: the un-lowered bare-bool predicate.
    assert leaf_caller_taint_is_collapsed({"kind": "equality", "operator": "truthy", "operands": [computed]})
    # Absent derived_from stays not-determined — no taint claim from absence.
    assert not leaf_caller_taint_is_collapsed(
        {"kind": "equality", "operator": "truthy", "operands": [{"source": "computed", "derived_from": None}]}
    )


def test_self_gate_never_replaces_a_named_state_variable_attribution(tmp_path, earned_public):
    """Part A is subordinate to the operand resolution it would overwrite: a
    fallback leaf that recovered the underlying state VARIABLE keeps it (that
    name is what controller enrollment and the pause/reentrancy passes key on).
    Trading a named authority variable for a selector would be strictly less."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) private allowed;
            function check(address who) public view returns (bool) {
                return allowed[who];
            }
            function f() external {
                if (!check(msg.sender)) revert();
            }
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "C")
    trees = _build_pipeline(contract)
    leaves = _leaves(trees["f()"])
    names = {
        op.get("state_variable_name")
        for leaf in leaves
        for op in leaf.get("operands") or []
        if op.get("source") == "state_variable"
    }
    descriptor_vars = {(leaf.get("set_descriptor") or {}).get("storage_var") for leaf in leaves}
    assert "allowed" in names or "allowed" in descriptor_vars
