"""Regression: the effective-permissions function set covers every
state-changing external/public ABI entry point, even when the authority
gate and the state writes live in inline assembly the high-level IR can't
see as a predicate tree or a sink.

Drives the production stack: real Slither compile -> ``build_effects`` ->
``build_effective_permissions``. The fixture mirrors the Solady
``EnumerableRoles`` shape (RoleRegistry): ``setRole``/``grantRole``/
``revokeRole`` mutate role storage via ``sstore`` and gate the caller via
an assembly owner-read, so neither a sink nor a predicate tree is emitted.
Such functions must surface as honest ``unsupported`` rows with no
principals attached, rather than being silently dropped.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest
from eth_utils.crypto import keccak

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.policy.effective_permissions import build_effective_permissions  # noqa: E402
from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
)

# A self-contained Solady EnumerableRoles-style contract. The role-storage
# mutation and the owner gate are entirely inline assembly, exactly as in
# Solady's library, so the high-level IR yields no state_write sink and no
# caller_authority predicate leaf for the three mutators.
_SOLADY_ROLES_SOURCE = """
pragma solidity ^0.8.19;

contract MiniEnumerableRoles {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function _senderIsOwner() private view returns (bool result) {
        assembly {
            result := eq(caller(), sload(owner.slot))
        }
    }

    function _setRole(address holder, uint256 role, bool active) internal {
        assembly {
            mstore(0x00, role)
            mstore(0x20, holder)
            let slot := keccak256(0x00, 0x40)
            sstore(slot, active)
        }
    }

    function setRole(address holder, uint256 role, bool active) public payable {
        if (!_senderIsOwner()) revert();
        _setRole(holder, role, active);
    }

    function grantRole(bytes32 role, address account) public {
        setRole(account, uint256(role), true);
    }

    function revokeRole(bytes32 role, address account) public {
        setRole(account, uint256(role), false);
    }

    function hasRole(address holder, uint256 role) public view returns (bool result) {
        assembly {
            mstore(0x00, role)
            mstore(0x20, holder)
            result := iszero(iszero(sload(keccak256(0x00, 0x40))))
        }
    }

    function MAX_ROLE() public pure returns (uint256) {
        return type(uint256).max;
    }
}
"""


def _selector(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


@pytest.fixture(scope="module")
def roles_artifacts(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("mini_roles")
    src = tmp / "MiniEnumerableRoles.sol"
    src.write_text(textwrap.dedent(_SOLADY_ROLES_SOURCE).strip() + "\n")
    sl = Slither(str(src))
    contract = next(c for c in sl.contracts if c.name == "MiniEnumerableRoles")
    effects = build_effects(contract)
    predicate_trees = build_predicate_artifacts(contract)
    return effects, predicate_trees


def _build(roles_artifacts):
    effects, predicate_trees = roles_artifacts
    analysis = {
        "subject": {
            "address": "0x000000000000000000000000000000000000dead",
            "name": "MiniEnumerableRoles",
        },
    }
    # The resolver ran but found no guard tree for the three mutators (their
    # gate is invisible to the IR), so it produced no capability for them.
    return build_effective_permissions(
        analysis,
        effects=effects,
        predicate_trees=predicate_trees,
        capability_resolver_output={},
    )


def test_assembly_only_mutators_surface_as_unsupported_rows(roles_artifacts):
    payload = _build(roles_artifacts)
    by_selector = {fn["selector"]: fn for fn in payload["functions"]}

    # Both unsupported reasons describe an unresolved gate: the abi-mutability
    # surface adds the row when the gate yields no tree at all
    # (``assembly_only_authority_not_extracted``); when the IR does recover a
    # tree but the resolver finds no semantic capability, the row is already
    # produced under the tree union. Either way the function is visible,
    # gated, and principal-free.
    unsupported_gate_reasons = {
        "assembly_only_authority_not_extracted",
        "missing_semantic_capability_for_predicate_tree",
    }
    for signature in (
        "setRole(address,uint256,bool)",
        "grantRole(bytes32,address)",
        "revokeRole(bytes32,address)",
    ):
        sel = _selector(signature)
        assert sel in by_selector, f"{signature} ({sel}) missing from effective functions"
        fn = by_selector[sel]
        assert fn.get("status") == "unsupported"
        assert fn["authority_public"] is False
        # No principals auto-attached — the gate is unresolved, not public.
        assert fn["controllers"] == []
        assert fn.get("capability_expr", {}).get("unsupported_reason") in unsupported_gate_reasons


def test_abi_only_state_changer_uses_assembly_reason(roles_artifacts):
    """A state-changing entry point that produced no sink, no predicate tree,
    and no resolver capability is included via the ABI mutability surface and
    flagged with the assembly-only reason — never projected public."""
    effects, _ = roles_artifacts
    analysis = {"subject": {"address": "0x000000000000000000000000000000000000dead", "name": "Stub"}}
    # A bare state-changing record with no sink and no covering tree/cap.
    effects_no_sink = {
        "schema_version": "semantic",
        "contract_name": "Stub",
        "functions": {
            "writeOpaque(uint256)": {
                "function": "writeOpaque(uint256)",
                "selector": _selector("writeOpaque(uint256)"),
                "sinks": [],
                "effect_labels": [],
                "effect_targets": [],
                "action_summary": "Performs a contract action.",
                "state_changing": True,
            }
        },
    }
    payload = build_effective_permissions(analysis, effects=effects_no_sink, capability_resolver_output={})
    fns = {fn["function"]: fn for fn in payload["functions"]}
    assert "writeOpaque(uint256)" in fns
    fn = fns["writeOpaque(uint256)"]
    assert fn.get("status") == "unsupported"
    assert fn["authority_public"] is False
    assert fn["controllers"] == []
    assert fn.get("capability_expr", {}).get("unsupported_reason") == "assembly_only_authority_not_extracted"


def test_view_and_pure_reads_do_not_gain_rows(roles_artifacts):
    payload = _build(roles_artifacts)
    selectors = {fn["selector"] for fn in payload["functions"]}

    # view/pure entry points are NOT part of the state-changing ABI surface.
    assert _selector("hasRole(address,uint256)") not in selectors
    assert _selector("MAX_ROLE()") not in selectors


def test_state_changing_flag_tracks_solidity_mutability(roles_artifacts):
    effects, _ = roles_artifacts
    functions = effects["functions"]

    for mutator in (
        "setRole(address,uint256,bool)",
        "grantRole(bytes32,address)",
        "revokeRole(bytes32,address)",
    ):
        assert functions[mutator]["state_changing"] is True

    for reader in ("hasRole(address,uint256)", "MAX_ROLE()"):
        assert functions[reader]["state_changing"] is False


class _StubFn:
    def __init__(self, *, name="f", visibility="external", view=False, pure=False, is_fallback=False, is_receive=False):
        self.name = name
        self.visibility = visibility
        self.view = view
        self.pure = pure
        self.is_fallback = is_fallback
        self.is_receive = is_receive


@pytest.mark.parametrize(
    "fn,expected",
    [
        (_StubFn(name="setRole", visibility="external"), True),
        (_StubFn(name="setRole", visibility="public"), True),
        (_StubFn(name="getRate", visibility="external", view=True), False),
        (_StubFn(name="hashLeaf", visibility="public", pure=True), False),
        (_StubFn(is_fallback=True), False),
        (_StubFn(is_receive=True), False),
        # fallback/receive identified by name even when the boolean flags are absent.
        (_StubFn(name="fallback"), False),
        (_StubFn(name="receive"), False),
        # internal/private functions are not part of the ABI mutability surface.
        (_StubFn(name="helper", visibility="internal"), False),
        (_StubFn(name="helper", visibility="private"), False),
    ],
)
def test_state_changing_entry_point_predicate(fn, expected):
    from services.static.contract_analysis_pipeline.effects import _is_state_changing_entry_point

    assert _is_state_changing_entry_point(fn) is expected
