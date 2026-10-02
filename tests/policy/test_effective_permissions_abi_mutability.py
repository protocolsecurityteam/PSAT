"""Assembly-only gates (Solady ``EnumerableRoles``) yield no sink or tree, so these must surface as ``unsupported``
rows, not be dropped.
"""

from __future__ import annotations

import textwrap

import pytest
from eth_utils.crypto import keccak

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.policy.effective_permissions import build_effective_permissions  # noqa: E402
from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
)

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


_TAKEOVER_PROXY_SOURCE = """
pragma solidity ^0.8.19;

contract TakeOverProxy {
    address impl;

    function takeOver(address a) public {
        assembly { sstore(0, a) }
    }

    fallback() external payable {
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, 0, calldatasize())
            let result := delegatecall(gas(), sload(0), ptr, calldatasize(), 0, 0)
            returndatacopy(ptr, 0, returndatasize())
            switch result
            case 0 { revert(ptr, returndatasize()) }
            default { return(ptr, returndatasize()) }
        }
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


@pytest.fixture(scope="module")
def takeover_artifacts(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("takeover_proxy")
    src = tmp / "TakeOverProxy.sol"
    src.write_text(textwrap.dedent(_TAKEOVER_PROXY_SOURCE).strip() + "\n")
    sl = Slither(str(src))
    contract = next(c for c in sl.contracts if c.name == "TakeOverProxy")
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
    return build_effective_permissions(
        analysis,
        effects=effects,
        predicate_trees=predicate_trees,
        capability_resolver_output={},
    )


def test_assembly_only_mutators_surface_as_unsupported_rows(roles_artifacts):
    payload = _build(roles_artifacts)
    by_selector = {fn["selector"]: fn for fn in payload["functions"]}

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
        assert fn["controllers"] == []
        assert fn.get("capability_expr", {}).get("unsupported_reason") in unsupported_gate_reasons


def test_abi_only_state_changer_uses_assembly_reason(roles_artifacts):
    effects, _ = roles_artifacts
    analysis = {"subject": {"address": "0x000000000000000000000000000000000000dead", "name": "Stub"}}
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


def test_assembly_writer_with_invisible_gate_stays_unsupported(takeover_artifacts):
    """Without the assembly-sink guard it projects ``public``; the structural asserts pin the routing."""
    effects, predicate_trees = takeover_artifacts
    analysis = {"subject": {"address": "0x000000000000000000000000000000000000dead", "name": "TakeOverProxy"}}

    take = effects["functions"]["takeOver(address)"]
    assert any(
        s["kind"] == "state_write" and s["target"].startswith("assembly_storage:") for s in take.get("sinks") or []
    ), "takeOver must carry an assembly state_write sink (else it routes via abi_only, not the guard)"
    trees = predicate_trees.get("trees", predicate_trees)
    assert "takeOver(address)" not in trees, "takeOver must have no predicate tree (else it routes via the tree branch)"

    payload = build_effective_permissions(
        analysis,
        effects=effects,
        predicate_trees=predicate_trees,
        capability_resolver_output={},
    )
    by_sig = {fn["function"]: fn for fn in payload["functions"]}

    fn = by_sig["takeOver(address)"]
    assert fn.get("status") == "unsupported"
    assert fn["authority_public"] is False
    assert fn["controllers"] == []
    assert fn.get("capability_expr", {}).get("unsupported_reason") == "assembly_only_authority_not_extracted"


def test_inline_assembly_sstore_and_delegatecall_surface_as_sinks(takeover_artifacts):
    """Fails if the effects.py SolidityCall branches are reverted."""
    effects, _ = takeover_artifacts
    functions = effects["functions"]

    take = functions["takeOver(address)"]
    write_sinks = [s for s in take.get("sinks") or [] if s["kind"] == "state_write"]
    assert any(s["target"].startswith("assembly_storage:") for s in write_sinks), take.get("sinks")
    assert take.get("writer_selectors"), "assembly sstore must populate writer_selectors"

    fb = functions["fallback()"]
    dc_sinks = [s for s in fb.get("sinks") or [] if s["kind"] == "delegatecall"]
    assert any(s["target"].startswith("assembly_delegatecall:") for s in dc_sinks), fb.get("sinks")
    assert "delegatecall_execution" in (fb.get("effect_labels") or [])
    assert fb.get("action_summary") == "Executes delegatecall-controlled logic."


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
        (_StubFn(name="fallback"), False),
        (_StubFn(name="receive"), False),
        (_StubFn(name="helper", visibility="internal"), False),
        (_StubFn(name="helper", visibility="private"), False),
    ],
)
def test_state_changing_entry_point_predicate(fn, expected):
    from services.static.contract_analysis_pipeline.effects import _is_state_changing_entry_point

    assert _is_state_changing_entry_point(fn) is expected
