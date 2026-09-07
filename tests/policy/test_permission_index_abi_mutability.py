"""Regression: the effective-permissions function set covers every
state-changing external/public ABI entry point, even when the authority
gate and the state writes live in inline assembly the high-level IR can't
see as a predicate tree or a sink.

Drives the production stack: real Slither compile -> ``build_effects`` ->
``build_permission_index``. The fixture mirrors the Solady
``EnumerableRoles`` shape (RoleRegistry): ``setRole``/``grantRole``/
``revokeRole`` mutate role storage via ``sstore`` and gate the caller via
an assembly owner-read, so neither a sink nor a predicate tree is emitted.
Such functions must surface as honest ``unsupported`` rows with no
principals attached, rather than being silently dropped.
"""

from __future__ import annotations

import textwrap

import pytest
from eth_utils.crypto import keccak

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.policy.permission_index import build_permission_index  # noqa: E402
from services.static.claims import attach_claims_to_effects, build_claims  # noqa: E402
from services.static.static_analysis.effects import build_effects  # noqa: E402
from services.static.static_analysis.predicate_artifacts import (  # noqa: E402
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


# An EIP-1967-style proxy whose state write AND fallback delegatecall are
# entirely inline assembly, and — critically — whose mutator ``takeOver`` has
# NO high-level caller gate at all. Slither emits a ``SolidityCall sstore``
# IR for the write (no predicate tree, no high-level state_variables_written),
# so this mutator routes through the assembly-sink path, NOT the predicate-tree
# path the Solady-roles fixture above exercises.
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
    attach_claims_to_effects(effects, build_claims(contract, effects, {}))
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
    attach_claims_to_effects(effects, build_claims(contract, effects, {}))
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
    return build_permission_index(
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
                "state_changing": True,
            }
        },
    }
    payload = build_permission_index(analysis, effects=effects_no_sink, capability_resolver_output={})
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


def test_assembly_writer_with_invisible_gate_stays_unsupported(takeover_artifacts):
    """Co-land guard regression: an assembly state writer whose gate is NOT
    extractable as a predicate tree must route through the *assembly-sink*
    guard (``assembly_only_signatures``), not the abi-only or predicate-tree
    branches.

    ``takeOver`` carries an inline-assembly ``sstore`` sink (so it is removed
    from ``abi_only_signatures``) and produces no predicate tree (so it is not
    caught by ``missing_semantic_capability_for_predicate_tree``). The ONLY
    thing keeping it ``unsupported`` is the assembly-sink guard added by this
    fix; with that guard removed it projects ``public`` (verified manually).
    The two structural asserts below pin the routing so the test cannot pass
    via a different unsupported branch.
    """
    effects, predicate_trees = takeover_artifacts
    analysis = {"subject": {"address": "0x000000000000000000000000000000000000dead", "name": "TakeOverProxy"}}

    # Structural preconditions that force the assembly-sink branch:
    take = effects["functions"]["takeOver(address)"]
    assert any(
        s["kind"] == "state_write" and s["target"].startswith("assembly_storage:") for s in take.get("sinks") or []
    ), "takeOver must carry an assembly state_write sink (else it routes via abi_only, not the guard)"
    trees = predicate_trees.get("trees", predicate_trees)
    assert "takeOver(address)" not in trees, "takeOver must have no predicate tree (else it routes via the tree branch)"

    payload = build_permission_index(
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
    """Effects accuracy regression: the assembly ``sstore`` write and the
    assembly ``delegatecall`` fallback must each surface as a sink, with the
    writer selector populated and the delegatecall-execution capability
    recovered. Fails if the effects.py SolidityCall sstore/delegatecall
    branches are reverted (both sinks vanish)."""
    effects, _ = takeover_artifacts
    functions = effects["functions"]

    # Assembly sstore -> state_write sink keyed by the slot, writer monitorable
    # by selector.
    take = functions["takeOver(address)"]
    write_sinks = [s for s in take.get("sinks") or [] if s["kind"] == "state_write"]
    assert any(s["target"].startswith("assembly_storage:") for s in write_sinks), take.get("sinks")
    assert take.get("writer_selectors"), "assembly sstore must populate writer_selectors"

    # Assembly delegatecall fallback -> delegatecall sink + supported claim.
    fb = functions["fallback()"]
    dc_sinks = [s for s in fb.get("sinks") or [] if s["kind"] == "delegatecall"]
    assert any(s["target"].startswith("assembly_delegatecall:") for s in dc_sinks), fb.get("sinks")
    assert any(claim["claim_id"] == "delegatecall.execute" for claim in fb.get("claims") or [])


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
    from services.static.static_analysis.effects import _is_state_changing_entry_point

    assert _is_state_changing_entry_point(fn) is expected
