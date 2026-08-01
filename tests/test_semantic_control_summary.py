"""``_build_semantic_control_summary`` semantic signal.

Validates the structural inclusion rule: a function is in
``semantic_functions`` iff EITHER:
  * its predicate tree has a leaf with
    ``authority_role IN {caller_authority, delegated_authority}``, OR
  * its effects record carries a sensitive sink (state_write,
    external_call, delegatecall, contract_creation, selfdestruct).

Tree-keys-as-included used to over-include pause / reentrancy / time /
business side-condition trees. This test pins the structural rule in place.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
)
from services.static.contract_analysis_pipeline.summaries import (  # noqa: E402
    _build_semantic_control_summary,
)


def _compile(tmp_path: Path, source: str, contract_name: str = "C"):
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    sl = Slither(str(f))
    return next(c for c in sl.contracts if c.name == contract_name)


def _detect(tmp_path, source, contract_name="C"):
    contract = _compile(tmp_path, source, contract_name)
    predicate_trees = build_predicate_artifacts(contract)
    effects = build_effects(contract)
    return _build_semantic_control_summary(contract, tmp_path, predicate_trees, effects)


def test_caller_authority_leaf_admits_function(tmp_path):
    """Direct ``msg.sender == owner`` gate → caller_authority leaf →
    included."""
    source = """
    pragma solidity ^0.8.19;
    contract C {
        address public owner;
        uint256 public value;
        constructor() { owner = msg.sender; }
        function setValue(uint256 v) external {
            require(msg.sender == owner, "not owner");
            value = v;
        }
    }
    """
    ac = _detect(tmp_path, source)
    semantic_signatures = {pf["function"] for pf in ac["semantic_functions"]}
    assert "setValue(uint256)" in semantic_signatures


def test_sensitive_sink_admits_unguarded_function(tmp_path):
    """An unguarded external_call / state_write counts as a sensitive
    sink — the function is still included so consumers can find
    it."""
    source = """
    pragma solidity ^0.8.19;
    contract C {
        address public owner;
        function publicSetOwner(address newOwner) external {
            owner = newOwner;
        }
    }
    """
    ac = _detect(tmp_path, source)
    semantic_signatures = {pf["function"] for pf in ac["semantic_functions"]}
    assert "publicSetOwner(address)" in semantic_signatures


def test_pause_only_tree_does_not_admit_function(tmp_path):
    """A function whose only tree-leaf is a pause check should NOT be
    in semantic_functions if it has no sensitive sink. Pause-only
    is a side-condition; it doesn't make a function caller-authorized."""
    source = """
    pragma solidity ^0.8.19;
    contract C {
        bool public _paused;
        address public owner;
        modifier whenNotPaused() {
            require(!_paused);
            _;
        }
        function pause() external {
            require(msg.sender == owner);
            _paused = true;
        }
        // This view function is gated by pause but reads no state and
        // calls nothing sensitive. Tree has only a pause leaf →
        // structural rule rejects.
        function readOnly() external view whenNotPaused returns (uint256) {
            return 42;
        }
    }
    """
    ac = _detect(tmp_path, source)
    semantic_signatures = {pf["function"] for pf in ac["semantic_functions"]}
    # ``pause()`` has caller_authority + state_write.
    assert "pause()" in semantic_signatures
    # ``readOnly()`` has only a pause leaf and no sensitive sink.
    assert "readOnly()" not in semantic_signatures


def test_role_definitions_from_predicate_role_keys(tmp_path):
    """``role_definitions`` comes from role keys used in predicate trees — and
    only from the in-contract ``mapping_membership`` shape.

    The cross-contract ``registry.hasRole(ROLE, msg.sender)`` gate below names two
    real roles and mints NEITHER. ``callee_signature`` is read off
    ``ir.function.full_name`` (``predicates.py:2338``), the interface the CALLER
    declared, so it is not a proven property of the deployed callee: a slot lens
    or a merkle-tree contract declared under the name ``hasRole(bytes32,address)``
    lowers to a byte-identical descriptor, and those shapes minted ERC-7201
    pointers as roles (see ``tests/test_role_definition_leaf_admission.py``).

    The absence is a **coverage caveat**, not a finding: these roles are
    ``not_determined``, never "this contract has no roles"
    (``SCORING_INVARIANTS.md`` B4c).
    """
    source = """
    pragma solidity ^0.8.19;
    interface IRoleRegistry {
        function hasRole(bytes32 role, address account) external view returns (bool);
    }
    contract C {
        IRoleRegistry public roleRegistry;
        bytes32 public constant ADMIN_ROLE = keccak256("ADMIN");
        bytes32 public constant MINTER_ROLE = keccak256("MINTER");
        uint256 public value;
        constructor(IRoleRegistry rr) { roleRegistry = rr; }
        function mint() external {
            require(roleRegistry.hasRole(MINTER_ROLE, msg.sender), "no");
            value = 1;
        }
        function admin() external {
            require(roleRegistry.hasRole(ADMIN_ROLE, msg.sender), "no");
            value = 2;
        }
    }
    """
    ac = _detect(tmp_path, source)
    role_names = {r["role"] for r in ac["role_definitions"]}
    assert role_names == set()


def test_delegated_authority_leaf_admits_function(tmp_path):
    """Cross-contract ``hasRole`` gate → delegated_authority leaf →
    included."""
    source = """
    pragma solidity ^0.8.19;
    interface IRoleRegistry {
        function hasRole(bytes32 role, address account) external view returns (bool);
    }
    contract C {
        IRoleRegistry public roleRegistry;
        bytes32 public constant PAUSER_ROLE = keccak256("PAUSER");
        bool public paused;
        constructor(address rr) { roleRegistry = IRoleRegistry(rr); }
        function pauseContract() external {
            require(roleRegistry.hasRole(PAUSER_ROLE, msg.sender), "no");
            paused = true;
        }
    }
    """
    ac = _detect(tmp_path, source)
    semantic_signatures = {pf["function"] for pf in ac["semantic_functions"]}
    assert "pauseContract()" in semantic_signatures
