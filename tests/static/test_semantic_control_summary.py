"""``_build_semantic_control_summary`` semantic signal.

Pins the structural inclusion rule: a function is in ``semantic_functions`` iff its predicate
tree has a ``caller_authority``/``delegated_authority`` leaf, OR its effects record carries a
sensitive sink (state_write, external_call, delegatecall, contract_creation, selfdestruct).
Tree-keys-as-included used to over-include pause / reentrancy / time / business trees.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

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
    """Pause-only with no sensitive sink is a side-condition, not caller authorization."""
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


def test_delegated_authority_leaf_admits_function(tmp_path):
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
