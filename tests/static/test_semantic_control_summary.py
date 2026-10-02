"""A function is in ``semantic_functions`` iff it has a caller/delegated authority leaf or a sensitive sink;
tree-keys-as-included over-included side-condition trees.
"""

from __future__ import annotations

import pytest

slither = pytest.importorskip("slither")

from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
)
from services.static.contract_analysis_pipeline.summaries import (  # noqa: E402
    _build_semantic_control_summary,
)
from tests.support.slither_compile import _compile_contract  # noqa: E402


def _detect(tmp_path, source, contract_name="C"):
    contract = _compile_contract(tmp_path, source, contract_name)
    predicate_trees = build_predicate_artifacts(contract)
    effects = build_effects(contract)
    return _build_semantic_control_summary(contract, tmp_path, predicate_trees, effects)


def test_pause_only_tree_does_not_admit_function(tmp_path):
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
    assert "pause()" in semantic_signatures
    assert "readOnly()" not in semantic_signatures
