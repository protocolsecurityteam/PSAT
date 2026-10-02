"""A bare aggregate has no single storable address, and a ``constant`` consulted only by business logic is a
sentinel; neither is a controller.
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
from services.static.contract_analysis_pipeline.tracking import (  # noqa: E402
    build_controller_tracking,
)


def _compile(tmp_path: Path, source: str, contract_name: str):
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    sl = Slither(str(f))
    return next(c for c in sl.contracts if c.name == contract_name)


def _build(tmp_path: Path, source: str, contract_name: str):
    contract = _compile(tmp_path, source, contract_name)
    predicate_trees = build_predicate_artifacts(contract)
    effects = build_effects(contract)
    semantic_control = _build_semantic_control_summary(contract, tmp_path, predicate_trees, effects)
    return build_controller_tracking(contract, tmp_path, predicate_trees, effects, semantic_control)


def test_business_only_constant_sentinel_dropped(tmp_path):
    source = """
    pragma solidity ^0.8.19;
    interface IStrategy {}
    contract C {
        IStrategy public constant beaconChainETHStrategy =
            IStrategy(0xbeaC0eeEeeeeEEeEeEEEEeeEEeEeeeEeeEEBEaC0);
        mapping(address => uint256) public shares;
        function addShares(address staker, IStrategy strategy, uint256 amount) external {
            require(strategy != beaconChainETHStrategy, "no beacon");
            shares[staker] += amount;
        }
    }
    """
    by_id = {t["controller_id"]: t for t in _build(tmp_path, source, "C")}
    assert "state_variable:beaconChainETHStrategy" not in by_id, list(by_id.keys())
