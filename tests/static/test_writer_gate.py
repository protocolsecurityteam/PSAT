"""A 1-key caller-keyed mapping can't be told apart as auth vs personal flag from the read site; the discriminator is
how it's written.
"""

from __future__ import annotations

import pytest

slither = pytest.importorskip("slither")

from services.static.contract_analysis_pipeline.writer_gate import (  # noqa: E402
    apply_writer_gate_pass,
)
from tests.support.predicate_trees import _all_leaves, _build_trees  # noqa: E402
from tests.support.slither_compile import _compile  # noqa: E402

# Rule a: all writers self-keyed stays business.


# Rule b.i: an auth-gated external-keyed writer promotes.


# Rule b.ii: self-administered (Maker wards).


def test_self_administered_wards_promotes(tmp_path):
    """Without ``map[k]==1`` recognition wards looks like a uint read. HIGH confidence: a tight structural match."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => uint256) public wards;
            function rely(address addr) external {
                require(wards[msg.sender] == 1);
                wards[addr] = 1;
            }
            function someAction() external view {
                require(wards[msg.sender] == 1);
            }
        }
    """,
    )
    contract = sl.contracts[0]
    trees = _build_trees(contract)
    apply_writer_gate_pass(contract, trees)
    leaves = _all_leaves(trees["someAction()"])
    assert len(leaves) == 1
    leaf = leaves[0]
    assert leaf["kind"] == "membership"
    assert leaf["set_descriptor"]["truthy_value"] == "1"
    assert leaf["authority_role"] == "caller_authority"
    assert leaf["confidence"] == "high"


# Rule c: an ungated external-keyed writer stays business.


# Inherited OZ Ownable through ``_checkOwner`` (EtherFi LiquidityPool): the builder must bind the operand to ``_owner``.
