"""A reach condition is published with the exact operations that decide it, so resolution can read it at a block; a
condition those operations can't state carries none and stays unread. State or calldata it reads nominates no
controller, while a reach condition on the caller still names who passes
(``fixtures/contracts/predicates/reach_reads.sol``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from eth_utils.crypto import keccak

pytest.importorskip("slither")

pytestmark = pytest.mark.compile

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "contracts" / "predicates" / "reach_reads.sol"


@pytest.fixture(scope="module")
def artifacts(tmp_path_factory) -> tuple[dict[str, Any], dict[str, Any]]:
    from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts
    from tests.support.foundry_project import write_foundry_project

    project = write_foundry_project(tmp_path_factory.mktemp("reach_reads"), "ReachReads", FIXTURE.read_text())
    analysis, trees, _effects = collect_contract_analysis_with_artifacts(project)
    assert isinstance(trees, dict)
    return dict(analysis), trees


def _reach_leaves(tree: Any) -> list[dict[str, Any]]:
    from services.static.contract_analysis_pipeline.predicate_types import is_reach_condition

    if tree.get("op") == "LEAF":
        return [tree["leaf"]] if is_reach_condition(tree["leaf"]) else []
    return [leaf for child in tree.get("children") or [] for leaf in _reach_leaves(child)]


def _reads(artifacts, signature: str) -> list[Any]:
    return [leaf.get("reach_read") for leaf in _reach_leaves(artifacts[1]["trees"][signature])]


def _selector(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


def test_an_open_role_is_read_through_the_public_view_with_its_role_folded(artifacts):
    [read] = _reads(artifacts, "execute(uint256)")
    role = str(int(keccak(text="EXECUTOR_ROLE").hex(), 16))
    assert read == {
        "expression": {
            "op": "not",
            "type": "bool",
            "value": {
                "op": "call",
                "type": "bool",
                "selector": _selector("hasRole(bytes32,address)"),
                "signature": "hasRole(bytes32,address)",
                "arguments": [
                    {"op": "const", "type": "bytes32", "value": role},
                    {
                        "op": "convert",
                        "type": "address",
                        "value": {"op": "const", "type": "uint256", "value": "0", "literal": True},
                    },
                ],
            },
        },
        # The gate isn't reached where its branch condition fails.
        "holds": False,
    }


@pytest.mark.parametrize("signature", ["executeTransaction(uint256)", "unlessLocked(uint256)"])
def test_a_state_disjunct_beside_a_caller_check_is_a_reach_condition_with_its_read(artifacts, signature):
    [read] = _reads(artifacts, signature)
    assert read is not None and read["holds"] is True
    assert read["expression"]["op"] == "not"
    assert read["expression"]["value"]["op"] == "storage"
    assert read["expression"]["value"]["type"] == "bool"


def test_disjuncts_that_both_read_state_stay_a_side_condition(artifacts):
    assert _reach_leaves(artifacts[1]["trees"]["eitherFlag(uint256)"]) == []


def test_a_reassigned_parameter_is_not_read_as_calldata(artifacts):
    assert _reads(artifacts, "reassigned(uint256,bool)") == [None]


def test_a_branch_on_storage_written_before_it_is_an_unread_reach_condition(artifacts):
    [leaf] = _reach_leaves(artifacts[1]["trees"]["writtenFirst(uint256)"])
    assert leaf["unsupported_reason"] == "branch_reads_state_written_before"
    assert "reach_read" not in leaf


def test_calldata_is_read_as_the_parameter_the_caller_sends(artifacts):
    [read] = _reads(artifacts, "rateFor(address)")
    assert read is not None
    operands = [read["expression"]["left"], read["expression"]["right"]]
    assert {"op": "param", "type": "address", "index": 0, "name": "quote"} in operands

