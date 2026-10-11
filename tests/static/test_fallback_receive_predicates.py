"""Having no selector was treated as having no caller. No tree was built, so PriorityWithdrawalQueue and
WithdrawRequestNFT's gated ``receive()`` published ``authority_public = True``. And the rendered ``fallback()`` /
``receive()`` were hashed into fake selectors on 7 rows; ``db/effect_cache.py`` fixes ``""`` as the sentinel.
"""

from __future__ import annotations

import textwrap

import pytest

pytest.importorskip("slither")
from slither import Slither

from services.policy.effective_permissions import _abi_signature_and_selector
from services.resolution.predicate_evaluator import evaluate_tree
from services.static.contract_analysis_pipeline.effects import build_effects
from services.static.contract_analysis_pipeline.predicate_artifacts import (
    build_predicate_artifacts,
    has_no_selector,
    is_canonical_abi_signature,
)

SOURCE = """
    pragma solidity ^0.8.19;
    contract C {
        address public owner;
        uint256 public total;
        // Gated fallback: a tree MUST be built and MUST carry the owner gate.
        fallback() external payable {
            require(msg.sender == owner, "not owner");
            total += msg.value;
        }
        // Open receive: a tree is attempted and legitimately finds nothing.
        receive() external payable {
            total += msg.value;
        }
        // Control: an ordinary selector-bearing entry point.
        function contribute() external payable {
            total += msg.value;
        }
    }
"""


@pytest.fixture(scope="module")
def contract(tmp_path_factory):
    path = tmp_path_factory.mktemp("classr") / "C.sol"
    path.write_text(textwrap.dedent(SOURCE).strip() + "\n")
    slither = Slither(str(path))
    return next(c for c in slither.contracts if c.name == "C")


def test_gated_fallback_tree_carries_the_caller_authority_leaf(contract):
    tree = ((build_predicate_artifacts(contract) or {}).get("trees") or {})["fallback()"]
    leaves: list[dict] = []

    def walk(node):
        if not isinstance(node, dict):
            return
        if node.get("op") == "LEAF":
            leaves.append(node.get("leaf") or {})
            return
        for child in node.get("children") or []:
            walk(child)

    walk(tree)
    roles = {leaf.get("authority_role") for leaf in leaves}
    assert "caller_authority" in roles, f"the fallback's owner gate was not lifted: {roles}"
    assert evaluate_tree(tree).kind == "finite_set"


@pytest.mark.parametrize("signature", ["fallback()", "receive()"])
def test_selectorless_signatures_are_not_canonical(signature):
    assert has_no_selector(signature) is True
    assert is_canonical_abi_signature(signature) is False


@pytest.mark.parametrize("signature", ["fallback()", "receive()"])
def test_fallback_state_write_publishes_no_writer_selector(contract, signature):
    functions = build_effects(contract)["functions"]
    assert functions[signature]["writer_selectors"] == []
    assert functions[signature]["selector"] == ""
    assert functions[signature]["state_writes"], "the write itself is still recorded"


def test_no_named_function_can_receive_the_selectorless_sentinel():
    """``_selector_key`` folds ``None`` onto ``""``, so a named function with it would inherit the fallback's claims;
    recognition must be signature-exact.
    """
    named = [
        "alertMetadataUpdate(uint256)",
        "alertBatchMetadataUpdate(uint256,uint256)",
        "fallbackHandler()",
        "receiveELRewards()",
        "receiveWithAuthorization(address,address,uint256,uint256,uint256,bytes32,bytes)",
        "setAuthority(IFoo.Bar)",
    ]
    for signature in named:
        selector = _abi_signature_and_selector(signature, {})[1]
        assert selector != "", f"{signature} was handed the proven-no-selector sentinel"
        assert selector is None or selector.startswith("0x")

    assert _abi_signature_and_selector("alertMetadataUpdate(uint256)", {})[1] == "0x6800a4f4"
    assert _abi_signature_and_selector("fallbackHandler()", {})[1] == "0xeed2f252"
    assert _abi_signature_and_selector("setAuthority(IFoo.Bar)", {})[1] is None
    assert _abi_signature_and_selector("fallback()", {})[1] == ""
    assert _abi_signature_and_selector("receive()", {})[1] == ""
