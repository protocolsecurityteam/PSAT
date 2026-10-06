"""A contract-typed slot getter must retain its authority target without name heuristics."""

from types import SimpleNamespace
from typing import Any

import pytest

from services.resolution.capabilities import CapabilityExpr
from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree
from services.static.contract_analysis_pipeline.predicates import build_predicate_tree
from services.static.contract_analysis_pipeline.storage_accessors import constant_address_slot
from tests.support.slither_compile import _compile


def leaves(tree: Any) -> list[dict]:
    return (
        [tree["leaf"]]
        if tree.get("op") == "LEAF"
        else [leaf for child in tree.get("children", []) for leaf in leaves(child)]
    )


def compile_gate(tmp_path, getter=None):
    getter = getter or "address a; bytes32 p = POSITION; assembly { a := sload(p) } return IRegistry(a);"
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IRegistry { function permits(address actor) external view returns (bool); }
        contract Gate {
            bytes32 constant POSITION = bytes32(uint256(123));
            bool public alternate;
            function registry() public view returns (IRegistry) { GETTER }
            function execute() external view { require(registry().permits(msg.sender)); }
        }
    """.replace("GETTER", getter),
    )
    return next(c for c in sl.contracts if c.name == "Gate")


def test_contract_typed_getter_resolves_authority_at_runtime_slot(tmp_path, monkeypatch):
    contract = compile_gate(tmp_path)
    getter = next(f for f in contract.functions if f.name == "registry")
    assert constant_address_slot(getter) == "0x" + f"{123:064x}"
    tree = build_predicate_tree(next(f for f in contract.functions if f.name == "execute"))
    gate = next(leaf for leaf in leaves(tree) if leaf.get("set_descriptor"))
    assert gate["authority_role"] == "delegated_authority"
    target = "0x" + "12" * 20
    runtime = "0x" + "34" * 20
    holder = "0x" + "56" * 20
    reads = []

    def rpc(url, method, params, **kwargs):
        reads.append((method, params))
        return "0x" + "00" * 12 + target[2:]

    monkeypatch.setattr("services.clients.rpc.rpc_request", rpc)

    class Adapter:
        _outer_ctx = SimpleNamespace(rpc_url="http://rpc.example", contract_address=runtime, chain_id=1, block=100)

        def enumerate(self, descriptor, contract_address):
            assert descriptor["authority_contract"]["address"] == target
            return CapabilityExpr.finite_set([holder], quality="exact", confidence="enumerable")

    cap = evaluate_tree(tree, EvaluationContext(contract_address=runtime, adapter=Adapter(), block=100))
    assert cap.members == [holder]
    assert reads == [("eth_getStorageAt", [runtime, "0x" + f"{123:064x}", "0x64"])]


@pytest.mark.parametrize(
    "getter",
    [
        "if (alternate) return IRegistry(msg.sender); address a; bytes32 p=POSITION; "
        "assembly { a := sload(p) } return IRegistry(a);",
        "address a; bytes32 p=POSITION; assembly { a := shr(96, sload(p)) } return IRegistry(a);",
        "uint word; bytes32 p=POSITION; assembly { word := sload(p) } return IRegistry(address(uint160(uint8(word))));",
        "bytes32 word; bytes32 p=POSITION; assembly { word := sload(p) } return IRegistry(address(bytes20(word)));",
        "uint raw = 1234; uint8 p = uint8(raw); address a; assembly { a := sload(p) } return IRegistry(a);",
    ],
)
def test_ambiguous_or_packed_getter_does_not_claim_a_plain_address_slot(tmp_path, getter):
    contract = compile_gate(tmp_path, getter)
    assert constant_address_slot(next(f for f in contract.functions if f.name == "registry")) is None


def test_unreadable_authority_slot_stays_unknown(tmp_path, monkeypatch):
    contract = compile_gate(tmp_path)
    tree = build_predicate_tree(next(f for f in contract.functions if f.name == "execute"))
    monkeypatch.setattr("services.clients.rpc.rpc_request", lambda *a, **k: "0x")

    class Adapter:
        _outer_ctx = SimpleNamespace(
            rpc_url="http://rpc.example", contract_address="0x" + "11" * 20, chain_id=1, block=100
        )

        def enumerate(self, descriptor, contract_address):
            raise AssertionError("Unknown target must not be enumerated as the current contract")

    cap = evaluate_tree(tree, EvaluationContext(adapter=Adapter()))
    assert cap.kind == "external_check_only"
    assert cap.check is not None
    assert cap.check.target_address is None
