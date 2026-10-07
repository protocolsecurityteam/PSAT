"""Caller authorization must survive nested boolean helpers and early false returns."""

import json
import subprocess
import time
from typing import Any

import pytest
import requests
from eth_abi.abi import encode
from eth_utils.crypto import keccak

from services.resolution.predicate_evaluator import evaluate_tree
from services.static.contract_analysis_pipeline.predicates import build_predicate_tree
from tests.support.anvil import anvil_env  # noqa: F401
from tests.support.slither_compile import _compile


def leaves(tree: Any) -> list[dict[str, Any]]:
    if not tree:
        return []
    if tree.get("op") == "LEAF":
        return [tree["leaf"]]
    return [leaf for child in tree.get("children", []) for leaf in leaves(child)]


@pytest.mark.parametrize("wrapper", [False, True])
def test_nested_helper_keeps_caller_bound_external_authorization(tmp_path, wrapper):
    source = """
        pragma solidity ^0.8.19;
        interface Registry {
            function permits(address account, address target, bytes32 action) external view returns (bool);
        }
        contract Dispatcher {
            Registry public registry;
            bool public initialized;
            uint256 public calls;
            function execute(bytes calldata payload) external {
                require(WRAPPER(msg.sender, keccak256(payload)), "denied");
                calls++;
            }
            function accepts(address account, bytes32 action) internal view returns (bool) {
                return admitted(account, action);
            }
            function admitted(address account, bytes32 action) internal view returns (bool) {
                if (!initialized) return false;
                return registry.permits(account, address(this), action);
            }
        }
    """.replace("WRAPPER", "accepts" if wrapper else "admitted")
    sl = _compile(tmp_path, source)
    contract = next(c for c in sl.contracts if c.name == "Dispatcher")
    fn = next(f for f in contract.functions if f.name == "execute")
    tree = build_predicate_tree(fn)
    result = leaves(tree)
    assert evaluate_tree(tree).kind != "conditional_universal"
    gates = [leaf for leaf in result if leaf.get("authority_role") == "delegated_authority"]
    assert gates, result
    assert any(operand.get("source") == "msg_sender" for leaf in gates for operand in leaf.get("operands", [])), gates


def test_business_only_twin_does_not_invent_authority(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract Dispatcher {
            bool public initialized;
            uint256 public calls;
            function execute(bytes calldata payload) external {
                require(accepts(msg.sender, payload), "disabled");
                calls++;
            }
            function accepts(address, bytes calldata) internal view returns (bool) {
                return admitted();
            }
            function admitted() internal view returns (bool) {
                if (!initialized) return false;
                return true;
            }
        }
    """,
    )
    fn = next(f for f in sl.contracts[0].functions if f.name == "execute")
    assert evaluate_tree(build_predicate_tree(fn)).kind == "conditional_universal"
    assert not any(
        leaf.get("authority_role") in {"caller_authority", "delegated_authority"}
        for leaf in leaves(build_predicate_tree(fn))
    )


@pytest.mark.anvil
def test_nested_authorization_matches_execution_and_authentication_free_twin(anvil_env):
    rpc_url, tmp_path = anvil_env
    source = """
        pragma solidity ^0.8.19;
        contract Registry {
            address immutable owner = msg.sender;
            function permits(address actor) external view returns (bool) { return actor == owner; }
        }
        contract Guarded {
            Registry public registry;
            bool public initialized = true;
            uint256 public calls;
            constructor(Registry r) { registry = r; }
            function execute() external { require(accepts(msg.sender)); calls++; }
            function accepts(address actor) internal view returns (bool) { return admitted(actor); }
            function admitted(address actor) internal view virtual returns (bool) {
                if (!initialized) return false;
                return registry.permits(actor);
            }
        }
        contract OpenTwin is Guarded {
            constructor(Registry r) Guarded(r) {}
            function admitted(address) internal view override returns (bool) {
                if (!initialized) return false;
                return true;
            }
        }
    """
    sl = _compile(tmp_path, source)
    for name, expected_public in [("Guarded", False), ("OpenTwin", True)]:
        c = next(c for c in sl.contracts if c.name == name)
        f = next(f for f in c.functions if f.name == "execute")
        assert (evaluate_tree(build_predicate_tree(f)).kind == "conditional_universal") is expected_public
    compiled = subprocess.run(
        ["solc", "--combined-json", "bin", str(tmp_path / "C.sol")],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    binaries = {key.rsplit(":", 1)[1]: value["bin"] for key, value in json.loads(compiled.stdout)["contracts"].items()}

    def rpc(method, params):
        response = requests.post(
            rpc_url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=10
        )
        response.raise_for_status()
        result = response.json()
        assert "error" not in result, result
        return result["result"]

    owner, outsider = rpc("eth_accounts", [])[:2]

    def send(sender, **tx):
        txhash = rpc("eth_sendTransaction", [{"from": sender, "gas": hex(4_000_000), **tx}])
        for _ in range(200):
            receipt = rpc("eth_getTransactionReceipt", [txhash])
            if receipt is not None:
                return receipt
            time.sleep(0.01)
        pytest.fail(f"Local transaction was not mined: {txhash}")

    registry_receipt = send(owner, data="0x" + binaries["Registry"])
    assert registry_receipt["status"] == "0x1"
    registry = registry_receipt["contractAddress"]
    for name, expected_outsider_success in [("Guarded", False), ("OpenTwin", True)]:
        deployment = send(owner, data="0x" + binaries[name] + encode(["address"], [registry]).hex())
        assert deployment["status"] == "0x1"
        address = deployment["contractAddress"]
        data = "0x" + keccak(text="execute()")[:4].hex()
        assert send(owner, to=address, data=data)["status"] == "0x1"
        assert (send(outsider, to=address, data=data)["status"] == "0x1") is expected_outsider_success
