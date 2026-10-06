import json
import subprocess
import time
from typing import Any, cast

import pytest
import requests
from eth_utils.crypto import keccak

from services.policy.capability_surface import project_capability_surface
from services.policy.effective_permissions_writer import _column_values_for_capability as column_values_for_capability
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.predicate_evaluator import evaluate_tree
from services.static.contract_analysis_pipeline.predicate_artifacts import build_predicate_artifacts_with_pause_info
from tests.support.anvil import anvil_env  # noqa: F401
from tests.support.slither_compile import _compile


@pytest.mark.parametrize(
    "writer,public",
    [
        ("function add(address who) external { require(msg.sender == owner); links[who] = address(this); }", False),
        ("function add(address who) external { links[who] = address(this); }", True),
        ("function add() external { links[msg.sender] = address(this); }", True),
        ("function remove(address who) external { delete links[who]; }", False),
        (
            "function setup(address who) external { require(!initialized); "
            "initialized=true; links[who]=address(this); }",
            False,
        ),
    ],
)
@pytest.mark.parametrize("zero", ["address(0)", "address(uint160(uint256(0)))"])
def test_address_registry_gate_and_public_registration_twin(tmp_path, writer, public, zero):
    parsed = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => address) private links;
            address owner;
            bool initialized;
            WRITER
            function execute(address target, bytes calldata payload) external {
                require(msg.sender != address(1) && links[msg.sender] != address(0));
                (bool success,) = target.call(payload); require(success);
            }
        }
        """.replace("WRITER", writer).replace("address(0)", zero),
    )
    contract = next(c for c in parsed.contracts if c.name == "C")
    artifact, _ = build_predicate_artifacts_with_pause_info(contract)
    cap = evaluate_tree(artifact["trees"]["execute(address,bytes)"])
    assert project_capability_surface(capability_to_dict(cap)).authority_public is public
    if not public:
        assert column_values_for_capability(capability_to_dict(cap))["authority_openness"] == "not_determined"


@pytest.mark.anvil
def test_registry_authority_matches_transactions_and_authentication_free_twin(anvil_env):
    url, path = anvil_env
    parsed = _compile(
        path,
        """
        pragma solidity ^0.8.19;
        contract RegistryGate {
            mapping(address => address) private entries;
            uint public count;
            constructor() { entries[msg.sender] = address(this); }
            function execute() external virtual {
                require(msg.sender != address(1) && entries[msg.sender] != address(0)); count++;
            }
        }
        contract OpenTwin is RegistryGate {
            function execute() external override { count++; }
        }
    """,
    )
    binaries = json.loads(
        subprocess.run(
            ["solc", "--combined-json", "bin", str(path / "C.sol")],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        ).stdout
    )["contracts"]

    def rpc(method, params):
        r = requests.post(url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=10).json()
        assert "error" not in r, r
        return r["result"]

    owner, outsider = rpc("eth_accounts", [])[:2]

    def send(sender, **tx):
        txhash = rpc("eth_sendTransaction", [{"from": sender, "gas": hex(2000000), **tx}])
        for _ in range(100):
            receipt = rpc("eth_getTransactionReceipt", [txhash])
            if receipt is not None:
                return receipt
            time.sleep(0.01)
        pytest.fail("Local transaction was not mined")

    for name, public in [("RegistryGate", False), ("OpenTwin", True)]:
        contract = next(c for c in parsed.contracts if c.name == name)
        artifact, _ = build_predicate_artifacts_with_pause_info(contract)
        cap = evaluate_tree(artifact["trees"].get("execute()"))
        assert project_capability_surface(capability_to_dict(cap)).authority_public is public
        bytecode = next(v["bin"] for k, v in binaries.items() if k.endswith(":" + name))
        deployed = send(owner, data="0x" + bytecode)
        assert deployed["status"] == "0x1"
        call = {"to": deployed["contractAddress"], "data": "0x" + keccak(text="execute()")[:4].hex()}
        assert send(owner, **call)["status"] == "0x1"
        assert (send(outsider, **call)["status"] == "0x1") is public


@pytest.mark.parametrize("allowed_op,expected_kind", [("ne", "finite_set"), ("eq", "cofinite_blacklist")])
def test_allowed_value_predicate_is_not_negated_twice(allowed_op, expected_kind):
    from services.resolution.capabilities import CapabilityExpr
    from services.resolution.predicate_evaluator import EvaluationContext

    member = "0x" + "71" * 20

    class Adapter:
        def enumerate(self, descriptor, contract_address):
            # Both forms enumerate nonzero entries. The default-zero allow case
            # then complements this set; the registered-member gate does not.
            assert descriptor["value_predicate"]["op"] == "ne"
            return CapabilityExpr.finite_set([member], quality="exact", confidence="enumerable")

    tree = {
        "op": "LEAF",
        "leaf": {
            "kind": "membership",
            "operator": "falsy" if allowed_op == "ne" else "truthy",
            "authority_role": "caller_authority",
            "operands": [{"source": "msg_sender"}],
            "set_descriptor": {
                "kind": "mapping_membership",
                "key_sources": [{"source": "msg_sender"}],
                "value_predicate": {"op": allowed_op, "rhs_values": ["0"], "value_type": "address"},
            },
        },
    }
    cap = evaluate_tree(cast(Any, tree), EvaluationContext(adapter=Adapter()))
    assert cap.kind == expected_kind
    assert (cap.members if allowed_op == "ne" else cap.blacklist) == [member]
