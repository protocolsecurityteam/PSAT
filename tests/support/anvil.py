from __future__ import annotations

import socket
import subprocess
import time
from pathlib import Path

import pytest
import requests
from eth_abi.abi import decode, encode
from eth_utils.crypto import keccak

PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ACCOUNT0 = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"


def calldata(signature, values=()):
    types = signature.split("(", 1)[1][:-1].split(",") if not signature.endswith("()") else []
    return "0x" + (keccak(text=signature)[:4] + encode(types, list(values))).hex()


def rpc(url, method, params):
    response = requests.post(url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=15)
    response.raise_for_status()
    body = response.json()
    if "error" in body:
        raise RuntimeError(body["error"])
    return body["result"]


def send(url, sender, data, to=None, *, value=0):
    tx = {"from": sender, "data": data, "gas": hex(8_000_000)}
    if value:
        tx["value"] = hex(value)
    if to is not None:
        tx["to"] = to
    tx_hash = rpc(url, "eth_sendTransaction", [tx])
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        receipt = rpc(url, "eth_getTransactionReceipt", [tx_hash])
        if receipt is not None:
            return receipt
        time.sleep(0.02)
    raise AssertionError("Anvil did not mine the transaction")


def call(url, address, signature, values=(), returns=(), sender=None, block="latest"):
    tx = {"to": address, "data": calldata(signature, values)}
    if sender is not None:
        tx["from"] = sender
    result = rpc(url, "eth_call", [tx, block])
    return decode(list(returns), bytes.fromhex(result[2:])) if returns else result


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _terminate(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _start_anvil(attempts: int = 5, timeout: float = 15.0) -> tuple[subprocess.Popen, int]:
    """The port is released before anvil binds, so a dead child once the port answers means someone else owns it;
    retry elsewhere.
    """
    for _ in range(attempts):
        port = _free_port()
        proc = subprocess.Popen(
            ["anvil", "--port", str(port), "--silent"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if _wait_for_port(port, timeout=timeout) and proc.poll() is None:
            return proc, port
        _terminate(proc)
    raise RuntimeError(f"anvil did not start in time on any of {attempts} ports")


@pytest.fixture()
def anvil_env(tmp_path):
    proc, port = _start_anvil()
    try:
        foundry_toml = tmp_path / "foundry.toml"
        foundry_toml.write_text("[profile.default]\nsrc = '.'\nout = 'out'\n")
        yield f"http://127.0.0.1:{port}", tmp_path
    finally:
        _terminate(proc)


def materialization_keys(session) -> set[tuple[str, str]]:
    from sqlalchemy import select

    from db.models import ContractMaterialization

    return set(session.execute(select(ContractMaterialization.chain, ContractMaterialization.address)).all())


def purge_materializations(session, keep: set[tuple[str, str]]) -> None:
    """Every module deploys from the same account into a fresh node, so contract #1 lands on the same address and a
    leftover row is a unique violation; the per-module cleanups don't reach this table.
    """
    from sqlalchemy import select

    from db.models import ContractMaterialization

    session.rollback()
    for row in session.execute(select(ContractMaterialization)).scalars().all():
        if (row.chain, row.address) not in keep:
            session.delete(row)
    session.commit()


def _cast(args: list[str], rpc_url: str) -> str:
    result = subprocess.run(
        ["cast"] + args + ["--rpc-url", rpc_url],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"cast failed: {result.stderr}")
    return result.stdout.strip()


def _cast_send(to: str, sig: str, args: list[str], rpc_url: str, private_key: str = PRIVATE_KEY) -> str:
    cmd = ["cast", "send", to, sig] + args + ["--rpc-url", rpc_url, "--private-key", private_key]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"cast send failed: {result.stderr}")
    return result.stdout.strip()


def _compile_and_deploy(
    source: str,
    contract_name: str,
    constructor_args: list[str],
    rpc_url: str,
    private_key: str,
    tmp_path: Path,
) -> str:
    src_file = tmp_path / f"{contract_name}.sol"
    src_file.write_text(source)

    cmd = [
        "forge",
        "create",
        f"{src_file}:{contract_name}",
        "--rpc-url",
        rpc_url,
        "--private-key",
        private_key,
        "--broadcast",
        "--no-cache",
    ]
    if constructor_args:
        cmd += ["--constructor-args"] + constructor_args

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, cwd=str(tmp_path))
    if result.returncode != 0:
        raise RuntimeError(f"forge create failed for {contract_name}: {result.stderr}\n{result.stdout}")

    for line in result.stdout.split("\n"):
        if "Deployed to:" in line or "deployed to:" in line.lower():
            return line.split(":")[-1].strip().lower()

    raise RuntimeError(f"Could not parse address from forge create output:\n{result.stdout}")


OWNABLE_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TestOwnable {
    address public owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "not owner");
        address old = owner;
        owner = newOwner;
        emit OwnershipTransferred(old, newOwner);
    }
}
"""

PROXY_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TestProxy {
    bytes32 internal constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    event Upgraded(address indexed implementation);

    constructor(address impl) {
        _setImplementation(impl);
    }

    function upgradeTo(address newImpl) external {
        _setImplementation(newImpl);
    }

    function _setImplementation(address impl) internal {
        assembly { sstore(_IMPLEMENTATION_SLOT, impl) }
        emit Upgraded(impl);
    }

    fallback() external payable {
        address impl;
        assembly { impl := sload(_IMPLEMENTATION_SLOT) }
        (bool ok, bytes memory data) = impl.delegatecall(msg.data);
        require(ok);
        assembly { return(add(data, 0x20), mload(data)) }
    }
    receive() external payable {}
}
"""

IMPL_V1_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract ImplV1 { uint256 public version = 1; }
"""

IMPL_V2_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract ImplV2 { uint256 public version = 2; }
"""

PAUSABLE_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TestPausable {
    bool public paused;
    address public owner;
    event Paused(address account);
    event Unpaused(address account);

    constructor() {
        owner = msg.sender;
    }

    function pause() external {
        require(msg.sender == owner, "not owner");
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external {
        require(msg.sender == owner, "not owner");
        paused = false;
        emit Unpaused(msg.sender);
    }
}
"""

SAFE_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TestSafe {
    address[] internal _owners;
    uint256 internal _threshold;
    event AddedOwner(address owner);
    event RemovedOwner(address owner);
    event ChangedThreshold(uint256 threshold);

    constructor() {
        _owners.push(msg.sender);
        _threshold = 1;
    }

    // Match real Gnosis Safe selectors
    function getOwners() external view returns (address[] memory) { return _owners; }
    function getThreshold() external view returns (uint256) { return _threshold; }

    function addOwner(address _owner) external {
        _owners.push(_owner);
        emit AddedOwner(_owner);
    }

    function removeOwner(address _owner) external {
        for (uint i = 0; i < _owners.length; i++) {
            if (_owners[i] == _owner) {
                _owners[i] = _owners[_owners.length - 1];
                _owners.pop();
                break;
            }
        }
        emit RemovedOwner(_owner);
    }

    function changeThreshold(uint256 t) external {
        _threshold = t;
        emit ChangedThreshold(t);
    }
}
"""

SOLMATE_OWNED_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TestSolmateOwned {
    address public owner;
    event OwnerUpdated(address indexed user, address indexed newOwner);

    constructor() {
        owner = msg.sender;
        emit OwnerUpdated(address(0), msg.sender);
    }

    function setOwner(address newOwner) external {
        require(msg.sender == owner, "UNAUTHORIZED");
        owner = newOwner;
        emit OwnerUpdated(msg.sender, newOwner);
    }
}
"""
