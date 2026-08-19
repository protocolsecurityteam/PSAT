"""Shared harness for the Anvil-backed monitoring tests: port allocation, node
spawn, ``cast``/``forge`` shells, and the Solidity stand-ins the deploy helpers
compile."""

from __future__ import annotations

import socket
import subprocess
import time
from pathlib import Path

import pytest

# Anvil default account 0.
PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ACCOUNT0 = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"


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
    """Spawn anvil on a free port and return ``(process, port)`` once it answers.

    ``_free_port`` reports a port it cannot reserve — the bind is released before
    anvil execs, so another process may claim it in between. This does not
    prevent that race, it recovers from it: anvil exits when its own bind fails,
    so a child that is dead once the port answers means someone else owns the
    port, and the whole spawn is retried elsewhere. The invariant held is that a
    returned process is alive and its port is accepting connections.
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
    """Start an anvil node and yield ``(rpc_url, tmp_path)``."""
    proc, port = _start_anvil()
    try:
        foundry_toml = tmp_path / "foundry.toml"
        foundry_toml.write_text("[profile.default]\nsrc = '.'\nout = 'out'\n")
        yield f"http://127.0.0.1:{port}", tmp_path
    finally:
        _terminate(proc)


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


# ---------------------------------------------------------------------------
# Solidity test contracts
# ---------------------------------------------------------------------------

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
