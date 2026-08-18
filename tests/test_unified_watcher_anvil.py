"""Anvil integration tests for the unified protocol monitoring scanner.

Deploys minimal governance contracts on a local Anvil node, registers them
as MonitoredContract rows, performs governance actions, then verifies that
scan_for_events detects the correct events.

Requires:
  - anvil, cast, forge (from Foundry) on PATH

Run with:
    uv run pytest tests/test_unified_watcher_anvil.py -v --timeout=120
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session as SASession

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.models import (
    Base,
    MonitoredContract,
    MonitoredEvent,
    ProxyUpgradeEvent,
    WatchedProxy,
)

# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------

_has_anvil = shutil.which("anvil") is not None
_has_cast = shutil.which("cast") is not None
_has_forge = shutil.which("forge") is not None

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")


def _can_connect() -> bool:
    if not DATABASE_URL:
        return False
    try:
        engine = create_engine(DATABASE_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


pytestmark = [
    pytest.mark.skipif(not _has_anvil, reason="anvil not found on PATH"),
    pytest.mark.skipif(not _has_cast, reason="cast not found on PATH"),
    pytest.mark.skipif(not _has_forge, reason="forge not found on PATH"),
    pytest.mark.skipif(not _can_connect(), reason="PostgreSQL not available"),
]

# Anvil default account 0 private key
PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ACCOUNT0 = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"


@pytest.fixture(autouse=True)
def _disable_scan_confirmation_depth(monkeypatch):
    # These anvil chains are only a handful of blocks long; the production
    # 12-block confirmation clamp would hide every just-emitted event.
    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")


# ---------------------------------------------------------------------------
# Helpers (copied from test_proxy_watcher_anvil.py)
# ---------------------------------------------------------------------------


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


def _cast_send(to: str, sig: str, args: list[str], rpc_url: str, private_key: str) -> str:
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
            addr = line.split(":")[-1].strip()
            return addr.lower()

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

DSAUTH_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// DSAuth shape used by Maker / MKR / DAI / Vat / Vow / Cat — single-arg
// LogSetOwner with the address indexed. Topic0 differs from both OZ
// and Solmate; the only arg is the new owner.
contract TestDSAuth {
    address public owner;
    event LogSetOwner(address indexed owner);

    constructor() {
        owner = msg.sender;
        emit LogSetOwner(msg.sender);
    }

    function setOwner(address newOwner) external {
        require(msg.sender == owner, "not-authorized");
        owner = newOwner;
        emit LogSetOwner(newOwner);
    }
}
"""

COMPOUND_ADMIN_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Compound Comptroller / cToken admin shape: NewAdmin(address) with the
// admin packed in data (non-indexed). Used across every Compound fork
// (Sonne, Moonwell, Venus, Iron Bank, …).
contract TestCompoundAdmin {
    address public admin;
    event NewAdmin(address newAdmin);

    constructor() {
        admin = msg.sender;
        emit NewAdmin(msg.sender);
    }

    function _setAdmin(address newAdmin) external {
        require(msg.sender == admin, "only admin");
        admin = newAdmin;
        emit NewAdmin(newAdmin);
    }
}
"""

OZ_OWNABLE2STEP_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// OZ Ownable2Step shape: OwnershipTransferStarted on transferOwnership
// (intent), OwnershipTransferred on acceptOwnership (commit). The
// Started event is invisible to the pre-fix scanner — its topic0 is
// distinct from the OZ Ownable OwnershipTransferred topic0.
contract TestOwnable2Step {
    address public owner;
    address public pendingOwner;
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "not owner");
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "not pending owner");
        address old = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(old, owner);
    }
}
"""

SOLMATE_AUTH_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TestSolmateAuth {
    address public owner;
    address public authority;
    event OwnerUpdated(address indexed user, address indexed newOwner);
    event AuthorityUpdated(address indexed user, address indexed newAuthority);

    constructor(address _authority) {
        owner = msg.sender;
        authority = _authority;
        emit OwnerUpdated(address(0), msg.sender);
        emit AuthorityUpdated(address(0), _authority);
    }

    function setAuthority(address newAuthority) external {
        require(msg.sender == owner, "UNAUTHORIZED");
        authority = newAuthority;
        emit AuthorityUpdated(msg.sender, newAuthority);
    }
}
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

TIMELOCK_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TestTimelock {
    uint256 public minDelay;
    event CallScheduled(bytes32 indexed id, uint256 indexed index,
        address target, uint256 value, bytes data, bytes32 predecessor, uint256 delay);
    event CallExecuted(bytes32 indexed id, uint256 indexed index,
        address target, uint256 value, bytes data);
    event MinDelayChange(uint256 oldDuration, uint256 newDuration);

    constructor(uint256 _minDelay) {
        minDelay = _minDelay;
    }

    function schedule(bytes32 id, uint256 index, address target,
        uint256 value, bytes calldata data, bytes32 predecessor, uint256 delay) external {
        emit CallScheduled(id, index, target, value, data, predecessor, delay);
    }

    function execute(bytes32 id, uint256 index, address target, uint256 value, bytes calldata data) external {
        emit CallExecuted(id, index, target, value, data);
    }

    function updateDelay(uint256 newDelay) external {
        uint256 oldDelay = minDelay;
        minDelay = newDelay;
        emit MinDelayChange(oldDelay, newDelay);
    }
}
"""

ROLE_CONTROL_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TestRoleControl {
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    function grantRole(bytes32 role, address account) external {
        emit RoleGranted(role, account, msg.sender);
    }

    function revokeRole(bytes32 role, address account) external {
        emit RoleRevoked(role, account, msg.sender);
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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def anvil_env(tmp_path):
    """Start an anvil node and yield (rpc_url, tmp_path)."""
    port = _free_port()
    rpc_url = f"http://127.0.0.1:{port}"

    anvil_proc = subprocess.Popen(
        ["anvil", "--port", str(port), "--silent"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        if not _wait_for_port(port, timeout=15):
            raise RuntimeError("anvil did not start in time")

        # Create foundry.toml for compilation
        foundry_toml = tmp_path / "foundry.toml"
        foundry_toml.write_text("[profile.default]\nsrc = '.'\nout = 'out'\n")

        yield rpc_url, tmp_path
    finally:
        anvil_proc.terminate()
        try:
            anvil_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            anvil_proc.kill()
            anvil_proc.wait()


@pytest.fixture()
def test_db():
    """PostgreSQL database session with monitoring tables."""
    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine)

    session = SASession(engine, expire_on_commit=False)
    try:
        yield session
    finally:
        session.rollback()
        from db.models import Protocol, ProtocolSubscription

        for model in [
            MonitoredEvent,
            MonitoredContract,
            ProxyUpgradeEvent,
            WatchedProxy,
            ProtocolSubscription,
            Protocol,
        ]:
            try:
                session.query(model).delete()
            except Exception:
                session.rollback()
        session.commit()
        session.close()
        engine.dispose()


def _synthetic_tracking_plan_for(contract_type: str) -> dict | None:
    """Mint a minimal ``ControlTrackingPlan``-shaped dict for tests
    whose anvil-deployed contracts never went through the static
    analyzer.

    Mirrors what the analyzer would emit for the canonical Ownable /
    Pausable shapes the test fixtures use (OWNABLE_SOURCE,
    PAUSABLE_SOURCE). Vendored entries (proxy slot, Safe getThreshold,
    Timelock getMinDelay) come from ``build_polling_plan`` directly via
    contract_type, so this only fills the analyzer-driven gap.
    """
    controllers: list[dict] = []
    if contract_type in ("regular", "pausable", "role_control", "proxy"):
        controllers.append(
            {
                "controller_id": "state_variable:owner",
                "read_spec": {
                    "strategy": "getter_call",
                    "target": "owner",
                    "kind": "state_variable",
                    "state_variable_name": "owner",
                    "type": "address",
                    "type_kind": "address",
                },
            }
        )
    if contract_type == "pausable":
        controllers.append(
            {
                "controller_id": "state_variable:paused",
                "read_spec": {
                    "strategy": "getter_call",
                    "target": "paused",
                    "kind": "state_variable",
                    "state_variable_name": "paused",
                    "type": "bool",
                    "type_kind": "primitive",
                },
            }
        )
    if not controllers:
        return None
    return {"tracked_controllers": controllers}


def _register_contract(
    session: SASession,
    address: str,
    contract_type: str,
    last_scanned_block: int,
    monitoring_config: dict | None = None,
    watched_proxy_id: uuid.UUID | None = None,
    proxy_type: str | None = None,
) -> MonitoredContract:
    """Register a MonitoredContract in the test DB.

    Builds a synthetic polling plan from ``contract_type`` (and
    ``proxy_type`` when given) using ``build_polling_plan`` so the
    runtime poll path sees the same shape it would after a real
    enrollment. When *monitoring_config* is provided, the polling plan
    is merged in unless the caller already supplied one.
    """
    from services.monitoring.polling_plan import build_polling_plan

    # Build the polling plan first so it can ride along with whatever
    # monitoring_config the caller hands us (or the default below).
    # PROXY_SOURCE in this module writes to the EIP-1967 slot via
    # assembly, so default proxy contracts to that vendored entry.
    plan_proxy_type = proxy_type or ("eip1967" if contract_type == "proxy" else None)
    polling_plan = build_polling_plan(
        # Deliberately unnarrowed: tests register out-of-vocab types
        # ("role_control") to exercise the watcher on the ungated column.
        contract_type=contract_type,  # pyright: ignore[reportArgumentType]
        proxy_type=plan_proxy_type,
        tracking_plan=_synthetic_tracking_plan_for(contract_type),
        tracked_topics=None,
    )

    if monitoring_config is None:
        monitoring_config = {
            "watch_upgrades": contract_type == "proxy",
            "watch_ownership": True,
            "watch_pause": contract_type == "pausable",
            "watch_roles": contract_type == "role_control",
            "watch_safe_signers": contract_type == "safe",
            "watch_timelock": contract_type == "timelock",
        }
    monitoring_config = dict(monitoring_config)
    monitoring_config.setdefault("polling_plan", polling_plan)

    mc = MonitoredContract(
        id=uuid.uuid4(),
        address=address.lower(),
        chain="ethereum",
        contract_type=contract_type,
        monitoring_config=monitoring_config,
        last_known_state={},
        last_scanned_block=last_scanned_block,
        needs_polling=bool(monitoring_config.get("polling_plan")),
        is_active=True,
        enrollment_source="manual",
        watched_proxy_id=watched_proxy_id,
    )
    session.add(mc)
    session.commit()
    return mc


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_ownership_transfer_detected(anvil_env, test_db):
    """Deploy Ownable, register, transfer ownership, scan, assert event."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    _register_contract(test_db, addr, "regular", current_block)

    # Transfer ownership to a new address
    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)

    assert len(events) == 1
    evt = events[0]
    assert evt.event_type == "ownership_transferred"
    assert evt.data is not None
    assert evt.data.get("new_owner", "").lower() == new_owner.lower()


def test_solmate_owner_updated_detected(anvil_env, test_db):
    """Deploy Solmate-style Owned, register with a tracked_topics entry for
    OwnerUpdated, transfer ownership, scan, assert the scanner picks up the
    Solmate event under the canonical ``ownership_transferred`` event_type.

    Guards Bug 3: without the per-contract topic dispatch, OwnerUpdated's
    topic0 isn't in the global eth_getLogs filter and the event is dropped
    at the network layer before any decoder runs.
    """
    from eth_utils.crypto import keccak

    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(SOLMATE_OWNED_SOURCE, "TestSolmateOwned", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    owner_updated_topic0 = "0x" + keccak(text="OwnerUpdated(address,address)").hex()
    monitoring_config = {
        "watch_ownership": True,
        "tracked_topics": [
            {
                "topic0": owner_updated_topic0,
                "signature": "OwnerUpdated(address,address)",
                "event_type": "ownership_transferred",
                "controller_id": "state_variable:owner",
                "inputs": [
                    {"name": "user", "type": "address", "indexed": True},
                    {"name": "newOwner", "type": "address", "indexed": True},
                ],
            }
        ],
    }
    _register_contract(test_db, addr, "regular", current_block, monitoring_config=monitoring_config)

    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "setOwner(address)", [new_owner], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)

    assert len(events) == 1
    evt = events[0]
    assert evt.event_type == "ownership_transferred"
    assert evt.data is not None
    assert evt.data.get("new_owner", "").lower() == new_owner.lower()


def test_solmate_authority_updated_detected(anvil_env, test_db):
    """Deploy Solmate-style Auth, register with a tracked_topics entry for
    AuthorityUpdated, swap the authority, scan, assert the event is detected
    under event_type='authority_updated' with the new authority value in the
    decoded data.

    AuthorityUpdated has no OZ counterpart — without per-contract topic
    dispatch, an authority swap (entire access-control regime change) is
    invisible to the scanner.
    """
    from eth_utils.crypto import keccak

    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    initial_authority = "0x0000000000000000000000000000000000000001"
    addr = _compile_and_deploy(
        SOLMATE_AUTH_SOURCE,
        "TestSolmateAuth",
        [initial_authority],
        rpc_url,
        PRIVATE_KEY,
        tmp_path,
    )
    current_block = int(_cast(["block-number"], rpc_url))

    authority_topic0 = "0x" + keccak(text="AuthorityUpdated(address,address)").hex()
    monitoring_config = {
        "watch_ownership": True,
        "watch_authority": True,
        "tracked_topics": [
            {
                "topic0": authority_topic0,
                "signature": "AuthorityUpdated(address,address)",
                "event_type": "authority_updated",
                "controller_id": "external_contract:authority",
                "inputs": [
                    {"name": "user", "type": "address", "indexed": True},
                    {"name": "newAuthority", "type": "address", "indexed": True},
                ],
            }
        ],
    }
    _register_contract(test_db, addr, "regular", current_block, monitoring_config=monitoring_config)

    new_authority = "0x3994741a5b29c60D0AB318dE1024F9256fe959dc"
    _cast_send(addr, "setAuthority(address)", [new_authority], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)

    assert len(events) == 1
    evt = events[0]
    assert evt.event_type == "authority_updated"
    assert evt.data is not None
    assert evt.data.get("new_authority", "").lower() == new_authority.lower()


def test_dsauth_log_set_owner_detected(anvil_env, test_db):
    """Maker / DSAuth-family LogSetOwner detection.

    Why this test exists as part of the general-bug regression set:
    DSAuth's ``LogSetOwner(address indexed owner)`` has a topic0
    distinct from both OZ ``OwnershipTransferred`` and Solmate
    ``OwnerUpdated``. Without per-contract topic dispatch the scanner's
    eth_getLogs filter never includes its topic0, and the event is
    dropped at the network layer — same shape of gap as Bug 3 but
    against a completely different ABI family (Maker DSS, MKR, DAI,
    Vat/Vow/Cat). Validates that the generic dispatcher generalizes
    beyond Solmate.

    Also exercises the *single-arg* decode + semantic-key fallback path:
    LogSetOwner only carries the new owner (no previous), so the
    decoder should fill ``new_owner`` without inventing an ``old_owner``.
    """
    from eth_utils.crypto import keccak

    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(DSAUTH_SOURCE, "TestDSAuth", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    topic0 = "0x" + keccak(text="LogSetOwner(address)").hex()
    monitoring_config = {
        "watch_ownership": True,
        "tracked_topics": [
            {
                "topic0": topic0,
                "signature": "LogSetOwner(address)",
                "event_type": "ownership_transferred",
                "controller_id": "state_variable:owner",
                "inputs": [{"name": "owner", "type": "address", "indexed": True}],
            }
        ],
    }
    _register_contract(test_db, addr, "regular", current_block, monitoring_config=monitoring_config)

    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "setOwner(address)", [new_owner], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)

    assert len(events) == 1
    evt = events[0]
    assert evt.event_type == "ownership_transferred"
    assert evt.data is not None
    assert evt.data.get("new_owner", "").lower() == new_owner.lower()
    # Single-arg event carries no previous-owner value; decoder must
    # not invent one.
    assert "old_owner" not in evt.data


def test_compound_new_admin_detected(anvil_env, test_db):
    """Compound Comptroller / cToken NewAdmin detection.

    Compound's ``NewAdmin(address newAdmin)`` packs the admin into the
    log data field rather than a topic — exercises the eth_abi
    non-indexed decode path. Distinct topic0 from every other ABI
    family. Validates the dispatcher works for data-side decoding,
    not just indexed-topic events.
    """
    from eth_utils.crypto import keccak

    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(COMPOUND_ADMIN_SOURCE, "TestCompoundAdmin", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    topic0 = "0x" + keccak(text="NewAdmin(address)").hex()
    monitoring_config = {
        "watch_ownership": True,
        "tracked_topics": [
            {
                "topic0": topic0,
                "signature": "NewAdmin(address)",
                "event_type": "admin_changed",
                "controller_id": "state_variable:admin",
                "inputs": [{"name": "newAdmin", "type": "address", "indexed": False}],
            }
        ],
    }
    _register_contract(test_db, addr, "regular", current_block, monitoring_config=monitoring_config)

    new_admin = "0x3994741a5b29c60D0AB318dE1024F9256fe959dc"
    _cast_send(addr, "_setAdmin(address)", [new_admin], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)

    assert len(events) == 1
    evt = events[0]
    assert evt.event_type == "admin_changed"
    assert evt.data is not None
    assert evt.data.get("new_admin", "").lower() == new_admin.lower()


def test_ozownable2step_transfer_started_detected(anvil_env, test_db):
    """OZ Ownable2Step OwnershipTransferStarted detection.

    Same ABI shape as the OZ Ownable ``OwnershipTransferred`` (two
    indexed addresses, OZ-conventional ``previousOwner`` /
    ``newOwner`` names), but a different event name → different
    topic0. Without per-contract dispatch, the *intent* phase of a
    two-step ownership move is invisible — only the final
    ``OwnershipTransferred`` is registered. Defense-in-depth
    monitoring wants both phases.
    """
    from eth_utils.crypto import keccak

    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(OZ_OWNABLE2STEP_SOURCE, "TestOwnable2Step", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    topic0 = "0x" + keccak(text="OwnershipTransferStarted(address,address)").hex()
    monitoring_config = {
        "watch_ownership": True,
        "tracked_topics": [
            {
                "topic0": topic0,
                "signature": "OwnershipTransferStarted(address,address)",
                "event_type": "ownership_transfer_started",
                "controller_id": "state_variable:pendingOwner",
                "inputs": [
                    {"name": "previousOwner", "type": "address", "indexed": True},
                    {"name": "newOwner", "type": "address", "indexed": True},
                ],
            }
        ],
    }
    _register_contract(test_db, addr, "regular", current_block, monitoring_config=monitoring_config)

    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)

    assert len(events) == 1
    evt = events[0]
    assert evt.event_type == "ownership_transfer_started"
    assert evt.data is not None
    assert evt.data.get("new_owner", "").lower() == new_owner.lower()
    # previousOwner here is the deployer (account 0).
    assert evt.data.get("old_owner", "").lower() == ACCOUNT0.lower()


def test_pre_fix_filter_drops_non_oz_event(anvil_env, test_db):
    """Regression guard for the *general* bug shape.

    Deploys a Solmate-Owned, registers it with WATCH_OWNERSHIP=True
    but *no* tracked_topics. Transfers ownership. Asserts the scanner
    detects nothing — proves the pre-fix scanner behavior is preserved
    when tracked_topics is absent (so the fix is purely additive: zero
    new events when no tracking_plan has been threaded through
    enrollment). Pair with ``test_solmate_owner_updated_detected``:
    same contract + same on-chain action, only the monitoring_config
    differs. If this test ever starts catching the event, something
    has leaked Solmate's topic0 into the hand-rolled global filter.
    """
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(SOLMATE_OWNED_SOURCE, "TestSolmateOwned", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    # No tracked_topics — simulates a row that was enrolled before the
    # general fix landed (or a contract whose tracking_plan is still
    # pending materialization).
    _register_contract(
        test_db,
        addr,
        "regular",
        current_block,
        monitoring_config={"watch_ownership": True},
    )

    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "setOwner(address)", [new_owner], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)

    assert events == [], (
        "Solmate OwnerUpdated detected without per-contract topic dispatch — "
        "either the hand-rolled global registry leaked Solmate's topic0, or "
        "tracked_topics is being inferred from somewhere unexpected. Both "
        "would defeat the regression guard for the general-bug fix."
    )


def test_pause_unpause_detected(anvil_env, test_db):
    """Deploy Pausable, pause, scan, unpause, scan, assert both events."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(PAUSABLE_SOURCE, "TestPausable", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    _register_contract(test_db, addr, "pausable", current_block)

    # Pause
    _cast_send(addr, "pause()", [], rpc_url, PRIVATE_KEY)
    events = scan_for_events(test_db, rpc_url)
    assert len(events) == 1
    assert events[0].event_type == "paused"

    # Unpause
    _cast_send(addr, "unpause()", [], rpc_url, PRIVATE_KEY)
    events2 = scan_for_events(test_db, rpc_url)
    assert len(events2) == 1
    assert events2[0].event_type == "unpaused"


def test_safe_signer_changes_detected(anvil_env, test_db):
    """Deploy Safe, add/remove/changeThreshold, scan, assert 3 events."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(SAFE_SOURCE, "TestSafe", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    _register_contract(test_db, addr, "safe", current_block)

    new_signer = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "addOwner(address)", [new_signer], rpc_url, PRIVATE_KEY)
    _cast_send(addr, "removeOwner(address)", [new_signer], rpc_url, PRIVATE_KEY)
    _cast_send(addr, "changeThreshold(uint256)", ["2"], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)

    event_types = sorted([e.event_type for e in events])
    assert "signer_added" in event_types
    assert "signer_removed" in event_types
    assert "threshold_changed" in event_types
    assert len(events) == 3


def test_timelock_operations_detected(anvil_env, test_db):
    """Deploy Timelock, schedule/execute/updateDelay, scan, assert 3 events."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(TIMELOCK_SOURCE, "TestTimelock", ["3600"], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    _register_contract(test_db, addr, "timelock", current_block)

    # Schedule a call
    op_id = "0x" + "ab" * 32
    target = "0x0000000000000000000000000000000000000001"
    _cast_send(
        addr,
        "schedule(bytes32,uint256,address,uint256,bytes,bytes32,uint256)",
        [op_id, "0", target, "0", "0x", "0x" + "00" * 32, "3600"],
        rpc_url,
        PRIVATE_KEY,
    )

    # Execute a call
    _cast_send(
        addr,
        "execute(bytes32,uint256,address,uint256,bytes)",
        [op_id, "0", target, "0", "0x"],
        rpc_url,
        PRIVATE_KEY,
    )

    # Update delay
    _cast_send(addr, "updateDelay(uint256)", ["7200"], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)
    event_types = sorted([e.event_type for e in events])
    assert "timelock_scheduled" in event_types
    assert "timelock_executed" in event_types
    assert "delay_changed" in event_types
    assert len(events) == 3


def test_role_changes_detected(anvil_env, test_db):
    """Deploy a role-control contract, grant/revoke, scan, assert 2 events."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(ROLE_CONTROL_SOURCE, "TestRoleControl", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    _register_contract(
        test_db, addr, "role_control", current_block, monitoring_config={"watch_roles": True, "watch_ownership": True}
    )

    role = "0x" + "00" * 32  # DEFAULT_ADMIN_ROLE
    account = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "grantRole(bytes32,address)", [role, account], rpc_url, PRIVATE_KEY)
    _cast_send(addr, "revokeRole(bytes32,address)", [role, account], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)
    event_types = sorted([e.event_type for e in events])
    assert "role_granted" in event_types
    assert "role_revoked" in event_types
    assert len(events) == 2


def test_proxy_upgrade_backward_compat(anvil_env, test_db):
    """Upgrade a proxy registered in both tables, verify write-through."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    impl_v1 = _compile_and_deploy(IMPL_V1_SOURCE, "ImplV1", [], rpc_url, PRIVATE_KEY, tmp_path)
    impl_v2 = _compile_and_deploy(IMPL_V2_SOURCE, "ImplV2", [], rpc_url, PRIVATE_KEY, tmp_path)
    proxy_addr = _compile_and_deploy(PROXY_SOURCE, "TestProxy", [impl_v1], rpc_url, PRIVATE_KEY, tmp_path)

    current_block = int(_cast(["block-number"], rpc_url))

    # Create WatchedProxy
    wp = WatchedProxy(
        id=uuid.uuid4(),
        proxy_address=proxy_addr.lower(),
        chain="ethereum",
        label="test-proxy",
        last_known_implementation=impl_v1.lower(),
        last_scanned_block=current_block,
    )
    test_db.add(wp)
    test_db.commit()

    # Create MonitoredContract linked to WatchedProxy
    _register_contract(
        test_db,
        proxy_addr,
        "proxy",
        current_block,
        monitoring_config={"watch_upgrades": True, "watch_ownership": True},
        watched_proxy_id=wp.id,
    )

    # Upgrade
    _cast_send(proxy_addr, "upgradeTo(address)", [impl_v2], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)

    # Should have created a MonitoredEvent
    assert len(events) >= 1
    upgrade_events = [e for e in events if e.event_type == "upgraded"]
    assert len(upgrade_events) == 1

    # Should ALSO have created a ProxyUpgradeEvent (backward compat)
    proxy_events = (
        test_db.execute(select(ProxyUpgradeEvent).where(ProxyUpgradeEvent.watched_proxy_id == wp.id)).scalars().all()
    )
    assert len(proxy_events) == 1
    assert proxy_events[0].new_implementation.lower() == impl_v2.lower()

    # WatchedProxy should be updated
    test_db.refresh(wp)
    assert wp.last_known_implementation is not None
    assert wp.last_known_implementation.lower() == impl_v2.lower()


def test_mixed_contracts_single_scan(anvil_env, test_db):
    """Register multiple contract types, perform actions, single scan detects all."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    ownable_addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
    pausable_addr = _compile_and_deploy(PAUSABLE_SOURCE, "TestPausable", [], rpc_url, PRIVATE_KEY, tmp_path)
    safe_addr = _compile_and_deploy(SAFE_SOURCE, "TestSafe", [], rpc_url, PRIVATE_KEY, tmp_path)

    current_block = int(_cast(["block-number"], rpc_url))

    _register_contract(test_db, ownable_addr, "regular", current_block)
    _register_contract(test_db, pausable_addr, "pausable", current_block)
    _register_contract(test_db, safe_addr, "safe", current_block)

    # Perform actions on each
    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(ownable_addr, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)
    _cast_send(pausable_addr, "pause()", [], rpc_url, PRIVATE_KEY)
    _cast_send(safe_addr, "addOwner(address)", [new_owner], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)

    event_types = sorted([e.event_type for e in events])
    assert "ownership_transferred" in event_types
    assert "paused" in event_types
    assert "signer_added" in event_types
    assert len(events) >= 3


def test_poll_detects_ownership_change(anvil_env, test_db):
    """Transfer ownership and detect via polling (state comparison)."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import poll_for_state_changes

    addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)

    current_block = int(_cast(["block-number"], rpc_url))

    mc = _register_contract(
        test_db,
        addr,
        "regular",
        current_block,
        monitoring_config={"watch_ownership": True},
    )
    mc.needs_polling = True
    mc.last_known_state = {"owner": ACCOUNT0.lower()}
    test_db.commit()

    # Transfer ownership
    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)

    events = poll_for_state_changes(test_db, rpc_url)

    assert len(events) >= 1
    owner_changes = [e for e in events if e.data and e.data.get("field") == "owner"]
    assert len(owner_changes) == 1
    assert owner_changes[0].data is not None
    assert owner_changes[0].data["new_value"].lower() == new_owner.lower()


# ---------------------------------------------------------------------------
# Edge case & regression tests
# ---------------------------------------------------------------------------


def test_should_watch_filters_disabled_events(anvil_env, test_db):
    """Events are ignored when their config flag is disabled."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    pausable_addr = _compile_and_deploy(PAUSABLE_SOURCE, "TestPausable", [], rpc_url, PRIVATE_KEY, tmp_path)
    ownable_addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    # Register pausable with watch_pause=False — should be filtered out
    _register_contract(
        test_db,
        pausable_addr,
        "pausable",
        current_block,
        monitoring_config={"watch_pause": False, "watch_ownership": False},
    )
    # Register ownable with watch_ownership=True — should be detected
    _register_contract(
        test_db,
        ownable_addr,
        "regular",
        current_block,
        monitoring_config={"watch_ownership": True, "watch_pause": False},
    )

    # Trigger both events
    _cast_send(pausable_addr, "pause()", [], rpc_url, PRIVATE_KEY)
    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(ownable_addr, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)

    # Only the ownership transfer should be detected; pause should be filtered
    event_types = [e.event_type for e in events]
    assert "ownership_transferred" in event_types
    assert "paused" not in event_types


def test_state_updated_after_ownership_transfer(anvil_env, test_db):
    """last_known_state is updated with new owner after OwnershipTransferred."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    mc = _register_contract(test_db, addr, "regular", current_block)
    mc.last_known_state = {"owner": ACCOUNT0.lower()}
    test_db.commit()

    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)

    scan_for_events(test_db, rpc_url)

    test_db.refresh(mc)
    state = mc.last_known_state
    assert state is not None
    assert state.get("owner", "").lower() == new_owner.lower()


def test_state_updated_after_pause(anvil_env, test_db):
    """last_known_state tracks paused=True after Paused and paused=False after Unpaused."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(PAUSABLE_SOURCE, "TestPausable", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    mc = _register_contract(test_db, addr, "pausable", current_block)
    mc.last_known_state = {}
    test_db.commit()

    # Pause
    _cast_send(addr, "pause()", [], rpc_url, PRIVATE_KEY)
    scan_for_events(test_db, rpc_url)
    test_db.refresh(mc)
    state = mc.last_known_state
    assert state is not None
    assert state.get("paused") is True

    # Unpause
    _cast_send(addr, "unpause()", [], rpc_url, PRIVATE_KEY)
    scan_for_events(test_db, rpc_url)
    test_db.refresh(mc)
    state = mc.last_known_state
    assert state is not None
    assert state.get("paused") is False


def test_state_updated_after_proxy_upgrade(anvil_env, test_db):
    """last_known_state tracks implementation after Upgraded event."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    impl_v1 = _compile_and_deploy(IMPL_V1_SOURCE, "ImplV1", [], rpc_url, PRIVATE_KEY, tmp_path)
    impl_v2 = _compile_and_deploy(IMPL_V2_SOURCE, "ImplV2", [], rpc_url, PRIVATE_KEY, tmp_path)
    proxy_addr = _compile_and_deploy(PROXY_SOURCE, "TestProxy", [impl_v1], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    mc = _register_contract(
        test_db,
        proxy_addr,
        "proxy",
        current_block,
        monitoring_config={"watch_upgrades": True, "watch_ownership": True},
    )
    mc.last_known_state = {"implementation": impl_v1.lower()}
    test_db.commit()

    _cast_send(proxy_addr, "upgradeTo(address)", [impl_v2], rpc_url, PRIVATE_KEY)
    scan_for_events(test_db, rpc_url)

    test_db.refresh(mc)
    state = mc.last_known_state
    assert state is not None
    assert state.get("implementation", "").lower() == impl_v2.lower()


def test_dedup_multi_contract_overlap(anvil_env, test_db):
    """When two contracts have different last_scanned_block values,
    the overlap window is scanned once and events are not duplicated.

    The scanner uses min(last_scanned_block) as the start, so a contract
    with a lower block triggers a re-scan of blocks the other contract
    already saw. Dedup ensures those already-recorded events aren't
    created again.
    """
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr1 = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
    addr2 = _compile_and_deploy(PAUSABLE_SOURCE, "TestPausable", [], rpc_url, PRIVATE_KEY, tmp_path)
    block_after_deploy = int(_cast(["block-number"], rpc_url))

    # Register both at the same starting point
    mc1 = _register_contract(test_db, addr1, "regular", block_after_deploy)
    mc2 = _register_contract(test_db, addr2, "pausable", block_after_deploy)

    # Trigger events on both
    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr1, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)
    _cast_send(addr2, "pause()", [], rpc_url, PRIVATE_KEY)

    # First scan: both events detected
    events1 = scan_for_events(test_db, rpc_url)
    assert len(events1) == 2

    # Now add a THIRD contract at an earlier block — this forces the
    # scanner to re-scan the range where addr1 and addr2 events live
    addr3 = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
    _register_contract(test_db, addr3, "regular", block_after_deploy)

    # Second scan: re-scans the overlap range but should NOT re-create
    # the ownership_transferred and paused events for addr1/addr2
    events2 = scan_for_events(test_db, rpc_url)

    # Only events for addr3 (if any) should be new — the constructor
    # emits OwnershipTransferred(address(0), msg.sender) at deploy time,
    # but that was before mc3's last_scanned_block (deploy block < register block).
    # So events2 should be empty.
    for e in events2:
        # No event should belong to mc1 or mc2 (those were already recorded)
        assert e.monitored_contract_id != mc1.id, "Duplicate event for contract 1"
        assert e.monitored_contract_id != mc2.id, "Duplicate event for contract 2"

    # Total events in DB for mc1 and mc2 should still be exactly 1 each
    mc1_events = test_db.execute(
        select(func.count()).select_from(MonitoredEvent).where(MonitoredEvent.monitored_contract_id == mc1.id)
    ).scalar()
    mc2_events = test_db.execute(
        select(func.count()).select_from(MonitoredEvent).where(MonitoredEvent.monitored_contract_id == mc2.id)
    ).scalar()
    assert mc1_events == 1
    assert mc2_events == 1


def test_last_scanned_block_advances(anvil_env, test_db):
    """last_scanned_block advances after scan; second scan returns empty."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    mc = _register_contract(test_db, addr, "regular", current_block)

    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)
    assert len(events) == 1

    test_db.refresh(mc)
    assert mc.last_scanned_block > current_block
    assert mc.last_scanned_block >= events[0].block_number

    # Second scan with no new blocks should return empty
    events2 = scan_for_events(test_db, rpc_url)
    assert len(events2) == 0


def test_state_updated_after_threshold_change(anvil_env, test_db):
    """last_known_state tracks threshold after ChangedThreshold event."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(SAFE_SOURCE, "TestSafe", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    mc = _register_contract(test_db, addr, "safe", current_block)
    mc.last_known_state = {"threshold": 1}
    test_db.commit()

    _cast_send(addr, "changeThreshold(uint256)", ["3"], rpc_url, PRIVATE_KEY)
    scan_for_events(test_db, rpc_url)

    test_db.refresh(mc)
    state = mc.last_known_state
    assert state is not None
    assert state.get("threshold") == 3


def test_state_updated_after_delay_change(anvil_env, test_db):
    """last_known_state tracks min_delay after MinDelayChange event."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(TIMELOCK_SOURCE, "TestTimelock", ["3600"], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    mc = _register_contract(test_db, addr, "timelock", current_block)
    mc.last_known_state = {"min_delay": 3600}
    test_db.commit()

    _cast_send(addr, "updateDelay(uint256)", ["7200"], rpc_url, PRIVATE_KEY)
    scan_for_events(test_db, rpc_url)

    test_db.refresh(mc)
    state = mc.last_known_state
    assert state is not None
    assert state.get("min_delay") == 7200


def test_enrollment_config_produces_correct_detection(anvil_env, test_db):
    """Contracts registered with enrollment-style configs detect matching events only."""
    rpc_url, tmp_path = anvil_env
    # Simulate enrollment output for a pausable contract
    from unittest.mock import MagicMock

    from services.monitoring.enrollment import _build_monitoring_config, _determine_contract_type
    from services.monitoring.unified_watcher import scan_for_events

    contract = MagicMock()
    contract.is_proxy = False
    contract.proxy_type = None
    summary = MagicMock()
    summary.is_upgradeable = False
    summary.is_pausable = True
    summary.has_timelock = False
    summary.control_model = None

    ct = _determine_contract_type(contract, summary, [])
    config = _build_monitoring_config(summary, [], ct)

    # Deploy a pausable contract
    addr = _compile_and_deploy(PAUSABLE_SOURCE, "TestPausable", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    # Register with the config that enrollment would produce
    _register_contract(test_db, addr, ct, current_block, monitoring_config=config)

    # Pause (watch_pause should be True)
    _cast_send(addr, "pause()", [], rpc_url, PRIVATE_KEY)
    events = scan_for_events(test_db, rpc_url)

    assert len(events) == 1
    assert events[0].event_type == "paused"

    # The config should NOT have watch_upgrades or watch_safe_signers
    assert config.get("watch_upgrades") is False
    assert config.get("watch_safe_signers") is False


def test_notify_protocol_events_sends_discord(anvil_env, test_db):
    """notify_protocol_events sends Discord embeds for detected events."""
    rpc_url, tmp_path = anvil_env
    from unittest.mock import patch

    # ProtocolSubscription table already exists via Base.metadata.create_all
    from db.models import Protocol, ProtocolSubscription
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    proto = Protocol(name="__test_notify__")
    test_db.add(proto)
    test_db.flush()

    mc = _register_contract(test_db, addr, "regular", current_block)
    mc.protocol_id = proto.id
    test_db.commit()

    # Create a protocol subscription
    sub = ProtocolSubscription(
        id=uuid.uuid4(),
        protocol_id=proto.id,
        discord_webhook_url="https://discord.com/api/webhooks/test/fake",
        label="test-sub",
    )
    test_db.add(sub)
    test_db.commit()

    # Trigger event
    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)

    # scan_for_events now delivers the Discord notification per window as part
    # of the scan itself, so patch the wire before scanning and assert the
    # embed from that scan-triggered post.
    with patch("services.monitoring.notifier.requests.post") as mock_post:
        mock_post.return_value = MagicMock(ok=True)
        events = scan_for_events(test_db, rpc_url)
        assert len(events) >= 1

        assert mock_post.call_count == 1
        call_kwargs = mock_post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        embed = payload["embeds"][0]
        assert "ownership_transferred" in embed["title"]
        assert embed["color"] == 0xFF0000  # red for ownership transfer


def test_notify_event_filter_restricts_types(anvil_env, test_db):
    """ProtocolSubscription with event_filter only gets matching event types."""
    rpc_url, tmp_path = anvil_env
    from unittest.mock import MagicMock, patch

    from db.models import Protocol, ProtocolSubscription
    from services.monitoring.unified_watcher import scan_for_events

    # ProtocolSubscription table already exists via Base.metadata.create_all

    pausable_addr = _compile_and_deploy(PAUSABLE_SOURCE, "TestPausable", [], rpc_url, PRIVATE_KEY, tmp_path)
    ownable_addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    proto = Protocol(name="__test_filter__")
    test_db.add(proto)
    test_db.flush()

    mc1 = _register_contract(test_db, pausable_addr, "pausable", current_block)
    mc1.protocol_id = proto.id
    mc2 = _register_contract(test_db, ownable_addr, "regular", current_block)
    mc2.protocol_id = proto.id
    test_db.commit()

    # Subscription only wants "paused" events
    sub = ProtocolSubscription(
        id=uuid.uuid4(),
        protocol_id=proto.id,
        discord_webhook_url="https://discord.com/api/webhooks/test/fake",
        event_filter={"event_types": ["paused"]},
    )
    test_db.add(sub)
    test_db.commit()

    # Trigger both events
    _cast_send(pausable_addr, "pause()", [], rpc_url, PRIVATE_KEY)
    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(ownable_addr, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)

    # scan_for_events now delivers notifications per window as part of the scan
    # itself; patch the wire before scanning and assert the filtered post.
    with patch("services.monitoring.notifier.requests.post") as mock_post:
        mock_post.return_value = MagicMock(ok=True)
        events = scan_for_events(test_db, rpc_url)
        assert len(events) >= 2  # both detected in DB

        # Only the "paused" event should trigger a Discord notification
        assert mock_post.call_count == 1
        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert "paused" in payload["embeds"][0]["title"]


def test_poll_detects_pause_state_change(anvil_env, test_db):
    """Poller detects paused() flipping from false to true."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import poll_for_state_changes

    addr = _compile_and_deploy(PAUSABLE_SOURCE, "TestPausable", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    mc = _register_contract(
        test_db,
        addr,
        "pausable",
        current_block,
        monitoring_config={"watch_pause": True},
    )
    mc.needs_polling = True
    mc.last_known_state = {"paused": False}
    test_db.commit()

    _cast_send(addr, "pause()", [], rpc_url, PRIVATE_KEY)

    events = poll_for_state_changes(test_db, rpc_url)

    pause_changes = [e for e in events if e.data and e.data.get("field") == "paused"]
    assert len(pause_changes) == 1
    assert pause_changes[0].data is not None
    assert pause_changes[0].data["new_value"] == "True"


def test_poll_detects_threshold_change(anvil_env, test_db):
    """Poller detects getThreshold() changing on a safe contract."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import poll_for_state_changes

    addr = _compile_and_deploy(SAFE_SOURCE, "TestSafe", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    mc = _register_contract(
        test_db,
        addr,
        "safe",
        current_block,
        monitoring_config={"watch_safe_signers": True},
    )
    mc.needs_polling = True
    mc.last_known_state = {"threshold": 1}
    test_db.commit()

    _cast_send(addr, "changeThreshold(uint256)", ["5"], rpc_url, PRIVATE_KEY)

    events = poll_for_state_changes(test_db, rpc_url)

    threshold_changes = [e for e in events if e.data and e.data.get("field") == "threshold"]
    assert len(threshold_changes) == 1
    assert threshold_changes[0].data is not None
    assert threshold_changes[0].data["new_value"] == "5"


def test_poll_no_change_no_events(anvil_env, test_db):
    """Poller creates no events when state hasn't changed."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import poll_for_state_changes

    addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    mc = _register_contract(
        test_db,
        addr,
        "regular",
        current_block,
        monitoring_config={"watch_ownership": True},
    )
    mc.needs_polling = True
    mc.last_known_state = {"owner": ACCOUNT0.lower()}
    test_db.commit()

    # Don't change anything — poll should return empty
    events = poll_for_state_changes(test_db, rpc_url)
    assert len(events) == 0


# ---------------------------------------------------------------------------
# Scan+poll dedup tests
# ---------------------------------------------------------------------------


def test_poll_suppressed_when_scan_already_detected_upgrade(anvil_env, test_db):
    """When the scanner already detected an Upgraded event, the poller should
    NOT create a duplicate state_changed_poll for the same implementation change.

    Simulates the race condition where the scanner committed a MonitoredEvent
    but the poller still has stale last_known_state (read before scanner commit).
    """
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import poll_for_state_changes

    impl_v1 = _compile_and_deploy(IMPL_V1_SOURCE, "ImplV1", [], rpc_url, PRIVATE_KEY, tmp_path)
    impl_v2 = _compile_and_deploy(IMPL_V2_SOURCE, "ImplV2", [], rpc_url, PRIVATE_KEY, tmp_path)
    proxy_addr = _compile_and_deploy(PROXY_SOURCE, "TestProxy", [impl_v1], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    mc = _register_contract(
        test_db,
        proxy_addr,
        "proxy",
        current_block,
        monitoring_config={"watch_upgrades": True, "watch_ownership": True},
    )
    mc.needs_polling = True
    mc.last_known_state = {"implementation": impl_v1.lower()}
    test_db.commit()

    # Upgrade the proxy
    _cast_send(proxy_addr, "upgradeTo(address)", [impl_v2], rpc_url, PRIVATE_KEY)

    # Simulate: scanner already detected the upgrade (but poller has stale state)
    scanner_event = MonitoredEvent(
        id=uuid.uuid4(),
        monitored_contract_id=mc.id,
        event_type="upgraded",
        block_number=current_block + 1,
        tx_hash="0x" + "ab" * 32,
        data={"implementation": impl_v2.lower()},
    )
    test_db.add(scanner_event)
    test_db.commit()

    # Poller runs — storage shows impl_v2 but last_known_state still has impl_v1
    # Without fix: creates a duplicate state_changed_poll event
    # With fix: suppressed because scanner already detected "upgraded"
    poll_events = poll_for_state_changes(test_db, rpc_url)
    impl_changes = [e for e in poll_events if e.data and e.data.get("field") == "implementation"]
    assert len(impl_changes) == 0, "Poller should not create duplicate event when scanner already detected upgrade"


def test_poll_suppressed_when_scan_already_detected_ownership(anvil_env, test_db):
    """Scanner already detected OwnershipTransferred — poller should NOT
    create a duplicate state_changed_poll for the owner field."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import poll_for_state_changes

    addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    mc = _register_contract(
        test_db,
        addr,
        "regular",
        current_block,
        monitoring_config={"watch_ownership": True},
    )
    mc.needs_polling = True
    mc.last_known_state = {"owner": ACCOUNT0.lower()}
    test_db.commit()

    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)

    # Simulate scanner already detected it
    scanner_event = MonitoredEvent(
        id=uuid.uuid4(),
        monitored_contract_id=mc.id,
        event_type="ownership_transferred",
        block_number=current_block + 1,
        tx_hash="0x" + "cd" * 32,
        data={"old_owner": ACCOUNT0.lower(), "new_owner": new_owner.lower()},
    )
    test_db.add(scanner_event)
    test_db.commit()

    poll_events = poll_for_state_changes(test_db, rpc_url)
    owner_changes = [e for e in poll_events if e.data and e.data.get("field") == "owner"]
    assert len(owner_changes) == 0, (
        "Poller should not create duplicate event when scanner already detected ownership change"
    )


def test_poll_still_creates_event_when_no_scanner_event(anvil_env, test_db):
    """When there is NO scanner event, the poller should still create its event.
    This confirms the suppression only fires when a scanner event exists."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import poll_for_state_changes

    impl_v1 = _compile_and_deploy(IMPL_V1_SOURCE, "ImplV1", [], rpc_url, PRIVATE_KEY, tmp_path)
    impl_v2 = _compile_and_deploy(IMPL_V2_SOURCE, "ImplV2", [], rpc_url, PRIVATE_KEY, tmp_path)
    proxy_addr = _compile_and_deploy(PROXY_SOURCE, "TestProxy", [impl_v1], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    mc = _register_contract(
        test_db,
        proxy_addr,
        "proxy",
        current_block,
        monitoring_config={"watch_upgrades": True, "watch_ownership": True},
    )
    mc.needs_polling = True
    mc.last_known_state = {"implementation": impl_v1.lower()}
    test_db.commit()

    # Upgrade but do NOT run scanner — no scanner events exist
    _cast_send(proxy_addr, "upgradeTo(address)", [impl_v2], rpc_url, PRIVATE_KEY)

    poll_events = poll_for_state_changes(test_db, rpc_url)
    impl_changes = [e for e in poll_events if e.data and e.data.get("field") == "implementation"]
    assert len(impl_changes) == 1, "Poller should create event when no scanner event exists"


# ---------------------------------------------------------------------------
# Polling-plan regression tests — custom-named slots end-to-end.
#
# These prove the post-refactor invariants the new ``polling_plan`` shape
# is supposed to guarantee:
#
#   1. A custom-named state-var (``protocolAdmin``, ``feeRecipient``) is
#      visible to the poll path purely via the analyzer-derived
#      polling-plan entry — no contract_type branching, no per-slot
#      selector constant, no hand-rolled event-type entry.
#   2. The first-observation-no-event rule still holds for custom slots.
#   3. Per-contract scan/poll suppression derives from ``tracked_topics``
#      so a custom event fired by the scanner suppresses the matching
#      poll observation.
#   4. The poll path and the event path write to the same
#      ``last_known_state`` key for the same slot, regardless of which
#      path observed the change first.
#   5. End-to-end enrollment from a ``ContractMaterialization`` row
#      projects the analyzer's tracked_controllers into a polling_plan.
#   6. Poll-detected changes to canonical-name admin slots
#      (``admin``) trigger reanalysis through the unified
#      write-target vocabulary, not a special-case poll-field whitelist.
# ---------------------------------------------------------------------------


CUSTOM_ADMIN_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Custom-named control slot whose name is invisible to the pre-refactor
// hardcoded poll selectors. The analyzer-derived polling plan should
// surface ``protocolAdmin`` and ``feeRecipient`` from this contract's
// ``read_spec.target`` values without any per-slot code in the watcher.
contract CustomAdminContract {
    address public protocolAdmin;
    address public feeRecipient;
    event ProtocolAdminChanged(address indexed previousAdmin, address indexed newAdmin);
    event FeeRecipientChanged(address indexed previousRecipient, address indexed newRecipient);

    constructor() {
        protocolAdmin = msg.sender;
        feeRecipient = msg.sender;
    }

    function setProtocolAdmin(address newAdmin) external {
        require(msg.sender == protocolAdmin, "not admin");
        address prev = protocolAdmin;
        protocolAdmin = newAdmin;
        emit ProtocolAdminChanged(prev, newAdmin);
    }

    function setFeeRecipient(address newRecipient) external {
        require(msg.sender == protocolAdmin, "not admin");
        address prev = feeRecipient;
        feeRecipient = newRecipient;
        emit FeeRecipientChanged(prev, newRecipient);
    }
}
"""


def _custom_admin_polling_plan(extra_controllers: list[dict] | None = None) -> list[dict]:
    """Mint a polling_plan with the ``protocolAdmin`` and ``feeRecipient``
    analyzer-derived entries CustomAdminContract would yield in a real
    tracking-plan projection. Callers can append extra entries via
    *extra_controllers* (e.g. to add a tracked-topic-driven suppress
    list)."""
    from services.monitoring.polling_plan import build_polling_plan

    tracked_controllers: list[dict] = [
        {
            "controller_id": "state_variable:protocolAdmin",
            "read_spec": {
                "strategy": "getter_call",
                "target": "protocolAdmin",
                "kind": "state_variable",
                "state_variable_name": "protocolAdmin",
                "type": "address",
                "type_kind": "address",
            },
        },
        {
            "controller_id": "state_variable:feeRecipient",
            "read_spec": {
                "strategy": "getter_call",
                "target": "feeRecipient",
                "kind": "state_variable",
                "state_variable_name": "feeRecipient",
                "type": "address",
                "type_kind": "address",
            },
        },
    ]
    if extra_controllers:
        tracked_controllers.extend(extra_controllers)
    return build_polling_plan(
        contract_type="regular",
        proxy_type=None,
        tracking_plan={"tracked_controllers": tracked_controllers},
        tracked_topics=None,
    )


def test_poll_detects_custom_named_slot_change(anvil_env, test_db):
    """Custom-named slot polling via analyzer-derived plan entry.

    Regression for the pre-refactor blind spot: the old poller hardcoded
    selectors for ``owner()`` / ``paused()`` / ``getThreshold()`` /
    ``getMinDelay()`` and the EIP-1967 slot, so a slot named
    ``protocolAdmin`` was invisible to the poll path even after the
    analyzer correctly surfaced it. The new design derives the selector
    from ``read_spec.target`` at enrollment time and dispatches on the
    persisted polling_plan entry."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import poll_for_state_changes

    addr = _compile_and_deploy(CUSTOM_ADMIN_SOURCE, "CustomAdminContract", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    plan = _custom_admin_polling_plan()
    assert any(e["field"] == "protocolAdmin" for e in plan), (
        "polling_plan builder did not surface protocolAdmin from the analyzer-derived entry — "
        "the analyzer-driven dispatch is the only way this slot becomes visible"
    )

    mc = _register_contract(
        test_db,
        addr,
        "regular",
        current_block,
        monitoring_config={"polling_plan": plan, "watch_ownership": False},
    )
    mc.last_known_state = {"protocolAdmin": ACCOUNT0.lower()}
    test_db.commit()

    new_admin = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "setProtocolAdmin(address)", [new_admin], rpc_url, PRIVATE_KEY)

    events = poll_for_state_changes(test_db, rpc_url)

    custom_changes = [e for e in events if e.data and e.data.get("field") == "protocolAdmin"]
    assert len(custom_changes) == 1, f"expected exactly one protocolAdmin change, got {[e.event_type for e in events]}"
    assert custom_changes[0].data is not None
    assert custom_changes[0].data["new_value"].lower() == new_admin.lower()
    assert custom_changes[0].data["old_value"].lower() == ACCOUNT0.lower()

    # State key must also be the analyzer-emitted state_variable_name so
    # subsequent poll/event observations converge on the same slot key.
    test_db.refresh(mc)
    state = mc.last_known_state or {}
    assert state.get("protocolAdmin", "").lower() == new_admin.lower()


def test_poll_custom_slot_first_observation_no_event(anvil_env, test_db):
    """First observation of a custom slot seeds state but emits no event.

    Regression for the post-refactor first-observation rule: when
    ``last_known_state[field]`` is absent for a polling-plan field, the
    first successful read records the value but does NOT fire a
    state_changed_poll (it isn't a state CHANGE — it's a first read).
    Critical for custom slots because they have no
    ``contract.implementation``-style column to seed from."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import poll_for_state_changes

    addr = _compile_and_deploy(CUSTOM_ADMIN_SOURCE, "CustomAdminContract", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    mc = _register_contract(
        test_db,
        addr,
        "regular",
        current_block,
        monitoring_config={"polling_plan": _custom_admin_polling_plan(), "watch_ownership": False},
    )
    # Deliberately leave last_known_state empty for the custom slots.
    mc.last_known_state = {}
    test_db.commit()

    events = poll_for_state_changes(test_db, rpc_url)

    # No events emitted on first observation.
    custom_events = [e for e in events if e.data and e.data.get("field") in ("protocolAdmin", "feeRecipient")]
    assert custom_events == [], f"first-observation should not emit events, got {[e.data for e in custom_events]}"

    # But state IS seeded so the second observation has a baseline.
    test_db.refresh(mc)
    state = mc.last_known_state or {}
    assert state.get("protocolAdmin", "").lower() == ACCOUNT0.lower()
    assert state.get("feeRecipient", "").lower() == ACCOUNT0.lower()


def test_poll_suppressed_for_custom_slot_when_scanner_fires(anvil_env, test_db):
    """Per-contract suppress list derives from ``tracked_topics``.

    Regression for the suppression generalization: the old poller had a
    global ``_POLL_FIELD_TO_SCAN_EVENTS`` table covering only the five
    vendored fields. Custom slots had no suppression at all. The new
    design derives ``suppress_when_scan_event_types`` per-entry from the
    contract's ``tracked_topics`` so a scanner-detected custom-event
    suppresses the matching poll observation."""
    from eth_utils.crypto import keccak

    rpc_url, tmp_path = anvil_env
    from services.monitoring.polling_plan import build_polling_plan
    from services.monitoring.unified_watcher import poll_for_state_changes

    addr = _compile_and_deploy(CUSTOM_ADMIN_SOURCE, "CustomAdminContract", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    # ``tracked_topics`` carries the per-contract event spec for
    # ProtocolAdminChanged with effect_tags.writes=["protocolAdmin"].
    # The polling-plan builder reads these to seed the suppress list.
    topic0 = "0x" + keccak(text="ProtocolAdminChanged(address,address)").hex()
    custom_event_type = "controller_changed:state_variable:protocolAdmin"
    tracked_topics = [
        {
            "topic0": topic0,
            "signature": "ProtocolAdminChanged(address,address)",
            "event_type": custom_event_type,
            "controller_id": "state_variable:protocolAdmin",
            "inputs": [
                {"name": "previousAdmin", "type": "address", "indexed": True},
                {"name": "newAdmin", "type": "address", "indexed": True},
            ],
            "effect_tags": {"writes": ["protocolAdmin"]},
        }
    ]
    plan = build_polling_plan(
        contract_type="regular",
        proxy_type=None,
        tracking_plan={
            "tracked_controllers": [
                {
                    "controller_id": "state_variable:protocolAdmin",
                    "read_spec": {
                        "strategy": "getter_call",
                        "target": "protocolAdmin",
                        "state_variable_name": "protocolAdmin",
                        "type": "address",
                        "type_kind": "address",
                    },
                }
            ]
        },
        tracked_topics=tracked_topics,
    )
    pa_entry = next(e for e in plan if e["field"] == "protocolAdmin")
    assert custom_event_type in (pa_entry.get("suppress_when_scan_event_types") or []), (
        "polling-plan builder did not derive the per-contract suppress list from tracked_topics"
    )

    mc = _register_contract(
        test_db,
        addr,
        "regular",
        current_block,
        monitoring_config={
            "polling_plan": plan,
            "tracked_topics": tracked_topics,
            "watch_ownership": False,
        },
    )
    mc.last_known_state = {"protocolAdmin": ACCOUNT0.lower()}
    test_db.commit()

    new_admin = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "setProtocolAdmin(address)", [new_admin], rpc_url, PRIVATE_KEY)

    # Pre-insert the scanner's MonitoredEvent for this change.
    scanner_event = MonitoredEvent(
        id=uuid.uuid4(),
        monitored_contract_id=mc.id,
        event_type=custom_event_type,
        block_number=current_block + 1,
        tx_hash="0x" + "ef" * 32,
        data={"previousAdmin": ACCOUNT0.lower(), "newAdmin": new_admin.lower()},
    )
    test_db.add(scanner_event)
    test_db.commit()

    poll_events = poll_for_state_changes(test_db, rpc_url)
    custom_polls = [e for e in poll_events if e.data and e.data.get("field") == "protocolAdmin"]
    assert custom_polls == [], (
        "poll should suppress the custom-slot change because the per-contract tracked-topic event already recorded it"
    )


def test_poll_and_event_paths_write_same_state_key(anvil_env, test_db):
    """Poll path and event path converge on the same ``last_known_state`` key.

    Regression for the state-key naming contract: the poll path writes
    to ``last_known_state[entry["field"]]`` which is the analyzer's
    ``state_variable_name``. The event-side generic resolver
    (``_resolve_value_for_write_target``) also writes to
    ``last_known_state[write_target]`` for the same name. If they ever
    diverged (e.g. poll writes ``protocolAdmin`` but event writes
    ``newProtocolAdmin``) a single mutation would create two separate
    ghost entries.

    Uses Compound-shape event arg names (``previousAdmin`` / ``newAdmin``
    for a ``protocolAdmin`` write target) to exercise the ``new*`` ABI
    heuristic in the resolver — neither the bare-name match nor the OZ
    ``new<Cap>`` convention applies here, so this is the path that
    catches non-OZ ABIs."""
    from eth_utils.crypto import keccak

    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import poll_for_state_changes, scan_for_events

    addr = _compile_and_deploy(CUSTOM_ADMIN_SOURCE, "CustomAdminContract", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    # tracked_topics so the scanner can decode + dispatch the custom event.
    # Compound-style arg names so neither parsed["protocolAdmin"] nor
    # parsed["newProtocolAdmin"] matches — the resolver has to fall back
    # to walking _inputs and finding ``newAdmin`` via the "starts with
    # new" heuristic.
    topic0 = "0x" + keccak(text="ProtocolAdminChanged(address,address)").hex()
    tracked_topics = [
        {
            "topic0": topic0,
            "signature": "ProtocolAdminChanged(address,address)",
            "event_type": "controller_changed:state_variable:protocolAdmin",
            "controller_id": "state_variable:protocolAdmin",
            "inputs": [
                {"name": "previousAdmin", "type": "address", "indexed": True},
                {"name": "newAdmin", "type": "address", "indexed": True},
            ],
            "effect_tags": {"writes": ["protocolAdmin"]},
        }
    ]

    mc = _register_contract(
        test_db,
        addr,
        "regular",
        current_block,
        monitoring_config={
            "polling_plan": _custom_admin_polling_plan(),
            "tracked_topics": tracked_topics,
            "watch_ownership": False,
        },
    )
    mc.last_known_state = {"protocolAdmin": ACCOUNT0.lower()}
    test_db.commit()

    # Path 1: event → state update via _update_state_from_event's
    # generic name-match fallback (no canonical tag entry for ``protocolAdmin``).
    admin_b = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "setProtocolAdmin(address)", [admin_b], rpc_url, PRIVATE_KEY)
    scan_for_events(test_db, rpc_url)

    test_db.refresh(mc)
    state_after_event = dict(mc.last_known_state or {})
    assert state_after_event.get("protocolAdmin", "").lower() == admin_b.lower(), (
        f"event-side state write went to a different key — got state {state_after_event}"
    )
    # Critical: the state must be keyed on the analyzer's write_target
    # (``protocolAdmin``), not on the ABI's arg name (``newAdmin``) —
    # otherwise the poll path would read state[protocolAdmin] and the
    # event path would write state[newAdmin] and they'd never converge.
    assert "newAdmin" not in state_after_event
    assert "newProtocolAdmin" not in state_after_event

    # Path 2: poll → state update on a subsequent change. ACCOUNT2 owns
    # the new admin role now, so we use its key to perform the next call.
    account2_key = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    admin_c = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
    _cast_send(addr, "setProtocolAdmin(address)", [admin_c], rpc_url, account2_key)

    poll_for_state_changes(test_db, rpc_url)
    test_db.refresh(mc)
    state_after_poll = dict(mc.last_known_state or {})
    assert state_after_poll.get("protocolAdmin", "").lower() == admin_c.lower(), (
        f"poll-side state write went to a different key — got state {state_after_poll}"
    )


def test_enrollment_builds_polling_plan_for_custom_slot_from_tracking_plan(anvil_env, test_db):
    """End-to-end: ContractMaterialization tracking_plan → polling_plan.

    Validates the full enrollment pipeline:
      * ``_load_tracking_plan_artifacts`` reads the materialization
      * ``build_polling_plan`` projects ``tracked_controllers`` to entries
      * The persisted ``MonitoredContract.monitoring_config["polling_plan"]``
        carries the analyzer-derived custom-slot entry alongside any
        vendored entries

    This is the integration regression for the "custom slots become
    visible to polling once the analyzer surfaces them" claim — proves
    the data flow works without test-helper short-circuits."""
    from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
    from db.models import Contract, ContractMaterialization, Job, Protocol
    from services.monitoring.enrollment import enroll_protocol_contracts

    rpc_url, tmp_path = anvil_env
    addr = _compile_and_deploy(CUSTOM_ADMIN_SOURCE, "CustomAdminContract", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))  # noqa: F841 — block reference for parity with other tests

    # Compute the contract's bytecode keccak so the materialization row
    # matches what ``find_by_address`` would resolve.
    code = _cast(["code", addr], rpc_url).strip()
    bytecode_keccak = "0x" + keccak_text(code if code.startswith("0x") else "0x" + code)

    # Anvil re-uses deterministic deploy addresses across tests in the
    # same module and the ``test_db`` fixture doesn't clean Contract /
    # Job / ContractMaterialization rows between tests — make the test
    # idempotent against leftover state from earlier runs.
    proto = Protocol(name=f"custom_admin_protocol_{uuid.uuid4().hex[:8]}")
    test_db.add(proto)
    test_db.flush()

    contract = test_db.execute(
        select(Contract).where(Contract.address == addr.lower(), Contract.chain == "ethereum")
    ).scalar_one_or_none()
    if contract is None:
        contract = Contract(
            address=addr.lower(),
            chain="ethereum",
            protocol_id=proto.id,
            contract_name="CustomAdminContract",
        )
        test_db.add(contract)
        test_db.flush()
    else:
        contract.protocol_id = proto.id

    existing_job = test_db.execute(select(Job).where(func.lower(Job.address) == addr.lower())).scalar_one_or_none()
    if existing_job is None:
        _add_completed_job(test_db, addr.lower(), proto.id)
    else:
        existing_job.protocol_id = proto.id
        from db.models import JobStatus

        existing_job.status = JobStatus.completed
        test_db.flush()

    from sqlalchemy import delete as sa_delete

    test_db.execute(
        sa_delete(ContractMaterialization).where(
            ContractMaterialization.chain == "ethereum",
            ContractMaterialization.address == addr.lower(),
        )
    )
    test_db.flush()

    tracking_plan = {
        "schema_version": "0.1",
        "contract_address": addr.lower(),
        "contract_name": "CustomAdminContract",
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": [
            {
                "controller_id": "state_variable:protocolAdmin",
                "label": "protocolAdmin",
                "source": "protocolAdmin",
                "kind": "state_variable",
                "read_spec": {
                    "strategy": "getter_call",
                    "target": "protocolAdmin",
                    "kind": "state_variable",
                    "state_variable_name": "protocolAdmin",
                    "type": "address",
                    "type_kind": "address",
                },
                "tracking_mode": "event_plus_state",
                "event_watch": None,
                "polling_fallback": {
                    "contract_address": addr.lower(),
                    "polling_sources": ["protocolAdmin"],
                    "cadence": "realtime_confirm",
                    "notes": [],
                },
                "notes": [],
            }
        ],
    }
    test_db.add(
        ContractMaterialization(
            chain="1",
            bytecode_keccak=bytecode_keccak,
            address=addr.lower(),
            contract_name="CustomAdminContract",
            tracking_plan=tracking_plan,
            status="ready",
            # Enrollment reads via the version-filtered ``find_by_address``; seed
            # at the current analyzer version so the row is visible after an
            # ANALYSIS_SCHEMA_VERSION bump, not just at the DB default.
            analysis_schema_version=ANALYSIS_SCHEMA_VERSION,
        )
    )
    test_db.commit()

    enrolled = enroll_protocol_contracts(test_db, proto.id, rpc_url, "ethereum")
    assert len(enrolled) == 1

    mc = enrolled[0]
    plan = (mc.monitoring_config or {}).get("polling_plan") or []
    fields = sorted(e.get("field") for e in plan)
    assert "protocolAdmin" in fields, (
        f"enrollment did not project the tracking_plan's protocolAdmin controller "
        f"into the polling_plan — got fields {fields}"
    )

    pa_entry = next(e for e in plan if e["field"] == "protocolAdmin")
    assert pa_entry["kind"] == "getter_call"
    assert pa_entry["target"] == "protocolAdmin"
    assert pa_entry["type_kind"] == "address"
    # Selector is keccak("protocolAdmin()")[:4]; pinning this catches a
    # regression where the projection forgets to pre-compute the selector
    # and the poll loop would fail at dispatch time.
    from services.monitoring.polling_plan import selector_for

    assert pa_entry["selector"] == selector_for("protocolAdmin")

    # Needs polling must be True since the projection produced a non-empty plan.
    assert mc.needs_polling is True


def test_poll_custom_admin_slot_triggers_reanalysis_via_unified_vocab(anvil_env, test_db):
    """Poll-detected change to an ``admin``-named slot triggers reanalysis.

    Regression for the tag-vocabulary unification: pre-refactor,
    ``REANALYSIS_POLL_FIELDS = {"implementation", "owner"}`` was the
    only allowlist — a custom contract whose admin slot was just named
    ``admin`` (Compound shape) wouldn't trigger reanalysis on poll
    detection even though the event-side already would (via
    ``_REANALYSIS_WRITE_TARGETS``). The unified design routes both
    paths through the same write-target set."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.polling_plan import build_polling_plan
    from services.monitoring.unified_watcher import poll_for_state_changes

    addr = _compile_and_deploy(COMPOUND_ADMIN_SOURCE, "TestCompoundAdmin", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    # Build a polling plan with just the ``admin`` analyzer-derived
    # entry — no vendored Safe/Timelock/Proxy entries, no ownership entry.
    plan = build_polling_plan(
        contract_type="regular",
        proxy_type=None,
        tracking_plan={
            "tracked_controllers": [
                {
                    "controller_id": "state_variable:admin",
                    "read_spec": {
                        "strategy": "getter_call",
                        "target": "admin",
                        "state_variable_name": "admin",
                        "type": "address",
                        "type_kind": "address",
                    },
                }
            ]
        },
        tracked_topics=None,
    )
    assert any(e["field"] == "admin" for e in plan)

    mc = _register_contract(
        test_db,
        addr,
        "regular",
        current_block,
        monitoring_config={"polling_plan": plan, "watch_ownership": False},
    )
    mc.last_known_state = {"admin": ACCOUNT0.lower()}
    test_db.commit()

    new_admin = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "_setAdmin(address)", [new_admin], rpc_url, PRIVATE_KEY)

    poll_events = poll_for_state_changes(test_db, rpc_url)
    admin_changes = [e for e in poll_events if e.data and e.data.get("field") == "admin"]
    assert len(admin_changes) == 1

    # A reanalysis job must have been queued — proves the poll path uses
    # the same write-target vocabulary the event path uses.
    from db.models import Job

    jobs = (
        test_db.execute(
            select(Job).where(
                func.lower(Job.address) == addr.lower(),
                Job.status.in_(("queued", "processing")),
            )
        )
        .scalars()
        .all()
    )
    assert len(jobs) == 1, (
        f"poll-detected admin change did not trigger reanalysis through the unified "
        f"write-target vocabulary — got jobs {[(j.address, j.status) for j in jobs]}"
    )


def test_event_state_write_resolves_compound_shape_custom_slot(anvil_env, test_db):
    """``_resolve_value_for_write_target`` handles non-OZ ABI shapes
    for custom-named slots.

    Deploys CustomAdminContract (which emits ``FeeRecipientChanged
    (address indexed previousRecipient, address indexed newRecipient)``)
    and tags the event in ``tracked_topics`` as writing the
    ``feeRecipient`` slot. Neither parsed["feeRecipient"] nor
    parsed["newFeeRecipient"] matches; the resolver has to walk
    ``_inputs`` and find ``newRecipient`` via the "starts with new"
    heuristic. Validates the post-refactor claim that custom slots
    work end-to-end regardless of the ABI's arg-naming convention."""
    from eth_utils.crypto import keccak

    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(CUSTOM_ADMIN_SOURCE, "CustomAdminContract", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    topic0 = "0x" + keccak(text="FeeRecipientChanged(address,address)").hex()
    tracked_topics = [
        {
            "topic0": topic0,
            "signature": "FeeRecipientChanged(address,address)",
            "event_type": "controller_changed:state_variable:feeRecipient",
            "controller_id": "state_variable:feeRecipient",
            "inputs": [
                # Compound-shape: neither name matches feeRecipient or
                # newFeeRecipient directly. The resolver must pick
                # ``newRecipient`` via the ``new*`` ABI heuristic.
                {"name": "previousRecipient", "type": "address", "indexed": True},
                {"name": "newRecipient", "type": "address", "indexed": True},
            ],
            "effect_tags": {"writes": ["feeRecipient"]},
        }
    ]

    mc = _register_contract(
        test_db,
        addr,
        "regular",
        current_block,
        monitoring_config={
            "polling_plan": _custom_admin_polling_plan(),
            "tracked_topics": tracked_topics,
            "watch_ownership": False,
        },
    )
    mc.last_known_state = {"feeRecipient": ACCOUNT0.lower()}
    test_db.commit()

    new_recipient = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "setFeeRecipient(address)", [new_recipient], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)
    recipient_events = [e for e in events if e.event_type == "controller_changed:state_variable:feeRecipient"]
    assert len(recipient_events) == 1, (
        f"scanner did not pick up the FeeRecipientChanged event — got {[e.event_type for e in events]}"
    )

    test_db.refresh(mc)
    state = dict(mc.last_known_state or {})
    assert state.get("feeRecipient", "").lower() == new_recipient.lower(), (
        f"resolver did not pull newRecipient via the ABI new* heuristic — got state {state}"
    )
    # No ghost arg-named keys.
    assert "newRecipient" not in state
    assert "newFeeRecipient" not in state


def test_event_state_write_resolves_single_arg_dsauth_shape(anvil_env, test_db):
    """``_resolve_value_for_write_target`` handles DSAuth single-arg
    events via the bare-name match.

    DSAuth's ``LogSetOwner(address indexed owner)`` has a single arg
    named ``owner`` — bare-name match should resolve it directly even
    without an OZ-style ``new`` prefix. This is the simplest path in
    the resolver but worth pinning because the prior fallback already
    handled it and we mustn't regress."""
    from eth_utils.crypto import keccak

    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(DSAUTH_SOURCE, "TestDSAuth", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    topic0 = "0x" + keccak(text="LogSetOwner(address)").hex()
    # Even with effect_tags writes=["owner"], _WRITE_TARGET_TO_STATE
    # catches "owner" via the canonical _extract_new_owner extractor
    # which reads parsed["new_owner"]. The semantic-key assignment in
    # parse_tracked_log fills that for the canonical
    # ``ownership_transferred`` event_type — so attach that here.
    tracked_topics = [
        {
            "topic0": topic0,
            "signature": "LogSetOwner(address)",
            "event_type": "ownership_transferred",
            "controller_id": "state_variable:owner",
            "inputs": [
                {"name": "owner", "type": "address", "indexed": True},
            ],
            "effect_tags": {"writes": ["owner"]},
        }
    ]

    mc = _register_contract(
        test_db,
        addr,
        "regular",
        current_block,
        monitoring_config={
            "polling_plan": [],
            "tracked_topics": tracked_topics,
            "watch_ownership": True,
        },
    )
    mc.last_known_state = {"owner": ACCOUNT0.lower()}
    test_db.commit()

    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "setOwner(address)", [new_owner], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)
    owner_events = [e for e in events if e.event_type == "ownership_transferred"]
    assert len(owner_events) == 1

    test_db.refresh(mc)
    state = dict(mc.last_known_state or {})
    assert state.get("owner", "").lower() == new_owner.lower(), (
        f"DSAuth single-arg event did not update state[owner] — got {state}"
    )


def keccak_text(text: str) -> str:
    """Helper to compute the keccak-256 of an EVM hex bytestring.

    Used by the enrollment integration test to derive the
    ``bytecode_keccak`` primary key for the materialization row.
    """
    from eth_utils.crypto import keccak

    if isinstance(text, str) and text.startswith("0x"):
        return keccak(hexstr=text).hex()
    return keccak(text=text).hex()


def _add_completed_job(session, address: str, protocol_id: int) -> None:
    """Insert a completed Job so ``enroll_protocol_contracts``'s
    ``analyzed_addrs`` filter includes *address*."""
    from db.models import Job, JobStage, JobStatus

    session.add(
        Job(
            address=address,
            protocol_id=protocol_id,
            status=JobStatus.completed,
            stage=JobStage.done,
        )
    )
    session.flush()
