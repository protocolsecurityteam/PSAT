"""Requires anvil, cast and forge on PATH."""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path
from typing import NamedTuple
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session as SASession

from db.models import (
    Base,
    MonitoredContract,
    MonitoredEvent,
    ProxyUpgradeEvent,
    WatchedProxy,
)
from tests.conftest import requires_postgres
from tests.support.anvil import (
    ACCOUNT0,
    IMPL_V1_SOURCE,
    IMPL_V2_SOURCE,
    OWNABLE_SOURCE,
    PRIVATE_KEY,
    PROXY_SOURCE,
    _cast,
    _cast_send,
    _compile_and_deploy,
    anvil_env,  # noqa: F401
    materialization_keys,
    purge_materializations,
)


_has_anvil = shutil.which("anvil") is not None
_has_cast = shutil.which("cast") is not None
_has_forge = shutil.which("forge") is not None

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")

pytestmark = [
    pytest.mark.skipif(not _has_anvil, reason="anvil not found on PATH"),
    pytest.mark.skipif(not _has_cast, reason="cast not found on PATH"),
    pytest.mark.skipif(not _has_forge, reason="forge not found on PATH"),
    requires_postgres,
    pytest.mark.anvil,
    pytest.mark.compile,
]


@pytest.fixture(autouse=True)
def _disable_scan_confirmation_depth(monkeypatch):
    # The 12-block confirmation clamp would hide events on a short Anvil chain.
    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")


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


@pytest.fixture()
def test_db():
    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine)

    session = SASession(engine, expire_on_commit=False)
    pre_materializations = materialization_keys(session)
    try:
        yield session
    finally:
        purge_materializations(session, pre_materializations)
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
    """Vendored entries come from ``build_polling_plan``; this fills only the analyzer-driven gap."""
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
    from services.monitoring.polling_plan import build_polling_plan

    # PROXY_SOURCE writes the EIP-1967 slot via assembly.
    plan_proxy_type = proxy_type or ("eip1967" if contract_type == "proxy" else None)
    polling_plan = build_polling_plan(
        # Tests use legacy-row types the producer never mints; the column's CHECK still admits them.
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


def test_ownership_transfer_detected(anvil_env, test_db):
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    _register_contract(test_db, addr, "regular", current_block)

    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)

    assert len(events) == 1
    evt = events[0]
    assert evt.event_type == "ownership_transferred"
    assert evt.data is not None
    assert evt.data.get("new_owner", "").lower() == new_owner.lower()


def test_solmate_owner_updated_detected(anvil_env, test_db):
    """Bug 3: without per-contract topic dispatch, OwnerUpdated's topic0 isn't in the global filter."""
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
    """Without per-contract dispatch an authority swap is invisible to the scanner."""
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
    """Bug 3 against the DSAuth ABI family, plus single-arg decode and the bare-name write-target match."""
    from eth_utils.crypto import keccak

    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(DSAUTH_SOURCE, "TestDSAuth", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    topic0 = "0x" + keccak(text="LogSetOwner(address)").hex()
    monitoring_config = {
        "watch_ownership": True,
        "polling_plan": [],
        "tracked_topics": [
            {
                "topic0": topic0,
                "signature": "LogSetOwner(address)",
                "event_type": "ownership_transferred",
                "controller_id": "state_variable:owner",
                "inputs": [{"name": "owner", "type": "address", "indexed": True}],
                "effect_tags": {"writes": ["owner"]},
            }
        ],
    }
    mc = _register_contract(test_db, addr, "regular", current_block, monitoring_config=monitoring_config)
    mc.last_known_state = {"owner": ACCOUNT0.lower()}
    test_db.commit()

    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "setOwner(address)", [new_owner], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)

    assert len(events) == 1
    evt = events[0]
    assert evt.event_type == "ownership_transferred"
    assert evt.data is not None
    assert evt.data.get("new_owner", "").lower() == new_owner.lower()
    assert "old_owner" not in evt.data

    owner_events = [e for e in events if e.event_type == "ownership_transferred"]
    assert len(owner_events) == 1

    test_db.refresh(mc)
    state = dict(mc.last_known_state or {})
    assert state.get("owner", "").lower() == new_owner.lower(), (
        f"DSAuth single-arg event did not update state[owner] — got {state}"
    )


def test_compound_new_admin_detected(anvil_env, test_db):
    """The admin is in log data, not a topic."""
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
    """Without per-contract dispatch the intent phase is invisible."""
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
    assert evt.data.get("old_owner", "").lower() == ACCOUNT0.lower()


def test_pre_fix_filter_drops_non_oz_event(anvil_env, test_db):
    """Proves the fix is purely additive: if this catches the event, Solmate's topic0 leaked into the global filter."""
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(SOLMATE_OWNED_SOURCE, "TestSolmateOwned", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

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
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(PAUSABLE_SOURCE, "TestPausable", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    _register_contract(test_db, addr, "pausable", current_block)

    _cast_send(addr, "pause()", [], rpc_url, PRIVATE_KEY)
    events = scan_for_events(test_db, rpc_url)
    assert len(events) == 1
    assert events[0].event_type == "paused"

    _cast_send(addr, "unpause()", [], rpc_url, PRIVATE_KEY)
    events2 = scan_for_events(test_db, rpc_url)
    assert len(events2) == 1
    assert events2[0].event_type == "unpaused"


def test_safe_signer_changes_detected(anvil_env, test_db):
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
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    addr = _compile_and_deploy(TIMELOCK_SOURCE, "TestTimelock", ["3600"], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    _register_contract(test_db, addr, "timelock", current_block)

    op_id = "0x" + "ab" * 32
    target = "0x0000000000000000000000000000000000000001"
    _cast_send(
        addr,
        "schedule(bytes32,uint256,address,uint256,bytes,bytes32,uint256)",
        [op_id, "0", target, "0", "0x", "0x" + "00" * 32, "3600"],
        rpc_url,
        PRIVATE_KEY,
    )

    _cast_send(
        addr,
        "execute(bytes32,uint256,address,uint256,bytes)",
        [op_id, "0", target, "0", "0x"],
        rpc_url,
        PRIVATE_KEY,
    )

    _cast_send(addr, "updateDelay(uint256)", ["7200"], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)
    event_types = sorted([e.event_type for e in events])
    assert "timelock_scheduled" in event_types
    assert "timelock_executed" in event_types
    assert "delay_changed" in event_types
    assert len(events) == 3


def test_role_changes_detected(anvil_env, test_db):
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
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    impl_v1 = _compile_and_deploy(IMPL_V1_SOURCE, "ImplV1", [], rpc_url, PRIVATE_KEY, tmp_path)
    impl_v2 = _compile_and_deploy(IMPL_V2_SOURCE, "ImplV2", [], rpc_url, PRIVATE_KEY, tmp_path)
    proxy_addr = _compile_and_deploy(PROXY_SOURCE, "TestProxy", [impl_v1], rpc_url, PRIVATE_KEY, tmp_path)

    current_block = int(_cast(["block-number"], rpc_url))

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

    _register_contract(
        test_db,
        proxy_addr,
        "proxy",
        current_block,
        monitoring_config={"watch_upgrades": True, "watch_ownership": True},
        watched_proxy_id=wp.id,
    )

    _cast_send(proxy_addr, "upgradeTo(address)", [impl_v2], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)

    assert len(events) >= 1
    upgrade_events = [e for e in events if e.event_type == "upgraded"]
    assert len(upgrade_events) == 1

    proxy_events = (
        test_db.execute(select(ProxyUpgradeEvent).where(ProxyUpgradeEvent.watched_proxy_id == wp.id)).scalars().all()
    )
    assert len(proxy_events) == 1
    assert proxy_events[0].new_implementation.lower() == impl_v2.lower()

    test_db.refresh(wp)
    assert wp.last_known_implementation is not None
    assert wp.last_known_implementation.lower() == impl_v2.lower()


def test_poll_detects_ownership_change(anvil_env, test_db):
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

    events = poll_for_state_changes(test_db, rpc_url)

    assert len(events) >= 1
    owner_changes = [e for e in events if e.data and e.data.get("field") == "owner"]
    assert len(owner_changes) == 1
    assert owner_changes[0].data is not None
    assert owner_changes[0].data["new_value"].lower() == new_owner.lower()


def test_should_watch_filters_disabled_events(anvil_env, test_db):
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    pausable_addr = _compile_and_deploy(PAUSABLE_SOURCE, "TestPausable", [], rpc_url, PRIVATE_KEY, tmp_path)
    ownable_addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    _register_contract(
        test_db,
        pausable_addr,
        "pausable",
        current_block,
        monitoring_config={"watch_pause": False, "watch_ownership": False},
    )
    _register_contract(
        test_db,
        ownable_addr,
        "regular",
        current_block,
        monitoring_config={"watch_ownership": True, "watch_pause": False},
    )

    _cast_send(pausable_addr, "pause()", [], rpc_url, PRIVATE_KEY)
    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(ownable_addr, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)

    events = scan_for_events(test_db, rpc_url)

    event_types = [e.event_type for e in events]
    assert "ownership_transferred" in event_types
    assert "paused" not in event_types


# The cases share one anvil node; each flips ``is_active`` off so the next scan sees one active contract.


class _StateCase(NamedTuple):
    address: str
    contract_type: str
    monitoring_config: dict | None
    initial_state: dict
    steps: list[tuple[str, list[str], str, object]]


def _state_case_ownership_transfer(rpc_url: str, tmp_path: Path) -> _StateCase:
    addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    return _StateCase(
        addr,
        "regular",
        None,
        {"owner": ACCOUNT0.lower()},
        [("transferOwnership(address)", [new_owner], "owner", new_owner)],
    )


def _state_case_pause(rpc_url: str, tmp_path: Path) -> _StateCase:
    addr = _compile_and_deploy(PAUSABLE_SOURCE, "TestPausable", [], rpc_url, PRIVATE_KEY, tmp_path)
    return _StateCase(
        addr,
        "pausable",
        None,
        {},
        [("pause()", [], "paused", True), ("unpause()", [], "paused", False)],
    )


def _state_case_proxy_upgrade(rpc_url: str, tmp_path: Path) -> _StateCase:
    impl_v1 = _compile_and_deploy(IMPL_V1_SOURCE, "ImplV1", [], rpc_url, PRIVATE_KEY, tmp_path)
    impl_v2 = _compile_and_deploy(IMPL_V2_SOURCE, "ImplV2", [], rpc_url, PRIVATE_KEY, tmp_path)
    proxy_addr = _compile_and_deploy(PROXY_SOURCE, "TestProxy", [impl_v1], rpc_url, PRIVATE_KEY, tmp_path)
    return _StateCase(
        proxy_addr,
        "proxy",
        {"watch_upgrades": True, "watch_ownership": True},
        {"implementation": impl_v1.lower()},
        [("upgradeTo(address)", [impl_v2], "implementation", impl_v2)],
    )


def _state_case_threshold_change(rpc_url: str, tmp_path: Path) -> _StateCase:
    addr = _compile_and_deploy(SAFE_SOURCE, "TestSafe", [], rpc_url, PRIVATE_KEY, tmp_path)
    return _StateCase(
        addr,
        "safe",
        None,
        {"threshold": 1},
        [("changeThreshold(uint256)", ["3"], "threshold", 3)],
    )


def _state_case_delay_change(rpc_url: str, tmp_path: Path) -> _StateCase:
    addr = _compile_and_deploy(TIMELOCK_SOURCE, "TestTimelock", ["3600"], rpc_url, PRIVATE_KEY, tmp_path)
    return _StateCase(
        addr,
        "timelock",
        None,
        {"min_delay": 3600},
        [("updateDelay(uint256)", ["7200"], "min_delay", 7200)],
    )


_STATE_UPDATE_CASES = (
    _state_case_ownership_transfer,
    _state_case_pause,
    _state_case_proxy_upgrade,
    _state_case_threshold_change,
    _state_case_delay_change,
)


def _assert_state_value(case: str, state: dict, key: str, expected: object) -> None:
    """Identity for booleans, case-insensitive for addresses, equality for numbers."""
    actual = state.get(key)
    detail = f"[{case}] last_known_state[{key!r}] is {actual!r}, expected {expected!r}"
    if isinstance(expected, bool):
        assert actual is expected, detail
    elif isinstance(expected, str):
        assert isinstance(actual, str) and actual.lower() == expected.lower(), detail
    else:
        assert actual == expected, detail


def test_state_updated_after_event(anvil_env, test_db):
    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import scan_for_events

    for build_case in _STATE_UPDATE_CASES:
        name = build_case.__name__.removeprefix("_state_case_")
        case = build_case(rpc_url, tmp_path)
        current_block = int(_cast(["block-number"], rpc_url))

        mc = _register_contract(
            test_db,
            case.address,
            case.contract_type,
            current_block,
            monitoring_config=case.monitoring_config,
        )
        mc.last_known_state = dict(case.initial_state)
        test_db.commit()

        for signature, args, key, expected in case.steps:
            _cast_send(case.address, signature, args, rpc_url, PRIVATE_KEY)
            scan_for_events(test_db, rpc_url)
            test_db.refresh(mc)
            state = mc.last_known_state
            assert state is not None, f"[{name}] last_known_state was cleared"
            _assert_state_value(name, state, key, expected)

        mc.is_active = False
        test_db.commit()


def test_enrollment_config_produces_correct_detection(anvil_env, test_db):
    rpc_url, tmp_path = anvil_env
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

    addr = _compile_and_deploy(PAUSABLE_SOURCE, "TestPausable", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

    _register_contract(test_db, addr, ct, current_block, monitoring_config=config)

    _cast_send(addr, "pause()", [], rpc_url, PRIVATE_KEY)
    events = scan_for_events(test_db, rpc_url)

    assert len(events) == 1
    assert events[0].event_type == "paused"

    assert config.get("watch_upgrades") is False
    assert config.get("watch_safe_signers") is False


def test_notify_protocol_events_sends_discord(anvil_env, test_db):
    rpc_url, tmp_path = anvil_env
    from unittest.mock import patch

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

    sub = ProtocolSubscription(
        id=uuid.uuid4(),
        protocol_id=proto.id,
        discord_webhook_url="https://discord.com/api/webhooks/test/fake",
        label="test-sub",
    )
    test_db.add(sub)
    test_db.commit()

    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)

    # The scan delivers the notification itself.
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
    rpc_url, tmp_path = anvil_env
    from unittest.mock import MagicMock, patch

    from db.models import Protocol, ProtocolSubscription
    from services.monitoring.unified_watcher import scan_for_events

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

    sub = ProtocolSubscription(
        id=uuid.uuid4(),
        protocol_id=proto.id,
        discord_webhook_url="https://discord.com/api/webhooks/test/fake",
        event_filter={"event_types": ["paused"]},
    )
    test_db.add(sub)
    test_db.commit()

    _cast_send(pausable_addr, "pause()", [], rpc_url, PRIVATE_KEY)
    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(ownable_addr, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)

    with patch("services.monitoring.notifier.requests.post") as mock_post:
        mock_post.return_value = MagicMock(ok=True)
        events = scan_for_events(test_db, rpc_url)
        assert len(events) >= 2  # both detected in DB

        assert mock_post.call_count == 1
        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert "paused" in payload["embeds"][0]["title"]


def test_poll_detects_pause_state_change(anvil_env, test_db):
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

    events = poll_for_state_changes(test_db, rpc_url)
    assert len(events) == 0


def test_poll_suppressed_when_scan_already_detected_upgrade(anvil_env, test_db):
    """The scanner committed while the poller holds stale state."""
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

    _cast_send(proxy_addr, "upgradeTo(address)", [impl_v2], rpc_url, PRIVATE_KEY)

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

    poll_events = poll_for_state_changes(test_db, rpc_url)
    impl_changes = [e for e in poll_events if e.data and e.data.get("field") == "implementation"]
    assert len(impl_changes) == 0, "Poller should not create duplicate event when scanner already detected upgrade"


def test_poll_suppressed_when_scan_already_detected_ownership(anvil_env, test_db):
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

    _cast_send(proxy_addr, "upgradeTo(address)", [impl_v2], rpc_url, PRIVATE_KEY)

    poll_events = poll_for_state_changes(test_db, rpc_url)
    impl_changes = [e for e in poll_events if e.data and e.data.get("field") == "implementation"]
    assert len(impl_changes) == 1, "Poller should create event when no scanner event exists"


# Custom slots are visible to polling purely via analyzer-derived plan entries; first observation emits nothing;
# suppression derives from ``tracked_topics``; poll and event paths write the same state key.


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
    """The old poller hardcoded selectors, so ``protocolAdmin`` was invisible."""
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

    test_db.refresh(mc)
    state = mc.last_known_state or {}
    assert state.get("protocolAdmin", "").lower() == new_admin.lower()


def test_poll_custom_slot_first_observation_no_event(anvil_env, test_db):
    """A first read is not a change."""
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
    mc.last_known_state = {}
    test_db.commit()

    events = poll_for_state_changes(test_db, rpc_url)

    custom_events = [e for e in events if e.data and e.data.get("field") in ("protocolAdmin", "feeRecipient")]
    assert custom_events == [], f"first-observation should not emit events, got {[e.data for e in custom_events]}"

    test_db.refresh(mc)
    state = mc.last_known_state or {}
    assert state.get("protocolAdmin", "").lower() == ACCOUNT0.lower()
    assert state.get("feeRecipient", "").lower() == ACCOUNT0.lower()


def test_poll_suppressed_for_custom_slot_when_scanner_fires(anvil_env, test_db):
    """The old global suppression map covered only the five vendored fields."""
    from eth_utils.crypto import keccak

    rpc_url, tmp_path = anvil_env
    from services.monitoring.polling_plan import build_polling_plan
    from services.monitoring.unified_watcher import poll_for_state_changes

    addr = _compile_and_deploy(CUSTOM_ADMIN_SOURCE, "CustomAdminContract", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

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
    """Diverging keys would turn one mutation into two ghost entries; compound-style arg names force the "starts with
    new" heuristic.
    """
    from eth_utils.crypto import keccak

    rpc_url, tmp_path = anvil_env
    from services.monitoring.unified_watcher import poll_for_state_changes, scan_for_events

    addr = _compile_and_deploy(CUSTOM_ADMIN_SOURCE, "CustomAdminContract", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

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

    admin_b = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    _cast_send(addr, "setProtocolAdmin(address)", [admin_b], rpc_url, PRIVATE_KEY)
    scan_for_events(test_db, rpc_url)

    test_db.refresh(mc)
    state_after_event = dict(mc.last_known_state or {})
    assert state_after_event.get("protocolAdmin", "").lower() == admin_b.lower(), (
        f"event-side state write went to a different key — got state {state_after_event}"
    )
    # Keyed on the write target, not the ABI arg name.
    assert "newAdmin" not in state_after_event
    assert "newProtocolAdmin" not in state_after_event

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
    """No test-helper short-circuits."""
    from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
    from db.models import Contract, ContractMaterialization, Job, Protocol
    from services.monitoring.enrollment import enroll_protocol_contracts

    rpc_url, tmp_path = anvil_env
    addr = _compile_and_deploy(CUSTOM_ADMIN_SOURCE, "CustomAdminContract", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))  # noqa: F841 — block reference for parity with other tests

    code = _cast(["code", addr], rpc_url).strip()
    bytecode_keccak = "0x" + keccak_text(code if code.startswith("0x") else "0x" + code)

    # Anvil reuses deploy addresses and ``test_db`` leaves these rows, so stay idempotent.
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
            # Seeded at the current version so it stays visible after a schema bump.
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
    # The poll loop fails at dispatch without the precomputed selector.
    from services.monitoring.polling_plan import selector_for

    assert pa_entry["selector"] == selector_for("protocolAdmin")

    assert mc.needs_polling is True


def test_poll_custom_admin_slot_triggers_reanalysis_via_unified_vocab(anvil_env, test_db):
    """The old poll allowlist missed ``admin`` slots the event side already handled; both share one write-target set
    now.
    """
    rpc_url, tmp_path = anvil_env
    from services.monitoring.polling_plan import build_polling_plan
    from services.monitoring.unified_watcher import poll_for_state_changes

    addr = _compile_and_deploy(COMPOUND_ADMIN_SOURCE, "TestCompoundAdmin", [], rpc_url, PRIVATE_KEY, tmp_path)
    current_block = int(_cast(["block-number"], rpc_url))

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
    assert "newRecipient" not in state
    assert "newFeeRecipient" not in state


def keccak_text(text: str) -> str:
    from eth_utils.crypto import keccak

    if isinstance(text, str) and text.startswith("0x"):
        return keccak(hexstr=text).hex()
    return keccak(text=text).hex()


def _add_completed_job(session, address: str, protocol_id: int) -> None:
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
