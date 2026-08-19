"""Integration tests proving that governance events detected by the unified
watcher propagate to the relational database tables (Contract, ControllerValue,
UpgradeEvent) — not just MonitoredEvent / last_known_state.

Deploys contracts on Anvil, sets up full relational DB state (Protocol,
Contract, ControllerValue, UpgradeEvent, MonitoredContract), triggers
governance actions, scans, and asserts the relational tables are updated.

Requires:
  - anvil, cast, forge (from Foundry) on PATH
  - PostgreSQL (TEST_DATABASE_URL env var)

Run with:
    TEST_DATABASE_URL=postgresql://psat:psat@localhost:5433/psat_test \
        uv run pytest tests/monitoring/test_relational_sync.py -v --timeout=120
"""

from __future__ import annotations

import os
import shutil
import uuid

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from db.models import (
    Base,
    Contract,
    ControllerValue,
    Job,
    JobStage,
    JobStatus,
    MonitoredContract,
    Protocol,
    UpgradeEvent,
    WatchedProxy,
)
from schemas.control_tracking import MonitoredContractType
from tests.conftest import requires_postgres
from tests.support.anvil import (
    ACCOUNT0,
    IMPL_V1_SOURCE,
    IMPL_V2_SOURCE,
    OWNABLE_SOURCE,
    PRIVATE_KEY,
    _cast,
    _cast_send,
    _compile_and_deploy,
    anvil_env,  # noqa: F401
)

# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------

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

PROTO_NAME = "__test_relational_sync__"


@pytest.fixture(autouse=True)
def _disable_scan_confirmation_depth(monkeypatch):
    # These anvil chains are only a handful of blocks long; the production
    # 12-block confirmation clamp would hide every just-emitted event.
    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")


# ---------------------------------------------------------------------------
# Solidity sources
# ---------------------------------------------------------------------------

# Local variant: unlike the shared ``PROXY_SOURCE`` this one also owns the
# EIP-1967 admin slot, which these tests rotate via ``changeAdmin``.
PROXY_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TestProxy {
    bytes32 internal constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 internal constant _ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    event Upgraded(address indexed implementation);
    event AdminChanged(address previousAdmin, address newAdmin);

    constructor(address impl) {
        _setImplementation(impl);
        assembly { sstore(_ADMIN_SLOT, caller()) }
    }

    function upgradeTo(address newImpl) external {
        _setImplementation(newImpl);
    }

    function changeAdmin(address newAdmin) external {
        address prev;
        assembly { prev := sload(_ADMIN_SLOT) }
        assembly { sstore(_ADMIN_SLOT, newAdmin) }
        emit AdminChanged(prev, newAdmin);
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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def pg_session():
    """Full-schema PostgreSQL session. Cleans up test rows on teardown."""
    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine)
    session = Session(engine, expire_on_commit=False)
    try:
        yield session
    finally:
        session.rollback()
        proto = session.execute(select(Protocol).where(Protocol.name == PROTO_NAME)).scalar_one_or_none()
        if proto:
            for mc in session.execute(
                select(MonitoredContract).where(MonitoredContract.protocol_id == proto.id)
            ).scalars():
                if mc.watched_proxy_id:
                    wp = session.get(WatchedProxy, mc.watched_proxy_id)
                    if wp:
                        session.delete(wp)
                session.delete(mc)
            for j in session.execute(select(Job).where(Job.protocol_id == proto.id)).scalars():
                session.delete(j)
            for c in session.execute(select(Contract).where(Contract.protocol_id == proto.id)).scalars():
                session.delete(c)
            session.delete(proto)
        session.commit()
        session.close()
        engine.dispose()


def _setup_protocol(session: Session) -> Protocol:
    proto = Protocol(name=PROTO_NAME)
    session.add(proto)
    session.flush()
    return proto


def _setup_contract(
    session: Session,
    address: str,
    protocol: Protocol,
    *,
    is_proxy: bool = False,
    proxy_type: str | None = None,
    implementation: str | None = None,
    admin: str | None = None,
    name: str = "TestContract",
) -> Contract:
    contract = Contract(
        address=address,
        chain="ethereum",
        protocol_id=protocol.id,
        contract_name=name,
        is_proxy=is_proxy,
        proxy_type=proxy_type,
        implementation=implementation,
        admin=admin,
    )
    session.add(contract)
    session.flush()
    job = Job(
        address=address,
        protocol_id=protocol.id,
        status=JobStatus.completed,
        stage=JobStage.done,
    )
    session.add(job)
    session.flush()
    contract.job_id = job.id
    session.flush()
    return contract


def _setup_monitored(
    session: Session,
    contract: Contract,
    contract_type: MonitoredContractType,
    last_scanned_block: int,
    protocol: Protocol,
    *,
    watched_proxy_id: uuid.UUID | None = None,
    initial_state: dict | None = None,
) -> MonitoredContract:
    from services.monitoring.polling_plan import build_polling_plan

    # Match what enrollment would produce for these contract shapes so
    # tests that flip needs_polling=True after setup exercise the same
    # poll dispatch the production path uses.
    plan_proxy_type = (contract.proxy_type or None) or ("custom" if contract_type == "proxy" else None)
    tracking_plan: dict | None = None
    if contract_type in ("regular", "pausable", "proxy"):
        tracked: list[dict] = [
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
            },
        ]
        if contract_type == "pausable":
            tracked.append(
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
        tracking_plan = {"tracked_controllers": tracked}
    polling_plan = build_polling_plan(
        contract_type=contract_type,
        proxy_type=plan_proxy_type,
        tracking_plan=tracking_plan,
        tracked_topics=None,
    )
    config = {
        "watch_upgrades": contract_type == "proxy",
        "watch_ownership": True,
        "watch_pause": contract_type == "pausable",
        "watch_roles": contract_type == "role_control",
        "watch_safe_signers": contract_type == "safe",
        "watch_timelock": contract_type == "timelock",
        "polling_plan": polling_plan,
    }
    mc = MonitoredContract(
        id=uuid.uuid4(),
        address=contract.address.lower(),
        chain="ethereum",
        protocol_id=protocol.id,
        contract_id=contract.id,
        contract_type=contract_type,
        monitoring_config=config,
        last_known_state=initial_state or {},
        last_scanned_block=last_scanned_block,
        needs_polling=False,
        is_active=True,
        enrollment_source="auto",
        watched_proxy_id=watched_proxy_id,
    )
    session.add(mc)
    session.flush()
    return mc


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestUpgradeUpdatesContractTable:
    """Gap 1: Upgrade events must update Contract.implementation and create
    UpgradeEvent rows."""

    def test_upgrade_updates_contract_implementation(self, anvil_env, pg_session):
        """After scan detects an Upgraded event, Contract.implementation
        must reflect the new implementation address."""
        rpc_url, tmp_path = anvil_env
        from services.monitoring.unified_watcher import scan_for_events

        impl_v1 = _compile_and_deploy(IMPL_V1_SOURCE, "ImplV1", [], rpc_url, PRIVATE_KEY, tmp_path)
        impl_v2 = _compile_and_deploy(IMPL_V2_SOURCE, "ImplV2", [], rpc_url, PRIVATE_KEY, tmp_path)
        proxy_addr = _compile_and_deploy(PROXY_SOURCE, "TestProxy", [impl_v1], rpc_url, PRIVATE_KEY, tmp_path)
        current_block = int(_cast(["block-number"], rpc_url))

        proto = _setup_protocol(pg_session)
        contract = _setup_contract(
            pg_session,
            proxy_addr,
            proto,
            is_proxy=True,
            proxy_type="eip1967",
            implementation=impl_v1,
        )

        wp = WatchedProxy(
            id=uuid.uuid4(),
            proxy_address=proxy_addr,
            chain="ethereum",
            label="test-proxy",
            proxy_type="eip1967",
            last_known_implementation=impl_v1,
            last_scanned_block=current_block,
        )
        pg_session.add(wp)
        pg_session.flush()

        _setup_monitored(
            pg_session,
            contract,
            "proxy",
            current_block,
            proto,
            watched_proxy_id=wp.id,
            initial_state={"implementation": impl_v1},
        )
        pg_session.commit()

        # Upgrade the proxy
        _cast_send(proxy_addr, "upgradeTo(address)", [impl_v2], rpc_url, PRIVATE_KEY)

        events = scan_for_events(pg_session, rpc_url)
        assert any(e.event_type == "upgraded" for e in events)

        # --- The critical assertion: Contract.implementation must be updated ---
        pg_session.refresh(contract)
        assert contract.implementation is not None
        assert contract.implementation.lower() == impl_v2.lower(), (
            f"Contract.implementation was not updated: expected {impl_v2.lower()}, got {contract.implementation}"
        )

    def test_upgrade_creates_upgrade_event_row(self, anvil_env, pg_session):
        """After scan detects an Upgraded event, an UpgradeEvent row must
        be created in the relational table."""
        rpc_url, tmp_path = anvil_env
        from services.monitoring.unified_watcher import scan_for_events

        impl_v1 = _compile_and_deploy(IMPL_V1_SOURCE, "ImplV1", [], rpc_url, PRIVATE_KEY, tmp_path)
        impl_v2 = _compile_and_deploy(IMPL_V2_SOURCE, "ImplV2", [], rpc_url, PRIVATE_KEY, tmp_path)
        proxy_addr = _compile_and_deploy(PROXY_SOURCE, "TestProxy", [impl_v1], rpc_url, PRIVATE_KEY, tmp_path)
        current_block = int(_cast(["block-number"], rpc_url))

        proto = _setup_protocol(pg_session)
        contract = _setup_contract(
            pg_session,
            proxy_addr,
            proto,
            is_proxy=True,
            proxy_type="eip1967",
            implementation=impl_v1,
        )
        _setup_monitored(
            pg_session,
            contract,
            "proxy",
            current_block,
            proto,
            initial_state={"implementation": impl_v1},
        )
        pg_session.commit()

        _cast_send(proxy_addr, "upgradeTo(address)", [impl_v2], rpc_url, PRIVATE_KEY)
        scan_for_events(pg_session, rpc_url)

        # --- The critical assertion: UpgradeEvent row must exist ---
        ue_rows = (
            pg_session.execute(select(UpgradeEvent).where(UpgradeEvent.contract_id == contract.id)).scalars().all()
        )
        assert len(ue_rows) >= 1, "No UpgradeEvent row was created for the detected upgrade"
        latest = ue_rows[-1]
        assert latest.new_impl.lower() == impl_v2.lower()
        assert latest.old_impl is not None and latest.old_impl.lower() == impl_v1.lower()
        assert latest.proxy_address.lower() == proxy_addr.lower()


class TestAdminChangedPropagation:
    """Gap 2: AdminChanged events must update Contract.admin and
    MonitoredContract.last_known_state['admin']."""

    def test_admin_changed_updates_contract_admin(self, anvil_env, pg_session):
        """After scan detects AdminChanged, Contract.admin must be updated."""
        rpc_url, tmp_path = anvil_env
        from services.monitoring.unified_watcher import scan_for_events

        impl_v1 = _compile_and_deploy(IMPL_V1_SOURCE, "ImplV1", [], rpc_url, PRIVATE_KEY, tmp_path)
        proxy_addr = _compile_and_deploy(PROXY_SOURCE, "TestProxy", [impl_v1], rpc_url, PRIVATE_KEY, tmp_path)
        current_block = int(_cast(["block-number"], rpc_url))

        new_admin = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

        proto = _setup_protocol(pg_session)
        contract = _setup_contract(
            pg_session,
            proxy_addr,
            proto,
            is_proxy=True,
            proxy_type="eip1967",
            implementation=impl_v1,
            admin=ACCOUNT0,
        )
        mc = _setup_monitored(
            pg_session,
            contract,
            "proxy",
            current_block,
            proto,
            initial_state={"implementation": impl_v1, "admin": ACCOUNT0.lower()},
        )
        pg_session.commit()

        # Change admin
        _cast_send(proxy_addr, "changeAdmin(address)", [new_admin], rpc_url, PRIVATE_KEY)

        events = scan_for_events(pg_session, rpc_url)
        assert any(e.event_type == "admin_changed" for e in events)

        # --- Critical assertion: Contract.admin must be updated ---
        pg_session.refresh(contract)
        assert contract.admin is not None
        assert contract.admin.lower() == new_admin.lower(), (
            f"Contract.admin not updated: expected {new_admin.lower()}, got {contract.admin}"
        )

        # --- Critical assertion: last_known_state must track admin ---
        pg_session.refresh(mc)
        assert mc.last_known_state is not None
        assert mc.last_known_state.get("admin", "").lower() == new_admin.lower(), (
            "MonitoredContract.last_known_state['admin'] not updated"
        )


class TestOwnershipUpdatesControllerValue:
    """Gap 3: Ownership transfers must update ControllerValue rows."""

    def test_ownership_transfer_updates_controller_value(self, anvil_env, pg_session):
        """After scan detects OwnershipTransferred, the ControllerValue row
        for 'owner' must be updated to the new owner address."""
        rpc_url, tmp_path = anvil_env
        from services.monitoring.unified_watcher import scan_for_events

        addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
        current_block = int(_cast(["block-number"], rpc_url))
        new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

        proto = _setup_protocol(pg_session)
        contract = _setup_contract(pg_session, addr, proto, name="TestOwnable")

        # Set up initial ControllerValue for owner (as the resolution worker would)
        cv = ControllerValue(
            contract_id=contract.id,
            controller_id="owner",
            value=ACCOUNT0.lower(),
            resolved_type="eoa",
            source="owner()",
        )
        pg_session.add(cv)
        pg_session.flush()

        _setup_monitored(
            pg_session,
            contract,
            "regular",
            current_block,
            proto,
            initial_state={"owner": ACCOUNT0.lower()},
        )
        pg_session.commit()

        # Transfer ownership
        _cast_send(addr, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)

        events = scan_for_events(pg_session, rpc_url)
        assert any(e.event_type == "ownership_transferred" for e in events)

        # --- Critical assertion: ControllerValue must be updated ---
        pg_session.refresh(cv)
        assert cv.value is not None
        assert cv.value.lower() == new_owner.lower(), (
            f"ControllerValue 'owner' not updated: expected {new_owner.lower()}, got {cv.value}"
        )


class TestUpgradePollingUpdatesRelational:
    """Gap 4: Polling-detected implementation changes must also propagate
    to the Contract table and create UpgradeEvent rows."""

    def test_poll_upgrade_updates_contract_implementation(self, anvil_env, pg_session):
        """When poll_for_state_changes detects an implementation change,
        Contract.implementation must be updated."""
        rpc_url, tmp_path = anvil_env
        from services.monitoring.unified_watcher import poll_for_state_changes

        impl_v1 = _compile_and_deploy(IMPL_V1_SOURCE, "ImplV1", [], rpc_url, PRIVATE_KEY, tmp_path)
        impl_v2 = _compile_and_deploy(IMPL_V2_SOURCE, "ImplV2", [], rpc_url, PRIVATE_KEY, tmp_path)
        proxy_addr = _compile_and_deploy(PROXY_SOURCE, "TestProxy", [impl_v1], rpc_url, PRIVATE_KEY, tmp_path)
        current_block = int(_cast(["block-number"], rpc_url))

        proto = _setup_protocol(pg_session)
        # The PROXY_SOURCE writes to the EIP-1967 slot via assembly and
        # has no ``implementation()`` getter, so its proxy_type is
        # ``eip1967`` even though the test framing uses the word
        # "custom". The polling-plan builder reads proxy_type to pick
        # the right vendored entry (storage slot vs. getter call).
        contract = _setup_contract(
            pg_session,
            proxy_addr,
            proto,
            is_proxy=True,
            proxy_type="eip1967",
            implementation=impl_v1,
        )
        mc = _setup_monitored(
            pg_session,
            contract,
            "proxy",
            current_block,
            proto,
            initial_state={"implementation": impl_v1},
        )
        mc.needs_polling = True
        pg_session.commit()

        # Upgrade by calling the proxy's upgradeTo. The poll reads the
        # EIP-1967 slot directly — the storage-slot path is what the
        # ``eip1967`` vendored entry resolves to.
        _cast_send(proxy_addr, "upgradeTo(address)", [impl_v2], rpc_url, PRIVATE_KEY)

        events = poll_for_state_changes(pg_session, rpc_url)
        assert any(e.data and e.data.get("field") == "implementation" for e in events)

        # --- Critical assertion ---
        pg_session.refresh(contract)
        assert contract.implementation is not None
        assert contract.implementation.lower() == impl_v2.lower(), (
            f"Contract.implementation not updated by poll: expected {impl_v2.lower()}, got {contract.implementation}"
        )


class TestPollOwnershipUpdatesControllerValue:
    """Gap 5: Polling-detected ownership changes must update ControllerValue."""

    def test_poll_ownership_updates_controller_value(self, anvil_env, pg_session):
        """When poll_for_state_changes detects an owner change,
        ControllerValue must be updated."""
        rpc_url, tmp_path = anvil_env
        from services.monitoring.unified_watcher import poll_for_state_changes

        addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
        current_block = int(_cast(["block-number"], rpc_url))
        new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

        proto = _setup_protocol(pg_session)
        contract = _setup_contract(pg_session, addr, proto, name="TestOwnable")

        cv = ControllerValue(
            contract_id=contract.id,
            controller_id="owner",
            value=ACCOUNT0.lower(),
            resolved_type="eoa",
            source="owner()",
        )
        pg_session.add(cv)
        pg_session.flush()

        mc = _setup_monitored(
            pg_session,
            contract,
            "regular",
            current_block,
            proto,
            initial_state={"owner": ACCOUNT0.lower()},
        )
        mc.needs_polling = True
        pg_session.commit()

        _cast_send(addr, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)

        events = poll_for_state_changes(pg_session, rpc_url)
        assert any(e.data and e.data.get("field") == "owner" for e in events)

        # --- Critical assertion ---
        pg_session.refresh(cv)
        assert cv.value is not None
        assert cv.value.lower() == new_owner.lower(), (
            f"ControllerValue 'owner' not updated by poll: expected {new_owner.lower()}, got {cv.value}"
        )
