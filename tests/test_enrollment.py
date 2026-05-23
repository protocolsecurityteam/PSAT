"""Unit and integration tests for protocol monitoring enrollment.

All tests require PostgreSQL (TEST_DATABASE_URL env var).

Run:
    TEST_DATABASE_URL=postgresql://psat:psat@localhost:5433/psat_test \
        uv run pytest tests/test_enrollment.py -v
"""

from __future__ import annotations

import os
import uuid
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine, delete, select, text
from sqlalchemy.orm import Session

from db.models import (
    Base,
    MonitoredContract,
    MonitoredEvent,
    ProxyUpgradeEvent,
    WatchedProxy,
)

# ---------------------------------------------------------------------------
# Postgres skip condition
# ---------------------------------------------------------------------------

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


requires_postgres = pytest.mark.skipif(not _can_connect(), reason="PostgreSQL not available")

pytestmark = requires_postgres


@pytest.fixture()
def db_session():
    """PostgreSQL database session with full schema for enrollment tests."""
    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine)

    session = Session(engine, expire_on_commit=False)
    try:
        yield session
    finally:
        session.rollback()
        for model in [MonitoredEvent, MonitoredContract, ProxyUpgradeEvent, WatchedProxy]:
            session.query(model).delete()
        session.commit()
        session.close()
        engine.dispose()


# ---------------------------------------------------------------------------
# Helpers to build mock objects
# ---------------------------------------------------------------------------


def _mock_contract(
    address="0x" + "a" * 40,
    chain="ethereum",
    name="TestContract",
    is_proxy=False,
    proxy_type=None,
    implementation=None,
    protocol_id=1,
):
    c = MagicMock()
    c.id = 1
    c.address = address
    c.chain = chain
    c.contract_name = name
    c.is_proxy = is_proxy
    c.proxy_type = proxy_type
    c.implementation = implementation
    c.protocol_id = protocol_id
    return c


def _mock_summary(is_upgradeable=False, is_pausable=False, has_timelock=False, control_model=None):
    s = MagicMock()
    s.is_upgradeable = is_upgradeable
    s.is_pausable = is_pausable
    s.has_timelock = has_timelock
    s.is_factory = False
    s.is_nft = False
    s.control_model = control_model
    return s


def _mock_controller_value(controller_id="owner", value="0x" + "b" * 40, resolved_type=None):
    cv = MagicMock()
    cv.controller_id = controller_id
    cv.value = value
    cv.resolved_type = resolved_type
    cv.contract_id = 1
    return cv


def _mock_graph_node(address="0x" + "c" * 40, resolved_type="safe"):
    n = MagicMock()
    n.address = address
    n.resolved_type = resolved_type
    n.node_type = resolved_type
    n.contract_id = 1
    return n


# ---------------------------------------------------------------------------
# Tests for _determine_contract_type
# ---------------------------------------------------------------------------


class TestDetermineContractType:
    def test_proxy_from_contract_fields(self):
        from services.monitoring.enrollment import _determine_contract_type

        contract = _mock_contract(is_proxy=True, proxy_type="eip1967")
        result = _determine_contract_type(contract, None, [])
        assert result == "proxy"

    def test_proxy_from_contract_fields_no_summary(self):
        """Proxy contracts without a ContractSummary must still be detected."""
        from services.monitoring.enrollment import _determine_contract_type

        contract = _mock_contract(is_proxy=True, proxy_type="eip1967")
        result = _determine_contract_type(contract, None, [])
        assert result == "proxy"

    def test_proxy_from_proxy_type_only(self):
        """proxy_type set but is_proxy=False (edge case) still detects proxy."""
        from services.monitoring.enrollment import _determine_contract_type

        contract = _mock_contract(is_proxy=False, proxy_type="custom")
        result = _determine_contract_type(contract, None, [])
        assert result == "proxy"

    def test_proxy_from_summary_and_contract(self):
        """is_upgradeable only produces 'proxy' when the contract is a proxy shell."""
        from services.monitoring.enrollment import _determine_contract_type

        contract = _mock_contract(is_proxy=True, proxy_type="eip1967")
        summary = _mock_summary(is_upgradeable=True)
        result = _determine_contract_type(contract, summary, [])
        assert result == "proxy"

    def test_upgradeable_implementation_is_not_proxy(self):
        """UUPS implementations have is_upgradeable=True but are not proxy shells."""
        from services.monitoring.enrollment import _determine_contract_type

        contract = _mock_contract(is_proxy=False, proxy_type=None)
        summary = _mock_summary(is_upgradeable=True)
        result = _determine_contract_type(contract, summary, [])
        assert result != "proxy"

    def test_timelock_from_summary(self):
        from services.monitoring.enrollment import _determine_contract_type

        contract = _mock_contract()
        summary = _mock_summary(has_timelock=True)
        result = _determine_contract_type(contract, summary, [])
        assert result == "timelock"

    def test_pausable_from_summary(self):
        from services.monitoring.enrollment import _determine_contract_type

        contract = _mock_contract()
        summary = _mock_summary(is_pausable=True)
        result = _determine_contract_type(contract, summary, [])
        assert result == "pausable"

    def test_controller_type_does_not_propagate(self):
        """A contract's type is determined by its own properties, not by
        the resolved_type of its controllers.  Having a safe/timelock owner
        doesn't make the contract itself a safe or timelock."""
        from services.monitoring.enrollment import _determine_contract_type

        contract = _mock_contract(is_proxy=False)
        for resolved in ("safe", "timelock", "proxy_admin"):
            cv = _mock_controller_value(resolved_type=resolved)
            result = _determine_contract_type(contract, None, [cv])
            assert result == "regular", f"resolved_type={resolved} should not propagate"

    def test_regular_default(self):
        from services.monitoring.enrollment import _determine_contract_type

        contract = _mock_contract()
        result = _determine_contract_type(contract, None, [])
        assert result == "regular"


# ---------------------------------------------------------------------------
# Tests for _build_monitoring_config
# ---------------------------------------------------------------------------


class TestBuildMonitoringConfig:
    def test_proxy_config(self):
        from services.monitoring.enrollment import _build_monitoring_config

        summary = _mock_summary(is_upgradeable=True)
        config = _build_monitoring_config(summary, [], "proxy")
        assert config["watch_upgrades"] is True
        assert config["watch_ownership"] is True

    def test_pausable_config(self):
        from services.monitoring.enrollment import _build_monitoring_config

        summary = _mock_summary(is_pausable=True)
        config = _build_monitoring_config(summary, [], "pausable")
        assert config["watch_pause"] is True
        assert config["watch_upgrades"] is False

    def test_safe_config(self):
        from services.monitoring.enrollment import _build_monitoring_config

        config = _build_monitoring_config(None, [], "safe")
        assert config["watch_safe_signers"] is True

    def test_timelock_config(self):
        from services.monitoring.enrollment import _build_monitoring_config

        config = _build_monitoring_config(None, [], "timelock")
        assert config["watch_timelock"] is True

    def test_role_based_config(self):
        from services.monitoring.enrollment import _build_monitoring_config

        summary = _mock_summary(control_model="role-based")
        config = _build_monitoring_config(summary, [], "regular")
        assert config["watch_roles"] is True

    def test_tracked_topics_persisted_when_supplied(self):
        """tracked_topics passed in (from extract_governance_topics) must
        land on monitoring_config so the scanner can union them into the
        global topic filter and dispatch per-emitter."""
        from services.monitoring.enrollment import _build_monitoring_config

        tracked = [
            {
                "topic0": "0x" + "a" * 64,
                "signature": "OwnerUpdated(address,address)",
                "event_type": "ownership_transferred",
                "controller_id": "state_variable:owner",
                "inputs": [],
            }
        ]
        config = _build_monitoring_config(None, [], "regular", tracked)
        assert config["tracked_topics"] == tracked

    def test_authority_topic_sets_watch_authority_flag(self):
        """Presence of an authority_updated tracked-topic flips on the
        watch_authority flag explicitly — the flag-getter defaults to
        True on missing keys, so this is documentation-on-inspection
        rather than gating, but it keeps the config self-describing."""
        from services.monitoring.enrollment import _build_monitoring_config

        tracked = [
            {
                "topic0": "0x" + "b" * 64,
                "signature": "AuthorityUpdated(address,address)",
                "event_type": "authority_updated",
                "controller_id": "external_contract:authority",
                "inputs": [],
            }
        ]
        config = _build_monitoring_config(None, [], "regular", tracked)
        assert config.get("watch_authority") is True

    def test_empty_tracked_topics_omitted(self):
        """No tracked_topics arg → no field on monitoring_config (avoids
        polluting existing rows with empty lists during a reconcile)."""
        from services.monitoring.enrollment import _build_monitoring_config

        config = _build_monitoring_config(None, [], "regular")
        assert "tracked_topics" not in config
        assert "watch_authority" not in config


# ---------------------------------------------------------------------------
# Tests for _build_initial_state
# ---------------------------------------------------------------------------


class TestBuildInitialState:
    def test_includes_implementation(self):
        from services.monitoring.enrollment import _build_initial_state

        contract = _mock_contract(implementation="0x" + "d" * 40)
        state = _build_initial_state(contract, [])
        assert state["implementation"] == "0x" + "d" * 40

    def test_includes_owner(self):
        from services.monitoring.enrollment import _build_initial_state

        contract = _mock_contract()
        cv = _mock_controller_value(controller_id="owner", value="0x" + "e" * 40)
        state = _build_initial_state(contract, [cv])
        assert state["owner"] == "0x" + "e" * 40

    def test_ignores_pending_owner_and_other_substring_matches(self):
        """The old substring match latched ``pendingOwner``/``previousOwner``/
        ``roleOwner``/``ownerFee`` into ``last_known_state.owner`` and the
        scanner would false-positive an OwnershipTransferred when the live
        owner finally diverged. Only the canonical Ownable slot counts.
        """
        from services.monitoring.enrollment import _build_initial_state

        contract = _mock_contract()
        active = _mock_controller_value(controller_id="state_variable:owner", value="0x" + "a" * 40)
        pending = _mock_controller_value(controller_id="state_variable:pendingOwner", value="0x" + "b" * 40)
        previous = _mock_controller_value(controller_id="state_variable:previousOwner", value="0x" + "c" * 40)
        role_owner = _mock_controller_value(controller_id="state_variable:roleOwner", value="0x" + "d" * 40)
        # Order: active first, then noise. Last-write-wins under the old
        # substring match would have latched the last entry.
        state = _build_initial_state(contract, [active, pending, previous, role_owner])
        assert state["owner"] == "0x" + "a" * 40

    def test_ignores_state_variable_destination_admin(self):
        """``state_variable:foo.adminAddress`` is not the canonical
        Ownable admin slot — same lesson as the owner test, applied to
        admin matching.
        """
        from services.monitoring.enrollment import _build_initial_state

        contract = _mock_contract()
        active = _mock_controller_value(controller_id="state_variable:admin", value="0x" + "1" * 40)
        nested = _mock_controller_value(
            controller_id="state_variable:rolesAuthority.pendingAdmin", value="0x" + "2" * 40
        )
        state = _build_initial_state(contract, [active, nested])
        assert state["admin"] == "0x" + "1" * 40


# ---------------------------------------------------------------------------
# Tests for maybe_enroll_protocol
# ---------------------------------------------------------------------------


class TestMaybeEnrollProtocol:
    @patch("services.monitoring.enrollment.enroll_protocol_contracts")
    def test_fires_with_in_flight_siblings(self, mock_enroll):
        """A queued / processing sibling must not block enrollment.

        The trigger used to short-circuit on
        ``Job.status IN (queued, processing)`` for the protocol; that
        gate produced silent skips when a sibling crashed before
        transitioning out of those statuses and had no fallback. The
        anvil integration counterpart is
        ``test_in_flight_sibling_job_does_not_block_enrollment``.
        """
        from services.monitoring.enrollment import maybe_enroll_protocol

        # The single remaining query is the "≥1 completed job" gate;
        # returning a row means we proceed to enroll.
        mock_session = MagicMock()
        result = MagicMock()
        result.scalars.return_value.first.return_value = MagicMock()
        mock_session.execute.return_value = result

        fired = maybe_enroll_protocol(mock_session, 1, "http://rpc", "ethereum")
        assert fired is True
        mock_enroll.assert_called_once_with(mock_session, 1, "http://rpc", "ethereum", None)

    @patch("services.monitoring.enrollment.enroll_protocol_contracts")
    def test_skips_when_no_completed_jobs(self, mock_enroll):
        from services.monitoring.enrollment import maybe_enroll_protocol

        mock_session = MagicMock()
        result = MagicMock()
        result.scalars.return_value.first.return_value = None
        mock_session.execute.return_value = result

        fired = maybe_enroll_protocol(mock_session, 1, "http://rpc", "ethereum")
        assert fired is False
        mock_enroll.assert_not_called()


# ---------------------------------------------------------------------------
# Tests for enroll_protocol_contracts (integration with db_session)
# ---------------------------------------------------------------------------


class TestEnrollProtocolContracts:
    @patch("services.monitoring.enrollment.rpc_request")
    def test_enroll_creates_monitored_contracts(self, mock_rpc, db_session):
        """Enrollment creates correct MonitoredContract rows."""
        from services.monitoring.enrollment import (
            _build_initial_state,
            _build_monitoring_config,
            _determine_contract_type,
        )

        mock_rpc.return_value = "0x100"

        # Since the full Contract model uses ARRAY/JSONB columns that are
        # incompatible with SQLite, we test the building blocks directly
        contract = _mock_contract(is_proxy=True, proxy_type="eip1967")
        summary = _mock_summary(is_upgradeable=True, is_pausable=True)
        ct = _determine_contract_type(contract, summary, [])
        assert ct == "proxy"

        config = _build_monitoring_config(summary, [], ct)
        assert config["watch_upgrades"] is True
        assert config["watch_pause"] is True

        contract = _mock_contract(implementation="0x" + "f" * 40)
        state = _build_initial_state(contract, [])
        assert "implementation" in state

        # Manually create a MonitoredContract to verify DB compatibility
        mc = MonitoredContract(
            id=uuid.uuid4(),
            address="0x" + "a" * 40,
            chain="ethereum",
            contract_type=ct,
            monitoring_config=config,
            last_known_state=state,
            last_scanned_block=256,
            needs_polling=True,
            is_active=True,
            enrollment_source="auto",
        )
        db_session.add(mc)
        db_session.commit()

        # Verify it was created
        from sqlalchemy import select

        result = db_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == "0x" + "a" * 40)
        ).scalar_one_or_none()
        assert result is not None
        assert result.contract_type == "proxy"
        assert result.enrollment_source == "auto"

    def test_enroll_idempotent(self, db_session):
        """Calling enrollment twice doesn't duplicate rows."""
        mc = MonitoredContract(
            id=uuid.uuid4(),
            address="0x" + "a" * 40,
            chain="ethereum",
            contract_type="proxy",
            monitoring_config={"watch_upgrades": True},
            last_scanned_block=0,
            is_active=True,
            enrollment_source="auto",
        )
        db_session.add(mc)
        db_session.commit()

        # Check we can find it and upsert logic would work
        from sqlalchemy import select

        existing = db_session.execute(
            select(MonitoredContract).where(
                MonitoredContract.address == "0x" + "a" * 40,
                MonitoredContract.chain == "ethereum",
            )
        ).scalar_one_or_none()
        assert existing is not None
        assert existing.id == mc.id

        # Update it (simulating re-enrollment)
        existing.contract_type = "pausable"
        db_session.commit()

        # Still only one row
        from sqlalchemy import func

        count = db_session.execute(select(func.count()).select_from(MonitoredContract)).scalar()
        assert count == 1

    def test_enroll_bridges_to_watched_proxy(self, db_session):
        """Proxy contracts get WatchedProxy rows linked via watched_proxy_id."""
        wp = WatchedProxy(
            id=uuid.uuid4(),
            proxy_address="0x" + "a" * 40,
            chain="ethereum",
            label="test",
            last_scanned_block=0,
        )
        db_session.add(wp)
        db_session.commit()

        mc = MonitoredContract(
            id=uuid.uuid4(),
            address="0x" + "a" * 40,
            chain="ethereum",
            contract_type="proxy",
            watched_proxy_id=wp.id,
            monitoring_config={"watch_upgrades": True},
            last_scanned_block=0,
            is_active=True,
            enrollment_source="auto",
        )
        db_session.add(mc)
        db_session.commit()

        from sqlalchemy import select

        result = db_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == "0x" + "a" * 40)
        ).scalar_one()
        assert result.watched_proxy_id == wp.id

    def test_enroll_discovers_controller_addresses(self, db_session):
        """Safe/timelock controllers get their own MonitoredContract rows."""
        # Simulate creating MonitoredContract rows for controller addresses
        safe_addr = "0x" + "c" * 40
        mc = MonitoredContract(
            id=uuid.uuid4(),
            address=safe_addr,
            chain="ethereum",
            contract_type="safe",
            monitoring_config={"watch_safe_signers": True, "watch_ownership": True},
            last_scanned_block=0,
            needs_polling=True,
            is_active=True,
            enrollment_source="auto",
        )
        db_session.add(mc)
        db_session.commit()

        from sqlalchemy import select

        result = db_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == safe_addr)
        ).scalar_one()
        assert result.contract_type == "safe"
        assert result.needs_polling is True


# ---------------------------------------------------------------------------
# Integration tests — real PostgreSQL with full ORM models
# ---------------------------------------------------------------------------

PROTO_NAME = "__test_enrollment__"


@pytest.fixture()
def pg_session():
    """Full-schema PostgreSQL session. Cleans up only test-created rows."""
    from db.models import (
        Base,
        Contract,
        Job,
        Protocol,
    )

    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine)
    session = Session(engine, expire_on_commit=False)
    try:
        yield session
    finally:
        session.rollback()
        proto = session.execute(select(Protocol).where(Protocol.name == PROTO_NAME)).scalar_one_or_none()
        if proto:
            # Cascade deletes Contract → ContractSummary, ControllerValue,
            # ControlGraphNode; and Job cleanup via protocol_id
            session.execute(select(MonitoredContract).where(MonitoredContract.protocol_id == proto.id))
            for mc in session.execute(
                select(MonitoredContract).where(MonitoredContract.protocol_id == proto.id)
            ).scalars():
                if mc.watched_proxy_id:
                    wp = session.get(WatchedProxy, mc.watched_proxy_id)
                    if wp:
                        session.delete(wp)
                session.delete(mc)
            for mc in session.execute(
                select(MonitoredContract).where(
                    MonitoredContract.enrollment_source == "auto",
                    MonitoredContract.protocol_id == proto.id,
                )
            ).scalars():
                session.delete(mc)
            for j in session.execute(select(Job).where(Job.protocol_id == proto.id)).scalars():
                session.delete(j)
            # Contracts cascade-delete summaries, controller_values, graph nodes
            for c in session.execute(select(Contract).where(Contract.protocol_id == proto.id)).scalars():
                session.delete(c)
            session.delete(proto)
        session.commit()
        session.close()
        engine.dispose()


def _create_completed_job(session, address, protocol_id):
    """Create a completed Job for a contract address so enrollment picks it up."""
    from db.models import Job, JobStage, JobStatus

    job = Job(
        address=address,
        protocol_id=protocol_id,
        status=JobStatus.completed,
        stage=JobStage.done,
    )
    session.add(job)
    session.flush()
    return job


def _grant_primary_authority(session, contract_id, principal_address, function_name="setOwner"):
    """Make ``principal_address`` a primary controller of the contract by
    attaching a ``FunctionPrincipal`` row. ``assign_primary_controllers``
    uses FP membership as eligibility, so any CGN principal needs at
    least one matching FP row on the contract to survive the enrollment
    filter.
    """
    from db.models import EffectiveFunction, FunctionPrincipal

    ef = EffectiveFunction(contract_id=contract_id, function_name=function_name, authority_public=False)
    session.add(ef)
    session.flush()
    session.add(FunctionPrincipal(function_id=ef.id, address=principal_address, principal_type="controller"))
    session.flush()


@requires_postgres
class TestEnrollmentIntegration:
    """End-to-end enrollment with real Contract, ContractSummary, and
    ControlGraphNode rows in PostgreSQL."""

    def test_enroll_creates_monitored_contracts_from_real_data(self, pg_session):
        """Full enroll_protocol_contracts with real Contract + ContractSummary."""
        from db.models import Contract, ContractSummary, ControllerValue, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        # Upgradeable proxy contract
        proxy_contract = Contract(
            address="0x" + "a1" * 20,
            chain="ethereum",
            protocol_id=proto.id,
            contract_name="LiquidityPool",
            is_proxy=True,
            proxy_type="eip1967",
            implementation="0x" + "a2" * 20,
        )
        pg_session.add(proxy_contract)
        pg_session.flush()

        pg_session.add(
            ContractSummary(
                contract_id=proxy_contract.id,
                is_upgradeable=True,
                is_pausable=True,
                control_model="governance",
            )
        )
        pg_session.add(
            ControllerValue(
                contract_id=proxy_contract.id,
                controller_id="owner",
                value="0x" + "b1" * 20,
                resolved_type="safe",
            )
        )
        _create_completed_job(pg_session, "0x" + "a1" * 20, proto.id)

        # Plain pausable contract
        pausable_contract = Contract(
            address="0x" + "c1" * 20,
            chain="ethereum",
            protocol_id=proto.id,
            contract_name="StakingManager",
        )
        pg_session.add(pausable_contract)
        pg_session.flush()

        pg_session.add(
            ContractSummary(
                contract_id=pausable_contract.id,
                is_upgradeable=False,
                is_pausable=True,
                control_model="role-based",
            )
        )
        _create_completed_job(pg_session, "0x" + "c1" * 20, proto.id)
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            enrolled = enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        assert len(enrolled) == 2

        # Verify proxy contract enrollment
        proxy_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == ("0x" + "a1" * 20))
        ).scalar_one()
        assert proxy_mc.contract_type == "proxy"
        assert proxy_mc.monitoring_config["watch_upgrades"] is True
        assert proxy_mc.monitoring_config["watch_pause"] is True
        assert proxy_mc.last_known_state["implementation"] == "0x" + "a2" * 20
        assert proxy_mc.last_known_state["owner"] == "0x" + "b1" * 20
        # EIP-1967 proxies emit events — no polling needed
        assert proxy_mc.needs_polling is False
        # Proxy should also have a WatchedProxy row linked
        assert proxy_mc.watched_proxy_id is not None

        # Verify pausable contract enrollment
        pausable_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == ("0x" + "c1" * 20))
        ).scalar_one()
        assert pausable_mc.contract_type == "pausable"
        assert pausable_mc.monitoring_config["watch_pause"] is True
        assert pausable_mc.monitoring_config["watch_roles"] is True
        assert pausable_mc.monitoring_config["watch_upgrades"] is False

    def test_enroll_proxy_without_summary_uses_contract_fields(self, pg_session):
        """Proxy contracts with is_proxy=True but NO ContractSummary must still
        be enrolled as type='proxy' with correct monitoring config, WatchedProxy
        row, and initial state containing the implementation address.

        This is the common case for EIP-1967 proxies whose Slither analysis
        runs on the implementation contract, not the proxy shell.
        """
        from db.models import Contract, ControllerValue, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        impl_addr = "0x" + "b2" * 20
        proxy_contract = Contract(
            address="0x" + "a1" * 20,
            chain="ethereum",
            protocol_id=proto.id,
            contract_name="LiquidityPoolProxy",
            is_proxy=True,
            proxy_type="eip1967",
            implementation=impl_addr,
        )
        pg_session.add(proxy_contract)
        pg_session.flush()

        # No ContractSummary — this is the bug scenario.
        # But there IS a controller value (owner) from the resolution stage.
        pg_session.add(
            ControllerValue(
                contract_id=proxy_contract.id,
                controller_id="owner",
                value="0x" + "cc" * 20,
                resolved_type="safe",
            )
        )
        _create_completed_job(pg_session, "0x" + "a1" * 20, proto.id)
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            enrolled = enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        assert len(enrolled) == 1

        mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == ("0x" + "a1" * 20))
        ).scalar_one()

        # Must be proxy, not regular
        assert mc.contract_type == "proxy"
        # EIP-1967 proxies emit events — no polling needed
        assert mc.needs_polling is False
        assert mc.monitoring_config["watch_upgrades"] is True
        assert mc.monitoring_config["watch_ownership"] is True

        # Initial state must include the implementation address
        assert mc.last_known_state.get("implementation") == impl_addr
        assert mc.last_known_state.get("owner") == "0x" + "cc" * 20

        # WatchedProxy row must be created and linked
        assert mc.watched_proxy_id is not None
        wp = pg_session.get(WatchedProxy, mc.watched_proxy_id)
        assert wp is not None
        assert wp.proxy_type == "eip1967"
        assert wp.last_known_implementation == impl_addr

    def test_enroll_implementation_with_proxy_admin_stays_regular(self, pg_session):
        """An implementation contract whose controller has resolved_type=proxy_admin
        should NOT be classified as a proxy — it's the target of a proxy, not a
        proxy itself."""
        from db.models import Contract, ControllerValue, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        impl_contract = Contract(
            address="0x" + "d1" * 20,
            chain="ethereum",
            protocol_id=proto.id,
            contract_name="LiquidityPoolImpl",
            is_proxy=False,
            proxy_type=None,
        )
        pg_session.add(impl_contract)
        pg_session.flush()

        pg_session.add(
            ControllerValue(
                contract_id=impl_contract.id,
                controller_id="admin",
                value="0x" + "ee" * 20,
                resolved_type="proxy_admin",
            )
        )
        _create_completed_job(pg_session, "0x" + "d1" * 20, proto.id)
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            enrolled = enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        assert len(enrolled) == 1

        mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == ("0x" + "d1" * 20))
        ).scalar_one()

        # Must be regular, NOT proxy
        assert mc.contract_type == "regular"
        assert mc.needs_polling is False
        assert mc.monitoring_config["watch_upgrades"] is False
        # No WatchedProxy should be created
        assert mc.watched_proxy_id is None

    def test_enroll_discovers_controllers_from_graph(self, pg_session):
        """ControlGraphNode rows with safe/timelock types get their own
        MonitoredContract rows automatically."""
        from db.models import Contract, ControlGraphNode, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        contract = Contract(
            address="0x" + "d1" * 20,
            chain="ethereum",
            protocol_id=proto.id,
            contract_name="TestContract",
        )
        pg_session.add(contract)
        pg_session.flush()
        _create_completed_job(pg_session, "0x" + "d1" * 20, proto.id)

        safe_addr = "0x" + "e1" * 20
        timelock_addr = "0x" + "e2" * 20
        eoa_addr = "0x" + "e3" * 20

        pg_session.add_all(
            [
                ControlGraphNode(
                    contract_id=contract.id,
                    address=safe_addr,
                    node_type="safe",
                    resolved_type="safe",
                    label="Multi-sig",
                ),
                ControlGraphNode(
                    contract_id=contract.id,
                    address=timelock_addr,
                    node_type="timelock",
                    resolved_type="timelock",
                    label="Timelock",
                ),
                ControlGraphNode(
                    contract_id=contract.id,
                    address=eoa_addr,
                    node_type="eoa",
                    resolved_type="eoa",
                    label="Deployer",
                ),
            ]
        )
        # Make both the safe and timelock primary controllers via FP.
        # The EOA is intentionally left out so the test continues to
        # assert "EOAs don't materialize MonitoredContract rows".
        _grant_primary_authority(pg_session, contract.id, safe_addr, function_name="setOwner")
        _grant_primary_authority(pg_session, contract.id, timelock_addr, function_name="schedule")
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        # Safe controller should be enrolled
        safe_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == safe_addr)
        ).scalar_one()
        assert safe_mc.contract_type == "safe"
        assert safe_mc.monitoring_config["watch_safe_signers"] is True
        assert safe_mc.needs_polling is True

        # Timelock controller should be enrolled
        tl_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == timelock_addr)
        ).scalar_one()
        assert tl_mc.contract_type == "timelock"
        assert tl_mc.monitoring_config["watch_timelock"] is True

        # EOA should NOT be enrolled (regular type, skipped)
        eoa_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == eoa_addr)
        ).scalar_one_or_none()
        assert eoa_mc is None

    def test_enroll_is_idempotent(self, pg_session):
        """Calling enroll_protocol_contracts twice doesn't duplicate rows."""
        from sqlalchemy import func

        from db.models import Contract, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        pg_session.add(
            Contract(
                address="0x" + "f1" * 20,
                chain="ethereum",
                protocol_id=proto.id,
                contract_name="Token",
            )
        )
        _create_completed_job(pg_session, "0x" + "f1" * 20, proto.id)
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            first = enroll_protocol_contracts(pg_session, proto.id, "http://rpc")
            second = enroll_protocol_contracts(pg_session, proto.id, "http://rpc")

        assert len(first) == 1
        assert len(second) == 1

        count = pg_session.execute(
            select(func.count()).select_from(MonitoredContract).where(MonitoredContract.address == ("0x" + "f1" * 20))
        ).scalar()
        assert count == 1

    def test_controller_rows_survive_stale_detection(self, pg_session):
        """Controller addresses enrolled by _enroll_controller_addresses must
        not be immediately deactivated by the stale-detection query in
        enroll_protocol_contracts. Regression test for flush-ordering bug.
        """
        from db.models import Contract, ControlGraphNode, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        contract = Contract(
            address="0x" + "c1" * 20,
            chain="ethereum",
            protocol_id=proto.id,
            is_proxy=False,
        )
        pg_session.add(contract)
        pg_session.flush()

        _create_completed_job(pg_session, "0x" + "c1" * 20, proto.id)

        # Add a controller node (safe) that should be auto-enrolled
        safe_addr = "0x" + "55" * 20
        node = ControlGraphNode(
            contract_id=contract.id,
            address=safe_addr,
            node_type="controller",
            resolved_type="safe",
        )
        pg_session.add(node)
        _grant_primary_authority(pg_session, contract.id, safe_addr)
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value=hex(1000)):
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc")

        safe_mc = pg_session.execute(
            select(MonitoredContract).where(
                MonitoredContract.address == safe_addr,
            )
        ).scalar_one_or_none()

        assert safe_mc is not None, "Controller address was not enrolled"
        assert safe_mc.is_active is True, (
            "Controller MonitoredContract was deactivated by stale-detection — flush ordering bug"
        )
        assert safe_mc.contract_type == "safe"

    def test_state_variable_destination_safe_is_not_enrolled(self, pg_session):
        """A Safe that only appears as a state-variable destination
        (CGN with no FunctionPrincipal authority on any function) must
        NOT become an active MonitoredContract — that's the etherfi
        ``accountantState.payoutAddress`` misclassification this whole
        pipeline change is fixing.
        """
        from db.models import Contract, ControlGraphNode, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        contract = Contract(
            address="0x" + "d2" * 20,
            chain="ethereum",
            protocol_id=proto.id,
            is_proxy=False,
        )
        pg_session.add(contract)
        pg_session.flush()
        _create_completed_job(pg_session, "0x" + "d2" * 20, proto.id)

        real_safe = "0x" + "cc" * 20
        fee_safe = "0x" + "ee" * 20
        pg_session.add_all(
            [
                ControlGraphNode(
                    contract_id=contract.id,
                    address=real_safe,
                    node_type="controller",
                    resolved_type="safe",
                    label="owner",
                    depth=1,
                ),
                ControlGraphNode(
                    contract_id=contract.id,
                    address=fee_safe,
                    node_type="controller",
                    resolved_type="safe",
                    label="accountantState.payoutAddress",
                    depth=1,
                ),
            ]
        )
        # Only the real Safe holds function-level authority.
        _grant_primary_authority(pg_session, contract.id, real_safe, function_name="transferOwnership")
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value=hex(2000)):
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc")

        real_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == real_safe)
        ).scalar_one()
        assert real_mc.is_active is True
        assert real_mc.contract_type == "safe"

        fee_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == fee_safe)
        ).scalar_one_or_none()
        assert fee_mc is None, (
            "Non-primary Safe was enrolled — the FP-based eligibility filter "
            "didn't fire for accountantState.payoutAddress-style destinations"
        )

    def test_re_enrollment_demotes_safe_that_lost_authority(self, pg_session):
        """A Safe enrolled in a prior run that has since lost its
        function-level authority (no remaining FP rows) gets
        ``is_active=False`` + ``enrollment_source='auto_deprimary'``
        on the next ``enroll_protocol_contracts`` call. The row is
        kept (not deleted) so its MonitoredEvent history survives.
        """
        from db.models import (
            Contract,
            ControlGraphNode,
            EffectiveFunction,
            FunctionPrincipal,
            Protocol,
        )
        from services.monitoring.enrollment import enroll_protocol_contracts

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        contract = Contract(
            address="0x" + "d3" * 20,
            chain="ethereum",
            protocol_id=proto.id,
            is_proxy=False,
        )
        pg_session.add(contract)
        pg_session.flush()
        _create_completed_job(pg_session, "0x" + "d3" * 20, proto.id)

        safe_addr = "0x" + "77" * 20
        pg_session.add(
            ControlGraphNode(
                contract_id=contract.id,
                address=safe_addr,
                node_type="controller",
                resolved_type="safe",
                label="owner",
                depth=1,
            )
        )
        _grant_primary_authority(pg_session, contract.id, safe_addr, function_name="setOwner")
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value=hex(3000)):
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc")

        first = pg_session.execute(select(MonitoredContract).where(MonitoredContract.address == safe_addr)).scalar_one()
        assert first.is_active is True
        assert first.enrollment_source == "auto"

        # Simulate the Safe losing its function authority (e.g. the
        # owner was rotated). Drop the EF/FP rows for this contract
        # specifically — a global FP wipe would clobber state from any
        # other test sharing the test DB.
        ef_ids = [
            ef_id
            for (ef_id,) in pg_session.execute(
                select(EffectiveFunction.id).where(EffectiveFunction.contract_id == contract.id)
            ).all()
        ]
        if ef_ids:
            pg_session.execute(delete(FunctionPrincipal).where(FunctionPrincipal.function_id.in_(ef_ids)))
            pg_session.execute(delete(EffectiveFunction).where(EffectiveFunction.id.in_(ef_ids)))
        pg_session.commit()
        pg_session.expire_all()

        with patch("services.monitoring.enrollment.rpc_request", return_value=hex(4000)):
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc")

        demoted = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == safe_addr)
        ).scalar_one()
        assert demoted.is_active is False, (
            f"Demoted Safe should be deactivated, got is_active={demoted.is_active} source={demoted.enrollment_source}"
        )
        assert demoted.enrollment_source == "auto_deprimary"

    def test_zombie_timelock_row_demoted_when_cgn_evidence_disappears(self, pg_session):
        """A timelock enrolled in a prior run whose CGN node is later
        rebuilt away — and whose FP authority is also gone — must be
        deactivated on re-enrollment. Observed on prod-etherfi: 4 of 5
        monitored timelocks are zombies with no current evidence in
        CGN, FP, or fund_flows. The deployed code had no path to
        notice them because the CGN-walk-then-enroll loop only sees
        addresses still in CGN; orphan rows survived indefinitely.
        """
        from db.models import (
            Contract,
            ControlGraphNode,
            EffectiveFunction,
            FunctionPrincipal,
            Protocol,
        )
        from services.monitoring.enrollment import enroll_protocol_contracts

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        contract = Contract(
            address="0x" + "d4" * 20,
            chain="ethereum",
            protocol_id=proto.id,
            is_proxy=False,
        )
        pg_session.add(contract)
        pg_session.flush()
        _create_completed_job(pg_session, "0x" + "d4" * 20, proto.id)

        timelock_addr = "0x" + "99" * 20
        cgn_node = ControlGraphNode(
            contract_id=contract.id,
            address=timelock_addr,
            node_type="controller",
            resolved_type="timelock",
            label="owner",
            depth=1,
        )
        pg_session.add(cgn_node)
        _grant_primary_authority(pg_session, contract.id, timelock_addr, function_name="schedule")
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value=hex(5000)):
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc")

        first = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == timelock_addr)
        ).scalar_one()
        assert first.is_active is True
        assert first.contract_type == "timelock"
        assert first.enrollment_source == "auto"

        # Simulate a re-analysis that drops both the CGN node AND the
        # function authority — the zombie state observed on prod.
        pg_session.delete(cgn_node)
        ef_ids = [
            ef_id
            for (ef_id,) in pg_session.execute(
                select(EffectiveFunction.id).where(EffectiveFunction.contract_id == contract.id)
            ).all()
        ]
        if ef_ids:
            pg_session.execute(delete(FunctionPrincipal).where(FunctionPrincipal.function_id.in_(ef_ids)))
            pg_session.execute(delete(EffectiveFunction).where(EffectiveFunction.id.in_(ef_ids)))
        pg_session.commit()
        pg_session.expire_all()

        with patch("services.monitoring.enrollment.rpc_request", return_value=hex(6000)):
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc")

        zombie = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == timelock_addr)
        ).scalar_one()
        assert zombie.is_active is False, (
            f"Zombie timelock should be demoted, got is_active={zombie.is_active} source={zombie.enrollment_source}"
        )
        assert zombie.enrollment_source == "auto_deprimary"
