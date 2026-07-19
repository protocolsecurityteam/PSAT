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

    def test_zero_address_owner_is_not_seeded(self):
        """A renounced/zero owner is never a useful baseline: seeding it makes
        the first live poll of a real owner false-fire a state change (and
        re-enrollment re-arms it). Leaving it unseeded makes that first
        observation silent instead.
        """
        from services.monitoring.enrollment import _build_initial_state

        contract = _mock_contract()
        cv = _mock_controller_value(controller_id="owner", value="0x" + "0" * 40)
        state = _build_initial_state(contract, [cv])
        assert "owner" not in state

    def test_zero_address_variants_and_plan_fields_not_seeded(self):
        from services.monitoring.enrollment import _build_initial_state

        contract = _mock_contract(implementation="0x0")
        admin = _mock_controller_value(controller_id="state_variable:admin", value="0x0")
        custom = _mock_controller_value(controller_id="state_variable:feeRecipient", value="0x" + "0" * 40)
        plan = [{"field": "feeRecipient", "kind": "getter_call", "selector": "0xab"}]
        state = _build_initial_state(contract, [admin, custom], plan)
        assert "admin" not in state
        assert "feeRecipient" not in state
        assert "implementation" not in state  # zero impl is dropped too

    def test_real_field_still_seeded_when_zero_sibling_present(self):
        from services.monitoring.enrollment import _build_initial_state

        contract = _mock_contract()
        real = _mock_controller_value(controller_id="owner", value="0x" + "a" * 40)
        zero_admin = _mock_controller_value(controller_id="state_variable:admin", value="0x" + "0" * 40)
        state = _build_initial_state(contract, [real, zero_admin])
        assert state["owner"] == "0x" + "a" * 40
        assert "admin" not in state


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
        # Fast-path hint skips the expensive primary-controller pass
        # (enroll_controllers=False); the reconciler converges controllers.
        mock_enroll.assert_called_once_with(mock_session, 1, "http://rpc", "ethereum", None, enroll_controllers=False)

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


def _grant_primary_authority(
    session,
    contract_id,
    principal_address,
    function_name="setOwner",
    resolved_type=None,
    effect_labels=None,
    details=None,
):
    """Make ``principal_address`` a primary controller of the contract by
    attaching a ``FunctionPrincipal`` row. ``assign_primary_controllers``
    uses FP membership as eligibility, so any CGN principal needs at
    least one matching FP row on the contract to survive the enrollment
    filter.

    ``resolved_type`` types the FP row (Safe / Timelock / proxy_admin).
    Enrollment seeds candidates from this when the address has no usable
    ``control_graph_nodes`` type, mirroring the Surface canvas.

    ``effect_labels`` sets the function's effect labels, which the
    co-controller rule reads — a privileged label (e.g. ``pause_toggle``)
    keeps a non-primary caller as a monitored co-controller.
    """
    _grant_shared_authority(
        session,
        contract_id,
        [principal_address],
        function_name=function_name,
        resolved_type=resolved_type,
        effect_labels=effect_labels,
        details=details,
    )


def _grant_shared_authority(
    session,
    contract_id,
    principal_addresses,
    function_name="setOwner",
    resolved_type=None,
    effect_labels=None,
    details=None,
):
    """Attach a single ``EffectiveFunction`` callable by *every* address in
    *principal_addresses*. The shared caller-set size is what the co-controller
    rule uses to tell a tightly-gated governance function from a broad
    permissionless whitelist (e.g. ``createBid`` shared by dozens of bidders),
    so a faithful bidder model needs one function with many callers — not one
    function per caller.
    """
    from db.models import EffectiveFunction, FunctionPrincipal

    ef = EffectiveFunction(
        contract_id=contract_id, function_name=function_name, authority_public=False, effect_labels=effect_labels
    )
    session.add(ef)
    session.flush()
    for addr in principal_addresses:
        session.add(
            FunctionPrincipal(
                function_id=ef.id,
                address=addr,
                principal_type="controller",
                resolved_type=resolved_type,
                details=details,
            )
        )
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
        # The polling-plan projection still emits an EIP-1967 vendored
        # storage-slot entry as a safety net, so needs_polling=True.
        # Duplicate poll events are suppressed by the scan/poll dedupe.
        assert proxy_mc.needs_polling is True
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
        # EIP-1967 still emits Upgraded events the scanner catches, but
        # the poll path now runs as a belt-and-suspenders safety net
        # for the same impl slot. The poll/scan dedupe filter swallows
        # the duplicate so this is no-cost notification-wise.
        assert mc.needs_polling is True
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

    def test_enroll_enrolls_primary_controllers(self, pg_session):
        """Principals that primary-control a contract get their own
        MonitoredContract rows — Safe and Timelock — while EOAs are dropped
        (nothing event-bearing to monitor). These are the winner-take-all
        primaries the Surface canvas groups by; enrollment shares that
        computation via ``controllers_for_protocol``.
        """
        from db.models import Contract, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        safe_addr = "0x" + "e1" * 20
        timelock_addr = "0x" + "e2" * 20
        eoa_addr = "0x" + "e3" * 20

        # Each principal is the sole FP controller of its own contract, so each
        # wins primary_for for that contract (no winner-take-all contest).
        for caddr, cname, principal, ptype, fn in [
            ("0x" + "d1" * 20, "GovernedBySafe", safe_addr, "safe", "setOwner"),
            ("0x" + "d2" * 20, "GovernedByTimelock", timelock_addr, "timelock", "schedule"),
            ("0x" + "d3" * 20, "GovernedByEOA", eoa_addr, "eoa", "poke"),
        ]:
            contract = Contract(address=caddr, chain="ethereum", protocol_id=proto.id, contract_name=cname)
            pg_session.add(contract)
            pg_session.flush()
            _create_completed_job(pg_session, caddr, proto.id)
            _grant_primary_authority(pg_session, contract.id, principal, function_name=fn, resolved_type=ptype)
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        # Safe primary controller enrolled.
        safe_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == safe_addr)
        ).scalar_one()
        assert safe_mc.contract_type == "safe"
        assert safe_mc.monitoring_config["watch_safe_signers"] is True
        assert safe_mc.needs_polling is True

        # Timelock primary controller enrolled.
        tl_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == timelock_addr)
        ).scalar_one()
        assert tl_mc.contract_type == "timelock"
        assert tl_mc.monitoring_config["watch_timelock"] is True

        # EOA primary controller is NOT monitored (dropped upstream).
        eoa_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == eoa_addr)
        ).scalar_one_or_none()
        assert eoa_mc is None

    def test_enroll_cgn_unknown_governance_safe_still_enrolls(self, pg_session):
        """A governance Safe whose ControlGraphNode is typed ``unknown`` (the
        resolution-stage walk never classified it) must still enroll, because
        enrollment derives controllers from the shared governance computation,
        which types principals from ``FunctionPrincipal`` and picks the primary
        controller per contract. The Safe wins primary_for over a co-controlling
        EOA, and the EOA is dropped (not monitored). Regression for the etherfi
        governance Safe that showed on Surface but was missing from monitoring
        because its CGN type was ``unknown``.
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
            contract_name="EtherFiTimelock",
        )
        pg_session.add(contract)
        pg_session.flush()
        _create_completed_job(pg_session, "0x" + "d2" * 20, proto.id)

        gov_safe = "0x" + "e4" * 20
        gov_eoa = "0x" + "e5" * 20

        # CGN sees the Safe but the resolution-stage classifier left it
        # ``unknown`` — the exact state that hid it from monitoring before.
        pg_session.add(
            ControlGraphNode(
                contract_id=contract.id,
                address=gov_safe,
                node_type="unknown",
                resolved_type="unknown",
                label="governance",
            )
        )
        # FunctionPrincipal types the Safe ``safe`` (live classify fallback at
        # write time) and grants both addresses call authority; the Safe wins
        # the per-contract primary-controller contest over the EOA.
        _grant_primary_authority(pg_session, contract.id, gov_safe, function_name="cancel", resolved_type="safe")
        _grant_primary_authority(pg_session, contract.id, gov_eoa, function_name="execute", resolved_type="eoa")
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        # Safe enrolls as a primary controller even though CGN typed it ``unknown``.
        safe_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == gov_safe)
        ).scalar_one()
        assert safe_mc.contract_type == "safe"
        assert safe_mc.is_active is True
        assert safe_mc.enrollment_source == "auto"

        # EOA stays unenrolled — EOAs are dropped, and it lost the contest anyway.
        eoa_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == gov_eoa)
        ).scalar_one_or_none()
        assert eoa_mc is None

    def test_enroll_excludes_permissionless_bidder_safes(self, pg_session):
        """Safes whose only authority is a broad, permissionless function are
        not enrolled — neither as primary (they lose the contest) nor as
        co-controllers (the function is shared by too many callers to read as a
        governance gate). Mirrors EtherFi's ``createBid`` on AuctionManager,
        shared by ~33 whitelisted bidders. The bare FP-authority signal alone
        over-enrolled every bidder.
        """
        from db.models import Contract, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        big_safe = "0x" + "e6" * 20  # governs the second contract -> wins, enrolled
        # Many bidder safes share one createBid function -> permissionless,
        # so the co-controller rule's caller-set arm drops them.
        bidder_safes = ["0x" + f"{0xB0 + i:02x}" * 20 for i in range(6)]

        auction = Contract(
            address="0x" + "d1" * 20, chain="ethereum", protocol_id=proto.id, contract_name="AuctionManager"
        )
        governed = Contract(address="0x" + "d2" * 20, chain="ethereum", protocol_id=proto.id, contract_name="Governed")
        pg_session.add_all([auction, governed])
        pg_session.flush()
        _create_completed_job(pg_session, auction.address, proto.id)
        _create_completed_job(pg_session, governed.address, proto.id)

        # One shared createBid function callable by big_safe + every bidder (7
        # callers > the gate threshold), labelled only external_contract_call
        # (no privileged label). big_safe also governs the second contract, so
        # it wins the auction's primary contest and is the only one enrolled.
        _grant_shared_authority(
            pg_session,
            auction.id,
            [big_safe, *bidder_safes],
            function_name="createBid",
            resolved_type="safe",
            effect_labels=["external_contract_call"],
        )
        _grant_primary_authority(pg_session, governed.id, big_safe, function_name="setOwner", resolved_type="safe")
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        # The governing Safe is enrolled.
        assert (
            pg_session.execute(select(MonitoredContract).where(MonitoredContract.address == big_safe))
            .scalar_one()
            .contract_type
            == "safe"
        )
        # No permissionless bidder Safe is enrolled.
        for bidder in bidder_safes:
            assert (
                pg_session.execute(
                    select(MonitoredContract).where(MonitoredContract.address == bidder)
                ).scalar_one_or_none()
                is None
            ), f"bidder {bidder} should not be enrolled"

    def test_enroll_includes_privileged_co_controller(self, pg_session):
        """A guardian Safe that holds a privileged power (``pause``) on a
        contract it LOSES the primary contest for is still enrolled — as a
        co-controller. Regression for EtherFi 0x2aca, a 4-of-7 pause /
        fund-recovery multisig hidden from monitoring because the
        timelock-passthrough governance Safe won all 8 of its contracts.
        Monitoring must watch it even though the Surface canvas groups the
        contract under the winner.
        """
        from db.models import Contract, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        gov_safe = "0x" + "e6" * 20  # governs both contracts -> wins both primaries
        guardian = "0x" + "e7" * 20  # can pause one contract -> loses primary, co-controls

        pool = Contract(address="0x" + "d1" * 20, chain="ethereum", protocol_id=proto.id, contract_name="LiquidityPool")
        other = Contract(address="0x" + "d2" * 20, chain="ethereum", protocol_id=proto.id, contract_name="Other")
        pg_session.add_all([pool, other])
        pg_session.flush()
        _create_completed_job(pg_session, pool.address, proto.id)
        _create_completed_job(pg_session, other.address, proto.id)

        # gov_safe governs both contracts (owns more) so it wins pool's primary
        # over the guardian. The guardian's only authority is pause on pool — a
        # privileged label, so it's kept as a co-controller despite losing.
        _grant_primary_authority(pg_session, pool.id, gov_safe, function_name="setOwner", resolved_type="safe")
        _grant_primary_authority(pg_session, other.id, gov_safe, function_name="setOwner", resolved_type="safe")
        _grant_primary_authority(
            pg_session,
            pool.id,
            guardian,
            function_name="pauseContract",
            resolved_type="safe",
            effect_labels=["pause_toggle"],
        )
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        # The winner is enrolled (primary).
        assert (
            pg_session.execute(select(MonitoredContract).where(MonitoredContract.address == gov_safe))
            .scalar_one()
            .contract_type
            == "safe"
        )
        # The guardian is enrolled too — as a co-controller, not a primary.
        guardian_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == guardian)
        ).scalar_one()
        assert guardian_mc.contract_type == "safe"
        assert guardian_mc.is_active is True
        assert guardian_mc.monitoring_config["watch_safe_signers"] is True

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
            first = enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")
            second = enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        assert len(first) == 1
        assert len(second) == 1

        count = pg_session.execute(
            select(func.count()).select_from(MonitoredContract).where(MonitoredContract.address == ("0x" + "f1" * 20))
        ).scalar()
        assert count == 1

    def test_reenrollment_merges_state_without_clobbering_observations(self, pg_session):
        """Re-enrollment must not overwrite a value the watcher already observed
        — a blind reset re-armed a phantom event every reconcile. Observed keys
        win; the seed only fills keys the observed state is missing.
        """
        from db.models import Contract, ControllerValue, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        impl = "0x" + "a2" * 20
        seed_owner = "0x" + "b1" * 20
        observed_owner = "0x" + "cd" * 20  # the live rotation the watcher recorded

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        contract = Contract(
            address="0x" + "a1" * 20,
            chain="ethereum",
            protocol_id=proto.id,
            contract_name="Vault",
            is_proxy=True,
            proxy_type="eip1967",
            implementation=impl,
        )
        pg_session.add(contract)
        pg_session.flush()
        pg_session.add(ControllerValue(contract_id=contract.id, controller_id="owner", value=seed_owner))
        _create_completed_job(pg_session, "0x" + "a1" * 20, proto.id)
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == ("0x" + "a1" * 20))
        ).scalar_one()
        assert mc.last_known_state["owner"] == seed_owner  # first enroll seeds

        # Simulate a watcher observation: owner rotated live, and drop the seeded
        # implementation key so the merge has a missing key to re-fill.
        mc.last_known_state = {"owner": observed_owner}
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        pg_session.expire_all()
        mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == ("0x" + "a1" * 20))
        ).scalar_one()
        assert mc.last_known_state["owner"] == observed_owner  # observation preserved
        assert mc.last_known_state["implementation"] == impl  # missing key re-seeded

    def test_reenrollment_merge_hygiene_cleanses_zero_and_prunes_stale(self, pg_session):
        """Re-enrollment merge hygiene: (a) a zero-address observation is dropped
        (cleanses a row seeded 0x0 before the seed fix, so it can't fire one last
        phantom), (b) a key neither seeded nor read by the current polling plan is
        pruned (last_known_state is served verbatim by the API), and (c) canonical
        owner/admin/implementation keys survive regardless.
        """
        from db.models import Contract, ControllerValue, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        impl = "0x" + "a2" * 20
        real_admin = "0x" + "dd" * 20
        zero = "0x" + "0" * 40

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        contract = Contract(
            address="0x" + "a1" * 20,
            chain="ethereum",
            protocol_id=proto.id,
            contract_name="Vault",
            is_proxy=True,
            proxy_type="eip1967",
            implementation=impl,
        )
        pg_session.add(contract)
        pg_session.flush()
        pg_session.add(ControllerValue(contract_id=contract.id, controller_id="admin", value=real_admin))
        _create_completed_job(pg_session, "0x" + "a1" * 20, proto.id)
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == ("0x" + "a1" * 20))
        ).scalar_one()
        # A persisted state carrying: a poisoned zero owner (pre-seed-fix), an
        # observed real admin (canonical), and a legacy key no longer produced.
        mc.last_known_state = {"owner": zero, "admin": real_admin, "legacyField": "0x" + "ee" * 20}
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        pg_session.expire_all()
        mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == ("0x" + "a1" * 20))
        ).scalar_one()
        state = mc.last_known_state
        assert "owner" not in state  # (a) zero observation cleansed, not re-seeded
        assert "legacyField" not in state  # (b) stale non-plan key pruned
        assert state["admin"] == real_admin  # (c) canonical observed value kept
        assert state["implementation"] == impl  # canonical seed re-fills the missing key

    def test_enroll_iterates_contracts_in_sorted_address_order(self, pg_session):
        """Contracts are processed in lowercased-address order so concurrent
        enrollers of the same protocol acquire monitored_contracts row locks in
        one global order (no AB/BA deadlock). The returned list is built in that
        iteration order, so its addresses must come out sorted regardless of
        insert order."""
        from db.models import Contract, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        # Insert deliberately out of order.
        for suffix in ("c3", "a1", "b2"):
            addr = "0x" + suffix * 20
            pg_session.add(Contract(address=addr, chain="ethereum", protocol_id=proto.id, contract_name=suffix))
            _create_completed_job(pg_session, addr, proto.id)
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            enrolled = enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        addrs = [mc.address for mc in enrolled]
        assert addrs == sorted(addrs)
        assert addrs == ["0x" + "a1" * 20, "0x" + "b2" * 20, "0x" + "c3" * 20]

    def _seed_one_contract_protocol(self, pg_session):
        from db.models import Contract, Protocol

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()
        addr = "0x" + "a1" * 20
        pg_session.add(Contract(address=addr, chain="ethereum", protocol_id=proto.id, contract_name="V"))
        _create_completed_job(pg_session, addr, proto.id)
        pg_session.commit()
        return proto

    def test_maybe_enroll_skips_and_marks_dirty_when_lock_held(self, pg_session):
        """The load-bearing assertion: while a sibling holds the enrollment lock,
        maybe_enroll writes ZERO MonitoredContract rows and leaves a dirty queue
        row (so the reconciler converges what this run's snapshot missed). Once
        the holder's txn ends, the next call enrolls normally."""
        from sqlalchemy import func

        from db.models import MonitoringEnrollmentQueue
        from services.monitoring.enrollment import maybe_enroll_protocol

        proto = self._seed_one_contract_protocol(pg_session)

        # A sibling holds the same transaction-scoped advisory lock.
        holder_engine = create_engine(DATABASE_URL)
        holder = Session(holder_engine, expire_on_commit=False)
        held = holder.execute(
            text("SELECT pg_try_advisory_xact_lock(hashtext('protocol_enrollment'), :pid)"),
            {"pid": proto.id},
        ).scalar()
        assert held is True
        try:
            with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
                fired = maybe_enroll_protocol(pg_session, proto.id, "http://rpc", "ethereum")
            assert fired is False
            n = pg_session.execute(
                select(func.count()).select_from(MonitoredContract).where(MonitoredContract.protocol_id == proto.id)
            ).scalar()
            assert n == 0  # nothing enrolled while the lock was held
            q = pg_session.execute(
                select(MonitoringEnrollmentQueue).where(MonitoringEnrollmentQueue.protocol_id == proto.id)
            ).scalar_one_or_none()
            assert q is not None  # dirty row left for the reconciler
        finally:
            holder.rollback()  # release the lock
            holder.close()
            holder_engine.dispose()

        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            fired2 = maybe_enroll_protocol(pg_session, proto.id, "http://rpc", "ethereum")
        assert fired2 is True
        pg_session.expire_all()
        n2 = pg_session.execute(
            select(func.count()).select_from(MonitoredContract).where(MonitoredContract.protocol_id == proto.id)
        ).scalar()
        assert n2 == 1

    def test_advisory_lock_released_on_enroll_commit(self, pg_session):
        """A normal maybe_enroll holds the lock only for its own transaction —
        a separate session can acquire it immediately after (release-on-commit)."""
        from services.monitoring.enrollment import maybe_enroll_protocol

        proto = self._seed_one_contract_protocol(pg_session)
        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            assert maybe_enroll_protocol(pg_session, proto.id, "http://rpc", "ethereum") is True

        other_engine = create_engine(DATABASE_URL)
        other = Session(other_engine, expire_on_commit=False)
        try:
            got = other.execute(
                text("SELECT pg_try_advisory_xact_lock(hashtext('protocol_enrollment'), :pid)"),
                {"pid": proto.id},
            ).scalar()
            assert got is True  # lock was freed when maybe_enroll committed
        finally:
            other.rollback()
            other.close()
            other_engine.dispose()

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
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

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
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

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
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

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
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        demoted = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == safe_addr)
        ).scalar_one()
        assert demoted.is_active is False, (
            f"Demoted Safe should be deactivated, got is_active={demoted.is_active} source={demoted.enrollment_source}"
        )
        assert demoted.enrollment_source == "auto_deprimary"

    def test_stale_detection_is_chain_scoped_for_twins(self, pg_session):
        """A stale base-chain MonitoredContract whose ethereum twin (same
        address) is freshly enrolled must be deactivated — the stale comparison
        keys on (address, chain), not address alone. Without the chain the base
        row is shadowed by its enrolled eth twin and lingers active forever.
        """
        from db.models import Contract, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        addr = "0x" + "a1" * 20
        eth_contract = Contract(address=addr, chain="ethereum", protocol_id=proto.id, contract_name="Twin")
        pg_session.add(eth_contract)
        pg_session.flush()
        _create_completed_job(pg_session, addr, proto.id)

        # A pre-existing auto-enrolled base twin with no analyzed contract this
        # run — stale, and must be deactivated by the chain-scoped stale check.
        pg_session.add(
            MonitoredContract(
                id=uuid.uuid4(),
                address=addr,
                chain="base",
                protocol_id=proto.id,
                contract_type="regular",
                monitoring_config={},
                last_scanned_block=0,
                is_active=True,
                enrollment_source="auto",
            )
        )
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        pg_session.expire_all()
        eth_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == addr, MonitoredContract.chain == "ethereum")
        ).scalar_one()
        assert eth_mc.is_active is True  # the freshly enrolled twin is untouched

        base_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == addr, MonitoredContract.chain == "base")
        ).scalar_one()
        assert base_mc.is_active is False, "stale base twin should be deactivated by the chain-scoped stale check"

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
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

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
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        zombie = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == timelock_addr)
        ).scalar_one()
        assert zombie.is_active is False, (
            f"Zombie timelock should be demoted, got is_active={zombie.is_active} source={zombie.enrollment_source}"
        )
        assert zombie.enrollment_source == "auto_deprimary"


@requires_postgres
class TestControlGraphTypeReconciliation:
    """``reconcile_control_graph_types`` folds authoritative FunctionPrincipal
    typing back into ``control_graph_nodes`` so every CGN consumer reads one
    consistent type — the fix for governance principals the resolution stage
    left ``unknown``."""

    @staticmethod
    def _proto_contract(session, addr, name="EtherFiTimelock"):
        from db.models import Contract, Protocol

        proto = Protocol(name=PROTO_NAME)
        session.add(proto)
        session.flush()
        contract = Contract(address=addr, chain="ethereum", protocol_id=proto.id, contract_name=name)
        session.add(contract)
        session.flush()
        return contract

    @staticmethod
    def _add_cgn(session, contract_id, addr, resolved_type):
        from db.models import ControlGraphNode

        session.add(
            ControlGraphNode(
                contract_id=contract_id, address=addr, node_type=resolved_type, resolved_type=resolved_type
            )
        )
        session.flush()

    @staticmethod
    def _node_type(session, contract_id, addr):
        from db.models import ControlGraphNode

        return (
            session.execute(
                select(ControlGraphNode.resolved_type).where(
                    ControlGraphNode.contract_id == contract_id,
                    ControlGraphNode.address == addr,
                )
            )
            .scalars()
            .one()
        )

    def test_upgrades_unknown_cgn_from_fp(self, pg_session):
        """A node the resolution stage left ``unknown`` is upgraded to the
        type FunctionPrincipal assigned it."""
        from services.governance.control_graph_types import reconcile_control_graph_types

        c = self._proto_contract(pg_session, "0x" + "a3" * 20)
        gov_safe = "0x" + "e6" * 20
        self._add_cgn(pg_session, c.id, gov_safe, "unknown")
        _grant_primary_authority(pg_session, c.id, gov_safe, function_name="cancel", resolved_type="safe")
        pg_session.commit()

        assert reconcile_control_graph_types(pg_session, [c.id]) == 1
        assert self._node_type(pg_session, c.id, gov_safe) == "safe"

    def test_does_not_downgrade_concrete_cgn(self, pg_session):
        """A graph-walk-determined concrete type is never overwritten, even if
        FunctionPrincipal disagrees."""
        from services.governance.control_graph_types import reconcile_control_graph_types

        c = self._proto_contract(pg_session, "0x" + "a4" * 20)
        addr = "0x" + "e7" * 20
        self._add_cgn(pg_session, c.id, addr, "timelock")
        _grant_primary_authority(pg_session, c.id, addr, function_name="schedule", resolved_type="safe")
        pg_session.commit()

        assert reconcile_control_graph_types(pg_session, [c.id]) == 0
        assert self._node_type(pg_session, c.id, addr) == "timelock"

    def test_skips_non_governance_fp_types(self, pg_session):
        """EOA / contract FP types are left alone — only Safe / Timelock /
        proxy admin (monitored principal kinds) are folded back."""
        from services.governance.control_graph_types import reconcile_control_graph_types

        c = self._proto_contract(pg_session, "0x" + "a5" * 20)
        eoa_addr = "0x" + "e8" * 20
        self._add_cgn(pg_session, c.id, eoa_addr, "unknown")
        _grant_primary_authority(pg_session, c.id, eoa_addr, function_name="poke", resolved_type="eoa")
        pg_session.commit()

        assert reconcile_control_graph_types(pg_session, [c.id]) == 0
        assert self._node_type(pg_session, c.id, eoa_addr) == "unknown"

    def test_idempotent(self, pg_session):
        """A second run after convergence upgrades nothing."""
        from services.governance.control_graph_types import reconcile_control_graph_types

        c = self._proto_contract(pg_session, "0x" + "a6" * 20)
        addr = "0x" + "e9" * 20
        self._add_cgn(pg_session, c.id, addr, "unknown")
        _grant_primary_authority(pg_session, c.id, addr, function_name="upgradeTo", resolved_type="proxy_admin")
        pg_session.commit()

        assert reconcile_control_graph_types(pg_session, [c.id]) == 1
        pg_session.flush()
        assert reconcile_control_graph_types(pg_session, [c.id]) == 0
        assert self._node_type(pg_session, c.id, addr) == "proxy_admin"

    @staticmethod
    def _node_details(session, contract_id, addr):
        from db.models import ControlGraphNode

        return (
            session.execute(
                select(ControlGraphNode.details).where(
                    ControlGraphNode.contract_id == contract_id,
                    ControlGraphNode.address == addr,
                )
            )
            .scalars()
            .one()
        )

    def test_folds_safe_owners_and_threshold_from_fp(self, pg_session):
        """Upgrading a node to ``safe`` also folds the signer set + threshold
        the classifier stored on FunctionPrincipal — so the node doesn't end up
        asserting ``safe`` with no owners (the bug that hid a multisig's signers
        on the Surface canvas)."""
        from services.governance.control_graph_types import reconcile_control_graph_types

        c = self._proto_contract(pg_session, "0x" + "b1" * 20)
        gov_safe = "0x" + "f1" * 20
        owners = ["0x" + "11" * 20, "0x" + "22" * 20, "0x" + "33" * 20]
        self._add_cgn(pg_session, c.id, gov_safe, "unknown")
        _grant_primary_authority(
            pg_session,
            c.id,
            gov_safe,
            function_name="cancel",
            resolved_type="safe",
            details={"owners": owners, "threshold": 2},
        )
        pg_session.commit()

        assert reconcile_control_graph_types(pg_session, [c.id]) == 1
        assert self._node_type(pg_session, c.id, gov_safe) == "safe"
        details = self._node_details(pg_session, c.id, gov_safe) or {}
        assert details.get("owners") == owners
        assert details.get("threshold") == 2

    def test_backfills_config_onto_already_typed_node(self, pg_session):
        """A node a prior *type-only* reconcile already flipped to ``safe`` (no
        owners) is repaired on the next run — the selector revisits
        governance-typed rows so existing data converges, and re-running once
        backfilled changes nothing."""
        from services.governance.control_graph_types import reconcile_control_graph_types

        c = self._proto_contract(pg_session, "0x" + "b2" * 20)
        gov_safe = "0x" + "f2" * 20
        owners = ["0x" + "44" * 20, "0x" + "55" * 20]
        # Node is already 'safe' but carries no owners — the half-reconciled state.
        self._add_cgn(pg_session, c.id, gov_safe, "safe")
        _grant_primary_authority(
            pg_session,
            c.id,
            gov_safe,
            function_name="cancel",
            resolved_type="safe",
            details={"owners": owners, "threshold": 2},
        )
        pg_session.commit()

        # No type change, but config is backfilled → counts as one row changed.
        assert reconcile_control_graph_types(pg_session, [c.id]) == 1
        pg_session.flush()
        assert (self._node_details(pg_session, c.id, gov_safe) or {}).get("owners") == owners
        # Converged: a second run touches nothing.
        assert reconcile_control_graph_types(pg_session, [c.id]) == 0

    def test_does_not_fold_owners_onto_disagreeing_type(self, pg_session):
        """A safe's owners are never attached to a node the resolution stage
        concretely typed ``timelock`` — type stays, and no safe-shaped config
        leaks onto it."""
        from services.governance.control_graph_types import reconcile_control_graph_types

        c = self._proto_contract(pg_session, "0x" + "b3" * 20)
        addr = "0x" + "f3" * 20
        self._add_cgn(pg_session, c.id, addr, "timelock")
        _grant_primary_authority(
            pg_session,
            c.id,
            addr,
            function_name="schedule",
            resolved_type="safe",
            details={"owners": ["0x" + "66" * 20], "threshold": 1},
        )
        pg_session.commit()

        assert reconcile_control_graph_types(pg_session, [c.id]) == 0
        assert self._node_type(pg_session, c.id, addr) == "timelock"
        assert not (self._node_details(pg_session, c.id, addr) or {}).get("owners")

    def test_folds_per_chain_for_same_address_twins(self, pg_session):
        """Same principal address on two chains that is a Safe on ethereum and a
        Timelock on base: each chain's CGN node must keep its own chain's type and
        config. Folding by bare address alone would let the higher-priority
        (Safe) type and its owners overwrite the base node's Timelock typing.
        """
        from db.models import Contract, Protocol
        from services.governance.control_graph_types import reconcile_control_graph_types

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        principal = "0x" + "f7" * 20
        owners = ["0x" + "11" * 20, "0x" + "22" * 20]

        eth_c = Contract(address="0x" + "c7" * 20, chain="ethereum", protocol_id=proto.id, contract_name="TwinEth")
        base_c = Contract(address="0x" + "c7" * 20, chain="base", protocol_id=proto.id, contract_name="TwinBase")
        pg_session.add_all([eth_c, base_c])
        pg_session.flush()

        self._add_cgn(pg_session, eth_c.id, principal, "unknown")
        self._add_cgn(pg_session, base_c.id, principal, "unknown")
        # Ethereum sees the principal as a Safe (with signers); base sees a Timelock.
        _grant_primary_authority(
            pg_session,
            eth_c.id,
            principal,
            function_name="cancel",
            resolved_type="safe",
            details={"owners": owners, "threshold": 2},
        )
        _grant_primary_authority(
            pg_session,
            base_c.id,
            principal,
            function_name="schedule",
            resolved_type="timelock",
            details={"min_delay": 172800},
        )
        pg_session.commit()

        reconcile_control_graph_types(pg_session, [eth_c.id, base_c.id])

        assert self._node_type(pg_session, eth_c.id, principal) == "safe"
        assert self._node_type(pg_session, base_c.id, principal) == "timelock"
        # The Safe's owners must not bleed onto the base Timelock node.
        assert (self._node_details(pg_session, eth_c.id, principal) or {}).get("owners") == owners
        assert not (self._node_details(pg_session, base_c.id, principal) or {}).get("owners")
