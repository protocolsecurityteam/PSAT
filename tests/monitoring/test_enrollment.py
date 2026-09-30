from __future__ import annotations

import os
import uuid
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine, delete, select, text
from sqlalchemy.orm import Session

from db.models import (
    MonitoredContract,
    WatchedProxy,
)
from tests.conftest import requires_postgres

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")

pytestmark = requires_postgres


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


class TestDetermineContractType:
    @pytest.mark.parametrize(
        "contract_kw, summary_kw, controller_types, expected",
        [
            pytest.param(
                {"is_proxy": True, "proxy_type": "eip1967"}, None, [], "proxy", id="proxy-from-contract-no-summary"
            ),
            pytest.param(
                {"is_proxy": False, "proxy_type": "custom"}, None, [], "proxy", id="proxy-from-proxy-type-only"
            ),
            pytest.param(
                {"is_proxy": True, "proxy_type": "eip1967"},
                {"is_upgradeable": True},
                [],
                "proxy",
                id="proxy-from-summary-and-contract",
            ),
            pytest.param(
                {"is_proxy": False, "proxy_type": None},
                {"is_upgradeable": True},
                [],
                "not-proxy",
                id="upgradeable-implementation-is-not-proxy",
            ),
            pytest.param({}, {"has_timelock": True}, [], "timelock", id="timelock-from-summary"),
            pytest.param({}, {"is_pausable": True}, [], "pausable", id="pausable-from-summary"),
            # A controller's type must not classify the contract it governs.
            *[
                pytest.param(
                    {"is_proxy": False},
                    None,
                    [resolved],
                    "regular",
                    id=f"controller-type-{resolved}-does-not-propagate",
                )
                for resolved in ("safe", "timelock", "proxy_admin")
            ],
            pytest.param({}, None, [], "regular", id="regular-default"),
        ],
    )
    def test_determine_contract_type(self, contract_kw, summary_kw, controller_types, expected):
        from services.monitoring.enrollment import _determine_contract_type

        contract = _mock_contract(**contract_kw)
        summary = None if summary_kw is None else _mock_summary(**summary_kw)
        cvs = [_mock_controller_value(resolved_type=t) for t in controller_types]
        result = _determine_contract_type(contract, summary, cvs)
        if expected == "not-proxy":
            assert result != "proxy"
        else:
            assert result == expected


class TestBuildMonitoringConfig:
    @pytest.mark.parametrize(
        "summary_kw, contract_type, expected_flags",
        [
            pytest.param(
                {"is_upgradeable": True},
                "proxy",
                {"watch_upgrades": True, "watch_ownership": True},
                id="proxy",
            ),
            pytest.param(
                {"is_pausable": True}, "pausable", {"watch_pause": True, "watch_upgrades": False}, id="pausable"
            ),
            pytest.param(None, "safe", {"watch_safe_signers": True}, id="safe"),
            pytest.param(None, "timelock", {"watch_timelock": True}, id="timelock"),
            pytest.param({"control_model": "role-based"}, "regular", {"watch_roles": True}, id="role-based"),
        ],
    )
    def test_config_flags(self, summary_kw, contract_type, expected_flags):
        from services.monitoring.enrollment import _build_monitoring_config

        summary = None if summary_kw is None else _mock_summary(**summary_kw)
        config = _build_monitoring_config(summary, [], contract_type)
        for flag, value in expected_flags.items():
            assert config[flag] is value

    def test_tracked_topics_persisted_when_supplied(self):
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

    def test_empty_tracked_topics_witnessed_as_empty_list(self):
        """Key absence is never a builder output."""
        from services.monitoring.enrollment import _build_monitoring_config

        config = _build_monitoring_config(None, [], "regular")
        assert config["tracked_topics"] == []
        assert "tracking_plan_not_determined" not in config
        assert "watch_authority" not in config


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
        """The old substring match latched ``pendingOwner`` and friends into ``owner``; only the canonical Ownable
        slot counts.
        """
        from services.monitoring.enrollment import _build_initial_state

        contract = _mock_contract()
        active = _mock_controller_value(controller_id="state_variable:owner", value="0x" + "a" * 40)
        pending = _mock_controller_value(controller_id="state_variable:pendingOwner", value="0x" + "b" * 40)
        previous = _mock_controller_value(controller_id="state_variable:previousOwner", value="0x" + "c" * 40)
        role_owner = _mock_controller_value(controller_id="state_variable:roleOwner", value="0x" + "d" * 40)
        # Last-write-wins under the old match would have latched the last entry.
        state = _build_initial_state(contract, [active, pending, previous, role_owner])
        assert state["owner"] == "0x" + "a" * 40

    def test_ignores_state_variable_destination_admin(self):
        from services.monitoring.enrollment import _build_initial_state

        contract = _mock_contract()
        active = _mock_controller_value(controller_id="state_variable:admin", value="0x" + "1" * 40)
        nested = _mock_controller_value(
            controller_id="state_variable:rolesAuthority.pendingAdmin", value="0x" + "2" * 40
        )
        state = _build_initial_state(contract, [active, nested])
        assert state["admin"] == "0x" + "1" * 40

    def test_zero_address_owner_is_not_seeded(self):
        """A zero owner would make the first live poll of a real owner false-fire."""
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


class TestMaybeEnrollProtocol:
    @patch("services.monitoring.enrollment.enroll_protocol_contracts")
    def test_fires_with_in_flight_siblings(self, mock_enroll):
        """The old status gate skipped when a sibling crashed before transitioning."""
        from services.monitoring.enrollment import maybe_enroll_protocol

        mock_session = MagicMock()
        result = MagicMock()
        result.scalars.return_value.first.return_value = MagicMock()
        mock_session.execute.return_value = result

        fired = maybe_enroll_protocol(mock_session, 1, "http://rpc", "ethereum")
        assert fired is True
        # The reconciler converges controllers.
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


PROTO_NAME = "__test_enrollment__"


@pytest.fixture()
def pg_session():
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
            for c in session.execute(select(Contract).where(Contract.protocol_id == proto.id)).scalars():
                session.delete(c)
            session.delete(proto)
        session.commit()
        session.close()
        engine.dispose()


def _create_completed_job(session, address, protocol_id):
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
    """``resolved_type`` seeds candidates when the address has no usable CGN type; ``effect_labels`` feeds the
    co-controller rule.
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
    """The shared caller-set size tells a gated function from a permissionless whitelist."""
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
    def test_enroll_creates_monitored_contracts_from_real_data(self, pg_session):
        from db.models import Contract, ContractSummary, ControllerValue, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

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

        proxy_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == ("0x" + "a1" * 20))
        ).scalar_one()
        assert proxy_mc.contract_type == "proxy"
        assert proxy_mc.monitoring_config["watch_upgrades"] is True
        assert proxy_mc.monitoring_config["watch_pause"] is True
        assert proxy_mc.last_known_state["implementation"] == "0x" + "a2" * 20
        assert proxy_mc.last_known_state["owner"] == "0x" + "b1" * 20
        # The polling plan still emits the EIP-1967 slot as a safety net; the scan/poll dedupe suppresses duplicates.
        assert proxy_mc.needs_polling is True
        assert proxy_mc.watched_proxy_id is not None

        pausable_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == ("0x" + "c1" * 20))
        ).scalar_one()
        assert pausable_mc.contract_type == "pausable"
        assert pausable_mc.monitoring_config["watch_pause"] is True
        assert pausable_mc.monitoring_config["watch_roles"] is True
        assert pausable_mc.monitoring_config["watch_upgrades"] is False

    def test_enroll_proxy_without_summary_uses_contract_fields(self, pg_session):
        """Slither ran on the implementation, so the proxy shell has no ContractSummary."""
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

        assert mc.contract_type == "proxy"
        assert mc.needs_polling is True
        assert mc.monitoring_config["watch_upgrades"] is True
        assert mc.monitoring_config["watch_ownership"] is True

        assert mc.last_known_state.get("implementation") == impl_addr
        assert mc.last_known_state.get("owner") == "0x" + "cc" * 20

        assert mc.watched_proxy_id is not None
        wp = pg_session.get(WatchedProxy, mc.watched_proxy_id)
        assert wp is not None
        assert wp.proxy_type == "eip1967"
        assert wp.last_known_implementation == impl_addr

    def test_enroll_implementation_with_proxy_admin_stays_regular(self, pg_session):
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

        assert mc.contract_type == "regular"
        assert mc.needs_polling is False
        assert mc.monitoring_config["watch_upgrades"] is False
        assert mc.watched_proxy_id is None

    def test_enroll_enrolls_primary_controllers(self, pg_session):
        from db.models import Contract, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        safe_addr = "0x" + "e1" * 20
        timelock_addr = "0x" + "e2" * 20
        eoa_addr = "0x" + "e3" * 20

        # No winner-take-all contest.
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

        safe_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == safe_addr)
        ).scalar_one()
        assert safe_mc.contract_type == "safe"
        assert safe_mc.monitoring_config["watch_safe_signers"] is True
        assert safe_mc.needs_polling is True

        tl_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == timelock_addr)
        ).scalar_one()
        assert tl_mc.contract_type == "timelock"
        assert tl_mc.monitoring_config["watch_timelock"] is True

        # EOAs are dropped upstream.
        eoa_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == eoa_addr)
        ).scalar_one_or_none()
        assert eoa_mc is None

    def test_controllers_enroll_on_the_chain_of_the_contracts_they_govern(self, pg_session, monkeypatch):
        """A shared Safe gets a row on each chain it governs; the old single-chain fallback missed its base twin."""
        from db.models import Contract, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")
        monkeypatch.setenv("ERPC_BASE_URL", "http://erpc.local")

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        shared_safe = "0x" + "a1" * 20
        base_only_safe = "0x" + "a2" * 20

        for caddr, cchain, principal in [
            ("0x" + "d4" * 20, "ethereum", shared_safe),
            ("0x" + "d5" * 20, "base", shared_safe),
            ("0x" + "d6" * 20, "base", base_only_safe),
        ]:
            contract = Contract(address=caddr, chain=cchain, protocol_id=proto.id, contract_name=f"C{caddr[-2:]}")
            pg_session.add(contract)
            pg_session.flush()
            job = _create_completed_job(pg_session, caddr, proto.id)
            job.request = {"chain": cchain}
            job.chain_id = 8453 if cchain == "base" else 1
            pg_session.flush()
            _grant_primary_authority(pg_session, contract.id, principal, resolved_type="safe")
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        shared_rows = (
            pg_session.execute(select(MonitoredContract).where(MonitoredContract.address == shared_safe))
            .scalars()
            .all()
        )
        assert sorted(mc.chain for mc in shared_rows) == ["base", "ethereum"]
        assert all(mc.contract_type == "safe" and mc.is_active for mc in shared_rows)

        base_rows = (
            pg_session.execute(select(MonitoredContract).where(MonitoredContract.address == base_only_safe))
            .scalars()
            .all()
        )
        assert [mc.chain for mc in base_rows] == ["base"]

    def test_off_allowlist_controller_chain_is_skipped_not_redirected(self, pg_session, monkeypatch):
        from db.models import Contract, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        base_safe = "0x" + "a3" * 20
        contract = Contract(address="0x" + "d7" * 20, chain="base", protocol_id=proto.id, contract_name="BaseC")
        pg_session.add(contract)
        pg_session.flush()
        job = _create_completed_job(pg_session, contract.address, proto.id)
        job.request = {"chain": "base"}
        job.chain_id = 8453
        pg_session.flush()
        _grant_primary_authority(pg_session, contract.id, base_safe, resolved_type="safe")
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        rows = (
            pg_session.execute(select(MonitoredContract).where(MonitoredContract.address == base_safe)).scalars().all()
        )
        assert rows == []

    def test_enroll_cgn_unknown_governance_safe_still_enrolls(self, pg_session):
        """Regression for the etherfi governance Safe shown on Surface but missing from monitoring."""
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

        pg_session.add(
            ControlGraphNode(
                contract_id=contract.id,
                address=gov_safe,
                node_type="unknown",
                resolved_type="unknown",
                label="governance",
            )
        )
        _grant_primary_authority(pg_session, contract.id, gov_safe, function_name="cancel", resolved_type="safe")
        _grant_primary_authority(pg_session, contract.id, gov_eoa, function_name="execute", resolved_type="eoa")
        pg_session.commit()

        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            enroll_protocol_contracts(pg_session, proto.id, "http://rpc", "ethereum")

        safe_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == gov_safe)
        ).scalar_one()
        assert safe_mc.contract_type == "safe"
        assert safe_mc.is_active is True
        assert safe_mc.enrollment_source == "auto"

        eoa_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == gov_eoa)
        ).scalar_one_or_none()
        assert eoa_mc is None

    def test_enroll_excludes_permissionless_bidder_safes(self, pg_session):
        """Mirrors EtherFi's ``createBid`` (~33 whitelisted bidders), which the bare FP signal over-enrolled."""
        from db.models import Contract, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

        big_safe = "0x" + "e6" * 20  # governs the second contract -> wins, enrolled
        bidder_safes = ["0x" + f"{0xB0 + i:02x}" * 20 for i in range(6)]

        auction = Contract(
            address="0x" + "d1" * 20, chain="ethereum", protocol_id=proto.id, contract_name="AuctionManager"
        )
        governed = Contract(address="0x" + "d2" * 20, chain="ethereum", protocol_id=proto.id, contract_name="Governed")
        pg_session.add_all([auction, governed])
        pg_session.flush()
        _create_completed_job(pg_session, auction.address, proto.id)
        _create_completed_job(pg_session, governed.address, proto.id)

        # More than the gate threshold of callers, and no privileged label.
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

        assert (
            pg_session.execute(select(MonitoredContract).where(MonitoredContract.address == big_safe))
            .scalar_one()
            .contract_type
            == "safe"
        )
        for bidder in bidder_safes:
            assert (
                pg_session.execute(
                    select(MonitoredContract).where(MonitoredContract.address == bidder)
                ).scalar_one_or_none()
                is None
            ), f"bidder {bidder} should not be enrolled"

    def test_enroll_includes_privileged_co_controller(self, pg_session):
        """Regression for EtherFi 0x2aca, a pause multisig hidden because another Safe won every primary contest."""
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

        assert (
            pg_session.execute(select(MonitoredContract).where(MonitoredContract.address == gov_safe))
            .scalar_one()
            .contract_type
            == "safe"
        )
        guardian_mc = pg_session.execute(
            select(MonitoredContract).where(MonitoredContract.address == guardian)
        ).scalar_one()
        assert guardian_mc.contract_type == "safe"
        assert guardian_mc.is_active is True
        assert guardian_mc.monitoring_config["watch_safe_signers"] is True

    def test_enroll_is_idempotent(self, pg_session):
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
        """A blind reset re-armed a phantom event every reconcile."""
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
        """``last_known_state`` is served verbatim, so zero observations and stale keys are cleaned."""
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
        """Concurrent enrollers then take row locks in one order (no AB/BA deadlock)."""
        from db.models import Contract, Protocol
        from services.monitoring.enrollment import enroll_protocol_contracts

        proto = Protocol(name=PROTO_NAME)
        pg_session.add(proto)
        pg_session.flush()

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
        from sqlalchemy import func

        from db.models import MonitoringEnrollmentQueue
        from services.monitoring.enrollment import maybe_enroll_protocol

        proto = self._seed_one_contract_protocol(pg_session)

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
        """A flush-ordering regression."""
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
        """The etherfi ``accountantState.payoutAddress`` misclassification."""
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
        """The row is kept so its event history survives."""
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

        # A global FP wipe would clobber other tests' state.
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
        """Without the chain, a stale base row is shadowed by its eth twin forever."""
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
        """4 of 5 prod etherfi timelocks were zombies: the enroll loop only sees addresses still in CGN."""
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
        from services.governance.control_graph_types import reconcile_control_graph_types

        c = self._proto_contract(pg_session, "0x" + "a3" * 20)
        gov_safe = "0x" + "e6" * 20
        self._add_cgn(pg_session, c.id, gov_safe, "unknown")
        _grant_primary_authority(pg_session, c.id, gov_safe, function_name="cancel", resolved_type="safe")
        pg_session.commit()

        assert reconcile_control_graph_types(pg_session, [c.id]) == 1
        assert self._node_type(pg_session, c.id, gov_safe) == "safe"

    def test_does_not_downgrade_concrete_cgn(self, pg_session):
        from services.governance.control_graph_types import reconcile_control_graph_types

        c = self._proto_contract(pg_session, "0x" + "a4" * 20)
        addr = "0x" + "e7" * 20
        self._add_cgn(pg_session, c.id, addr, "timelock")
        _grant_primary_authority(pg_session, c.id, addr, function_name="schedule", resolved_type="safe")
        pg_session.commit()

        assert reconcile_control_graph_types(pg_session, [c.id]) == 0
        assert self._node_type(pg_session, c.id, addr) == "timelock"

    def test_skips_non_governance_fp_types(self, pg_session):
        from services.governance.control_graph_types import reconcile_control_graph_types

        c = self._proto_contract(pg_session, "0x" + "a5" * 20)
        eoa_addr = "0x" + "e8" * 20
        self._add_cgn(pg_session, c.id, eoa_addr, "unknown")
        _grant_primary_authority(pg_session, c.id, eoa_addr, function_name="poke", resolved_type="eoa")
        pg_session.commit()

        assert reconcile_control_graph_types(pg_session, [c.id]) == 0
        assert self._node_type(pg_session, c.id, eoa_addr) == "unknown"

    def test_idempotent(self, pg_session):
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
        """A ``safe`` node with no owners hid the multisig's signers on the Surface canvas."""
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
        from services.governance.control_graph_types import reconcile_control_graph_types

        c = self._proto_contract(pg_session, "0x" + "b2" * 20)
        gov_safe = "0x" + "f2" * 20
        owners = ["0x" + "44" * 20, "0x" + "55" * 20]
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

        assert reconcile_control_graph_types(pg_session, [c.id]) == 1
        pg_session.flush()
        assert (self._node_details(pg_session, c.id, gov_safe) or {}).get("owners") == owners
        assert reconcile_control_graph_types(pg_session, [c.id]) == 0

    def test_does_not_fold_owners_onto_disagreeing_type(self, pg_session):
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
        """Folding by bare address would overwrite the base Timelock typing."""
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
        assert (self._node_details(pg_session, eth_c.id, principal) or {}).get("owners") == owners
        assert not (self._node_details(pg_session, base_c.id, principal) or {}).get("owners")

    @staticmethod
    def _node_analysis_state(session, contract_id, addr):
        from db.models import ControlGraphNode

        return (
            session.execute(
                select(ControlGraphNode.analysis_state).where(
                    ControlGraphNode.contract_id == contract_id,
                    ControlGraphNode.address == addr,
                )
            )
            .scalars()
            .one()
        )

    def test_safe_upgrade_stamps_coherent_analysis_state(self, pg_session):
        """('safe', NULL) is a self-refuting pair."""
        from services.governance.control_graph_types import reconcile_control_graph_types

        c = self._proto_contract(pg_session, "0x" + "b5" * 20)
        gov_safe = "0x" + "f5" * 20
        self._add_cgn(pg_session, c.id, gov_safe, "unknown")
        _grant_primary_authority(pg_session, c.id, gov_safe, function_name="cancel", resolved_type="safe")
        pg_session.commit()

        assert reconcile_control_graph_types(pg_session, [c.id]) == 1
        assert self._node_type(pg_session, c.id, gov_safe) == "safe"
        assert self._node_analysis_state(pg_session, c.id, gov_safe) == "not_analyzable"

    def test_pretyped_safe_with_null_state_is_healed_and_converges(self, pg_session):
        from services.governance.control_graph_types import reconcile_control_graph_types

        c = self._proto_contract(pg_session, "0x" + "b6" * 20)
        gov_safe = "0x" + "f6" * 20
        self._add_cgn(pg_session, c.id, gov_safe, "safe")
        _grant_primary_authority(pg_session, c.id, gov_safe, function_name="cancel", resolved_type="safe")
        pg_session.commit()

        assert self._node_analysis_state(pg_session, c.id, gov_safe) is None
        assert reconcile_control_graph_types(pg_session, [c.id]) == 1
        pg_session.flush()
        assert self._node_analysis_state(pg_session, c.id, gov_safe) == "not_analyzable"
        assert reconcile_control_graph_types(pg_session, [c.id]) == 0

    def test_analyzable_upgrade_leaves_analysis_state_null(self, pg_session):
        from services.governance.control_graph_types import reconcile_control_graph_types

        c = self._proto_contract(pg_session, "0x" + "b7" * 20)
        addr = "0x" + "f8" * 20
        self._add_cgn(pg_session, c.id, addr, "unknown")
        _grant_primary_authority(pg_session, c.id, addr, function_name="schedule", resolved_type="timelock")
        pg_session.commit()

        assert reconcile_control_graph_types(pg_session, [c.id]) == 1
        assert self._node_type(pg_session, c.id, addr) == "timelock"
        assert self._node_analysis_state(pg_session, c.id, addr) is None

    def test_determined_analysis_state_never_overwritten(self, pg_session):
        from db.models import ControlGraphNode
        from services.governance.control_graph_types import reconcile_control_graph_types

        c = self._proto_contract(pg_session, "0x" + "b8" * 20)
        gov_safe = "0x" + "f9" * 20
        pg_session.add(
            ControlGraphNode(
                contract_id=c.id,
                address=gov_safe,
                node_type="unknown",
                resolved_type="unknown",
                analysis_state="attempt_failed",
                details={"materialize_error": "boom"},
            )
        )
        pg_session.flush()
        _grant_primary_authority(pg_session, c.id, gov_safe, function_name="cancel", resolved_type="safe")
        pg_session.commit()

        assert reconcile_control_graph_types(pg_session, [c.id]) == 1
        assert self._node_type(pg_session, c.id, gov_safe) == "safe"
        assert self._node_analysis_state(pg_session, c.id, gov_safe) == "attempt_failed"


class TestTrackingPlanNotDetermined:
    """Not-determined vs found-nothing at the enrollment boundary.

    The loader returns no topics in four situations and only one is a finding, so ``monitoring_config`` must not
    present the other three as one. Uses the real ``find_by_address``, since the collapse happens inside it.
    """

    _TOPIC0 = "0x" + "ab" * 32
    _PLAN_WITH_EVENTS = {
        "tracked_controllers": [
            {
                "controller_id": "state_variable:guardian",
                "event_watch": {
                    "events": [
                        {
                            "topic0": _TOPIC0,
                            "signature": "GuardianChanged(address,address)",
                            "inputs": [{"name": "old", "type": "address", "indexed": True}],
                        }
                    ]
                },
            }
        ]
    }

    @pytest.fixture()
    def materialization_factory(self, pg_session):
        from db.models import ContractMaterialization

        made: list[tuple[str, str]] = []

        def _make(address: str, **overrides):
            from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
            from utils.chains import chain_cache_token

            keccak = ("0x" + uuid.uuid4().hex * 2)[:66]
            fields = {
                # The chain-token normalization is part of what find_by_address does.
                "chain": chain_cache_token("ethereum"),
                "bytecode_keccak": keccak,
                "address": address.lower(),
                "contract_name": "Fixture",
                "status": "ready",
                "analysis_schema_version": ANALYSIS_SCHEMA_VERSION,
            }
            fields.update(overrides)
            row = ContractMaterialization(**fields)
            pg_session.add(row)
            pg_session.commit()
            made.append((fields["chain"], keccak))
            return row

        try:
            yield _make
        finally:
            pg_session.rollback()
            for chain, keccak in made:
                row = pg_session.get(ContractMaterialization, (chain, keccak))
                if row is not None:
                    pg_session.delete(row)
            pg_session.commit()

    @pytest.mark.parametrize(
        "address_byte, row_overrides",
        [
            # 35 of 85 rows have no materialization, so nothing ever read a tracking plan.
            pytest.param("11", None, id="no-materialization-row"),
            # A superseded schema is a miss on purpose; publishing zero topics would deny real governance events.
            pytest.param(
                "33", lambda version: {"analysis_schema_version": version - 1}, id="superseded-schema-version"
            ),
            pytest.param("44", lambda version: {"status": "building"}, id="unready-row"),
        ],
    )
    def test_missing_current_materialization_is_not_determined(
        self, pg_session, materialization_factory, address_byte, row_overrides
    ):
        from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
        from services.monitoring import enrollment as enr

        address = "0x" + address_byte * 20
        if row_overrides is not None:
            materialization_factory(
                address, tracking_plan=self._PLAN_WITH_EVENTS, **row_overrides(ANALYSIS_SCHEMA_VERSION)
            )
        contract = SimpleNamespace(address=address, chain="ethereum")

        topics, plan, not_determined = enr._load_tracking_plan_artifacts(pg_session, cast(Any, contract))
        assert (topics, plan) == ([], None)
        assert not_determined == "no_current_materialization"

        config = enr._build_monitoring_config(None, [], "regular", topics, None, plan_not_determined=not_determined)
        assert "tracked_topics" not in config
        assert config["tracking_plan_not_determined"] == "no_current_materialization"

    def test_unreadable_plan_is_stamped_with_its_own_reason(self, pg_session, materialization_factory, monkeypatch):
        """An outage and a missing materialization have different remedies."""
        from db.storage import StorageContentNotDetermined
        from services.monitoring import enrollment as enr

        address = "0x" + "55" * 20
        materialization_factory(address, tracking_plan_blob_key="artifacts/x/tracking_plan.json")
        monkeypatch.setattr(
            enr,
            "hydrate_tracking_plan",
            lambda _row: (_ for _ in ()).throw(StorageContentNotDetermined("bucket unreachable")),
        )
        contract = SimpleNamespace(address=address, chain="ethereum")

        topics, plan, not_determined = enr._load_tracking_plan_artifacts(pg_session, cast(Any, contract))
        assert (topics, plan) == ([], None)
        assert not_determined == "plan_not_readable"

        config = enr._build_monitoring_config(None, [], "regular", topics, None, plan_not_determined=not_determined)
        assert config["tracking_plan_not_determined"] == "plan_not_readable"

    def test_a_plan_object_the_bucket_says_is_gone_gets_its_own_token(
        self, pg_session, materialization_factory, monkeypatch
    ):
        """An absent object reads the same forever; an unreachable bucket may answer next tick."""
        from db.storage import StorageContentAbsent
        from services.monitoring import enrollment as enr

        address = "0x" + "66" * 20
        materialization_factory(address, tracking_plan_blob_key="artifacts/x/tracking_plan.json")
        monkeypatch.setattr(
            enr,
            "hydrate_tracking_plan",
            lambda _row: (_ for _ in ()).throw(StorageContentAbsent("no object at any candidate")),
        )
        contract = SimpleNamespace(address=address, chain="ethereum")

        topics, plan, not_determined = enr._load_tracking_plan_artifacts(pg_session, cast(Any, contract))
        assert (topics, plan) == ([], None)
        assert not_determined == "plan_object_absent"

        config = enr._build_monitoring_config(None, [], "regular", topics, None, plan_not_determined=not_determined)
        assert config["tracking_plan_not_determined"] == "plan_object_absent"

    def test_a_read_plan_with_no_events_stays_clean(self, pg_session, materialization_factory):
        """The one shape where empty ``tracked_topics`` is a finding (5 of 85 rows)."""
        from services.monitoring import enrollment as enr

        address = "0x" + "66" * 20
        materialization_factory(address, tracking_plan={"tracked_controllers": []})
        contract = SimpleNamespace(address=address, chain="ethereum")

        topics, plan, not_determined = enr._load_tracking_plan_artifacts(pg_session, cast(Any, contract))
        assert topics == []
        assert plan == {"tracked_controllers": []}
        assert not_determined is None

        config = enr._build_monitoring_config(None, [], "regular", topics, None, plan_not_determined=not_determined)
        assert config["tracked_topics"] == []
        assert "tracking_plan_not_determined" not in config

    def test_a_read_plan_with_events_stays_clean_and_publishes_them(self, pg_session, materialization_factory):
        from services.monitoring import enrollment as enr

        address = "0x" + "77" * 20
        materialization_factory(address, tracking_plan=self._PLAN_WITH_EVENTS)
        contract = SimpleNamespace(address=address, chain="ethereum")

        topics, _plan, not_determined = enr._load_tracking_plan_artifacts(pg_session, cast(Any, contract))
        assert not_determined is None
        assert [t["topic0"] for t in topics] == [self._TOPIC0]

        config = enr._build_monitoring_config(None, [], "regular", topics, None, plan_not_determined=not_determined)
        assert config["tracked_topics"] == topics
        assert "tracking_plan_not_determined" not in config

    def test_unanalyzed_primary_controller_config_is_flagged(self):
        """Primary controllers are enrolled without analysis, so their empty topics must be stamped."""
        from services.monitoring import enrollment as enr

        config = enr._build_monitoring_config(
            None, [], "safe", None, [{"field": "threshold"}], plan_not_determined="contract_not_analyzed"
        )
        assert config["tracking_plan_not_determined"] == "contract_not_analyzed"
