"""Integration tests for governance-event-triggered re-analysis job queuing.

Tests cover:
  - Correct event types trigger re-analysis jobs
  - Non-triggering events do NOT create jobs
  - In-flight job dedup prevents duplicates
  - Poll-detected state changes trigger appropriately
  - Caching system compatibility (new job doesn't break cache lookup)
  - Full Anvil integration: deploy → upgrade → scan → verify job queued

Requires:
  - PostgreSQL (TEST_DATABASE_URL env var)
  - anvil, cast, forge (from Foundry) on PATH — for Anvil integration tests

Run:
    TEST_DATABASE_URL=postgresql://psat:psat@localhost:5433/psat_test \
        uv run pytest tests/test_reanalysis.py -v --timeout=120
"""

from __future__ import annotations

import os
import shutil
import uuid

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session as SASession

from db.models import (
    Base,
    Contract,
    ContractSummary,
    Job,
    JobStage,
    JobStatus,
    MonitoredContract,
    MonitoredEvent,
    Protocol,
    ProtocolSubscription,
    ProxyUpgradeEvent,
    WatchedProxy,
)
from schemas.control_tracking import MonitoredContractType
from services.monitoring.reanalysis import (
    _REANALYSIS_WRITE_TARGETS,
    REANALYSIS_POLL_FIELDS_VENDORED,
    maybe_queue_reanalysis,
    should_trigger_reanalysis,
)
from tests.conftest import requires_postgres
from tests.support.anvil import (
    IMPL_V1_SOURCE,
    IMPL_V2_SOURCE,
    OWNABLE_SOURCE,
    PRIVATE_KEY,
    PROXY_SOURCE,
    _cast,
    _cast_send,
    _compile_and_deploy,
    anvil_env,  # noqa: F401
)

# Poll fields that should trigger reanalysis post-tag-migration: vendored
# triggers (``implementation``) plus the analyzer's control-relevant
# write targets (``owner``, ``_owner``, ``pendingOwner``, ``authority``,
# the admin family, ``_initialized``/``_initializing``). The poll path
# and the event path now share this vocabulary.
_REANALYSIS_POLL_FIELDS = REANALYSIS_POLL_FIELDS_VENDORED | _REANALYSIS_WRITE_TARGETS

# Canonical event types that should trigger a full re-analysis job. The
# tag-driven dispatch in ``should_trigger_reanalysis`` derives the same
# verdict from ``_HANDROLLED_EVENT_TYPE_TO_TAGS`` — these are the
# event_types whose synthesized tags either write a control-relevant
# slot, set ``delegates``, or set ``is_initializer``. ``upgraded_revision``
# is included because Aave V2's revision bump IS a delegate-target
# swap (was missing from the pre-tag-migration set).
_TRIGGERING_EVENT_TYPES = (
    "upgraded",
    "new_implementation",
    "changed_master_copy",
    "target_updated",
    "upgraded_revision",
    "diamond_cut",
    "beacon_upgraded",
    "admin_changed",
    "ownership_transferred",
    "authority_updated",
    "initialized",
)

# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------

_has_anvil = shutil.which("anvil") is not None
_has_cast = shutil.which("cast") is not None
_has_forge = shutil.which("forge") is not None

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")

requires_anvil = pytest.mark.skipif(
    not (_has_anvil and _has_cast and _has_forge),
    reason="Foundry tools (anvil/cast/forge) not found on PATH",
)

pytestmark = requires_postgres


@pytest.fixture(autouse=True)
def _disable_scan_confirmation_depth(monkeypatch):
    # These anvil chains are only a handful of blocks long; the production
    # 12-block confirmation clamp would hide every just-emitted event.
    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")


# ---------------------------------------------------------------------------
# Solidity test contracts
# ---------------------------------------------------------------------------

PAUSABLE_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TestPausable {
    bool public paused;
    address public owner;
    event Paused(address account);
    event Unpaused(address account);

    constructor() { owner = msg.sender; }

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

ADMIN_PROXY_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TestAdminProxy {
    bytes32 internal constant _ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    event AdminChanged(address previousAdmin, address newAdmin);

    constructor() {
        assembly { sstore(_ADMIN_SLOT, caller()) }
    }

    function changeAdmin(address newAdmin) external {
        address old;
        assembly { old := sload(_ADMIN_SLOT) }
        assembly { sstore(_ADMIN_SLOT, newAdmin) }
        emit AdminChanged(old, newAdmin);
    }
}
"""


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_session():
    """PostgreSQL session with full schema, cleaned up after each test."""
    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine)

    session = SASession(engine, expire_on_commit=False)
    try:
        yield session
    finally:
        session.rollback()
        # Clean up in FK-safe order
        for model in [
            MonitoredEvent,
            MonitoredContract,
            ProxyUpgradeEvent,
            WatchedProxy,
            ProtocolSubscription,
        ]:
            try:
                session.query(model).delete()
            except Exception:
                session.rollback()
        # Clean jobs, contracts, protocols
        for model in [Job, ContractSummary, Contract, Protocol]:
            try:
                session.query(model).delete()
            except Exception:
                session.rollback()
        session.commit()
        session.close()
        engine.dispose()


def _make_protocol(session: SASession, name: str = "TestProtocol") -> Protocol:
    proto = Protocol(name=name)
    session.add(proto)
    session.commit()
    session.refresh(proto)
    return proto


def _make_monitored_contract(
    session: SASession,
    address: str,
    contract_type: MonitoredContractType = "regular",
    last_scanned_block: int = 0,
    protocol_id: int | None = None,
    chain: str = "ethereum",
    needs_polling: bool = False,
    proxy_type: str | None = None,
) -> MonitoredContract:
    from services.monitoring.polling_plan import build_polling_plan

    # PROXY_SOURCE in this test module writes to the EIP-1967 slot via
    # assembly; default to the matching vendored entry so the storage-
    # slot poll dispatch actually reads the upgraded value.
    plan_proxy_type = proxy_type or ("eip1967" if contract_type == "proxy" else None)
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

    mc = MonitoredContract(
        id=uuid.uuid4(),
        address=address.lower(),
        chain=chain,
        protocol_id=protocol_id,
        contract_type=contract_type,
        monitoring_config={
            "watch_upgrades": contract_type == "proxy",
            "watch_ownership": True,
            "watch_pause": contract_type == "pausable",
            "watch_roles": False,
            "watch_safe_signers": contract_type == "safe",
            "watch_timelock": contract_type == "timelock",
            "polling_plan": polling_plan,
        },
        last_known_state={},
        last_scanned_block=last_scanned_block,
        needs_polling=needs_polling,
        is_active=True,
        enrollment_source="auto",
    )
    session.add(mc)
    session.commit()
    return mc


# ---------------------------------------------------------------------------
# Unit tests: should_trigger_reanalysis
# ---------------------------------------------------------------------------


class TestShouldTriggerReanalysis:
    """Pure logic tests — no DB needed."""

    @pytest.mark.parametrize("event_type", sorted(_TRIGGERING_EVENT_TYPES))
    def test_triggering_event_types(self, event_type):
        assert should_trigger_reanalysis(event_type) is True

    @pytest.mark.parametrize(
        "event_type",
        [
            "paused",
            "unpaused",
            "role_granted",
            "role_revoked",
            "signer_added",
            "signer_removed",
            "threshold_changed",
            "timelock_scheduled",
            "timelock_executed",
            "delay_changed",
        ],
    )
    def test_non_triggering_event_types(self, event_type):
        assert should_trigger_reanalysis(event_type) is False

    @pytest.mark.parametrize("field", sorted(_REANALYSIS_POLL_FIELDS))
    def test_poll_triggering_fields(self, field):
        assert should_trigger_reanalysis("state_changed_poll", {"field": field}) is True

    @pytest.mark.parametrize("field", ["paused", "threshold", "min_delay", "owners"])
    def test_poll_non_triggering_fields(self, field):
        assert should_trigger_reanalysis("state_changed_poll", {"field": field}) is False

    def test_poll_no_data(self):
        assert should_trigger_reanalysis("state_changed_poll") is False
        assert should_trigger_reanalysis("state_changed_poll", {}) is False

    def test_effect_tags_writes_owner_triggers(self):
        """Generic-classification fallback: an event_type the canonical
        set doesn't recognize, but whose effect_tags say the emitter
        writes ``owner``, still triggers reanalysis. Covers protocols
        whose admin slots are renamed (e.g. fork ``protocolOwner``)."""
        assert (
            should_trigger_reanalysis(
                "controller_changed:state_variable:owner",
                {"effect_tags": {"writes": ["owner"]}},
            )
            is True
        )

    def test_effect_tags_delegates_triggers(self):
        """A DELEGATECALL in the emitter body is unconditionally
        upgrade-equivalent — proxy fallback / custom upgrade
        choreography. Trigger reanalysis."""
        assert (
            should_trigger_reanalysis(
                "controller_changed:custom",
                {"effect_tags": {"delegates": True}},
            )
            is True
        )

    def test_effect_tags_is_initializer_triggers(self):
        """Re-init detected by the modifier rather than the slot name —
        OZ forks that rename ``_initialized`` still get caught."""
        assert (
            should_trigger_reanalysis(
                "controller_changed:custom",
                {"effect_tags": {"is_initializer": True}},
            )
            is True
        )

    def test_handrolled_ownership_transferred_data_synthesizes_tags(self):
        """An ``ownership_transferred`` event passing through the
        hand-rolled decoder (``parse_governance_log``) now carries
        ``effect_tags={"writes": ["owner"]}`` in its data. Verify the
        reanalysis check fires when given that shape — i.e. the
        synthesis path produces a tag-equivalent verdict to the bare
        event_type path. This is the production path: scan_for_events
        always passes event_data (which includes effect_tags) when it
        queues a reanalysis job."""
        data = {
            "old_owner": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "new_owner": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
            "effect_tags": {"writes": ["owner"]},
        }
        assert should_trigger_reanalysis("ownership_transferred", data) is True

    def test_handrolled_upgraded_data_synthesizes_tags(self):
        """Same shape as above but for proxy Upgraded — verifies the
        ``delegates: True`` path fires when the hand-rolled decoder
        attaches it."""
        data = {
            "implementation": "0x" + "aa" * 20,
            "effect_tags": {"writes": ["implementation"], "delegates": True},
        }
        assert should_trigger_reanalysis("upgraded", data) is True


# ---------------------------------------------------------------------------
# DB integration tests: maybe_queue_reanalysis
# ---------------------------------------------------------------------------


class TestMaybeQueueReanalysis:
    """Tests that exercise the full DB path (requires PostgreSQL)."""

    def test_upgrade_queues_job(self, db_session):
        mc = _make_monitored_contract(db_session, "0x" + "aa" * 20, "proxy")
        job = maybe_queue_reanalysis(db_session, mc, "upgraded")
        assert job is not None
        assert job.address == mc.address
        assert job.status == JobStatus.queued
        assert job.stage == JobStage.discovery
        req = job.request or {}
        assert req.get("reanalysis_trigger") == "upgraded"
        assert req.get("chain") == "ethereum"

    @pytest.mark.parametrize(
        ("addr_byte", "contract_type", "event_type"),
        [
            ("bb", "regular", "ownership_transferred"),
            ("cc", "proxy", "admin_changed"),
            ("dd", "proxy", "beacon_upgraded"),
        ],
    )
    def test_triggering_event_queues_job(self, db_session, addr_byte, contract_type, event_type):
        mc = _make_monitored_contract(db_session, "0x" + addr_byte * 20, contract_type)
        job = maybe_queue_reanalysis(db_session, mc, event_type)
        assert job is not None
        assert job.address == mc.address
        assert job.request is not None
        assert job.request.get("reanalysis_trigger") == event_type

    def test_non_triggering_event_returns_none(self, db_session):
        mc = _make_monitored_contract(db_session, "0x" + "ee" * 20)
        for event_type in ("paused", "unpaused", "role_granted", "signer_added", "delay_changed"):
            assert maybe_queue_reanalysis(db_session, mc, event_type) is None

        # Verify no jobs were created
        jobs = db_session.execute(select(Job).where(func.lower(Job.address) == mc.address.lower())).scalars().all()
        assert len(jobs) == 0

    def test_dedup_skips_when_job_in_flight(self, db_session):
        addr = "0x" + "ff" * 20
        mc = _make_monitored_contract(db_session, addr, "proxy")

        # First call creates a job
        job1 = maybe_queue_reanalysis(db_session, mc, "upgraded")
        assert job1 is not None

        # Second call should skip (job1 is queued)
        job2 = maybe_queue_reanalysis(db_session, mc, "upgraded")
        assert job2 is None

        # Only one job exists
        jobs = db_session.execute(select(Job).where(func.lower(Job.address) == addr.lower())).scalars().all()
        assert len(jobs) == 1

    def test_dedup_allows_after_completion(self, db_session):
        addr = "0x" + "ab" * 20
        mc = _make_monitored_contract(db_session, addr, "proxy")

        job1 = maybe_queue_reanalysis(db_session, mc, "upgraded")
        assert job1 is not None

        # Mark the first job as completed
        job1.status = JobStatus.completed
        job1.stage = JobStage.done
        db_session.commit()

        # Now a new job should be created
        job2 = maybe_queue_reanalysis(db_session, mc, "upgraded")
        assert job2 is not None
        assert job2.id != job1.id

    def test_dedup_respects_chain(self, db_session, monkeypatch):
        # This test models a deployment where base has passed the inv-14
        # enablement checklist; re-analysis gates off-allowlist chains (inv. 14),
        # so make the base-enabled premise explicit rather than relying on {1}.
        monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")
        addr = "0x" + "cd" * 20

        mc_eth = _make_monitored_contract(db_session, addr, "proxy", chain="ethereum")
        mc_base = _make_monitored_contract(db_session, addr, "proxy", chain="base")

        # Create job for ethereum
        job_eth = maybe_queue_reanalysis(db_session, mc_eth, "upgraded")
        assert job_eth is not None

        # Should still allow a job for base (different chain)
        job_base = maybe_queue_reanalysis(db_session, mc_base, "upgraded")
        assert job_base is not None
        assert job_base.id != job_eth.id

    def test_protocol_id_propagates(self, db_session):
        proto = _make_protocol(db_session, "Aave")
        mc = _make_monitored_contract(
            db_session,
            "0x" + "11" * 20,
            "proxy",
            protocol_id=proto.id,
        )
        job = maybe_queue_reanalysis(db_session, mc, "upgraded")
        assert job is not None
        assert job.protocol_id == proto.id
        assert job.request is not None
        assert job.request.get("protocol_id") == proto.id

    def test_poll_implementation_triggers_job(self, db_session):
        mc = _make_monitored_contract(db_session, "0x" + "22" * 20, "proxy")
        data = {"field": "implementation", "old_value": "0xold", "new_value": "0xnew"}
        job = maybe_queue_reanalysis(db_session, mc, "state_changed_poll", data)
        assert job is not None
        assert job.request is not None
        assert job.request.get("reanalysis_trigger") == "poll:implementation"

    def test_poll_owner_triggers_job(self, db_session):
        mc = _make_monitored_contract(db_session, "0x" + "33" * 20)
        data = {"field": "owner", "old_value": "0xold", "new_value": "0xnew"}
        job = maybe_queue_reanalysis(db_session, mc, "state_changed_poll", data)
        assert job is not None
        assert job.request is not None
        assert job.request.get("reanalysis_trigger") == "poll:owner"

    def test_poll_paused_does_not_trigger(self, db_session):
        mc = _make_monitored_contract(db_session, "0x" + "44" * 20, "pausable")
        data = {"field": "paused", "old_value": "False", "new_value": "True"}
        job = maybe_queue_reanalysis(db_session, mc, "state_changed_poll", data)
        assert job is None

    def test_different_event_types_dedup_each_other(self, db_session):
        """An upgrade and an ownership_transferred for the same address produce one job."""
        addr = "0x" + "55" * 20
        mc = _make_monitored_contract(db_session, addr, "proxy")

        job1 = maybe_queue_reanalysis(db_session, mc, "upgraded")
        assert job1 is not None

        # A different event type for the same address should still be deduped
        job2 = maybe_queue_reanalysis(db_session, mc, "ownership_transferred")
        assert job2 is None

    def test_cache_compatibility(self, db_session):
        """A re-analysis job does not break find_completed_static_cache.

        The cache finder looks for completed+done jobs with source files and
        contract_analysis artifacts. A queued re-analysis job should not
        interfere because it has status=queued, stage=discovery.
        """
        from db.queue import find_completed_static_cache, store_artifact, store_source_files

        addr = "0x" + "66" * 20

        # Create a completed job that acts as a cache source
        old_job = Job(
            address=addr.lower(),
            status=JobStatus.completed,
            stage=JobStage.done,
            request={"address": addr.lower(), "chain": "ethereum"},
        )
        db_session.add(old_job)
        db_session.commit()
        db_session.refresh(old_job)

        store_source_files(db_session, old_job.id, {"src/A.sol": "contract A {}"})
        store_artifact(db_session, old_job.id, "contract_analysis", data={"functions": []})

        # Create Contract + ContractSummary (required by find_completed_static_cache)
        contract = Contract(
            job_id=old_job.id,
            address=addr.lower(),
            chain="ethereum",
            contract_name="TestContract",
        )
        db_session.add(contract)
        db_session.commit()
        db_session.refresh(contract)

        summary = ContractSummary(contract_id=contract.id, control_model="owner")
        db_session.add(summary)
        db_session.commit()

        # Now queue a re-analysis job
        mc = _make_monitored_contract(db_session, addr, "proxy")
        reanalysis_job = maybe_queue_reanalysis(db_session, mc, "upgraded")
        assert reanalysis_job is not None
        assert reanalysis_job.status == JobStatus.queued

        # find_completed_static_cache should still find the OLD completed job
        cached = find_completed_static_cache(db_session, addr, chain="ethereum")
        assert cached is not None
        assert cached.id == old_job.id
        assert cached.status == JobStatus.completed


# ---------------------------------------------------------------------------
# Anvil integration tests: scan → detect → queue
# ---------------------------------------------------------------------------


@requires_anvil
class TestReanalysisAnvilIntegration:
    """Full flow tests: deploy contracts on Anvil, trigger events via
    scan_for_events, verify re-analysis jobs are queued."""

    def test_proxy_upgrade_triggers_reanalysis_job(self, anvil_env, db_session):
        """Deploy proxy, upgrade, scan → reanalysis job queued."""
        rpc_url, tmp_path = anvil_env
        from services.monitoring.unified_watcher import scan_for_events

        impl_v1 = _compile_and_deploy(IMPL_V1_SOURCE, "ImplV1", [], rpc_url, PRIVATE_KEY, tmp_path)
        impl_v2 = _compile_and_deploy(IMPL_V2_SOURCE, "ImplV2", [], rpc_url, PRIVATE_KEY, tmp_path)
        proxy_addr = _compile_and_deploy(
            PROXY_SOURCE,
            "TestProxy",
            [impl_v1],
            rpc_url,
            PRIVATE_KEY,
            tmp_path,
        )

        current_block = int(_cast(["block-number"], rpc_url))

        proto = _make_protocol(db_session, "ProxyTest")
        _make_monitored_contract(
            db_session,
            proxy_addr,
            "proxy",
            current_block,
            protocol_id=proto.id,
        )

        # Upgrade
        _cast_send(proxy_addr, "upgradeTo(address)", [impl_v2], rpc_url, PRIVATE_KEY)

        events = scan_for_events(db_session, rpc_url)
        assert any(e.event_type == "upgraded" for e in events)

        # Verify re-analysis job was created
        jobs = (
            db_session.execute(
                select(Job).where(
                    func.lower(Job.address) == proxy_addr.lower(),
                    Job.status == JobStatus.queued,
                )
            )
            .scalars()
            .all()
        )
        assert len(jobs) == 1
        job = jobs[0]
        assert job.protocol_id == proto.id
        assert job.request.get("reanalysis_trigger") == "upgraded"
        assert job.stage == JobStage.discovery

    def test_ownership_transfer_triggers_reanalysis_job(self, anvil_env, db_session):
        """Deploy ownable, transfer, scan → reanalysis job queued."""
        rpc_url, tmp_path = anvil_env
        from services.monitoring.unified_watcher import scan_for_events

        addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
        current_block = int(_cast(["block-number"], rpc_url))

        proto = _make_protocol(db_session, "OwnableTest")
        _make_monitored_contract(
            db_session,
            addr,
            "regular",
            current_block,
            protocol_id=proto.id,
        )

        new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
        _cast_send(addr, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)

        events = scan_for_events(db_session, rpc_url)
        assert any(e.event_type == "ownership_transferred" for e in events)

        jobs = (
            db_session.execute(
                select(Job).where(
                    func.lower(Job.address) == addr.lower(),
                    Job.status == JobStatus.queued,
                )
            )
            .scalars()
            .all()
        )
        assert len(jobs) == 1
        assert jobs[0].request.get("reanalysis_trigger") == "ownership_transferred"

    def test_admin_changed_triggers_reanalysis_job(self, anvil_env, db_session):
        """Deploy admin proxy, change admin, scan → reanalysis job queued."""
        rpc_url, tmp_path = anvil_env
        from services.monitoring.unified_watcher import scan_for_events

        addr = _compile_and_deploy(
            ADMIN_PROXY_SOURCE,
            "TestAdminProxy",
            [],
            rpc_url,
            PRIVATE_KEY,
            tmp_path,
        )
        current_block = int(_cast(["block-number"], rpc_url))

        proto = _make_protocol(db_session, "AdminTest")
        _make_monitored_contract(
            db_session,
            addr,
            "proxy",
            current_block,
            protocol_id=proto.id,
        )

        new_admin = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
        _cast_send(addr, "changeAdmin(address)", [new_admin], rpc_url, PRIVATE_KEY)

        events = scan_for_events(db_session, rpc_url)
        assert any(e.event_type == "admin_changed" for e in events)

        jobs = (
            db_session.execute(
                select(Job).where(
                    func.lower(Job.address) == addr.lower(),
                    Job.status == JobStatus.queued,
                )
            )
            .scalars()
            .all()
        )
        assert len(jobs) == 1
        assert jobs[0].request.get("reanalysis_trigger") == "admin_changed"

    def test_pause_does_not_trigger_reanalysis(self, anvil_env, db_session):
        """Deploy pausable, pause, scan → NO reanalysis job."""
        rpc_url, tmp_path = anvil_env
        from services.monitoring.unified_watcher import scan_for_events

        addr = _compile_and_deploy(PAUSABLE_SOURCE, "TestPausable", [], rpc_url, PRIVATE_KEY, tmp_path)
        current_block = int(_cast(["block-number"], rpc_url))

        _make_monitored_contract(db_session, addr, "pausable", current_block)

        _cast_send(addr, "pause()", [], rpc_url, PRIVATE_KEY)

        events = scan_for_events(db_session, rpc_url)
        assert any(e.event_type == "paused" for e in events)

        # No reanalysis job should exist
        jobs = db_session.execute(select(Job).where(func.lower(Job.address) == addr.lower())).scalars().all()
        assert len(jobs) == 0

    def test_multiple_upgrades_single_scan_creates_one_job(self, anvil_env, db_session):
        """Two upgrades in consecutive blocks → only one reanalysis job (dedup)."""
        rpc_url, tmp_path = anvil_env
        from services.monitoring.unified_watcher import scan_for_events

        impl_v1 = _compile_and_deploy(IMPL_V1_SOURCE, "ImplV1", [], rpc_url, PRIVATE_KEY, tmp_path)
        impl_v2 = _compile_and_deploy(IMPL_V2_SOURCE, "ImplV2", [], rpc_url, PRIVATE_KEY, tmp_path)
        # Deploy a third impl for the second upgrade
        impl_v3_source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract ImplV3 { uint256 public version = 3; }
"""
        impl_v3 = _compile_and_deploy(impl_v3_source, "ImplV3", [], rpc_url, PRIVATE_KEY, tmp_path)

        proxy_addr = _compile_and_deploy(
            PROXY_SOURCE,
            "TestProxy",
            [impl_v1],
            rpc_url,
            PRIVATE_KEY,
            tmp_path,
        )

        current_block = int(_cast(["block-number"], rpc_url))
        _make_monitored_contract(db_session, proxy_addr, "proxy", current_block)

        # Two upgrades in quick succession
        _cast_send(proxy_addr, "upgradeTo(address)", [impl_v2], rpc_url, PRIVATE_KEY)
        _cast_send(proxy_addr, "upgradeTo(address)", [impl_v3], rpc_url, PRIVATE_KEY)

        events = scan_for_events(db_session, rpc_url)
        upgrade_events = [e for e in events if e.event_type == "upgraded"]
        assert len(upgrade_events) == 2  # Two upgrade events detected

        # But only ONE reanalysis job (second upgrade deduped against first)
        jobs = (
            db_session.execute(
                select(Job).where(
                    func.lower(Job.address) == proxy_addr.lower(),
                    Job.status == JobStatus.queued,
                )
            )
            .scalars()
            .all()
        )
        assert len(jobs) == 1

    def test_poll_implementation_change_triggers_reanalysis(self, anvil_env, db_session):
        """Poll detects impl change → reanalysis job queued."""
        rpc_url, tmp_path = anvil_env
        from services.monitoring.unified_watcher import poll_for_state_changes

        impl_v1 = _compile_and_deploy(IMPL_V1_SOURCE, "ImplV1", [], rpc_url, PRIVATE_KEY, tmp_path)
        impl_v2 = _compile_and_deploy(IMPL_V2_SOURCE, "ImplV2", [], rpc_url, PRIVATE_KEY, tmp_path)
        proxy_addr = _compile_and_deploy(
            PROXY_SOURCE,
            "TestProxy",
            [impl_v1],
            rpc_url,
            PRIVATE_KEY,
            tmp_path,
        )

        current_block = int(_cast(["block-number"], rpc_url))
        mc = _make_monitored_contract(
            db_session,
            proxy_addr,
            "proxy",
            current_block,
            needs_polling=True,
        )
        mc.last_known_state = {"implementation": impl_v1.lower()}
        db_session.commit()

        # Upgrade (poll doesn't read events, it reads storage)
        _cast_send(proxy_addr, "upgradeTo(address)", [impl_v2], rpc_url, PRIVATE_KEY)

        events = poll_for_state_changes(db_session, rpc_url)
        impl_changes = [e for e in events if e.data and e.data.get("field") == "implementation"]
        assert len(impl_changes) == 1

        # Reanalysis job should be queued
        jobs = (
            db_session.execute(
                select(Job).where(
                    func.lower(Job.address) == proxy_addr.lower(),
                    Job.status == JobStatus.queued,
                )
            )
            .scalars()
            .all()
        )
        assert len(jobs) == 1
        assert jobs[0].request.get("reanalysis_trigger") == "poll:implementation"

    def test_mixed_events_only_trigger_for_relevant(self, anvil_env, db_session):
        """Multiple contracts, mixed events → only triggering ones get jobs."""
        rpc_url, tmp_path = anvil_env
        from services.monitoring.unified_watcher import scan_for_events

        # Deploy ownable (trigger) and pausable (no trigger)
        ownable_addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
        pausable_addr = _compile_and_deploy(PAUSABLE_SOURCE, "TestPausable", [], rpc_url, PRIVATE_KEY, tmp_path)

        current_block = int(_cast(["block-number"], rpc_url))

        _make_monitored_contract(db_session, ownable_addr, "regular", current_block)
        _make_monitored_contract(db_session, pausable_addr, "pausable", current_block)

        # Trigger both
        new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
        _cast_send(ownable_addr, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)
        _cast_send(pausable_addr, "pause()", [], rpc_url, PRIVATE_KEY)

        events = scan_for_events(db_session, rpc_url)
        assert len(events) >= 2

        # Only the ownable contract should have a reanalysis job
        ownable_jobs = (
            db_session.execute(select(Job).where(func.lower(Job.address) == ownable_addr.lower())).scalars().all()
        )
        assert len(ownable_jobs) == 1

        pausable_jobs = (
            db_session.execute(select(Job).where(func.lower(Job.address) == pausable_addr.lower())).scalars().all()
        )
        assert len(pausable_jobs) == 0


# ---------------------------------------------------------------------------
# Webhook embed tests: event annotation + completion notification
# ---------------------------------------------------------------------------


@requires_anvil
class TestEventEmbedAnnotation:
    """Verify that the event webhook embed shows a reanalysis note."""

    def test_event_data_contains_reanalysis_job_id(self, anvil_env, db_session):
        """After scan, the MonitoredEvent.data has reanalysis_job_id."""
        rpc_url, tmp_path = anvil_env
        from services.monitoring.unified_watcher import scan_for_events

        addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
        current_block = int(_cast(["block-number"], rpc_url))
        _make_monitored_contract(db_session, addr, "regular", current_block)

        new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
        _cast_send(addr, "transferOwnership(address)", [new_owner], rpc_url, PRIVATE_KEY)

        events = scan_for_events(db_session, rpc_url)
        ownership_events = [e for e in events if e.event_type == "ownership_transferred"]
        assert len(ownership_events) == 1

        evt = ownership_events[0]
        assert evt.data is not None
        assert "reanalysis_job_id" in evt.data
        # The job ID should match an actual queued job
        job_id = evt.data["reanalysis_job_id"]
        job = db_session.get(Job, uuid.UUID(job_id))
        assert job is not None
        assert job.status == JobStatus.queued

    def test_non_triggering_event_has_no_job_id(self, anvil_env, db_session):
        """Pause events do NOT get annotated with reanalysis_job_id."""
        rpc_url, tmp_path = anvil_env
        from services.monitoring.unified_watcher import scan_for_events

        addr = _compile_and_deploy(PAUSABLE_SOURCE, "TestPausable", [], rpc_url, PRIVATE_KEY, tmp_path)
        current_block = int(_cast(["block-number"], rpc_url))
        _make_monitored_contract(db_session, addr, "pausable", current_block)

        _cast_send(addr, "pause()", [], rpc_url, PRIVATE_KEY)

        events = scan_for_events(db_session, rpc_url)
        for evt in events:
            data = evt.data or {}
            assert "reanalysis_job_id" not in data


# ---------------------------------------------------------------------------
# Embed shape only — no chain involved, so these stay outside the anvil class.
# ---------------------------------------------------------------------------


def test_embed_includes_reanalysis_field(db_session):
    """_format_governance_embed adds a Re-analysis field when job ID is present."""
    from services.monitoring.notifier import _format_governance_embed

    mc = _make_monitored_contract(db_session, "0x" + "a1" * 20)
    evt = MonitoredEvent(
        id=uuid.uuid4(),
        monitored_contract_id=mc.id,
        event_type="upgraded",
        block_number=100,
        tx_hash="0x" + "ab" * 32,
        data={"implementation": "0x" + "b2" * 20, "reanalysis_job_id": "abcd1234-0000-0000-0000-000000000000"},
    )
    db_session.add(evt)
    db_session.commit()
    db_session.refresh(evt)

    embed = _format_governance_embed(evt, db_session)
    field_map = {f["name"]: f["value"] for f in embed["fields"]}
    assert "Re-analysis" in field_map
    assert "abcd1234" in field_map["Re-analysis"]


def test_embed_without_reanalysis_has_no_field(db_session):
    """Normal event embed does NOT have a Re-analysis field."""
    from services.monitoring.notifier import _format_governance_embed

    mc = _make_monitored_contract(db_session, "0x" + "c3" * 20, "pausable")
    evt = MonitoredEvent(
        id=uuid.uuid4(),
        monitored_contract_id=mc.id,
        event_type="paused",
        block_number=200,
        tx_hash="0x" + "cd" * 32,
        data={"account": "0x" + "d4" * 20},
    )
    db_session.add(evt)
    db_session.commit()
    db_session.refresh(evt)

    embed = _format_governance_embed(evt, db_session)
    field_names = [f["name"] for f in embed["fields"]]
    assert "Re-analysis" not in field_names


class TestSnapshotAndDiff:
    """Test the snapshot capture and diff logic."""

    def test_snapshot_captures_contract_state(self, db_session):
        from services.monitoring.reanalysis import _build_snapshot

        addr = "0x" + "a1" * 20
        proto = _make_protocol(db_session, "SnapTest")
        contract = Contract(
            address=addr.lower(),
            chain="ethereum",
            protocol_id=proto.id,
            contract_name="SnapContract",
            implementation="0x" + "b2" * 20,
            admin="0x" + "c3" * 20,
        )
        db_session.add(contract)
        db_session.commit()
        db_session.refresh(contract)

        summary = ContractSummary(
            contract_id=contract.id,
            control_model="owner",
            is_pausable=True,
        )
        db_session.add(summary)
        db_session.commit()

        mc = _make_monitored_contract(db_session, addr, "proxy", protocol_id=proto.id)
        mc.contract_id = contract.id
        db_session.commit()

        snap = _build_snapshot(db_session, mc)
        assert snap["implementation"] == "0x" + "b2" * 20
        assert snap["admin"] == "0x" + "c3" * 20
        assert snap["control_model"] == "owner"
        assert snap["is_pausable"] is True

    def test_snapshot_stored_in_job_request(self, db_session):
        addr = "0x" + "d4" * 20
        proto = _make_protocol(db_session, "ReqSnapTest")
        contract = Contract(
            address=addr.lower(),
            chain="ethereum",
            protocol_id=proto.id,
            implementation="0x" + "e5" * 20,
        )
        db_session.add(contract)
        db_session.commit()
        db_session.refresh(contract)

        summary = ContractSummary(contract_id=contract.id, control_model="owner")
        db_session.add(summary)
        db_session.commit()

        mc = _make_monitored_contract(db_session, addr, "proxy", protocol_id=proto.id)
        mc.contract_id = contract.id
        db_session.commit()

        job = maybe_queue_reanalysis(db_session, mc, "upgraded")
        assert job is not None
        assert job.request is not None
        snap = job.request.get("reanalysis_snapshot", {})
        assert snap.get("implementation") == "0x" + "e5" * 20

    def test_diff_detects_implementation_change(self, db_session):
        from services.monitoring.reanalysis import build_reanalysis_diff

        addr = "0x" + "f6" * 20
        contract = Contract(
            address=addr.lower(),
            chain="ethereum",
            implementation="0x" + "11" * 20,  # NEW impl
        )
        db_session.add(contract)
        db_session.commit()

        job = Job(
            address=addr.lower(),
            status=JobStatus.completed,
            stage=JobStage.done,
            request={
                "address": addr.lower(),
                "chain": "ethereum",
                "reanalysis_trigger": "upgraded",
                "reanalysis_snapshot": {
                    "implementation": "0x" + "00" * 20,  # OLD impl
                },
            },
        )
        db_session.add(job)
        db_session.commit()

        changes = build_reanalysis_diff(db_session, job)
        assert any("Implementation" in c for c in changes)

    def test_diff_detects_function_changes(self, db_session):
        from services.monitoring.reanalysis import build_reanalysis_diff

        addr = "0x" + "a7" * 20
        contract = Contract(address=addr.lower(), chain="ethereum")
        db_session.add(contract)
        db_session.commit()
        db_session.refresh(contract)

        # Add new functions
        from db.models import EffectiveFunction

        for name in ["transfer", "approve", "newFunction"]:
            db_session.add(
                EffectiveFunction(
                    contract_id=contract.id,
                    function_name=name,
                )
            )
        db_session.commit()

        job = Job(
            address=addr.lower(),
            status=JobStatus.completed,
            stage=JobStage.done,
            request={
                "address": addr.lower(),
                "chain": "ethereum",
                "reanalysis_trigger": "upgraded",
                "reanalysis_snapshot": {
                    "effective_functions": ["transfer", "approve"],
                },
            },
        )
        db_session.add(job)
        db_session.commit()

        changes = build_reanalysis_diff(db_session, job)
        assert any("newFunction" in c for c in changes)

    def test_diff_empty_when_nothing_changed(self, db_session):
        from services.monitoring.reanalysis import build_reanalysis_diff

        addr = "0x" + "b8" * 20
        contract = Contract(
            address=addr.lower(),
            chain="ethereum",
            implementation="0x" + "cc" * 20,
        )
        db_session.add(contract)
        db_session.commit()

        job = Job(
            address=addr.lower(),
            status=JobStatus.completed,
            stage=JobStage.done,
            request={
                "address": addr.lower(),
                "chain": "ethereum",
                "reanalysis_trigger": "upgraded",
                "reanalysis_snapshot": {
                    "implementation": "0x" + "cc" * 20,  # same
                },
            },
        )
        db_session.add(job)
        db_session.commit()

        changes = build_reanalysis_diff(db_session, job)
        assert changes == []


class TestCompletionWebhook:
    """Test the reanalysis completion Discord notification."""

    @pytest.fixture()
    def _protocol_with_sub(self, db_session):
        """Create a protocol with a Discord subscription."""
        from db.models import ProtocolSubscription

        proto = _make_protocol(db_session, "WebhookTest")
        sub = ProtocolSubscription(
            protocol_id=proto.id,
            discord_webhook_url="https://discord.com/api/webhooks/test/reanalysis",
            label="test-sub",
        )
        db_session.add(sub)
        db_session.commit()
        return proto

    def test_completion_sends_webhook(self, db_session, _protocol_with_sub):
        from unittest.mock import MagicMock, patch

        from services.monitoring.notifier import notify_reanalysis_complete

        proto = _protocol_with_sub
        addr = "0x" + "d9" * 20

        contract = Contract(
            address=addr.lower(),
            chain="ethereum",
            implementation="0x" + "11" * 20,
            contract_name="TestVault",
            protocol_id=proto.id,
        )
        db_session.add(contract)
        db_session.commit()

        job = Job(
            address=addr.lower(),
            status=JobStatus.completed,
            stage=JobStage.done,
            protocol_id=proto.id,
            request={
                "address": addr.lower(),
                "chain": "ethereum",
                "reanalysis_trigger": "upgraded",
                "reanalysis_snapshot": {"implementation": "0x" + "00" * 20},
            },
        )
        db_session.add(job)
        db_session.commit()
        db_session.refresh(job)

        with patch("services.monitoring.notifier.requests.post") as mock_post:
            mock_post.return_value = MagicMock(ok=True)
            notify_reanalysis_complete(db_session, job)

            mock_post.assert_called_once()
            payload = mock_post.call_args[1]["json"]
            embed = payload["embeds"][0]

            assert "Re-analysis complete" in embed["title"]
            assert "TestVault" in embed["title"]
            assert embed["color"] == 0x2ECC71  # green

            field_map = {f["name"]: f["value"] for f in embed["fields"]}
            assert "upgraded" in field_map["Trigger"]
            assert str(job.id)[:8] in field_map["Job"]
            assert "Implementation" in field_map["Changes detected"]

    def test_completion_no_webhook_without_protocol(self, db_session):
        """Job without protocol_id → no webhook sent."""
        from unittest.mock import patch

        from services.monitoring.notifier import notify_reanalysis_complete

        job = Job(
            address="0x" + "e0" * 20,
            status=JobStatus.completed,
            stage=JobStage.done,
            protocol_id=None,
            request={"reanalysis_trigger": "upgraded", "address": "0x" + "e0" * 20, "chain": "ethereum"},
        )
        db_session.add(job)
        db_session.commit()
        db_session.refresh(job)

        with patch("services.monitoring.notifier.requests.post") as mock_post:
            notify_reanalysis_complete(db_session, job)
            mock_post.assert_not_called()

    def test_completion_no_webhook_without_subscriptions(self, db_session):
        """Protocol with no subscriptions → no webhook sent."""
        from unittest.mock import patch

        from services.monitoring.notifier import notify_reanalysis_complete

        proto = _make_protocol(db_session, "NoSubTest")
        job = Job(
            address="0x" + "f1" * 20,
            status=JobStatus.completed,
            stage=JobStage.done,
            protocol_id=proto.id,
            request={"reanalysis_trigger": "upgraded", "address": "0x" + "f1" * 20, "chain": "ethereum"},
        )
        db_session.add(job)
        db_session.commit()
        db_session.refresh(job)

        with patch("services.monitoring.notifier.requests.post") as mock_post:
            notify_reanalysis_complete(db_session, job)
            mock_post.assert_not_called()

    def test_completion_shows_no_changes_when_identical(self, db_session, _protocol_with_sub):
        from unittest.mock import MagicMock, patch

        from services.monitoring.notifier import notify_reanalysis_complete

        proto = _protocol_with_sub
        addr = "0x" + "a2" * 20

        contract = Contract(
            address=addr.lower(),
            chain="ethereum",
            implementation="0x" + "bb" * 20,
            protocol_id=proto.id,
        )
        db_session.add(contract)
        db_session.commit()

        job = Job(
            address=addr.lower(),
            status=JobStatus.completed,
            stage=JobStage.done,
            protocol_id=proto.id,
            request={
                "address": addr.lower(),
                "chain": "ethereum",
                "reanalysis_trigger": "upgraded",
                "reanalysis_snapshot": {"implementation": "0x" + "bb" * 20},  # same
            },
        )
        db_session.add(job)
        db_session.commit()
        db_session.refresh(job)

        with patch("services.monitoring.notifier.requests.post") as mock_post:
            mock_post.return_value = MagicMock(ok=True)
            notify_reanalysis_complete(db_session, job)

            embed = mock_post.call_args[1]["json"]["embeds"][0]
            field_map = {f["name"]: f["value"] for f in embed["fields"]}
            assert "No significant differences" in field_map["Changes detected"]

    def test_completion_embed_references_job_id(self, db_session, _protocol_with_sub):
        """Both event and completion embeds reference the same Job ID."""
        from unittest.mock import MagicMock, patch

        from services.monitoring.notifier import _format_governance_embed, notify_reanalysis_complete

        proto = _protocol_with_sub
        addr = "0x" + "b3" * 20

        contract = Contract(
            address=addr.lower(),
            chain="ethereum",
            protocol_id=proto.id,
        )
        db_session.add(contract)
        db_session.commit()

        mc = _make_monitored_contract(db_session, addr, "proxy", protocol_id=proto.id)
        mc.contract_id = contract.id
        db_session.commit()

        # Simulate: event with reanalysis_job_id
        job = Job(
            address=addr.lower(),
            status=JobStatus.completed,
            stage=JobStage.done,
            protocol_id=proto.id,
            request={
                "address": addr.lower(),
                "chain": "ethereum",
                "reanalysis_trigger": "upgraded",
                "reanalysis_snapshot": {},
            },
        )
        db_session.add(job)
        db_session.commit()
        db_session.refresh(job)

        short_id = str(job.id)[:8]

        # Event embed
        evt = MonitoredEvent(
            id=uuid.uuid4(),
            monitored_contract_id=mc.id,
            event_type="upgraded",
            block_number=500,
            tx_hash="0x" + "ff" * 32,
            data={"implementation": "0x" + "22" * 20, "reanalysis_job_id": str(job.id)},
        )
        db_session.add(evt)
        db_session.commit()
        db_session.refresh(evt)

        event_embed = _format_governance_embed(evt, db_session)
        event_fields = {f["name"]: f["value"] for f in event_embed["fields"]}
        assert short_id in event_fields["Re-analysis"]

        # Completion embed
        with patch("services.monitoring.notifier.requests.post") as mock_post:
            mock_post.return_value = MagicMock(ok=True)
            notify_reanalysis_complete(db_session, job)

            completion_embed = mock_post.call_args[1]["json"]["embeds"][0]
            completion_fields = {f["name"]: f["value"] for f in completion_embed["fields"]}
            assert short_id in completion_fields["Job"]
