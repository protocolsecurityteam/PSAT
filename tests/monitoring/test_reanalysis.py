"""Anvil tests need anvil/cast/forge on PATH; all need TEST_DATABASE_URL."""

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
    maybe_queue_reanalysis,
    should_trigger_reanalysis,
)
from tests.conftest import requires_postgres
from tests.support.anvil import (
    IMPL_V1_SOURCE,
    IMPL_V2_SOURCE,
    PRIVATE_KEY,
    PROXY_SOURCE,
    _cast,
    _cast_send,
    _compile_and_deploy,
    anvil_env,  # noqa: F401
)
from tests.support.isolation import _disable_scan_confirmation_depth  # noqa: F401  (fixture, registered by import)

# ``upgraded_revision`` is included because Aave V2's revision bump is a delegate-target swap.


_has_anvil = shutil.which("anvil") is not None
_has_cast = shutil.which("cast") is not None
_has_forge = shutil.which("forge") is not None

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")

requires_anvil = pytest.mark.skipif(
    not (_has_anvil and _has_cast and _has_forge),
    reason="Foundry tools (anvil/cast/forge) not found on PATH",
)

pytestmark = [requires_postgres, pytest.mark.anvil, pytest.mark.compile]


@pytest.fixture()
def db_session():
    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine)

    session = SASession(engine, expire_on_commit=False)
    try:
        yield session
    finally:
        session.rollback()
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

    # The vendored EIP-1967 entry lets the storage-slot poll read the upgraded value.
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


class TestShouldTriggerReanalysis:
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

    @pytest.mark.parametrize(
        "args",
        [
            pytest.param(({"field": "paused"},), id="field_paused"),
            pytest.param(({"field": "threshold"},), id="field_threshold"),
            pytest.param(({"field": "min_delay"},), id="field_min_delay"),
            pytest.param(({"field": "owners"},), id="field_owners"),
            pytest.param((), id="no_data"),
            pytest.param(({},), id="empty_data"),
        ],
    )
    def test_poll_non_triggering_data(self, args):
        assert should_trigger_reanalysis("state_changed_poll", *args) is False

    @pytest.mark.parametrize(
        ("event_type", "effect_tags"),
        [
            # Renamed admin slots (e.g. ``protocolOwner``) still trigger.
            pytest.param("controller_changed:state_variable:owner", {"writes": ["owner"]}, id="writes_owner"),
            pytest.param("controller_changed:custom", {"delegates": True}, id="delegates"),
            # Detected by modifier, so forks renaming ``_initialized`` are caught.
            pytest.param("controller_changed:custom", {"is_initializer": True}, id="is_initializer"),
        ],
    )
    def test_effect_tags_trigger(self, event_type, effect_tags):
        assert should_trigger_reanalysis(event_type, {"effect_tags": effect_tags}) is True


class TestMaybeQueueReanalysis:
    def test_dedup_skips_when_job_in_flight(self, db_session):
        addr = "0x" + "ff" * 20
        mc = _make_monitored_contract(db_session, addr, "proxy")

        job1 = maybe_queue_reanalysis(db_session, mc, "upgraded")
        assert job1 is not None

        job2 = maybe_queue_reanalysis(db_session, mc, "upgraded")
        assert job2 is None

        jobs = db_session.execute(select(Job).where(func.lower(Job.address) == addr.lower())).scalars().all()
        assert len(jobs) == 1

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

    @pytest.mark.parametrize(
        ("field", "addr_byte", "contract_type"),
        [
            pytest.param("implementation", "22", "proxy", id="implementation"),
            pytest.param("owner", "33", "regular", id="owner"),
        ],
    )
    def test_poll_field_triggers_job(self, db_session, field, addr_byte, contract_type):
        mc = _make_monitored_contract(db_session, "0x" + addr_byte * 20, contract_type)
        data = {"field": field, "old_value": "0xold", "new_value": "0xnew"}
        job = maybe_queue_reanalysis(db_session, mc, "state_changed_poll", data)
        assert job is not None
        assert job.request is not None
        assert job.request.get("reanalysis_trigger") == f"poll:{field}"


@requires_anvil
class TestReanalysisAnvilIntegration:
    def test_proxy_upgrade_triggers_reanalysis_job(self, anvil_env, db_session):
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

        _cast_send(proxy_addr, "upgradeTo(address)", [impl_v2], rpc_url, PRIVATE_KEY)

        events = scan_for_events(db_session, rpc_url)
        assert any(e.event_type == "upgraded" for e in events)

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

    def test_poll_implementation_change_triggers_reanalysis(self, anvil_env, db_session):
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

        _cast_send(proxy_addr, "upgradeTo(address)", [impl_v2], rpc_url, PRIVATE_KEY)

        events = poll_for_state_changes(db_session, rpc_url)
        impl_changes = [e for e in events if e.data and e.data.get("field") == "implementation"]
        assert len(impl_changes) == 1

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


# No chain involved, so these stay outside the anvil class.


def test_embed_includes_reanalysis_field(db_session):
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


class TestSnapshotAndDiff:
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

    def test_diff_detects_function_changes(self, db_session):
        from services.monitoring.reanalysis import build_reanalysis_diff

        addr = "0x" + "a7" * 20
        contract = Contract(address=addr.lower(), chain="ethereum")
        db_session.add(contract)
        db_session.commit()
        db_session.refresh(contract)

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


class TestCompletionWebhook:
    @pytest.fixture()
    def _protocol_with_sub(self, db_session):
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

        with patch("services.monitoring.notifier.requests.post") as mock_post:
            mock_post.return_value = MagicMock(ok=True)
            notify_reanalysis_complete(db_session, job)

            completion_embed = mock_post.call_args[1]["json"]["embeds"][0]
            completion_fields = {f["name"]: f["value"] for f in completion_embed["fields"]}
            assert short_id in completion_fields["Job"]
