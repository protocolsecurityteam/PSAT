"""Unit tests for the unified watcher and relational sync (no Anvil required).

Covers:
  - JSONB dirty-tracking (flag_modified)
  - Per-contract scan block filtering
  - Reverted eth_call handling in polling
  - Owner controller_id matching precision

Requires:
  - PostgreSQL (TEST_DATABASE_URL env var)

Run with:
    TEST_DATABASE_URL=postgresql://psat:psat@localhost:5433/psat_test \
        uv run pytest tests/test_watcher_unit.py -v
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session as SASession

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.models import (
    Base,
    Contract,
    ControllerValue,
    MonitoredContract,
    MonitoredEvent,
    Protocol,
    WatchedProxy,
)
from tests.conftest import requires_postgres

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")

pytestmark = requires_postgres


def ADDR(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


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
            ControllerValue,
            Contract,
            Protocol,
            WatchedProxy,
        ]:
            try:
                session.query(model).delete()
            except Exception:
                session.rollback()
        session.commit()
        session.close()
        engine.dispose()


# =========================================================================
# JSONB dirty-tracking
# =========================================================================


class TestJsonbDirtyTracking:
    """Verify that last_known_state changes survive a commit/refresh cycle."""

    def test_state_update_persists_after_commit(self, db_session: SASession):
        """Mutating last_known_state via dict-copy + reassign must persist.

        Without flag_modified(), SQLAlchemy may not detect the change on JSONB
        columns, causing the UPDATE to be silently skipped on commit.
        """
        mc = MonitoredContract(
            id=uuid.uuid4(),
            address=ADDR(1),
            chain="ethereum",
            contract_type="proxy",
            monitoring_config={},
            last_known_state={"implementation": ADDR(99)},
            last_scanned_block=100,
            needs_polling=True,
            is_active=True,
        )
        db_session.add(mc)
        db_session.commit()

        mc_id = mc.id

        # Simulate what _update_state_from_event does
        state = dict(mc.last_known_state or {})
        state["owner"] = ADDR(42)
        mc.last_known_state = state
        db_session.commit()

        # Re-load from a fresh query to bypass identity map caching
        db_session.expire_all()
        reloaded = db_session.get(MonitoredContract, mc_id)
        assert reloaded is not None
        assert reloaded.last_known_state is not None
        assert reloaded.last_known_state.get("owner") == ADDR(42), (
            "last_known_state change was lost after commit — flag_modified() is likely missing"
        )

    def test_poll_state_update_persists(self, db_session: SASession):
        """poll_for_state_changes also updates last_known_state the same way."""
        mc = MonitoredContract(
            id=uuid.uuid4(),
            address=ADDR(2),
            chain="ethereum",
            contract_type="pausable",
            monitoring_config={},
            last_known_state={"paused": False},
            last_scanned_block=100,
            needs_polling=True,
            is_active=True,
        )
        db_session.add(mc)
        db_session.commit()

        mc_id = mc.id

        state = dict(mc.last_known_state or {})
        state["paused"] = True
        mc.last_known_state = state
        db_session.commit()

        db_session.expire_all()
        reloaded = db_session.get(MonitoredContract, mc_id)
        assert reloaded is not None
        assert reloaded.last_known_state is not None
        assert reloaded.last_known_state.get("paused") is True


# =========================================================================
# Per-contract scan block filtering
# =========================================================================


class TestCohortScanBlock:
    """Verify the cohort scanner groups contracts by block bucket and never
    re-scans a block range a cohort has already covered.

    The scanner now issues eth_getLogs through the shared bisecting fetcher
    (``services.resolution.repos.event_logs_rpc``), so both RPC entry points
    are stubbed: the head read on ``unified_watcher.rpc_request`` and getLogs
    on the fetcher's ``rpc_request``.
    """

    @staticmethod
    def _install(monkeypatch, head, calls):
        def mock_rpc(url, method, params, *, chain_id=None):
            calls.append((method, params))
            if method == "eth_blockNumber":
                return hex(head)
            if method == "eth_getLogs":
                return []
            return None

        monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
        monkeypatch.setattr("services.monitoring.unified_watcher.rpc_request", mock_rpc)
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", mock_rpc)

    def test_contracts_at_different_heights_scan_in_separate_cohorts(self, db_session: SASession, monkeypatch):
        """A contract at block 100 (bucket 0) and one at 5000 (bucket 2) land
        in different cohorts; neither cohort's getLogs re-scans blocks the
        other has already covered."""
        from services.monitoring.unified_watcher import scan_for_events

        behind = ADDR(1)
        ahead = ADDR(2)
        db_session.add_all(
            [
                MonitoredContract(
                    id=uuid.uuid4(),
                    address=behind,
                    chain="ethereum",
                    contract_type="regular",
                    monitoring_config={},
                    last_known_state={},
                    last_scanned_block=100,
                    needs_polling=False,
                    is_active=True,
                ),
                MonitoredContract(
                    id=uuid.uuid4(),
                    address=ahead,
                    chain="ethereum",
                    contract_type="regular",
                    monitoring_config={},
                    last_known_state={},
                    last_scanned_block=5000,
                    needs_polling=False,
                    is_active=True,
                ),
            ]
        )
        db_session.commit()

        calls: list = []
        self._install(monkeypatch, 6000, calls)
        scan_for_events(db_session, "http://fake-rpc")

        log_calls = [c for c in calls if c[0] == "eth_getLogs"]
        # No getLogs ever mixes the two cohorts' addresses.
        for _, params in log_calls:
            addrs = {a.lower() for a in params[0]["address"]}
            assert addrs in ({behind.lower()}, {ahead.lower()})

        behind_calls = [c for c in log_calls if behind.lower() in {a.lower() for a in c[1][0]["address"]}]
        ahead_calls = [c for c in log_calls if ahead.lower() in {a.lower() for a in c[1][0]["address"]}]
        # The ahead cohort starts at 5001 — its already-scanned range is never re-read.
        assert min(int(c[1][0]["fromBlock"], 16) for c in ahead_calls) == 5001
        assert min(int(c[1][0]["fromBlock"], 16) for c in behind_calls) == 101

    def test_same_block_contracts_share_one_cohort(self, db_session: SASession, monkeypatch):
        """Contracts at the same block form one cohort scanned in a single
        multi-address getLogs over only the new blocks."""
        from services.monitoring.unified_watcher import scan_for_events

        db_session.add_all(
            [
                MonitoredContract(
                    id=uuid.uuid4(),
                    address=ADDR(1),
                    chain="ethereum",
                    contract_type="regular",
                    monitoring_config={},
                    last_known_state={},
                    last_scanned_block=1000,
                    needs_polling=False,
                    is_active=True,
                ),
                MonitoredContract(
                    id=uuid.uuid4(),
                    address=ADDR(2),
                    chain="ethereum",
                    contract_type="regular",
                    monitoring_config={},
                    last_known_state={},
                    last_scanned_block=1000,
                    needs_polling=False,
                    is_active=True,
                ),
            ]
        )
        db_session.commit()

        calls: list = []
        self._install(monkeypatch, 1500, calls)
        scan_for_events(db_session, "http://fake-rpc")

        log_calls = [c for c in calls if c[0] == "eth_getLogs"]
        assert len(log_calls) == 1
        assert {a.lower() for a in log_calls[0][1][0]["address"]} == {ADDR(1).lower(), ADDR(2).lower()}
        assert int(log_calls[0][1][0]["fromBlock"], 16) == 1001
        assert int(log_calls[0][1][0]["toBlock"], 16) == 1500


# =========================================================================
# Reverted eth_call in polling
# =========================================================================


class TestRevertedEthCallPolling:
    """Verify that reverted or garbage eth_call results don't produce events."""

    def test_revert_error_data_not_treated_as_address(self):
        """Revert ABI data should not be parsed as a valid address."""
        from utils.rpc import parse_address_result

        # Solidity revert: Error(string) selector + ABI-encoded "nope"
        revert_data = (
            "0x08c379a0"
            "0000000000000000000000000000000000000000000000000000000000000020"
            "0000000000000000000000000000000000000000000000000000000000000004"
            "6e6f706500000000000000000000000000000000000000000000000000000000"
        )
        result = parse_address_result(revert_data)
        assert result is None, f"Revert data was parsed as address: {result}"

    def test_short_revert_returns_none(self):
        """Short revert responses (< 66 chars) must return None."""
        from utils.rpc import parse_address_result

        assert parse_address_result("0x") is None
        assert parse_address_result("0x08c379a0") is None
        assert parse_address_result(None) is None
        assert parse_address_result("") is None

    def test_poll_skips_error_rpc_results(self, db_session: SASession):
        """An errored poll call produces no value and no event — and the
        contract's ``last_poll_status`` records the error while a
        successful-but-undecodable call records ``no_value``, not ``ok``.
        """
        from services.monitoring.polling_plan import build_polling_plan
        from services.monitoring.unified_watcher import poll_for_state_changes

        # ``custom`` proxy_type yields a single ``implementation()`` poll
        # entry — same dispatch shape as the prior contract_type-based
        # path, but exercised through the new polling_plan code path so
        # this test still pins the "errored RPC result → no event" rule.
        polling_plan = build_polling_plan(
            contract_type="proxy",
            proxy_type="custom",
            tracking_plan=None,
            tracked_topics=None,
        )
        # Add an owner entry too so the mock batch's index-1 revert
        # hits a real poll dispatch slot rather than being out-of-range.
        polling_plan.append(
            {
                "field": "owner",
                "kind": "getter_call",
                "target": "owner",
                "selector": "0x8da5cb5b",
                "type_kind": "address",
            }
        )

        mc = MonitoredContract(
            id=uuid.uuid4(),
            address=ADDR(1),
            chain="ethereum",
            contract_type="proxy",
            monitoring_config={"polling_plan": polling_plan},
            last_known_state={"implementation": ADDR(99)},
            last_scanned_block=100,
            needs_polling=True,
            is_active=True,
        )
        db_session.add(mc)
        db_session.commit()

        def mock_batch(url, calls):
            # Slot 0 errored (revert); slot 1 answered but returned junk
            # short data the decoder can't use.
            results: list[tuple[str | None, str]] = [(None, "error")] * len(calls)
            if len(calls) > 1:
                results[1] = ("0x08c379a0", "ok")
            return results

        with patch("services.monitoring.unified_watcher.rpc_batch_request_classified", side_effect=mock_batch):
            events = poll_for_state_changes(db_session, "http://fake-rpc")

        assert len(events) == 0
        db_session.expire_all()
        reloaded = db_session.get(MonitoredContract, mc.id)
        assert reloaded is not None
        # Plan is field-sorted: implementation (errored), owner (answered
        # but undecodable — published as valueless, never as healthy).
        assert reloaded.last_poll_status == {"implementation": "error", "owner": "no_value"}
        # The error never contaminated the value plane.
        assert reloaded.last_known_state == {"implementation": ADDR(99)}


# =========================================================================
# Owner controller_id matching
# =========================================================================


class TestOwnerControllerMatching:
    """Verify ownership_transferred only updates the correct controller rows."""

    def test_only_exact_owner_controllers_updated(self, db_session: SASession):
        """controller_id='token_owner_registry' should NOT be updated when
        an ownership_transferred event fires — only 'owner' should.
        """
        from services.monitoring.unified_watcher import _sync_relational_tables

        proto = Protocol(name="TestOwnerMatch1")
        db_session.add(proto)
        db_session.flush()

        contract = Contract(
            address=ADDR(1),
            chain="ethereum",
            protocol_id=proto.id,
        )
        db_session.add(contract)
        db_session.flush()

        cv_owner = ControllerValue(
            contract_id=contract.id,
            controller_id="owner",
            value=ADDR(10),
        )
        cv_fake = ControllerValue(
            contract_id=contract.id,
            controller_id="token_owner_registry",
            value=ADDR(20),
        )
        db_session.add_all([cv_owner, cv_fake])
        db_session.flush()

        mc = MonitoredContract(
            id=uuid.uuid4(),
            address=ADDR(1),
            chain="ethereum",
            contract_id=contract.id,
            contract_type="regular",
            monitoring_config={},
            last_known_state={},
            last_scanned_block=100,
            is_active=True,
        )
        db_session.add(mc)
        db_session.commit()

        parsed = {
            "event_type": "ownership_transferred",
            "block_number": 200,
            "tx_hash": "0xabc",
            "new_owner": ADDR(50),
            "old_owner": ADDR(10),
        }

        _sync_relational_tables(db_session, mc, parsed)
        db_session.commit()

        db_session.expire_all()
        cv_owner_reloaded = db_session.get(ControllerValue, cv_owner.id)
        cv_fake_reloaded = db_session.get(ControllerValue, cv_fake.id)

        assert cv_owner_reloaded is not None
        assert cv_fake_reloaded is not None
        assert cv_owner_reloaded.value == ADDR(50), "Real owner should be updated"
        assert cv_fake_reloaded.value == ADDR(20), (
            f"token_owner_registry was incorrectly updated to {cv_fake_reloaded.value} — ilike('%owner%') is too broad"
        )

    def test_poll_sync_only_updates_exact_owner(self, db_session: SASession):
        """Same check for _sync_relational_from_poll."""
        from services.monitoring.unified_watcher import _sync_relational_from_poll

        proto = Protocol(name="TestOwnerMatch2")
        db_session.add(proto)
        db_session.flush()

        contract = Contract(
            address=ADDR(3),
            chain="ethereum",
            protocol_id=proto.id,
        )
        db_session.add(contract)
        db_session.flush()

        cv_owner = ControllerValue(
            contract_id=contract.id,
            controller_id="owner",
            value=ADDR(10),
        )
        cv_previous = ControllerValue(
            contract_id=contract.id,
            controller_id="previous_owner_map",
            value=ADDR(20),
        )
        db_session.add_all([cv_owner, cv_previous])
        db_session.flush()

        mc = MonitoredContract(
            id=uuid.uuid4(),
            address=ADDR(3),
            chain="ethereum",
            contract_id=contract.id,
            contract_type="regular",
            monitoring_config={},
            last_known_state={},
            last_scanned_block=100,
            is_active=True,
        )
        db_session.add(mc)
        db_session.commit()

        _sync_relational_from_poll(db_session, mc, "owner", ADDR(50), ADDR(10))
        db_session.commit()

        db_session.expire_all()
        cv_owner_reloaded = db_session.get(ControllerValue, cv_owner.id)
        cv_previous_reloaded = db_session.get(ControllerValue, cv_previous.id)
        assert cv_owner_reloaded is not None
        assert cv_previous_reloaded is not None
        assert cv_owner_reloaded.value == ADDR(50)
        assert cv_previous_reloaded.value == ADDR(20), "previous_owner_map was incorrectly updated"


# =========================================================================
# Custom-named controller slots via effect_tags
# =========================================================================


class TestCustomNamedSlotEndToEnd:
    """End-to-end proof that the tag-driven dispatch handles a controller
    slot the canonical maps don't know about.

    A protocol with a custom slot named ``protocolAdmin`` that isn't in
    ``_WRITE_TARGET_TO_STATE`` / ``_WRITE_TARGET_TO_CONFIG_KEYS`` /
    ``_HANDROLLED_EVENT_TYPE_TO_TAGS`` should still flow through every
    downstream consumer when the static analyzer attaches
    ``effect_tags.writes=["protocolAdmin"]`` to its setter event.
    """

    def _setup_custom_slot_fixture(self, session: SASession):
        proto = Protocol(name="CustomSlotProtocol")
        session.add(proto)
        session.flush()

        contract = Contract(
            address=ADDR(1),
            chain="ethereum",
            protocol_id=proto.id,
        )
        session.add(contract)
        session.flush()

        # Pre-existing ControllerValue row under the static-analyzer
        # canonical id "state_variable:protocolAdmin" — the row the
        # tag-driven sync must find via the generalized lookup
        # (write_target, state_variable:write_target, external_contract:write_target).
        cv = ControllerValue(
            contract_id=contract.id,
            controller_id="state_variable:protocolAdmin",
            value=ADDR(10),
        )
        session.add(cv)
        session.flush()

        mc = MonitoredContract(
            id=uuid.uuid4(),
            address=ADDR(1),
            chain="ethereum",
            contract_id=contract.id,
            contract_type="regular",
            monitoring_config={"watch_ownership": True},
            last_known_state={"protocolAdmin": ADDR(10)},
            last_scanned_block=100,
            is_active=True,
        )
        session.add(mc)
        session.commit()
        return mc, cv

    def test_state_updates_for_custom_slot(self, db_session: SASession):
        """``_update_state_from_event`` reflects the custom-slot write
        via the generic name-match fallback — looks at parsed["newProtocolAdmin"]
        when the canonical extractor map has no entry for "protocolAdmin"."""
        from services.monitoring.unified_watcher import _update_state_from_event

        mc, _ = self._setup_custom_slot_fixture(db_session)

        parsed = {
            "event_type": "controller_changed:state_variable:protocolAdmin",
            "block_number": 200,
            "tx_hash": "0xabc",
            "newProtocolAdmin": ADDR(50),
            "effect_tags": {"writes": ["protocolAdmin"]},
        }

        _update_state_from_event(mc, parsed)
        db_session.commit()
        db_session.expire_all()
        reloaded = db_session.get(MonitoredContract, mc.id)
        assert reloaded is not None
        assert reloaded.last_known_state is not None
        assert reloaded.last_known_state.get("protocolAdmin") == ADDR(50)

    def test_controller_value_syncs_for_custom_slot(self, db_session: SASession):
        """``_sync_relational_tables`` matches the ControllerValue row
        under ``state_variable:protocolAdmin`` via the generalized
        prefix-form lookup."""
        from services.monitoring.unified_watcher import _sync_relational_tables

        mc, cv = self._setup_custom_slot_fixture(db_session)

        parsed = {
            "event_type": "controller_changed:state_variable:protocolAdmin",
            "block_number": 200,
            "tx_hash": "0xabc",
            "newProtocolAdmin": ADDR(50),
            "effect_tags": {"writes": ["protocolAdmin"]},
        }
        _sync_relational_tables(db_session, mc, parsed)
        db_session.commit()
        db_session.expire_all()

        cv_reloaded = db_session.get(ControllerValue, cv.id)
        assert cv_reloaded is not None
        assert cv_reloaded.value == ADDR(50), (
            "ControllerValue with controller_id=state_variable:protocolAdmin "
            "was not updated — the tag-driven sync's generalized prefix-form "
            "lookup is missing the state_variable: prefix"
        )

    def test_reanalysis_does_not_fire_for_unrelated_custom_slot(self):
        """A custom-named slot that isn't in ``_REANALYSIS_WRITE_TARGETS``
        (e.g. ``feeRecipient``) must NOT trigger reanalysis even though
        the event flows through every other dispatch path. Reanalysis
        is reserved for control-graph-invalidating writes."""
        from services.monitoring.reanalysis import should_trigger_reanalysis

        assert (
            should_trigger_reanalysis(
                "controller_changed:state_variable:feeRecipient",
                {"effect_tags": {"writes": ["feeRecipient"]}},
            )
            is False
        )

    def test_reanalysis_fires_for_control_relevant_custom_slot(self):
        """A custom-named slot that IS a control-relevant rename (e.g. a
        fork that calls its admin field ``protocolAdmin`` but writes
        ``admin``) triggers reanalysis via the tag intersection check."""
        from services.monitoring.reanalysis import should_trigger_reanalysis

        # The static analyzer tagged the emitter as writing "admin" even
        # though the surface name is "protocolAdmin" — that's the
        # generalization payoff.
        assert (
            should_trigger_reanalysis(
                "controller_changed:state_variable:protocolAdmin",
                {"effect_tags": {"writes": ["admin"]}},
            )
            is True
        )

    def test_should_watch_passes_custom_slot_with_default_config(self, db_session: SASession):
        """``_should_watch`` allows events whose write targets don't map
        to any specific config flag — there's no way for the user to
        opt out of an unrecognized slot without a config key, so default
        is allow."""
        from services.monitoring.unified_watcher import _should_watch

        mc, _ = self._setup_custom_slot_fixture(db_session)
        parsed = {
            "event_type": "controller_changed:state_variable:protocolAdmin",
            "effect_tags": {"writes": ["protocolAdmin"]},
        }
        assert _should_watch(mc, parsed) is True


# ---------------------------------------------------------------------------
# Timelock event decode (CallScheduled / CallExecuted)
# ---------------------------------------------------------------------------


class TestTimelockEventDecode:
    """Verify the parser pulls target/value/calldata/predecessor/delay out
    of the static + dynamic regions of CallScheduled/CallExecuted log data.

    The watcher used to keep only operation_id + index, dropping everything
    that would actually let the UI say 'queued: setX on AuctionManager
    (delay 3d)'. These tests pin the new decode shape so a future regression
    that re-narrows the parser fails loudly.
    """

    def test_call_scheduled_decodes_static_fields(self):
        from services.monitoring.event_topics import CALL_SCHEDULED_TOPIC0, parse_governance_log

        target_word = "0" * 24 + "0" * 38 + "01"
        value_word = "0" * 64
        bytes_offset = format(160, "x").zfill(64)  # 5 head words * 32B
        predecessor_word = "0" * 64
        delay_word = format(3600, "x").zfill(64)
        calldata = "12345678abcd"  # selector 0x12345678 + 2-byte tail
        cd_len = format(6, "x").zfill(64)
        cd_padded = calldata + "0" * (64 - len(calldata))
        data_hex = "0x" + target_word + value_word + bytes_offset + predecessor_word + delay_word + cd_len + cd_padded

        log = {
            "topics": [CALL_SCHEDULED_TOPIC0, "0x" + "ab" * 32, "0x" + format(0, "x").zfill(64)],
            "data": data_hex,
            "blockNumber": "0x100",
            "transactionHash": "0xfeed",
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["event_type"] == "timelock_scheduled"
        assert ev["operation_id"] == "0x" + "ab" * 32
        assert ev["index"] == 0
        assert ev["target"] == "0x" + "00" * 19 + "01"
        assert ev["value"] == 0
        assert ev["predecessor"] == "0x" + "00" * 32
        assert ev["delay"] == 3600
        assert ev["calldata_length"] == 6
        assert ev["selector"] == "0x12345678"

    def test_call_executed_decodes_static_fields(self):
        from services.monitoring.event_topics import CALL_EXECUTED_TOPIC0, parse_governance_log

        target_word = "0" * 24 + "0" * 38 + "02"
        value_word = format(1000000000000000000, "x").zfill(64)  # 1 ETH
        bytes_offset = format(96, "x").zfill(64)  # 3 head words
        cd_len = format(4, "x").zfill(64)
        selector_word = "deadbeef" + "0" * 56
        data_hex = "0x" + target_word + value_word + bytes_offset + cd_len + selector_word

        log = {
            "topics": [CALL_EXECUTED_TOPIC0, "0x" + "cd" * 32, "0x" + format(7, "x").zfill(64)],
            "data": data_hex,
            "blockNumber": "0x200",
            "transactionHash": "0xbabe",
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["event_type"] == "timelock_executed"
        assert ev["operation_id"] == "0x" + "cd" * 32
        assert ev["index"] == 7
        assert ev["target"] == "0x" + "00" * 19 + "02"
        assert ev["value"] == 10**18
        assert ev["calldata_length"] == 4
        assert ev["selector"] == "0xdeadbeef"

    def test_short_data_field_does_not_crash(self):
        """Defensive: a malformed log with a short data field shouldn't
        raise — the parser should set the indexed fields and skip the
        rest. Catches RPCs that occasionally truncate before the body."""
        from services.monitoring.event_topics import CALL_SCHEDULED_TOPIC0, parse_governance_log

        log = {
            "topics": [CALL_SCHEDULED_TOPIC0, "0x" + "ab" * 32, "0x" + format(0, "x").zfill(64)],
            "data": "0x" + "00" * 32,  # only 1 word — way too short
            "blockNumber": "0x1",
            "transactionHash": "0xa",
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["operation_id"] == "0x" + "ab" * 32
        assert ev["index"] == 0
        assert "target" not in ev
        assert "delay" not in ev


class TestBatchTimelockDedupe:
    """OZ TimelockController scheduleBatch / executeBatch emit one
    CallScheduled / CallExecuted log per call in the batch, all sharing
    tx_hash + block_number + event_type but with distinct logIndex.

    Earlier dedupe used a 4-tuple key (mc, tx, block, type) and would
    collapse those down to one MonitoredEvent row, hiding the rest of
    the batch from the UI. The fix splits dedupe into a DB-level
    4-tuple guard (no row dup against existing data) and an in-scan
    5-tuple guard that includes log_index so batch logs land as
    separate rows when scanned for the first time.
    """

    def test_batch_call_scheduled_logs_persist_separately(self, db_session: SASession):
        from services.monitoring.event_topics import CALL_SCHEDULED_TOPIC0
        from services.monitoring.unified_watcher import scan_for_events

        timelock_addr = ADDR(7)
        mc = MonitoredContract(
            id=uuid.uuid4(),
            address=timelock_addr,
            chain="ethereum",
            contract_type="timelock",
            monitoring_config={"watch_timelock": True},
            last_known_state={},
            last_scanned_block=100,
            needs_polling=False,
            is_active=True,
        )
        db_session.add(mc)
        db_session.commit()

        # Two CallScheduled logs from the same tx — distinct logIndex.
        # data layout: 5 head words (target/value/bytes_off/predecessor/delay)
        # + bytes_len + selector. Bytes_off is 5*32 = 160 (0xa0).
        head = (
            "0" * 24
            + "00" * 19
            + "01"  # target = 0x...01
            + "0" * 64  # value = 0
            + format(160, "x").zfill(64)  # bytes_offset
            + "0" * 64  # predecessor
            + format(3600, "x").zfill(64)  # delay
        )
        cd_section = format(4, "x").zfill(64) + "deadbeef" + "0" * 56
        log_data = "0x" + head + cd_section

        def mock_rpc(_url, method, _params, *, chain_id=None):
            if method == "eth_blockNumber":
                return hex(200)
            if method == "eth_getLogs":
                return [
                    {
                        "address": timelock_addr,
                        "topics": [
                            CALL_SCHEDULED_TOPIC0,
                            "0x" + "ab" * 32,
                            "0x" + format(0, "x").zfill(64),
                        ],
                        "data": log_data,
                        "blockNumber": "0x96",  # 150
                        "transactionHash": "0x" + "fe" * 32,
                        "blockHash": "0x" + "11" * 32,
                        "transactionIndex": "0x0",
                        "logIndex": "0x0",
                    },
                    {
                        "address": timelock_addr,
                        "topics": [
                            CALL_SCHEDULED_TOPIC0,
                            "0x" + "ab" * 32,
                            "0x" + format(1, "x").zfill(64),  # index=1 (second call in batch)
                        ],
                        "data": log_data,
                        "blockNumber": "0x96",
                        "transactionHash": "0x" + "fe" * 32,
                        "blockHash": "0x" + "11" * 32,
                        "transactionIndex": "0x0",
                        "logIndex": "0x1",
                    },
                ]
            return None

        with (
            patch("services.monitoring.unified_watcher.rpc_request", side_effect=mock_rpc),
            patch("services.resolution.repos.event_logs_rpc.rpc_request", side_effect=mock_rpc),
        ):
            new_events = scan_for_events(db_session, "http://fake-rpc")

        assert len(new_events) == 2, f"expected 2 batch-event rows, got {len(new_events)}"
        # Both rows should reference the same tx + block + type but be
        # distinct rows (different ids) so the UI can render each call.
        ids = {e.id for e in new_events}
        assert len(ids) == 2
        for e in new_events:
            assert e.event_type == "timelock_scheduled"
            assert e.tx_hash == "0x" + "fe" * 32
            assert e.block_number == 150

    def test_batch_call_executed_logs_persist_separately(self, db_session: SASession):
        """Same batch-dedupe story for executeBatch as for scheduleBatch.

        The dedupe path is event-type agnostic, but the CallExecuted code
        path is what the UI will actually render in 'recent activity', so
        a separate regression keeps both halves of the lifecycle pinned.
        """
        from services.monitoring.event_topics import CALL_EXECUTED_TOPIC0
        from services.monitoring.unified_watcher import scan_for_events

        timelock_addr = ADDR(8)
        mc = MonitoredContract(
            id=uuid.uuid4(),
            address=timelock_addr,
            chain="ethereum",
            contract_type="timelock",
            monitoring_config={"watch_timelock": True},
            last_known_state={},
            last_scanned_block=200,
            needs_polling=False,
            is_active=True,
        )
        db_session.add(mc)
        db_session.commit()

        # CallExecuted has 3 head words (target/value/bytes_off).
        head = (
            "0" * 24
            + "00" * 19
            + "02"  # target
            + "0" * 64  # value
            + format(96, "x").zfill(64)  # bytes_offset = 3*32
        )
        cd_section = format(4, "x").zfill(64) + "cafef00d" + "0" * 56
        log_data = "0x" + head + cd_section

        def mock_rpc(_url, method, _params, *, chain_id=None):
            if method == "eth_blockNumber":
                return hex(300)
            if method == "eth_getLogs":
                return [
                    {
                        "address": timelock_addr,
                        "topics": [
                            CALL_EXECUTED_TOPIC0,
                            "0x" + "cd" * 32,
                            "0x" + format(0, "x").zfill(64),
                        ],
                        "data": log_data,
                        "blockNumber": "0xfa",  # 250
                        "transactionHash": "0x" + "ba" * 32,
                        "blockHash": "0x" + "22" * 32,
                        "transactionIndex": "0x0",
                        "logIndex": "0x0",
                    },
                    {
                        "address": timelock_addr,
                        "topics": [
                            CALL_EXECUTED_TOPIC0,
                            "0x" + "cd" * 32,
                            "0x" + format(1, "x").zfill(64),
                        ],
                        "data": log_data,
                        "blockNumber": "0xfa",
                        "transactionHash": "0x" + "ba" * 32,
                        "blockHash": "0x" + "22" * 32,
                        "transactionIndex": "0x0",
                        "logIndex": "0x1",
                    },
                ]
            return None

        with (
            patch("services.monitoring.unified_watcher.rpc_request", side_effect=mock_rpc),
            patch("services.resolution.repos.event_logs_rpc.rpc_request", side_effect=mock_rpc),
        ):
            new_events = scan_for_events(db_session, "http://fake-rpc")

        assert len(new_events) == 2
        for e in new_events:
            assert e.event_type == "timelock_executed"
            assert e.tx_hash == "0x" + "ba" * 32
            assert e.block_number == 250


class TestSafeExecutionEvents:
    """GnosisSafe ExecutionSuccess / ExecutionFailure are emitted for
    EVERY executed Safe tx — they're the on-chain breadcrumb you'd render
    as 'recent activity' on a Safe principal card. Pin the topic→type
    mapping and the field decode so a future regression that reorders
    or drops these is caught.
    """

    def test_execution_success_decodes(self):
        from services.monitoring.event_topics import EXECUTION_SUCCESS_TOPIC0, parse_governance_log

        safe_tx_hash = "0x" + "ab" * 32
        payment = format(123456, "x").zfill(64)
        log = {
            "topics": [EXECUTION_SUCCESS_TOPIC0],
            "data": safe_tx_hash + payment[2:] if False else "0x" + "ab" * 32 + payment,
            "blockNumber": "0x100",
            "transactionHash": "0xfeed",
            "logIndex": "0x3",
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["event_type"] == "safe_tx_executed"
        assert ev["safe_tx_hash"] == safe_tx_hash
        assert ev["payment"] == 123456
        assert ev["log_index"] == 3

    def test_execution_failure_decodes(self):
        from services.monitoring.event_topics import EXECUTION_FAILURE_TOPIC0, parse_governance_log

        safe_tx_hash = "0x" + "cd" * 32
        payment = format(0, "x").zfill(64)
        log = {
            "topics": [EXECUTION_FAILURE_TOPIC0],
            "data": "0x" + "cd" * 32 + payment,
            "blockNumber": "0x100",
            "transactionHash": "0xbabe",
            "logIndex": "0x0",
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["event_type"] == "safe_tx_failed"
        assert ev["safe_tx_hash"] == safe_tx_hash
        assert ev["payment"] == 0

    def test_short_data_does_not_crash(self):
        """Defensive: short/malformed data field should not raise."""
        from services.monitoring.event_topics import EXECUTION_SUCCESS_TOPIC0, parse_governance_log

        log = {
            "topics": [EXECUTION_SUCCESS_TOPIC0],
            "data": "0x" + "ab" * 8,  # well under the 64+64 hex chars expected
            "blockNumber": "0x1",
            "transactionHash": "0xa",
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["event_type"] == "safe_tx_executed"
        assert "safe_tx_hash" not in ev
        assert "payment" not in ev

    def test_indexed_txhash_variant_decodes(self):
        """The 1.4.1 singleton indexes txHash: topics[1] carries the hash and the
        body is payment alone.

        Byte-for-byte the log at index 414 of mainnet tx
        ``0xf047c068b4d7311344adfb02fc56310d7200d12799a9894675b3b66ff5f2b431``,
        emitted by Safe ``0x607d0c7e3578802eb46d388cb86cfba8ff657306`` — one of
        the four executions that decoded to neither field before this arm
        existed (topic0 is identical to the non-indexed form, so nothing else
        distinguished them).
        """
        from services.monitoring.event_topics import EXECUTION_SUCCESS_TOPIC0, parse_governance_log

        log = {
            "address": "0x607d0c7e3578802eb46d388cb86cfba8ff657306",
            "topics": [
                EXECUTION_SUCCESS_TOPIC0,
                "0x557306e1acffe8fbc5eeed5d3c7f67aae3713431d50c9224fec4ec51efc2a7b2",
            ],
            "data": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "blockNumber": hex(25683190),
            "transactionHash": "0xf047c068b4d7311344adfb02fc56310d7200d12799a9894675b3b66ff5f2b431",
            "logIndex": hex(414),
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["event_type"] == "safe_tx_executed"
        assert ev["safe_tx_hash"] == "0x557306e1acffe8fbc5eeed5d3c7f67aae3713431d50c9224fec4ec51efc2a7b2"
        assert ev["payment"] == 0

    def test_indexed_failure_variant_decodes(self):
        from services.monitoring.event_topics import EXECUTION_FAILURE_TOPIC0, parse_governance_log

        log = {
            "topics": [EXECUTION_FAILURE_TOPIC0, "0x" + "cd" * 32],
            "data": "0x" + format(4200, "x").zfill(64),
            "blockNumber": "0x100",
            "transactionHash": "0xbabe",
            "logIndex": "0x0",
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["event_type"] == "safe_tx_failed"
        assert ev["safe_tx_hash"] == "0x" + "cd" * 32
        assert ev["payment"] == 4200

    def test_indexed_variant_with_two_word_body_publishes_no_payment(self):
        """A second topic proves txHash is indexed, so the body should be payment
        alone. A body that is not says the layout is not the one we can read —
        the hash still decodes from its own topic, and no payment is invented
        from a word we cannot place."""
        from services.monitoring.event_topics import EXECUTION_SUCCESS_TOPIC0, parse_governance_log

        log = {
            "topics": [EXECUTION_SUCCESS_TOPIC0, "0x" + "ab" * 32],
            "data": "0x" + "11" * 32 + "22" * 32,
            "blockNumber": "0x1",
            "transactionHash": "0xa",
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["safe_tx_hash"] == "0x" + "ab" * 32
        assert "payment" not in ev

    def test_indexed_variant_with_empty_body_publishes_no_payment(self):
        from services.monitoring.event_topics import EXECUTION_SUCCESS_TOPIC0, parse_governance_log

        log = {
            "topics": [EXECUTION_SUCCESS_TOPIC0, "0x" + "ab" * 32],
            "data": "0x",
            "blockNumber": "0x1",
            "transactionHash": "0xa",
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["safe_tx_hash"] == "0x" + "ab" * 32
        assert "payment" not in ev

    def test_indexed_variant_with_malformed_topic_publishes_no_hash(self):
        """The payment word is still witnessed; the hash is not, and a truncated
        topic is never left-padded into one."""
        from services.monitoring.event_topics import EXECUTION_SUCCESS_TOPIC0, parse_governance_log

        log = {
            "topics": [EXECUTION_SUCCESS_TOPIC0, "0xabcd"],
            "data": "0x" + format(7, "x").zfill(64),
            "blockNumber": "0x1",
            "transactionHash": "0xa",
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert "safe_tx_hash" not in ev
        assert ev["payment"] == 7

    def test_execution_from_module_success_decodes(self):
        """Module-triggered Safe executions: address indexed in topics[1],
        no SafeTx hash, no payment. Used when a pre-authorised module
        (e.g. recovery, batch executor) calls into the Safe directly.
        """
        from services.monitoring.event_topics import EXECUTION_FROM_MODULE_SUCCESS_TOPIC0, parse_governance_log

        module_addr = "0x" + "ee" * 20
        log = {
            "topics": [
                EXECUTION_FROM_MODULE_SUCCESS_TOPIC0,
                "0x" + "0" * 24 + "ee" * 20,  # padded module address in topic
            ],
            "data": "0x",
            "blockNumber": "0x10",
            "transactionHash": "0xfeed",
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["event_type"] == "safe_module_executed"
        assert ev["module"] == module_addr

    def test_execution_from_module_failure_decodes(self):
        from services.monitoring.event_topics import EXECUTION_FROM_MODULE_FAILURE_TOPIC0, parse_governance_log

        module_addr = "0x" + "ff" * 20
        log = {
            "topics": [
                EXECUTION_FROM_MODULE_FAILURE_TOPIC0,
                "0x" + "0" * 24 + "ff" * 20,
            ],
            "data": "0x",
            "blockNumber": "0x10",
            "transactionHash": "0xbeef",
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["event_type"] == "safe_module_failed"
        assert ev["module"] == module_addr
