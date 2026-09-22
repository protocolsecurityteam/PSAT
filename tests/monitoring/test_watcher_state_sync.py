"""Watcher state-sync unit tests: poll results, controller-row matching, and
custom-named controller slots.

Every test here drives the unified watcher's *state* plane — what a poll or an
event does to ``last_known_state``, ``last_poll_status`` and the relational
``ControllerValue`` rows — as opposed to the scan/window budgeting
(``test_unified_watcher_budget.py``) or the pure log decode
(``test_event_topics_tracked.py``).

Requires PostgreSQL (``TEST_DATABASE_URL``).
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

from sqlalchemy.orm import Session as SASession

from db.models import (
    Contract,
    ControllerValue,
    MonitoredContract,
    Protocol,
)
from tests.conftest import requires_postgres

pytestmark = requires_postgres


def ADDR(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


# =========================================================================
# Reverted eth_call in polling
# =========================================================================


class TestRevertedEthCallPolling:
    """Verify that reverted or garbage eth_call results don't produce events."""

    def test_revert_error_data_not_treated_as_address(self):
        """Revert ABI data should not be parsed as a valid address."""
        from services.clients.rpc import parse_address_result

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
        from services.clients.rpc import parse_address_result

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
            observation_plan=None,
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
