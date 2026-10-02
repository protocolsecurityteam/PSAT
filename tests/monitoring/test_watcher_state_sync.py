"""The watcher's state plane; scan budgeting and log decode have their own files."""

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


class TestRevertedEthCallPolling:
    def test_revert_error_data_not_treated_as_address(self):
        from services.clients.rpc import parse_address_result

        revert_data = (
            "0x08c379a0"
            "0000000000000000000000000000000000000000000000000000000000000020"
            "0000000000000000000000000000000000000000000000000000000000000004"
            "6e6f706500000000000000000000000000000000000000000000000000000000"
        )
        result = parse_address_result(revert_data)
        assert result is None, f"Revert data was parsed as address: {result}"

    def test_poll_skips_error_rpc_results(self, db_session: SASession):
        from services.monitoring.polling_plan import build_polling_plan
        from services.monitoring.unified_watcher import poll_for_state_changes

        polling_plan = build_polling_plan(
            contract_type="proxy",
            proxy_type="custom",
            tracking_plan=None,
            tracked_topics=None,
        )
        # So the batch's index-1 revert hits a real dispatch slot.
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
        # Answered but undecodable is published as valueless, never healthy.
        assert reloaded.last_poll_status == {"implementation": "error", "owner": "no_value"}
        assert reloaded.last_known_state == {"implementation": ADDR(99)}


class TestCustomNamedSlotEndToEnd:
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

    def test_controller_value_syncs_for_custom_slot(self, db_session: SASession):
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
