"""Replay harness for the recorded 2026-08-01 monitoring scan window.

The fixture (``tests/fixtures/monitoring/replay_scan_window.json.gz``) is a
read-only snapshot of the audited dev-DB state: the enrolled configs of the
three contracts that emitted, every log the scanner's ``topics_union`` +
address filter would have fetched in the window, and the identity of all 446
``monitored_events`` rows that pass produced.

The harness feeds those logs back through ``_process_window`` so any change to
the taxonomy is measured as a differential against a recorded run rather than
against a hand-written expectation.
"""

from __future__ import annotations

import gzip
import json
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import Contract, MonitoredContract, MonitoredEvent, Protocol
from services.monitoring.unified_watcher import _Cohort, _process_window
from services.resolution.repos.event_logs_rpc import _decode_log

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "monitoring" / "replay_scan_window.json.gz"


def load_replay_fixture() -> dict[str, Any]:
    # Gzipped: the recording is a complete audited window (446 raw logs) that
    # only ever changes by wholesale regeneration, so line-diffability buys
    # nothing and the hex-heavy JSON compresses ~6x.
    with gzip.open(FIXTURE_PATH, "rt") as fh:
        return json.load(fh)


class ReplayEnv:
    """The seeded contracts + decoded logs for one replay."""

    def __init__(self, session: Session, fixture: dict[str, Any]) -> None:
        self.session = session
        self.fixture = fixture
        self.protocol_id: int = 0
        self.contracts: dict[str, MonitoredContract] = {}
        self.cohort: _Cohort | None = None
        self.logs: list = []

    def seed(self) -> "ReplayEnv":
        session = self.session
        protocol = Protocol(name="replay-etherfi", chains=["ethereum"])
        session.add(protocol)
        session.flush()
        self.protocol_id = protocol.id

        member_ids: list[uuid.UUID] = []
        addresses: list[str] = []
        for row in self.fixture["contracts"]:
            contract = Contract(
                protocol_id=protocol.id,
                address=row["address"],
                chain=row["chain"],
                contract_name=row["address"][:10],
            )
            session.add(contract)
            session.flush()
            mc = MonitoredContract(
                id=uuid.uuid4(),
                address=row["address"],
                chain=row["chain"],
                protocol_id=protocol.id,
                contract_id=contract.id,
                contract_type=row["contract_type"],
                monitoring_config=row["monitoring_config"],
                last_known_state=row["last_known_state"],
                last_scanned_block=self.fixture["window"]["from_block"] - 1,
                enrollment_block=row["enrollment_block"],
                needs_polling=bool(row["needs_polling"]),
                is_active=True,
            )
            session.add(mc)
            session.flush()
            self.contracts[row["address"]] = mc
            member_ids.append(mc.id)
            addresses.append(row["address"].lower())
        session.commit()

        self.cohort = _Cohort(
            chain=self.fixture["window"]["chain"],
            member_ids=member_ids,
            addresses=addresses,
            cursor=self.fixture["window"]["from_block"] - 1,
        )
        # Decode through the production fetcher path so ``raw`` is the same
        # dict shape ``_process_window``'s tracked-spec branch reads.
        self.logs = [decoded for log in self.fixture["logs"] if (decoded := _decode_log(log)) is not None]
        return self

    def run(self) -> list[MonitoredEvent]:
        assert self.cohort is not None
        window = self.fixture["window"]
        events = _process_window(
            self.session,
            self.cohort,
            self.logs,
            window["from_block"],
            window["to_block"],
        )
        self.session.commit()
        return events

    def persisted_identities(self) -> set[tuple[str, str, str, int]]:
        """``(address, event_type, tx_hash, log_index)`` for every persisted row.

        This is the differential unit: the same identity the partial unique
        index uses, plus the emitter so a row is attributable.
        """
        rows = self.session.execute(
            select(
                MonitoredContract.address,
                MonitoredEvent.event_type,
                MonitoredEvent.tx_hash,
                MonitoredEvent.log_index,
            ).join(MonitoredContract, MonitoredContract.id == MonitoredEvent.monitored_contract_id)
        ).all()
        return {(a.lower(), et, tx, li) for a, et, tx, li in rows}


def baseline_identities(fixture: dict[str, Any]) -> set[tuple[str, str, str, int]]:
    return {(a.lower(), et, tx, li) for a, et, tx, li, _hist in fixture["baseline_event_identities"]}


def build_replay(session: Session) -> ReplayEnv:
    return ReplayEnv(session, load_replay_fixture()).seed()
