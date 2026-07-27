"""``UpgradeEvent`` write-path integrity (W0-9).

Three writers fill ``upgrade_events``: the upgrade-history artifact
projection, the log scanner, and the storage-slot poller. Two properties are
pinned here, both of which were false before this file existed:

1. **No writer may invent a block number.** The poller reads a slot, so it has
   no block; it used to write ``block_number=0``. Every consumer orders by
   ``block_number ASC NULLS LAST``
   (``services/audits/coverage.py``, ``services/aggregations/
   contract_audit_timeline.py``, ``services/discovery/upgrade_history.py``),
   and ``0 < every real block``, so the poll row sorted *ahead of the genuine
   genesis deployment* and every impl-era window shifted by one.
2. **Every writer identifies itself.** ``old_impl`` is NULL both when a writer
   does not record predecessors and when there was none; ``timestamp`` is a
   block time for two writers and a detection time for the third. ``source``
   is the only thing that tells those apart.

Each ordering test carries its own **defect control**: the same fixture with
``block_number=0`` re-inserted, asserted to still corrupt the ordering. If a
future change makes 0 harmless the control fails and the test says so, rather
than passing vacuously.

Fixture addresses and blocks are real mainnet data for the proxy this item's
positive control names — ``0x8b71140a…`` (contract_id 518 locally, 18 real
upgrade events, actively polled on the EIP-1967 slot).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import select

from db.models import (
    UPGRADE_SOURCE_BACKFILL,
    UPGRADE_SOURCE_EVENT_SCAN,
    UPGRADE_SOURCE_POLL,
    Contract,
    MonitoredContract,
    Protocol,
    UpgradeEvent,
)
from services.monitoring.unified_watcher import _sync_relational_tables, poll_for_state_changes

# Real mainnet values (verified by eth_getStorageAt on the EIP-1967 slot at
# blocks 18000000 / 24000000 / 25619159 / head-10).
PROXY = "0x8b71140ad2e5d1e7018d2a7f8a288bd3cd38916f"
IMPL_GENESIS = "0x0c5631727ecf13f3e726bc3301e364af51b69295"  # active at block 18000000
IMPL_MIDDLE = "0x0f366df7af5003fc7c6524665ca58bdeaddc3745"  # active at block 24000000
IMPL_CURRENT = "0xcf5928ea7d7f164ec868ceda7a69e08a102b5e05"  # active at 25619159 and head
IMPL_NEXT = "0x1cb489ef513e1cc35c4657c91853a2e6ff1957de"  # a later, distinct impl

BLOCK_GENESIS = 17174453
BLOCK_MIDDLE = 23000000
BLOCK_CURRENT = 25533308

# The exact ordering all three consumers use.
CANONICAL_ORDER = (UpgradeEvent.block_number.asc().nullslast(), UpgradeEvent.id.asc())


def _word(addr: str) -> str:
    return "0x" + "0" * 24 + addr[2:]


@pytest.fixture()
def proxy_with_history(db_session):
    """A proxy Contract with two genuine, block-carrying upgrade events."""
    protocol = Protocol(name=f"w0-9-{uuid.uuid4().hex[:10]}")
    db_session.add(protocol)
    db_session.commit()

    contract = Contract(
        protocol_id=protocol.id,
        address=PROXY,
        chain="ethereum",
        contract_name="W09Proxy",
        is_proxy=True,
        implementation=IMPL_CURRENT,
    )
    db_session.add(contract)
    db_session.commit()

    for impl, blk, ts in (
        (IMPL_GENESIS, BLOCK_GENESIS, datetime(2023, 5, 20, tzinfo=timezone.utc)),
        (IMPL_MIDDLE, BLOCK_MIDDLE, datetime(2025, 3, 1, tzinfo=timezone.utc)),
        (IMPL_CURRENT, BLOCK_CURRENT, datetime(2026, 6, 1, tzinfo=timezone.utc)),
    ):
        db_session.add(
            UpgradeEvent(
                contract_id=contract.id,
                proxy_address=PROXY,
                old_impl=None,
                new_impl=impl,
                block_number=blk,
                timestamp=ts,
                tx_hash="0x" + "a" * 64,
                source=UPGRADE_SOURCE_BACKFILL,
            )
        )
    db_session.commit()

    try:
        yield contract
    finally:
        db_session.rollback()
        db_session.query(UpgradeEvent).filter_by(contract_id=contract.id).delete()
        db_session.query(MonitoredContract).filter_by(contract_id=contract.id).delete()
        db_session.query(Contract).filter_by(id=contract.id).delete()
        db_session.query(Protocol).filter_by(id=protocol.id).delete()
        db_session.commit()


def _seed_monitored(session, contract, *, current_impl: str) -> MonitoredContract:
    mc = MonitoredContract(
        id=uuid.uuid4(),
        address=PROXY,
        chain="ethereum",
        contract_type="proxy",
        contract_id=contract.id,
        protocol_id=contract.protocol_id,
        monitoring_config={
            "polling_plan": [
                {
                    "field": "implementation",
                    "kind": "storage_slot",
                    "slot": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
                    "type_kind": "address",
                }
            ]
        },
        last_known_state={"implementation": current_impl},
        last_scanned_block=0,
        needs_polling=True,
        is_active=True,
        last_polled_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    session.add(mc)
    session.commit()
    return mc


def _run_poll(session, observed_impl: str) -> None:
    """Drive the real ``poll_for_state_changes`` with only the wire stubbed."""

    def _mock(_url, calls):
        return [_word(observed_impl) for _ in calls]

    with patch("services.monitoring.unified_watcher.rpc_batch_request", side_effect=_mock):
        poll_for_state_changes(session, "http://rpc")


def _ordered(session, contract_id: int) -> list[UpgradeEvent]:
    return list(
        session.execute(select(UpgradeEvent).where(UpgradeEvent.contract_id == contract_id).order_by(*CANONICAL_ORDER))
        .scalars()
        .all()
    )


# --- 1. the poller never invents a block --------------------------------


def test_poll_detected_upgrade_writes_no_block_and_no_tx(db_session, proxy_with_history, monkeypatch):
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "5")
    _seed_monitored(db_session, proxy_with_history, current_impl=IMPL_CURRENT)

    _run_poll(db_session, IMPL_NEXT)
    db_session.expire_all()

    rows = _ordered(db_session, proxy_with_history.id)
    poll_rows = [r for r in rows if r.source == UPGRADE_SOURCE_POLL]
    assert len(poll_rows) == 1, "the poll path must write exactly one UpgradeEvent"
    row = poll_rows[0]

    assert row.new_impl == IMPL_NEXT
    assert row.old_impl == IMPL_CURRENT, "the poller knows the predecessor and must record it"
    # The whole item: not 0, and not any other fabricated block.
    assert row.block_number is None
    assert row.block_number != 0
    assert row.tx_hash is None
    # Absent here is the previously-fixed root cause of ImplWindow.from_ts=None.
    assert row.timestamp is not None
    assert row.timestamp >= datetime.now(timezone.utc) - timedelta(hours=1)


def test_poll_detected_upgrade_sorts_after_every_real_event(db_session, proxy_with_history, monkeypatch):
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "5")
    _seed_monitored(db_session, proxy_with_history, current_impl=IMPL_CURRENT)

    _run_poll(db_session, IMPL_NEXT)
    db_session.expire_all()

    rows = _ordered(db_session, proxy_with_history.id)
    assert [r.new_impl for r in rows] == [IMPL_GENESIS, IMPL_MIDDLE, IMPL_CURRENT, IMPL_NEXT]
    assert rows[0].block_number == BLOCK_GENESIS, "the genuine genesis deployment must stay first"

    # --- defect control: the same fixture with the old sentinel ---------
    # Proves this assertion can still see the defect it was written for.
    db_session.add(
        UpgradeEvent(
            contract_id=proxy_with_history.id,
            proxy_address=PROXY,
            new_impl="0x" + "d" * 40,
            block_number=0,
            tx_hash="",
        )
    )
    db_session.commit()
    corrupted = _ordered(db_session, proxy_with_history.id)
    assert corrupted[0].block_number == 0, "control: block_number=0 still sorts ahead of genesis"
    assert corrupted[0].new_impl != IMPL_GENESIS


# --- 2. every writer identifies itself ----------------------------------


def test_poll_and_event_scan_writers_stamp_distinct_sources(db_session, proxy_with_history, monkeypatch):
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "5")
    mc = _seed_monitored(db_session, proxy_with_history, current_impl=IMPL_CURRENT)

    _run_poll(db_session, IMPL_NEXT)

    _sync_relational_tables(
        db_session,
        mc,
        {
            "event_type": "upgraded",
            "implementation": IMPL_CURRENT,
            "block_number": BLOCK_CURRENT + 1000,
            "tx_hash": "0x" + "b" * 64,
        },
    )
    db_session.commit()
    db_session.expire_all()

    by_source: dict[str | None, list[UpgradeEvent]] = {}
    for row in _ordered(db_session, proxy_with_history.id):
        by_source.setdefault(row.source, []).append(row)

    assert set(by_source) == {
        UPGRADE_SOURCE_BACKFILL,
        UPGRADE_SOURCE_POLL,
        UPGRADE_SOURCE_EVENT_SCAN,
    }, "all three writers must be distinguishable"
    # The log-derived row carries a real block; only the poll row does not.
    assert by_source[UPGRADE_SOURCE_EVENT_SCAN][0].block_number == BLOCK_CURRENT + 1000
    assert by_source[UPGRADE_SOURCE_POLL][0].block_number is None
    # old_impl NULL now means "this writer does not record it" — readable.
    assert all(r.old_impl is None for r in by_source[UPGRADE_SOURCE_BACKFILL])
    assert by_source[UPGRADE_SOURCE_POLL][0].old_impl is not None


def test_artifact_projection_stamps_backfill_source(db_session, proxy_with_history):
    from services.discovery.upgrade_history import project_to_events

    db_session.query(UpgradeEvent).filter_by(contract_id=proxy_with_history.id).delete()
    db_session.commit()

    stats = project_to_events(
        db_session,
        subject_contract_id=proxy_with_history.id,
        subject_chain="ethereum",
        artifact_data={
            "proxies": {
                PROXY: {
                    "proxy_address": PROXY,
                    "events": [
                        {
                            "event_type": "upgraded",
                            "implementation": IMPL_GENESIS,
                            "block_number": BLOCK_GENESIS,
                            "timestamp": 1684540000,
                            "tx_hash": "0x" + "c" * 64,
                        }
                    ],
                }
            }
        },
    )
    db_session.commit()

    assert stats["events_written"] == 1
    rows = _ordered(db_session, proxy_with_history.id)
    assert [r.source for r in rows] == [UPGRADE_SOURCE_BACKFILL]
    assert rows[0].block_number == BLOCK_GENESIS


# --- 3. the consumer that re-collapsed the NULL --------------------------


def test_impl_windows_keep_genesis_first_when_a_row_has_no_block(db_session, proxy_with_history):
    """``_compute_impl_windows_batch`` used to fold NULL→0 and sort on it,
    which put a block-less event back in front of genesis after the SQL
    ordering had correctly sunk it."""
    from services.audits.coverage import _compute_impl_windows_batch

    db_session.add(
        UpgradeEvent(
            contract_id=proxy_with_history.id,
            proxy_address=PROXY,
            old_impl=IMPL_CURRENT,
            new_impl=IMPL_NEXT,
            block_number=None,
            timestamp=datetime(2026, 7, 1, tzinfo=timezone.utc),
            source=UPGRADE_SOURCE_POLL,
        )
    )
    db_session.commit()

    impls = []
    for addr in (IMPL_GENESIS, IMPL_MIDDLE, IMPL_CURRENT, IMPL_NEXT):
        c = Contract(protocol_id=proxy_with_history.protocol_id, address=addr, chain="ethereum", contract_name="Impl")
        db_session.add(c)
        impls.append(c)
    db_session.commit()

    try:
        windows = _compute_impl_windows_batch(db_session, impls)

        genesis = windows[impls[0].id][0]
        assert genesis.from_block == BLOCK_GENESIS
        assert genesis.to_block == BLOCK_MIDDLE
        assert genesis.successor == "known"

        # The block-less impl's own window: start unknown, and honestly so.
        pollw = windows[impls[3].id][0]
        assert pollw.from_block is None
        assert pollw.successor == "none"

        # The impl it replaced is closed, not open — to_block is None only
        # because the successor's block is unknown.
        prev = windows[impls[2].id][0]
        assert prev.to_block is None
        assert prev.successor == "block_unknown"
    finally:
        db_session.rollback()
        db_session.query(Contract).filter(Contract.id.in_([c.id for c in impls])).delete(synchronize_session=False)
        db_session.commit()


def test_undated_audit_does_not_attach_to_a_superseded_impl():
    """The open-window pick keyed off ``to_block is None``, which a block-less
    successor also produces — an undated audit would then be filed against an
    impl that had already been replaced."""
    from services.audits.coverage import ImplWindow, _confidence_for_impl_era

    superseded = ImplWindow(
        proxy_contract_id=1,
        proxy_address=PROXY,
        from_block=BLOCK_CURRENT,
        to_block=None,  # unknown, because the poll row that closed it has no block
        from_ts=datetime(2026, 6, 1, tzinfo=timezone.utc),
        to_ts=datetime(2026, 7, 1, tzinfo=timezone.utc),
        successor="block_unknown",
    )
    current = ImplWindow(
        proxy_contract_id=1,
        proxy_address=PROXY,
        from_block=None,
        to_block=None,
        from_ts=datetime(2026, 7, 1, tzinfo=timezone.utc),
        to_ts=None,
        successor="none",
    )

    confidence, window = _confidence_for_impl_era(None, [superseded, current])
    assert confidence == "low"
    assert window is current

    # Positive case: a dated audit inside the superseded window still lands
    # there, at high confidence — the hedge above did not cost the real answer.
    dated, w = _confidence_for_impl_era(datetime(2026, 6, 15, tzinfo=timezone.utc), [superseded, current])
    assert dated == "high"
    assert w is superseded


def test_half_known_block_window_is_not_published_as_open_ended():
    """``site/src/auditMatching.js`` reads a NULL ``covered_to_block`` beside a
    non-NULL ``covered_from_block`` as +infinity. A window whose upper bound is
    unknown must therefore publish neither bound."""
    from services.audits.coverage import ImplWindow, _publishable_block_bounds

    closed = ImplWindow(
        proxy_contract_id=1,
        proxy_address=PROXY,
        from_block=BLOCK_GENESIS,
        to_block=BLOCK_MIDDLE,
        from_ts=None,
        to_ts=None,
        successor="known",
    )
    assert _publishable_block_bounds(closed) == (BLOCK_GENESIS, BLOCK_MIDDLE)

    still_current = ImplWindow(
        proxy_contract_id=1,
        proxy_address=PROXY,
        from_block=BLOCK_CURRENT,
        to_block=None,
        from_ts=None,
        to_ts=None,
        successor="none",
    )
    assert _publishable_block_bounds(still_current) == (BLOCK_CURRENT, None)

    half_known = ImplWindow(
        proxy_contract_id=1,
        proxy_address=PROXY,
        from_block=BLOCK_CURRENT,
        to_block=None,
        from_ts=None,
        to_ts=None,
        successor="block_unknown",
    )
    assert _publishable_block_bounds(half_known) == (None, None)
