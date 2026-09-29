"""Preserve emitter evidence while avoiding redundant event-store reads."""

from dataclasses import replace

import pytest
from sqlalchemy import event, func, select, tuple_

from db.models import IndexedEventLog, MonitoredContract, Protocol
from services.scoring.distill.universe import _literal_addresses, load_protocol_universe
from tests.conftest import requires_postgres
from utils.chains import UnknownChainError, chain_by_name

pytestmark = requires_postgres

ADDRESS = "0x" + "ab" * 20
CHECKSUM_CASE = "0x" + "aB" * 20
UPPER_PREFIX = "0X" + "aB" * 20
OTHER = "0x" + "cd" * 20
COUNTERPARTY = "0x" + "ef" * 20


def _log(session, address, chain_id=1):
    session.add(
        IndexedEventLog(
            chain_id=chain_id,
            event_address=address,
            topic0="0x" + "00" * 32,
            tx_hash=b"\x01" * 32,
            log_index=0,
            block_number=1,
            block_hash=b"\x02" * 32,
            transaction_index=0,
            topics=[COUNTERPARTY],
            data_words=[COUNTERPARTY],
        )
    )


def _legacy_emitters(session, enrolled):
    """Evaluate the previous SQL path against the same PostgreSQL fixtures."""
    addresses = set().union(*(_literal_addresses(address) for address, _ in enrolled))
    pairs = []
    for address, chain in enrolled:
        try:
            pairs.append((int(chain_by_name(chain).chain_id), address.lower()))
        except (UnknownChainError, ValueError, TypeError):
            continue
    if pairs:
        for address in session.scalars(
            select(IndexedEventLog.event_address)
            .where(tuple_(IndexedEventLog.chain_id, func.lower(IndexedEventLog.event_address)).in_(pairs))
            .distinct()
        ):
            addresses |= _literal_addresses(address)
    return frozenset(addresses)


@pytest.fixture
def protocol_and_empty_universe(db_session):
    protocol = Protocol(name="universe scan regression")
    db_session.add(protocol)
    db_session.flush()
    empty = load_protocol_universe(db_session, protocol.id)
    assert empty is not None
    assert empty.addresses == frozenset()
    assert empty.sources["monitored_event_emitters"] == 0
    return protocol, empty


def _load_with_log_queries(session, protocol_id):
    queries = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        if "indexed_event_logs" in statement:
            queries.append((statement, parameters))

    connection = session.connection()
    event.listen(connection, "before_cursor_execute", capture)
    try:
        universe = load_protocol_universe(session, protocol_id)
    finally:
        event.remove(connection, "before_cursor_execute", capture)
    return universe, queries


@pytest.mark.parametrize(
    "address,chain,log_address,log_chain,expected,lookup",
    [
        (ADDRESS, "ethereum", None, 1, {ADDRESS}, False),
        (CHECKSUM_CASE, "ethereum", ADDRESS, 1, {ADDRESS}, False),
        (ADDRESS, "base", CHECKSUM_CASE, 8453, {ADDRESS}, False),
        (ADDRESS, "unknown-chain", ADDRESS, 1, {ADDRESS}, False),
        (UPPER_PREFIX, "ethereum", ADDRESS, 1, {ADDRESS}, True),
        (UPPER_PREFIX, "ethereum", CHECKSUM_CASE, 1, {ADDRESS}, True),
        (UPPER_PREFIX, "ethereum", None, 1, set(), True),
        (UPPER_PREFIX, "ethereum", UPPER_PREFIX, 1, set(), True),
        (UPPER_PREFIX, "ethereum", ADDRESS, 8453, set(), True),
        (UPPER_PREFIX, "unknown-chain", ADDRESS, 1, set(), False),
        ("invalid", "ethereum", "invalid", 1, set(), True),
        ("", "ethereum", None, 1, set(), True),
    ],
)
@pytest.mark.parametrize("active", [True, False])
def test_emitter_membership_matches_legacy_without_standard_address_scans(
    db_session, protocol_and_empty_universe, address, chain, log_address, log_chain, expected, lookup, active
):
    protocol, empty = protocol_and_empty_universe
    db_session.add(MonitoredContract(protocol_id=protocol.id, address=address, chain=chain, is_active=active))
    if log_address is not None:
        _log(db_session, log_address, log_chain)
    _log(db_session, OTHER)  # Unenrolled emitters and topic counterparties stay excluded.
    db_session.flush()

    legacy = _legacy_emitters(db_session, [(address, chain)])
    assert legacy == frozenset(expected)
    universe, queries = _load_with_log_queries(db_session, protocol.id)
    assert universe == replace(
        empty, addresses=legacy, sources={**empty.sources, "monitored_event_emitters": len(legacy)}
    )
    assert len(queries) == int(lookup)


def test_mixed_enrollment_only_looks_up_exceptional_pairs(db_session, protocol_and_empty_universe):
    protocol, empty = protocol_and_empty_universe
    exceptional = "0X" + "cd" * 20
    enrolled = [(ADDRESS, "ethereum"), (CHECKSUM_CASE, "base"), (exceptional, "base")]
    for address, chain in enrolled:
        db_session.add(MonitoredContract(protocol_id=protocol.id, address=address, chain=chain))
    other_protocol = Protocol(name="unrelated protocol")
    db_session.add(other_protocol)
    db_session.flush()
    db_session.add(MonitoredContract(protocol_id=other_protocol.id, address=COUNTERPARTY, chain="ethereum"))
    _log(db_session, ADDRESS)
    _log(db_session, CHECKSUM_CASE, 8453)
    _log(db_session, OTHER, 8453)
    _log(db_session, COUNTERPARTY)
    db_session.flush()

    legacy = _legacy_emitters(db_session, enrolled)
    assert legacy == frozenset({ADDRESS, OTHER})
    universe, queries = _load_with_log_queries(db_session, protocol.id)
    assert universe == replace(empty, addresses=legacy, sources={**empty.sources, "monitored_event_emitters": 2})
    assert len(queries) == 1
    # Inspect executed bind values: standard rows must not sneak into fallback.
    assert set(queries[0][1].values()) == {8453, OTHER}


def test_no_enrollment_never_reads_event_store(db_session, protocol_and_empty_universe):
    protocol, empty = protocol_and_empty_universe
    _log(db_session, OTHER)
    db_session.flush()
    universe, queries = _load_with_log_queries(db_session, protocol.id)
    assert universe == empty
    assert queries == []
