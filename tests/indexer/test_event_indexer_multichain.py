"""The indexer threads a per-job / per-cursor chain_id instead of stamping chain 1."""

from __future__ import annotations

import dataclasses
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, cast

import pytest
from sqlalchemy import func, select

from services.resolution.repos.event_logs_rpc import FetchedEventLog
from tests.conftest import DATABASE_URL as _DB_URL
from tests.conftest import _can_connect, requires_postgres
from tests.support.indexer_stubs import _DeterministicBlockHash
from tests.support.solmate_trees import _SOLMATE_CANCALL_TREES
from utils.chains import ChainInfo, chain_by_id
from workers.event_log_indexer import (
    _SOLMATE_ROLE_TOPICS,
    _build_indexer_fetchers,
    enroll_event_cursor,
    enroll_from_completed_jobs,
    scan_enrolled_events,
)

_BASE = 8453
_BASE_HYPERSYNC = "https://base.hypersync.xyz"
# Every covered chain goes through its own eRPC route; the native HyperSync host rejects JSON-RPC.
_ERPC_BASE = "https://erpc.example"
_MAINNET_ERPC = f"{_ERPC_BASE}/main/evm/1"
_BASE_ERPC = f"{_ERPC_BASE}/main/evm/{_BASE}"
_UNCOVERED = 42161  # arbitrum
_AUTHORITY = "0x" + "5c" * 20
_TOPIC = "0x" + "ab" * 32


def _url(fetcher: object) -> str:
    return cast(Any, fetcher).rpc_url


@pytest.fixture(autouse=True)
def _no_creation_witness(monkeypatch):
    """This module asserts the cursor's ``chain_id``, not the grade."""
    import workers.event_log_indexer as eli

    def _no_wire(*_a, **_kw):
        raise RuntimeError("no rpc")

    monkeypatch.setattr(eli, "rpc_request", _no_wire)


def _base_chaininfo(**overrides) -> ChainInfo:
    base = chain_by_id(_BASE)
    return dataclasses.replace(base, hypersync_url=_BASE_HYPERSYNC, **overrides)


def test_build_fetchers_mainnet_uses_erpc(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", _ERPC_BASE)
    fetchers, head_fetchers, block_hash_fetchers = _build_indexer_fetchers()
    assert set(fetchers) == {1, _BASE}
    assert _url(fetchers[1]) == _MAINNET_ERPC
    assert _url(head_fetchers[1]) == _MAINNET_ERPC
    assert _url(block_hash_fetchers[1]) == _MAINNET_ERPC


def test_build_fetchers_second_chain_uses_erpc(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", _ERPC_BASE)
    chains = (chain_by_id(1), _base_chaininfo())
    fetchers, head_fetchers, block_hash_fetchers = _build_indexer_fetchers(chains=chains)
    assert _url(fetchers[1]) == _MAINNET_ERPC
    assert _url(fetchers[_BASE]) == _BASE_ERPC
    assert _url(head_fetchers[_BASE]) == _BASE_ERPC
    assert _url(block_hash_fetchers[_BASE]) == _BASE_ERPC


def test_build_fetchers_skips_chains_without_hypersync_url(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", _ERPC_BASE)
    chains = (chain_by_id(1), chain_by_id(_UNCOVERED))
    fetchers, _, _ = _build_indexer_fetchers(chains=chains)
    assert _UNCOVERED not in fetchers
    assert set(fetchers) == {1}


@pytest.fixture()
def session():
    if not _can_connect():
        pytest.skip("PostgreSQL not available")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from db.models import Contract, IndexedEventCursor, IndexedEventLog, Job, Protocol

    engine = create_engine(_DB_URL)
    s = Session(engine, expire_on_commit=False)
    try:
        yield s
    finally:
        s.rollback()
        for model in (IndexedEventLog, IndexedEventCursor, Contract):
            s.query(model).delete()
        s.query(Job).delete()
        s.query(Protocol).delete()
        s.commit()
        s.close()
        engine.dispose()


@requires_postgres
def test_enroll_stamps_cursor_with_jobs_chain(session, monkeypatch):
    import workers.event_log_indexer as eli
    from db.models import Contract, ControllerValue, IndexedEventCursor, Job, JobStage, JobStatus, Protocol
    from db.queue import store_artifact

    authority = "0x" + "ab" * 20
    deploy = 12_000_000
    monkeypatch.setattr(
        eli,
        "get_contract_creation_block",
        lambda address, **_kw: deploy if address.lower() == authority else None,
    )

    protected = "0x" + "11" * 20
    job = Job(
        address=protected,
        chain_id=_BASE,
        request={"address": protected, "name": "T", "chain": "base"},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(job)
    session.flush()
    store_artifact(session, job.id, "predicate_trees", data=_SOLMATE_CANCALL_TREES)

    proto = Protocol(name=f"base_enroll_{uuid.uuid4().hex[:8]}", chains=["base"])
    session.add(proto)
    session.flush()
    contract = Contract(address=protected, chain="base", protocol_id=proto.id, job_id=job.id)
    session.add(contract)
    session.flush()
    session.add(ControllerValue(contract_id=contract.id, controller_id="state_variable:authority", value=authority))
    session.commit()

    inserted = enroll_from_completed_jobs(session)
    assert inserted >= len(_SOLMATE_ROLE_TOPICS)

    rows = session.execute(
        select(IndexedEventCursor.chain_id, IndexedEventCursor.last_indexed_block).where(
            func.lower(IndexedEventCursor.event_address) == authority
        )
    ).all()
    assert rows, "no cursor enrolled for the Base authority"
    assert {r[0] for r in rows} == {_BASE}
    assert all(r[1] == deploy - 1 for r in rows)


class _EmptyFetcher:
    def __init__(self) -> None:
        self.from_blocks: list[int] = []

    def fetch_logs(self, *, event_address, topics, from_block, to_block) -> list[FetchedEventLog]:
        self.from_blocks.append(from_block)
        return []


class _FixedHead:
    def __init__(self, head: int) -> None:
        self._head = head

    def head_block(self) -> int:
        return self._head


@requires_postgres
def test_scan_uses_registry_confirmation_depth_per_chain(session, monkeypatch):
    import workers.event_log_indexer as eli

    head = 30_000_000
    custom_depth = 50
    # The scan must use this chain's depth, not the fleet-wide 12.
    monkeypatch.setattr(
        eli,
        "chain_by_id",
        lambda cid: _base_chaininfo(confirmation_depth=custom_depth) if cid == _BASE else chain_by_id(cid),
    )

    enroll_event_cursor(session, chain_id=_BASE, event_address=_AUTHORITY, topic0=_TOPIC, start_block=head - 1_000)
    session.commit()

    fetcher = _EmptyFetcher()
    scan_enrolled_events(
        session,
        fetchers={_BASE: fetcher},
        head_fetchers={_BASE: _FixedHead(head)},
        block_hash_fetchers={_BASE: _DeterministicBlockHash()},
        max_windows_per_cursor=500,
    )

    row = session.execute(
        select(eli.IndexedEventCursor.last_indexed_block, eli.IndexedEventCursor.backfill_complete).where(
            func.lower(eli.IndexedEventCursor.event_address) == _AUTHORITY
        )
    ).first()
    assert row is not None
    assert row[0] == head - custom_depth
    assert row[1] is True


@requires_postgres
def test_scan_logs_once_when_chain_has_no_fetcher(session, caplog):
    # A cursor enrolled on a chain with no fetcher (indexer disabled for it) is
    # skipped — but loudly, once, so a stalled chain is visible.
    enroll_event_cursor(session, chain_id=_BASE, event_address=_AUTHORITY, topic0=_TOPIC, start_block=100)
    enroll_event_cursor(
        session, chain_id=_BASE, event_address="0x" + "7d" * 20, topic0="0x" + "cc" * 32, start_block=100
    )
    session.commit()

    with caplog.at_level(logging.WARNING, logger="workers.event_log_indexer"):
        summary = scan_enrolled_events(
            session,
            fetchers={},  # no fetcher for chain 8453
            head_fetchers={},
            block_hash_fetchers={},
        )

    assert summary.windows_scanned == 0
    skip_records = [
        r for r in caplog.records if "no fetcher for chain" in r.getMessage() and getattr(r, "chain_id", None) == _BASE
    ]
    assert len(skip_records) == 1


@requires_postgres
def test_scan_failure_logs_bounded_exc_msg(session, monkeypatch, caplog):
    # A bounded exc_msg keeps the error attributable without traceback storms.
    import services.resolution.repos.event_logs_rpc as rpc_repo

    monkeypatch.setenv("ERPC_BASE_URL", _ERPC_BASE)
    fetchers, head_fetchers, block_hash_fetchers = _build_indexer_fetchers(chains=(_base_chaininfo(),))

    def _boom(*_args, **_kwargs):
        raise RuntimeError("upstream rejected the query: malformed request")

    monkeypatch.setattr(rpc_repo, "rpc_request", _boom)

    enroll_event_cursor(session, chain_id=_BASE, event_address=_AUTHORITY, topic0=_TOPIC, start_block=100)
    session.commit()

    with caplog.at_level(logging.WARNING, logger="workers.event_log_indexer"):
        summary = scan_enrolled_events(
            session,
            fetchers=fetchers,
            head_fetchers=head_fetchers,
            block_hash_fetchers=block_hash_fetchers,
        )

    assert summary.failed_groups >= 1
    failed = [r for r in caplog.records if "group scan failed" in r.getMessage()]
    assert failed
    assert any(
        isinstance(getattr(r, "exc_msg", None), str) and "malformed" in r.exc_msg and len(r.exc_msg) <= 200
        for r in failed
    )
