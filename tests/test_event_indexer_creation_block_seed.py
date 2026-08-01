"""Regression: event-log cursors are seeded from the event address's *creation
block*, not block 0 — the slowness half of the block-0 cursor bug.

A freshly-enrolled RolesAuthority cursor used to start at block 0 and rescan the
~20M empty pre-deployment blocks (hundreds of empty ``eth_getLogs`` per topic)
before reaching its first real event. These tests pin that:

  * the backfill's first window starts AT the seed and never scans below it, and
    a cold cursor that reaches head flips ``backfill_complete``;
  * ``enroll_from_completed_jobs`` seeds a Solmate authority's role cursors at
    ``creation_block - 1`` (resolved via Etherscan ``getcontractcreation``);
  * the companion pins the old behavior — seeding at 0 fetches from block 1.
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import func, select  # noqa: E402

from services.resolution.repos.event_logs_rpc import FetchedEventLog  # noqa: E402
from workers.event_log_indexer import (  # noqa: E402
    _SOLMATE_ROLE_TOPICS,
    enroll_event_cursor,
    enroll_from_completed_jobs,
    scan_enrolled_events,
)

_DB_URL: str = os.environ.get("TEST_DATABASE_URL", os.environ.get("DATABASE_URL", "")) or ""


@pytest.fixture(autouse=True)
def _no_creation_witness(monkeypatch):
    """Enrollment grades its seed with three pinned chain reads before writing
    the cursor. Nothing in this module asserts that grade — the subject is the
    seed itself — so the wire is stubbed to the unreachable-RPC failure, whose
    documented outcome is ``(None, not_determined)``."""
    import workers.event_log_indexer as eli

    def _no_wire(*_a, **_kw):
        raise RuntimeError("no rpc")

    monkeypatch.setattr(eli, "rpc_request", _no_wire)


def _can_connect() -> bool:
    if not _DB_URL:
        return False
    try:
        from sqlalchemy import create_engine, text

        engine = create_engine(_DB_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


requires_postgres = pytest.mark.skipif(not _can_connect(), reason="PostgreSQL not available")

_DEPLOY = 19_000_000
_HEAD = 19_300_000
_CONFIRMATIONS = 12
_TARGET = _HEAD - _CONFIRMATIONS
_MAX_SPAN = 100_000
_AUTHORITY = "0x" + "5c" * 20
_TOPIC = "0x" + "ab" * 32


class _SeedAwareFetcher:
    """Records every ``from_block`` and refuses to scan below the deploy block —
    the empty pre-deployment range the creation-block seed must skip. Emits one
    synthetic event at the deploy block so the backfill has something to index."""

    def __init__(self, deploy: int) -> None:
        self.deploy = deploy
        self.from_blocks: list[int] = []

    def fetch_logs(self, *, event_address, topics, from_block, to_block) -> list[FetchedEventLog]:
        self.from_blocks.append(from_block)
        if from_block < self.deploy:
            raise AssertionError(f"indexer scanned pre-deployment block {from_block} < deploy {self.deploy}")
        out: list[FetchedEventLog] = []
        if from_block <= self.deploy <= to_block:
            out.append(
                FetchedEventLog(
                    tx_hash=b"\x01" * 32,
                    log_index=0,
                    block_number=self.deploy,
                    block_hash=b"\x02" * 32,
                    transaction_index=0,
                    topics=[topics[0], "0x" + "00" * 31 + "01"],
                    data_words=["0x" + "00" * 31 + "01"],
                )
            )
        return out


class _RecordingFetcher:
    """Records ``from_block`` only — never raises — so the companion test can
    observe the wasteful low scan a block-0 seed produces."""

    def __init__(self) -> None:
        self.from_blocks: list[int] = []

    def fetch_logs(self, *, event_address, topics, from_block, to_block) -> list[FetchedEventLog]:
        self.from_blocks.append(from_block)
        return []


class _FixedHead:
    def head_block(self) -> int:
        return _HEAD


class _DeterministicBlockHash:
    def block_hash(self, block_number: int) -> bytes:
        return block_number.to_bytes(32, "big")


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


def _maps(fetcher):
    return ({1: fetcher}, {1: _FixedHead()}, {1: _DeterministicBlockHash()})


def _cursor_state(session, address: str):
    from db.models import IndexedEventCursor

    row = session.execute(
        select(IndexedEventCursor.last_indexed_block, IndexedEventCursor.backfill_complete).where(
            func.lower(IndexedEventCursor.event_address) == address.lower()
        )
    ).first()
    return (row[0], row[1]) if row else (None, None)


@requires_postgres
def test_backfill_starts_at_seed_and_never_scans_pre_deploy(session):
    enroll_event_cursor(session, chain_id=1, event_address=_AUTHORITY, topic0=_TOPIC, start_block=_DEPLOY - 1)
    session.commit()

    fetcher = _SeedAwareFetcher(_DEPLOY)
    fetchers, heads, hashes = _maps(fetcher)
    scan_enrolled_events(
        session,
        fetchers=fetchers,
        head_fetchers=heads,
        block_hash_fetchers=hashes,
        confirmation_depth=_CONFIRMATIONS,
        max_block_span=_MAX_SPAN,
        max_windows_per_cursor=500,
    )

    # The very first window begins AT the deploy block; nothing below is fetched
    # (the fetcher would have raised). Old behavior (seed 0) would start at 1.
    assert fetcher.from_blocks, "indexer never called the fetcher"
    assert min(fetcher.from_blocks) == _DEPLOY

    # Backfill reached head and flipped the completeness flag the resolvers gate on.
    last_block, complete = _cursor_state(session, _AUTHORITY)
    assert last_block == _TARGET
    assert complete is True


@requires_postgres
def test_block0_seed_scans_pre_deploy_range(session):
    # The bug, pinned: a cursor seeded at 0 fetches from block 1 — the empty
    # pre-deployment scan the creation-block seed eliminates.
    enroll_event_cursor(session, chain_id=1, event_address=_AUTHORITY, topic0=_TOPIC, start_block=0)
    session.commit()

    fetcher = _RecordingFetcher()
    fetchers, heads, hashes = _maps(fetcher)
    scan_enrolled_events(
        session,
        fetchers=fetchers,
        head_fetchers=heads,
        block_hash_fetchers=hashes,
        confirmation_depth=_CONFIRMATIONS,
        max_block_span=_MAX_SPAN,
        max_windows_per_cursor=5,
    )
    assert fetcher.from_blocks and min(fetcher.from_blocks) == 1


_SOLMATE_CANCALL_TREES = {
    "trees": {
        "pause()": {
            "op": "LEAF",
            "leaf": {
                "set_descriptor": {
                    "kind": "external_set",
                    "callee_signature": "canCall(address,address,bytes4)",
                    "authority_contract": {
                        "address_source": {"source": "state_variable", "state_variable_name": "authority"}
                    },
                }
            },
        }
    }
}


@requires_postgres
def test_enroll_from_completed_jobs_seeds_solmate_cursor_at_creation_block(session, monkeypatch):
    import workers.event_log_indexer as eli
    from db.models import Contract, ControllerValue, Job, JobStage, JobStatus, Protocol
    from db.queue import store_artifact

    authority = "0x" + "ab" * 20
    deploy = 18_500_000
    monkeypatch.setattr(
        eli,
        "get_contract_creation_block",
        lambda address, **_kw: deploy if address.lower() == authority else None,
    )

    protected = "0x" + "11" * 20
    job = Job(
        address=protected,
        request={"address": protected, "name": "T"},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(job)
    session.flush()
    store_artifact(session, job.id, "predicate_trees", data=_SOLMATE_CANCALL_TREES)

    proto = Protocol(name=f"seed_test_{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    contract = Contract(address=protected, chain="ethereum", protocol_id=proto.id, job_id=job.id)
    session.add(contract)
    session.flush()
    session.add(ControllerValue(contract_id=contract.id, controller_id="state_variable:authority", value=authority))
    session.commit()

    inserted = enroll_from_completed_jobs(session)
    assert inserted >= len(_SOLMATE_ROLE_TOPICS)

    # All three RolesAuthority role cursors are seeded one below the authority's
    # deploy block (so the first scan window starts AT deploy), and not yet
    # marked complete (the backfill hasn't run).
    for topic0 in _SOLMATE_ROLE_TOPICS:
        from db.models import IndexedEventCursor

        row = session.execute(
            select(IndexedEventCursor.last_indexed_block, IndexedEventCursor.backfill_complete)
            .where(IndexedEventCursor.chain_id == 1)
            .where(func.lower(IndexedEventCursor.event_address) == authority)
            .where(func.lower(IndexedEventCursor.topic0) == topic0.lower())
        ).first()
        assert row is not None, f"cursor for {topic0} not enrolled"
        assert row[0] == deploy - 1
        assert row[1] is False


@requires_postgres
def test_enroll_from_completed_jobs_skips_zero_authority(session, monkeypatch):
    # A Solmate canCall descriptor whose authority is renounced (0x0) must enroll
    # NO cursor: 0x0 has no creation block, so it would seed at genesis and backfill
    # the whole chain for an address that can never emit role events.
    import workers.event_log_indexer as eli
    from db.models import Contract, ControllerValue, IndexedEventCursor, Job, JobStage, JobStatus, Protocol
    from db.queue import store_artifact

    # If the guard works, _seed_block is never reached for 0x0; stub anyway so a
    # regression that *does* reach it can't quietly "succeed" with a real block.
    monkeypatch.setattr(eli, "get_contract_creation_block", lambda *a, **k: 18_500_000)

    protected = "0x" + "11" * 20
    job = Job(
        address=protected,
        request={"address": protected, "name": "T"},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(job)
    session.flush()
    store_artifact(session, job.id, "predicate_trees", data=_SOLMATE_CANCALL_TREES)

    proto = Protocol(name=f"zero_auth_{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    contract = Contract(address=protected, chain="ethereum", protocol_id=proto.id, job_id=job.id)
    session.add(contract)
    session.flush()
    session.add(
        ControllerValue(contract_id=contract.id, controller_id="state_variable:authority", value="0x" + "0" * 40)
    )
    session.commit()

    inserted = enroll_from_completed_jobs(session)
    assert inserted == 0
    zero_cursors = session.execute(
        select(func.count())
        .select_from(IndexedEventCursor)
        .where(func.lower(IndexedEventCursor.event_address) == "0x" + "0" * 40)
    ).scalar()
    assert zero_cursors == 0


def test_get_contract_creation_block_prefers_blocknumber(monkeypatch):
    import utils.etherscan as es

    monkeypatch.setattr(
        es,
        "get",
        lambda module, action, **params: {
            "status": "1",
            "result": [
                {"contractAddress": "0x" + "ab" * 20, "contractCreator": "0x" + "cd" * 20, "blockNumber": "18500000"}
            ],
        },
    )
    assert es.get_contract_creation_block("0x" + "ab" * 20, chain_id=1) == 18_500_000


def test_get_contract_creation_block_falls_back_to_txhash(monkeypatch):
    import utils.etherscan as es
    import utils.rpc as rpc

    monkeypatch.setattr(
        es,
        "get",
        lambda module, action, **params: {"status": "1", "result": [{"txHash": "0x" + "11" * 32}]},
    )
    monkeypatch.setattr(rpc, "rpc_request", lambda url, method, params, chain_id=None: {"blockNumber": hex(18_500_000)})
    assert es.get_contract_creation_block("0x" + "ab" * 20, chain_id=1, rpc_url="http://stub") == 18_500_000


def test_get_contract_creation_block_returns_none_on_failure(monkeypatch):
    import utils.etherscan as es

    def _raise(*_a, **_k):
        raise RuntimeError("etherscan down")

    monkeypatch.setattr(es, "get", _raise)
    assert es.get_contract_creation_block("0x" + "ab" * 20, chain_id=1) is None


def test_get_contract_creation_block_accepts_int_blocknumber(monkeypatch):
    import utils.etherscan as es

    monkeypatch.setattr(
        es, "get", lambda module, action, **params: {"status": "1", "result": [{"blockNumber": 18_500_000}]}
    )
    assert es.get_contract_creation_block("0x" + "ab" * 20, chain_id=1) == 18_500_000


def test_get_contract_creation_block_rejects_non_address():
    import utils.etherscan as es

    assert es.get_contract_creation_block("not-an-address", chain_id=1) is None


def test_get_contract_creation_block_none_when_no_block_and_no_txhash(monkeypatch):
    import utils.etherscan as es

    # Neither blockNumber nor a usable txHash → None (caller defers enrollment).
    monkeypatch.setattr(
        es, "get", lambda module, action, **params: {"status": "1", "result": [{"contractCreator": "0x" + "cd" * 20}]}
    )
    assert es.get_contract_creation_block("0x" + "ab" * 20, chain_id=1) is None


def test_seed_block_defers_on_lookup_error(monkeypatch):
    import workers.event_log_indexer as eli
    from workers.event_log_indexer import _seed_block

    def _raise(*_a, **_k):
        raise RuntimeError("etherscan down")

    monkeypatch.setattr(eli, "get_contract_creation_block", _raise)
    # A transient lookup failure must DEFER (None), never seed at genesis (0) — the
    # caller then skips enrollment and retries next pass rather than backfilling
    # ~20M empty pre-deploy blocks.
    assert _seed_block(_AUTHORITY, {}, chain_id=1) is None


def test_is_enrollable_event_address_rejects_zero_and_none():
    from workers.event_log_indexer import _is_enrollable_event_address

    assert _is_enrollable_event_address(_AUTHORITY) is True
    assert _is_enrollable_event_address("0x" + "0" * 40) is False  # renounced/unset authority
    assert _is_enrollable_event_address(None) is False
    assert _is_enrollable_event_address("0xdeadbeef") is False  # wrong length


@requires_postgres
def test_index_step_marks_backfill_complete_when_already_at_head(session):
    # A cursor already at/past the confirmed head takes the early-return path:
    # it must flip backfill_complete and never call the fetcher (no window).
    enroll_event_cursor(session, chain_id=1, event_address=_AUTHORITY, topic0=_TOPIC, start_block=_HEAD)
    session.commit()

    fetcher = _RecordingFetcher()
    fetchers, heads, hashes = _maps(fetcher)
    scan_enrolled_events(
        session,
        fetchers=fetchers,
        head_fetchers=heads,
        block_hash_fetchers=hashes,
        confirmation_depth=_CONFIRMATIONS,
        max_block_span=_MAX_SPAN,
        max_windows_per_cursor=5,
    )
    assert fetcher.from_blocks == []  # already at head → no scan window
    _, complete = _cursor_state(session, _AUTHORITY)
    assert complete is True


@requires_postgres
def test_pg_repo_not_backfill_complete_is_not_trusted(session):
    # The durable read gating that makes creation-block seeding safe: a cursor
    # seeded at the deploy block (positive) but not yet backfilled must NOT be
    # trusted — min_indexed_block returns None and the folds report
    # no_index_cursor (so the read fails closed) rather than folding a partial
    # history as if it were exact. Once the backfill completes, it's trusted.
    from db.models import IndexedEventCursor, IndexedEventLog
    from services.resolution.repos.event_logs_pg import PostgresEventLogRepo

    addr = "0x" + "7e" * 20
    topic = "0x" + "cd" * 32
    member = "0x" + "77" * 20
    session.add(
        IndexedEventCursor(
            chain_id=1, event_address=addr, topic0=topic, last_indexed_block=19_000_000, backfill_complete=False
        )
    )
    session.add(
        IndexedEventLog(
            chain_id=1,
            event_address=addr,
            topic0=topic,
            tx_hash=b"\x01" * 32,
            log_index=0,
            block_number=18_500_000,
            block_hash=b"\x02" * 32,
            transaction_index=0,
            topics=[topic, "0x" + "00" * 12 + member[2:]],
            data_words=[],
        )
    )
    session.commit()

    repo = PostgresEventLogRepo(session)
    assert repo.min_indexed_block(chain_id=1, event_address=addr, topic0s=[topic]) is None
    hist = repo.fold_event_history(
        chain_id=1,
        event_address=addr,
        event_hints=[{"topic0": topic, "direction": "add", "topics_to_keys": {1: 0}, "data_to_keys": {}}],
        key_sources=[{"source": "msg_sender"}],
    )
    assert hist.partial_reason == "no_index_cursor"
    writes = repo.fold_event_writes(
        chain_id=1,
        event_address=addr,
        topic0=topic,
        topics_to_keys={1: 0},
        data_to_keys={},
        key_sources=[{"source": "msg_sender"}],
        direction="add",
    )
    assert writes.partial_reason == "no_index_cursor"

    # Once the backfill completes, the same durable read is trusted and resolves.
    cursor = session.execute(select(IndexedEventCursor)).scalar_one()
    cursor.backfill_complete = True
    session.commit()
    assert repo.min_indexed_block(chain_id=1, event_address=addr, topic0s=[topic]) == 19_000_000
    # Evaluate at a height the (now backfilled) cursor covers — the resolver pins a
    # finalized height for this purpose (#119). A bare ``block=None`` would mean
    # "evaluate at live head", which the durable cursor structurally lags, so the
    # coverage gate correctly demotes that to lower_bound.
    hist2 = repo.fold_event_history(
        chain_id=1,
        event_address=addr,
        event_hints=[{"topic0": topic, "direction": "add", "topics_to_keys": {1: 0}, "data_to_keys": {}}],
        key_sources=[{"source": "msg_sender"}],
        block=19_000_000,
    )
    assert hist2.confidence == "enumerable"
    assert hist2.members == [member]
