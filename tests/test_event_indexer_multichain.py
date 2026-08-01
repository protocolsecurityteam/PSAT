"""M1.1 item 3 — the indexer threads a per-job / per-cursor chain_id instead of
stamping everything chain 1.

These tests prove a second-chain (Base, 8453) input reaches every threaded path:

  * ``_build_indexer_fetchers`` builds one fetcher per registry chain that
    declares HyperSync coverage — every chain, mainnet included, reads its own
    eRPC route (``{ERPC_BASE_URL}/main/evm/{chain_id}``); a ``hypersync_url is
    None`` chain gets no fetcher at all;
  * ``enroll_from_completed_jobs`` stamps each cursor with the enrolled job's own
    ``chain_id`` (a Base job → chain 8453 cursors, not chain 1);
  * ``scan_enrolled_events`` derives its confirmation depth per chain from the
    registry, and logs loudly (once) when a cursor's chain has no fetcher.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import func, select  # noqa: E402

from services.resolution.repos.event_logs_rpc import FetchedEventLog  # noqa: E402
from utils.chains import ChainInfo, chain_by_id  # noqa: E402
from workers.event_log_indexer import (  # noqa: E402
    _SOLMATE_ROLE_TOPICS,
    _build_indexer_fetchers,
    enroll_event_cursor,
    enroll_from_completed_jobs,
    scan_enrolled_events,
)

_DB_URL: str = os.environ.get("TEST_DATABASE_URL", os.environ.get("DATABASE_URL", "")) or ""

_BASE = 8453
_BASE_HYPERSYNC = "https://base.hypersync.xyz"
# The indexer routes EVERY covered chain — mainnet included — through its own
# eRPC route, never the native HyperSync host (that host is the resolution repos'
# query API and rejects JSON-RPC). A covered chain's fetcher URL is this route.
_ERPC_BASE = "https://erpc.example"
_MAINNET_ERPC = f"{_ERPC_BASE}/main/evm/1"
_BASE_ERPC = f"{_ERPC_BASE}/main/evm/{_BASE}"
# A registry chain still marked indexer-disabled (hypersync_url=None). Base used
# to play the "uncovered chain" role here, but Phase 2 enabled it — so the
# placeholder moves to arbitrum, which stays disabled until it earns its slot.
_UNCOVERED = 42161  # arbitrum
_AUTHORITY = "0x" + "5c" * 20
_TOPIC = "0x" + "ab" * 32


def _url(fetcher: object) -> str:
    """rpc_url of a concrete Rpc*Fetcher; the fetcher maps are typed by Protocol,
    which deliberately doesn't carry the attribute."""
    return cast(Any, fetcher).rpc_url


@pytest.fixture(autouse=True)
def _no_creation_witness(monkeypatch):
    """Enrollment grades its seed with three pinned chain reads before writing
    the cursor. Nothing here asserts that grade — the subject is the cursor's
    ``chain_id`` — so the wire is stubbed to the unreachable-RPC failure, whose
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


def _base_chaininfo(**overrides) -> ChainInfo:
    """A Base ChainInfo with its HyperSync URL pinned, for tests that need a
    covered second chain independent of registry state."""
    base = chain_by_id(_BASE)
    return dataclasses.replace(base, hypersync_url=_BASE_HYPERSYNC, **overrides)


# --------------------------------------------------------------------------- #
# Fetcher map — per-chain eRPC routes, gated by registry hypersync_url coverage
# --------------------------------------------------------------------------- #


def test_build_fetchers_mainnet_uses_erpc(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", _ERPC_BASE)
    fetchers, head_fetchers, block_hash_fetchers = _build_indexer_fetchers()
    # Covered chains today are mainnet + Base (Phase 2). Both read their own eRPC
    # route — mainnet is not special, there is no dedicated indexer lane.
    assert set(fetchers) == {1, _BASE}
    assert _url(fetchers[1]) == _MAINNET_ERPC
    assert _url(head_fetchers[1]) == _MAINNET_ERPC
    assert _url(block_hash_fetchers[1]) == _MAINNET_ERPC


def test_build_fetchers_second_chain_uses_erpc(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", _ERPC_BASE)
    chains = (chain_by_id(1), _base_chaininfo())
    fetchers, head_fetchers, block_hash_fetchers = _build_indexer_fetchers(chains=chains)
    # A covered second chain reads its OWN eRPC route — never mainnet's, never the
    # native HyperSync query host.
    assert _url(fetchers[1]) == _MAINNET_ERPC
    assert _url(fetchers[_BASE]) == _BASE_ERPC
    assert _url(head_fetchers[_BASE]) == _BASE_ERPC
    assert _url(block_hash_fetchers[_BASE]) == _BASE_ERPC


def test_build_fetchers_skips_chains_without_hypersync_url(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", _ERPC_BASE)
    # An indexer-disabled chain (hypersync_url=None) → no fetcher.
    chains = (chain_by_id(1), chain_by_id(_UNCOVERED))
    fetchers, _, _ = _build_indexer_fetchers(chains=chains)
    assert _UNCOVERED not in fetchers
    assert set(fetchers) == {1}


# --------------------------------------------------------------------------- #
# Enrollment — cursor chain_id comes from the job's chain
# --------------------------------------------------------------------------- #

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
    # A Base job: its first-class chain_id is 8453 (dual-written from
    # request["chain"]), so every cursor it enrolls must be stamped 8453 — not the
    # legacy mainnet default.
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
    # Every enrolled cursor carries the job's chain, and none was stamped chain 1.
    assert {r[0] for r in rows} == {_BASE}
    assert all(r[1] == deploy - 1 for r in rows)


# --------------------------------------------------------------------------- #
# Scan — per-chain confirmation depth + loud skip on a fetcher-less chain
# --------------------------------------------------------------------------- #


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


class _DeterministicBlockHash:
    def block_hash(self, block_number: int) -> bytes:
        return block_number.to_bytes(32, "big")


@requires_postgres
def test_scan_uses_registry_confirmation_depth_per_chain(session, monkeypatch):
    import workers.event_log_indexer as eli

    head = 30_000_000
    custom_depth = 50
    # Base with a bespoke confirmation depth — the scan must subtract THIS chain's
    # depth from head, not the fleet-wide 12.
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
    # Caught up to head - custom_depth (not head - 12).
    assert row[0] == head - custom_depth
    assert row[1] is True


@requires_postgres
def test_scan_logs_once_when_chain_has_no_fetcher(session, caplog):
    # A cursor enrolled on a chain with no fetcher (indexer disabled for it) is
    # skipped — but loudly, once, so a stalled chain is visible (inv. 4/10).
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
    # Exactly one warning for the chain, even though two cursor groups were skipped.
    assert len(skip_records) == 1


@requires_postgres
def test_scan_failure_logs_bounded_exc_msg(session, monkeypatch, caplog):
    # A swallowed group-scan failure must carry a bounded, sanitized exc_msg so the
    # error is attributable without re-enabling per-window traceback storms.
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
    # Bounded, present exc_msg carrying the swallowed detail.
    assert any(
        isinstance(getattr(r, "exc_msg", None), str) and "malformed" in r.exc_msg and len(r.exc_msg) <= 200
        for r in failed
    )
