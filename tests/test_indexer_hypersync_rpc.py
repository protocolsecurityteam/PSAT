"""The event-log indexer runs on HyperSync only — never a metered provider.

The whole psat app was scaled to zero after the Alchemy spend cap was hit; the
indexer is a high-frequency poller and an accidental fall-through to Alchemy/eRPC
is what makes that recur (see EVENT_INDEXER_RPC_COST_VERDICT.md). These tests pin
the HyperSync-only resolution, the Bearer-auth that reaches the wire, and the
guard that stops scanning the junk 0x0 cursor.

Wire-level only is stubbed (``requests.Session.post``); the real fetcher classes,
``rpc_request`` and ``rpc_headers`` run.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import func, select  # noqa: E402

from services.resolution.repos.event_logs_rpc import (  # noqa: E402
    RpcBlockHashFetcher,
    RpcEventLogFetcher,
    RpcHeadBlockFetcher,
)
from utils.rpc import PUBLIC_ETH_RPC_URL  # noqa: E402
from workers.event_log_indexer import (  # noqa: E402
    DEFAULT_HYPERRPC_URL,
    build_indexer_fetchers,
    enroll_event_cursor,
    resolve_indexer_rpc,
    scan_enrolled_events,
)


# --------------------------------------------------------------------------- #
# resolve_indexer_rpc — HyperSync-only, no metered fallback                    #
# --------------------------------------------------------------------------- #
def test_resolve_explicit_url_wins(monkeypatch):
    monkeypatch.setenv("PSAT_INDEXER_RPC_URL", "https://operator.node/rpc")
    monkeypatch.setenv("ENVIO_API_TOKEN", "tok")
    assert resolve_indexer_rpc() == ("https://operator.node/rpc", None)


def test_resolve_token_builds_hyperrpc_bearer(monkeypatch):
    monkeypatch.delenv("PSAT_INDEXER_RPC_URL", raising=False)
    monkeypatch.setenv("ENVIO_API_TOKEN", "tok123")
    url, headers = resolve_indexer_rpc()
    assert url == DEFAULT_HYPERRPC_URL
    assert headers == {"Authorization": "Bearer tok123"}


def test_resolve_no_config_uses_public_node(monkeypatch):
    monkeypatch.delenv("PSAT_INDEXER_RPC_URL", raising=False)
    monkeypatch.delenv("ENVIO_API_TOKEN", raising=False)
    url, headers = resolve_indexer_rpc()
    assert url == PUBLIC_ETH_RPC_URL
    assert headers is None


def test_resolve_never_uses_alchemy_or_erpc(monkeypatch):
    """The load-bearing guarantee: even with eRPC/Alchemy configured in the env,
    the indexer never resolves to a metered provider. A regression here re-opens
    the spend-cap risk the feature exists to close."""
    monkeypatch.delenv("PSAT_INDEXER_RPC_URL", raising=False)
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.fly.dev")
    monkeypatch.setenv("ALCHEMY_API_KEY", "secret")

    monkeypatch.setenv("ENVIO_API_TOKEN", "tok")
    url_with_token, _ = resolve_indexer_rpc()
    monkeypatch.delenv("ENVIO_API_TOKEN", raising=False)
    url_without_token, _ = resolve_indexer_rpc()

    for url in (url_with_token, url_without_token):
        assert "erpc" not in url.lower()
        assert "alchemy" not in url.lower()
    assert url_with_token == DEFAULT_HYPERRPC_URL
    assert url_without_token == PUBLIC_ETH_RPC_URL


# --------------------------------------------------------------------------- #
# Auth threading: the Bearer header reaches the HTTP layer                     #
# --------------------------------------------------------------------------- #
class _FakeResp:
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


_WIRE_RESULTS = {
    "eth_getLogs": [],
    "eth_blockNumber": "0x10",
    "eth_getBlockByNumber": {"hash": "0x" + "11" * 32},
}


def test_build_indexer_fetchers_carries_url_and_auth():
    auth = {"Authorization": "Bearer abc"}
    fetchers, heads, hashes = build_indexer_fetchers(DEFAULT_HYPERRPC_URL, auth)
    ev, head, block_hash = fetchers[1], heads[1], hashes[1]
    assert isinstance(ev, RpcEventLogFetcher)
    assert isinstance(head, RpcHeadBlockFetcher)
    assert isinstance(block_hash, RpcBlockHashFetcher)
    assert ev.rpc_url == DEFAULT_HYPERRPC_URL
    assert ev.headers == auth
    assert head.headers == auth
    assert block_hash.headers == auth


def test_fetchers_send_bearer_auth_to_wire(monkeypatch):
    calls: list[tuple[str, str, dict]] = []

    def fake_post(self, url, json: dict[str, Any] | None = None, timeout=None, headers=None, **kwargs):
        assert json is not None
        method = str(json["method"])
        calls.append((url, method, dict(headers or {})))
        return _FakeResp({"jsonrpc": "2.0", "id": 1, "result": _WIRE_RESULTS[method]})

    monkeypatch.setattr(requests.Session, "post", fake_post)

    auth = {"Authorization": "Bearer testtoken"}
    url = DEFAULT_HYPERRPC_URL
    RpcEventLogFetcher(url, headers=auth).fetch_logs(
        event_address="0x" + "ab" * 20, topic0="0x" + "cd" * 32, from_block=1, to_block=3
    )
    RpcHeadBlockFetcher(url, headers=auth).head_block()
    RpcBlockHashFetcher(url, headers=auth).block_hash(100)

    assert {method for _, method, _ in calls} == {"eth_getLogs", "eth_blockNumber", "eth_getBlockByNumber"}
    for called_url, _method, sent_headers in calls:
        assert called_url == url
        assert sent_headers.get("Authorization") == "Bearer testtoken"
        assert sent_headers.get("Content-Type") == "application/json"


def test_fetchers_omit_auth_when_no_headers(monkeypatch):
    """No token → no Authorization header (the public-node path stays unauthed)."""
    seen: list[dict] = []

    def fake_post(self, url, json=None, timeout=None, headers=None, **kwargs):
        seen.append(dict(headers or {}))
        return _FakeResp({"jsonrpc": "2.0", "id": 1, "result": "0x10"})

    monkeypatch.setattr(requests.Session, "post", fake_post)
    RpcHeadBlockFetcher(PUBLIC_ETH_RPC_URL).head_block()
    assert seen and "Authorization" not in seen[0]


# --------------------------------------------------------------------------- #
# Junk 0x0 cursor is skipped by the scan                                       #
# --------------------------------------------------------------------------- #
_DB_URL: str = os.environ.get("TEST_DATABASE_URL", os.environ.get("DATABASE_URL", "")) or ""


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

_REAL = "0x" + "39" * 20
_ZERO = "0x" + "00" * 20
_TOPIC = "0x" + "ab" * 32


class _RecordingFetcher:
    def __init__(self) -> None:
        self.seen_addresses: list[str] = []

    def fetch_logs(self, *, event_address: str, topic0: str, from_block: int, to_block: int):
        self.seen_addresses.append(event_address.lower())
        return []


class _FixedHead:
    def head_block(self) -> int:
        return 1_000_000


class _DeterministicHash:
    def block_hash(self, block_number: int) -> bytes:
        return block_number.to_bytes(32, "big")


@pytest.fixture()
def session():
    if not _can_connect():
        pytest.skip("PostgreSQL not available")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from db.models import IndexedEventCursor, IndexedEventLog

    engine = create_engine(_DB_URL)
    s = Session(engine, expire_on_commit=False)
    try:
        yield s
    finally:
        s.rollback()
        for model in (IndexedEventLog, IndexedEventCursor):
            s.query(model).delete()
        s.commit()
        s.close()
        engine.dispose()


@requires_postgres
def test_scan_skips_zero_address_cursor(session):
    """A 0x0 cursor (predates the enroll guard) must never be handed to the
    fetcher — it can't emit logs, so scanning it just burns an RPC round-trip."""
    enroll_event_cursor(session, chain_id=1, event_address=_REAL, topic0=_TOPIC)
    enroll_event_cursor(session, chain_id=1, event_address=_ZERO, topic0=_TOPIC)
    session.commit()

    fetcher = _RecordingFetcher()
    summary = scan_enrolled_events(
        session,
        fetchers={1: fetcher},
        head_fetchers={1: _FixedHead()},
        block_hash_fetchers={1: _DeterministicHash()},
        confirmation_depth=12,
        max_block_span=10_000,
        max_windows_per_cursor=3,
    )

    assert _REAL.lower() in fetcher.seen_addresses
    assert _ZERO.lower() not in fetcher.seen_addresses
    # The junk cursor is excluded from the heartbeat total, and never advances.
    assert summary.total_cursors == 1
    from db.models import IndexedEventCursor

    zero_block = session.execute(
        select(IndexedEventCursor.last_indexed_block).where(func.lower(IndexedEventCursor.event_address) == _ZERO)
    ).scalar_one()
    assert zero_block == 0
