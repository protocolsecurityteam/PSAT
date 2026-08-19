"""inv-7 URL↔chain_id guard — threading proof (audit finding F6).

``rpc_request``'s runtime guard (``_assert_url_chain_id``) is a no-op unless the
caller declares ``chain_id``. These tests drive each threaded production path with
a non-mainnet chain (base = 8453) and assert the *declared* chain_id actually
reaches the wire — so a silent ``=1`` default (or a dropped declaration) fails
here, not in prod. Only the wire (``rpc_request`` / ``get_code`` / the batch
helper) is stubbed at each consuming module's import site; the production
functions run unmodified, matching the hermetic offline suite.

The negative case proves the guard genuinely fires *through* the threading: an
eRPC-shaped URL for one chain paired with a different declared chain_id raises.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from db.models import Contract, MonitoredContract, Protocol, WatchedProxy

BASE_CHAIN_ID = 8453
ERPC_BASE = "https://erpc.test"
BASE_URL = f"{ERPC_BASE}/main/evm/{BASE_CHAIN_ID}"
MAINNET_SEED = "http://mainnet-seed"


def _addr(prefix: str) -> str:
    return "0x" + (prefix * 40)[:40]


# ---------------------------------------------------------------------------
# monitoring — proxy_watcher.resolve_current_implementation
# ---------------------------------------------------------------------------


def test_proxy_watcher_resolve_impl_threads_chain_id(monkeypatch):
    from services.monitoring import proxy_watcher

    seen: list[int | None] = []

    def _rpc(url, method, params, *a, chain_id=None, **kw):
        seen.append(chain_id)
        # eth_getStorageAt for the eip1967 slot → a real impl word.
        return "0x" + "0" * 24 + _addr("f")[2:]

    monkeypatch.setattr(proxy_watcher, "rpc_request", _rpc)

    proxy_watcher.resolve_current_implementation(_addr("a"), BASE_URL, proxy_type="eip1967", chain_id=BASE_CHAIN_ID)
    assert seen == [BASE_CHAIN_ID]


# ---------------------------------------------------------------------------
# routers/monitored — _current_head_block
# ---------------------------------------------------------------------------


def test_router_current_head_block_threads_chain_id(monkeypatch):
    import routers.monitored as monitored

    monkeypatch.setenv("ERPC_BASE_URL", ERPC_BASE)
    seen: list[int | None] = []

    def _rpc(url, method, params, *a, chain_id=None, **kw):
        seen.append(chain_id)
        return "0x10"

    monkeypatch.setattr(monitored, "rpc_request", _rpc)

    monitored._current_head_block("base")
    assert seen == [BASE_CHAIN_ID]


# ---------------------------------------------------------------------------
# event repos — RpcEventLogFetcher
# ---------------------------------------------------------------------------


def test_event_log_fetcher_threads_constructor_chain_id(monkeypatch):
    from services.resolution.repos import event_logs_rpc

    seen: list[int | None] = []

    def _rpc(url, method, params, *a, chain_id=None, **kw):
        seen.append(chain_id)
        return []

    monkeypatch.setattr(event_logs_rpc, "rpc_request", _rpc)

    fetcher = event_logs_rpc.RpcEventLogFetcher(BASE_URL, chain_id=BASE_CHAIN_ID)
    fetcher.fetch_logs(event_address=_addr("a"), topics=["0x" + "1" * 64], from_block=0, to_block=0)
    assert seen == [BASE_CHAIN_ID]


# ---------------------------------------------------------------------------
# resolution — tracking.classify_resolved_address
# ---------------------------------------------------------------------------


def test_tracking_classify_threads_chain_id(monkeypatch):
    from services.resolution import tracking

    tracking.clear_classify_cache()
    seen: list[int | None] = []

    def _rpc(url, method, params, *a, chain_id=None, **kw):
        seen.append(chain_id)
        return "0x"  # empty code → "eoa", short-circuits before the probes

    monkeypatch.setattr(tracking, "_rpc_request", _rpc)

    # Unique non-zero address so the process-wide classify cache never hits.
    kind, _details = tracking.classify_resolved_address(BASE_URL, _addr("b"), chain_id=BASE_CHAIN_ID)
    assert kind == "eoa"
    assert seen and all(c == BASE_CHAIN_ID for c in seen)


# ---------------------------------------------------------------------------
# discovery — static_dependencies.discover_dependencies
# ---------------------------------------------------------------------------


def test_static_dependencies_thread_chain_id(monkeypatch):
    from services.discovery import static_dependencies

    seen: list[int | None] = []

    def _get_code(url, address, *, chain_id=None):
        seen.append(chain_id)
        return "0x60"  # has code, no PUSH20 → no dependencies to recurse into

    monkeypatch.setattr(static_dependencies, "get_code", _get_code)

    static_dependencies.discover_dependencies(BASE_URL, _addr("a"), chain_id=BASE_CHAIN_ID)
    assert seen and all(c == BASE_CHAIN_ID for c in seen)


# ---------------------------------------------------------------------------
# discovery — secondary_impl.resolve_secondary_impl_addresses
# ---------------------------------------------------------------------------


def test_secondary_impl_threads_chain_id(monkeypatch):
    from services.discovery import secondary_impl

    seen: list[int | None] = []

    def _rpc(url, method, params, *a, chain_id=None, **kw):
        seen.append(chain_id)
        return "0x" + "0" * 24 + _addr("d")[2:]

    # resolve_secondary_impl_addresses imports rpc_request from services.clients.rpc at call time.
    monkeypatch.setattr("services.clients.rpc.rpc_request", _rpc)

    out = secondary_impl.resolve_secondary_impl_addresses(
        BASE_URL,
        _addr("a"),
        [{"slot": 1}],
        require_code=False,
        chain_id=BASE_CHAIN_ID,
    )
    assert out  # the storage read decoded to an address
    assert seen == [BASE_CHAIN_ID]


# ---------------------------------------------------------------------------
# discovery — classifier.classify_single
# ---------------------------------------------------------------------------


def test_classifier_classify_single_threads_chain_id(monkeypatch):
    from services.discovery import classifier

    seen: list[int | None] = []

    def _batch(url, calls, *a, chain_id=None, **kw):
        seen.append(chain_id)
        return [("0x" + "0" * 64, False)] * len(calls)  # all proxy slots read zero

    def _rpc_call(url, method, params, *a, chain_id=None, **kw):
        seen.append(chain_id)
        return "0x"  # every getter reverts/empty → not a proxy

    monkeypatch.setattr(classifier, "rpc_batch_request_with_status", _batch)
    monkeypatch.setattr(classifier, "rpc_call", _rpc_call)

    # Non-proxy bytecode (no eip1167 prefix, no DELEGATECALL) so classification
    # runs the slot batch + getter probes then settles on "regular".
    info = classifier.classify_single(_addr("a"), BASE_URL, bytecode="0x6001", chain_id=BASE_CHAIN_ID)
    assert info["type"] == "regular"
    assert seen and all(c == BASE_CHAIN_ID for c in seen)


# ---------------------------------------------------------------------------
# monitoring — enrollment seed-block read
# ---------------------------------------------------------------------------


def test_enrollment_seed_block_threads_chain_id(db_session, monkeypatch):
    from db.models import Job, JobStage, JobStatus
    from services.monitoring.enrollment import enroll_protocol_contracts

    monkeypatch.setenv("ERPC_BASE_URL", ERPC_BASE)
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")

    proto = Protocol(name=f"__guard_enroll_{uuid.uuid4().hex[:8]}__")
    db_session.add(proto)
    db_session.flush()

    proxy_addr = _addr("e")
    db_session.add(
        Contract(
            address=proxy_addr,
            chain="base",
            protocol_id=proto.id,
            contract_name="BaseProxy",
            is_proxy=True,
            proxy_type="eip1967",
            implementation=_addr("f"),
        )
    )
    db_session.add(Job(address=proxy_addr, protocol_id=proto.id, status=JobStatus.completed, stage=JobStage.done))
    db_session.commit()

    seen: list[int | None] = []

    def _rpc(url, method, params, *a, chain_id=None, **kw):
        seen.append(chain_id)
        return "0x100"

    monkeypatch.setattr("services.monitoring.enrollment.rpc_request", _rpc)

    # Seeded with the mainnet URL; the base contract must declare its OWN chain id.
    enroll_protocol_contracts(db_session, proto.id, MAINNET_SEED, "ethereum")

    wp = db_session.execute(select(WatchedProxy).where(WatchedProxy.proxy_address == proxy_addr)).scalar_one()
    assert wp.chain == "base"
    mc = db_session.execute(select(MonitoredContract).where(MonitoredContract.address == proxy_addr)).scalar_one()
    assert mc.chain == "base"

    # The seed-block read declared base's chain id, never a mainnet default.
    assert seen and all(c == BASE_CHAIN_ID for c in seen)


# ---------------------------------------------------------------------------
# Negative — the guard fires THROUGH a threaded path
# ---------------------------------------------------------------------------


def test_threaded_path_guard_raises_on_mismatch(monkeypatch):
    """A fetcher constructed for chain 1 but handed a base-routed eRPC URL must
    raise via ``_assert_url_chain_id`` — proving the declaration reaches the guard
    (not just that the guard exists in isolation)."""
    from services.resolution.repos.event_logs_rpc import RpcEventLogFetcher

    monkeypatch.setenv("ERPC_BASE_URL", ERPC_BASE)
    fetcher = RpcEventLogFetcher(BASE_URL, chain_id=1)  # URL routes 8453, declares 1
    with pytest.raises(RuntimeError, match="chain_id"):
        fetcher.fetch_logs(event_address=_addr("a"), topics=["0x" + "1" * 64], from_block=0, to_block=0)
