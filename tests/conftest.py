from __future__ import annotations

import os
import sys
import threading
import urllib.error
import urllib.request
from collections import defaultdict
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import requests
import requests.adapters
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Offline runs route every RPC to a stub eRPC URL, since prod has no public fallback and CI has no .env. The URL is
# never dialed; a real ERPC_BASE_URL still wins.
if not os.environ.get("ERPC_BASE_URL"):
    os.environ["ERPC_BASE_URL"] = "http://erpc.invalid"

_STORAGE_ENV_KEYS = (
    "ARTIFACT_STORAGE_ENDPOINT",
    "ARTIFACT_STORAGE_BUCKET",
    "ARTIFACT_STORAGE_ACCESS_KEY",
    "ARTIFACT_STORAGE_SECRET_KEY",
    "ARTIFACT_STORAGE_PREFIX",
)

from db.models import (  # noqa: E402
    AddressFloorWitness,
    AuditContractCoverage,
    BalanceCollectionState,
    CompanyPagePurge,
    CompanyPageRevision,
    CompanyPageSnapshot,
    Contract,
    ContractBalance,
    ContractBalanceFetch,
    ContractCreationWitness,
    DaemonLease,
    EffectVerdict,
    IndexedEventCursor,
    IndexedEventLog,
    IndexerWork,
    Job,
    MonitoredContract,
    MonitoredEvent,
    Protocol,
    ProtocolSubscription,
    ProxySubscription,
    ProxyUpgradeEvent,
    RoleHolderPlane,
    RoleHolderPlaneRefresh,
    TvlSnapshot,
    UpgradeTransaction,
    WatchedProxy,
)

# The offline suite must make zero external calls: `.env` carries paid keys that `load_dotenv()` leaks into
# the test process. Every external wire goes through `requests`, while TestClient, MinIO and Postgres do not,
# so patching the `requests` transport fences off exactly the paid surface. `local_netguard.py` is the
# socket-level backstop.

_guard_lock = threading.Lock()
_guard_blocked: list[tuple[str, str]] = []  # (nodeid, host)
_guard_state = {"nodeid": "<collection>", "allow_all": False}
_real_http_send = requests.adapters.HTTPAdapter.send
_real_urlopen = urllib.request.urlopen


def _host_is_local(host: str | None) -> bool:
    if not host:
        return False
    lowered = host.lower()
    if lowered == "localhost" or lowered.endswith((".localhost", ".local")):
        return True
    try:
        ip = ip_address(host)
    except ValueError:
        return False  # a real hostname → treat as external
    return ip.is_loopback or ip.is_private or ip.is_link_local


def _guard_check(url: str) -> str | None:
    """Records the block (and, with ``PSAT_GUARD_TRACE``, the call site)."""
    if _guard_state["allow_all"]:
        return None
    host = urlsplit(url).hostname
    if _host_is_local(host):
        return None
    host = host or url
    # The guard's self-test raises without recording, since a recorded block fails the session.
    if "test_offline_network_guard" in _guard_state["nodeid"]:
        return host
    with _guard_lock:
        _guard_blocked.append((_guard_state["nodeid"], host))
    trace_to = os.environ.get("PSAT_GUARD_TRACE")
    if trace_to:
        import traceback

        # A file survives xdist output capture.
        path = trace_to if "/" in trace_to else "/tmp/psat_guard_trace.log"
        block = (
            f"\n[trace] {host} <= {_guard_state['nodeid']}\n"
            + "".join(f for f in traceback.format_stack()[:-1] if "/PSAT/" in f and "/conftest.py" not in f)[-1600:]
        )
        with open(path, "a") as fh:
            fh.write(block)
    return host


def _guarded_http_send(self, request, *args, **kwargs):
    host = _guard_check(request.url)
    if host is not None:
        parts = urlsplit(request.url)
        # Drop the query string, where API keys live.
        raise requests.exceptions.ConnectionError(
            f"[offline-guard] blocked external {request.method} {parts.scheme}://{host}{parts.path} — "
            f"offline tests must stub this wire (test: {_guard_state['nodeid']}). See the offline "
            f"network guard in tests/conftest.py."
        )
    return _real_http_send(self, request, *args, **kwargs)


def _guarded_urlopen(url, *args, **kwargs):
    target = url.full_url if isinstance(url, urllib.request.Request) else url
    host = _guard_check(target) if isinstance(target, str) else None
    if host is not None:
        raise urllib.error.URLError(
            f"[offline-guard] blocked external urlopen {host} — offline tests must stub this wire "
            f"(test: {_guard_state['nodeid']}). See the offline network guard in tests/conftest.py."
        )
    return _real_urlopen(url, *args, **kwargs)


if not getattr(requests.adapters.HTTPAdapter.send, "_psat_offline_guard", False):
    setattr(_guarded_http_send, "_psat_offline_guard", True)
    requests.adapters.HTTPAdapter.send = _guarded_http_send
    urllib.request.urlopen = _guarded_urlopen


def pytest_configure(config):
    # Live runs legitimately hit the server during collection and session fixtures.
    markexpr = getattr(config.option, "markexpr", "") or ""
    if "live" in markexpr and "not live" not in markexpr:
        _guard_state["allow_all"] = True


def pytest_runtest_logstart(nodeid, location):
    _guard_state["nodeid"] = nodeid


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    # Armed before fixtures are built, including session-scoped ones like the live health gate.
    _guard_state["allow_all"] = item.get_closest_marker("live") is not None


def pytest_sessionfinish(session, exitstatus):
    """A degraded-path test can swallow the guard's error and still pass, so the session status is escalated."""
    if not _guard_blocked:
        return
    worker = getattr(session.config, "workerinput", None)
    tag = worker["workerid"] if worker else "main"
    by_host: dict[str, set[str]] = defaultdict(set)
    for nodeid, host in _guard_blocked:
        by_host[host].add(nodeid.split("::")[0])
    print(f"\n[offline-guard:{tag}] {len(_guard_blocked)} blocked external call(s):", file=sys.stderr)
    for host in sorted(by_host):
        for f in sorted(by_host[host]):
            print(f"[offline-guard:{tag}] {host} <= {f}", file=sys.stderr)
    if session.exitstatus == 0:
        session.exitstatus = 1


DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")

os.environ.setdefault("PSAT_ADMIN_KEY", "test-admin-key")


TEST_STORAGE_ENDPOINT = os.environ.get("TEST_ARTIFACT_STORAGE_ENDPOINT", "")
TEST_STORAGE_BUCKET = os.environ.get("TEST_ARTIFACT_STORAGE_BUCKET", "")
TEST_STORAGE_ACCESS_KEY = os.environ.get("TEST_ARTIFACT_STORAGE_ACCESS_KEY", "")
TEST_STORAGE_SECRET_KEY = os.environ.get("TEST_ARTIFACT_STORAGE_SECRET_KEY", "")


def _can_connect_storage() -> bool:
    if not all([TEST_STORAGE_ENDPOINT, TEST_STORAGE_BUCKET, TEST_STORAGE_ACCESS_KEY, TEST_STORAGE_SECRET_KEY]):
        return False
    try:
        from db.storage import StorageClient

        client = StorageClient(
            TEST_STORAGE_ENDPOINT,
            TEST_STORAGE_BUCKET,
            TEST_STORAGE_ACCESS_KEY,
            TEST_STORAGE_SECRET_KEY,
        )
        client.ensure_bucket()
        return True
    except Exception:
        return False


requires_storage = pytest.mark.skipif(
    not _can_connect_storage(),
    reason="Object storage not available (set TEST_ARTIFACT_STORAGE_* and run minio)",
)


def _purge_bucket(client) -> None:
    paginator = client._client.get_paginator("list_objects_v2")
    keys: list[dict[str, str]] = []
    for page in paginator.paginate(Bucket=client.bucket):
        for obj in page.get("Contents", []):
            keys.append({"Key": obj["Key"]})
    for i in range(0, len(keys), 1000):
        if keys[i : i + 1000]:
            client._client.delete_objects(Bucket=client.bucket, Delete={"Objects": keys[i : i + 1000]})


@pytest.fixture()
def storage_bucket(monkeypatch):
    if not _can_connect_storage():
        pytest.skip("TEST_ARTIFACT_STORAGE_* not set or minio unreachable")

    monkeypatch.setenv("ARTIFACT_STORAGE_ENDPOINT", TEST_STORAGE_ENDPOINT)
    monkeypatch.setenv("ARTIFACT_STORAGE_BUCKET", TEST_STORAGE_BUCKET)
    monkeypatch.setenv("ARTIFACT_STORAGE_ACCESS_KEY", TEST_STORAGE_ACCESS_KEY)
    monkeypatch.setenv("ARTIFACT_STORAGE_SECRET_KEY", TEST_STORAGE_SECRET_KEY)

    from db.storage import get_storage_client, reset_client_cache

    reset_client_cache()
    client = get_storage_client()
    assert client is not None
    client.ensure_bucket()
    _purge_bucket(client)
    try:
        yield client
    finally:
        _purge_bucket(client)
        reset_client_cache()


@pytest.fixture
def _stub_rpc_bytecode(monkeypatch):
    """Empty code is treated as unknown bytecode; patching ``get_code_with_keccak`` covers ``get_code`` too."""
    from eth_utils.crypto import keccak

    empty_keccak = "0x" + keccak(b"").hex()
    monkeypatch.setattr("services.clients.rpc.get_code_with_keccak", lambda *a, **k: ("0x", empty_keccak))
    monkeypatch.setattr("services.clients.rpc.get_code", lambda *a, **k: "0x")
    monkeypatch.setattr("services.clients.rpc.get_code_batch", lambda rpc_url, addresses, **k: {})


@pytest.fixture
def _stub_live_authority(monkeypatch):
    """Offline these return ``None`` and ``indeterminate``, the documented no-RPC paths, so behaviour is unchanged."""
    monkeypatch.setattr(
        "services.resolution.predicate_evaluator.authority._live_resolve_authority",
        lambda *a, **k: None,
    )
    # Both the head-block read and the latch reads use the live wire.
    monkeypatch.setattr(
        "services.resolution.capability_resolver._maybe_one_shot_probe",
        lambda *a, **k: None,
    )


@pytest.fixture
def _stub_defillama_protocols(monkeypatch):
    """``[]`` gives the same empty result as a failed live fetch."""
    monkeypatch.setattr("services.discovery.protocol_resolver._fetch_protocols", lambda: [])


@pytest.fixture
def _stub_classifier_rpc(monkeypatch):
    """All-error slot reads make classification run offline as 'no proxy pattern'."""
    import services.discovery.classifier as _cls

    monkeypatch.setattr(
        _cls,
        "rpc_batch_request_with_status",
        lambda rpc_url, calls, *a, **k: [(None, True)] * len(calls),
    )
    monkeypatch.setattr(_cls, "rpc_call", lambda *a, **k: None)


@pytest.fixture
def _stub_chain_resolver(monkeypatch):
    """A no-op ``_probe_chains`` leaves every address unresolved, as if the probes found nothing."""
    monkeypatch.setattr("services.discovery.chain_resolver._probe_chains", lambda *a, **k: None)


@pytest.fixture(autouse=True)
def _scrub_storage_env(monkeypatch):
    """Clear ARTIFACT_STORAGE_* before every test.

    `db/models/session.py` calls `load_dotenv()` at import, which re-populates these
    from a developer's `.env` after any one-time scrub. Doing it per-test
    via monkeypatch is the only reliable way to keep the storage-off path
    available; tests that need real storage receive `storage_bucket`, which
    re-sets the same vars (monkeypatch lets the later setenv win).
    """
    for k in _STORAGE_ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    try:
        from db.storage import reset_client_cache
    except ImportError:
        pass
    else:
        reset_client_cache()
    yield


@pytest.fixture(autouse=True)
def _bypass_admin_key():
    try:
        import api as _api
        from routers.deps import require_admin_key
    except Exception:
        yield
        return
    _api.app.dependency_overrides[require_admin_key] = lambda: None
    try:
        yield
    finally:
        _api.app.dependency_overrides.pop(require_admin_key, None)


@pytest.fixture(autouse=True)
def _force_resolution_multicall_off(monkeypatch):
    """The Multicall3 flags default on, but offline tests stub only the per-call wire; the parity tests re-enable
    them in the test body.
    """
    for target in (
        "services.resolution.tracking._CLASSIFY_MULTICALL_ENABLED",
        "services.resolution.tracking._SNAPSHOT_MULTICALL_ENABLED",
        "services.resolution.external_check_materializer._EXTERNAL_CHECK_MULTICALL_ENABLED",
    ):
        monkeypatch.setattr(target, False)


@pytest.fixture(autouse=True)
def _force_differential_probe_off(monkeypatch):
    """The differential probe defaults on; the dedicated probe tests re-enable it in the test body."""
    monkeypatch.setenv("PSAT_DIFFERENTIAL_PROBE", "0")


@pytest.fixture(autouse=True)
def _stub_resolution_finality_head_read(monkeypatch):
    """The #119 finality pin reads live head unconditionally.

    Raising reproduces the head-read-failure path (unpinned, lower_bound); the #119 tests feed a canned head in the test
    body.
    """

    def _no_head_read(*a, **k):
        raise RuntimeError("offline: resolution head read stubbed (see tests/conftest.py)")

    monkeypatch.setattr("services.resolution.capability_resolver.rpc_request", _no_head_read)


@pytest.fixture(autouse=True)
def _stub_safe_protection_head_read(monkeypatch):
    """The Safe protection probe's head read is unconditional.

    Raising reproduces the failure path (every field not_determined); stubbed at ``_resolve_pinned_block`` because other
    tests feed ``_current_block_number``.
    """
    monkeypatch.setattr("services.resolution.tracking._resolve_pinned_block", lambda *_a, **_kw: None)


@pytest.fixture(autouse=True)
def _stub_indexer_witness_wire(monkeypatch):
    """Keep the offline suite hermetic against the indexer's floor-witness retries.

    Every enrolment drain ends with ``rewitness_due_floors``, which re-runs the seed
    lookup (Etherscan) and the three-read witness (RPC) for any cursored address with
    no witness row or a due failure. That read is unconditional on such fixtures.
    Raising here reproduces the outage path the code already takes (seed unknown or
    witness failed -> a ``failed`` row with backoff), so nothing dials out. Tests that
    drive enrolment or the witness patch these bindings in the test body, which runs
    after this fixture."""

    def _no_wire(*a, **k):
        raise RuntimeError("offline: indexer witness wire stubbed (see tests/conftest.py)")

    monkeypatch.setattr("workers.event_log_indexer.rpc_request", _no_wire)
    monkeypatch.setattr("workers.event_log_indexer.get_contract_creation_block", _no_wire)


@pytest.fixture(autouse=True)
def _stub_role_store_wire(monkeypatch):
    """The role-store adapter's probe and pin reads are unconditional.

    Raising reproduces the unreachable-RPC path; dedicated tests re-patch in the test body.
    """

    def _no_wire(*a, **k):
        raise RuntimeError("offline: role-store wire read stubbed (see tests/conftest.py)")

    monkeypatch.setattr("services.resolution.role_store_standards.get_code", _no_wire)
    monkeypatch.setattr("services.resolution.role_store_standards.rpc_request", _no_wire)
    monkeypatch.setattr("services.resolution.adapters.enumerable_role_store.rpc_request", _no_wire)
    # The creation-block lookup dials out when a local .env has a key; None is the documented lookup-failed path.
    monkeypatch.setattr("services.resolution.creation_block_floor.get_contract_creation_block", lambda *a, **k: None)


@pytest.fixture(autouse=True)
def _stub_event_tail_wire(monkeypatch):
    """Keep the offline suite hermetic against the event-fold tail scan.

    A warm cursor behind a pinned resolution block is completed by a live
    ``eth_getLogs`` over ``(cursor, pin]`` whenever the pass has an ``rpc_url``.
    Raising here reproduces the tail-failure path (fail closed), so no resolver
    test dials the wire. Dedicated tail tests monkeypatch this binding in the
    test body (which runs after this fixture) to feed canned logs."""

    def _no_wire(*a, **k):
        raise RuntimeError("offline: event tail wire read stubbed (see tests/conftest.py)")

    monkeypatch.setattr("services.resolution.event_tail.rpc_request", _no_wire)


@pytest.fixture(autouse=True)
def _stub_seed_witness_wire(monkeypatch):
    """Keep the offline suite hermetic against the indexer's floor witness.

    Every enrolment source, restaking included, grades its seed with three
    pinned reads (two ``eth_getCode``, one ``eth_getLogs``). Raising here
    reproduces the witness-failure path (``not_determined``). Witness tests
    patch this binding in the test body (``tests/support/witness_wire.py``)."""

    def _no_wire(*a, **k):
        raise RuntimeError("offline: seed witness wire read stubbed (see tests/conftest.py)")

    monkeypatch.setattr("workers.event_log_indexer.rpc_request", _no_wire)


class SessionFactory:
    """Wires sessionmaker consumers to the test DB without mutating ``DATABASE_URL`` globally."""

    def __init__(self, session):
        self._session = session

    def __call__(self):
        return self

    def __enter__(self):
        return self._session

    def __exit__(self, *exc):
        return False


@pytest.fixture()
def api_client(monkeypatch, db_session):
    from fastapi.testclient import TestClient

    import api as api_module
    from routers import deps

    monkeypatch.setattr(deps, "SessionLocal", SessionFactory(db_session))
    return TestClient(api_module.app)


@pytest.fixture
def spa_index(tmp_path, monkeypatch):
    """``routers.spa`` serves only the built ``site/dist``, and offline CI runs no build."""
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text(
        "<!doctype html><title>Run an address and inspect the control surface</title>",
        encoding="utf-8",
    )
    monkeypatch.setattr("routers.spa.SITE_DIST_DIR", dist)
    return dist


def _can_connect() -> bool:
    if not DATABASE_URL:
        return False
    try:
        engine = create_engine(DATABASE_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


requires_postgres = pytest.mark.skipif(not _can_connect(), reason="PostgreSQL not available (set TEST_DATABASE_URL)")


def run_alembic_upgrade(url: str) -> None:
    from alembic.config import Config

    from alembic import command

    repo_root = Path(__file__).resolve().parents[1]
    cfg = Config(str(repo_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(repo_root / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")


@pytest.fixture(scope="session", autouse=True)
def _migrate_test_db_once():
    if not _can_connect():
        return
    run_alembic_upgrade(DATABASE_URL)


def ADDR(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


def _topic_for(addr: str) -> str:
    return "0x" + "0" * 24 + addr[2:]


def _admin_data(old: str, new: str) -> str:
    return "0x" + "0" * 24 + old[2:] + "0" * 24 + new[2:]


def _make_log(
    address: str,
    topic0: str,
    topic1: str | None = None,
    data: str = "0x",
    block: str = "0x64",
    tx: str = "0xaaa",
    log_index: str = "0x0",
    timestamp: str = "0x65a00000",
) -> dict:
    return {
        "address": address,
        "topics": [topic0] + ([topic1] if topic1 else []),
        "data": data,
        "blockNumber": block,
        "transactionHash": tx,
        "logIndex": log_index,
        "timeStamp": timestamp,
    }


@pytest.fixture()
def db_session():
    engine = create_engine(DATABASE_URL)
    session = Session(engine, expire_on_commit=False)
    try:
        yield session
    finally:
        session.rollback()
        # Coverage references Contract, AuditReport and Protocol, so it goes first.
        for model in [
            AuditContractCoverage,
            BalanceCollectionState,
            MonitoredEvent,
            MonitoredContract,
            ProtocolSubscription,
            TvlSnapshot,
            ProxyUpgradeEvent,
            ProxySubscription,
            WatchedProxy,
            IndexedEventLog,
            IndexedEventCursor,
            AddressFloorWitness,
            # A poll/scan value-change queues a re-analysis Job (discovery
            # stage, queued). Left behind, it's claimable by an unrelated
            # claim_job in another test on the same xdist worker. FK children
            # are ON DELETE CASCADE and Job.protocol_id is SET NULL, so this
            # is order-independent among the rows below.
            Job,
            # Verdicts never cascade.
            EffectVerdict,
            Contract,
            Protocol,
            # Only reachable once Contract is gone.
            UpgradeTransaction,
            ContractCreationWitness,
            # Leases carry a live TTL; clear them so warm-DB reruns don't couple.
            DaemonLease,
            # Entity-keyed balance rows (no contract FK) are reachable by no cascade, and a leftover reading would read
            # as the next run's freshness.
            ContractBalance,
            ContractBalanceFetch,
            # Plane rows have no FK; a leftover row would become the next test's stored floor.
            RoleHolderPlane,
            RoleHolderPlaneRefresh,
            # Revision/outbox rows survive source deletion, so clear them after the source tables.
            IndexerWork,
            CompanyPageSnapshot,
            CompanyPagePurge,
            CompanyPageRevision,
        ]:
            session.query(model).delete()
        session.commit()
        session.close()
        engine.dispose()
