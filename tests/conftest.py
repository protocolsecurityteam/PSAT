"""Shared fixtures and helpers for proxy monitoring tests."""

from __future__ import annotations

import os
import sys
import threading
import urllib.error
import urllib.request
import uuid
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

# The offline suite is hermetic: route every RPC resolution to a stub eRPC URL so
# no test depends on a real ERPC_BASE_URL. Prod default_rpc_url() has no public
# fallback, so with no route require_rpc_url() raises -- and CI has no .env for the
# import-time load_dotenv() to read, so the var is simply absent there. The wire
# itself is stubbed per-test and fenced by local_netguard, so this URL is never
# dialed. A real ERPC_BASE_URL already in the environment (e.g. the live CI job)
# still wins.
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
    AuditContractCoverage,
    Contract,
    DaemonLease,
    EffectVerdict,
    IndexedEventCursor,
    IndexedEventLog,
    Job,
    MonitoredContract,
    MonitoredEvent,
    Protocol,
    ProtocolSubscription,
    ProxySubscription,
    ProxyUpgradeEvent,
    TvlSnapshot,
    WatchedProxy,
)

# ---------------------------------------------------------------------------
# Offline network guard
# ---------------------------------------------------------------------------
#
# The offline suite (`pytest -m "not live"`) must make ZERO real external
# network calls. `.env` carries real *paid* keys (OpenRouter, Alchemy, Tavily,
# Exa) and `db.models` calls `load_dotenv()` at import, so those values leak
# into the test process — an unmocked call would spend money / burn rate limits
# / hit live state. Every external wire in this codebase goes through the
# `requests` library (RPC, Etherscan, OpenRouter, GitHub, DeFiLlama, Exa,
# Tavily). The local services do not: TestClient speaks httpx, MinIO/boto3 use
# urllib3 directly, Postgres uses libpq (C). So patching the single `requests`
# transport chokepoint fences off exactly the paid surface and leaves Postgres,
# MinIO and the in-process API untouched.
#
# Tests must stub their wire (the `utils.rpc` / `utils.etherscan` / `utils.llm`
# / github / defillama helpers). Anything left unmocked trips this guard and
# fails loudly in-process. `local_netguard.py` is the socket-level backstop
# that also catches any non-`requests` egress.

_guard_lock = threading.Lock()
_guard_blocked: list[tuple[str, str]] = []  # (nodeid, host)
_guard_state = {"nodeid": "<collection>", "allow_all": False}
_real_http_send = requests.adapters.HTTPAdapter.send
_real_urlopen = urllib.request.urlopen


def _host_is_local(host: str | None) -> bool:
    """True for loopback / private / link-local hosts (Postgres, MinIO, Anvil)."""
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
    """Return the offending host when *url* is external and the guard is armed.

    Records the block (and, with ``PSAT_GUARD_TRACE``, the call site) as a side
    effect; returns ``None`` when the call is allowed through.
    """
    if _guard_state["allow_all"]:
        return None
    host = urlsplit(url).hostname
    if _host_is_local(host):
        return None
    host = host or url
    # The guard's own self-test deliberately triggers blocks: raise (so the test
    # observes it) but don't record — a recorded block fails the session.
    if "test_offline_network_guard" in _guard_state["nodeid"]:
        return host
    with _guard_lock:
        _guard_blocked.append((_guard_state["nodeid"], host))
    trace_to = os.environ.get("PSAT_GUARD_TRACE")
    if trace_to:
        import traceback

        # Append the call site to a file (survives pytest/xdist output capture).
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
        # Drop the query string — Etherscan & friends carry the API key there.
        raise requests.exceptions.ConnectionError(
            f"[offline-guard] blocked external {request.method} {parts.scheme}://{host}{parts.path} — "
            f"offline tests must stub this wire (test: {_guard_state['nodeid']}). See the offline "
            f"network guard in tests/conftest.py."
        )
    return _real_http_send(self, request, *args, **kwargs)


def _guarded_urlopen(url, *args, **kwargs):
    # `urllib.request.urlopen` accepts a URL string or a Request object.
    target = url.full_url if isinstance(url, urllib.request.Request) else url
    host = _guard_check(target) if isinstance(target, str) else None
    if host is not None:
        raise urllib.error.URLError(
            f"[offline-guard] blocked external urlopen {host} — offline tests must stub this wire "
            f"(test: {_guard_state['nodeid']}). See the offline network guard in tests/conftest.py."
        )
    return _real_urlopen(url, *args, **kwargs)


if not getattr(requests.adapters.HTTPAdapter.send, "_psat_offline_guard", False):
    _guarded_http_send._psat_offline_guard = True
    requests.adapters.HTTPAdapter.send = _guarded_http_send
    urllib.request.urlopen = _guarded_urlopen


def pytest_configure(config):
    # The guard protects the OFFLINE suite. A live run (-m "live ...") legitimately
    # talks to the deployed server during collection and session-scoped fixtures
    # (e.g. tests/live/conftest.py's health gate), so disable the guard wholesale.
    markexpr = getattr(config.option, "markexpr", "") or ""
    if "live" in markexpr and "not live" not in markexpr:
        _guard_state["allow_all"] = True


def pytest_runtest_logstart(nodeid, location):
    _guard_state["nodeid"] = nodeid


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    # Arm/disarm per item BEFORE its fixtures are built — including session-scoped
    # ones like the live health gate, which a function-scoped fixture ran too late
    # to cover. Live tests (auto-marked under tests/live/) legitimately hit external
    # hosts, so they opt out; everything else stays guarded.
    _guard_state["allow_all"] = item.get_closest_marker("live") is not None


def pytest_sessionfinish(session, exitstatus):
    """Report any blocked external calls and fail the session if there were any.

    A degraded-path test can *swallow* the guard's ConnectionError and still
    pass — so the per-test result alone won't catch a leak. Escalating the
    session exit status here makes an unmocked wire fail the (serial) build
    even when the calling code degrades gracefully.
    """
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


# ---------------------------------------------------------------------------
# PostgreSQL connection
# ---------------------------------------------------------------------------

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")

os.environ.setdefault("PSAT_ADMIN_KEY", "test-admin-key")

# ---------------------------------------------------------------------------
# Object storage (minio in dev, Tigris in prod) — opt-in via storage_bucket
# ---------------------------------------------------------------------------

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
    """Wire ARTIFACT_STORAGE_* to the test bucket and clean it on teardown."""
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
    """Stub the eth_getCode bytecode helpers so offline tests never probe a real RPC.

    Returns empty code (``"0x"``); every caller treats that as "no / unknown
    bytecode" — the same path these tests already took when the RPC was
    unreachable. Patching ``get_code_with_keccak`` covers ``get_code`` too (it
    delegates), regardless of how a module imported the name.
    """
    from eth_utils.crypto import keccak

    empty_keccak = "0x" + keccak(b"").hex()
    monkeypatch.setattr("utils.rpc.get_code_with_keccak", lambda *a, **k: ("0x", empty_keccak))
    monkeypatch.setattr("utils.rpc.get_code", lambda *a, **k: "0x")
    monkeypatch.setattr("utils.rpc.get_code_batch", lambda rpc_url, addresses, **k: {})


@pytest.fixture
def _stub_live_authority(monkeypatch):
    """Stub the live owner()/governor() getter read in predicate evaluation.

    ``_live_resolve_authority`` issues an ``eth_call`` when a reachable RPC is in
    the evaluation context; offline there is none, so it returns ``None`` (the
    documented "pure-unit evaluation, keep the lower_bound placeholder" path).
    Returning ``None`` here reproduces that exact behaviour without the wire.

    Also stubs the on-chain one-shot consumed/live probe (same hermeticity
    concern — a live read during ``resolve_contract_capabilities``): offline it
    returns ``indeterminate``, exactly the documented "no reachable RPC → keep
    the static badge" path, so the projection is unchanged without the wire.
    """
    monkeypatch.setattr(
        "services.resolution.predicate_evaluator._live_resolve_authority",
        lambda *a, **k: None,
    )
    # Disable the on-chain one-shot probe wholesale offline (its head-block read
    # AND its latch reads both use the live wire). A no-op leaves every one-shot
    # row at its static badge — the documented "no reachable RPC → static stands"
    # path — so the projection is unchanged without any network.
    monkeypatch.setattr(
        "services.resolution.capability_resolver._maybe_one_shot_probe",
        lambda *a, **k: None,
    )


@pytest.fixture
def _stub_defillama_protocols(monkeypatch):
    """Stub the DefiLlama protocol-list fetch (``api.llama.fi/protocols``).

    Returns ``[]`` — ``resolve_protocol`` already maps "no protocols" to the
    same empty ``{"slug": None, ...}`` result it returns when the live fetch
    fails, so offline tests see identical behaviour without the wire.
    """
    monkeypatch.setattr("services.discovery.protocol_resolver._fetch_protocols", lambda: [])


@pytest.fixture
def _stub_classifier_rpc(monkeypatch):
    """Stub the proxy/impl classifier's RPC probes (batched slot read → all-error
    so it falls back to the per-slot reader, plus the per-slot ``rpc_call`` used by
    storage-slot / implementation / facet probes). Classification then runs offline
    as 'no proxy pattern' — incidental to callers that only need a dependency map."""
    import services.discovery.classifier as _cls

    monkeypatch.setattr(
        _cls,
        "rpc_batch_request_with_status",
        lambda rpc_url, calls, *a, **k: [(None, True)] * len(calls),
    )
    monkeypatch.setattr(_cls, "rpc_call", lambda *a, **k: None)


@pytest.fixture
def _stub_chain_resolver(monkeypatch):
    """Stub multi-chain resolution (``chain_resolver`` probes eRPC via urllib).

    Neutralises the per-chain ``eth_getCode`` probes (``_probe_chains`` mutates
    its ``matched`` dict in place, so a no-op leaves every address unresolved —
    the same outcome as the probes finding nothing), so resolution runs with no
    wire and no RPC dependency.
    """
    monkeypatch.setattr("services.discovery.chain_resolver._probe_chains", lambda *a, **k: None)


@pytest.fixture(autouse=True)
def _scrub_storage_env(monkeypatch):
    """Clear ARTIFACT_STORAGE_* before every test.

    `db/models.py` calls `load_dotenv()` at import, which re-populates these
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
    """Override the admin-key dependency for every test so existing API tests keep working."""
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
    """Keep the offline suite hermetic against the resolution Multicall3 read-collapse.

    The three flags default ON in code so real runs (local + prod) need no env, but
    offline tests stub only the per-call wire (``tracking._rpc_request`` /
    ``_rpc_batch_request_with_status``) — NOT ``utils.rpc.rpc_request``, which
    ``multicall3_aggregate3`` calls. With the default ON, in-process resolution tests
    would fire REAL aggregate3 eth_calls and then fall back: non-hermetic, slow, flaky.
    Forcing the constants False routes the general suite through the stubbed per-call
    path. The dedicated parity tests (test_classify_batch_parity, test_control_tracker,
    test_external_check_materializer) set these True inside the test body — which runs
    after this fixture — so they still exercise the ON path.
    """
    for target in (
        "services.resolution.tracking._CLASSIFY_MULTICALL_ENABLED",
        "services.resolution.tracking._SNAPSHOT_MULTICALL_ENABLED",
        "services.resolution.external_check_materializer._EXTERNAL_CHECK_MULTICALL_ENABLED",
    ):
        monkeypatch.setattr(target, False)


@pytest.fixture(autouse=True)
def _force_differential_probe_off(monkeypatch):
    """Keep the offline suite hermetic against the differential probe (default ON in
    code, so real runs need no env). With the flag on, in-process resolution tests
    would issue REAL ``eth_call`` probes during the policy stage: non-hermetic, slow,
    netguard-tripping. Forcing the env off routes offline resolution through the
    static path. The dedicated probe tests inject a stubbed ``call_batch`` / set the
    flag in the test body (which runs after this fixture), so they still exercise it."""
    monkeypatch.setenv("PSAT_DIFFERENTIAL_PROBE", "0")


@pytest.fixture(autouse=True)
def _stub_resolution_finality_head_read(monkeypatch):
    """Keep the offline suite hermetic against the #119 finality-margin head pin.

    ``resolve_contract_capabilities`` now reads live head once per pass
    (``_resolve_resolution_block`` -> ``eth_blockNumber``) to pin the event-fold
    evaluation height. Unlike the default-OFF differential probe, this read is
    UNCONDITIONAL, and offline the resolver still resolves a real eRPC ``rpc_url``
    (``require_rpc_url``) — so the read would hit the network and trip the offline
    guard. Making the resolver's ``rpc_request`` raise reproduces the exact
    "blocknum read failure -> unpinned ``block=None`` -> fold demotes to
    lower_bound" path the code already takes when the head read fails, so offline
    behaviour is byte-identical without the wire. ``_resolve_probe_block`` (probe,
    already flag-gated off above) shares this binding and stays a no-op too. The
    dedicated #119 tests monkeypatch ``rpc_request`` in the test body (which runs
    after this fixture) to feed a canned head, so they still exercise the real pin."""

    def _no_head_read(*a, **k):
        raise RuntimeError("offline: resolution head read stubbed (see tests/conftest.py)")

    monkeypatch.setattr("services.resolution.capability_resolver.rpc_request", _no_head_read)


@pytest.fixture(autouse=True)
def _stub_safe_protection_head_read(monkeypatch):
    """Keep the offline suite hermetic against the Safe module/guard probe.

    ``_probe_safe_protection`` fires on every address classified as a Safe and
    resolves ``latest`` to a concrete height first (``eth_blockNumber``) so the
    published ``probe_block`` is the height the words came from. That head read is
    unconditional and offline the classifier still resolves a real eRPC URL, so it
    would hit the wire. Making it raise reproduces the exact head-read-failure path
    the code already takes — probe suppressed, every protection field
    ``not_determined``, zero further RPC — so offline behaviour is byte-identical
    without the wire. Stubbed at ``_resolve_pinned_block`` rather than at
    ``_current_block_number``, which the control-snapshot builder also uses and
    several tests feed their own canned head. The dedicated C1 tests re-patch this
    binding in the test body (which runs after this fixture) to pin 25643300."""
    monkeypatch.setattr("services.resolution.tracking._resolve_pinned_block", lambda *_a, **_kw: None)


@pytest.fixture(autouse=True)
def _stub_role_store_wire(monkeypatch):
    """Keep the offline suite hermetic against the role-store wire reads.

    ``EnumerableRoleStoreAdapter.matches`` runs on every external_set dispatch and
    calls ``resolve_probe_code`` (``eth_getCode`` / EIP-1967 ``eth_getStorageAt``)
    to detect the standard; the adapter's ``_pin_probe_block`` reads
    ``eth_blockNumber`` on an unpinned pass. Both are UNCONDITIONAL wire reads on
    a resolvable authority, so any resolver-driving test would otherwise dial the
    poisoned eRPC URL and trip the offline guard. Raising here reproduces the
    exact failure path the code already takes on an unreachable RPC (detection
    inconclusive -> matches()=0 -> inline/guard; pin failure -> probe_unavailable),
    so offline behaviour is byte-identical without the wire. Dedicated role-store
    tests monkeypatch these bindings in the test body (which runs after this
    fixture), so they still exercise detection, fold, and probe."""

    def _no_wire(*a, **k):
        raise RuntimeError("offline: role-store wire read stubbed (see tests/conftest.py)")

    monkeypatch.setattr("services.resolution.role_store_standards.get_code", _no_wire)
    monkeypatch.setattr("services.resolution.role_store_standards.rpc_request", _no_wire)
    monkeypatch.setattr("services.resolution.adapters.enumerable_role_store.rpc_request", _no_wire)
    # The scan-floor's Etherscan creation-block lookup is keyless-silent in CI but
    # dials out when a local .env carries an API key. None is the documented
    # "lookup failed -> cursor/defer" path, identical to the keyless behaviour.
    monkeypatch.setattr("services.resolution.creation_block_floor.get_contract_creation_block", lambda *a, **k: None)


class SessionFactory:
    """Stand-in for sessionmaker that yields a single shared Session.

    Use to wire ``routers.deps.SessionLocal`` (or any code expecting a
    sessionmaker) at the test DB without mutating ``DATABASE_URL`` globally.
    """

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
    """TestClient with ``routers.deps.SessionLocal`` pointed at the test DB session.

    Avoids the prod-default engine (DATABASE_URL=postgresql://...:5433/psat)
    that the FastAPI app would otherwise use.
    """
    from fastapi.testclient import TestClient

    import api as api_module
    from routers import deps

    monkeypatch.setattr(deps, "SessionLocal", SessionFactory(db_session))
    return TestClient(api_module.app)


@pytest.fixture
def spa_index(tmp_path, monkeypatch):
    """Point the SPA router at a stand-in built ``dist/index.html``.

    ``routers.spa`` serves the index only from the built ``site/dist`` — the
    source-index fallback was removed so prod can never serve an unbuilt page.
    The offline CI job runs no ``npm run build``, so tests asserting the SPA
    HTML is served need a stand-in dist rather than the real (absent) one.
    """
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
    """Run ``alembic upgrade head`` against ``url``. Idempotent."""
    from alembic.config import Config

    from alembic import command

    repo_root = Path(__file__).resolve().parents[1]
    cfg = Config(str(repo_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(repo_root / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")


@pytest.fixture(scope="session", autouse=True)
def _migrate_test_db_once():
    """Bring TEST_DATABASE_URL up to head once per session."""
    if not _can_connect():
        return
    run_alembic_upgrade(DATABASE_URL)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def ADDR(n: int) -> str:
    """Generate a deterministic 0x-prefixed address from an integer."""
    return "0x" + hex(n)[2:].zfill(40)


def _topic_for(addr: str) -> str:
    """Pad a 20-byte address to a 32-byte topic."""
    return "0x" + "0" * 24 + addr[2:]


def _admin_data(old: str, new: str) -> str:
    """ABI-encode two addresses as data for AdminChanged events."""
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
    """Build a mock eth_getLogs result entry."""
    return {
        "address": address,
        "topics": [topic0] + ([topic1] if topic1 else []),
        "data": data,
        "blockNumber": block,
        "transactionHash": tx,
        "logIndex": log_index,
        "timeStamp": timestamp,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_session():
    """PostgreSQL database session with full schema.

    The session-scoped ``_migrate_test_db_once`` fixture has already brought
    the schema up; this fixture just opens a session and cleans up rows on
    teardown.
    """
    engine = create_engine(DATABASE_URL)
    session = Session(engine, expire_on_commit=False)
    try:
        yield session
    finally:
        session.rollback()
        # Clean monitoring + coverage tables (order respects FK constraints).
        # AuditContractCoverage references Contract + AuditReport + Protocol;
        # delete it before those get cascaded away via Protocol cleanup.
        for model in [
            AuditContractCoverage,
            MonitoredEvent,
            MonitoredContract,
            ProtocolSubscription,
            TvlSnapshot,
            ProxyUpgradeEvent,
            ProxySubscription,
            WatchedProxy,
            IndexedEventLog,
            IndexedEventCursor,
            # A poll/scan value-change queues a re-analysis Job (discovery
            # stage, queued). Left behind, it's claimable by an unrelated
            # claim_job in another test on the same xdist worker. FK children
            # are ON DELETE CASCADE and Job.protocol_id is SET NULL, so this
            # is order-independent among the rows below.
            Job,
            # Verdicts only SET NULL their function_id when effective_functions
            # rows go away — they never cascade, so sweep them explicitly.
            EffectVerdict,
            Contract,
            Protocol,
            # Scanner/poller passes commit durable daemon_leases rows (with a
            # live 120s TTL under a per-process holder). Clear them so warm-DB
            # reruns don't couple lease state across unrelated passes.
            DaemonLease,
        ]:
            session.query(model).delete()
        session.commit()
        session.close()
        engine.dispose()


def _add_proxy(
    session: Session,
    address: str,
    chain: str = "ethereum",
    label: str | None = None,
    last_known_impl: str | None = None,
    last_scanned_block: int = 0,
    needs_polling: bool = False,
    proxy_type: str | None = None,
) -> WatchedProxy:
    """Insert a WatchedProxy row and return it."""
    proxy = WatchedProxy(
        id=uuid.uuid4(),
        proxy_address=address,
        chain=chain,
        label=label,
        proxy_type=proxy_type,
        last_known_implementation=last_known_impl,
        last_scanned_block=last_scanned_block,
        needs_polling=needs_polling,
    )
    session.add(proxy)
    session.commit()
    return proxy


def _add_subscription(
    session: Session,
    proxy: WatchedProxy,
    discord_url: str,
    label: str | None = None,
) -> ProxySubscription:
    """Insert a ProxySubscription row and return it."""
    sub = ProxySubscription(
        id=uuid.uuid4(),
        watched_proxy_id=proxy.id,
        discord_webhook_url=discord_url,
        label=label,
    )
    session.add(sub)
    session.commit()
    return sub
