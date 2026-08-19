"""Regression guard: a resolution-time HyperSync scan can never silently walk
from genesis.

The Envio HyperSync SDK issues a getLogs scan ONLY by constructing
``hypersync.Query(...)`` then ``client.get(query)``. This test pins the
boundary so a 7th live-scan path can't reappear and 429-storm cold authority
addresses (the failure mode of the local run that motivated this fix):

  (a) the three HyperSync entry points reject an omitted ``from_block`` — a
      caller that forgets the floor fails fast instead of defaulting to 0;
  (b) a source-level scan catches any new ``.Query(`` site or any enumerator
      signature that reintroduces a ``from_block`` default;
  (c) the shared floor-or-defer helper DEFERS (returns None) on an unknown
      floor, never fails open to 0; and the missed recursive path floors when a
      floor is known and skips the live scan when it isn't.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Any, cast

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import services.resolution.creation_block_floor as floor_mod  # noqa: E402
from services.resolution import mapping_enumerator  # noqa: E402
from services.resolution.repos.event_logs_hypersync import HyperSyncEventLogRepo  # noqa: E402

_REPO = Path(__file__).resolve().parents[1]


# (a) required-arg structural guard ------------------------------------------


def test_enumerators_raise_typeerror_when_from_block_omitted():
    """The structural guard, enforced at the call boundary: omitting ``from_block``
    must raise ``TypeError`` — not silently default to a genesis (0) scan. It would
    have caught the missed recursive path (which called the enumerator with no
    ``from_block``)."""
    import asyncio

    # The omitted from_block is the point of the test; pyright correctly objects,
    # so silence it here — the runtime TypeError is what we assert.
    with pytest.raises(TypeError, match="from_block"):
        asyncio.run(mapping_enumerator.enumerate_mapping_allowlist("0x" + "aa" * 20, [], bearer_token="t"))  # pyright: ignore[reportCallIssue]
    with pytest.raises(TypeError, match="from_block"):
        asyncio.run(mapping_enumerator.enumerate_mapping_values("0x" + "aa" * 20, [], bearer_token="t"))  # pyright: ignore[reportCallIssue]
    with pytest.raises(TypeError, match="from_block"):
        HyperSyncEventLogRepo()  # pyright: ignore[reportCallIssue]


# (b) completeness grep encoded as a source assertion ------------------------

# The exhaustive set of live-HyperSync scan sites: every module that constructs
# a ``hypersync.Query(...)``. Adding a new one is fine — but it must take a
# floored ``from_block`` (resolved via resolve_scan_floor) and route the client
# through the shared bound. New modules MUST be added here deliberately.
_KNOWN_QUERY_MODULES = {
    "services/resolution/mapping_enumerator.py",
    "services/resolution/external_check_materializer.py",
    "services/resolution/predicate_evaluator.py",
    "services/resolution/repos/event_logs_hypersync.py",
}


def _live_py_files() -> list[Path]:
    out: list[Path] = []
    for sub in ("services", "workers", "routers"):
        root = _REPO / sub
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            if "test" in path.parts:
                continue
            out.append(path)
    return out


def test_no_new_hypersync_query_site_escapes_the_inventory():
    found: set[str] = set()
    for path in _live_py_files():
        src = path.read_text()
        if ".Query(" in src and ("hypersync" in src or "hypersync_module" in src):
            found.add(str(path.relative_to(_REPO)))
    new_sites = found - _KNOWN_QUERY_MODULES
    assert not new_sites, (
        f"New hypersync .Query( site(s) {sorted(new_sites)} not in the floor-or-defer inventory. "
        "Route from_block through resolve_scan_floor and register the module here."
    )


def _is_hypersync_query_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "Query"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in {"hypersync", "hypersync_module"}
    )


def _innermost_functions_building_hypersync_query(
    tree: ast.AST,
) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """The INNERMOST function that directly builds a ``hypersync.Query(...)``.

    ``ast.walk`` descends into nested ``def``s, so an outer function would falsely
    appear to "build" a query its inner ``_scan`` closure actually constructs (the
    predicate_evaluator shape). Attribute the Query to the closest enclosing
    function so the floor/defer assertions land on the real scan site, not its
    caller.
    """
    parent: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[id(child)] = node

    out: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in ast.walk(tree):
        if not _is_hypersync_query_call(node):
            continue
        cur: ast.AST | None = node
        while cur is not None and not isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            cur = parent.get(id(cur))
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)) and cur not in out:
            out.append(cur)
    return out


def _calls_named(fn: ast.AST, name: str) -> bool:
    """True if ``fn`` contains an actual ``ast.Call`` to a function named ``name``
    (a direct ``name(...)`` or ``mod.name(...)`` invocation) — NOT merely an import
    or attribute reference. This is what defeats the 'keep the import line' mutation."""
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == name:
            return True
        if isinstance(func, ast.Attribute) and func.attr == name:
            return True
    return False


def _has_is_none_defer_branch(fn: ast.AST, floor_names: set[str]) -> bool:
    """True if ``fn`` tests ``<floor_var> is None`` — the defer sentinel branch that
    skips the live scan on an unknown floor."""
    for node in ast.walk(fn):
        if not isinstance(node, ast.Compare):
            continue
        if (
            isinstance(node.left, ast.Name)
            and node.left.id in floor_names
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.Is)
            and len(node.comparators) == 1
            and isinstance(node.comparators[0], ast.Constant)
            and node.comparators[0].value is None
        ):
            return True
    return False


def _floor_assignment_targets(fn: ast.AST) -> set[str]:
    """Variable names assigned the result of a ``resolve_scan_floor(...)`` call,
    e.g. ``floor = resolve_scan_floor(...)``."""
    names: set[str] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            f = node.value.func
            is_floor = (isinstance(f, ast.Name) and f.id == "resolve_scan_floor") or (
                isinstance(f, ast.Attribute) and f.attr == "resolve_scan_floor"
            )
            if is_floor:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        names.add(tgt.id)
    return names


def _from_block_kwargs_in_query_calls(fn: ast.AST) -> list[ast.keyword]:
    out: list[ast.keyword] = []
    for node in ast.walk(fn):
        if not _is_hypersync_query_call(node):
            continue
        node = cast(ast.Call, node)
        for kw in node.keywords:
            if kw.arg == "from_block":
                out.append(kw)
    return out


def test_inline_query_sites_resolve_a_floor():
    """The two INLINE ``hypersync.Query(`` sites (the param-keyed key-word
    observation in predicate_evaluator and the external-check candidate scan) build
    their own query rather than routing through the enumerator's required
    ``from_block`` — so the required-arg guard can't protect them. Pin, STRUCTURALLY
    (not by substring), that each such function:

      (a) actually CALLs ``resolve_scan_floor`` (an ``ast.Call``, not the lingering
          import line — this defeats the 'keep the import, route a 0 into the Query'
          mutation the reviewer flagged);
      (b) has a ``floor is None`` defer/skip branch on the floored variable; and
      (c) every ``hypersync.Query(...)`` it builds binds ``from_block`` to that
          floored variable (a ``Name``) — never a literal ``0`` and never a literal
          at all.

    The enumerator/repo modules build queries from a parameter, so they're covered
    by the required-arg + AST-default guards instead and are excluded here.
    """
    inline_modules = {
        "services/resolution/predicate_evaluator.py",
        "services/resolution/external_check_materializer.py",
    }
    for rel in inline_modules:
        src = (_REPO / rel).read_text()
        tree = ast.parse(src)
        query_fns = _innermost_functions_building_hypersync_query(tree)
        assert query_fns, f"{rel}: expected an inline hypersync.Query( site; inventory drifted"
        for fn in query_fns:
            # (a) a real call, not the import line.
            assert _calls_named(fn, "resolve_scan_floor"), (
                f"{rel}:{fn.name} builds a hypersync.Query( but never CALLS resolve_scan_floor "
                "(an import alone does not float a floor) — it may genesis-scan."
            )

            floor_vars = _floor_assignment_targets(fn)
            assert floor_vars, (
                f"{rel}:{fn.name} calls resolve_scan_floor but does not bind its result to a "
                "variable used as the scan floor."
            )

            # (b) defer on the unknown-floor sentinel.
            assert _has_is_none_defer_branch(fn, floor_vars), (
                f"{rel}:{fn.name} has no `floor is None` defer branch — an unknown floor must "
                "SKIP the live scan, not fall through to a genesis walk."
            )

            # (c) the Query's from_block binds to the floored variable, never a literal.
            from_block_kwargs = _from_block_kwargs_in_query_calls(fn)
            assert from_block_kwargs, f"{rel}:{fn.name} builds a hypersync.Query( without a from_block= keyword"
            for kw in from_block_kwargs:
                assert not isinstance(kw.value, ast.Constant), (
                    f"{rel}:{fn.name} passes a LITERAL from_block to hypersync.Query( "
                    f"(value={getattr(kw.value, 'value', '?')!r}) — must bind the floored variable, "
                    "not a constant (a literal 0 is the genesis footgun)."
                )
                # The from_block must trace back to the floored variable: either the
                # floor var directly, or a loop cursor seeded from it (current_from =
                # floor). Require it to be a plain Name reference, not a call/expr.
                assert isinstance(kw.value, ast.Name), (
                    f"{rel}:{fn.name} from_block is not a simple variable reference — "
                    "cannot prove it traces to the resolved floor."
                )

    # Cross-check: the floored variable IS actually seeded from the floor. The loop
    # cursor (``current_from``) must be assigned from a floor variable somewhere in
    # the function, so a `from_block=current_from` provably traces to resolve_scan_floor.
    for rel in inline_modules:
        src = (_REPO / rel).read_text()
        tree = ast.parse(src)
        for fn in _innermost_functions_building_hypersync_query(tree):
            floor_vars = _floor_assignment_targets(fn)
            cursor_names = {
                kw.value.id for kw in _from_block_kwargs_in_query_calls(fn) if isinstance(kw.value, ast.Name)
            }
            seeded_from_floor = floor_vars & cursor_names  # from_block=floor directly
            if not seeded_from_floor:
                # Otherwise require an assignment `cursor = <floor_var>` seeding it.
                for node in ast.walk(fn):
                    if (
                        isinstance(node, ast.Assign)
                        and isinstance(node.value, ast.Name)
                        and node.value.id in floor_vars
                    ):
                        for tgt in node.targets:
                            if isinstance(tgt, ast.Name) and tgt.id in cursor_names:
                                seeded_from_floor.add(tgt.id)
            assert seeded_from_floor, (
                f"{rel}:{fn.name}: hypersync.Query from_block does not provably trace to "
                "resolve_scan_floor's result (no `cursor = floor` seed) — it could be a stray variable."
            )


def test_no_enumerator_reintroduces_a_from_block_default():
    """Parse the enumerator module and fail if any ``enumerate_*`` /
    ``__init__`` ``from_block`` regains a default — whether it is declared
    keyword-only OR positional-with-default (``def f(addr, from_block=0)``).
    Both shapes silently re-arm a genesis scan, so both are guarded."""
    for rel in ("services/resolution/mapping_enumerator.py", "services/resolution/repos/event_logs_hypersync.py"):
        tree = ast.parse((_REPO / rel).read_text())
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # keyword-only defaults align 1:1 with kwonlyargs.
            for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
                if arg.arg == "from_block":
                    assert default is None, (
                        f"{rel}:{node.name} reintroduced a keyword-only from_block default — genesis footgun"
                    )
            # positional defaults bind to the LAST len(defaults) positional args
            # (incl. posonlyargs).
            posargs = node.args.posonlyargs + node.args.args
            pos_defaults = node.args.defaults
            if pos_defaults:
                defaulted = posargs[len(posargs) - len(pos_defaults) :]
                for arg, default in zip(defaulted, pos_defaults):
                    if arg.arg == "from_block":
                        raise AssertionError(
                            f"{rel}:{node.name} reintroduced a positional from_block default "
                            f"(={ast.dump(default)}) — genesis footgun"
                        )


# (c) floor-or-defer semantics ----------------------------------------------


def test_resolve_scan_floor_never_fails_open_to_zero(monkeypatch):
    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: None)
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", lambda *_a, **_k: None)
    # Unknown floor → DEFER sentinel, never 0.
    assert floor_mod.resolve_scan_floor("0x" + "ab" * 20, 1) is None

    floor_mod.clear_scan_floor_cache()

    def _raise(*_a, **_k):
        raise RuntimeError("etherscan 429")

    monkeypatch.setattr(floor_mod, "get_contract_creation_block", _raise)
    assert floor_mod.resolve_scan_floor("0x" + "cd" * 20, 1) is None


def test_resolve_scan_floor_does_not_cache_none_permanently(monkeypatch):
    """P1.4: a DEFER (None) must not pin for the process life — once the creation block
    backfills, a later call resolves it instead of serving the stale None."""
    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_FLOOR_DEFER_TTL_S", 0.0)  # None re-resolves immediately
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: None)
    created: dict[str, int | None] = {"v": None}
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", lambda *_a, **_k: created["v"])

    addr = "0x" + "ab" * 20
    assert floor_mod.resolve_scan_floor(addr, 1) is None  # unknown → defer
    created["v"] = 9_000_000  # index backfills the creation block
    assert floor_mod.resolve_scan_floor(addr, 1) == 9_000_000 - 1  # picked up, not stale None


class _FakeSession:
    """A stand-in that satisfies the ``hasattr(session, "execute")`` live-session check;
    ``_floor_from_cursor`` is monkeypatched in these tests so ``execute`` is never reached."""

    def execute(self, *_a, **_k):
        raise AssertionError("monkeypatched _floor_from_cursor should be used, not raw execute")


def test_resolve_scan_floor_rechecks_cursor_within_ttl_with_session(monkeypatch):
    """Self-heal under the raised defer TTL: a deferring address re-reads the durable cursor
    on every call when a live session is threaded, so a cursor the indexer seeds mid-run is
    picked up at once — WITHOUT re-hitting the rate-limited Etherscan creation-block lookup."""
    floor_mod.clear_scan_floor_cache()
    cursor: dict[str, int | None] = {"v": None}  # cursor not yet seeded
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: cursor["v"])
    es_calls = {"n": 0}

    def _creation(*_a, **_k):
        es_calls["n"] += 1
        return None  # creation block unresolvable → first call defers

    monkeypatch.setattr(floor_mod, "get_contract_creation_block", _creation)

    addr = "0x" + "ab" * 20
    sess = _FakeSession()
    assert floor_mod.resolve_scan_floor(addr, 1, session=sess) is None  # defer; Etherscan consulted once
    assert es_calls["n"] == 1
    cursor["v"] = 6_000_000  # indexer backfills the cursor mid-run
    # Within the (long) defer TTL the cheap cursor re-read picks up the floor; Etherscan is NOT re-hit.
    assert floor_mod.resolve_scan_floor(addr, 1, session=sess) == 6_000_000
    assert es_calls["n"] == 1, "Etherscan must not be re-hit once the cursor self-heals"


def test_resolve_scan_floor_throttles_re_resolution_within_ttl_sessionless(monkeypatch):
    """Without a threaded session a deferring address must NOT re-resolve within the defer TTL —
    neither the cursor read (a fresh SessionLocal/Neon checkout) nor the rate-limited Etherscan
    lookup may fire on every call. This is the churn the re-tune removes."""
    floor_mod.clear_scan_floor_cache()
    cursor_calls = {"n": 0}
    es_calls = {"n": 0}

    def _cursor(*_a, **_k):
        cursor_calls["n"] += 1
        return None

    def _creation(*_a, **_k):
        es_calls["n"] += 1
        return None

    monkeypatch.setattr(floor_mod, "_floor_from_cursor", _cursor)
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", _creation)

    addr = "0x" + "cd" * 20
    assert floor_mod.resolve_scan_floor(addr, 1) is None  # call 1: full resolve
    assert (cursor_calls["n"], es_calls["n"]) == (1, 1)
    assert floor_mod.resolve_scan_floor(addr, 1) is None  # call 2: throttled, no re-resolve
    assert (cursor_calls["n"], es_calls["n"]) == (1, 1), "session-less defer must not re-probe within the TTL"


def test_resolve_scan_floor_session_recheck_still_none_throttles_etherscan(monkeypatch):
    """A threaded-session defer whose cursor is STILL None re-reads the cheap cursor every call
    but does NOT re-hit the rate-limited Etherscan lookup within the throttle window."""
    floor_mod.clear_scan_floor_cache()
    cursor_calls = {"n": 0}
    es_calls = {"n": 0}

    def _cursor(*_a, **_k):
        cursor_calls["n"] += 1
        return None

    def _creation(*_a, **_k):
        es_calls["n"] += 1
        return None

    monkeypatch.setattr(floor_mod, "_floor_from_cursor", _cursor)
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", _creation)

    sess = _FakeSession()  # has .execute; _floor_from_cursor is monkeypatched so execute is never reached
    addr = "0x" + "ef" * 20
    assert floor_mod.resolve_scan_floor(addr, 1, session=sess) is None  # call 1
    assert es_calls["n"] == 1
    assert floor_mod.resolve_scan_floor(addr, 1, session=sess) is None  # call 2: cursor re-read, Etherscan throttled
    assert cursor_calls["n"] == 2, "the cheap cursor must be re-read every call when a session is threaded"
    assert es_calls["n"] == 1, "Etherscan must stay throttled while the cursor is still None"


def test_resolve_scan_floor_caches_resolved_int_for_process_life(monkeypatch):
    """A resolved (immutable) creation-block floor is cached: a second call must not
    re-issue the creation-block lookup."""
    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: None)
    calls = {"n": 0}

    def _creation(*_a, **_k):
        calls["n"] += 1
        return 5_000_000

    monkeypatch.setattr(floor_mod, "get_contract_creation_block", _creation)
    addr = "0x" + "cd" * 20
    assert floor_mod.resolve_scan_floor(addr, 1) == 4_999_999
    assert floor_mod.resolve_scan_floor(addr, 1) == 4_999_999
    assert calls["n"] == 1  # cached, not re-probed


def test_floor_cache_size_capped(monkeypatch):
    """P1.4: the per-process floor memo is size-capped — many distinct addresses evict
    the oldest rather than growing unbounded."""
    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_FLOOR_CACHE_MAX", 8)
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: None)
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", lambda _addr, **_k: 1_000_000)
    for i in range(40):
        floor_mod.resolve_scan_floor("0x" + f"{i:040x}", 1)
    assert len(floor_mod._FLOOR_CACHE) <= 8


def _recursive_module():
    import services.resolution.recursive as recursive

    return recursive


def test_recursive_cold_no_floor_does_not_live_scan(monkeypatch):
    """The missed path (recursive replay): with a token present but no resolvable
    floor, the replay must DEFER — never invoke the live enumerator (which would
    genesis-walk a cold ACL address)."""
    recursive = _recursive_module()

    monkeypatch.setenv("ENVIO_API_TOKEN", "tok")
    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: None)
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", lambda *_a, **_k: None)

    called: dict = {"n": 0}

    def _boom(*_a, **_k):
        called["n"] += 1
        raise AssertionError("live enumerator must not run on an unknown floor")

    monkeypatch.setattr(mapping_enumerator, "enumerate_mapping_allowlist_sync", _boom)

    address = "0x" + "be" * 20
    specs = [
        {
            "event_signature": "RoleGranted(address)",
            "mapping_name": "acl",
            "direction": "add",
            "key_position": 0,
            "indexed_positions": [0],
        }
    ]
    nodes: dict = {}
    edges: dict = {}
    status = recursive._replay_mapping_principals(
        address=address,
        mapping_specs=cast(Any, specs),
        contract_node_id="contract:" + address,
        depth=0,
        nodes=nodes,
        edges=edges,
        chain_id=1,
    )
    assert called["n"] == 0
    assert status == "deferred_no_floor"


def test_recursive_known_floor_scans_from_floor_not_zero(monkeypatch):
    recursive = _recursive_module()

    monkeypatch.setenv("ENVIO_API_TOKEN", "tok")
    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "resolve_scan_floor", lambda *_a, **_k: 6_000_000)

    captured: dict = {}

    def _spy(addr, specs, **kwargs):
        captured["from_block"] = kwargs.get("from_block")
        return {"principals": [], "status": "complete", "pages_fetched": 1, "last_block_scanned": 0, "error": None}

    monkeypatch.setattr(mapping_enumerator, "enumerate_mapping_allowlist_sync", _spy)

    address = "0x" + "be" * 20
    specs = [
        {
            "event_signature": "RoleGranted(address)",
            "mapping_name": "acl",
            "direction": "add",
            "key_position": 0,
            "indexed_positions": [0],
        }
    ]
    recursive._replay_mapping_principals(
        address=address,
        mapping_specs=cast(Any, specs),
        contract_node_id="contract:" + address,
        depth=0,
        nodes={},
        edges={},
        chain_id=1,
    )
    assert captured.get("from_block") == 6_000_000


# (d) durable-cursor floor source (DB-backed) ------------------------------


def test_floor_from_cursor_reads_min_last_indexed_block(db_session):
    """The PRIMARY floor source is the durable cursor: MIN(last_indexed_block)
    across the address's cursors, a pure PG read (no Etherscan)."""
    from db.models import IndexedEventCursor

    addr = "0x" + "fe" * 20
    db_session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=addr.lower(),
            topic0="0x" + "11" * 32,
            last_indexed_block=4_200_000,
            backfill_complete=True,
        )
    )
    db_session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=addr.lower(),
            topic0="0x" + "22" * 32,
            last_indexed_block=4_100_000,
            backfill_complete=False,
        )
    )
    db_session.commit()

    floor_mod.clear_scan_floor_cache()
    assert floor_mod._floor_from_cursor(addr, 1, db_session) == 4_100_000


def test_floor_from_cursor_reuses_threaded_session_no_fresh_sessionlocal(monkeypatch):
    """Threading a live session reuses it for the cursor read; a fresh ``SessionLocal`` (the
    per-call Neon checkout the re-tune removes) must never be opened when a session is passed."""
    import db.models as dbm

    def _boom(*_a, **_k):
        raise AssertionError("must not open a fresh SessionLocal when a session is threaded")

    monkeypatch.setattr(dbm, "SessionLocal", _boom)

    class _FakeResult:
        def scalar(self):
            return 4242

    class _LiveSession:
        def execute(self, *_a, **_k):
            return _FakeResult()

    assert floor_mod._floor_from_cursor("0x" + "ab" * 20, 1, _LiveSession()) == 4242


def test_resolve_scan_floor_uses_cursor_without_etherscan(db_session, monkeypatch):
    from db.models import IndexedEventCursor

    addr = "0x" + "ef" * 20
    db_session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=addr.lower(),
            topic0="0x" + "33" * 32,
            last_indexed_block=7_777_777,
            backfill_complete=True,
        )
    )
    db_session.commit()

    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(
        floor_mod,
        "get_contract_creation_block",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("cursor floor must win, no Etherscan call")),
    )
    assert floor_mod.resolve_scan_floor(addr, 1, session=db_session) == 7_777_777


# (e) the shared client bound -----------------------------------------------


def test_build_hypersync_client_passes_bounded_retries():
    from services.resolution import hypersync_bound

    captured: dict = {}

    class _FakeModule:
        @staticmethod
        def ClientConfig(**kwargs):
            captured.update(kwargs)
            return kwargs

        @staticmethod
        def HypersyncClient(config):
            return ("client", config)

    client = hypersync_bound.build_hypersync_client(_FakeModule, url="https://eth.hypersync.xyz", bearer_token="tok")
    assert client[0] == "client"
    assert isinstance(captured.get("max_num_retries"), int)


def test_build_hypersync_client_falls_back_without_retry_support():
    from services.resolution import hypersync_bound

    class _OldModule:
        @staticmethod
        def ClientConfig(**kwargs):
            if "max_num_retries" in kwargs:
                raise TypeError("unexpected keyword max_num_retries")
            return kwargs

        @staticmethod
        def HypersyncClient(config):
            return config

    cfg = hypersync_bound.build_hypersync_client(_OldModule, url="u", bearer_token="t")
    assert "max_num_retries" not in cfg


def test_enumerator_constructs_client_through_the_bound():
    """When no client is injected, the enumerator builds its HyperSync client via
    the shared bound (max_num_retries set) — not a bare ClientConfig."""
    import asyncio

    captured: dict = {}

    class _FakeClient:
        async def get(self, _query):
            from types import SimpleNamespace

            return SimpleNamespace(data=[], next_block=None)

    class _FakeFieldEnumMeta(type):
        def __iter__(cls):
            yield cls("topic0")

    class _FakeField(metaclass=_FakeFieldEnumMeta):
        def __init__(self, name):
            self.value = name

    from types import SimpleNamespace

    class _FakeModule:
        Query = SimpleNamespace
        LogSelection = SimpleNamespace
        FieldSelection = SimpleNamespace
        LogField = _FakeField

        @staticmethod
        def ClientConfig(**kwargs):
            captured.update(kwargs)
            return kwargs

        @staticmethod
        def HypersyncClient(_config):
            return _FakeClient()

    spec = {
        "event_signature": "Rely(address)",
        "mapping_name": "wards",
        "event_name": "Rely",
        "direction": "add",
        "key_position": 0,
        "indexed_positions": [0],
    }
    result = asyncio.run(
        mapping_enumerator.enumerate_mapping_allowlist(
            "0x" + "aa" * 20,
            [spec],  # pyright: ignore[reportArgumentType]
            from_block=5_000_000,
            bearer_token="tok",
            hypersync_module=_FakeModule(),
        )
    )
    assert result["status"] == "complete"
    assert isinstance(captured.get("max_num_retries"), int)  # routed through the bound


def test_hypersync_slot_is_a_per_token_semaphore():
    from services.resolution import hypersync_bound

    entered = []
    with hypersync_bound.hypersync_slot("tok-a"):
        entered.append("a")
    assert entered == ["a"]
    # Same token reuses one bounded semaphore instance.
    assert hypersync_bound._semaphore_for("tok-a") is hypersync_bound._semaphore_for("tok-a")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
