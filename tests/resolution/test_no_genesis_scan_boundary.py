"""No resolution-time HyperSync scan may silently walk from genesis: enumerators reject an omitted ``from_block``, a
source scan catches any new ``.Query(`` site, and the floor helper defers rather than failing open to 0.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, cast

import pytest

import services.resolution.creation_block_floor as floor_mod
from services.resolution import mapping_enumerator

_REPO = Path(__file__).resolve().parents[2]
_CREATION = "creation_block_minus_one"


def test_enumerators_raise_typeerror_when_from_block_omitted():
    """It would have caught the missed recursive path."""
    import asyncio

    # The runtime TypeError is what's asserted.
    with pytest.raises(TypeError, match="from_block"):
        asyncio.run(mapping_enumerator.enumerate_mapping_allowlist("0x" + "aa" * 20, [], bearer_token="t"))  # pyright: ignore[reportCallIssue]
    with pytest.raises(TypeError, match="from_block"):
        asyncio.run(mapping_enumerator.enumerate_mapping_values("0x" + "aa" * 20, [], bearer_token="t"))  # pyright: ignore[reportCallIssue]


# A new scan site must take a floored ``from_block`` and the shared client bound; add it here deliberately.
_KNOWN_QUERY_MODULES = {
    "services/resolution/mapping_enumerator.py",
    "services/resolution/external_check_materializer.py",
    "services/resolution/predicate_evaluator/membership.py",
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
    """``ast.walk`` descends into nested defs, so an outer function would falsely appear to build its closure's
    query.
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
    """Defeats the "keep the import line" mutation."""
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
    """The two inline Query sites bypass the enumerator's required arg, so each must call ``resolve_scan_floor``,
    defer on None, and bind every ``from_block`` to the floored variable.
    """
    inline_modules = {
        "services/resolution/predicate_evaluator/membership.py",
        "services/resolution/external_check_materializer.py",
    }
    for rel in inline_modules:
        src = (_REPO / rel).read_text()
        tree = ast.parse(src)
        query_fns = _innermost_functions_building_hypersync_query(tree)
        assert query_fns, f"{rel}: expected an inline hypersync.Query( site; inventory drifted"
        for fn in query_fns:
            assert _calls_named(fn, "resolve_scan_floor"), (
                f"{rel}:{fn.name} builds a hypersync.Query( but never CALLS resolve_scan_floor "
                "(an import alone does not float a floor) — it may genesis-scan."
            )

            floor_vars = _floor_assignment_targets(fn)
            assert floor_vars, (
                f"{rel}:{fn.name} calls resolve_scan_floor but does not bind its result to a "
                "variable used as the scan floor."
            )

            assert _has_is_none_defer_branch(fn, floor_vars), (
                f"{rel}:{fn.name} has no `floor is None` defer branch — an unknown floor must "
                "SKIP the live scan, not fall through to a genesis walk."
            )

            from_block_kwargs = _from_block_kwargs_in_query_calls(fn)
            assert from_block_kwargs, f"{rel}:{fn.name} builds a hypersync.Query( without a from_block= keyword"
            for kw in from_block_kwargs:
                assert not isinstance(kw.value, ast.Constant), (
                    f"{rel}:{fn.name} passes a LITERAL from_block to hypersync.Query( "
                    f"(value={getattr(kw.value, 'value', '?')!r}) — must bind the floored variable, "
                    "not a constant (a literal 0 is the genesis footgun)."
                )
                assert isinstance(kw.value, ast.Name), (
                    f"{rel}:{fn.name} from_block is not a simple variable reference — "
                    "cannot prove it traces to the resolved floor."
                )

    # So ``from_block=current_from`` provably traces to resolve_scan_floor.
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


def test_resolve_scan_floor_never_fails_open_to_zero(monkeypatch):
    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: None)
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", lambda *_a, **_k: None)
    assert floor_mod.resolve_scan_floor("0x" + "ab" * 20, 1) is None

    floor_mod.clear_scan_floor_cache()

    def _raise(*_a, **_k):
        raise RuntimeError("etherscan 429")

    monkeypatch.setattr(floor_mod, "get_contract_creation_block", _raise)
    assert floor_mod.resolve_scan_floor("0x" + "cd" * 20, 1) is None


def test_resolve_scan_floor_does_not_cache_none_permanently(monkeypatch):
    """A DEFER (None) must not pin for the process life — once the creation block
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
    """``_floor_from_cursor`` is monkeypatched, so ``execute`` is never reached."""

    def execute(self, *_a, **_k):
        raise AssertionError("monkeypatched _floor_from_cursor should be used, not raw execute")


def test_resolve_scan_floor_rechecks_cursor_within_ttl_with_session(monkeypatch):
    """A mid-run cursor is picked up without re-hitting the rate-limited Etherscan lookup."""
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
    assert floor_mod.resolve_scan_floor(addr, 1, session=sess) == 6_000_000
    assert es_calls["n"] == 1, "Etherscan must not be re-hit once the cursor self-heals"


def test_resolve_scan_floor_throttles_re_resolution_within_ttl_sessionless(monkeypatch):
    """Without a session a deferring address must not re-resolve within the TTL."""
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
    """The per-process floor memo is size-capped — many distinct addresses evict
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
    """The live enumerator would genesis-walk a cold ACL address."""
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


def _witnessed_cursor(address: str, topic0: str, *, last: int, first: int | None, basis: str | None):
    from db.models import IndexedEventCursor

    return IndexedEventCursor(
        chain_id=1,
        event_address=address.lower(),
        topic0=topic0,
        last_indexed_block=last,
        backfill_complete=True,
        first_indexed_block=first,
        first_indexed_block_basis=basis,
    )


class _EtherscanSpy:
    """A creation lookup that would produce a floor; the resolver swallows lookup errors, so a raising stub couldn't
    tell a deferral from a fallback."""

    def __init__(self, created: int = 1_000_000) -> None:
        self.created = created
        self.calls: list[str] = []

    def __call__(self, address, **_k):
        self.calls.append(address)
        return self.created


def _no_etherscan(monkeypatch) -> _EtherscanSpy:
    spy = _EtherscanSpy()
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", spy)
    return spy


def test_floor_from_cursor_reads_min_witnessed_first_indexed_block(db_session):
    """The floor is the witnessed deploy block, MIN(first_indexed_block) over creation-witnessed cursors; a
    cursor's frontier (last_indexed_block) is never a floor."""
    addr = "0x" + "fe" * 20
    db_session.add(_witnessed_cursor(addr, "0x" + "11" * 32, last=26_000_000, first=4_200_000, basis=_CREATION))
    db_session.add(_witnessed_cursor(addr, "0x" + "22" * 32, last=4_050_000, first=4_100_000, basis=_CREATION))
    db_session.commit()

    floor_mod.clear_scan_floor_cache()
    assert floor_mod._floor_from_cursor(addr, 1, db_session) == 4_100_000


def test_advanced_cursor_yields_the_deploy_floor_not_its_frontier(db_session, monkeypatch):
    addr = "0x70a64840" + "00" * 16
    db_session.add(_witnessed_cursor(addr, "0x" + "44" * 32, last=25_932_421, first=21_238_973, basis=_CREATION))
    db_session.commit()
    floor_mod.clear_scan_floor_cache()
    etherscan = _no_etherscan(monkeypatch)
    assert floor_mod.resolve_scan_floor_with_basis(addr, 1, session=db_session) == (21_238_973, "cursor_first_indexed")
    assert etherscan.calls == []


def test_floor_from_cursor_reuses_threaded_session_no_fresh_sessionlocal(monkeypatch):
    """Threading a live session reuses it for the witness read; a fresh ``SessionLocal`` (the
    per-call Neon checkout the re-tune removes) must never be opened when a session is passed."""
    import db.models as dbm

    def _boom(*_a, **_k):
        raise AssertionError("must not open a fresh SessionLocal when a session is threaded")

    monkeypatch.setattr(dbm, "SessionLocal", _boom)

    class _FakeResult:
        def first(self):
            return None

        def one(self):
            return (4242, 0)

    class _LiveSession:
        def execute(self, *_a, **_k):
            return _FakeResult()

    assert floor_mod._floor_from_cursor("0x" + "ab" * 20, 1, _LiveSession()) == 4242


def test_resolve_scan_floor_uses_cursor_without_etherscan(db_session, monkeypatch):
    addr = "0x" + "ef" * 20
    db_session.add(_witnessed_cursor(addr, "0x" + "33" * 32, last=7_777_777, first=6_000_000, basis=_CREATION))
    db_session.commit()

    floor_mod.clear_scan_floor_cache()
    etherscan = _no_etherscan(monkeypatch)
    assert floor_mod.resolve_scan_floor(addr, 1, session=db_session) == 6_000_000
    assert etherscan.calls == []


def test_witness_table_wins_over_cursors(db_session, monkeypatch):
    from db.floor_witnesses import WITNESS_PRIOR_INCARNATION, WITNESS_PROVEN, record_floor_witness

    proven = "0x" + "a1" * 20
    refuted = "0x" + "a2" * 20
    for addr in (proven, refuted):
        db_session.add(_witnessed_cursor(addr, "0x" + "55" * 32, last=9_000_000, first=5_000_000, basis=_CREATION))
    record_floor_witness(db_session, chain_id=1, address=proven, outcome=WITNESS_PROVEN, first_indexed_block=4_000_000)
    record_floor_witness(db_session, chain_id=1, address=refuted, outcome=WITNESS_PRIOR_INCARNATION)
    db_session.commit()
    floor_mod.clear_scan_floor_cache()
    etherscan = _no_etherscan(monkeypatch)
    assert floor_mod.resolve_scan_floor(proven, 1, session=db_session) == 4_000_000
    assert floor_mod.resolve_scan_floor(refuted, 1, session=db_session) is None
    assert etherscan.calls == []


def test_attempted_and_failed_witness_defers_without_etherscan(db_session, monkeypatch):
    addr = "0x" + "a3" * 20
    db_session.add(_witnessed_cursor(addr, "0x" + "66" * 32, last=9_000_000, first=None, basis="not_determined"))
    db_session.commit()
    floor_mod.clear_scan_floor_cache()
    etherscan = _no_etherscan(monkeypatch)
    assert floor_mod.resolve_scan_floor_with_basis(addr, 1, session=db_session) == (None, None)
    assert etherscan.calls == []


def test_witnessed_cursor_outranks_an_unwitnessed_sibling(db_session, monkeypatch):
    """A restaking cursor enrolled before its witness existed sits beside witnessed hint cursors; the proven floor
    stands."""
    addr = "0x8b71140ad2e5d1e7018d2a7f8a288bd3cd38916f"
    db_session.add(_witnessed_cursor(addr, "0x" + "77" * 32, last=9_000_000, first=None, basis="not_determined"))
    db_session.add(_witnessed_cursor(addr, "0x" + "88" * 32, last=9_000_000, first=17_174_452, basis=_CREATION))
    db_session.commit()
    floor_mod.clear_scan_floor_cache()
    etherscan = _no_etherscan(monkeypatch)
    assert floor_mod.resolve_scan_floor(addr, 1, session=db_session) == 17_174_452
    assert etherscan.calls == []


def test_never_witnessed_address_uses_the_creation_lookup(db_session, monkeypatch):
    unwitnessed_cursor = "0x" + "a4" * 20
    no_cursor = "0x" + "a5" * 20
    db_session.add(_witnessed_cursor(unwitnessed_cursor, "0x" + "99" * 32, last=9_000_000, first=None, basis=None))
    db_session.commit()
    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", lambda *_a, **_k: 3_000_000)
    for addr in (unwitnessed_cursor, no_cursor):
        assert floor_mod.resolve_scan_floor_with_basis(addr, 1, session=db_session) == (
            2_999_999,
            "creation_block_lookup",
        )


def test_unreadable_witness_defers(monkeypatch):
    class _BrokenSession:
        def execute(self, *_a, **_k):
            raise RuntimeError("connection reset")

    floor_mod.clear_scan_floor_cache()
    etherscan = _no_etherscan(monkeypatch)
    assert floor_mod.resolve_scan_floor("0x" + "a6" * 20, 1, session=_BrokenSession()) is None
    assert etherscan.calls == []


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


def test_a_witness_recorded_after_an_etherscan_floor_wins(db_session, monkeypatch):
    from db.floor_witnesses import WITNESS_PRIOR_INCARNATION, WITNESS_PROVEN, record_floor_witness

    refuted = "0x" + "a7" * 20
    proven = "0x" + "a8" * 20
    floor_mod.clear_scan_floor_cache()
    etherscan = _no_etherscan(monkeypatch)
    for addr in (refuted, proven):
        assert floor_mod.resolve_scan_floor_with_basis(addr, 1, session=db_session) == (
            999_999,
            "creation_block_lookup",
        )
    record_floor_witness(db_session, chain_id=1, address=refuted, outcome=WITNESS_PRIOR_INCARNATION)
    record_floor_witness(db_session, chain_id=1, address=proven, outcome=WITNESS_PROVEN, first_indexed_block=900_000)
    db_session.commit()

    assert floor_mod.resolve_scan_floor_with_basis(refuted, 1, session=db_session) == (None, None)
    assert floor_mod.resolve_scan_floor_with_basis(proven, 1, session=db_session) == (900_000, "cursor_first_indexed")
    assert len(etherscan.calls) == 2


def test_a_sessionless_etherscan_floor_is_rechecked_against_the_witness(monkeypatch):
    floor_mod.clear_scan_floor_cache()
    witness: dict[str, Any] = {"v": None}
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: witness["v"])
    etherscan = _no_etherscan(monkeypatch)
    addr = "0x" + "a9" * 20
    assert floor_mod.resolve_scan_floor(addr, 1) == 999_999
    witness["v"] = "defer"
    assert floor_mod.resolve_scan_floor(addr, 1) is None
    assert len(etherscan.calls) == 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
