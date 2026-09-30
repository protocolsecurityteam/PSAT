"""FA-R2b: the value fold on EtherFiNodesManager reads the durable Postgres index, so it issues no live request; a
spy on the live path asserts zero calls. Event shapes mirror the audited run on ``0x8b71140a…``.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

import services.resolution.mapping_enumerator as mapping_enumerator
from db.models import IndexedEventCursor, IndexedEventLog
from services.resolution.adapters import EvaluationContext
from services.resolution.adapters.event_indexed import EventIndexedAdapter
from services.resolution.repos.event_logs_pg import PostgresEventLogRepo
from tests.conftest import requires_postgres

pytestmark = requires_postgres

# The empty proxy 0x789cbbe0 has no events.
STATE_HOLDER = "0x8b71140ad2e5d1e7018d2a7f8a288bd3cd38916f"
CALLER_A = "0x7835fb36a8143a014a2c381363cd1a4dee586d2a"
CALLER_B = "0xcd425f44758a08baab3c4908f3e3de5776e45d7a"
RESOLUTION_BLOCK = 25389671

_EIG_SIG = "UserAllowedForwardedEigenpodCallsUpdated(address,bytes4,bool)"
_EXT_SIG = "UserAllowedForwardedExternalCallsUpdated(address,bytes4,address,bool)"
EIG_TOPIC0 = mapping_enumerator._event_topic0(_EIG_SIG)
EXT_TOPIC0 = mapping_enumerator._event_topic0(_EXT_SIG)


def _word(addr_or_hex: str) -> str:
    return "0x" + addr_or_hex[2:].rjust(64, "0")


def _selector_word(selector: str) -> str:
    return "0x" + selector[2:].ljust(64, "0")


def _bool_word(value: bool) -> str:
    return "0x" + ("1".rjust(64, "0") if value else "0" * 64)


def _eig_log(caller: str, selector: str, value: bool, *, block: int, tx_index: int, log_index: int) -> IndexedEventLog:
    return IndexedEventLog(
        chain_id=1,
        event_address=STATE_HOLDER,
        topic0=EIG_TOPIC0,
        tx_hash=block.to_bytes(8, "big").rjust(32, b"\x00"),
        log_index=log_index,
        block_number=block,
        block_hash=block.to_bytes(8, "big").rjust(32, b"\x11"),
        transaction_index=tx_index,
        topics=[EIG_TOPIC0, _word(caller), _selector_word(selector)],
        data_words=[_bool_word(value)],
    )


def _ext_log(
    caller: str, selector: str, target: str, value: bool, *, block: int, tx_index: int, log_index: int
) -> IndexedEventLog:
    return IndexedEventLog(
        chain_id=1,
        event_address=STATE_HOLDER,
        topic0=EXT_TOPIC0,
        tx_hash=(block * 100 + log_index).to_bytes(8, "big").rjust(32, b"\x00"),
        log_index=log_index,
        block_number=block,
        block_hash=block.to_bytes(8, "big").rjust(32, b"\x22"),
        transaction_index=tx_index,
        topics=[EXT_TOPIC0, _word(caller), _selector_word(selector), _word(target)],
        data_words=[_bool_word(value)],
    )


def _cursor(topic0: str, *, last_block: int, complete: bool) -> IndexedEventCursor:
    return IndexedEventCursor(
        chain_id=1,
        event_address=STATE_HOLDER,
        topic0=topic0,
        last_indexed_block=last_block,
        backfill_complete=complete,
        first_indexed_block=0,
        first_indexed_block_basis="creation_block_minus_one",
    )


def _eigenpod_descriptor() -> dict:
    return {
        "kind": "mapping_membership",
        "storage_var": "allowedForwardedEigenpodCalls",
        "key_sources": [
            {"source": "msg_sender"},
            {"source": "parameter", "parameter_index": 1, "parameter_name": "selector"},
        ],
        "enumeration_hint": [
            {
                "topic0": EIG_TOPIC0,
                "topics_to_keys": {"1": 0, "2": 1},
                "data_to_keys": {},
                "direction": "set",
                "event_signature": _EIG_SIG,
                "event_name": "UserAllowedForwardedEigenpodCallsUpdated",
                "mapping_name": "allowedForwardedEigenpodCalls",
                "key_position": 1,
                "indexed_positions": [0, 1],
                "value_position": 2,
                "writer_function": "updateAllowedForwardedEigenpodCalls(address,bytes4,bool)",
            }
        ],
    }


def _external_descriptor() -> dict:
    return {
        "kind": "mapping_membership",
        "storage_var": "allowedForwardedExternalCalls",
        "key_sources": [
            {"source": "msg_sender"},
            {"source": "parameter", "parameter_index": 1, "parameter_name": "selector"},
            {"source": "parameter", "parameter_index": 2, "parameter_name": "target"},
        ],
        "enumeration_hint": [
            {
                "topic0": EXT_TOPIC0,
                "topics_to_keys": {"1": 0, "2": 1, "3": 2},
                "data_to_keys": {},
                "direction": "set",
                "event_signature": _EXT_SIG,
                "event_name": "UserAllowedForwardedExternalCallsUpdated",
                "mapping_name": "allowedForwardedExternalCalls",
                "key_position": 2,
                "indexed_positions": [0, 1, 2],
                "value_position": 3,
                "writer_function": "updateAllowedForwardedExternalCalls(address,bytes4,address,bool)",
            }
        ],
    }


@pytest.fixture(autouse=True)
def _stub_creation_block_floor(monkeypatch):
    """Tests of a specific floor or the defer path re-stub ``resolve_scan_floor``."""
    import services.resolution.creation_block_floor as floor_mod

    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "resolve_scan_floor_with_basis", lambda *_a, **_k: (0, "creation_block_lookup"))


@pytest.fixture
def no_live_calls(monkeypatch):
    calls: list[tuple] = []
    orig = mapping_enumerator.enumerate_mapping_values_sync

    def spy(*args, **kwargs):
        calls.append((args, kwargs))
        return orig(*args, **kwargs)

    monkeypatch.setattr(mapping_enumerator, "enumerate_mapping_values_sync", spy)
    return calls


def _seed(session, rows, cursors):
    for cursor in cursors:
        session.add(cursor)
    for row in rows:
        session.add(row)
    session.flush()


def test_durable_value_fold_recovers_single_eigenpod_caller(db_session, no_live_calls):
    rows = [
        _eig_log(CALLER_A, "0x88676cad", True, block=23591216, tx_index=0, log_index=146),
        _eig_log(CALLER_A, "0xf074ba62", True, block=23591216, tx_index=0, log_index=148),
        _eig_log(CALLER_A, "0x3f65cf19", True, block=23591216, tx_index=0, log_index=150),
    ]
    _seed(db_session, rows, [_cursor(EIG_TOPIC0, last_block=25389740, complete=True)])

    ctx = EvaluationContext(
        chain_id=1,
        contract_address=STATE_HOLDER,
        block=RESOLUTION_BLOCK,
        event_log_repo=PostgresEventLogRepo(db_session),
    )
    cap = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)

    assert cap.kind == "finite_set"
    assert cap.membership_quality == "exact"
    assert sorted(cap.members or []) == [CALLER_A.lower()]
    assert no_live_calls == []


def test_durable_value_fold_recovers_two_external_callers(db_session, no_live_calls):
    rows = [
        _ext_log(
            CALLER_A,
            "0x3ccc861d",
            "0x7750d328b314effa365a0402ccfd489b80b0adda",
            True,
            block=23591216,
            tx_index=0,
            log_index=144,
        ),
        _ext_log(
            CALLER_B,
            "0xeea9064b",
            "0x39053d51b77dc0d36036fc1fcc8cb819df8ef37a",
            True,
            block=24047816,
            tx_index=0,
            log_index=680,
        ),
    ]
    _seed(db_session, rows, [_cursor(EXT_TOPIC0, last_block=25389740, complete=True)])

    ctx = EvaluationContext(
        chain_id=1,
        contract_address=STATE_HOLDER,
        block=RESOLUTION_BLOCK,
        event_log_repo=PostgresEventLogRepo(db_session),
    )
    cap = EventIndexedAdapter().enumerate(_external_descriptor(), ctx)

    assert cap.kind == "finite_set"
    assert cap.membership_quality == "exact"
    assert sorted(cap.members or []) == sorted([CALLER_A.lower(), CALLER_B.lower()])
    assert no_live_calls == []


def test_durable_value_fold_drops_caller_whose_latest_value_is_false(db_session, no_live_calls):
    # The fold can only add real members, never open the function.
    rows = [
        _eig_log(CALLER_A, "0x88676cad", True, block=100, tx_index=0, log_index=0),
        _eig_log(CALLER_A, "0x88676cad", False, block=200, tx_index=0, log_index=0),
    ]
    _seed(db_session, rows, [_cursor(EIG_TOPIC0, last_block=25389740, complete=True)])

    ctx = EvaluationContext(
        chain_id=1,
        contract_address=STATE_HOLDER,
        block=RESOLUTION_BLOCK,
        event_log_repo=PostgresEventLogRepo(db_session),
    )
    cap = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)

    assert cap.kind == "finite_set"
    assert (cap.members or []) == []
    assert no_live_calls == []


def test_durable_value_fold_respects_resolution_block(db_session, no_live_calls):
    rows = [
        _eig_log(CALLER_A, "0x88676cad", True, block=RESOLUTION_BLOCK + 1000, tx_index=0, log_index=0),
    ]
    _seed(db_session, rows, [_cursor(EIG_TOPIC0, last_block=25389740, complete=True)])

    ctx = EvaluationContext(
        chain_id=1,
        contract_address=STATE_HOLDER,
        block=RESOLUTION_BLOCK,
        event_log_repo=PostgresEventLogRepo(db_session),
    )
    cap = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)

    assert cap.kind == "finite_set"
    assert (cap.members or []) == []
    assert no_live_calls == []


def test_cold_durable_index_with_rows_defers_pending_index(db_session, no_live_calls):
    # A cold cursor is incomplete by definition, so it defers without scanning even when rows exist.
    rows = [
        _eig_log(CALLER_A, "0x88676cad", True, block=23591216, tx_index=0, log_index=146),
    ]
    _seed(db_session, rows, [_cursor(EIG_TOPIC0, last_block=23600000, complete=False)])

    ctx = EvaluationContext(
        chain_id=1,
        contract_address=STATE_HOLDER,
        block=RESOLUTION_BLOCK,
        event_log_repo=PostgresEventLogRepo(db_session),
    )
    cap = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)

    assert cap.kind == "external_check_only"
    assert cap.check is not None
    assert cap.check.extra.get("deferred_pending_index") is True
    assert cap.check.extra.get("basis") == ["no_index_cursor", "caller_keyed_membership_allowlist"]
    assert cap.check.target_address == STATE_HOLDER
    assert no_live_calls == []


@pytest.fixture
def iter_rows_spy(monkeypatch):
    calls: list[dict] = []
    orig = PostgresEventLogRepo.iter_event_rows

    def spy(self, **kwargs):
        calls.append(kwargs)
        return orig(self, **kwargs)

    monkeypatch.setattr(PostgresEventLogRepo, "iter_event_rows", spy)
    return calls


def test_cold_durable_index_performs_zero_row_scans(db_session, no_live_calls, iter_rows_spy):
    _seed(db_session, [], [_cursor(EIG_TOPIC0, last_block=23600000, complete=False)])

    ctx = EvaluationContext(
        chain_id=1,
        contract_address=STATE_HOLDER,
        block=RESOLUTION_BLOCK,
        event_log_repo=PostgresEventLogRepo(db_session),
    )
    cap = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)

    assert cap.kind == "external_check_only"
    assert cap.check is not None
    assert cap.check.extra.get("deferred_pending_index") is True
    assert iter_rows_spy == []  # the wasted scan is skipped on cold
    assert no_live_calls == []


def test_no_cursor_at_all_performs_zero_row_scans(db_session, no_live_calls, iter_rows_spy):
    # The audited run wasted this scan on every caller-keyed-ACL function.
    ctx = EvaluationContext(
        chain_id=1,
        contract_address=STATE_HOLDER,
        block=RESOLUTION_BLOCK,
        event_log_repo=PostgresEventLogRepo(db_session),
    )
    cap = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)

    assert cap.kind == "external_check_only"
    assert cap.check is not None
    assert cap.check.extra.get("deferred_pending_index") is True
    assert iter_rows_spy == []
    assert no_live_calls == []


def test_warm_durable_index_still_scans_rows(db_session, no_live_calls, iter_rows_spy):
    rows = [_eig_log(CALLER_A, "0x88676cad", True, block=23591216, tx_index=0, log_index=146)]
    _seed(db_session, rows, [_cursor(EIG_TOPIC0, last_block=25389740, complete=True)])

    ctx = EvaluationContext(
        chain_id=1,
        contract_address=STATE_HOLDER,
        block=RESOLUTION_BLOCK,
        event_log_repo=PostgresEventLogRepo(db_session),
    )
    cap = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)

    assert cap.kind == "finite_set"
    assert cap.membership_quality == "exact"
    assert sorted(cap.members or []) == [CALLER_A.lower()]
    assert len(iter_rows_spy) == 1  # warm path scans exactly once
    assert no_live_calls == []


def test_cold_defer_projects_identically_to_unsupported_leaf(db_session, no_live_calls):
    # The cold deferral projects the same public/gated verdict as the unsupported leaf it replaces.
    from services.policy.capability_surface import project_capability_surface
    from services.resolution.capabilities import CapabilityExpr, Condition
    from services.resolution.capability_resolver import capability_to_dict

    ctx = EvaluationContext(
        chain_id=1,
        contract_address=STATE_HOLDER,
        block=RESOLUTION_BLOCK,
        event_log_repo=PostgresEventLogRepo(db_session),
    )
    defer = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)
    assert defer.kind == "external_check_only"
    public = CapabilityExpr.conditional_universal(Condition(kind="business", description="open sibling"))
    unsupported = CapabilityExpr.unsupported("mapping_value_scan_failed")

    def pub(cap) -> bool:
        return project_capability_surface(capability_to_dict(cap)).authority_public

    assert pub(CapabilityExpr.structural_and([defer, public])) is False
    assert pub(CapabilityExpr.structural_and([unsupported, public])) is False
    assert pub(CapabilityExpr.structural_or([defer, public])) == pub(
        CapabilityExpr.structural_or([unsupported, public])
    )
    assert no_live_calls == []


def test_structural_absent_repo_without_fold_event_values_falls_through_to_live(db_session, monkeypatch):
    # A repo without ``fold_event_values`` is structurally absent, not cold, so the live replay still runs.
    monkeypatch.delenv("ENVIO_API_TOKEN", raising=False)

    class _NoValueFoldRepo:
        def fold_event_history(self, **_kwargs):
            raise AssertionError("value path must not reach the add/remove fold")

    ctx = EvaluationContext(
        chain_id=1,
        contract_address=STATE_HOLDER,
        block=RESOLUTION_BLOCK,
        event_log_repo=cast(Any, _NoValueFoldRepo()),
    )
    cap = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)

    assert cap.kind == "unsupported"
    assert "mapping_value_scan_failed" in (cap.unsupported_reason or "")


def test_structural_absent_no_repo_falls_through_to_live(monkeypatch):
    monkeypatch.delenv("ENVIO_API_TOKEN", raising=False)
    ctx = EvaluationContext(chain_id=1, contract_address=STATE_HOLDER, block=RESOLUTION_BLOCK)
    cap = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)

    assert cap.kind == "unsupported"
    assert "mapping_value_scan_failed" in (cap.unsupported_reason or "")


def test_zero_event_address_does_not_defer_forever(db_session, monkeypatch):
    # A zero address never gets a cursor, so deferring would wait forever.
    monkeypatch.delenv("ENVIO_API_TOKEN", raising=False)
    desc = _eigenpod_descriptor()
    desc["enumeration_hint"][0]["event_address"] = "0x" + "0" * 40
    ctx = EvaluationContext(
        chain_id=1,
        contract_address=STATE_HOLDER,
        block=RESOLUTION_BLOCK,
        event_log_repo=PostgresEventLogRepo(db_session),
    )
    cap = EventIndexedAdapter().enumerate(desc, ctx)

    assert cap.kind == "unsupported"
    assert "mapping_value_scan_failed" in (cap.unsupported_reason or "")


def test_fold_repo_error_falls_through_to_live(monkeypatch):
    monkeypatch.delenv("ENVIO_API_TOKEN", raising=False)

    class _RaisingRepo:
        def fold_event_values(self, **_kwargs):
            raise RuntimeError("backend down")

    ctx = EvaluationContext(
        chain_id=1,
        contract_address=STATE_HOLDER,
        block=RESOLUTION_BLOCK,
        event_log_repo=cast(Any, _RaisingRepo()),
    )
    cap = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)

    assert cap.kind == "unsupported"
    assert "mapping_value_scan_failed" in (cap.unsupported_reason or "")


def test_non_cold_partial_reason_falls_through_to_live_not_defer(monkeypatch):
    # The defer discriminator is strictly ``no_index_cursor``.
    monkeypatch.delenv("ENVIO_API_TOKEN", raising=False)
    from services.resolution.repos.event_logs_pg import ValueFoldResult

    class _UnresolvedKeyRepo:
        def fold_event_values(self, **_kwargs):
            return ValueFoldResult(entries=[], complete=False, partial_reason="unresolved_event_key")

    ctx = EvaluationContext(
        chain_id=1,
        contract_address=STATE_HOLDER,
        block=RESOLUTION_BLOCK,
        event_log_repo=cast(Any, _UnresolvedKeyRepo()),
    )
    cap = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)

    assert cap.kind == "unsupported"
    assert "mapping_value_scan_failed" in (cap.unsupported_reason or "")


def test_durable_and_tree_recovers_membership_keeps_hasrole_external_and_not_public(db_session, no_live_calls):
    # The hasRole sibling stays external_check_only, so the AND is not opened.
    from services.resolution.adapters import AdapterRegistry
    from services.resolution.predicate_evaluator import evaluate_tree_with_registry

    rows = [_eig_log(CALLER_A, "0x88676cad", True, block=23591216, tx_index=0, log_index=146)]
    _seed(db_session, rows, [_cursor(EIG_TOPIC0, last_block=25389740, complete=True)])

    tree = {
        "op": "AND",
        "children": [
            {
                "op": "LEAF",
                "leaf": {
                    "kind": "membership",
                    "operator": "truthy",
                    "authority_role": "caller_authority",
                    "operands": [{"source": "msg_sender"}],
                    "set_descriptor": _eigenpod_descriptor(),
                },
            },
            {
                "op": "LEAF",
                "leaf": {
                    "kind": "external_bool",
                    "operator": "truthy",
                    "authority_role": "delegated_authority",
                    "callee_state_mutability": "view",
                    "callee_signature": "hasRole(bytes32,address)",
                    "expression": "hasRole(...)",
                    "operands": [{"source": "msg_sender"}],
                    "set_descriptor": {
                        "kind": "external_set",
                        "key_sources": [{"source": "msg_sender"}],
                        "authority_contract": {
                            "address_source": {"source": "state_variable", "state_variable_name": "roleRegistry"}
                        },
                        "callee_function": "hasRole",
                        "callee_signature": "hasRole(bytes32,address)",
                        "callee_selector": "0x91d14854",
                    },
                },
            },
        ],
    }
    registry = AdapterRegistry()
    registry.register(EventIndexedAdapter)
    cap = evaluate_tree_with_registry(
        cast(Any, tree),
        registry,
        EvaluationContext(
            chain_id=1,
            contract_address=STATE_HOLDER,
            block=RESOLUTION_BLOCK,
            event_log_repo=PostgresEventLogRepo(db_session),
        ),
    )

    assert cap.kind == "AND"
    children = cap.children or []
    finite = [c for c in children if c.kind == "finite_set"]
    external = [c for c in children if c.kind == "external_check_only"]
    assert len(finite) == 1
    assert sorted(finite[0].members or []) == [CALLER_A.lower()]
    assert len(external) == 1
    assert external[0].check is not None
    assert external[0].check.extra.get("callee_signature") == "hasRole(bytes32,address)"
    assert cap.unsupported_reason is None
    assert no_live_calls == []


_OWNERSET_SIG = "OwnerSet(address,uint256)"
OWNERSET_TOPIC0 = mapping_enumerator._event_topic0(_OWNERSET_SIG)


def _ownerset_log(key: str, value: int, *, block: int, tx_index: int, log_index: int) -> IndexedEventLog:
    return IndexedEventLog(
        chain_id=1,
        event_address=STATE_HOLDER,
        topic0=OWNERSET_TOPIC0,
        tx_hash=(block * 1000 + log_index).to_bytes(8, "big").rjust(32, b"\x00"),
        log_index=log_index,
        block_number=block,
        block_hash=block.to_bytes(8, "big").rjust(32, b"\x33"),
        transaction_index=tx_index,
        topics=[OWNERSET_TOPIC0, _word(key), "0x" + format(value, "064x")],
        data_words=[],
    )


def _ownerset_descriptor() -> dict:
    return {
        "kind": "mapping_membership",
        "storage_var": "ownerRole",
        "value_predicate": {"op": "eq", "rhs_values": ["3"], "value_type": "uint256"},
        "key_sources": [{"source": "msg_sender"}],
        "enumeration_hint": [
            {
                "topic0": OWNERSET_TOPIC0,
                "topics_to_keys": {"1": 0},
                "data_to_keys": {},
                "direction": "set",
                "event_signature": _OWNERSET_SIG,
                "event_name": "OwnerSet",
                "mapping_name": "ownerRole",
                "key_position": 0,
                "indexed_positions": [0, 1],
                "value_position": 1,
                "writer_function": "setOwnerRole(address,uint256)",
            }
        ],
    }


def test_durable_explicit_value_predicate_filters_by_value(db_session, no_live_calls):
    rows = [
        _ownerset_log(CALLER_A, 2, block=100, tx_index=0, log_index=0),
        _ownerset_log(CALLER_A, 3, block=200, tx_index=0, log_index=0),
        _ownerset_log(CALLER_B, 1, block=150, tx_index=0, log_index=0),
    ]
    _seed(db_session, rows, [_cursor(OWNERSET_TOPIC0, last_block=25389740, complete=True)])

    ctx = EvaluationContext(
        chain_id=1,
        contract_address=STATE_HOLDER,
        block=RESOLUTION_BLOCK,
        event_log_repo=PostgresEventLogRepo(db_session),
    )
    cap = EventIndexedAdapter().enumerate(_ownerset_descriptor(), ctx)

    assert cap.kind == "finite_set"
    assert cap.membership_quality == "exact"
    assert sorted(cap.members or []) == [CALLER_A.lower()]
    assert no_live_calls == []


def test_live_fallback_forwards_token_and_block_when_durable_absent(db_session, monkeypatch):
    captured: dict = {}

    async def fake_values(contract_address, writer_specs, **kwargs):
        captured["contract_address"] = contract_address
        captured["kwargs"] = kwargs
        return {
            "entries": [{"key": CALLER_A.lower(), "value_hex": _bool_word(True), "last_block": 100}],
            "status": "complete",
            "pages_fetched": 1,
            "last_block_scanned": 100,
            "error": None,
        }

    monkeypatch.setattr(mapping_enumerator, "enumerate_mapping_values", fake_values)
    mapping_enumerator._VALUE_CACHE.clear()

    class _NoValueFoldRepo: ...

    sentinel_client = object()
    sentinel_module = object()
    ctx = EvaluationContext(
        chain_id=1,
        contract_address=STATE_HOLDER,
        block=RESOLUTION_BLOCK,
        event_log_repo=cast(Any, _NoValueFoldRepo()),
        meta={
            "hypersync_token": "tok-123",
            "hypersync_client": sentinel_client,
            "hypersync_module": sentinel_module,
            "hypersync_url": "https://eth.example.xyz",
        },
    )
    cap = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)

    assert cap.kind == "finite_set"
    assert sorted(cap.members or []) == [CALLER_A.lower()]
    assert captured["contract_address"] == STATE_HOLDER
    kw = captured["kwargs"]
    assert kw.get("bearer_token") == "tok-123"
    assert kw.get("client") is sentinel_client
    assert kw.get("hypersync_url") == "https://eth.example.xyz"
    assert kw.get("to_block") == RESOLUTION_BLOCK


def test_live_fallback_floors_from_block_at_creation_block(monkeypatch):
    # The pre-deployment range is the 429-storm trigger on high-volume contracts.
    import services.resolution.creation_block_floor as floor_mod

    monkeypatch.delenv("ENVIO_API_TOKEN", raising=False)
    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(
        floor_mod, "resolve_scan_floor_with_basis", lambda *_a, **_k: (18_000_000 - 1, "creation_block_lookup")
    )

    captured: dict = {}

    async def fake_values(contract_address, writer_specs, **kwargs):
        captured["kwargs"] = kwargs
        return {"entries": [], "status": "complete", "pages_fetched": 1, "last_block_scanned": 0, "error": None}

    monkeypatch.setattr(mapping_enumerator, "enumerate_mapping_values", fake_values)
    mapping_enumerator._VALUE_CACHE.clear()

    class _NoValueFoldRepo:
        pass

    ctx = EvaluationContext(
        chain_id=1,
        contract_address=STATE_HOLDER,
        block=RESOLUTION_BLOCK,
        event_log_repo=cast(Any, _NoValueFoldRepo()),
        meta={"hypersync_token": "tok-123"},
    )
    cap = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)

    assert captured["kwargs"].get("from_block") == 18_000_000 - 1
    assert cap.trace == [
        {
            "step": "live_value_fold",
            "event_address": STATE_HOLDER,
            "scan_from_block": 18_000_000 - 1,
            "scan_to_block": RESOLUTION_BLOCK,
            "floor_basis": "creation_block_lookup",
        }
    ]


def test_live_fallback_defers_on_unknown_floor(monkeypatch):
    # An unresolvable floor must not fall open to a genesis scan.
    import services.resolution.creation_block_floor as floor_mod

    monkeypatch.delenv("ENVIO_API_TOKEN", raising=False)
    floor_mod.clear_scan_floor_cache()
    # Override the autouse floor stub: an unresolvable floor returns the DEFER sentinel (None).
    monkeypatch.setattr(floor_mod, "resolve_scan_floor_with_basis", lambda *_a, **_k: (None, None))

    invoked: dict = {"called": False}

    async def fake_values(contract_address, writer_specs, **kwargs):
        invoked["called"] = True
        return {"entries": [], "status": "complete", "pages_fetched": 1, "last_block_scanned": 0, "error": None}

    monkeypatch.setattr(mapping_enumerator, "enumerate_mapping_values", fake_values)
    mapping_enumerator._VALUE_CACHE.clear()

    class _NoValueFoldRepo:
        pass

    ctx = EvaluationContext(
        chain_id=1,
        contract_address=STATE_HOLDER,
        block=RESOLUTION_BLOCK,
        event_log_repo=cast(Any, _NoValueFoldRepo()),
        meta={"hypersync_token": "tok-123"},
    )
    result = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)

    assert invoked["called"] is False  # no live scan issued on an unknown floor
    assert result.kind == "external_check_only"
