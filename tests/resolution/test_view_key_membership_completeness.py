"""View-key membership publishes admins of observed roles only when every role write through the block was read.

Cursors and rows are real test-DB rows read by the real ``PostgresEventLogRepo``; the wires (HyperSync client,
``eth_getLogs``) are stubbed.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any, cast

import pytest

from db.models import ENROLLMENT_BASIS_PREDICATE_HINT, IndexedEventCursor, IndexedEventLog
from services.resolution.capabilities import CapabilityExpr
from services.resolution.event_tail import TailScan
from services.resolution.mapping_enumerator import _event_topic0
from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree, membership
from services.resolution.predicate_evaluator.membership import (
    UNPROVEN_EVENT_KEYS,
    _observed_event_key_words_from_hypersync,
    _scan_observed_event_key_words,
)
from services.resolution.repos.event_logs_pg import UNDECODABLE_EVENT_DATA
from services.resolution.repos.event_logs_rpc import FetchedEventLog
from tests.conftest import requires_postgres
from tests.support.hypersync_fakes import _FakeHypersyncModule

pytestmark = requires_postgres

ACL = "0x" + "a1" * 20
OTHER = "0x" + "a2" * 20
SAFE = "0x" + "ce" * 20
GRANT_T0 = _event_topic0("RoleGranted(bytes32,address,address)")
REVOKE_T0 = _event_topic0("RoleRevoked(bytes32,address,address)")
ROLE_A = "0x" + "aa" * 32
ROLE_B = "0x" + "bb" * 32
ADMIN_ROLE = "0x" + "00" * 32
PIN = 20_000


def _hint(topic0: str, *, address: str = ACL) -> dict[str, Any]:
    return {"topic0": topic0, "topics_to_keys": {1: 0, 2: 1}, "event_address": address}


HINTS = [_hint(GRANT_T0), _hint(REVOKE_T0)]


def _word(address: str) -> str:
    return "0x" + address[2:].lower().rjust(64, "0")


def _topics(topic0: str, role: str) -> list[str]:
    return [topic0, role, _word(SAFE), _word(SAFE)]


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    monkeypatch.delenv("ENVIO_API_TOKEN", raising=False)
    monkeypatch.delenv("PSAT_HYPERSYNC_URL", raising=False)
    monkeypatch.setitem(sys.modules, "hypersync", _FakeHypersyncModule())
    monkeypatch.setattr("services.resolution.creation_block_floor.resolve_scan_floor", lambda *_a, **_k: 100)


class _HyperSync:
    """The HyperSync client wire: each request returns the next page; ``fail_on`` (1-based) raises ``error`` there.

    The last page repeats, so a ``next_block`` that stops advancing models a stalled archive.
    """

    def __init__(
        self,
        pages: list[tuple[list[Any], int | None]] | None = None,
        error: Exception | None = None,
        fail_on: int = 1,
    ):
        self.pages = list(pages or [([], PIN + 1)])
        self.error = error
        self.fail_on = fail_on
        self.built = 0
        self.addresses: list[str] = []
        self.to_blocks: list[int | None] = []

    def install(self, monkeypatch) -> _HyperSync:
        def _build(_module, *, url, bearer_token):
            self.built += 1
            return self

        monkeypatch.setenv("ENVIO_API_TOKEN", "tok")
        monkeypatch.setattr("services.resolution.hypersync_bound.build_hypersync_client", _build)
        return self

    async def get(self, query):
        self.addresses.extend(query.logs[0].address)
        self.to_blocks.append(query.to_block)
        if self.error is not None and len(self.to_blocks) >= self.fail_on:
            raise self.error
        logs, next_block = self.pages.pop(0) if len(self.pages) > 1 else self.pages[0]
        return SimpleNamespace(data=list(logs), next_block=next_block)


def _hs_log(topic0: str, role: str, *, data: str = "0x") -> SimpleNamespace:
    return SimpleNamespace(topics=_topics(topic0, role), data=data)


def _cursor(
    session,
    topic0: str,
    *,
    last: int = PIN,
    complete: bool = True,
    address: str = ACL,
    enrollment_basis: str | None = ENROLLMENT_BASIS_PREDICATE_HINT,
) -> None:
    session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=address,
            topic0=topic0,
            last_indexed_block=last,
            backfill_complete=complete,
            first_indexed_block=0,
            first_indexed_block_basis="creation_block_minus_one",
            enrollment_basis=enrollment_basis,
        )
    )
    session.commit()


def _warm(session, *, last: int = PIN, address: str = ACL, **kwargs) -> None:
    for topic0 in (GRANT_T0, REVOKE_T0):
        _cursor(session, topic0, last=last, address=address, **kwargs)


_SEQ = {"n": 0}


def _row(session, topic0: str, role: str, block: int, *, address: str = ACL, data_hex: str | None = None) -> None:
    _SEQ["n"] += 1
    session.add(
        IndexedEventLog(
            chain_id=1,
            event_address=address,
            topic0=topic0,
            tx_hash=_SEQ["n"].to_bytes(32, "big"),
            log_index=0,
            block_number=block,
            block_hash=b"\x01" * 32,
            transaction_index=0,
            topics=_topics(topic0, role),
            data_words=[],
            data_hex=data_hex,
        )
    )
    session.commit()


def _getlogs_wire(monkeypatch, logs: list[dict] | Exception) -> list:
    calls: list = []

    def _rpc(_url, method, params, **_kw):
        assert method == "eth_getLogs"
        calls.append(params)
        if isinstance(logs, Exception):
            raise logs
        return logs

    monkeypatch.setattr("services.resolution.event_tail.rpc_request", _rpc)
    return calls


def _rpc_log(topic0: str, role: str, block: int, *, data: str = "0x") -> dict:
    return {
        "address": ACL,
        "topics": _topics(topic0, role),
        "data": data,
        "blockNumber": hex(block),
        "blockHash": "0x" + "11" * 32,
        "transactionHash": "0x" + "22" * 32,
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": False,
    }


def _outer(session, *, block: int | None = PIN, rpc_url: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        session=session,
        chain_id=1,
        block=block,
        rpc_url=rpc_url,
        contract_address=ACL,
        meta={},
        state_var_values={},
    )


def _scan(session, *, hints: list[dict[str, Any]] = HINTS, **outer_kwargs):
    return _scan_observed_event_key_words(
        session=session,
        outer_ctx=_outer(session, **outer_kwargs),
        descriptor=cast(Any, {"kind": "mapping_membership"}),
        event_hints=hints,
        key_index=0,
    )


# Durable read ---------------------------------------------------------------------------------------------------------


def test_a_proven_index_read_is_complete_without_hypersync(db_session, monkeypatch):
    hypersync = _HyperSync().install(monkeypatch)
    _warm(db_session)
    _row(db_session, GRANT_T0, ROLE_A, 150)
    _row(db_session, REVOKE_T0, ROLE_B, 160)

    observed = _scan(db_session)

    assert observed is not None
    assert observed.complete and observed.words == sorted([ROLE_A, ROLE_B])
    assert hypersync.built == 0


@pytest.mark.parametrize(
    "cursor",
    [
        pytest.param({"complete": False}, id="mid_backfill"),
        pytest.param({"enrollment_basis": "explicit_seed"}, id="ineligible_basis"),
    ],
)
def test_rows_under_an_unproven_cursor_never_publish_a_complete_role_set(db_session, cursor):
    _warm(db_session, **cursor)
    _row(db_session, GRANT_T0, ROLE_A, 150)

    observed = _scan(db_session)

    assert observed is not None and not observed.complete


def test_an_unproven_index_is_answered_by_a_complete_hypersync_scan(db_session, monkeypatch):
    pages: list[tuple[list[Any], int | None]] = [([_hs_log(GRANT_T0, ROLE_A), _hs_log(GRANT_T0, ROLE_B)], PIN + 1)]
    hypersync = _HyperSync(pages=pages).install(monkeypatch)
    _warm(db_session, complete=False)
    _row(db_session, GRANT_T0, ROLE_A, 150)

    observed = _scan(db_session)

    assert observed is not None
    assert observed.complete and observed.words == sorted([ROLE_A, ROLE_B])
    assert hypersync.built == 1


def test_a_lagging_index_is_completed_by_a_tail_over_rpc(db_session, monkeypatch):
    hypersync = _HyperSync().install(monkeypatch)
    _warm(db_session, last=PIN - 100)
    _row(db_session, GRANT_T0, ROLE_A, 150)
    calls = _getlogs_wire(monkeypatch, [_rpc_log(GRANT_T0, ROLE_B, PIN - 50)])

    observed = _scan(db_session, rpc_url="http://rpc.test")

    assert observed is not None
    assert observed.complete and observed.words == sorted([ROLE_A, ROLE_B])
    assert calls and hypersync.built == 0


def test_a_failed_tail_without_hypersync_is_incomplete(db_session, monkeypatch):
    _warm(db_session, last=PIN - 100)
    _row(db_session, GRANT_T0, ROLE_A, 150)
    _getlogs_wire(monkeypatch, RuntimeError("upstream 503"))

    observed = _scan(db_session, rpc_url="http://rpc.test")

    assert observed is not None and not observed.complete


def test_an_unpinned_read_is_never_proven_from_the_index(db_session):
    _warm(db_session)
    _row(db_session, GRANT_T0, ROLE_A, 150)

    observed = _scan(db_session, block=None)

    assert observed is not None and not observed.complete


def test_an_undecodable_tail_log_refuses_the_read(db_session, monkeypatch):
    # The RPC wire rejects a non-aligned log outright; a tail that still hands one back must not be skipped.
    unaligned = FetchedEventLog(
        tx_hash=b"\x02" * 32,
        log_index=0,
        block_number=PIN - 50,
        block_hash=b"\x03" * 32,
        transaction_index=0,
        topics=_topics(GRANT_T0, ROLE_B),
        data_words=[],
        data_hex="0x" + "ab" * 33,
    )
    monkeypatch.setattr(
        "services.resolution.event_tail.tail_scanner_for",
        lambda _ctx: (
            lambda _a, _t, frontier, block: TailScan(
                complete=True, from_block=frontier + 1, to_block=block, logs=(unaligned,)
            )
        ),
    )
    _warm(db_session, last=PIN - 100)

    assert _scan(db_session) is None


def test_hypersync_scans_only_the_addresses_the_index_cannot_prove(db_session, monkeypatch):
    hypersync = _HyperSync(pages=[([_hs_log(GRANT_T0, ROLE_B)], PIN + 1)]).install(monkeypatch)
    _warm(db_session)
    _row(db_session, GRANT_T0, ROLE_A, 150)

    observed = _scan(db_session, hints=[*HINTS, _hint(GRANT_T0, address=OTHER)])

    assert observed is not None
    assert observed.complete and observed.words == sorted([ROLE_A, ROLE_B])
    assert set(hypersync.addresses) == {OTHER}


def test_a_hint_naming_no_event_is_incomplete(db_session):
    _warm(db_session)

    observed = _scan(db_session, hints=[*HINTS, {"topics_to_keys": {1: 0}, "event_address": ACL}])

    assert observed is not None and not observed.complete


def test_a_failed_hypersync_scan_for_one_address_leaves_the_set_incomplete(db_session, monkeypatch):
    _HyperSync(error=RuntimeError("429 Too Many Requests")).install(monkeypatch)
    _warm(db_session)
    _row(db_session, GRANT_T0, ROLE_A, 150)

    observed = _scan(db_session, hints=[*HINTS, _hint(GRANT_T0, address=OTHER)])

    assert observed is not None and not observed.complete


def test_an_indexed_row_without_its_key_refuses_the_read(db_session):
    _warm(db_session)
    _row(db_session, GRANT_T0, ROLE_A, 150)
    db_session.add(
        IndexedEventLog(
            chain_id=1,
            event_address=ACL,
            topic0=GRANT_T0,
            tx_hash=b"\xee" * 32,
            log_index=0,
            block_number=160,
            block_hash=b"\x01" * 32,
            transaction_index=0,
            topics=[GRANT_T0],
            data_words=[],
        )
    )
    db_session.commit()

    assert _scan(db_session) is None


# HyperSync fallback ---------------------------------------------------------------------------------------------------


def _hypersync_scan(block: int | None = PIN, hints: list[dict[str, Any]] = HINTS):
    return _observed_event_key_words_from_hypersync(
        outer_ctx=SimpleNamespace(chain_id=1, block=block, meta={}, session=None, contract_address=ACL),
        descriptor=cast(Any, {"kind": "mapping_membership"}),
        event_hints=hints,
        key_index=0,
    )


def test_a_hypersync_scan_through_the_pinned_block_is_complete(monkeypatch):
    hypersync = _HyperSync(
        pages=[([_hs_log(GRANT_T0, ROLE_A)], PIN - 10), ([_hs_log(GRANT_T0, ROLE_B)], PIN + 1)]
    ).install(monkeypatch)

    observed = _hypersync_scan()

    assert observed.complete and observed.words == sorted([ROLE_A, ROLE_B])
    # HyperSync's ``to_block`` is exclusive: the pinned block itself is read.
    assert hypersync.to_blocks == [PIN + 1, PIN + 1]


@pytest.mark.parametrize(
    "tip",
    [
        pytest.param(PIN, id="stops_before_the_pinned_block"),
        pytest.param(PIN - 10, id="stalled_archive"),
    ],
)
def test_a_hypersync_scan_short_of_the_pinned_block_is_incomplete(monkeypatch, tip):
    _HyperSync(pages=[([_hs_log(GRANT_T0, ROLE_A)], PIN - 10), ([], tip), ([], tip)]).install(monkeypatch)

    observed = _hypersync_scan()

    assert not observed.complete


def test_a_hypersync_scan_without_a_next_block_is_incomplete(monkeypatch):
    _HyperSync(pages=[([_hs_log(GRANT_T0, ROLE_A)], None)]).install(monkeypatch)

    assert not _hypersync_scan().complete


def test_an_unpinned_hypersync_scan_is_never_complete(monkeypatch):
    hypersync = _HyperSync().install(monkeypatch)

    observed = _hypersync_scan(block=None)

    assert not observed.complete and hypersync.built == 0


def test_a_hypersync_error_keeps_what_it_saw_but_is_incomplete(monkeypatch):
    degraded: list[str] = []
    monkeypatch.setattr(membership, "record_degraded", lambda *, phase, **_k: degraded.append(phase))
    _HyperSync(pages=[([_hs_log(GRANT_T0, ROLE_A)], PIN - 10)], error=RuntimeError("403 Forbidden"), fail_on=2).install(
        monkeypatch
    )

    observed = _hypersync_scan()

    assert not observed.complete and observed.words == [ROLE_A]
    assert degraded == ["observed_event_key_words_scan"]


def test_a_hypersync_log_without_its_key_is_incomplete(monkeypatch):
    data_keyed = [{"topic0": GRANT_T0, "data_to_keys": {0: 0}, "event_address": ACL}]
    _HyperSync(pages=[([_hs_log(GRANT_T0, ROLE_A, data="0x" + "ab" * 33)], PIN + 1)]).install(monkeypatch)

    observed = _hypersync_scan(hints=data_keyed)

    assert not observed.complete


@pytest.mark.parametrize(
    "log",
    [
        pytest.param(SimpleNamespace(topics=[], data="0x"), id="no_topics"),
        pytest.param(_hs_log("0x" + "99" * 32, ROLE_A), id="unrequested_topic"),
    ],
)
def test_a_hypersync_log_outside_the_writer_hints_is_incomplete(monkeypatch, log):
    _HyperSync(pages=[([log], PIN + 1)]).install(monkeypatch)

    assert not _hypersync_scan().complete


def test_a_hypersync_scan_cut_at_the_page_cap_is_incomplete(monkeypatch):
    monkeypatch.setenv("PSAT_HYPERSYNC_EVENT_FALLBACK_MAX_PAGES", "1")
    _HyperSync(pages=[([_hs_log(GRANT_T0, ROLE_A)], PIN - 10), ([_hs_log(GRANT_T0, ROLE_B)], PIN + 1)]).install(
        monkeypatch
    )

    observed = _hypersync_scan()

    assert not observed.complete and observed.words == [ROLE_A]


def test_a_hypersync_scan_with_no_floor_is_incomplete(monkeypatch):
    monkeypatch.setattr("services.resolution.creation_block_floor.resolve_scan_floor", lambda *_a, **_k: None)
    hypersync = _HyperSync().install(monkeypatch)

    observed = _hypersync_scan()

    assert not observed.complete and hypersync.addresses == []


def test_no_hypersync_token_is_incomplete():
    observed = _hypersync_scan()

    assert not observed.complete and observed.words == []


# Published capability -------------------------------------------------------------------------------------------------


def _evaluate(session, monkeypatch) -> tuple[CapabilityExpr, list[list[str]]]:
    viewed: list[list[str]] = []

    def _admin_view(*, args, **_k):
        viewed.append(list(args))
        return [ADMIN_ROLE]

    monkeypatch.setattr(membership, "_call_unary_bytes32_view", _admin_view)

    class Adapter:
        _outer_ctx = _outer(session, rpc_url="http://rpc.test")

        def enumerate(self, descriptor, _contract_address):
            assert descriptor["key_sources"][0] == {"source": "constant", "constant_value": ADMIN_ROLE}
            return CapabilityExpr.finite_set([SAFE], quality="exact", confidence="enumerable")

    view_key = {"source": "view_call", "callee_signature": "getRoleAdmin(bytes32)", "callee_selector": "0x248a9ca3"}
    tree = {
        "op": "LEAF",
        "leaf": {
            "kind": "membership",
            "operator": "truthy",
            "authority_role": "caller_authority",
            "operands": [view_key, {"source": "msg_sender"}],
            "set_descriptor": {
                "kind": "mapping_membership",
                "storage_var": "_roles",
                "key_sources": [view_key, {"source": "msg_sender"}],
                "enumeration_hint": HINTS,
            },
            "references_msg_sender": True,
            "parameter_indices": [],
        },
    }
    cap = evaluate_tree(tree, EvaluationContext(contract_address=ACL, adapter=Adapter()))  # pyright: ignore[reportArgumentType]
    return cap, viewed


def test_a_proven_role_set_publishes_its_admins_holders(db_session, monkeypatch):
    _warm(db_session)
    _row(db_session, GRANT_T0, ROLE_A, 150)

    cap, viewed = _evaluate(db_session, monkeypatch)

    assert cap.kind == "finite_set" and cap.members == [SAFE]
    assert viewed == [[ROLE_A]]


def test_a_partial_role_set_is_published_as_unresolved(db_session, monkeypatch):
    _warm(db_session, complete=False)
    _row(db_session, GRANT_T0, ROLE_A, 150)

    cap, viewed = _evaluate(db_session, monkeypatch)

    assert cap.kind == "external_check_only"
    assert cap.check is not None
    assert cap.check.extra["basis"] == ["view_key_membership_unresolved", UNPROVEN_EVENT_KEYS]
    assert viewed == []


def test_an_undecodable_row_is_published_as_unresolved(db_session, monkeypatch):
    _warm(db_session)
    _row(db_session, GRANT_T0, ROLE_A, 150, data_hex="0x" + "ab" * 33)

    cap, _viewed = _evaluate(db_session, monkeypatch)

    assert cap.kind == "external_check_only"
    assert cap.check is not None
    assert cap.check.extra["basis"] == ["view_key_membership_unresolved", UNDECODABLE_EVENT_DATA]
