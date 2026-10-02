"""D4: enrolling from a tracking plan gathers history but must never turn a zero-row fold into "never written",
because the plan attributes topics to no variable.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import func, select, text

from db.models import (
    ENROLLMENT_BASIS_PREDICATE_HINT,
    ENROLLMENT_BASIS_TRACKED_TOPICS,
    FIRST_INDEXED_BASIS_CREATION,
    WINDOW_STATS_CONTINUOUS,
    WINDOW_STATS_UNMEASURED_LEGACY,
    IndexedEventCursor,
    IndexedEventLog,
    MonitoredContract,
    Protocol,
)
from services.resolution.absence_coverage import (
    REASON_COLD_CURSORS,
    REASON_LOWER_BOUND_UNKNOWN,
    REASON_MISSING_CURSORS,
    REASON_NO_INVERSE_INDEX,
    REASON_PAGE_RESIDUAL,
    absence_coverage,
)
from services.resolution.deferred_reconciler import _authority_backfilled
from services.resolution.repos.event_logs_pg import PostgresEventLogRepo
from services.resolution.repos.event_logs_rpc import (
    FetchWindowStat,
    RpcEventLogFetcher,
    default_result_cap,
)
from tests.conftest import requires_postgres
from workers.event_log_indexer import (
    _ALL_ROLE_STORE_TOPIC0S,
    PageLimits,
    _authority_has_role_store_cursor,
    _witness_seed_block,
    enroll_event_cursor,
    enroll_from_tracked_topics,
    index_event_group_steps,
)

# Code is empty at 20265588 and present at 20265589.
_ADDR = "0x3994741a5b29c60d0ab318de1024f9256fe959dc"
_SEED = 20_265_588
_TOPIC_ALLOW_TO = "0x039bcf51833310242b8b7c6aa0fbabf1bf2b5e5270807ee020f1920ef200666b"
_TOPIC_DENY_TO = "0x79fc685a7dbabb75a67df5e69a90602cef1f19bc465b060eab1ac56685e04a13"
_TOPIC_ALLOW_FROM = "0xae893dda71e2eee548f8291f458cceae4bd22b56a79906928591e4420444c0e9"
_TOPIC_DENY_FROM = "0xd658022b1a3aaf6ad3b3c615253712807f21a8f7bc3e4996e10618175d4afb2b"
_TOPIC_ALLOW_OP = "0x77cb944c14da76928795279d1519ce9150085a06e0a53c61d5a86fc4e0fd57c6"
_TOPIC_DENY_OP = "0x3afb02134e37f7205acf470adc2fc4ebb70614b1599a602d069790915380e2aa"
_DENYLIST_SURFACE = [
    _TOPIC_ALLOW_FROM,
    _TOPIC_DENY_FROM,
    _TOPIC_ALLOW_TO,
    _TOPIC_DENY_TO,
    _TOPIC_ALLOW_OP,
    _TOPIC_DENY_OP,
]

_CODE = "0x60806040"
_EMPTY = "0x"
_EIP7702_STUB = "0xef0100" + "ab" * 20


def _row(session, address: str = _ADDR, topic0: str = _TOPIC_ALLOW_TO) -> IndexedEventCursor:
    return session.execute(
        select(IndexedEventCursor)
        .where(IndexedEventCursor.event_address == address.lower())
        .where(IndexedEventCursor.topic0 == topic0.lower())
    ).scalar_one()


_KEY_SOURCES = [{"source": "msg_sender"}]


def _fold(session, topic0: str, *, block: int = 24_000_000):
    return PostgresEventLogRepo(session).fold_event_writes(
        chain_id=1,
        event_address=_ADDR,
        topic0=topic0,
        topics_to_keys={0: 0},
        data_to_keys={},
        key_sources=_KEY_SOURCES,
        direction="add",
        block=block,
    )


def _provenance(cursor: IndexedEventCursor) -> dict[str, Any]:
    return {
        "last_indexed_block": cursor.last_indexed_block,
        "first_indexed_block": cursor.first_indexed_block,
        "first_indexed_block_basis": cursor.first_indexed_block_basis,
        "backfill_complete": cursor.backfill_complete,
    }


class _StubRpc:
    def __init__(self, *, code_before=_EMPTY, code_at=_CODE, prior_logs=None, raise_on=None) -> None:
        self.code_before = code_before
        self.code_at = code_at
        self.prior_logs = [] if prior_logs is None else prior_logs
        self.raise_on = raise_on
        self.calls: list[tuple[str, Any]] = []

    def __call__(self, url, method, params, chain_id=None):
        self.calls.append((method, params))
        if self.raise_on == method:
            raise RuntimeError("stubbed upstream failure")
        if method == "eth_getCode":
            return self.code_before if int(params[1], 16) == _SEED else self.code_at
        if method == "eth_getLogs":
            return self.prior_logs
        raise AssertionError(f"unexpected method {method}")


@pytest.fixture()
def stub_rpc(monkeypatch):
    def _install(**kwargs):
        stub = _StubRpc(**kwargs)
        import workers.event_log_indexer as eli

        monkeypatch.setattr(eli, "rpc_request", stub)
        monkeypatch.setattr(eli, "require_rpc_url", lambda **_kw: "http://stub")
        # The creation block is the seed the witness grades, not the proof.
        monkeypatch.setattr(eli, "get_contract_creation_block", lambda *_a, **_k: _SEED + 1)
        return stub

    return _install


@requires_postgres
def test_enrol_persists_the_witnessed_lower_bound_byte_exactly(db_session):
    assert enroll_event_cursor(
        db_session,
        chain_id=1,
        event_address=_ADDR,
        topic0=_TOPIC_ALLOW_TO,
        start_block=_SEED,
        first_indexed_block=_SEED,
        first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION,
        enrollment_basis=ENROLLMENT_BASIS_PREDICATE_HINT,
    )
    db_session.commit()
    assert _provenance(_row(db_session)) == {
        "last_indexed_block": _SEED,
        "first_indexed_block": _SEED,
        "first_indexed_block_basis": FIRST_INDEXED_BASIS_CREATION,
        "backfill_complete": False,
    }


@requires_postgres
def test_enrol_without_provenance_defaults_to_not_determined(db_session):
    """``start_block``'s ``= 0`` default must not become a claim of coverage from genesis."""
    assert enroll_event_cursor(db_session, chain_id=1, event_address=_ADDR, topic0=_TOPIC_ALLOW_TO)
    db_session.execute(text("UPDATE indexed_event_cursors SET backfill_complete = true, last_indexed_block = 25000000"))
    db_session.commit()
    cursor = _row(db_session)
    assert cursor.first_indexed_block is None
    assert cursor.first_indexed_block_basis == "not_determined"
    assert cursor.enrollment_basis == "not_determined"
    result = _fold(db_session, _TOPIC_ALLOW_TO)
    assert (result.confidence, result.partial_reason) == ("partial", "no_index_cursor")


def test_witness_requires_all_three_reads_to_agree(stub_rpc):
    stub = stub_rpc()
    assert _witness_seed_block(_ADDR, _SEED, {}, chain_id=1) == (_SEED, FIRST_INDEXED_BASIS_CREATION)
    assert [m for m, _ in stub.calls] == ["eth_getCode", "eth_getCode", "eth_getLogs"]
    # Any log of any kind below the seed refutes the bound.
    _method, params = stub.calls[-1]
    assert params == [{"address": _ADDR, "fromBlock": "0x0", "toBlock": hex(_SEED)}]


def test_witness_rejects_a_prior_incarnation_and_discards_the_number(stub_rpc):
    """A CREATE2 redeploy means code at B isn't proof of first deployment."""
    stub_rpc(prior_logs=[{"blockNumber": "0x1"}])
    assert _witness_seed_block(_ADDR, _SEED, {}, chain_id=1) == (None, "not_determined")


def test_witness_rejects_an_eip7702_delegation_stub(stub_rpc):
    """A 0xef0100 delegation stub can be set and cleared, so it dates nothing."""
    stub_rpc(code_at=_EIP7702_STUB)
    assert _witness_seed_block(_ADDR, _SEED, {}, chain_id=1) == (None, "not_determined")


def test_witness_failure_yields_not_determined_never_a_bound(stub_rpc):
    stub_rpc(raise_on="eth_getLogs")
    assert _witness_seed_block(_ADDR, _SEED, {}, chain_id=1) == (None, "not_determined")
    stub_rpc(raise_on="eth_getCode")
    assert _witness_seed_block(_ADDR, _SEED, {}, chain_id=1) == (None, "not_determined")
    stub_rpc(code_before=_CODE)
    assert _witness_seed_block(_ADDR, _SEED, {}, chain_id=1) == (None, "not_determined")


@requires_postgres
def test_legacy_null_lower_bound_publishes_not_determined_never_zero(db_session):
    enroll_event_cursor(db_session, chain_id=1, event_address=_ADDR, topic0=_TOPIC_ALLOW_TO)
    db_session.execute(
        text(
            "UPDATE indexed_event_cursors SET first_indexed_block = NULL, "
            "first_indexed_block_basis = NULL, backfill_complete = true"
        )
    )
    db_session.commit()
    report = absence_coverage(db_session, chain_id=1, address=_ADDR)
    assert report["range_lower_bound"] is None
    assert report["range_lower_bound_basis"] == "not_determined"
    assert REASON_LOWER_BOUND_UNKNOWN in report["blocking_reasons"]
    assert 0 not in [report["range_lower_bound"]]


@requires_postgres
def test_migration_left_legacy_rows_unmeasured_not_measured_empty(db_session):
    db_session.execute(
        text(
            "INSERT INTO indexed_event_cursors (chain_id, event_address, topic0, last_indexed_block, "
            "backfill_complete, window_stats_basis) VALUES (1, :a, :t, 100, true, :b)"
        ),
        {"a": _ADDR, "t": _TOPIC_ALLOW_TO, "b": WINDOW_STATS_UNMEASURED_LEGACY},
    )
    db_session.commit()
    cursor = _row(db_session)
    assert (cursor.max_window_log_count, cursor.window_stats_cap) == (None, None)
    assert cursor.window_stats_basis == WINDOW_STATS_UNMEASURED_LEGACY
    assert absence_coverage(db_session, chain_id=1, address=_ADDR)["page_completeness"] == "not_determined"


# D4(b) — enrolment from tracking plans, and the ceiling that stays a ceiling


def _monitored(
    db_session,
    topics: list[str],
    *,
    chain: str = "ethereum",
    active: bool = True,
    address: str = _ADDR,
) -> None:
    protocol = Protocol(name=f"d4-{chain}-{int(active)}-{address[-6:]}")
    db_session.add(protocol)
    db_session.flush()
    db_session.add(
        MonitoredContract(
            address=address,
            chain=chain,
            protocol_id=protocol.id,
            is_active=active,
            monitoring_config={"tracked_topics": [{"topic0": t, "signature": "X(address)"} for t in topics]},
        )
    )
    db_session.commit()


@requires_postgres
def test_enrolment_drains_the_whole_fleet_across_passes(db_session, stub_rpc):
    """Bounding rows would re-walk the same head every pass."""
    stub_rpc()
    # ``0x0…0`` is refused by the enrollability guard, so start from 1.
    for i in range(1, 61):
        _monitored(db_session, [_TOPIC_DENY_TO], address="0x" + f"{i:040x}")
    assert enroll_from_tracked_topics(db_session, limit=50) == 50
    assert enroll_from_tracked_topics(db_session, limit=50) == 10
    assert db_session.execute(select(func.count()).select_from(IndexedEventCursor)).scalar_one() == 60
    assert enroll_from_tracked_topics(db_session, limit=50) == 0


@requires_postgres
def test_tracked_topics_enrol_the_writers_no_hint_ever_reached(db_session, stub_rpc):
    """AllowTo/DenyTo key on the recipient, so only the tracking plan names their writers."""
    stub_rpc()
    _monitored(db_session, _DENYLIST_SURFACE)
    assert enroll_from_tracked_topics(db_session) == 6
    enrolled = set(
        db_session.execute(select(IndexedEventCursor.topic0).where(IndexedEventCursor.event_address == _ADDR)).scalars()
    )
    assert enrolled == {t.lower() for t in _DENYLIST_SURFACE}
    assert _row(db_session).enrollment_basis == ENROLLMENT_BASIS_TRACKED_TOPICS


@requires_postgres
def test_tracked_topics_enrolment_skips_unresolvable_and_inactive_rows(db_session, stub_rpc):
    stub_rpc()
    _monitored(db_session, _DENYLIST_SURFACE, chain="not-a-real-chain")
    assert enroll_from_tracked_topics(db_session) == 0
    _monitored(db_session, _DENYLIST_SURFACE, chain="ethereum", active=False)
    assert enroll_from_tracked_topics(db_session) == 0
    assert db_session.execute(select(IndexedEventCursor)).first() is None


@requires_postgres
def test_coverage_gate_reports_missing_writers_and_licenses_nothing(db_session, stub_rpc):
    stub_rpc()
    _monitored(db_session, [_TOPIC_ALLOW_FROM, _TOPIC_DENY_FROM, _TOPIC_ALLOW_OP, _TOPIC_DENY_OP])
    enroll_from_tracked_topics(db_session)
    report = absence_coverage(db_session, chain_id=1, address=_ADDR, write_surface_topics=_DENYLIST_SURFACE)
    assert report["missing"] == sorted([_TOPIC_ALLOW_TO, _TOPIC_DENY_TO])
    assert report["enrollment_complete"] is False
    assert report["earned_negative_admissible"] is False
    assert REASON_MISSING_CURSORS in report["blocking_reasons"]


@requires_postgres
def test_full_surface_fully_witnessed_still_licenses_nothing(db_session):
    """Every checkable condition holds and the verdict is still false: a direct storage write or proxy swap emits
    none of the topics.
    """
    for topic in _DENYLIST_SURFACE:
        enroll_event_cursor(
            db_session,
            chain_id=1,
            event_address=_ADDR,
            topic0=topic,
            start_block=_SEED,
            first_indexed_block=_SEED,
            first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION,
            enrollment_basis=ENROLLMENT_BASIS_PREDICATE_HINT,
        )
    db_session.execute(
        text(
            "UPDATE indexed_event_cursors SET backfill_complete = true, max_window_log_count = 10, "
            "window_stats_cap = 50000, window_stats_basis = :b"
        ),
        {"b": WINDOW_STATS_CONTINUOUS},
    )
    db_session.commit()
    report = absence_coverage(
        db_session,
        chain_id=1,
        address=_ADDR,
        write_surface_topics=_DENYLIST_SURFACE,
        configured_cap=50_000,
    )
    assert report["page_completeness"] == "complete"
    assert report["range_lower_bound"] == _SEED
    assert report["missing"] == []
    assert {
        "write_surface": report["write_surface"],
        "write_surface_basis": report["write_surface_basis"],
        "enrollment_complete": report["enrollment_complete"],
        "earned_negative_admissible": report["earned_negative_admissible"],
        "blocking_reasons": report["blocking_reasons"],
    } == {
        "write_surface": None,
        "write_surface_basis": "not_determined",
        "enrollment_complete": False,
        "earned_negative_admissible": False,
        "blocking_reasons": [REASON_NO_INVERSE_INDEX],
    }


@requires_postgres
def test_cold_asserted_cursor_is_named_as_such(db_session):
    enroll_event_cursor(db_session, chain_id=1, event_address=_ADDR, topic0=_TOPIC_ALLOW_TO)
    db_session.commit()
    report = absence_coverage(db_session, chain_id=1, address=_ADDR, write_surface_topics=[_TOPIC_ALLOW_TO])
    assert report["enrolled"] == [_TOPIC_ALLOW_TO]
    assert report["warm"] == []
    assert REASON_COLD_CURSORS in report["blocking_reasons"]


# A1 — a tracking-plan cursor never becomes an exactness source


@requires_postgres
@pytest.mark.parametrize(
    "basis",
    [
        ENROLLMENT_BASIS_TRACKED_TOPICS,
        # The literal default ``enroll_event_cursor`` writes.
        "not_determined",
        # A new enrolment source is inert until allow-listed.
        "code_asserted_pubkey_fold",
    ],
)
def test_ineligible_basis_cannot_mint_an_exact_empty(db_session, basis):
    enroll_event_cursor(
        db_session,
        chain_id=1,
        event_address=_ADDR,
        topic0=_TOPIC_DENY_TO,
        start_block=_SEED,
        enrollment_basis=basis,
    )
    db_session.execute(text("UPDATE indexed_event_cursors SET backfill_complete = true, last_indexed_block = 25000000"))
    db_session.commit()
    assert db_session.execute(select(IndexedEventLog)).first() is None
    assert _row(db_session, topic0=_TOPIC_DENY_TO).enrollment_basis == basis

    result = _fold(db_session, _TOPIC_DENY_TO)
    assert (result.confidence, result.partial_reason) == ("partial", "no_index_cursor")
    assert result.members == []


@requires_postgres
@pytest.mark.parametrize(
    "enrollment_basis, first_basis, licensed",
    [
        (ENROLLMENT_BASIS_PREDICATE_HINT, FIRST_INDEXED_BASIS_CREATION, True),
        (None, FIRST_INDEXED_BASIS_CREATION, True),
        (ENROLLMENT_BASIS_PREDICATE_HINT, None, False),
        (ENROLLMENT_BASIS_PREDICATE_HINT, "explicit_seed", False),
        (ENROLLMENT_BASIS_PREDICATE_HINT, "not_determined", False),
        (None, None, False),
    ],
    ids=[
        "hint_witnessed",
        "legacy_basis_witnessed",
        "hint_null_bound",
        "hint_explicit_seed",
        "hint_not_determined",
        "legacy",
    ],
)
def test_exactness_needs_an_attributed_basis_and_a_witnessed_lower_bound(
    db_session, enrollment_basis, first_basis, licensed
):
    """The enrolment basis is an allow-list and so is the lower bound: only ``creation_block_minus_one`` is a
    witness, so NULL and ``explicit_seed`` bounds never license an exact fold."""
    enroll_event_cursor(db_session, chain_id=1, event_address=_ADDR, topic0=_TOPIC_ALLOW_TO, start_block=_SEED)
    db_session.execute(
        text(
            "UPDATE indexed_event_cursors SET backfill_complete = true, last_indexed_block = 25000000, "
            "enrollment_basis = :e, first_indexed_block_basis = :f, first_indexed_block = :b"
        ),
        {"e": enrollment_basis, "f": first_basis, "b": _SEED if first_basis == FIRST_INDEXED_BASIS_CREATION else None},
    )
    db_session.commit()
    result = _fold(db_session, _TOPIC_ALLOW_TO)
    if licensed:
        assert (result.confidence, result.partial_reason) == ("enumerable", None)
    else:
        assert (result.confidence, result.partial_reason) == ("partial", "no_index_cursor")
    assert (_authority_backfilled(db_session, 1, _ADDR)) is licensed


@requires_postgres
def test_refused_cursor_is_not_reported_warm(db_session):
    enroll_event_cursor(
        db_session,
        chain_id=1,
        event_address=_ADDR,
        topic0=_TOPIC_DENY_TO,
        start_block=_SEED,
        enrollment_basis=ENROLLMENT_BASIS_TRACKED_TOPICS,
    )
    db_session.execute(text("UPDATE indexed_event_cursors SET backfill_complete = true"))
    db_session.commit()
    report = absence_coverage(db_session, chain_id=1, address=_ADDR, write_surface_topics=[_TOPIC_DENY_TO])
    assert report["enrolled"] == [_TOPIC_DENY_TO]
    assert report["warm"] == []
    assert report["exactness_ineligible"] == [_TOPIC_DENY_TO]
    assert REASON_COLD_CURSORS in report["blocking_reasons"]


@requires_postgres
def test_uppercase_topic_is_not_silently_dropped_from_missing(db_session):
    report = absence_coverage(db_session, chain_id=1, address=_ADDR, write_surface_topics=[_TOPIC_DENY_TO.upper()])
    assert report["write_surface_asserted"] == [_TOPIC_DENY_TO]
    assert report["missing"] == [_TOPIC_DENY_TO]


@requires_postgres
def test_out_of_band_readers_ignore_refused_cursors(db_session):
    """A refused cursor that counted would skip enrolling the attributed one."""
    role_topic = _ALL_ROLE_STORE_TOPIC0S[0]
    enroll_event_cursor(
        db_session,
        chain_id=1,
        event_address=_ADDR,
        topic0=role_topic,
        start_block=_SEED,
        enrollment_basis=ENROLLMENT_BASIS_TRACKED_TOPICS,
    )
    db_session.execute(text("UPDATE indexed_event_cursors SET backfill_complete = true"))
    db_session.commit()
    assert _authority_has_role_store_cursor(db_session, 1, _ADDR) is False
    assert _authority_backfilled(db_session, 1, _ADDR) is False

    db_session.execute(
        text("UPDATE indexed_event_cursors SET enrollment_basis = :b"),
        {"b": ENROLLMENT_BASIS_PREDICATE_HINT},
    )
    db_session.commit()
    # Attributed but unwitnessed: still refused.
    assert _authority_has_role_store_cursor(db_session, 1, _ADDR) is False
    assert _authority_backfilled(db_session, 1, _ADDR) is False

    db_session.execute(
        text("UPDATE indexed_event_cursors SET first_indexed_block = :s, first_indexed_block_basis = :f"),
        {"s": _SEED, "f": FIRST_INDEXED_BASIS_CREATION},
    )
    db_session.commit()
    assert _authority_has_role_store_cursor(db_session, 1, _ADDR) is True
    assert _authority_backfilled(db_session, 1, _ADDR) is True


# D4(c) — a page at the cap is a reject, not a result


class _CappedRpc:
    def __init__(self, count_for) -> None:
        self.count_for = count_for
        self.windows: list[tuple[int, int]] = []

    def __call__(self, url, method, params, chain_id=None):
        assert method == "eth_getLogs"
        lo, hi = int(params[0]["fromBlock"], 16), int(params[0]["toBlock"], 16)
        self.windows.append((lo, hi))
        return [
            {
                "transactionHash": "0x" + "11" * 32,
                "blockHash": "0x" + "22" * 32,
                "logIndex": hex(i),
                "blockNumber": hex(lo),
                "transactionIndex": "0x0",
                "topics": [_TOPIC_DENY_TO],
                "data": "0x",
            }
            for i in range(self.count_for(lo, hi))
        ]


def _fetcher(monkeypatch, rpc, **kwargs) -> RpcEventLogFetcher:
    import services.resolution.repos.event_logs_rpc as mod

    monkeypatch.setattr(mod, "rpc_request", rpc)
    return RpcEventLogFetcher("http://stub", chain_id=1, **kwargs)


def test_page_at_the_cap_bisects_instead_of_advancing(monkeypatch):
    rpc = _CappedRpc(lambda lo, hi: 100 if (lo, hi) == (0, 99_999) else 1)
    fetcher = _fetcher(monkeypatch, rpc, max_block_range=1_000_000, min_bisect_span=10_000, result_cap=100)
    fetcher.fetch_logs(event_address=_ADDR, topics=[_TOPIC_DENY_TO], from_block=0, to_block=99_999)
    assert rpc.windows[0] == (0, 99_999)
    assert rpc.windows[1:3] == [(0, 49_999), (50_000, 99_999)]


def test_page_at_the_cap_on_the_floor_span_raises(monkeypatch):
    rpc = _CappedRpc(lambda lo, hi: 100)
    fetcher = _fetcher(monkeypatch, rpc, max_block_range=1_000_000, min_bisect_span=10_000, result_cap=100)
    with pytest.raises(RuntimeError, match="result cap"):
        fetcher.fetch_logs(event_address=_ADDR, topics=[_TOPIC_DENY_TO], from_block=0, to_block=9_999)


def test_page_below_the_cap_is_accepted_and_counted(monkeypatch):
    rpc = _CappedRpc(lambda lo, hi: 99)
    fetcher = _fetcher(monkeypatch, rpc, min_bisect_span=10_000, result_cap=100)
    stats: list[FetchWindowStat] = []
    logs = fetcher.fetch_logs(
        event_address=_ADDR, topics=[_TOPIC_DENY_TO], from_block=0, to_block=9_999, window_stats=stats
    )
    assert len(logs) == 99
    assert rpc.windows == [(0, 9_999)]
    assert stats == [FetchWindowStat(from_block=0, to_block=9_999, returned_log_count=99, cap=100)]


def test_unset_cap_never_raises_and_never_claims_completeness(monkeypatch):
    """Comparing to None raises TypeError, which would escape the bisect."""
    rpc = _CappedRpc(lambda lo, hi: 125_629)
    fetcher = _fetcher(monkeypatch, rpc, min_bisect_span=10_000, result_cap=None)
    stats: list[FetchWindowStat] = []
    fetcher.fetch_logs(event_address=_ADDR, topics=[_TOPIC_DENY_TO], from_block=0, to_block=9_999, window_stats=stats)
    assert rpc.windows == [(0, 9_999)]
    assert stats[0].cap is None


@pytest.mark.parametrize("payload", [None, {}, "0x", 0])
def test_unreadable_page_is_not_recorded_as_zero_logs(monkeypatch, payload):

    def _rpc(url, method, params, chain_id=None):
        return payload

    fetcher = _fetcher(monkeypatch, _rpc, min_bisect_span=10_000, result_cap=100)
    stats: list[FetchWindowStat] = []
    logs = fetcher.fetch_logs(
        event_address=_ADDR, topics=[_TOPIC_DENY_TO], from_block=0, to_block=9_999, window_stats=stats
    )
    assert logs == []
    assert [s.returned_log_count for s in stats] == [None]
    assert not any(s.returned_log_count == 0 for s in stats)


@requires_postgres
@pytest.mark.parametrize("payload", [None, {}])
def test_unreadable_page_downgrades_the_cursor_never_completes(db_session, monkeypatch, payload):

    class _BadFetcher:
        def fetch_logs(self, *, event_address, topics, from_block, to_block, window_stats=None):
            if window_stats is not None:
                window_stats.append(
                    FetchWindowStat(from_block=from_block, to_block=to_block, returned_log_count=None, cap=100)
                )
            return []

    enroll_event_cursor(
        db_session,
        chain_id=1,
        event_address=_ADDR,
        topic0=_TOPIC_DENY_TO,
        start_block=_SEED,
        first_indexed_block=_SEED,
        first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION,
        enrollment_basis=ENROLLMENT_BASIS_PREDICATE_HINT,
    )
    db_session.commit()
    for _ in index_event_group_steps(
        db_session,
        chain_id=1,
        event_address=_ADDR,
        fetcher=_BadFetcher(),
        target=_SEED + 5_000,
        block_hash_fetcher=_NoHash(),
        limits=PageLimits(max_block_span=1_000),
    ):
        db_session.commit()
    cursor = _row(db_session, topic0=_TOPIC_DENY_TO)
    assert cursor.max_window_log_count is None
    assert cursor.window_stats_basis == "not_determined"
    report = absence_coverage(db_session, chain_id=1, address=_ADDR, configured_cap=100)
    assert report["page_completeness"] == "not_determined"


def test_watcher_construction_does_not_inherit_the_env_cap(monkeypatch):
    """R8. ``iter_pages`` is shared with the monitoring watcher, which must keep returning pages, not
    bisect-and-raise."""
    monkeypatch.setenv("PSAT_GETLOGS_RESULT_CAP", "50000")
    assert default_result_cap() == 50_000
    watcher_fetcher = RpcEventLogFetcher("http://stub", max_block_range=10_000, min_bisect_span=1_000, chain_id=1)
    assert watcher_fetcher.result_cap is None
    assert RpcEventLogFetcher("http://stub", chain_id=1, result_cap=default_result_cap()).result_cap == 50_000


def test_default_result_cap_is_unset_and_ignores_junk(monkeypatch):
    monkeypatch.delenv("PSAT_GETLOGS_RESULT_CAP", raising=False)
    assert default_result_cap() is None
    monkeypatch.setenv("PSAT_GETLOGS_RESULT_CAP", "not-a-number")
    assert default_result_cap() is None
    monkeypatch.setenv("PSAT_GETLOGS_RESULT_CAP", "50000")
    assert default_result_cap() == 50_000


@requires_postgres
def test_completeness_is_refused_when_the_cap_in_force_changed(db_session):
    enroll_event_cursor(
        db_session,
        chain_id=1,
        event_address=_ADDR,
        topic0=_TOPIC_DENY_TO,
        start_block=_SEED,
        first_indexed_block=_SEED,
        first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION,
    )
    db_session.execute(
        text(
            "UPDATE indexed_event_cursors SET backfill_complete = true, max_window_log_count = 40000, "
            "window_stats_cap = 50000, window_stats_basis = :b"
        ),
        {"b": WINDOW_STATS_CONTINUOUS},
    )
    db_session.commit()
    same = absence_coverage(db_session, chain_id=1, address=_ADDR, configured_cap=50_000)
    assert same["page_completeness"] == "complete"
    raised = absence_coverage(db_session, chain_id=1, address=_ADDR, configured_cap=100_000)
    assert raised["page_completeness"] == "not_determined"
    assert REASON_PAGE_RESIDUAL in raised["blocking_reasons"]
    unset = absence_coverage(db_session, chain_id=1, address=_ADDR, configured_cap=None)
    assert unset["page_completeness"] == "not_determined"


# A6 — the shared fetcher's behaviour is unchanged for callers without stats


def test_fetch_without_accumulator_is_byte_identical(monkeypatch):

    def _run(**kwargs):
        rpc = _CappedRpc(lambda lo, hi: 3)
        fetcher = _fetcher(monkeypatch, rpc, max_block_range=50_000, min_bisect_span=10_000)
        logs = fetcher.fetch_logs(
            event_address=_ADDR, topics=[_TOPIC_DENY_TO], from_block=0, to_block=120_000, **kwargs
        )
        return rpc.windows, logs

    without_windows, without_logs = _run()
    with_windows, with_logs = _run(window_stats=[])
    assert without_windows == with_windows == [(0, 49_999), (50_000, 99_999), (100_000, 120_000)]
    assert without_logs == with_logs


def test_error_bisect_path_is_untouched(monkeypatch):
    windows: list[tuple[int, int]] = []

    def _rpc(url, method, params, chain_id=None):
        lo, hi = int(params[0]["fromBlock"], 16), int(params[0]["toBlock"], 16)
        windows.append((lo, hi))
        raise RuntimeError("Limit exceeded")

    fetcher = _fetcher(monkeypatch, _rpc, max_block_range=1_000_000, min_bisect_span=10_000)
    with pytest.raises(RuntimeError, match="Limit exceeded"):
        fetcher.fetch_logs(event_address=_ADDR, topics=[_TOPIC_DENY_TO], from_block=0, to_block=39_999)
    assert windows[:3] == [(0, 39_999), (0, 19_999), (0, 9_999)]


# The indexer records what its pages returned


class _StatsFetcher:
    def __init__(self, count: int, cap: int | None) -> None:
        self.count = count
        self.cap = cap

    def fetch_logs(self, *, event_address, topics, from_block, to_block, window_stats=None):
        if window_stats is not None:
            window_stats.append(
                FetchWindowStat(from_block=from_block, to_block=to_block, returned_log_count=self.count, cap=self.cap)
            )
        return []


class _StatelessFetcher:
    def fetch_logs(self, *, event_address, topics, from_block, to_block):
        return []


class _NoHash:
    def block_hash(self, block_number: int):
        return None


@requires_postgres
@pytest.mark.parametrize(
    "fetcher,expected_max,expected_cap,expected_basis",
    [
        (_StatsFetcher(7, 100), 7, 100, WINDOW_STATS_CONTINUOUS),
        (_StatsFetcher(7, None), 7, None, "not_determined"),
        (_StatelessFetcher(), None, None, "not_determined"),
    ],
)
def test_advancing_records_page_stats_or_downgrades(db_session, fetcher, expected_max, expected_cap, expected_basis):
    """Absent measurement is not a measurement of absence."""
    enroll_event_cursor(
        db_session,
        chain_id=1,
        event_address=_ADDR,
        topic0=_TOPIC_DENY_TO,
        start_block=_SEED,
        first_indexed_block=_SEED,
        first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION,
    )
    db_session.commit()
    assert _row(db_session, topic0=_TOPIC_DENY_TO).window_stats_basis == WINDOW_STATS_CONTINUOUS
    for _ in index_event_group_steps(
        db_session,
        chain_id=1,
        event_address=_ADDR,
        fetcher=fetcher,
        target=_SEED + 5_000,
        block_hash_fetcher=_NoHash(),
        limits=PageLimits(max_block_span=1_000),
    ):
        db_session.commit()
    cursor = _row(db_session, topic0=_TOPIC_DENY_TO)
    assert cursor.max_window_log_count == expected_max
    assert cursor.window_stats_cap == expected_cap
    assert cursor.window_stats_basis == expected_basis
