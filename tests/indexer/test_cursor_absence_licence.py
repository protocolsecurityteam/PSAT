"""D4 — what an event cursor proves about absence, and what it does not.

Absence of a log was treated as proof that an event never fired. Three things
that had to be true for that were never checked:

  * (a) the covered range's LOWER bound was not persisted at all. A cursor
    seeded at a deploy block and warm to head reads identically to one seeded
    above the first write.
  * (b) cursors were only ever enrolled from ``enumeration_hint`` records, which
    the static pass attaches only to caller-keyed mappings. A denylist keyed on
    the transfer RECIPIENT gets no hint at any emitter, so its writers had no
    cursor anywhere and its history was never indexed.
  * (c) a silently truncated 200-OK ``eth_getLogs`` page advanced the cursor
    past logs that were never returned. Only a raised error bisected.

These tests pin the honest states, and — the load-bearing half — pin that the
new evidence does NOT combine into a licence. Enrolling from a tracking plan
gathers history it could not see before; it must never turn a zero-row fold into
"this variable was never written", because the plan attributes topics to no
variable at all.
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
    _authority_has_role_store_cursor,
    _witness_seed_block,
    enroll_event_cursor,
    enroll_from_tracked_topics,
    index_event_group_step,
)

# The lane-D specimen: 0x3994741a…, whose code is empty at 20265588 and present
# at 20265589 (both reads reproduced against the pinned chain).
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
    """Pinned responses for the three-read witness, keyed by method+block."""

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
        # The creation block is the SEED the witness grades; it is not the proof,
        # so it is stubbed separately from the three pinned reads that are.
        monkeypatch.setattr(eli, "get_contract_creation_block", lambda *_a, **_k: _SEED + 1)
        return stub

    return _install


# ---------------------------------------------------------------------------
# D4(a) — the persisted lower bound and its three-read witness
# ---------------------------------------------------------------------------


@requires_postgres
def test_enrol_persists_the_witnessed_lower_bound_byte_exactly(db_session):
    """Arm 1. A cursor enrolled with a graded witness carries the bound AND what
    proves it, and is not yet backfilled."""
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
    """Arm 2, fail-closed. ``start_block``'s ``= 0`` default sits directly above
    the provenance arguments; omitting them must NOT inherit it as a claim that
    the range is covered from genesis — and the resulting row must actually be
    refused downstream, not merely labelled."""
    assert enroll_event_cursor(db_session, chain_id=1, event_address=_ADDR, topic0=_TOPIC_ALLOW_TO)
    db_session.execute(text("UPDATE indexed_event_cursors SET backfill_complete = true, last_indexed_block = 25000000"))
    db_session.commit()
    cursor = _row(db_session)
    assert cursor.first_indexed_block is None
    assert cursor.first_indexed_block_basis == "not_determined"
    assert cursor.enrollment_basis == "not_determined"
    # The label is worth nothing unless the gate acts on it.
    result = _fold(db_session, _TOPIC_ALLOW_TO)
    assert (result.confidence, result.partial_reason) == ("partial", "no_index_cursor")


def test_witness_requires_all_three_reads_to_agree(stub_rpc):
    """The empty→code transition alone is a necessary condition, not the proof.
    All three reads agreeing is what earns the basis."""
    stub = stub_rpc()
    assert _witness_seed_block(_ADDR, _SEED, {}, chain_id=1) == (_SEED, FIRST_INDEXED_BASIS_CREATION)
    assert [m for m, _ in stub.calls] == ["eth_getCode", "eth_getCode", "eth_getLogs"]
    # The third read is genesis-anchored, address-scoped, and carries NO topic
    # filter — any log of any kind below the seed refutes the bound.
    _method, params = stub.calls[-1]
    assert params == [{"address": _ADDR, "fromBlock": "0x0", "toBlock": hex(_SEED)}]


def test_witness_rejects_a_prior_incarnation_and_discards_the_number(stub_rpc):
    """A2 falsifier. Code appearing at B proves a deployment landed there, not
    that it was the first — a CREATE2 redeploy over a pre-Cancun-cleared address
    reads identically. A log below the seed refutes the bound, and the block is
    DISCARDED rather than kept as an unqualified number."""
    stub_rpc(prior_logs=[{"blockNumber": "0x1"}])
    assert _witness_seed_block(_ADDR, _SEED, {}, chain_id=1) == (None, "not_determined")


def test_witness_rejects_an_eip7702_delegation_stub(stub_rpc):
    """A2 falsifier. A 0xef0100‖address stub is code that was never deployed and
    can be set and cleared repeatedly, so the transition dates nothing."""
    stub_rpc(code_at=_EIP7702_STUB)
    assert _witness_seed_block(_ADDR, _SEED, {}, chain_id=1) == (None, "not_determined")


def test_witness_failure_yields_not_determined_never_a_bound(stub_rpc):
    """A2 falsifier. Every failure path lands on not_determined with no number."""
    stub_rpc(raise_on="eth_getLogs")
    assert _witness_seed_block(_ADDR, _SEED, {}, chain_id=1) == (None, "not_determined")
    stub_rpc(raise_on="eth_getCode")
    assert _witness_seed_block(_ADDR, _SEED, {}, chain_id=1) == (None, "not_determined")
    stub_rpc(code_before=_CODE)
    assert _witness_seed_block(_ADDR, _SEED, {}, chain_id=1) == (None, "not_determined")


@requires_postgres
def test_legacy_null_lower_bound_publishes_not_determined_never_zero(db_session):
    """Arm 5. A row that predates the column means "the lower bound is unknown".
    Read as 0 it would assert coverage from genesis — the strongest possible
    claim, minted from a missing value."""
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
    """A4. The legacy token must not read as a completeness measurement, and the
    counts stay NULL — a 0 there would be a measured empty page."""
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


# ---------------------------------------------------------------------------
# D4(b) — enrolment from tracking plans, and the ceiling that stays a ceiling
# ---------------------------------------------------------------------------


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
    """R2. The per-pass budget bounds addresses that still NEED a cursor, not
    rows inspected. Bounding rows would re-walk the same head of the ordering
    every pass, leaving the tail permanently unenrolled while the counter
    reported progress — and which addresses those are would depend on an id
    ordering nothing records."""
    stub_rpc()
    # From 1: ``0x0…0`` is correctly refused by ``_is_enrollable_event_address``
    # (no creation block, so it would seed at genesis), and counting it here would
    # make the arm test the guard rather than the draining.
    for i in range(1, 61):
        _monitored(db_session, [_TOPIC_DENY_TO], address="0x" + f"{i:040x}")
    assert enroll_from_tracked_topics(db_session, limit=50) == 50
    # Second pass must reach ranks 51-60, not re-inspect the first 50.
    assert enroll_from_tracked_topics(db_session, limit=50) == 10
    assert db_session.execute(select(func.count()).select_from(IndexedEventCursor)).scalar_one() == 60
    # Settled: a fully enrolled fleet costs no budget and no RPC.
    assert enroll_from_tracked_topics(db_session, limit=50) == 0


@requires_postgres
def test_tracked_topics_enrol_the_writers_no_hint_ever_reached(db_session, stub_rpc):
    """Arm 9. AllowTo/DenyTo key their mapping on the transfer RECIPIENT, so the
    static pass attaches no hint and nothing enrolled them. The tracking plan
    already names them; enrolling from it is what makes their history
    observable at all."""
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
    """Arm 9 fail-closed. An unresolvable chain is skipped rather than guessed as
    mainnet, and an inactive row is not a monitoring surface."""
    stub_rpc()
    _monitored(db_session, _DENYLIST_SURFACE, chain="not-a-real-chain")
    assert enroll_from_tracked_topics(db_session) == 0
    _monitored(db_session, _DENYLIST_SURFACE, chain="ethereum", active=False)
    assert enroll_from_tracked_topics(db_session) == 0
    assert db_session.execute(select(IndexedEventCursor)).first() is None


@requires_postgres
def test_coverage_gate_reports_missing_writers_and_licenses_nothing(db_session, stub_rpc):
    """Arm 6. With two of six writers unenrolled the report names them — and the
    earned negative is refused, which it would be even if none were missing."""
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
    """Arm 7 / A3 falsifier — the one that matters.

    Every condition a consumer could check is satisfied: all six writers
    enrolled, warm, lower bound witnessed, every page sub-cap under the cap
    actually in force. The verdict is still false, because the caller's belief
    about which topics write the variable is not a witness — a direct
    ``_roles[role].members[x] = true`` write, or an implementation swapped
    behind a proxy, emits none of them.
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
    """A cursor that exists but is not warm proves nothing about absence, and is
    reported separately from one that does not exist at all."""
    enroll_event_cursor(db_session, chain_id=1, event_address=_ADDR, topic0=_TOPIC_ALLOW_TO)
    db_session.commit()
    report = absence_coverage(db_session, chain_id=1, address=_ADDR, write_surface_topics=[_TOPIC_ALLOW_TO])
    assert report["enrolled"] == [_TOPIC_ALLOW_TO]
    assert report["warm"] == []
    assert REASON_COLD_CURSORS in report["blocking_reasons"]


# ---------------------------------------------------------------------------
# A1 — a tracking-plan cursor never becomes an exactness source
# ---------------------------------------------------------------------------


@requires_postgres
@pytest.mark.parametrize(
    "basis",
    [
        ENROLLMENT_BASIS_TRACKED_TOPICS,
        # The literal default ``enroll_event_cursor`` writes when a caller omits
        # the argument. A deny-list on the tracking-plan token alone would have
        # folded this one enumerable — the fail-open was already in the schema.
        "not_determined",
        # Any token nobody has thought of yet. A new enrolment source is inert
        # until someone deliberately adds it to the allow-list.
        "code_asserted_pubkey_fold",
    ],
)
def test_ineligible_basis_cannot_mint_an_exact_empty(db_session, basis):
    """R1 falsifier. Warm, at head, zero matching rows — the exact shape that
    publishes "this event never fired". Only an allow-listed basis may support
    it; every other value, recognised or not, folds partial."""
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
def test_legacy_and_hint_cursors_still_fold_enumerable(db_session):
    """R1 companion. The allow-list admits exactly two shapes, so rows that
    predate the column (NULL) and rows enrolled from a static hint keep folding
    exactly as before — inverting the gate did not demote them, and the deferral
    of the wider lower-bound gate is not silently broken here."""
    for topic, basis in ((_TOPIC_ALLOW_TO, None), (_TOPIC_ALLOW_FROM, ENROLLMENT_BASIS_PREDICATE_HINT)):
        enroll_event_cursor(
            db_session, chain_id=1, event_address=_ADDR, topic0=topic, start_block=_SEED, enrollment_basis=basis
        )
    db_session.execute(text("UPDATE indexed_event_cursors SET backfill_complete = true, last_indexed_block = 25000000"))
    db_session.execute(
        text("UPDATE indexed_event_cursors SET enrollment_basis = NULL WHERE topic0 = :t"),
        {"t": _TOPIC_ALLOW_TO},
    )
    db_session.commit()
    for topic in (_TOPIC_ALLOW_TO, _TOPIC_ALLOW_FROM):
        result = _fold(db_session, topic)
        assert result.confidence == "enumerable", topic
        assert result.partial_reason is None


@requires_postgres
def test_refused_cursor_is_not_reported_warm(db_session):
    """R7. ``warm`` must agree with what the gate does. A refused cursor reported
    as warm would say the recording surface is covered by a cursor that folds as
    cold."""
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
    """R7. Lower-casing after the ``0x`` prefix test threw away an uppercase
    topic, shortening ``missing`` — the caller would be told a writer is covered
    because its topic never survived the door."""
    report = absence_coverage(db_session, chain_id=1, address=_ADDR, write_surface_topics=[_TOPIC_DENY_TO.upper()])
    assert report["write_surface_asserted"] == [_TOPIC_DENY_TO]
    assert report["missing"] == [_TOPIC_DENY_TO]


@requires_postgres
def test_out_of_band_readers_ignore_refused_cursors(db_session):
    """R5. Both readers answer "is there a usable cursor here". A refused cursor
    that counted would skip the detection that enrols the attributed one, and
    would tell the reconciler the index caught up while the fold still reads
    cold — a permanently-skipped upgrade and a per-pass re-enqueue thrash."""
    # A real role-STORE topic (AccessControl RoleGranted family) — the set
    # ``_authority_has_role_store_cursor`` actually looks at.
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
    assert _authority_has_role_store_cursor(db_session, 1, _ADDR) is True
    assert _authority_backfilled(db_session, 1, _ADDR) is True


# ---------------------------------------------------------------------------
# D4(c) — a page at the cap is a reject, not a result
# ---------------------------------------------------------------------------


class _CappedRpc:
    """Returns ``count_for(from, to)`` synthetic logs and records every window."""

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
    """Arm 8. A 200-OK page whose length reaches the cap is indistinguishable
    from a truncated one, so it takes the same bisect an error takes. The halves
    are the existing split, unchanged."""
    rpc = _CappedRpc(lambda lo, hi: 100 if (lo, hi) == (0, 99_999) else 1)
    fetcher = _fetcher(monkeypatch, rpc, max_block_range=1_000_000, min_bisect_span=10_000, result_cap=100)
    fetcher.fetch_logs(event_address=_ADDR, topics=[_TOPIC_DENY_TO], from_block=0, to_block=99_999)
    assert rpc.windows[0] == (0, 99_999)
    assert rpc.windows[1:3] == [(0, 49_999), (50_000, 99_999)]


def test_page_at_the_cap_on_the_floor_span_raises(monkeypatch):
    """Arm 8. At the bisect floor there is nowhere left to narrow, so the only
    honest outcome is to fail — never to accept a page that cannot be proven
    whole and advance the cursor over it."""
    rpc = _CappedRpc(lambda lo, hi: 100)
    fetcher = _fetcher(monkeypatch, rpc, max_block_range=1_000_000, min_bisect_span=10_000, result_cap=100)
    with pytest.raises(RuntimeError, match="result cap"):
        fetcher.fetch_logs(event_address=_ADDR, topics=[_TOPIC_DENY_TO], from_block=0, to_block=9_999)


def test_page_below_the_cap_is_accepted_and_counted(monkeypatch):
    """Arm 8. No false positives: one under the cap is a whole page, recorded
    with the cap that gated it."""
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
    """A5. The guard must read ``cap is not None and len(...) >= cap`` literally:
    an unguarded comparison against None raises TypeError, which is not
    RuntimeError and would escape the bisect entirely."""
    rpc = _CappedRpc(lambda lo, hi: 125_629)
    fetcher = _fetcher(monkeypatch, rpc, min_bisect_span=10_000, result_cap=None)
    stats: list[FetchWindowStat] = []
    fetcher.fetch_logs(event_address=_ADDR, topics=[_TOPIC_DENY_TO], from_block=0, to_block=9_999, window_stats=stats)
    assert rpc.windows == [(0, 9_999)]
    assert stats[0].cap is None


@pytest.mark.parametrize("payload", [None, {}, "0x", 0])
def test_unreadable_page_is_not_recorded_as_zero_logs(monkeypatch, payload):
    """R3. A 200-OK body that is not a list is a page we could not read, not a
    page of zero logs. Counting it as 0 would mint a proven empty window out of
    a malformed payload."""

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
    """R3. The downgrade has to reach the cursor, or the malformed window is
    invisible to the completeness verdict and the range reads proven."""

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
    index_event_group_step(
        db_session,
        chain_id=1,
        event_address=_ADDR,
        topics=[_TOPIC_DENY_TO],
        fetcher=_BadFetcher(),
        target=_SEED + 5_000,
        block_hash_fetcher=_NoHash(),
        max_block_span=1_000,
    )
    db_session.commit()
    cursor = _row(db_session, topic0=_TOPIC_DENY_TO)
    assert cursor.max_window_log_count is None
    assert cursor.window_stats_basis == "not_determined"
    report = absence_coverage(db_session, chain_id=1, address=_ADDR, configured_cap=100)
    assert report["page_completeness"] == "not_determined"


def test_watcher_construction_does_not_inherit_the_env_cap(monkeypatch):
    """R8. ``_fetch_range`` is shared with the monitoring watcher, which does not
    persist window counts and must keep returning pages. Setting the indexer's
    cap must not silently give the watcher bisect-and-raise behaviour."""
    monkeypatch.setenv("PSAT_GETLOGS_RESULT_CAP", "50000")
    assert default_result_cap() == 50_000
    # The watcher's construction shape (services/monitoring/unified_watcher.py).
    watcher_fetcher = RpcEventLogFetcher("http://stub", max_block_range=10_000, min_bisect_span=1_000, chain_id=1)
    assert watcher_fetcher.result_cap is None
    # The indexer's builder is the one place that opts in.
    assert RpcEventLogFetcher("http://stub", chain_id=1, result_cap=default_result_cap()).result_cap == 50_000


def test_default_result_cap_is_unset_and_ignores_junk(monkeypatch):
    """The shipped default is "no cap is known", and a malformed override does
    not become one."""
    monkeypatch.delenv("PSAT_GETLOGS_RESULT_CAP", raising=False)
    assert default_result_cap() is None
    monkeypatch.setenv("PSAT_GETLOGS_RESULT_CAP", "not-a-number")
    assert default_result_cap() is None
    monkeypatch.setenv("PSAT_GETLOGS_RESULT_CAP", "50000")
    assert default_result_cap() == 50_000


@requires_postgres
def test_completeness_is_refused_when_the_cap_in_force_changed(db_session):
    """A5 falsifier. Pages accepted under one guard say nothing about a different
    guard. Raising the cap must not silently re-grade history that was never
    fetched under it."""
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


# ---------------------------------------------------------------------------
# A6 — the shared fetcher's behaviour is unchanged for callers without stats
# ---------------------------------------------------------------------------


def test_fetch_without_accumulator_is_byte_identical(monkeypatch):
    """A6. ``_fetch_range`` is shared with the monitoring watcher, which passes no
    accumulator. Same request sequence, same logs, with the cap unset."""

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
    """A6. The pre-existing raise-driven bisect keeps its exact split and its
    raise-at-the-floor behaviour."""
    windows: list[tuple[int, int]] = []

    def _rpc(url, method, params, chain_id=None):
        lo, hi = int(params[0]["fromBlock"], 16), int(params[0]["toBlock"], 16)
        windows.append((lo, hi))
        raise RuntimeError("Limit exceeded")

    fetcher = _fetcher(monkeypatch, _rpc, max_block_range=1_000_000, min_bisect_span=10_000)
    with pytest.raises(RuntimeError, match="Limit exceeded"):
        fetcher.fetch_logs(event_address=_ADDR, topics=[_TOPIC_DENY_TO], from_block=0, to_block=39_999)
    assert windows[:3] == [(0, 39_999), (0, 19_999), (0, 9_999)]


# ---------------------------------------------------------------------------
# The indexer records what its pages returned
# ---------------------------------------------------------------------------


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
    """A cursor that advances records what its pages returned. A fetcher that
    records nothing downgrades the cursor instead of leaving a stale claim — an
    absent measurement is not a measurement of absence."""
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
    index_event_group_step(
        db_session,
        chain_id=1,
        event_address=_ADDR,
        topics=[_TOPIC_DENY_TO],
        fetcher=fetcher,
        target=_SEED + 5_000,
        block_hash_fetcher=_NoHash(),
        max_block_span=1_000,
    )
    db_session.commit()
    cursor = _row(db_session, topic0=_TOPIC_DENY_TO)
    assert cursor.max_window_log_count == expected_max
    assert cursor.window_stats_cap == expected_cap
    assert cursor.window_stats_basis == expected_basis
