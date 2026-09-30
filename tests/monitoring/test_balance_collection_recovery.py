
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from db.models import Contract, ContractBalanceFetch, ContractBalanceLatest, Protocol
from db.models.balance_collection import BalanceCollectionState
from services.clients.etherscan import TokenBalancePage
from services.monitoring.balance_collection import (
    CollectionSubject,
    claim_read,
    collect_balances,
    finish_read,
)
from services.monitoring.balance_observation import NativeReading, record_observation
from services.monitoring.balance_reads import ObservationSubject, partial_asset_rows
from tests.conftest import requires_postgres

pytestmark = requires_postgres
TOKEN_A = "0x" + "a1" * 20
TOKEN_B = "0x" + "b2" * 20


def token(address=TOKEN_A, quantity=10):
    return dict(
        token_address=address,
        token_name="Token",
        token_symbol="T",
        decimals=0,
        decimals_reported=True,
        balance=quantity,
        price_usd=2,
        usd_value=quantity * 2,
    )


def make_target(session):
    protocol = Protocol(name="balance-regression-" + uuid4().hex)
    session.add(protocol)
    session.flush()
    contract = Contract(protocol_id=protocol.id, address="0x" + uuid4().hex + "00000000", chain="ethereum")
    session.add(contract)
    session.commit()
    return protocol, CollectionSubject(ObservationSubject.of_contract(contract), 1)


def native(attempted=False):
    return NativeReading(None, None, False, None, "ETH", "Ether", attempted=attempted)


def write(session, target, rows, status, when=None):
    return record_observation(
        session,
        subject=target.subject,
        chain_id=1,
        native=native(),
        page=TokenBalancePage(rows, len(rows), status, basis="test index"),
        writer="tvl",
        observed_at=when,
    )


def test_partial_does_not_replace_snapshot_or_prune_tail(db_session):
    protocol, target = make_target(db_session)
    now = datetime.now(timezone.utc)
    full = write(db_session, target, [token(), token(TOKEN_B)], "returned_assets", now - timedelta(hours=2))
    full_id = full.fetch.id
    for index in range(15):
        write(db_session, target, [token(quantity=index + 1)], "at_page_cap", now + timedelta(seconds=index))
    db_session.commit()
    current = list(
        db_session.scalars(
            select(ContractBalanceLatest).where(ContractBalanceLatest.contract_id == target.subject.contract_id)
        )
    )
    assert {r.token_address for r in current} == {TOKEN_A, TOKEN_B}
    assert {r.fetch_id for r in current} == {full_id}
    assert target.subject.contract_id is not None
    prefix = partial_asset_rows(db_session, protocol.id)[target.subject.contract_id]
    assert len(prefix) == 1 and prefix[0].raw_balance == "15"
    assert db_session.get(ContractBalanceFetch, full_id) is not None


def test_partial_first_is_visible_and_unknown_metadata_stays_unknown(db_session):
    protocol, target = make_target(db_session)
    entry = token()
    entry["decimals_reported"] = False
    write(db_session, target, [entry], "at_page_cap")
    db_session.commit()
    row = db_session.scalar(
        select(ContractBalanceLatest).where(ContractBalanceLatest.contract_id == target.subject.contract_id)
    )
    assert row.decimals_known is False and row.usd_value is None and row.price_usd is None


def test_old_lease_cannot_publish_after_new_generation(db_session):
    _, target = make_target(db_session)
    factory = sessionmaker(bind=db_session.get_bind(), expire_on_commit=False)
    first = claim_read(target, "tokens", session_factory=factory)
    state = db_session.get(BalanceCollectionState, (1, target.subject.address.lower(), "tokens"))
    state.lease_until = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()
    second = claim_read(target, "tokens", session_factory=factory)
    payload = dict(rows=[token()], page_length=1, status="returned_assets", pages_read=1, basis="test")
    assert finish_read(second, payload, outcome="success", writer="tvl", ttl=3600, session_factory=factory)
    payload["rows"] = [token(quantity=99)]
    assert not finish_read(first, payload, outcome="success", writer="tvl", ttl=3600, session_factory=factory)
    db_session.expire_all()
    row = db_session.scalar(
        select(ContractBalanceLatest).where(ContractBalanceLatest.contract_id == target.subject.contract_id)
    )
    assert row.raw_balance == "10"


def test_native_success_token_failure_survives_and_retries_only_failed_class(db_session, monkeypatch):
    _, target = make_target(db_session)
    factory = sessionmaker(bind=db_session.get_bind(), expire_on_commit=False)
    import services.monitoring.balance_collection as collector

    counts = {"native": 0, "tokens": 0}

    def pinned(addresses, **kwargs):
        counts["native"] += 1
        return 100, {a.lower(): 10**18 for a in addresses}

    def page(*args, **kwargs):
        counts["tokens"] += 1
        return TokenBalancePage([], None, "fetch_failed")

    monkeypatch.setattr(collector, "pinned_native_balances", pinned)
    monkeypatch.setattr(collector, "get_native_price", lambda chain: 2000)
    monkeypatch.setattr(collector, "fetch_asset_page", page)
    monkeypatch.setattr(collector, "get_eth_balance", lambda *a, **k: pytest.fail("unnecessary native fallback"))
    first = collect_balances([target], writer="tvl", session_factory=factory)
    assert first.failed == 1 and first.committed == 2
    second = collect_balances([target], writer="tvl", session_factory=factory)
    assert counts == {"native": 1, "tokens": 1}
    assert second.reused == 1 and second.deferred == 1
    state = db_session.get(BalanceCollectionState, (1, target.subject.address.lower(), "tokens"))
    state.next_attempt_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()
    monkeypatch.setattr(
        collector, "fetch_asset_page", lambda *a, **k: TokenBalancePage([token()], 1, "returned_assets")
    )
    collect_balances([target], writer="tvl", session_factory=factory)
    db_session.expire_all()
    rows = list(
        db_session.scalars(
            select(ContractBalanceLatest).where(ContractBalanceLatest.contract_id == target.subject.contract_id)
        )
    )
    assert {r.token_address for r in rows} == {None, TOKEN_A}
    assert counts["native"] == 1


def test_shared_entity_read_reused_without_duplicate_observations(db_session, monkeypatch):
    # One canonical identity even when two protocols include the same EOA.
    address = "0x" + uuid4().hex + "00000000"
    target = CollectionSubject(ObservationSubject.of_entity("ethereum", address), 1)
    factory = sessionmaker(bind=db_session.get_bind(), expire_on_commit=False)
    import services.monitoring.balance_collection as collector

    calls = []
    monkeypatch.setattr(collector, "pinned_native_balances", lambda addrs, **kw: (100, {a.lower(): 1 for a in addrs}))
    monkeypatch.setattr(collector, "get_native_price", lambda chain: 2000)

    def page(*a, **kw):
        calls.append(1)
        return TokenBalancePage([token()], 1, "returned_assets")

    monkeypatch.setattr(collector, "fetch_asset_page", page)
    collect_balances([target], writer="tvl", session_factory=factory)
    collect_balances([target], writer="tvl", session_factory=factory)
    assert len(calls) == 1
    rows = list(
        db_session.scalars(
            select(ContractBalanceLatest).where(
                ContractBalanceLatest.entity_address == address, ContractBalanceLatest.token_address == TOKEN_A
            )
        )
    )
    assert len(rows) == 1 and rows[0].contract_id is None


def test_quote_recovers_without_repeating_quantities_or_changing_their_time(db_session, monkeypatch):
    import services.monitoring.balance_collection as collector

    _, target = make_target(db_session)
    factory = sessionmaker(bind=db_session.get_bind(), expire_on_commit=False)
    reads = []
    monkeypatch.setattr(
        collector,
        "pinned_native_balances",
        lambda addresses, **kw: (reads.append(1) or 100, {a: 10**18 for a in addresses}),
    )
    monkeypatch.setattr(collector, "get_native_price", lambda chain: None)
    monkeypatch.setattr(collector, "fetch_asset_page", lambda *a, **kw: TokenBalancePage([], 0, "returned_empty"))
    collect_balances([target], writer="tvl", session_factory=factory)
    query = select(ContractBalanceLatest).where(
        ContractBalanceLatest.contract_id == target.subject.contract_id, ContractBalanceLatest.token_address.is_(None)
    )
    first = db_session.scalar(query)
    observed_at = first.observed_at
    assert first.usd_value is None
    quote = db_session.get(BalanceCollectionState, (1, "0x" + "0" * 40, "native_quote"))
    quote.next_attempt_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()
    monkeypatch.setattr(collector, "get_native_price", lambda chain: 2000)
    collect_balances([target], writer="tvl", session_factory=factory)
    db_session.expire_all()
    priced = db_session.scalar(query)
    assert priced.usd_value == 2000
    assert priced.observed_at == observed_at
    assert priced.price_observed_at > observed_at
    assert len(reads) == 1


def test_quote_budget_exhaustion_preserves_acquired_native_and_releases_other_claims(db_session, monkeypatch):
    import services.monitoring.balance_collection as collector
    from services.clients.request_budget import RequestBudget, charge_attempt

    _, target = make_target(db_session)
    factory = sessionmaker(bind=db_session.get_bind(), expire_on_commit=False)

    def pinned(addresses, **kwargs):
        charge_attempt("rpc")
        return 100, {a: 10**18 for a in addresses}

    def quote(chain):
        charge_attempt("etherscan")
        return 2000

    monkeypatch.setattr(collector, "pinned_native_balances", pinned)
    monkeypatch.setattr(collector, "get_native_price", quote)
    report = collect_balances([target], writer="tvl", session_factory=factory, budget=RequestBudget(limit=1))
    row = db_session.scalar(
        select(ContractBalanceLatest).where(ContractBalanceLatest.contract_id == target.subject.contract_id)
    )
    assert row.raw_balance == str(10**18) and row.usd_value is None
    assert report.committed == 1 and report.deferred == 1
    states = db_session.scalars(select(BalanceCollectionState)).all()
    assert all(state.lease_owner is None for state in states)


def test_bounded_pass_rotates_to_unread_protocol(db_session, monkeypatch):
    import services.monitoring.balance_collection as collector

    _, first = make_target(db_session)
    _, second = make_target(db_session)
    factory = sessionmaker(bind=db_session.get_bind(), expire_on_commit=False)
    monkeypatch.setenv("PSAT_BALANCE_SUBJECTS_PER_PASS", "1")
    monkeypatch.setattr(collector, "pinned_native_balances", lambda addresses, **kw: (100, {a: 1 for a in addresses}))
    monkeypatch.setattr(collector, "get_native_price", lambda chain: 2000)
    seen = []

    def page(address, **kwargs):
        seen.append(address)
        return TokenBalancePage([], None, "fetch_failed")

    monkeypatch.setattr(collector, "fetch_asset_page", page)
    collect_balances([first, second], writer="tvl", session_factory=factory)
    collect_balances([first, second], writer="tvl", session_factory=factory)
    assert set(seen) == {first.subject.address, second.subject.address}
    assert len(seen) == 2


def test_shorter_consumer_freshness_overrides_daily_success_but_not_failure_backoff(db_session):
    from services.monitoring.balance_collection import order_subjects, release_claim

    _, target = make_target(db_session)
    factory = sessionmaker(bind=db_session.get_bind(), expire_on_commit=False)
    now = datetime.now(timezone.utc)
    for read_class in ("native", "tokens"):
        db_session.add(
            BalanceCollectionState(
                chain_id=1,
                address=target.subject.address.lower(),
                read_class=read_class,
                outcome="success",
                observed_at=now - timedelta(hours=2),
                last_attempt_at=now - timedelta(hours=2),
                next_attempt_at=now + timedelta(hours=22),
                failures=0,
            )
        )
    db_session.commit()
    _, daily_due = order_subjects([target], ttl=86400, session_factory=factory)
    _, hourly_due = order_subjects([target], ttl=3600, session_factory=factory)
    assert not daily_due and hourly_due == {(1, target.subject.address.lower())}
    daily = claim_read(target, "native", max_age_seconds=86400, session_factory=factory)
    assert daily.reason == "fresh"
    hourly = claim_read(target, "native", max_age_seconds=3600, session_factory=factory)
    assert hourly.owner is not None
    release_claim(hourly, session_factory=factory)
    db_session.expire_all()
    state = db_session.get(BalanceCollectionState, (1, target.subject.address.lower(), "native"))
    state.failures = 2
    state.outcome = "failed"
    state.next_attempt_at = now + timedelta(minutes=10)
    db_session.commit()
    retry = claim_read(target, "native", max_age_seconds=3600, session_factory=factory)
    assert retry.owner is None and retry.reason == "backoff"


def test_aggregate_failure_does_not_rollback_or_refetch_successful_observations(db_session, monkeypatch):
    import services.monitoring.balance_collection as collector
    import services.monitoring.tvl as tvl

    protocol, target = make_target(db_session)
    protocol_id = protocol.id
    counts = {"native": 0, "tokens": 0}

    def pinned(addresses, **kwargs):
        counts["native"] += 1
        return 100, {a: 10**18 for a in addresses}

    def page(*args, **kwargs):
        counts["tokens"] += 1
        return TokenBalancePage([token()], 1, "returned_assets")

    def failed_aggregate(*args, **kwargs):
        raise RuntimeError("simulated failure after quantity commits")

    monkeypatch.setattr(collector, "pinned_native_balances", pinned)
    monkeypatch.setattr(collector, "fetch_asset_page", page)
    monkeypatch.setattr(collector, "get_native_price", lambda chain: 2000)
    monkeypatch.setattr(tvl, "fetch_defillama_tvl", failed_aggregate)
    with pytest.raises(RuntimeError, match="after quantity commits"):
        tvl.take_tvl_snapshot(db_session, protocol_id)
    db_session.rollback()
    rows = db_session.scalars(
        select(ContractBalanceLatest).where(ContractBalanceLatest.contract_id == target.subject.contract_id)
    ).all()
    assert {r.token_address for r in rows} == {None, TOKEN_A}
    monkeypatch.setattr(tvl, "fetch_defillama_tvl", lambda name: None)
    snapshot, _ = tvl.take_tvl_snapshot(db_session, protocol_id)
    assert snapshot is not None and snapshot.total_usd == 2020
    assert counts == {"native": 1, "tokens": 1}


@pytest.mark.parametrize("limit", [2, 64])
def test_tight_hourly_budget_eventually_attempts_every_account_and_class(db_session, monkeypatch, limit):
    import services.monitoring.balance_collection as collector
    from services.clients.request_budget import RequestBudget, charge_attempt

    targets = [make_target(db_session)[1] for _ in range(6)]
    factory = sessionmaker(bind=db_session.get_bind(), expire_on_commit=False)
    monkeypatch.setenv("PSAT_BALANCE_SUBJECTS_PER_PASS", str(limit))
    seen_native, seen_tokens = set(), set()

    def pinned(addresses, **kwargs):
        charge_attempt("rpc")
        charge_attempt("rpc")
        seen_native.update(addresses)
        return 100, {a: 10**18 for a in addresses}

    def quote(chain):
        charge_attempt("etherscan")
        return 2000

    def page(address, **kwargs):
        charge_attempt("etherscan")
        seen_tokens.add(address)
        return TokenBalancePage([], 0, "returned_empty")

    monkeypatch.setattr(collector, "pinned_native_balances", pinned)
    monkeypatch.setattr(collector, "get_native_price", quote)
    monkeypatch.setattr(collector, "fetch_asset_page", page)
    for _ in range(10):
        budget = RequestBudget(limit=4)
        collect_balances(targets, writer="tvl", session_factory=factory, budget=budget)
        assert sum(budget.attempts.values()) <= 4
        db_session.expire_all()
        for state in db_session.scalars(select(BalanceCollectionState)):
            for name in ("last_attempt_at", "next_attempt_at", "observed_at"):
                value = getattr(state, name)
                if value is not None:
                    setattr(state, name, value - timedelta(hours=2))
        db_session.commit()
    expected = {t.subject.address for t in targets}
    assert seen_native == seen_tokens == expected


def test_budget_does_not_claim_or_postpone_unattempted_accounts(db_session, monkeypatch):
    import services.monitoring.balance_collection as collector
    from services.clients.request_budget import RequestBudget, charge_attempt

    targets = [make_target(db_session)[1] for _ in range(4)]
    factory = sessionmaker(bind=db_session.get_bind(), expire_on_commit=False)
    monkeypatch.setattr(
        collector,
        "pinned_native_balances",
        lambda addresses, **kw: (charge_attempt("rpc") or 100, {a: 0 for a in addresses}),
    )
    monkeypatch.setattr(collector, "get_native_price", lambda chain: charge_attempt("etherscan") or 2000)
    collect_balances(targets, writer="tvl", session_factory=factory, budget=RequestBudget(limit=1))
    db_session.expire_all()
    assert not db_session.scalars(
        select(BalanceCollectionState).where(BalanceCollectionState.read_class == "tokens")
    ).all()


def test_warm_collection_is_read_only_and_does_not_repeat_provider_work(db_session, monkeypatch):
    from sqlalchemy import event

    import services.monitoring.balance_collection as collector

    targets = [make_target(db_session)[1] for _ in range(64)]
    factory = sessionmaker(bind=db_session.get_bind(), expire_on_commit=False)
    calls = []
    monkeypatch.setattr(
        collector,
        "pinned_native_balances",
        lambda addresses, **kw: (calls.append("native") or 100, {a: 10**18 for a in addresses}),
    )
    monkeypatch.setattr(collector, "get_native_price", lambda chain: calls.append("quote") or 2000)
    monkeypatch.setattr(
        collector,
        "fetch_asset_page",
        lambda *a, **kw: calls.append("tokens") or TokenBalancePage([], 0, "returned_empty"),
    )
    engine = db_session.get_bind()
    counts = {"statements": 0, "commits": 0}

    def statement(*args):
        counts["statements"] += 1

    def commit(*args):
        counts["commits"] += 1

    event.listen(engine, "before_cursor_execute", statement)
    event.listen(engine, "commit", commit)
    try:
        collect_balances(targets, writer="tvl", session_factory=factory)
        cold = dict(counts)
        counts.update(statements=0, commits=0)
        before = list(calls)
        report = collect_balances(targets, writer="tvl", session_factory=factory)
    finally:
        event.remove(engine, "before_cursor_execute", statement)
        event.remove(engine, "commit", commit)
    print(f"64-account collector: cold={cold}, warm={counts}")
    assert calls == before
    assert report.reused == 128 and report.committed == 0
    assert counts["commits"] == 0
    assert counts["statements"] <= 400
