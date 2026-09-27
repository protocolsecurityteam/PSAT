"""Bounded current-state collection used by resolution and the TVL monitor.

Provider calls run between short transactions. Leases and last successful payloads
are keyed on the physical account; publication still belongs to each protocol's
observation subject. Failed aggregates cannot roll these observations back.
"""

from __future__ import annotations

import logging
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

from sqlalchemy import case, func, select, tuple_
from sqlalchemy.dialects.postgresql import insert

from db.models import ContractBalanceFetch, SessionLocal
from db.models.balance_collection import BalanceCollectionState
from services.clients.etherscan import TokenBalancePage
from services.clients.request_budget import RequestBudget, RequestBudgetExceeded, request_budget
from services.monitoring.balance_observation import NativeReading, fetch_asset_page, record_observation
from services.monitoring.balance_reads import ObservationSubject, pinned_native_balances
from utils.balance_status import (
    ASSET_SET_STATUS_AT_PAGE_CAP,
    ASSET_SET_STATUS_FETCH_FAILED,
    STATUS_UNATTEMPTED,
)
from utils.chains import chain_by_id

logger = logging.getLogger(__name__)
FRESH_SECONDS = int(os.getenv("PSAT_BALANCE_FRESH_SECONDS", "3600"))
LEASE_SECONDS = 300


def get_eth_balance(address, *, chain_id):
    from services.clients import etherscan

    return etherscan.get_eth_balance(address, chain_id=chain_id)


def get_native_price(chain_id):
    from services.clients import etherscan

    return etherscan.get_eth_price(chain_id=1) if chain_id == 1 else etherscan.get_native_price(chain_id)


@dataclass(frozen=True)
class CollectionSubject:
    subject: ObservationSubject
    chain_id: int


@dataclass
class CollectionReport:
    cycle_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    attempted: int = 0
    reused: int = 0
    deferred: int = 0
    fetched: int = 0
    committed: int = 0
    failed: int = 0
    partial: int = 0
    oldest_observed_at: datetime | None = None


@dataclass(frozen=True)
class Claim:
    target: CollectionSubject
    read_class: str
    owner: str | None
    generation: int
    payload: dict | None
    observed_at: datetime | None
    reason: str


def _key(target: CollectionSubject, read_class: str) -> dict:
    return dict(chain_id=target.chain_id, address=target.subject.address.lower(), read_class=read_class)


def claim_read(target, read_class, *, max_age_seconds: int | None = None, session_factory=SessionLocal) -> Claim:
    with session_factory() as session:
        now = session.execute(select(func.clock_timestamp())).scalar_one()
        key = _key(target, read_class)
        session.execute(insert(BalanceCollectionState).values(**key).on_conflict_do_nothing())
        state = session.get(BalanceCollectionState, tuple(key.values()), with_for_update=True)
        assert state is not None
        if state.lease_until is not None and state.lease_until > now:
            reason = "leased"
        elif (
            state.next_attempt_at is not None
            and state.next_attempt_at > now
            and not (
                state.outcome == "success"
                and state.observed_at is not None
                and max_age_seconds is not None
                and (now - state.observed_at).total_seconds() >= max_age_seconds
            )
        ):
            reason = "backoff" if state.failures else "fresh"
        else:
            owner = str(uuid.uuid4())
            state.generation += 1
            state.lease_owner = owner
            state.lease_until = now + timedelta(seconds=LEASE_SECONDS)
            state.last_attempt_at = now
            result = Claim(target, read_class, owner, state.generation, state.payload, state.observed_at, "due")
            session.commit()
            return result
        result = Claim(target, read_class, None, state.generation, state.payload, state.observed_at, reason)
        session.commit()
        return result


def read_native_quote(chain_id: int, *, session_factory=SessionLocal):
    """Independent native quote retry/cache; quantities need not be reread."""
    target = CollectionSubject(ObservationSubject.of_entity(chain_by_id(chain_id).name, "0x" + "0" * 40), chain_id)
    claim = claim_read(target, "native_quote", max_age_seconds=300, session_factory=session_factory)
    if claim.owner is None:
        if claim.reason == "fresh" and claim.payload:
            return claim.payload["price"], claim.observed_at
        return None, None
    price = None
    try:
        price = get_native_price(chain_id)
        import math

        if price is not None and (not math.isfinite(price) or not 0 < price < 1e20):
            price = None
    except RequestBudgetExceeded:
        release_claim(claim, session_factory=session_factory)
        raise
    except Exception as exc:
        logger.warning("native quote unavailable", extra={"chain_id": chain_id, "exc_type": type(exc).__name__})
    with session_factory() as session:
        key = _key(target, "native_quote")
        state = session.get(BalanceCollectionState, tuple(key.values()), with_for_update=True)
        if state is None or state.lease_owner != claim.owner or state.generation != claim.generation:
            return None, None
        now = session.execute(select(func.clock_timestamp())).scalar_one()
        state.lease_owner = None
        state.lease_until = None
        state.failures = state.failures + 1 if price is None else 0
        state.outcome = "failed" if price is None else "success"
        state.next_attempt_at = now + timedelta(
            seconds=min(3600, 30 * 2 ** min(state.failures, 7)) if price is None else 300
        )
        if price is not None:
            state.payload = {"price": price}
            state.observed_at = now
        session.commit()
        return price, now if price is not None else None


def reprice_unpriced_native(claim: Claim, *, writer: str, session_factory=SessionLocal):
    """A quote update keeps the original quantity observation time."""
    if claim.read_class != "native" or not claim.payload or claim.payload.get("price_usd") is not None:
        return claim
    asset = chain_by_id(claim.target.chain_id).native_asset
    price, price_at = read_native_quote(1 if asset == "ETH" else claim.target.chain_id, session_factory=session_factory)
    if price is None or price_at is None:
        return claim
    with session_factory() as session:
        state = session.get(BalanceCollectionState, tuple(_key(claim.target, "native").values()), with_for_update=True)
        if state is None or state.generation != claim.generation:
            return claim
        payload = dict(claim.payload, price_usd=price, price_observed_at=price_at.isoformat())
        state.payload = payload
        session.commit()
    from dataclasses import replace

    return replace(claim, payload=payload)


def _publish(session, claim: Claim, payload: dict, observed_at: datetime, writer: str):
    subject = claim.target.subject
    # A cached physical read can be published to another eligible protocol subject,
    # but never stamped as a new observation or repeatedly inserted into its history.
    status_col = (
        ContractBalanceFetch.native_status if claim.read_class == "native" else ContractBalanceFetch.asset_set_status
    )
    exists = session.scalar(
        select(ContractBalanceFetch.id)
        .where(
            *subject.filters(ContractBalanceFetch),
            ContractBalanceFetch.observed_at == observed_at,
            status_col != STATUS_UNATTEMPTED,
        )
        .order_by(ContractBalanceFetch.id.desc())
        .limit(1)
    )
    if exists is not None:
        if claim.read_class != "native" or payload.get("price_usd") is None:
            return False
        from db.models import ContractBalance

        old = session.scalar(
            select(ContractBalance).where(
                ContractBalance.fetch_id == exists,
                ContractBalance.token_address.is_(None),
            )
        )
        if old is None or old.price_usd is not None:
            return False
    native = NativeReading(None, None, False, None, "", "", attempted=False)
    page = TokenBalancePage([], None, STATUS_UNATTEMPTED)
    if claim.read_class == "native":
        data = dict(payload)
        for key in ("observed_at", "price_observed_at"):
            if isinstance(data.get(key), str):
                data[key] = datetime.fromisoformat(data[key])
        native = NativeReading(**data)
    else:
        page = TokenBalancePage(**payload)
    record_observation(
        session,
        subject=subject,
        chain_id=claim.target.chain_id,
        native=native,
        page=page,
        writer=writer,
        observed_at=observed_at,
    )
    return True


def publish_reuse(claim: Claim, *, writer, session_factory=SessionLocal) -> bool:
    if claim.payload is None or claim.observed_at is None:
        return False
    with session_factory() as session:
        # Guard against an older cached read publishing after a newer generation.
        key = _key(claim.target, claim.read_class)
        state = session.get(BalanceCollectionState, tuple(key.values()), with_for_update=True)
        if state is None or state.generation != claim.generation:
            return False
        written = _publish(session, claim, claim.payload, claim.observed_at, writer)
        if written:
            _dirty(session, claim.target)
        session.commit()
        return written


def _dirty(session, target):
    from db.models import Contract
    from services.scoring.dirty import mark_protocol_score_dirty

    if target.subject.contract_id is not None:
        contract = session.get(Contract, target.subject.contract_id)
        if contract is not None:
            mark_protocol_score_dirty(session, contract.protocol_id, "balance_observation")
    # Entity observations are not owned by a protocol; the score staleness backstop
    # and the initiating protocol's cycle handle those shared evidence updates.


def finish_read(
    claim: Claim, payload: dict, *, outcome: str, writer: str, ttl: int, session_factory=SessionLocal
) -> bool:
    with session_factory() as session:
        now = session.execute(select(func.clock_timestamp())).scalar_one()
        key = _key(claim.target, claim.read_class)
        state = session.get(BalanceCollectionState, tuple(key.values()), with_for_update=True)
        if state is None or state.lease_owner != claim.owner or state.generation != claim.generation:
            return False
        state.lease_owner = None
        state.lease_until = None
        state.outcome = outcome
        if outcome == "success":
            state.failures = 0
            state.next_attempt_at = now + timedelta(seconds=ttl)
        else:
            state.failures += 1
            state.next_attempt_at = now + timedelta(seconds=min(3600, 30 * 2 ** min(state.failures - 1, 7)))
        # Partial prefixes are useful positive observations, stored separately by
        # the projection. Failed reads never replace the last usable payload.
        if outcome in ("success", "partial"):
            state.payload = payload
            state.observed_at = now
        written = _publish(session, claim, payload, now, writer)
        if written:
            _dirty(session, claim.target)
        next_attempt_at = state.next_attempt_at
        failures = state.failures
        session.commit()
        logger.info(
            "balance read committed",
            extra={
                **key,
                "generation": claim.generation,
                "outcome": outcome,
                "retry_count": failures,
                "next_attempt_at": next_attempt_at.isoformat() if next_attempt_at else None,
                "committed": int(written),
            },
        )
        return written


def release_claim(claim: Claim, *, session_factory=SessionLocal):
    with session_factory() as session:
        key = _key(claim.target, claim.read_class)
        state = session.get(BalanceCollectionState, tuple(key.values()), with_for_update=True)
        if state is not None and state.lease_owner == claim.owner:
            state.lease_owner = None
            state.lease_until = None
            state.next_attempt_at = session.execute(select(func.clock_timestamp())).scalar_one() + timedelta(seconds=30)
            state.outcome = "budget_deferred"
        session.commit()


def order_subjects(subjects, *, ttl=FRESH_SECONDS, session_factory=SessionLocal):
    """Due accounts first, then oldest attempts; a fresh prefix cannot starve a retry."""
    if not subjects:
        return [], set()
    keys = [(s.chain_id, s.subject.address.lower()) for s in subjects]
    with session_factory() as session:
        now = session.execute(select(func.clock_timestamp())).scalar_one()
        rows = session.execute(
            select(
                BalanceCollectionState.chain_id,
                BalanceCollectionState.address,
                func.max(BalanceCollectionState.last_attempt_at),
                func.min(BalanceCollectionState.next_attempt_at),
                func.count(),
                func.min(case((BalanceCollectionState.outcome == "success", BalanceCollectionState.observed_at))),
            )
            .where(tuple_(BalanceCollectionState.chain_id, BalanceCollectionState.address).in_(keys))
            .group_by(BalanceCollectionState.chain_id, BalanceCollectionState.address)
        ).all()
    times = {(chain, address): when for chain, address, when, _due, _count, _observed in rows}
    due = {
        (chain, address)
        for chain, address, _when, eligible, count, observed in rows
        if count < 2
        or eligible is None
        or eligible <= now
        or (observed is not None and (now - observed).total_seconds() >= ttl)
    }
    due.update(set(keys) - set(times))
    floor = datetime.min.replace(tzinfo=timezone.utc)
    ordered = sorted(
        subjects,
        key=lambda s: (
            (s.chain_id, s.subject.address.lower()) not in due,
            times.get((s.chain_id, s.subject.address.lower())) or floor,
            s.chain_id,
            s.subject.address.lower(),
        ),
    )
    return ordered, due


def collect_balances(
    subjects: list[CollectionSubject],
    *,
    writer: str,
    ttl: int = FRESH_SECONDS,
    session_factory=SessionLocal,
    budget: RequestBudget | None = None,
    heartbeat: Callable[[], None] | None = None,
) -> CollectionReport:
    report = CollectionReport()
    budget = budget or RequestBudget(
        limit=int(os.getenv("PSAT_BALANCE_REQUEST_BUDGET", "250")),
        seconds=float(os.getenv("PSAT_BALANCE_PASS_SECONDS", "120")),
    )
    pending: list[Claim] = []
    ordered, due = order_subjects(subjects, ttl=ttl, session_factory=session_factory)
    limit = max(1, int(os.getenv("PSAT_BALANCE_SUBJECTS_PER_PASS", "64")))
    subjects = ordered[:limit]
    report.deferred += sum((s.chain_id, s.subject.address.lower()) in due for s in ordered[limit:])
    with request_budget(budget):
        try:
            for target in subjects:
                for read_class in ("native", "tokens"):
                    claim = claim_read(target, read_class, max_age_seconds=ttl, session_factory=session_factory)
                    if claim.observed_at is not None:
                        report.oldest_observed_at = min(
                            report.oldest_observed_at or claim.observed_at, claim.observed_at
                        )
                    if claim.owner:
                        pending.append(claim)
                    else:
                        if claim.reason == "fresh":
                            claim = reprice_unpriced_native(claim, writer=writer, session_factory=session_factory)
                        report.reused += int(claim.reason == "fresh")
                        report.deferred += int(claim.reason != "fresh")
                        report.committed += int(publish_reuse(claim, writer=writer, session_factory=session_factory))
            quotes: dict[int, tuple[float | None, datetime | None]] = {}
            # Process small native batches per chain; a very large protocol never
            # creates one unbounded multicall payload or holds a lease indefinitely.
            chains = sorted({c.target.chain_id for c in pending})
            for chain_id in chains:
                native_claims = [c for c in pending if c.target.chain_id == chain_id and c.read_class == "native"]
                for offset in range(0, len(native_claims), 100):
                    budget.check()
                    group = native_claims[offset : offset + 100]
                    block, quantities = pinned_native_balances(
                        [c.target.subject.address for c in group], chain_id=chain_id
                    )
                    asset = chain_by_id(chain_id).native_asset
                    quote_chain = 1 if asset == "ETH" else chain_id
                    if quote_chain not in quotes:
                        try:
                            quotes[quote_chain] = read_native_quote(quote_chain, session_factory=session_factory)
                        except RequestBudgetExceeded:
                            # Quantities already acquired must survive a quote budget
                            # failure. Publish them unpriced before yielding the pass.
                            quotes[quote_chain] = (None, None)
                        except Exception as exc:
                            logger.warning(
                                "native quote unavailable", extra={"chain_id": chain_id, "exc_type": type(exc).__name__}
                            )
                            quotes[quote_chain] = (None, None)
                    quote, quote_time = quotes[quote_chain]
                    for claim in group:
                        value = quantities.get(claim.target.subject.address.lower())
                        at_block = block if value is not None else None
                        if value is None:
                            try:
                                value = get_eth_balance(claim.target.subject.address, chain_id=chain_id)
                            except RequestBudgetExceeded:
                                continue
                            except Exception as exc:
                                logger.warning(
                                    "native balance unavailable",
                                    extra={"chain_id": chain_id, "exc_type": type(exc).__name__},
                                )
                        native = NativeReading(
                            value, at_block, value is None, quote, asset, asset, price_observed_at=quote_time
                        )
                        payload = asdict(native)
                        if quote_time is not None:
                            payload["price_observed_at"] = quote_time.isoformat()
                        outcome = "failed" if value is None else "success"
                        report.attempted += 1
                        report.fetched += int(value is not None)
                        report.failed += int(value is None)
                        report.committed += int(
                            finish_read(
                                claim, payload, outcome=outcome, writer=writer, ttl=ttl, session_factory=session_factory
                            )
                        )
                        pending.remove(claim)
            # Oldest pending physical account first prevents prefix starvation
            # when a large protocol cannot finish in one provider budget.
            for claim in [c for c in pending if c.read_class == "tokens"]:
                budget.check()
                if heartbeat:
                    heartbeat()
                page = fetch_asset_page(claim.target.subject.address, chain_id=claim.target.chain_id)
                outcome = (
                    "failed"
                    if page.status == ASSET_SET_STATUS_FETCH_FAILED
                    else "partial"
                    if page.status == ASSET_SET_STATUS_AT_PAGE_CAP
                    else "success"
                )
                report.attempted += 1
                report.fetched += int(outcome != "failed")
                report.failed += int(outcome == "failed")
                report.partial += int(outcome == "partial")
                report.committed += int(
                    finish_read(
                        claim, asdict(page), outcome=outcome, writer=writer, ttl=ttl, session_factory=session_factory
                    )
                )
                pending.remove(claim)
        except RequestBudgetExceeded:
            report.deferred += len(pending)
        finally:
            for claim in pending:
                release_claim(claim, session_factory=session_factory)
            logger.info(
                "balance collection complete",
                extra={
                    **asdict(report),
                    "provider_attempts": dict(budget.attempts),
                    "duration_ms": int((__import__("time").monotonic() - budget.started) * 1000),
                },
            )
    return report
