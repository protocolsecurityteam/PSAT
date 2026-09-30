"""Shared balance-read primitives for the two ``contract_balances`` writers (TVL loop and resolution worker), so the
status a consumer reads doesn't depend on which one wrote it.

Traceability comes from the persisted provenance column, not ``record_degraded``, which is a no-op outside
``BaseWorker`` (the TVL loop). It is still called from :func:`pinned_native_balances` so resolution jobs'
``stage_errors`` don't claim a clean run.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

from sqlalchemy import case, select, tuple_
from sqlalchemy.orm import Session

from db.models import Contract, ContractBalance, ContractBalanceFetch
from services.clients.rpc import MULTICALL3_ADDRESS, multicall3_aggregate3, rpc_request, rpc_url_for_chain_id, selector
from utils.balance_status import (
    ASSET_ACCEPTED_STATUSES,
    ASSET_OBSERVED_STATUSES,
    ASSET_SET_STATUS_AT_PAGE_CAP,
    NATIVE_ACCEPTED_STATUSES,
    NATIVE_STATUS_FETCH_FAILED,
    NATIVE_STATUS_NOT_DETERMINED,
    NATIVE_STATUS_PROVEN_NONZERO,
    NATIVE_STATUS_PROVEN_ZERO,
    asset_snapshot_priority,
)
from utils.logging import record_degraded

logger = logging.getLogger(__name__)


def _degraded(exc: BaseException, *, phase: str, **context: Any) -> None:
    """Pair a swallowed WARNING with the job's degraded accumulator (no-op under the TVL loop)."""
    record_degraded(phase=phase, exc=exc, context=context)


@dataclass(frozen=True)
class ObservationSubject:
    """Who a balance observation is about: a ``contracts`` row or an entity with none, exactly one (matching the
    schema CHECK).

    Entities exist because the score's perimeter includes proven-codeless principals with only ``(chain, address)``
    identity. Hashable, so contract and entity keys can't collide in one dict. The address is normalized on the entity
    arm, where it is part of the identity.
    """

    contract_id: int | None
    chain: str | None
    address: str

    @classmethod
    def of_contract(cls, contract: Contract) -> ObservationSubject:
        return cls(contract_id=contract.id, chain=None, address=contract.address)

    @classmethod
    def of_entity(cls, chain: str, address: str) -> ObservationSubject:
        """An entity with no ``contracts`` row; *chain* is the plane's coalesced chain name, matching the entity key."""
        return cls(contract_id=None, chain=chain, address=(address or "").lower())

    @property
    def is_entity(self) -> bool:
        return self.contract_id is None

    def filters(self, model: Any) -> list[Any]:
        """The predicate for this subject's rows of *model*.

        The entity arm's ``contract_id IS NULL`` keeps it from also matching a contract row.
        """
        if self.contract_id is not None:
            return [model.contract_id == self.contract_id]
        return [
            model.contract_id.is_(None),
            model.entity_chain == self.chain,
            model.entity_address == self.address,
        ]

    def columns(self) -> dict[str, Any]:
        if self.contract_id is not None:
            return {"contract_id": self.contract_id, "entity_chain": None, "entity_address": None}
        return {"contract_id": None, "entity_chain": self.chain, "entity_address": self.address}


# A lagged height identifying the read, not a finality guarantee.
PINNED_FINALITY_MARGIN = 12

# A 32-byte hex word. ``"0x"`` (empty success) must not decode as a proven zero.
_WORD_HEX_LEN = 66


def pinned_native_balances(
    addresses: list[str],
    *,
    chain_id: int,
    rpc_url: str | None = None,
) -> tuple[int | None, dict[str, int]]:
    """Native balances at one pinned height: ``(block_number, {address_lower: wei})``.

    ``block_number`` is ``None`` (mapping empty) if the height or read failed; the caller falls back to the unpinned
    path. A missing address is a failed read, not a zero. The block is resolved first and every read issued at it;
    stamping a separate ``eth_blockNumber`` beside a ``latest`` read would invent the witness.
    """
    if not addresses:
        return None, {}
    url = rpc_url or rpc_url_for_chain_id(chain_id)
    # Multicall3 has the same address on every registered chain; a chain without it takes the safe unpinned fallback.
    if not url:
        return None, {}
    try:
        head = int(rpc_request(url, "eth_blockNumber", [], retries=1, chain_id=chain_id), 16)
    except Exception as exc:
        # Once per call. The resolution worker calls this per job, so pair with ``record_degraded`` there.
        _degraded(exc, phase="pinned_native_head", chain_id=chain_id, addresses=len(addresses))
        logger.warning(
            "pinned native balance: head read failed; the chain's holders fall back to the unpinned path",
            extra={
                "chain_id": chain_id,
                "addresses": len(addresses),
                "exc_type": type(exc).__name__,
                "error": str(exc),
            },
        )
        return None, {}
    block = max(1, head - PINNED_FINALITY_MARGIN)
    # Derived: a hand-typed selector mints wrong calldata silently.
    sel = selector("getEthBalance(address)")
    ordered = [a.lower() for a in addresses]
    calls = [(MULTICALL3_ADDRESS, sel + a[2:].rjust(64, "0")) for a in ordered]
    try:
        results = multicall3_aggregate3(url, calls, hex(block), chain_id=chain_id)
    except Exception as exc:
        _degraded(exc, phase="pinned_native_read", chain_id=chain_id, block_number=block, addresses=len(addresses))
        logger.warning(
            "pinned native balance: aggregate3 did not answer; the chain's holders fall back to the unpinned path",
            extra={
                "chain_id": chain_id,
                "block_number": block,
                "addresses": len(addresses),
                "exc_type": type(exc).__name__,
                "error": str(exc),
            },
        )
        return None, {}
    out: dict[str, int] = {}
    for address, (ok, data) in zip(ordered, results):
        if not ok or not isinstance(data, str) or len(data) != _WORD_HEX_LEN:
            # Includes ``(True, "0x")``; never decoded as 0.
            continue
        try:
            out[address] = int(data, 16)
        except ValueError:
            continue
    return block, out


def native_status_for(*, wei: int | None, pinned: bool, failed: bool) -> str:
    """The one place a native read becomes a status.

    ``failed``: no decodable word. Pinned zero: proven zero at a height. Unpinned zero: ``not_determined`` (Etherscan's
    ``latest`` carries no height). Nonzero: ``proven_nonzero``, but with a NULL block it is not an as-of-block fact (see
    :func:`native_balance_fact`).
    """
    if failed or wei is None:
        return NATIVE_STATUS_FETCH_FAILED
    if wei > 0:
        return NATIVE_STATUS_PROVEN_NONZERO
    return NATIVE_STATUS_PROVEN_ZERO if pinned else NATIVE_STATUS_NOT_DETERMINED


def native_balance_fact(native_status: str, block_number: int | None) -> str:
    """What a ``(native_status, block_number)`` pair asserts. Consumers must go through this, never the status alone."""
    if native_status == NATIVE_STATUS_PROVEN_ZERO:
        # The schema refuses this pair; guarded for in-memory callers.
        if block_number is None:
            return "not_determined"
        return f"proven_zero_at_block_{block_number}"
    if native_status == NATIVE_STATUS_PROVEN_NONZERO:
        return f"proven_nonzero_at_block_{block_number}" if block_number is not None else "nonzero_at_unrecorded_height"
    if native_status == NATIVE_STATUS_FETCH_FAILED:
        return "not_determined"
    return "not_determined"


def balance_history_depth() -> int:
    """Fetches kept per (contract, observed_address).

    Must be at least 1: 0 would resurrect the legacy rows as current holdings.
    """
    raw = os.getenv("PSAT_BALANCE_HISTORY_DEPTH", "10")
    try:
        depth = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"PSAT_BALANCE_HISTORY_DEPTH must be an integer >= 1, got {raw!r}") from exc
    if depth < 1:
        raise ValueError(f"PSAT_BALANCE_HISTORY_DEPTH must be >= 1, got {depth}")
    return depth


def prune_balance_fetches(session: Session, subject: ObservationSubject, observed_address: str) -> int:
    """Bound insert-only growth without deleting a published observation; returns fetch rows deleted.

    Prunes by fetch, never by row, keeping the ``depth`` newest and, per row class, the newest non-failed fetch.
    Otherwise consecutive failures would cascade-delete what the view publishes, which downstream turns into ``$0.00``.
    """
    depth = balance_history_depth()
    rows = session.execute(
        select(
            ContractBalanceFetch.id,
            ContractBalanceFetch.native_status,
            ContractBalanceFetch.asset_set_status,
        )
        .where(
            *subject.filters(ContractBalanceFetch),
            ContractBalanceFetch.observed_address == observed_address,
        )
        .order_by(ContractBalanceFetch.fetched_at.desc(), ContractBalanceFetch.id.desc())
    ).all()
    if len(rows) <= depth:
        return 0
    keep = {r.id for r in rows[:depth]}
    # Keep native, accepted token snapshot and newest partial prefix separately.
    for index, statuses in (
        (1, NATIVE_ACCEPTED_STATUSES),
        (2, ASSET_ACCEPTED_STATUSES),
        (2, (ASSET_SET_STATUS_AT_PAGE_CAP,)),
    ):
        for row in rows:
            if row[index] in statuses:
                keep.add(row.id)
                break
    doomed = [r.id for r in rows if r.id not in keep]
    if not doomed:
        return 0
    session.query(ContractBalanceFetch).filter(ContractBalanceFetch.id.in_(doomed)).delete(synchronize_session=False)
    return len(doomed)


def winning_asset_fetches(session: Session, protocol_id: int) -> dict[int, ContractBalanceFetch]:
    """Per contract, the fetch whose ERC-20 rows ``contract_balances_latest`` publishes.

    Completeness belongs to the row set, so read it from the owning fetch, not the latest (a later failure would
    withdraw a truncation still being summed). Same accepted-first rule as the view. Contracts with no non-failed fetch
    are absent: unknown, not a verdict.
    """
    from db.models import Contract

    rows = (
        session.query(ContractBalanceFetch)
        .join(Contract, Contract.id == ContractBalanceFetch.contract_id)
        .filter(
            Contract.protocol_id == protocol_id,
            ContractBalanceFetch.asset_set_status.in_(ASSET_OBSERVED_STATUSES),
        )
        .order_by(
            ContractBalanceFetch.contract_id,
            case((ContractBalanceFetch.asset_set_status.in_(ASSET_ACCEPTED_STATUSES), 1), else_=0).desc(),
            ContractBalanceFetch.fetched_at.desc(),
            ContractBalanceFetch.id.desc(),
        )
        .distinct(ContractBalanceFetch.contract_id)
        .all()
    )
    winners: dict[int, ContractBalanceFetch] = {}
    for fetch in rows:
        if fetch.contract_id is not None:
            previous = winners.get(fetch.contract_id)
            if previous is None or asset_snapshot_priority(fetch.asset_set_status) > asset_snapshot_priority(
                previous.asset_set_status
            ):
                winners[fetch.contract_id] = fetch
    return winners


def winning_entity_asset_fetches(
    session: Session, subjects: list[ObservationSubject]
) -> dict[ObservationSubject, ContractBalanceFetch]:
    """As :func:`winning_asset_fetches`, for entity subjects scoped to the caller's perimeter (entities have no
    protocol).
    """
    if not subjects:
        return {}
    by_identity = {(s.chain, s.address): s for s in subjects if s.is_entity}
    if not by_identity:
        return {}
    rows = (
        session.query(ContractBalanceFetch)
        .filter(
            ContractBalanceFetch.contract_id.is_(None),
            tuple_(ContractBalanceFetch.entity_chain, ContractBalanceFetch.entity_address).in_(list(by_identity)),
            ContractBalanceFetch.asset_set_status.in_(ASSET_OBSERVED_STATUSES),
        )
        .order_by(
            ContractBalanceFetch.entity_chain,
            ContractBalanceFetch.entity_address,
            case((ContractBalanceFetch.asset_set_status.in_(ASSET_ACCEPTED_STATUSES), 1), else_=0).desc(),
            ContractBalanceFetch.fetched_at.desc(),
            ContractBalanceFetch.id.desc(),
        )
        .distinct(ContractBalanceFetch.entity_chain, ContractBalanceFetch.entity_address)
        .all()
    )
    winners: dict[ObservationSubject, ContractBalanceFetch] = {}
    for fetch in rows:
        if fetch.entity_address is None:
            continue
        subject = by_identity.get((fetch.entity_chain, fetch.entity_address))
        if subject is not None:
            previous = winners.get(subject)
            if previous is None or asset_snapshot_priority(fetch.asset_set_status) > asset_snapshot_priority(
                previous.asset_set_status
            ):
                winners[subject] = fetch
    return winners


def contracts_missing_current_rows(session: Session, contract_ids: list[int]) -> set[int]:
    """Contracts whose current holdings the view can't publish for some class; callers omit them and flag partial
    instead of emitting ``0.0``.

    Two grounds: no non-failed fetch for a class, or (an integrity check) a winning ``proven_nonzero`` native fetch with
    no row. There is no asset-class equivalent, since an all-zero page legitimately persists no rows. Never-fetched
    contracts are excluded; their legacy rows still stand.
    """
    if not contract_ids:
        return set()
    fetches = session.execute(
        select(
            ContractBalanceFetch.id,
            ContractBalanceFetch.contract_id,
            ContractBalanceFetch.native_status,
            ContractBalanceFetch.asset_set_status,
        )
        .where(ContractBalanceFetch.contract_id.in_(contract_ids))
        .order_by(ContractBalanceFetch.fetched_at.desc(), ContractBalanceFetch.id.desc())
    ).all()
    if not fetches:
        return set()

    # Same winner rule as the view.
    native_winner: dict[int, tuple[int, str]] = {}
    asset_winner: dict[int, int] = {}
    fetched: set[int] = set()
    for fetch_id, contract_id, native_status, asset_status in fetches:
        fetched.add(contract_id)
        if native_status in NATIVE_ACCEPTED_STATUSES and contract_id not in native_winner:
            native_winner[contract_id] = (fetch_id, native_status)
        if asset_status in ASSET_OBSERVED_STATUSES and contract_id not in asset_winner:
            asset_winner[contract_id] = fetch_id

    promising = [fid for fid, status in native_winner.values() if status == NATIVE_STATUS_PROVEN_NONZERO]
    with_native_row: set[int] = set()
    if promising:
        with_native_row = {
            fid
            for fid in session.execute(
                select(ContractBalance.fetch_id).where(
                    ContractBalance.fetch_id.in_(promising),
                    ContractBalance.token_address.is_(None),
                )
            )
            .scalars()
            .all()
            if fid is not None
        }

    missing: set[int] = set()
    for contract_id in fetched:
        if contract_id not in native_winner or contract_id not in asset_winner:
            missing.add(contract_id)
            continue
        fetch_id, status = native_winner[contract_id]
        if status == NATIVE_STATUS_PROVEN_NONZERO and fetch_id not in with_native_row:
            missing.add(contract_id)
    return missing


def positive_raw_balance(raw_balance: object) -> bool:
    """Whether a stored ``raw_balance`` is strictly positive.

    Parsed in Python: the varchar compares lexicographically in SQL and ``::numeric`` raises on bad legacy values.
    Unparseable is excluded.
    """
    try:
        return int(str(raw_balance)) > 0
    except (TypeError, ValueError):
        return False


__all__ = [
    "PINNED_FINALITY_MARGIN",
    "ObservationSubject",
    "balance_history_depth",
    "contracts_missing_current_rows",
    "winning_asset_fetches",
    "winning_entity_asset_fetches",
    "native_balance_fact",
    "native_status_for",
    "pinned_native_balances",
    "positive_raw_balance",
    "prune_balance_fetches",
]


def latest_partial_asset_fetches(
    session: Session, protocol_id: int, *, winners: dict[int, ContractBalanceFetch] | None = None
) -> dict[int, ContractBalanceFetch]:
    """Newest partial prefix, separately from the accepted monetary snapshot."""
    rows = session.scalars(
        select(ContractBalanceFetch)
        .join(Contract)
        .where(
            Contract.protocol_id == protocol_id,
            ContractBalanceFetch.asset_set_status == ASSET_SET_STATUS_AT_PAGE_CAP,
        )
        .order_by(
            ContractBalanceFetch.contract_id, ContractBalanceFetch.fetched_at.desc(), ContractBalanceFetch.id.desc()
        )
        .distinct(ContractBalanceFetch.contract_id)
    ).all()
    out: dict[int, ContractBalanceFetch] = {}
    if winners is None:
        winners = winning_asset_fetches(session, protocol_id)
    for row in rows:
        if row.contract_id is None:
            continue
        winner = winners.get(row.contract_id)
        if winner is None or (row.fetched_at, row.id) >= (winner.fetched_at, winner.id):
            out.setdefault(row.contract_id, row)
    return out


def latest_partial_entity_asset_fetches(
    session: Session,
    subjects: list[ObservationSubject],
    *,
    winners: dict[ObservationSubject, ContractBalanceFetch] | None = None,
) -> dict[ObservationSubject, ContractBalanceFetch]:
    by_identity = {(s.chain, s.address): s for s in subjects if s.is_entity}
    if not by_identity:
        return {}
    rows = session.scalars(
        select(ContractBalanceFetch)
        .where(
            ContractBalanceFetch.contract_id.is_(None),
            tuple_(ContractBalanceFetch.entity_chain, ContractBalanceFetch.entity_address).in_(list(by_identity)),
            ContractBalanceFetch.asset_set_status == ASSET_SET_STATUS_AT_PAGE_CAP,
        )
        .order_by(
            ContractBalanceFetch.entity_chain,
            ContractBalanceFetch.entity_address,
            ContractBalanceFetch.fetched_at.desc(),
            ContractBalanceFetch.id.desc(),
        )
        .distinct(ContractBalanceFetch.entity_chain, ContractBalanceFetch.entity_address)
    ).all()
    if winners is None:
        winners = winning_entity_asset_fetches(session, subjects)
    out: dict[ObservationSubject, ContractBalanceFetch] = {}
    for row in rows:
        if row.entity_address is None:
            continue
        subject = by_identity[(row.entity_chain, row.entity_address)]
        winner = winners.get(subject)
        if winner is None or (row.fetched_at, row.id) >= (winner.fetched_at, winner.id):
            out.setdefault(subject, row)
    return out


def partial_asset_rows(session: Session, protocol_id: int) -> dict[int, list[ContractBalance]]:
    fetches = latest_partial_asset_fetches(session, protocol_id)
    if not fetches:
        return {}
    rows = session.scalars(
        select(ContractBalance).where(
            ContractBalance.fetch_id.in_([f.id for f in fetches.values()]),
            ContractBalance.token_address.is_not(None),
        )
    ).all()
    out: dict[int, list[ContractBalance]] = {}
    for row in rows:
        if row.contract_id is not None:
            out.setdefault(row.contract_id, []).append(row)
    return out
