"""Publish current balance observations at each subject's own address. Shared by resolution and TVL collection."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import Contract, ContractBalance, ContractBalanceFetch
from services.clients.etherscan import TokenBalancePage
from services.monitoring.balance_reads import ObservationSubject, native_status_for, prune_balance_fetches
from utils.balance_status import (
    ASSET_SET_SOURCE_ETHERSCAN_PAGES,
    ASSET_SET_STATUS_FETCH_FAILED,
    BALANCE_SOURCE_PINNED_NATIVE_READ,
    BALANCE_SOURCE_UNPINNED_NATIVE_READ,
    NATIVE_STATUS_PROVEN_ZERO,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class NativeReading:
    """Native quantity and price observations supplied by the shared collector."""

    wei: int | None
    block_number: int | None
    failed: bool
    price_usd: float | None
    symbol: str
    name: str
    attempted: bool = True
    observed_at: datetime | None = None
    price_observed_at: datetime | None = None


@dataclass(frozen=True)
class RecordedObservation:
    """What :func:`record_observation` persisted; callers report from this, not their inputs."""

    fetch: ContractBalanceFetch
    asset_set_status: str
    asset_set_source: str
    native_status: str
    rows: tuple[ContractBalance, ...]


def observation_contract(
    session: Session,
    *,
    fallback: Contract,
    chain_id: int,
    requested_address: str | None,
) -> Contract:
    """The row an observation of *requested_address* belongs to, scoped to the producing protocol.

    Another tenant's row is never adopted (that would let one protocol prune another's history). Unowned addresses fall
    back to *fallback*'s address.
    """
    from services.monitoring.chain_rpc import chain_id_for

    if not requested_address:
        return fallback
    wanted = requested_address.lower()
    if (fallback.address or "").lower() == wanted:
        return fallback
    if fallback.protocol_id is None:
        return fallback
    candidates = (
        session.execute(
            select(Contract)
            .where(func.lower(Contract.address) == wanted, Contract.protocol_id == fallback.protocol_id)
            .order_by(Contract.id)
        )
        .scalars()
        .all()
    )
    same_chain = [c for c in candidates if chain_id_for(c.chain) == chain_id]
    return same_chain[0] if same_chain else fallback


def fetch_asset_page(address: str, *, chain_id: int) -> TokenBalancePage:
    """Etherscan's answer, with any raise turned into the recorded failure state so no asset class ends with neither
    rows nor a status.
    """
    # Call-time import keeps the single Etherscan wire stubbable.
    from services.clients.etherscan import get_token_balances_page

    try:
        return get_token_balances_page(address, chain_id=chain_id)
    except Exception as exc:
        from services.clients.request_budget import RequestBudgetExceeded

        if isinstance(exc, RequestBudgetExceeded):
            raise
        logger.warning("token balance fetch raised for %s on chain %s: %s", address, chain_id, type(exc).__name__)
        return TokenBalancePage(
            rows=[],
            page_length=None,
            status=ASSET_SET_STATUS_FETCH_FAILED,
            pages_read=0,
            basis=f"etherscan addresstokenbalance raised: {type(exc).__name__}",
        )


def record_observation(
    session: Session,
    *,
    subject: ObservationSubject,
    chain_id: int,
    native: NativeReading,
    page: TokenBalancePage,
    writer: str,
    observed_at: datetime | None = None,
) -> RecordedObservation:
    """Publish one current-state result; caller commits.

    Unattempted classes don't replace observations, and partial token prefixes are never merged into an invented
    complete portfolio.
    """
    from utils.balance_status import STATUS_UNATTEMPTED

    when = observed_at or datetime.now(timezone.utc)
    native_status = (
        native_status_for(wei=native.wei, pinned=native.block_number is not None, failed=native.failed)
        if native.attempted
        else STATUS_UNATTEMPTED
    )
    fetch = ContractBalanceFetch(
        **subject.columns(),
        chain_id=chain_id,
        observed_address=subject.address,
        block_number=native.block_number,
        native_status=native_status,
        asset_set_status=page.status,
        asset_page_length=page.page_length,
        asset_set_source=ASSET_SET_SOURCE_ETHERSCAN_PAGES,
        asset_set_basis=page.basis,
        writer=writer,
        observed_at=when,
        fetched_at=when,
    )
    session.add(fetch)
    session.flush()
    # NUMERIC(38,18) can't hold arbitrary uint256 dollar values; keep the raw quantity regardless.
    import math

    native_usd = None
    if native.wei == 0 and native_status == NATIVE_STATUS_PROVEN_ZERO:
        native_usd = 0
    elif native.wei is not None and native.price_usd is not None:
        value = (native.wei / 1e18) * native.price_usd
        native_usd = value if math.isfinite(value) and 0 <= value < 1e20 else None
    written: list[ContractBalance] = []
    if (
        native.attempted
        and not native.failed
        and native.wei is not None
        and (native.wei > 0 or native_status == NATIVE_STATUS_PROVEN_ZERO)
    ):
        written.append(
            ContractBalance(
                **subject.columns(),
                token_address=None,
                token_name=native.name,
                token_symbol=native.symbol,
                decimals=18,
                decimals_known=True,
                raw_balance=str(native.wei),
                price_usd=native.price_usd,
                usd_value=native_usd,
                observed_address=subject.address,
                block_number=native.block_number,
                observed_at=native.observed_at or when,
                fetched_at=when,
                price_observed_at=native.price_observed_at if native.price_usd is not None else None,
                fetch_id=fetch.id,
                source=(
                    BALANCE_SOURCE_PINNED_NATIVE_READ
                    if native.block_number is not None
                    else BALANCE_SOURCE_UNPINNED_NATIVE_READ
                ),
            )
        )
    if page.status not in (ASSET_SET_STATUS_FETCH_FAILED, STATUS_UNATTEMPTED):
        for row in page.rows:
            if int(row["balance"]) <= 0:
                continue
            known = row.get("decimals_reported") is True
            written.append(
                ContractBalance(
                    **subject.columns(),
                    token_address=row["token_address"].lower(),
                    token_name=row.get("token_name"),
                    token_symbol=row.get("token_symbol"),
                    decimals=row.get("decimals", 18),
                    decimals_known=known,
                    raw_balance=str(row["balance"]),
                    price_usd=row.get("price_usd") if known else None,
                    usd_value=row.get("usd_value") if known else None,
                    observed_address=subject.address,
                    fetch_id=fetch.id,
                    source=ASSET_SET_SOURCE_ETHERSCAN_PAGES,
                    observed_at=when,
                    fetched_at=when,
                    price_observed_at=when if known and row.get("price_usd") is not None else None,
                )
            )
    session.add_all(written)
    session.flush()
    prune_balance_fetches(session, subject, subject.address)
    return RecordedObservation(
        fetch=fetch,
        asset_set_status=page.status,
        asset_set_source=ASSET_SET_SOURCE_ETHERSCAN_PAGES,
        native_status=native_status,
        rows=tuple(written),
    )
