"""Writers call ``get_token_balances_page`` because the list form can't tell an empty page from a failed fetch.

The pinned native read is a separate wire; see :func:`pinned_native_unavailable`.
"""

from __future__ import annotations

from services.clients.etherscan import TOKEN_BALANCE_PAGE_SIZE, TokenBalancePage
from utils.balance_status import (
    ASSET_SET_STATUS_AT_PAGE_CAP,
    ASSET_SET_STATUS_FETCH_FAILED,
    ASSET_SET_STATUS_RETURNED_ASSETS,
    ASSET_SET_STATUS_RETURNED_EMPTY,
)


def page(rows: list[dict], *, page_length: int | None = None) -> TokenBalancePage:
    """Pass ``page_length`` to model entries dropped by the ``raw_balance > 0`` filter."""
    raw = len(rows) if page_length is None else page_length
    if raw >= TOKEN_BALANCE_PAGE_SIZE:
        status = ASSET_SET_STATUS_AT_PAGE_CAP
    elif raw:
        status = ASSET_SET_STATUS_RETURNED_ASSETS
    else:
        status = ASSET_SET_STATUS_RETURNED_EMPTY
    return TokenBalancePage(
        rows=[dict(row, decimals_reported=row.get("decimals_reported", "decimals" in row)) for row in rows],
        page_length=raw,
        status=status,
    )


def failed_page() -> TokenBalancePage:
    return TokenBalancePage(rows=[], page_length=None, status=ASSET_SET_STATUS_FETCH_FAILED)


def pinned_native_unavailable(monkeypatch) -> None:
    """The pinned read hits its own wire first; failing it makes the writer fall back to the unpinned Etherscan
    answer, where zero is ``not_determined``.
    """
    monkeypatch.setattr(
        "services.monitoring.balance_reads.rpc_request",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("no rpc")),
    )
