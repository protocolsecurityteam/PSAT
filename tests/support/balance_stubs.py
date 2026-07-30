"""Stub helpers for the ERC-20 holdings-page wire.

``utils.etherscan.get_token_balances_page`` is what the two ``contract_balances``
writers call, because the older list-returning signature cannot distinguish an
empty page from a failed fetch — and writing rows from the latter publishes
"holds nothing". Tests that stub the wire therefore stub the page function, and
these helpers keep the derived ``status``/``page_length`` honest instead of
letting each call site invent a pair.
"""

from __future__ import annotations

from utils.balance_status import (
    ASSET_SET_STATUS_AT_PAGE_CAP,
    ASSET_SET_STATUS_FETCH_FAILED,
    ASSET_SET_STATUS_RETURNED_ASSETS,
    ASSET_SET_STATUS_RETURNED_EMPTY,
)
from utils.etherscan import TOKEN_BALANCE_PAGE_SIZE, TokenBalancePage


def page(rows: list[dict], *, page_length: int | None = None) -> TokenBalancePage:
    """A successful page carrying *rows*.

    ``page_length`` defaults to ``len(rows)``, which is what the endpoint returns
    when no entry was dropped by the ``raw_balance > 0`` filter. Pass it
    explicitly to model a page whose raw length exceeds the surviving rows — the
    case the stored-row count cannot see.
    """
    raw = len(rows) if page_length is None else page_length
    if raw >= TOKEN_BALANCE_PAGE_SIZE:
        status = ASSET_SET_STATUS_AT_PAGE_CAP
    elif raw:
        status = ASSET_SET_STATUS_RETURNED_ASSETS
    else:
        status = ASSET_SET_STATUS_RETURNED_EMPTY
    return TokenBalancePage(rows=rows, page_length=raw, status=status)


def failed_page() -> TokenBalancePage:
    """The shape a swallowed fetch failure produces: no rows, no page length."""
    return TokenBalancePage(rows=[], page_length=None, status=ASSET_SET_STATUS_FETCH_FAILED)
