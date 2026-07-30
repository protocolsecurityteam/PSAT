"""Shared balance-read primitives for the two ``contract_balances`` writers.

``services.monitoring.tvl`` and ``workers.resolution_worker`` are the only two
writers of that table (exhaustively swept). They ran different code with
different failure behaviour: one swallowed a native-fetch exception into
``eth_wei = 0`` and left no trace at all, the other returned early and recorded
a degraded phase. Everything they must now do IDENTICALLY lives here, so the
three-state a consumer reads does not depend on which loop happened to write it.

``record_degraded`` is deliberately NOT used from here. It is a no-op outside
``BaseWorker`` (``utils.logging``; bound only in ``workers.base``), and the TVL
loop runs outside it — adding it there would pass a mocked test and persist
nothing in production, which is the silent-no-trace shape this unit exists to
close. The discriminator is the PERSISTED provenance column instead, written by
both writers, which is what makes the trace identical rather than merely
similarly-named. The resolution worker keeps its own ``record_degraded`` call;
the TVL loop's substitute is the house-standard per-cycle heartbeat plus an
unconditional log.
"""

from __future__ import annotations

import logging
import os

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import ContractBalanceFetch
from utils.balance_status import (
    NATIVE_STATUS_FETCH_FAILED,
    NATIVE_STATUS_NOT_DETERMINED,
    NATIVE_STATUS_PROVEN_NONZERO,
    NATIVE_STATUS_PROVEN_ZERO,
    STATUS_FETCH_FAILED,
)
from utils.rpc import MULTICALL3_ADDRESS, multicall3_aggregate3, rpc_request, rpc_url_for_chain_id, selector

logger = logging.getLogger(__name__)

# Steps back from head before pinning. Same margin the resolver's probe uses, and
# the reason a height can be published at all: the read is issued AT this number,
# so the number is a witness of the read rather than an assumption about when an
# unpinned API answered.
PINNED_FINALITY_MARGIN = 12

# A 32-byte word, hex-encoded with the ``0x`` prefix. Anything else — most
# importantly ``"0x"``, which ``aggregate3`` returns with ``success=True`` for a
# call that returned no data — is NOT a balance. ``int("0x", 16)`` raises but
# ``int("0x0", 16)`` is 0, and a decode that tolerated short returndata would
# mint a ``proven_zero`` out of an empty return: a default standing in for a
# witness.
_WORD_HEX_LEN = 66


def _multicall3_supported(chain_id: int) -> bool:
    """Multicall3 is deployed at the same address on every chain in the registry.

    Kept as a named predicate so the pinned path has one place to become
    conditional if a chain without it is ever enabled, rather than failing with a
    decode error that would look like a transport problem.
    """
    return True


def pinned_native_balances(
    addresses: list[str],
    *,
    chain_id: int,
    rpc_url: str | None = None,
) -> tuple[int | None, dict[str, int]]:
    """Read native balances at ONE explicitly pinned height.

    Returns ``(block_number, {address_lower: wei})``. ``block_number`` is
    ``None`` — and the mapping empty — whenever the height or the read could not
    be established. There is no partial success at the block level: without a
    height, nothing read here may be published as a pinned fact, and the caller
    must fall back to the unpinned path where a zero is ``not_determined``.

    An address MISSING from the returned mapping is not a zero. It is "this
    sub-call did not yield a decodable 32-byte word", and the caller must treat
    it as a failed read.

    The block is resolved FIRST and every read is issued at it. Reading at
    ``"latest"`` and stamping a separately-fetched ``eth_blockNumber`` beside the
    answer would assert that the node answered at that head — an assumption, not
    a witness, and the invented-witness failure mode this whole unit is about.
    """
    if not addresses:
        return None, {}
    url = rpc_url or rpc_url_for_chain_id(chain_id)
    if not url or not _multicall3_supported(chain_id):
        return None, {}
    try:
        head = int(rpc_request(url, "eth_blockNumber", [], retries=1, chain_id=chain_id), 16)
    except Exception as exc:
        logger.info("pinned native balance: head read failed on chain %s: %s", chain_id, exc)
        return None, {}
    block = max(1, head - PINNED_FINALITY_MARGIN)
    # Derived, never hardcoded, for the reason ``multicall3_aggregate3`` states:
    # a typo in a hand-written selector mints wrong calldata silently.
    sel = selector("getEthBalance(address)")
    ordered = [a.lower() for a in addresses]
    calls = [(MULTICALL3_ADDRESS, sel + a[2:].rjust(64, "0")) for a in ordered]
    try:
        results = multicall3_aggregate3(url, calls, hex(block), chain_id=chain_id)
    except Exception as exc:
        logger.info("pinned native balance: aggregate3 failed on chain %s at %d: %s", chain_id, block, exc)
        return None, {}
    out: dict[str, int] = {}
    for address, (ok, data) in zip(ordered, results):
        if not ok or not isinstance(data, str) or len(data) != _WORD_HEX_LEN:
            # Includes the ``(True, "0x")`` empty-return shape. Excluded from the
            # mapping, never decoded as 0.
            continue
        try:
            out[address] = int(data, 16)
        except ValueError:
            continue
    return block, out


def native_status_for(*, wei: int | None, pinned: bool, failed: bool) -> str:
    """The one place a native read becomes a status.

    * ``failed`` — the read raised, came back an exception object, or produced no
      decodable word. Nothing is known about the balance.
    * pinned and zero — a proven zero: ``getEthBalance`` returned ``0x0`` AT a
      named height.
    * unpinned and zero — ``not_determined``. Etherscan answers ``tag=latest``
      and its response carries no height, so this is "zero at some unrecorded
      moment", which proves zero at no height. Publishing it as a proven zero is
      the exact conflation B2 names.
    * nonzero — ``proven_nonzero``, on either path. Read it as the PAIR with
      ``block_number``: with a NULL block it means "nonzero at an unrecorded
      height", never an as-of-block fact (see :func:`native_balance_fact`).
    """
    if failed or wei is None:
        return NATIVE_STATUS_FETCH_FAILED
    if wei > 0:
        return NATIVE_STATUS_PROVEN_NONZERO
    return NATIVE_STATUS_PROVEN_ZERO if pinned else NATIVE_STATUS_NOT_DETERMINED


def native_balance_fact(native_status: str, block_number: int | None) -> str:
    """What a ``(native_status, block_number)`` pair actually asserts.

    The status alone is not the fact and must never be consumed alone:
    ``proven_nonzero`` with a NULL block is a real observation with no height,
    and a consumer that read the status by itself would treat it as an
    as-of-block quantity. This is the single helper every consumer of
    ``native_status`` goes through.
    """
    if native_status == NATIVE_STATUS_PROVEN_ZERO:
        # The schema refuses this combination, so it is unreachable through the
        # DB; the branch exists so an in-memory caller cannot construct it either.
        if block_number is None:
            return "not_determined"
        return f"proven_zero_at_block_{block_number}"
    if native_status == NATIVE_STATUS_PROVEN_NONZERO:
        return f"proven_nonzero_at_block_{block_number}" if block_number is not None else "nonzero_at_unrecorded_height"
    if native_status == NATIVE_STATUS_FETCH_FAILED:
        return "not_determined"
    return "not_determined"


def balance_history_depth() -> int:
    """How many fetches per (contract, observed_address) retention keeps.

    Raises on a value below 1. Depth 0 would prune every fetch, and because the
    view's legacy arm shows pre-migration rows whenever no non-failed fetch
    exists, that would RESURRECT the 1,617 legacy rows as current holdings.
    """
    raw = os.getenv("PSAT_BALANCE_HISTORY_DEPTH", "10")
    try:
        depth = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"PSAT_BALANCE_HISTORY_DEPTH must be an integer >= 1, got {raw!r}") from exc
    if depth < 1:
        raise ValueError(f"PSAT_BALANCE_HISTORY_DEPTH must be >= 1, got {depth}")
    return depth


def prune_balance_fetches(session: Session, contract_id: int, observed_address: str) -> int:
    """Bound insert-only growth without ever deleting a published observation.

    The writers are insert-only now (the destructive per-contract DELETE is
    gone), and the TVL loop runs hourly, so history has to be bounded somewhere.
    It is bounded here, at the write point, by fetch — never by row — so a
    holdings set is only ever dropped whole.

    Two things are kept: the ``depth`` most recent fetches, AND, per row class,
    the most recent NON-FAILED fetch regardless of age. Without the second rule
    ``depth`` consecutive failures would evict the last good fetch and
    CASCADE-delete exactly the rows the view is currently publishing — an
    absence manufactured by a retention policy, which two downstream consumers
    turn into a published ``$0.00``.

    Returns the number of fetch rows deleted.
    """
    depth = balance_history_depth()
    rows = session.execute(
        select(
            ContractBalanceFetch.id,
            ContractBalanceFetch.native_status,
            ContractBalanceFetch.asset_set_status,
        )
        .where(
            ContractBalanceFetch.contract_id == contract_id,
            ContractBalanceFetch.observed_address == observed_address,
        )
        .order_by(ContractBalanceFetch.fetched_at.desc(), ContractBalanceFetch.id.desc())
    ).all()
    if len(rows) <= depth:
        return 0
    keep = {r.id for r in rows[:depth]}
    for status_index in (1, 2):  # native_status, then asset_set_status
        for row in rows:
            if row[status_index] != STATUS_FETCH_FAILED:
                keep.add(row.id)
                break
    doomed = [r.id for r in rows if r.id not in keep]
    if not doomed:
        return 0
    session.query(ContractBalanceFetch).filter(ContractBalanceFetch.id.in_(doomed)).delete(synchronize_session=False)
    return len(doomed)


def contracts_missing_current_rows(session: Session, contract_ids: list[int]) -> set[int]:
    """Contracts with no NON-FAILED fetch for at least one row class.

    Exactly the set whose current holdings the view cannot publish, so a total
    built over them is not a measurement of anything. A contract that has never
    been fetched at all is NOT in this set — its legacy rows are still the best
    available observation and the view still shows them.
    """
    if not contract_ids:
        return set()
    fetched = set(
        session.execute(
            select(ContractBalanceFetch.contract_id).where(ContractBalanceFetch.contract_id.in_(contract_ids))
        )
        .scalars()
        .all()
    )
    if not fetched:
        return set()
    ok_native = set(
        session.execute(
            select(ContractBalanceFetch.contract_id).where(
                ContractBalanceFetch.contract_id.in_(contract_ids),
                ContractBalanceFetch.native_status != STATUS_FETCH_FAILED,
            )
        )
        .scalars()
        .all()
    )
    ok_assets = set(
        session.execute(
            select(ContractBalanceFetch.contract_id).where(
                ContractBalanceFetch.contract_id.in_(contract_ids),
                ContractBalanceFetch.asset_set_status != STATUS_FETCH_FAILED,
            )
        )
        .scalars()
        .all()
    )
    return {cid for cid in fetched if cid not in ok_native or cid not in ok_assets}


def positive_raw_balance(raw_balance: object) -> bool:
    """Whether a stored ``raw_balance`` witnesses a strictly positive quantity.

    ``raw_balance`` is a varchar (the column stores decimal strings to avoid
    overflow), so this cannot be a SQL comparison: ``>`` would be lexicographic
    and a ``::numeric`` cast raises on any non-numeric legacy value, taking down
    the reading stage instead of skipping the row. Anything unparseable is
    EXCLUDED — the fail-closed direction. Measured on the pre-migration corpus:
    0 of 1617 rows are NULL, empty, zero or non-numeric, so this excludes
    nothing today and exists so a future writer cannot make row existence mean
    "holds this asset" again.
    """
    try:
        return int(str(raw_balance)) > 0
    except (TypeError, ValueError):
        return False


__all__ = [
    "PINNED_FINALITY_MARGIN",
    "balance_history_depth",
    "contracts_missing_current_rows",
    "native_balance_fact",
    "native_status_for",
    "pinned_native_balances",
    "positive_raw_balance",
    "prune_balance_fetches",
]
