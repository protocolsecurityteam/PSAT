"""Live tail scans that complete a lagging durable event fold over ``(frontier, block]``.

A warm cursor behind the evaluated block proves its rows only up to its frontier. The tail fetches the same topics at
the same address for the missing range, strictly: any rejected, malformed, removed or out-of-filter log fails the whole
tail, and a failed tail never licenses a stronger result than the durable rows alone.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from services.clients.rpc import rpc_request
from services.resolution.creation_block_floor import FLOOR_BASIS_TAIL
from services.resolution.repos.event_logs_rpc import FetchedEventLog, RpcEventLogFetcher
from utils.logging import record_degraded

logger = logging.getLogger(__name__)

# A tail this long is a stalled cursor, not a lagging one; resolution does not backfill in-line.
TAIL_MAX_SPAN = int(os.getenv("PSAT_EVENT_TAIL_MAX_SPAN", "50000"))
# Pages at or above this count are bisected, so a silently truncated page can't pass as whole.
TAIL_RESULT_CAP = 10_000

TAIL_SCAN_FAILED = "tail_scan_failed"
TAIL_SPAN_EXCEEDED = "tail_span_exceeded"


@dataclass(frozen=True)
class TailScan:
    """Logs in ``[from_block, to_block]`` in log order; ``complete`` only when every page came back whole."""

    complete: bool
    from_block: int
    to_block: int
    logs: tuple[FetchedEventLog, ...] = field(default=())
    reason: str | None = None

    def trace_fields(self) -> dict[str, Any]:
        return {"scan_from_block": self.from_block, "scan_to_block": self.to_block, "floor_basis": FLOOR_BASIS_TAIL}


# (event_address, topic0s, frontier, block) -> TailScan
TailScanner = Callable[[str, Sequence[str], int, int], TailScan]


class _TailFetcher(RpcEventLogFetcher):
    def _request_logs(self, params: list[Any]) -> Any:
        return rpc_request(self.rpc_url, "eth_getLogs", params, chain_id=self.chain_id)


def scan_event_tail(
    *,
    rpc_url: str,
    chain_id: int,
    event_address: str,
    topic0s: Sequence[str],
    frontier: int,
    block: int,
) -> TailScan:
    from_block = frontier + 1
    if block < from_block:
        return TailScan(complete=True, from_block=from_block, to_block=block)
    topics = sorted({t.lower() for t in topic0s if isinstance(t, str)})
    if not topics:
        return TailScan(complete=False, from_block=from_block, to_block=block, reason=TAIL_SCAN_FAILED)
    if block - frontier > TAIL_MAX_SPAN:
        logger.info(
            "event tail span exceeds the in-line limit; not scanning",
            extra={"event_address": event_address, "chain_id": chain_id, "frontier": frontier, "block": block},
        )
        return TailScan(complete=False, from_block=from_block, to_block=block, reason=TAIL_SPAN_EXCEEDED)
    logs: list[FetchedEventLog] = []
    try:
        _TailFetcher(rpc_url, chain_id=chain_id, result_cap=TAIL_RESULT_CAP).visit_logs(
            consume=logs.append,
            event_address=event_address.lower(),
            topics=topics,
            from_block=from_block,
            to_block=block,
        )
    except Exception as exc:
        record_degraded(
            phase="event_fold_tail",
            exc=exc,
            context={"event_address": event_address, "from_block": from_block, "to_block": block},
        )
        logger.warning(
            "event tail scan failed; the fold stays unproven past its frontier",
            extra={
                "event_address": event_address,
                "chain_id": chain_id,
                "from_block": from_block,
                "to_block": block,
                "exc_type": type(exc).__name__,
            },
        )
        return TailScan(complete=False, from_block=from_block, to_block=block, reason=TAIL_SCAN_FAILED)
    logs.sort(key=lambda log: (log.block_number, log.transaction_index, log.log_index))
    return TailScan(complete=True, from_block=from_block, to_block=block, logs=tuple(logs))


def tail_scanner_for(ctx: Any) -> TailScanner | None:
    """A scanner bound to the pass's RPC and chain, or ``None`` when the pass has no RPC or no pinned block (an unpinned
    head has no stable end for a tail).
    """
    rpc_url = getattr(ctx, "rpc_url", None)
    chain_id = getattr(ctx, "chain_id", None)
    if not isinstance(rpc_url, str) or not rpc_url or not isinstance(chain_id, int):
        return None
    if not isinstance(getattr(ctx, "block", None), int):
        return None
    meta = getattr(ctx, "meta", None)
    memo = meta.get("live_read_memo") if isinstance(meta, dict) else None

    def _scan(event_address: str, topic0s: Sequence[str], frontier: int, block: int) -> TailScan:
        key = (
            "event_tail",
            chain_id,
            event_address.lower(),
            tuple(sorted(t.lower() for t in topic0s)),
            frontier,
            block,
        )
        if isinstance(memo, dict) and isinstance(memo.get(key), TailScan):
            return memo[key]
        result = scan_event_tail(
            rpc_url=rpc_url,
            chain_id=chain_id,
            event_address=event_address,
            topic0s=topic0s,
            frontier=frontier,
            block=block,
        )
        # Failures aren't memoized, so one blip doesn't settle every function in the pass.
        if result.complete and isinstance(memo, dict):
            memo[key] = result
        return result

    return _scan
