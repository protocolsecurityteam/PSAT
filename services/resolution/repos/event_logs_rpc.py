"""RPC-backed fetchers for the generic event indexer."""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Sequence

from utils.rpc import RpcClientTimeout, rpc_request

logger = logging.getLogger(__name__)

# One eth_getLogs per window up to this span. The eRPC fast lane for getLogs
# (Envio HyperRPC) bills a flat 1000 credits per REQUEST regardless of block
# range — 60 requests/min total — and serves million-block ranges fine, so
# paging a window into small chunks burns the entire budget for no data
# (measured: 10k-page scanning cost ~140 credits per 1k blocks vs ~1 with
# single-request windows). Upstreams that can't take a wide range fail loudly
# (HyperRPC: -32005 "Limit exceeded: More than 50000 logs returned" / -32603
# "Query timed out"; regular nodes: explicit range caps) — never truncate — so
# ``_fetch_range`` bisects on error down to MIN_BISECT_SPAN before giving up.
MAX_BLOCK_RANGE = 1_000_000
MIN_BISECT_SPAN = 10_000

# Pause before the one same-window retry a client timeout earns. Short on
# purpose: it exists to let a transient stall clear, not to wait out an
# upstream, and it is paid at most once per window.
TIMEOUT_RETRY_BACKOFF_SECONDS = 0.5

# Result cap the upstream is believed to enforce by SILENTLY returning a short
# 200-OK page. A page whose length reaches it is treated as a reject and
# bisected, exactly like an error, because the alternative is advancing a cursor
# past logs that were never returned.
#
# Default None = "no cap is known to be in force", and that is a measurement,
# not a shrug: against the deployed eRPC route on 2026-07-30 single windows
# returned 9,030 / 45,055 / 68,256 / 125,629 logs, each with
# ``max(blockNumber) == toBlock`` — no truncation at any size tried, and the
# documented HyperRPC 50,000 result cap did not fire. Hard-coding 50,000 here
# would bisect windows that the upstream serves whole, spending request budget to
# buy nothing. The consequence is stated rather than hidden: while this is None
# no cursor can be promoted to page-complete, so every event-absence negative
# keeps an unquantified residual (see ``window_stats_basis``).
#
# It follows that this value is a claim about a third party at one moment, not an
# invariant — which is why the cap in force is persisted per cursor alongside the
# counts it gated, and a verdict is refused when the two disagree.
_RESULT_CAP_ENV = "PSAT_GETLOGS_RESULT_CAP"


def default_result_cap() -> int | None:
    raw = (os.getenv(_RESULT_CAP_ENV) or "").strip()
    if not raw:
        return None
    try:
        parsed = int(raw)
    except ValueError:
        logger.warning("ignoring non-integer %s=%r; treating the result cap as unknown", _RESULT_CAP_ENV, raw)
        return None
    return parsed if parsed > 0 else None


def normalize_topic_filter(topics: Sequence[Any]) -> list[list[str] | None]:
    """The ``topics`` argument in its one on-the-wire form.

    Returns the positional array ``eth_getLogs`` takes: index *i* is the
    constraint on topic position *i*, ``None`` meaning unconstrained.

    A flat sequence of strings is the historical topic0 OR-set and normalizes to
    ``[[t0, ...]]`` — byte-identical to what this fetcher has always sent, which
    is why no existing caller changes. Any other element type (a sequence or
    ``None``) means the caller is addressing positions explicitly, and each slot
    is taken as written. An empty slot list is refused rather than sent: ``[]``
    in a topic position matches NOTHING at some upstreams and EVERYTHING at
    others, so a batch that happened to come out empty would silently read as
    either "no transfers" or "every transfer on the chain".
    """
    entries = list(topics)
    if all(isinstance(entry, str) for entry in entries):
        # ``[[]]`` for an empty sequence, not ``[]`` — that is the exact payload
        # this fetcher has always sent, and the two are not the same filter.
        return [[str(t).lower() for t in entries]]
    out: list[list[str] | None] = []
    for index, entry in enumerate(entries):
        if entry is None:
            out.append(None)
            continue
        if isinstance(entry, str):
            out.append([entry.lower()])
            continue
        values = [str(t).lower() for t in entry]
        if not values:
            raise ValueError(f"topic position {index} was given an empty value list")
        out.append(values)
    return out


@dataclass(frozen=True)
class FetchWindowStat:
    """One accepted ``eth_getLogs`` page: the window, how many logs came back,
    and the cap that was in force when it was accepted.

    ``cap is None`` means no cap was enforced, so ``returned_log_count`` bounds
    nothing — the page may have been complete or may have been truncated by an
    upstream whose limit we do not know. Only a stat with a non-None ``cap`` and
    ``returned_log_count < cap`` witnesses a whole page.

    ``returned_log_count is None`` means the response was not a countable page at
    all (``result: null``, an object, anything but a list). That is NOT a page of
    zero logs: a malformed 200-OK recorded as 0 would read as a proven empty
    window, which is the strongest possible claim minted from the least
    information. It downgrades the cursor's window record instead.
    """

    from_block: int
    to_block: int
    returned_log_count: int | None
    cap: int | None


@dataclass(frozen=True)
class FetchedEventLog:
    tx_hash: bytes
    log_index: int
    block_number: int
    block_hash: bytes
    transaction_index: int
    topics: list[str]
    data_words: list[str]
    # Emitting contract, lowercased — how a multi-address caller attributes a
    # log to the cohort member that emitted it. Empty for logs a caller
    # constructed without one (single-address callers already know the address).
    address: str = ""
    # The untouched RPC log dict, so a caller that runs the raw-dict decode
    # pipeline (services/monitoring/event_topics.parse_any_log) gets its input
    # from the same bisecting fetch — excluded from equality (dicts are unhashable
    # and the decoded fields above already carry identity).
    raw: dict[str, Any] | None = field(default=None, compare=False)


class RpcEventLogFetcher:
    def __init__(
        self,
        rpc_url: str,
        *,
        max_block_range: int = MAX_BLOCK_RANGE,
        min_bisect_span: int = MIN_BISECT_SPAN,
        chain_id: int | None = None,
        result_cap: int | None = None,
        timeout: float | None = None,
    ) -> None:
        self.rpc_url = rpc_url
        self.max_block_range = max(1, max_block_range)
        self.min_bisect_span = max(1, min_bisect_span)
        # Default None — no cap, so no caller acquires the bisect-and-raise
        # behaviour by omission. The environment default is applied by the
        # DURABLE INDEXER's fetcher builder alone, because only it persists the
        # counts the cap gates; the live monitoring watcher constructs a fetcher
        # here too and must keep returning pages an operator's env var would
        # otherwise turn into a raise at the bisect floor.
        self.result_cap = result_cap
        # Declared so ``rpc_request`` can assert the eRPC URL routes this chain
        # (inv. 7). None keeps the guard a no-op for callers that lack a chain.
        self.chain_id = chain_id
        # None = the module default in ``rpc_request``, which is what every
        # landed caller gets. A caller whose windows are wide enough that an
        # honest answer outlasts that default passes its own ceiling. Timeouts
        # that still happen arrive typed (``RpcClientTimeout``) and buy one
        # same-window retry before the bisect path treats them as a reject: the
        # extent of a scan is a claim about the chain, never about how long this
        # process waited.
        self.timeout = timeout

    def fetch_logs(
        self,
        *,
        event_address: str | Sequence[str] | None = None,
        topics: Sequence[Any],
        from_block: int,
        to_block: int,
        window_stats: list[FetchWindowStat] | None = None,
    ) -> list[FetchedEventLog]:
        """Fetch logs matching ``topics``, optionally restricted to ``event_address``.

        ``topics`` takes two shapes and :func:`normalize_topic_filter` decides
        which by inspecting the elements, so no existing call site changes:

        * a flat sequence of topic strings — the historical shape — is an OR-set
          over topic position 0. Multiple topic0 values fold into one request
          (``"topics": [[t1, t2]]`` is OR semantics) so same-address cursors
          don't each rescan the same range; the request, not the range, is what
          the upstream budget meters.
        * a sequence whose elements are themselves sequences or ``None`` is the
          FULL positional topic array: element *i* constrains topic position *i*,
          ``None`` constrains nothing there. This is what an
          asset-discovery sweep needs — a recipient in topic position 2 or 3 with
          no emitter known in advance.

        ``event_address`` may be a single address (existing per-cursor callers),
        a list — a multi-address filter serves a whole cohort of monitored
        contracts in one request — or ``None``, which emits NO address key and
        matches every emitter. Per-emitter attribution is on each result's
        ``.address``. All shapes share this one bisect-on-reject implementation.

        A filter that constrains neither address nor any topic position is
        refused: it asks the upstream for every log on the chain, and the answer
        would be truncated in ways no cap check here can see.

        Pass ``window_stats`` to collect one :class:`FetchWindowStat` per
        ACCEPTED page (bisected windows contribute their leaves, not the rejected
        parent). Omitting it — what every caller that does not persist coverage
        does — leaves behaviour and the request sequence unchanged.
        """
        address_filter: str | list[str] | None
        if event_address is None or isinstance(event_address, str):
            address_filter = event_address
        else:
            address_filter = list(event_address)
        topic_filter = normalize_topic_filter(topics)
        if address_filter is None and not any(slot for slot in topic_filter):
            raise ValueError("eth_getLogs filter constrains neither address nor any topic position")
        out: list[FetchedEventLog] = []
        start = from_block
        while start <= to_block:
            end = min(to_block, start + self.max_block_range - 1)
            out.extend(self._fetch_range(address_filter, topic_filter, start, end, window_stats))
            start = end + 1
        return out

    def _fetch_range(
        self,
        event_address: str | list[str] | None,
        topics: list[list[str] | None],
        from_block: int,
        to_block: int,
        window_stats: list[FetchWindowStat] | None = None,
    ) -> list[FetchedEventLog]:
        log_filter: dict[str, Any] = {
            "topics": topics,
            "fromBlock": hex(from_block),
            "toBlock": hex(to_block),
        }
        # The key is OMITTED rather than sent as null: an explicit null address
        # is not a documented filter shape and upstreams differ on it, while an
        # absent key is the spec's own "any emitter".
        if event_address is not None:
            log_filter["address"] = event_address
        params = [log_filter]
        try:
            raw_logs = self._request_logs(params)
        except RpcClientTimeout:
            # A client timeout is this process's wait ending, not the upstream
            # rejecting the window, so bisecting on it splits a window that was
            # only SLOW — and each half inherits the same stall, fanning one
            # window out into hundreds of leaf requests. Retry the same window
            # once; only a second failure is read as a reject.
            time.sleep(TIMEOUT_RETRY_BACKOFF_SECONDS)
            try:
                raw_logs = self._request_logs(params)
            except RuntimeError as exc:
                return self._reject_window(event_address, topics, from_block, to_block, exc, window_stats)
        except RuntimeError as exc:
            return self._reject_window(event_address, topics, from_block, to_block, exc, window_stats)
        # A page whose length reaches the cap is indistinguishable from a page the
        # upstream truncated to the cap, so it is a REJECT, not a result: take the
        # same bisect the error path takes. Without this the window loop advances
        # ``start = end + 1`` over logs that were never returned, and the cursor
        # records a range it never actually read. The ``cap is not None`` guard is
        # load-bearing and must stay literal — an unguarded ``>=`` against None
        # raises TypeError, which is not RuntimeError and would escape the bisect
        # entirely, taking the whole scan down instead of narrowing the window.
        cap = self.result_cap
        # A response that is not a list is not a page of zero logs — it is a page
        # we could not read. Recording 0 would turn a malformed payload into a
        # proven empty window.
        count = len(raw_logs) if isinstance(raw_logs, list) else None
        if cap is not None and count is not None and count >= cap:
            span = to_block - from_block + 1
            if span <= self.min_bisect_span:
                raise RuntimeError(
                    f"eth_getLogs returned {count} logs at the {cap} result cap for "
                    f"[{from_block}, {to_block}] and the span is at the bisect floor: "
                    "the page cannot be proven whole"
                )
            logger.debug(
                "eth_getLogs window returned a page at the result cap; bisecting",
                extra={
                    "event_address": event_address,
                    "from_block": from_block,
                    "to_block": to_block,
                    "span": span,
                    "returned_log_count": count,
                    "result_cap": cap,
                },
            )
            return self._bisect_halves(event_address, topics, from_block, to_block, span, window_stats)
        if window_stats is not None:
            window_stats.append(
                FetchWindowStat(from_block=from_block, to_block=to_block, returned_log_count=count, cap=cap)
            )
        out: list[FetchedEventLog] = []
        if isinstance(raw_logs, list):
            for raw in raw_logs:
                decoded = _decode_log(raw)
                if decoded is not None:
                    out.append(decoded)
        return out

    def _request_logs(self, params: list[Any]) -> Any:
        # Two branches rather than one call passing ``timeout=None``: a fetcher
        # that declared no ceiling issues the SAME call it always has, argument
        # for argument, so nothing about the landed callers' request changes.
        if self.timeout is None:
            return rpc_request(self.rpc_url, "eth_getLogs", params, chain_id=self.chain_id)
        return rpc_request(self.rpc_url, "eth_getLogs", params, chain_id=self.chain_id, timeout=self.timeout)

    def _reject_window(
        self,
        event_address: str | list[str] | None,
        topics: list[list[str] | None],
        from_block: int,
        to_block: int,
        exc: RuntimeError,
        window_stats: list[FetchWindowStat] | None,
    ) -> list[FetchedEventLog]:
        # Result-cap / range-cap / query-timeout from the upstream. Halve and
        # recurse; a span at the floor is a real error, not a sizing problem.
        span = to_block - from_block + 1
        if span <= self.min_bisect_span:
            raise exc
        # Per-window detail (the parent scan logs the aggregate) — DEBUG.
        logger.debug(
            "eth_getLogs window rejected; bisecting",
            extra={
                "event_address": event_address,
                "from_block": from_block,
                "to_block": to_block,
                "span": span,
                "exc_type": type(exc).__name__,
            },
        )
        return self._bisect_halves(event_address, topics, from_block, to_block, span, window_stats)

    def _bisect_halves(
        self,
        event_address: str | list[str] | None,
        topics: list[list[str] | None],
        from_block: int,
        to_block: int,
        span: int,
        window_stats: list[FetchWindowStat] | None,
    ) -> list[FetchedEventLog]:
        mid = from_block + span // 2 - 1
        return self._fetch_range(event_address, topics, from_block, mid, window_stats) + self._fetch_range(
            event_address, topics, mid + 1, to_block, window_stats
        )


class RpcHeadBlockFetcher:
    def __init__(self, rpc_url: str, *, chain_id: int | None = None) -> None:
        self.rpc_url = rpc_url
        self.chain_id = chain_id

    def head_block(self) -> int:
        raw = rpc_request(self.rpc_url, "eth_blockNumber", [], chain_id=self.chain_id)
        if not isinstance(raw, str) or not raw.startswith("0x"):
            raise RuntimeError(f"Unexpected eth_blockNumber result: {raw!r}")
        return int(raw, 16)


class RpcBlockHashFetcher:
    def __init__(self, rpc_url: str, *, chain_id: int | None = None) -> None:
        self.rpc_url = rpc_url
        self.chain_id = chain_id

    def block_hash(self, block_number: int) -> bytes | None:
        raw = rpc_request(self.rpc_url, "eth_getBlockByNumber", [hex(block_number), False], chain_id=self.chain_id)
        if not isinstance(raw, dict):
            return None
        return _hex_to_bytes(raw.get("hash"), 32)


def _decode_log(raw: Any) -> FetchedEventLog | None:
    if not isinstance(raw, dict):
        return None
    topics = raw.get("topics")
    if not isinstance(topics, list) or not topics:
        return None
    tx_hash = _hex_to_bytes(raw.get("transactionHash"), 32)
    block_hash = _hex_to_bytes(raw.get("blockHash"), 32)
    if tx_hash is None or block_hash is None:
        return None
    try:
        log_index = _hex_int(raw.get("logIndex"))
        block_number = _hex_int(raw.get("blockNumber"))
        transaction_index = _hex_int(raw.get("transactionIndex"))
    except (TypeError, ValueError):
        return None
    emitter = raw.get("address")
    return FetchedEventLog(
        tx_hash=tx_hash,
        log_index=log_index,
        block_number=block_number,
        block_hash=block_hash,
        transaction_index=transaction_index,
        topics=[str(t).lower() for t in topics],
        data_words=_split_data_words(raw.get("data")),
        address=emitter.lower() if isinstance(emitter, str) else "",
        raw=raw,
    )


def _hex_int(raw: Any) -> int:
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise TypeError(raw)
    return int(raw, 16)


def _hex_to_bytes(raw: Any, size: int) -> bytes | None:
    if not isinstance(raw, str) or not raw.startswith("0x"):
        return None
    body = raw[2:]
    if len(body) != size * 2:
        return None
    try:
        return bytes.fromhex(body)
    except ValueError:
        return None


def _split_data_words(raw: Any) -> list[str]:
    if not isinstance(raw, str) or not raw.startswith("0x"):
        return []
    body = raw[2:]
    if len(body) % 64 != 0:
        return []
    return ["0x" + body[i : i + 64].lower() for i in range(0, len(body), 64)]
