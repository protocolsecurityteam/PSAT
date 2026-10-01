"""RPC-backed fetchers for the generic event indexer."""

from __future__ import annotations

import logging
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Iterator, Sequence, cast

from services.clients.rpc import RpcClientTimeout, rpc_request

logger = logging.getLogger(__name__)

# One eth_getLogs per window up to this span. HyperRPC bills per request regardless of range, so small pages waste the
# budget (measured ~140x). Upstreams that can't handle a range fail loudly rather than truncate, so ``iter_pages``
# bisects on error down to MIN_BISECT_SPAN.
MAX_BLOCK_RANGE = 1_000_000
MIN_BISECT_SPAN = 10_000

# Short: only for a transient stall, paid at most once per window.
TIMEOUT_RETRY_BACKOFF_SECONDS = 0.5

# A result cap the upstream might enforce with a silently short 200-OK page. Pages reaching it are treated as rejects
# and bisected so the cursor never skips unreturned logs.
#
# Default None was measured: on 2026-07-30 the deployed eRPC route returned up to 125,629 logs per window untruncated,
# and the documented 50,000 cap didn't fire. With None, no cursor can be page-complete, so event-absence negatives keep
# a residual (see ``window_stats_basis``). The cap in force is persisted per cursor.
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
    """The positional ``topics`` array for ``eth_getLogs`` (``None`` = unconstrained).

    A flat string sequence is the historical topic0 OR-set and becomes ``[[t0, ...]]``, unchanged on the wire. Sequences
    or ``None`` elements address positions explicitly. An empty slot list is refused: upstreams disagree on whether
    ``[]`` matches nothing or everything.
    """
    entries = list(topics)
    if all(isinstance(entry, str) for entry in entries):
        # ``[[]]``, not ``[]``: the historical payload; they're different filters.
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
    """One accepted ``eth_getLogs`` page: window, log count, and the cap in force.

    ``cap is None`` means the count bounds nothing. Only a non-None cap with ``returned_log_count < cap`` proves a whole
    page. ``returned_log_count is None`` means the response wasn't a countable list; recording 0 would mint a
    proven-empty window.
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
    # Emitting contract, lowercased, for multi-address callers; empty for single-address callers.
    address: str = ""
    # The raw ``data`` when it isn't word-aligned (``data_words`` is then empty): stored losslessly, never decoded.
    data_hex: str | None = None
    # The raw RPC dict for callers running ``services/monitoring/event_topics.parse_any_log``; excluded from equality.
    raw: dict[str, Any] | None = field(default=None, compare=False)


@dataclass(frozen=True)
class LogPage:
    """One accepted response over a contiguous block range.

    ``stats`` holds one record per accepted request behind the page (one for ``iter_pages``). ``rejected`` counts the
    requests refused or discarded since the previous page; ``rejected_span`` is the narrowest range the upstream itself
    refused among them (a size limit, a query timeout), ``None`` when it refused none.
    """

    from_block: int
    to_block: int
    logs: list[FetchedEventLog]
    stats: tuple[FetchWindowStat, ...]
    rejected: int = 0
    rejected_span: int | None = None

    @property
    def returned_log_count(self) -> int | None:
        counts = [stat.returned_log_count for stat in self.stats]
        if not counts or any(count is None for count in counts):
            return None
        return sum(cast(int, count) for count in counts)


class RpcScanCancelled(RuntimeError): ...


class MalformedLogPage(RuntimeError):
    """A strict fetch found a log it can't trust whole; the page is rejected, never partly kept."""

    def __init__(self, reason: str, from_block: int, to_block: int) -> None:
        super().__init__(f"eth_getLogs page [{from_block}, {to_block}] rejected: {reason}")
        self.reason = reason
        self.from_block = from_block
        self.to_block = to_block


class RpcRangeTooLarge(RuntimeError): ...


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
        before_retry: Callable[[], None] | None = None,
        keep_raw: bool = True,
        strict: bool = False,
    ) -> None:
        self.rpc_url = rpc_url
        self.max_block_range = max(1, max_block_range)
        self.min_bisect_span = max(1, min_bisect_span)
        # No cap by default; only the durable indexer's builder applies the env cap because only it persists the counts.
        # The live monitoring watcher must not start raising at the bisect floor.
        self.result_cap = result_cap
        # Lets ``rpc_request`` check the URL routes this chain.
        self.chain_id = chain_id
        # None uses ``rpc_request``'s default. Timeouts arrive as ``RpcClientTimeout`` and get one same-window retry
        # before being treated as a reject.
        self.timeout = timeout
        self.before_retry = before_retry
        # Only the live watcher reads ``FetchedEventLog.raw``; holding the dict more than doubles a page's memory.
        self.keep_raw = keep_raw
        # Strict pages reject on any malformed, removed, out-of-range or out-of-filter log instead of dropping it.
        self.strict = strict

    def fetch_logs(
        self,
        *,
        event_address: str | Sequence[str] | None = None,
        topics: Sequence[Any],
        from_block: int,
        to_block: int,
        window_stats: list[FetchWindowStat] | None = None,
    ) -> list[FetchedEventLog]:
        """Fetch logs matching ``topics``, optionally restricted to ``event_address``: every page of
        :meth:`iter_pages`, flattened in block order.

        ``topics`` is either a flat OR-set over topic0 (the historical shape; one request serves several cursors) or a
        full positional array (element *i* constrains position *i*), per :func:`normalize_topic_filter`.

        ``event_address`` may be one address, a list (one request per cohort; attribution via ``.address``), or ``None``
        (any emitter). A filter constraining neither address nor any topic is refused.

        ``window_stats`` collects one :class:`FetchWindowStat` per accepted page (bisected leaves, not rejected
        parents).
        """
        out: list[FetchedEventLog] = []
        for page in self.iter_pages(
            event_address=event_address,
            topics=topics,
            from_block=from_block,
            to_block=to_block,
            window_stats=window_stats,
        ):
            out.extend(page.logs)
        return out

    def iter_pages(
        self,
        *,
        event_address: str | Sequence[str] | None = None,
        topics: Sequence[Any],
        from_block: int,
        to_block: int,
        window_stats: list[FetchWindowStat] | None = None,
        max_page_logs: int | None = None,
    ) -> Iterator[LogPage]:
        """Yield accepted pages over ``[from_block, to_block]``, ascending and gap-free.

        A rejected request is bisected; at ``min_bisect_span`` the rejection propagates, as does a page at the result
        cap. A page over ``max_page_logs`` is discarded and bisected below the floor, down to one block; a single block
        over it is accepted whole. Each request happens on demand, so the caller can commit a page before the next.
        """
        address_filter: str | list[str] | None
        if event_address is None or isinstance(event_address, str):
            address_filter = event_address
        else:
            address_filter = list(event_address)
        topic_filter = normalize_topic_filter(topics)
        if address_filter is None and not any(slot for slot in topic_filter):
            raise ValueError("eth_getLogs filter constrains neither address nor any topic position")
        windows: list[tuple[int, int]] = []
        start = from_block
        while start <= to_block:
            end = min(to_block, start + self.max_block_range - 1)
            windows.append((start, end))
            start = end + 1
        pending = windows[::-1]
        rejected = 0
        rejected_span: int | None = None
        while pending:
            lo, hi = pending.pop()
            raw_logs = self._request_range(address_filter, topic_filter, lo, hi)
            span = hi - lo + 1
            if raw_logs is _REJECTED:
                rejected += 1
                rejected_span = span if rejected_span is None else min(rejected_span, span)
                pending.extend(_halves(lo, hi)[::-1])
                continue
            # A page at the cap is indistinguishable from a truncated one, so bisect it like an error. The ``is not
            # None`` guard matters: ``>=`` against None raises TypeError, which would escape the bisect.
            cap = self.result_cap
            # A non-list response is unreadable, not zero logs.
            count = len(raw_logs) if isinstance(raw_logs, list) else None
            if cap is not None and count is not None and count >= cap:
                if span <= self.min_bisect_span:
                    raise RuntimeError(
                        f"eth_getLogs returned {count} logs at the {cap} result cap for "
                        f"[{lo}, {hi}] and the span is at the bisect floor: "
                        "the page cannot be proven whole"
                    )
                logger.debug(
                    "eth_getLogs window returned a page at the result cap; bisecting",
                    extra={
                        "event_address": address_filter,
                        "from_block": lo,
                        "to_block": hi,
                        "span": span,
                        "returned_log_count": count,
                        "result_cap": cap,
                    },
                )
                raw_logs = None
                rejected += 1
                pending.extend(_halves(lo, hi)[::-1])
                continue
            if max_page_logs is not None and count is not None and count > max_page_logs:
                if span > 1:
                    logger.debug(
                        "eth_getLogs page over the memory ceiling; discarded and bisecting",
                        extra={
                            "event_address": address_filter,
                            "from_block": lo,
                            "to_block": hi,
                            "span": span,
                            "returned_log_count": count,
                            "max_page_logs": max_page_logs,
                        },
                    )
                    raw_logs = None
                    rejected += 1
                    pending.extend(_halves(lo, hi)[::-1])
                    continue
                # Blocks are atomic, so one block over the ceiling is taken whole; memory is bounded by it instead.
                logger.warning(
                    "single block exceeds the page ceiling; accepted whole",
                    extra={
                        "event_address": address_filter,
                        "block_number": lo,
                        "returned_log_count": count,
                        "max_page_logs": max_page_logs,
                    },
                )
            stat = FetchWindowStat(from_block=lo, to_block=hi, returned_log_count=count, cap=cap)
            if window_stats is not None:
                window_stats.append(stat)
            logs = (
                _strict_page(raw_logs, lo, hi, address_filter, topic_filter, keep_raw=self.keep_raw)
                if self.strict
                else self._decode_page(raw_logs)
            )
            page = LogPage(
                from_block=lo, to_block=hi, logs=logs, stats=(stat,), rejected=rejected, rejected_span=rejected_span
            )
            logs = []
            raw_logs = None
            yield page
            # Drop this frame's reference so the consumer's release frees the page before the next request.
            page = None
            rejected = 0
            rejected_span = None

    def _request_range(
        self, address_filter: str | list[str] | None, topic_filter: list[list[str] | None], lo: int, hi: int
    ) -> Any:
        """The response for one range, or ``_REJECTED`` when the range must be bisected."""
        log_filter: dict[str, Any] = {"topics": topic_filter, "fromBlock": hex(lo), "toBlock": hex(hi)}
        # Omit the key rather than send null: absence is the spec's "any emitter", explicit null isn't.
        if address_filter is not None:
            log_filter["address"] = address_filter
        params = [log_filter]
        try:
            try:
                return self._request_logs(params)
            except RpcClientTimeout:
                # A client timeout means we stopped waiting, not a reject. Bisecting a slow window fans it into
                # hundreds of slow leaves, so retry once first.
                time.sleep(TIMEOUT_RETRY_BACKOFF_SECONDS)
                return self._request_logs(params)
        except RpcScanCancelled:
            raise
        except RuntimeError as exc:
            # Upstream cap or timeout: halve; at the floor it's a real error.
            span = hi - lo + 1
            if span <= self.min_bisect_span:
                raise
            logger.debug(
                "eth_getLogs window rejected; bisecting",
                extra={
                    "event_address": address_filter,
                    "from_block": lo,
                    "to_block": hi,
                    "span": span,
                    "exc_type": type(exc).__name__,
                },
            )
            return _REJECTED

    def _decode_page(self, raw_logs: Any) -> list[FetchedEventLog]:
        out: list[FetchedEventLog] = []
        dropped = 0
        if isinstance(raw_logs, list):
            for raw in raw_logs:
                decoded = _decode_log(raw, keep_raw=self.keep_raw)
                if decoded is not None:
                    out.append(decoded)
                else:
                    dropped += 1
        unaligned = sum(1 for log in out if log.data_hex is not None)
        if dropped or unaligned:
            logger.debug(
                "eth_getLogs page carried logs that don't decode whole",
                extra={"dropped_logs": dropped, "unaligned_data_logs": unaligned},
            )
        return out

    def visit_logs(
        self,
        *,
        consume: Callable[[FetchedEventLog], None],
        event_address: str | Sequence[str] | None = None,
        topics: Sequence[Any],
        from_block: int,
        to_block: int,
        bisect: bool = True,
    ) -> None:
        """Visit validated pages without retaining full history.

        Callback effects are provisional until return; callers must discard the scan on any exception. ``bisect=False``
        leaves subdivision to a caller coordinating several filters, which must pass a single window.
        """
        if self.result_cap is None or self.result_cap <= 0:
            raise ValueError("streaming a complete scan requires an explicit result cap")
        if not bisect and to_block - from_block + 1 > self.max_block_range:
            raise ValueError("a coordinated partition must fit in one request window")
        address = event_address if isinstance(event_address, str) or event_address is None else list(event_address)
        filters = normalize_topic_filter(topics)
        if address is None and not any(filters):
            raise ValueError("eth_getLogs filter constrains neither address nor any topic position")
        addresses = (
            None if address is None else {a.lower() for a in ([address] if isinstance(address, str) else address)}
        )
        start = from_block
        while start <= to_block:
            end = min(to_block, start + self.max_block_range - 1)
            pending = [(start, end)]
            while pending:
                lo, hi = pending.pop()
                query: dict[str, Any] = {"topics": filters, "fromBlock": hex(lo), "toBlock": hex(hi)}
                if address is not None:
                    query["address"] = address
                rejected = False
                page: Any = None
                # Leave the handlers before descending; tracebacks may retain response bodies.
                try:
                    try:
                        page = self._request_logs([query])
                    except RpcClientTimeout:
                        time.sleep(TIMEOUT_RETRY_BACKOFF_SECONDS)
                        page = self._request_logs([query])
                except RpcScanCancelled:
                    raise
                except RuntimeError:
                    if hi - lo + 1 <= self.min_bisect_span:
                        raise
                    rejected = True
                if not rejected:
                    if not isinstance(page, list):
                        raise RuntimeError("eth_getLogs returned a malformed page")
                    if len(page) >= self.result_cap:
                        page = None
                        if hi - lo + 1 <= self.min_bisect_span:
                            raise RuntimeError("eth_getLogs reached the result cap at the bisect floor")
                        rejected = True
                if rejected:
                    if not bisect:
                        raise RpcRangeTooLarge("eth_getLogs requires a smaller partition")
                    mid = lo + (hi - lo + 1) // 2 - 1
                    pending.extend(((mid + 1, hi), (lo, mid)))
                    continue
                assert isinstance(page, list)
                _visit_page(page, lo, hi, addresses, filters, consume)
                page = None
            start = end + 1

    def _request_logs(self, params: list[Any]) -> Any:
        # Two calls rather than passing ``timeout=None``, so callers without a ceiling issue exactly the old call.
        if self.before_retry is not None:
            return rpc_request(
                self.rpc_url,
                "eth_getLogs",
                params,
                chain_id=self.chain_id,
                timeout=self.timeout,
                before_retry=self.before_retry,
            )
        if self.timeout is None:
            return rpc_request(self.rpc_url, "eth_getLogs", params, chain_id=self.chain_id)
        return rpc_request(self.rpc_url, "eth_getLogs", params, chain_id=self.chain_id, timeout=self.timeout)


_REJECTED: Any = object()


def _halves(lo: int, hi: int) -> list[tuple[int, int]]:
    mid = lo + (hi - lo + 1) // 2 - 1
    return [(lo, mid), (mid + 1, hi)]


def _visit_page(
    page: list[Any],
    lo: int,
    hi: int,
    addresses: set[str] | None,
    filters: list[list[str] | None],
    consume: Callable[[FetchedEventLog], None],
) -> None:
    # Identical logs can't cross disjoint validated partitions, so identity state lives for one page. Conflicts are
    # validated before exposing any event.
    identities: dict[tuple[bytes, int], FetchedEventLog] = {}
    positions: dict[tuple[int, int], tuple[bytes, int]] = {}
    blocks: dict[int, bytes] = {}
    for raw in page:
        decoded = _validate_scan_log(raw, lo, hi, addresses, filters)
        identity = (decoded.tx_hash, decoded.log_index)
        position = (decoded.block_number, decoded.log_index)
        if identity in identities and identities[identity] != decoded:
            raise RuntimeError("eth_getLogs returned conflicting duplicate identities")
        if position in positions and positions[position] != identity:
            raise RuntimeError("eth_getLogs returned conflicting log positions")
        if decoded.block_number in blocks and blocks[decoded.block_number] != decoded.block_hash:
            raise RuntimeError("eth_getLogs mixed block histories")
        identities[identity] = decoded
        positions[position] = identity
        blocks[decoded.block_number] = decoded.block_hash
    for decoded in identities.values():
        consume(decoded)


def _strict_page(
    raw_logs: Any,
    lo: int,
    hi: int,
    address_filter: str | list[str] | None,
    filters: list[list[str] | None],
    *,
    keep_raw: bool,
) -> list[FetchedEventLog]:
    if not isinstance(raw_logs, list):
        raise MalformedLogPage("the response is not a log list", lo, hi)
    addresses = (
        None
        if address_filter is None
        else {a.lower() for a in ([address_filter] if isinstance(address_filter, str) else address_filter)}
    )
    out: list[FetchedEventLog] = []
    identities: dict[tuple[bytes, int], FetchedEventLog] = {}
    positions: dict[tuple[int, int], tuple[bytes, int]] = {}
    blocks: dict[int, bytes] = {}
    for raw in raw_logs:
        decoded = _decode_log(raw, keep_raw=keep_raw)
        if decoded is None:
            raise MalformedLogPage("a log is missing or has malformed required fields", lo, hi)
        data = raw.get("data")
        valid = (
            lo <= decoded.block_number <= hi
            and decoded.log_index >= 0
            and decoded.transaction_index >= 0
            and _hex_to_bytes(decoded.address, 20) is not None
            and (addresses is None or decoded.address in addresses)
            and raw.get("removed", False) is False
            and len(decoded.topics) <= 4
            and all(_hex_to_bytes(t, 32) is not None for t in decoded.topics)
            and isinstance(data, str)
            and re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", data) is not None
            and all(
                slot is None or (i < len(decoded.topics) and decoded.topics[i] in slot)
                for i, slot in enumerate(filters)
            )
        )
        if not valid:
            raise MalformedLogPage("a log is removed, out of range, out of filter or malformed", lo, hi)
        identity = (decoded.tx_hash, decoded.log_index)
        position = (decoded.block_number, decoded.log_index)
        if identity in identities and identities[identity] != decoded:
            raise MalformedLogPage("conflicting duplicate log identities", lo, hi)
        if position in positions and positions[position] != identity:
            raise MalformedLogPage("conflicting log positions", lo, hi)
        if decoded.block_number in blocks and blocks[decoded.block_number] != decoded.block_hash:
            raise MalformedLogPage("one block with two hashes", lo, hi)
        identities[identity] = decoded
        positions[position] = identity
        blocks[decoded.block_number] = decoded.block_hash
        out.append(decoded)
    return out


def _validate_scan_log(
    raw: Any, lo: int, hi: int, addresses: set[str] | None, filters: list[list[str] | None]
) -> FetchedEventLog:
    decoded = _decode_log(raw)
    if decoded is None:
        raise RuntimeError("eth_getLogs returned an undecodable log")
    valid = (
        lo <= decoded.block_number <= hi
        and decoded.log_index >= 0
        and decoded.transaction_index >= 0
        and _hex_to_bytes(decoded.address, 20) is not None
        and (addresses is None or decoded.address in addresses)
        and raw.get("removed", False) is False
        and len(decoded.topics) <= 4
        and all(_hex_to_bytes(t, 32) is not None for t in decoded.topics)
        and isinstance(raw.get("data"), str)
        and re.fullmatch(r"0x(?:[0-9a-fA-F]{64})*", raw["data"]) is not None
        and all(
            slot is None or (i < len(decoded.topics) and decoded.topics[i] in slot) for i, slot in enumerate(filters)
        )
    )
    if not valid:
        raise RuntimeError("eth_getLogs returned a malformed, removed, or out-of-filter log")
    return decoded


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


def _decode_log(raw: Any, *, keep_raw: bool = True) -> FetchedEventLog | None:
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
    data = raw.get("data")
    return FetchedEventLog(
        tx_hash=tx_hash,
        log_index=log_index,
        block_number=block_number,
        block_hash=block_hash,
        transaction_index=transaction_index,
        topics=[str(t).lower() for t in topics],
        data_words=_split_data_words(data),
        address=emitter.lower() if isinstance(emitter, str) else "",
        raw=raw if keep_raw else None,
        data_hex=_unaligned_data(data),
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


def _unaligned_data(raw: Any) -> str | None:
    """Byte-valid ``data`` that isn't a whole number of words, lowercased; otherwise None."""
    if not isinstance(raw, str) or re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", raw) is None:
        return None
    return raw.lower() if (len(raw) - 2) % 64 else None


def _split_data_words(raw: Any) -> list[str]:
    if not isinstance(raw, str) or not raw.startswith("0x"):
        return []
    body = raw[2:]
    if len(body) % 64 != 0:
        return []
    return ["0x" + body[i : i + 64].lower() for i in range(0, len(body), 64)]
