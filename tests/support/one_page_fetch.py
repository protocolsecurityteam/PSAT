"""Serve an indexer test fake written as one ``fetch_logs`` call per request through ``iter_pages``."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import Any, Protocol

from services.resolution.repos.event_logs_rpc import FetchedEventLog, FetchWindowStat, LogPage


class _FetchesLogs(Protocol):
    def fetch_logs(
        self,
        *,
        event_address: Any,
        topics: Any,
        from_block: int,
        to_block: int,
        window_stats: list[FetchWindowStat] | None = None,
    ) -> list[FetchedEventLog]: ...


class OnePagePerFetch:
    """Each ``iter_pages`` call is one ``fetch_logs`` call, yielded whole as one page with the stats it recorded; a
    fake that records none yields a page with no stats."""

    def iter_pages(
        self: _FetchesLogs,
        *,
        event_address: str | Sequence[str],
        topics: Sequence[str],
        from_block: int,
        to_block: int,
        max_page_logs: int | None = None,
    ) -> Iterator[LogPage]:
        stats: list[FetchWindowStat] = []
        logs = self.fetch_logs(
            event_address=event_address,
            topics=topics,
            from_block=from_block,
            to_block=to_block,
            window_stats=stats,
        )
        yield LogPage(from_block=from_block, to_block=to_block, logs=logs, stats=tuple(stats))
