"""Write budgets apply across topics and never split one block."""

from dataclasses import replace

from tests.storage.test_job_submission_indexer_contention import make_log
from workers.event_log_indexer import _write_prefixes


def test_oversized_block_is_alone_and_complete():
    logs = [make_log(1)] + [make_log(2, number=i) for i in range(8)] + [make_log(3)]
    assert _write_prefixes(logs, 10, max_rows=3, max_bytes=1_000_000) == [(0, 1, 1), (1, 9, 2), (9, 10, 10)]


def test_payload_budget_splits_even_few_rows():
    logs = [replace(make_log(b), data_words=["0x" + "ff" * 1000]) for b in range(1, 4)]
    assert _write_prefixes(logs, 3, max_rows=100, max_bytes=3000) == [(0, 1, 1), (1, 2, 2), (2, 3, 3)]


def test_empty_window_still_advances_to_its_end():
    assert _write_prefixes([], 100, max_rows=3, max_bytes=100) == [(0, 0, 100)]
