from dataclasses import replace

from tests.storage.test_job_submission_indexer_contention import make_log
from workers.event_log_indexer import _write_prefixes


def test_payload_budget_splits_even_few_rows():
    logs = [replace(make_log(b), data_words=["0x" + "ff" * 1000]) for b in range(1, 4)]
    assert _write_prefixes(logs, 3, max_rows=100, max_bytes=3000) == [(0, 1, 1), (1, 2, 2), (2, 3, 3)]
