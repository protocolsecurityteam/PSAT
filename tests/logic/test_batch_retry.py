"""A batch the node drops as a whole is asked again, with waits, before any read in it counts as failed."""

from __future__ import annotations

import time

from services.logic import decide as D
from services.logic.decide import batch_results
from tests.logic.test_failed_reads import EXECUTOR, _Deployed, _verdict, built  # noqa: F401


class _Outage(_Deployed):
    """``_Deployed`` behind a node that answers nothing, single reads or batches, for ``seconds`` from the first
    request (``None``: never again); a batch comes back as the RPC client reports a request that failed wholesale."""

    def __init__(self, seconds: float | None):
        super().__init__()
        self.seconds, self.began = seconds, None
        self.rpc = self._single
        self.batch = self._batch

    def _down(self) -> bool:
        now = time.monotonic()
        self.began = now if self.began is None else self.began
        return self.seconds is None or now - self.began < self.seconds

    def _single(self, method, params):
        if self._down():
            raise RuntimeError("upstream timeout")
        return self._answer(method, params)

    def _batch(self, calls):
        if self._down():
            return batch_results([(None, "transport")] * len(calls))
        return [self._safe(m, p) for m, p in calls]


def test_a_batch_dropped_once_then_answered_reads_as_it_is(built):  # noqa: F811
    clean = _verdict(built, _Deployed())
    verdict = _verdict(built, _Outage(0.3))
    assert (verdict.openness, verdict.principals, verdict.complete) == (clean.openness, {EXECUTOR}, clean.complete)
    assert not any(g.startswith("read_failed") for g in verdict.gaps)


def test_a_batch_dropped_every_time_reads_as_failed_never_bolder(built, monkeypatch):  # noqa: F811
    monkeypatch.setattr(D, "BATCH_RETRY_WAIT", 0.0, raising=False)
    verdict = _verdict(built, _Outage(None))
    assert verdict.openness != "open"
    assert not verdict.principals and not verdict.complete


def test_retries_split_a_dropped_batch_in_halves_and_stop_at_the_budget(monkeypatch):
    monkeypatch.setattr(D, "BATCH_RETRY_WAIT", 0.0)
    sizes: list[int] = []

    def batch(calls):
        sizes.append(len(calls))
        return batch_results([(None, "transport")] * len(calls))

    def single(method, params):
        raise RuntimeError("down")

    chain = D.Chain(single, 1, batch)
    chain.prefetch([chain.storage_request(1, s) for s in range(8)])
    assert sizes == [8, 8, 4, 4, 4, 4]  # once whole, then in halves
    assert chain.sent == 8 * 4 and not chain._memo

    sizes.clear()
    capped = D.Chain(single, 1, batch)
    capped.limit = 12
    capped.prefetch([capped.storage_request(1, s) for s in range(8)])
    assert sizes == [8] and capped.sent == 8  # a retry past the read budget isn't sent

    sizes.clear()
    monkeypatch.setattr(D, "BATCH_RETRIES", 0)
    D.Chain(single, 1, batch).prefetch([chain.storage_request(1, s) for s in range(8)])
    assert sizes == [8]
