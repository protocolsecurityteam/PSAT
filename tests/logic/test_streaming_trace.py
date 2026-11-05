"""Streaming acquisition retains verified hints, never a successful partial RPC response."""

import hashlib
import io
import json
import tracemalloc

import pytest

from services.clients.logic_reads import ChainReads, hash_preimages
from services.clients.logic_trace import streamed_hash_preimages
from services.logic.model import BudgetExceeded, ReadError
from services.logic.source_context import digest

STEP = {"op": "KECCAK256", "stack": ["40", "00"], "memory": ["00" * 31 + "07", "00" * 31 + "04"]}


def test_stream_matches_existing_trace_hashes_across_nested_frames_and_field_order():
    trace = {
        "structLogs": [
            {"memory": STEP["memory"], "stack": STEP["stack"], "depth": 2, "op": "SHA3"},
            STEP,
            {"op": "STOP"},
        ]
    }
    data = json.dumps({"id": 1, "result": trace, "jsonrpc": "2.0"}).encode()
    assert streamed_hash_preimages(io.BytesIO(data), word_limit=10) == hash_preimages(trace)


@pytest.mark.parametrize(
    "body",
    [
        b'{"result":{"structLogs":[',
        b'{"result":{"structLogs":[]},"error":{"code":-1}}',
        b'{"error":{"code":-1}}',
        b'{"result":{}}',
        b'{"result":{"structLogs":[5]}}',
    ],
)
def test_incomplete_or_failed_response_is_not_an_empty_hint_set(body):
    with pytest.raises(ReadError):
        streamed_hash_preimages(io.BytesIO(body), word_limit=10)


def test_hint_budget_remains_a_budget_not_a_transport_error():
    body = json.dumps({"result": {"structLogs": [STEP]}}).encode()
    with pytest.raises(BudgetExceeded):
        streamed_hash_preimages(io.BytesIO(body), word_limit=1)
    calls = []

    def fetch(*args):
        calls.append(1)
        raise BudgetExceeded("trace preimage words")

    reads = ChainReads(lambda *args: "0x1", 1, trace_reader=fetch)
    with pytest.raises(BudgetExceeded):
        reads._transaction_hashes("tx")
    assert calls == [1] and not reads._trace_hash_cache


def test_compact_trace_cache_is_bounded_and_raw_traces_are_not_memoized():
    calls = []

    def fetch(method, params):
        calls.append(params[0])
        return {len(calls): b"x" * 32}

    reads = ChainReads(lambda *args: "0x1", 1, trace_reader=fetch, word_limit=2)
    for tx in ("one", "two", "one", "three"):
        reads._transaction_hashes(tx)
    assert calls == ["one", "two", "three"]
    assert list(reads._trace_hash_cache) == ["one", "three"]
    assert not any(k[1] == "debug_traceTransaction" for k in reads.memo)
    reads._transaction_hashes("two")
    assert calls[-1] == "two" and len(calls) == 4


class RepeatedTrace:
    """A large response produced lazily: the test itself never allocates the full body."""

    def __init__(self, count):
        self.count = count
        self.parts = iter([b'{"result":{"structLogs":['])
        self.buffer = b""
        self.started = False
        self.ended = False

    def readable(self):
        return True

    def read(self, n=-1):
        assert n >= 0, "streaming parser requested the entire response"
        if n == 0:
            return b""
        while len(self.buffer) < n and not self.ended:
            if not self.started:
                self.buffer += b'{"result":{"structLogs":['
                self.started = True
            elif self.count:
                self.buffer += json.dumps(STEP).encode() + (b"," if self.count > 1 else b"")
                self.count -= 1
            else:
                self.buffer += b"]}}"
                self.ended = True
        out, self.buffer = self.buffer[:n], self.buffer[n:]
        return out


def test_trace_memory_does_not_grow_with_instruction_count():
    tracemalloc.start()
    try:
        result = streamed_hash_preimages(RepeatedTrace(40000), word_limit=10)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result == hash_preimages({"structLogs": [STEP]})
    assert peak < 8 * 1024 * 1024


def test_artifact_digest_stays_byte_for_byte_compatible():
    value = {"unicode": "λ/💡", "large": 2**256 - 1, "nested": [{"x": True, "y": None}, [0.1, 1e-12, -0.0]]}
    old = hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()
    assert digest(value) == old


def test_transport_never_materializes_response_and_closes_on_parse_failure(monkeypatch):
    from services.clients import logic_trace

    seen = []

    class Response:
        def __init__(self):
            self.raw = io.BytesIO(b'{"result":{"structLogs":[]}}')

        def __enter__(self):
            return self

        def __exit__(self, *args):
            seen.append("closed")

        def raise_for_status(self):
            pass

        def json(self):
            raise AssertionError("materialized trace")

        @property
        def content(self):
            raise AssertionError("materialized trace")

    class Session:
        def post(self, *args, **kwargs):
            assert kwargs["stream"] is True
            return Response()

    monkeypatch.setattr(logic_trace, "_get_session", Session)
    monkeypatch.setattr(logic_trace, "_assert_url_chain_id", lambda *a: None)
    monkeypatch.setattr(logic_trace, "rpc_headers", lambda *a: {})
    assert logic_trace.trace_hash_preimages("unused", "debug_traceTransaction", [], chain_id=1, word_limit=10) == {}
    assert seen == ["closed"]


def test_broken_stream_uses_reader_retry_and_never_caches_partial_hints(monkeypatch):
    import urllib3

    from services.clients import logic_trace

    attempts = []

    class Broken:
        decode_content = False

        def read(self, n=-1):
            raise urllib3.exceptions.ProtocolError("broken stream")

    class Response:
        raw = Broken()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def raise_for_status(self):
            pass

    class Session:
        def post(self, *a, **kw):
            attempts.append(1)
            return Response()

    monkeypatch.setattr(logic_trace, "_get_session", Session)
    monkeypatch.setattr(logic_trace, "_assert_url_chain_id", lambda *a: None)
    monkeypatch.setattr(logic_trace, "rpc_headers", lambda *a: {})
    monkeypatch.setattr("services.clients.logic_reads.time.sleep", lambda *a: None)
    reads = ChainReads(
        lambda *args: "0x1",
        1,
        trace_reader=lambda method, params: logic_trace.trace_hash_preimages(
            "unused", method, params, chain_id=1, word_limit=10
        ),
    )
    with pytest.raises(ReadError):
        reads._transaction_hashes("tx")
    assert len(attempts) == 3 and not reads._trace_hash_cache
