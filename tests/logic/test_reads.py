"""Transport errors and trace hints stay separate from semantic claims."""

import pytest
from eth_utils import keccak

from services.clients.logic_reads import ChainReads, hash_preimages
from services.logic.model import BudgetExceeded, ReadError


def test_transient_storage_failure_retries_without_inventing_a_value(monkeypatch):
    monkeypatch.setattr("services.clients.logic_reads.time.sleep", lambda seconds: None)
    calls = []

    def rpc(method, params):
        calls.append((method, params))
        if len(calls) == 1:
            raise TimeoutError("timeout")
        return "0x2a"

    reads = ChainReads(rpc, 123)
    assert reads.storage(1, 2) == 42
    assert reads.storage(1, 2) == 42
    assert len(calls) == 2 and all(p[-1] == "0x7b" for _, p in calls)


def test_permanent_failure_aborts_instead_of_caching_zero(monkeypatch):
    monkeypatch.setattr("services.clients.logic_reads.time.sleep", lambda seconds: None)

    def rpc(method, params):
        raise TimeoutError("execution aborted (timeout)")

    reads = ChainReads(rpc, 123)
    with pytest.raises(ReadError):
        reads.storage(1, 2)
    assert not reads.memo


def test_budget_is_distinct_from_node_failure():
    reads = ChainReads(lambda m, p: "0x0", 123, read_limit=0)
    with pytest.raises(BudgetExceeded):
        reads.storage(1, 2)


def test_complete_storage_dump_requires_every_page():
    def rpc(method, params):
        if method == "eth_getBlockByNumber":
            return {"hash": "0xab", "transactions": [1, 2]}
        assert method == "debug_storageRangeAt" and params[:2] == ["0xab", 2]
        return {"storage": {"hashed": {"key": "0x1", "value": "0x3"}}, "nextKey": "0x7"}

    with pytest.raises(ReadError, match="cursor"):
        ChainReads(rpc, 123).storage_dump(1)


def test_opcode_trace_recovers_hash_inputs_not_a_guessed_original_key():
    raw = (7).to_bytes(32, "big") + (4).to_bytes(32, "big")
    trace = {"structLogs": [{"op": "KECCAK256", "stack": ["40", "00"], "memory": [raw[:32].hex(), raw[32:].hex()]}]}
    assert hash_preimages(trace) == {int.from_bytes(keccak(raw), "big"): raw}


def test_absent_traces_are_empty_hints_not_a_complete_key_list():
    reads = ChainReads(lambda m, p: None, 1, trace_preimages=lambda address, slots: {})
    assert reads.preimages(1, {2}) == {}
