"""A reach condition's recorded operations read at the pass's block with Solidity's own value semantics, every read
kept as the witness, and anything unread left undecided rather than guessed. Only the JSON-RPC HTTP session is
stubbed.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from eth_utils.crypto import keccak

from services.resolution.adapters import EvaluationContext
from services.resolution.pass_memo import PASS_MEMO
from services.resolution.reach_reads import read_reach

SUBJECT = "0x" + "5a" * 20
BLOCK = 1_000
RPC = "http://rpc.reach-reads.test"
SLOT = "0x" + "00" * 31 + "03"


def _selector(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


class _Wire:
    """Answers ``eth_call`` by calldata and ``eth_getStorageAt`` by slot; anything else is an RPC error."""

    def __init__(self, calls: dict[str, int | None], slots: dict[str, int | None] | None = None):
        self.calls = calls
        self.slots = slots or {}
        self.asked: list[tuple[str, list[Any]]] = []

    def post(self, _url, *, json, **_kwargs):
        method, params = json["method"], json["params"]
        self.asked.append((method, params))
        value = None
        if method == "eth_call" and params[0]["to"] == SUBJECT and params[1] == hex(BLOCK):
            value = self.calls.get(params[0]["data"])
        elif method == "eth_getStorageAt" and params[0] == SUBJECT and params[2] == hex(BLOCK):
            value = self.slots.get(params[1])
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": json.get("id")}
        if value is None:
            payload["error"] = {"code": -32000, "message": "execution reverted"}
        else:
            payload["result"] = "0x" + format(value, "064x")
        return SimpleNamespace(status_code=200, raise_for_status=lambda: None, json=lambda: payload)


def _ctx(*, rpc: str | None = RPC) -> Any:
    outer = EvaluationContext(chain_id=1, rpc_url=rpc, block=BLOCK, contract_address=SUBJECT, meta={PASS_MEMO: {}})
    return SimpleNamespace(adapter=SimpleNamespace(_outer_ctx=outer), contract_address=SUBJECT)


@pytest.fixture
def wire(monkeypatch):
    def install(calls: dict[str, int | None], slots: dict[str, int | None] | None = None) -> _Wire:
        stub = _Wire(calls, slots)
        monkeypatch.setattr("services.clients.rpc._get_session", lambda: stub)
        return stub

    return install


def _storage(name: str, type_: str, **layout: Any) -> dict[str, Any]:
    return {"op": "storage", "type": type_, "variable": name, "getter": _selector(f"{name}()"), **layout}


def _literal(value: int, type_: str = "uint256") -> dict[str, Any]:
    return {"op": "const", "type": type_, "value": str(value), "literal": True}


def _compare(op: str, left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    return {"op": op, "type": "bool", "left": left, "right": right}


def _stamp(expression: dict[str, Any], holds: bool = True) -> dict[str, Any]:
    return {"expression": expression, "holds": holds}


def test_a_narrowing_conversion_reads_the_narrowed_value(wire):
    wire({_selector("mode()"): 256})
    narrowed = {"op": "convert", "type": "uint8", "value": _storage("mode", "uint256")}
    truth = read_reach(_stamp(_compare("eq", narrowed, _literal(0))), _ctx())
    assert truth.holds is True
    [read] = truth.reads
    assert read == {
        "method": "eth_call",
        "params": [{"to": SUBJECT, "data": _selector("mode()")}, hex(BLOCK)],
        "block": BLOCK,
        "result": "0x" + format(256, "064x"),
    }


def test_a_signed_reinterpretation_reads_the_sign(wire):
    wire({_selector("big()"): 1 << 255})
    signed = {"op": "convert", "type": "int256", "value": _storage("big", "uint256")}
    assert read_reach(_stamp(_compare("lt", signed, _literal(0))), _ctx()).holds is True


def test_a_literal_takes_the_type_it_is_compared_with(wire):
    wire({_selector("flag()"): 1})
    assert read_reach(_stamp(_compare("eq", _storage("flag", "bool"), _literal(1))), _ctx()).holds is True
    # A literal that doesn't fit the other side's type can't be compared as written.
    wire({_selector("small()"): 1})
    truth = read_reach(_stamp(_compare("eq", _storage("small", "uint8"), _literal(256))), _ctx())
    assert truth.holds is None


def test_values_of_different_families_are_not_compared(wire):
    wire({_selector("a()"): 1, _selector("b()"): 1})
    truth = read_reach(_stamp(_compare("eq", _storage("a", "int256"), _storage("b", "uint256"))), _ctx())
    assert truth.holds is None and truth.reason == "reach_condition_type_mismatch"


def test_a_getter_word_the_type_cant_hold_is_unread(wire):
    wire({_selector("flag()"): 2})
    assert read_reach(_stamp(_storage("flag", "bool")), _ctx()).holds is None


def test_a_failed_getter_falls_back_to_the_packed_slot(wire):
    word = (0xAB << 8) | 0x01  # ``flag`` at offset 0, ``tag`` (uint8) at offset 1
    stub = wire({}, {SLOT: word})
    tag: dict[str, Any] = {"op": "storage", "type": "uint8", "variable": "tag", "getter": _selector("tag()")}
    tag.update(slot=SLOT, offset=1, size=1)
    truth = read_reach(_stamp(_compare("eq", tag, _literal(0xAB))), _ctx())
    assert truth.holds is True
    assert [method for method, _ in stub.asked] == ["eth_call", "eth_getStorageAt"]
    assert truth.reads[0]["error"] is True


def test_a_storage_read_that_fails_both_ways_is_unread(wire):
    wire({}, {})
    flag = _storage("flag", "bool", slot=SLOT, offset=0, size=1)
    truth = read_reach(_stamp(flag), _ctx())
    assert truth.holds is None and truth.reason == "reach_condition_storage_unread"


def test_a_view_call_encodes_its_arguments_as_the_abi_does(wire):
    role = int(keccak(text="EXECUTOR_ROLE").hex(), 16)
    data = _selector("hasRole(bytes32,address)") + format(role, "064x") + "0" * 64
    wire({data: 0})
    call = {
        "op": "call",
        "type": "bool",
        "selector": _selector("hasRole(bytes32,address)"),
        "arguments": [
            {"op": "const", "type": "bytes32", "value": str(role)},
            {"op": "convert", "type": "address", "value": _literal(0)},
        ],
    }
    assert read_reach(_stamp({"op": "not", "type": "bool", "value": call}), _ctx()).holds is True
    assert read_reach(_stamp(call), _ctx()).holds is False


def test_a_connective_is_decided_by_one_read_side_when_that_side_decides_it(wire):
    wire({_selector("on()"): 1, _selector("off()"): 0})
    unread = _storage("missing", "bool")
    on, off = _storage("on", "bool"), _storage("off", "bool")
    assert read_reach(_stamp({"op": "or", "type": "bool", "left": unread, "right": on}), _ctx()).holds is True
    assert read_reach(_stamp({"op": "and", "type": "bool", "left": unread, "right": off}), _ctx()).holds is False
    assert read_reach(_stamp({"op": "and", "type": "bool", "left": unread, "right": on}), _ctx()).holds is None


def test_nothing_is_read_without_a_pinned_block_or_rpc(wire):
    stub = wire({_selector("flag()"): 1})
    truth = read_reach(_stamp(_storage("flag", "bool")), _ctx(rpc=None))
    assert truth.holds is None and truth.reason == "reach_condition_no_rpc"
    assert stub.asked == []


def test_calldata_that_makes_the_condition_hold_is_its_witness(wire):
    wire({_selector("base()"): int("a5" * 20, 16)})
    quote = {"op": "param", "type": "address", "index": 0, "name": "quote"}
    truth = read_reach(_stamp(_compare("eq", quote, _storage("base", "address"))), _ctx())
    assert truth.holds is True
    assert truth.calldata == {"quote": "0x" + "a5" * 20}


def test_calldata_is_never_refuted(wire):
    wire({})
    amount = {"op": "param", "type": "uint256", "index": 0, "name": "amount"}
    # No calldata satisfies this, but not finding any is not a refutation.
    impossible = {
        "op": "and",
        "type": "bool",
        "left": _compare("gt", amount, _literal(10)),
        "right": _compare("lt", amount, _literal(5)),
    }
    truth = read_reach(_stamp(impossible), _ctx())
    assert truth.holds is None and truth.calldata is None


def test_the_chain_id_is_the_pass_chain(wire):
    stub = wire({})
    on_mainnet = _compare("eq", {"op": "chainid", "type": "uint256"}, _literal(1))
    assert read_reach(_stamp(on_mainnet), _ctx()).holds is True
    assert stub.asked == []
