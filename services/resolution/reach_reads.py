"""Whether a reach condition held at the pass's block: the operations static recorded (``REACH_READ``), evaluated over
``eth_call`` and ``eth_getStorageAt`` reads of the subject, with every read kept as the witness.

Values are exact Solidity values: conversions truncate, sign-extend and pad as the language does, and comparisons
apply only between values of one family. Anything outside that (a failed or malformed read, an unknown operation, a
mixed comparison) leaves the condition unread, never guessed. A condition on calldata holds when some calldata the
caller can send makes it hold: it is proven only by finding that calldata among a bounded set of candidates, and is
never refuted, since a candidate missing proves nothing.
"""

from __future__ import annotations

import itertools
import re
from typing import Any, NamedTuple

from .pass_memo import canonical, memoized


class ReachTruth(NamedTuple):
    holds: bool | None
    reads: list[dict[str, Any]]
    reason: str | None = None
    # The calldata that made the condition hold, by parameter name.
    calldata: dict[str, str] | None = None


class _Unread(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _Value(NamedTuple):
    type: str
    number: int
    literal: bool = False


def read_reach(stamp: Any, ctx: Any) -> ReachTruth:
    """The truth of one reach outcome (``{"expression", "holds"}``) under ``ctx`` (a predicate-evaluator context)."""
    if not isinstance(stamp, dict) or not isinstance(stamp.get("expression"), dict):
        return ReachTruth(None, [], "reach_condition_unstated")
    reader = _Reader.for_context(ctx)
    return memoized(
        reader.outer,
        ("reach_read", reader.key, canonical(stamp)),
        lambda: reader.truth(stamp),
    )


class _Reader:
    """Reads at one subject and block; with no RPC, contract or pinned block every read is unread."""

    def __init__(
        self, outer: Any, rpc_url: str | None, contract: str | None, block: int | None, chain_id: int | None
    ) -> None:
        self.outer = outer
        self.rpc_url = rpc_url
        self.contract = contract
        self.block = block
        self.chain_id = chain_id
        self.key = (chain_id, rpc_url, contract, block)
        self.reads: list[dict[str, Any]] = []
        self.calldata: dict[int, int] = {}

    @classmethod
    def for_context(cls, ctx: Any) -> _Reader:
        outer = getattr(getattr(ctx, "adapter", None), "_outer_ctx", None)
        rpc_url = getattr(outer, "rpc_url", None)
        contract = getattr(outer, "contract_address", None) or getattr(ctx, "contract_address", None)
        block = getattr(outer, "block", None)
        if not isinstance(rpc_url, str) or not rpc_url:
            rpc_url = None
        if not isinstance(contract, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", contract):
            contract = None
        # A read at "latest" isn't a read at the pass's block.
        if not isinstance(block, int) or isinstance(block, bool) or block <= 0:
            block = None
        return cls(outer, rpc_url, contract.lower() if contract else None, block, getattr(outer, "chain_id", None))

    def truth(self, stamp: dict[str, Any]) -> ReachTruth:
        self.reads = []
        expression = stamp["expression"]
        wanted = bool(stamp.get("holds"))
        parameters = _parameters(expression)
        if not parameters:
            self.calldata = {}
            return self._decide(expression, wanted)
        candidates = self._candidates(expression, parameters)
        reason = "reach_condition_calldata_not_witnessed"
        for values in itertools.islice(itertools.product(*candidates.values()), _MAX_CALLDATA_TRIES):
            self.calldata = dict(zip(candidates, values))
            truth = self._decide(expression, wanted)
            if truth.holds is True:
                calldata = {
                    parameters[index][1]: _render(value, parameters[index][0]) for index, value in self.calldata.items()
                }
                return truth._replace(calldata=calldata)
            if truth.holds is None and truth.reason != "reach_condition_calldata_unassigned":
                reason = truth.reason or reason
        return ReachTruth(None, list(self.reads), reason)

    def _decide(self, expression: dict[str, Any], wanted: bool) -> ReachTruth:
        try:
            value = self._evaluate(expression, 0)
        except _Unread as unread:
            return ReachTruth(None, list(self.reads), unread.reason)
        if value is None:
            return ReachTruth(None, list(self.reads), "reach_condition_short_circuit_unread")
        if value.type != "bool":
            return ReachTruth(None, list(self.reads), "reach_condition_not_bool")
        return ReachTruth(bool(value.number) == wanted, list(self.reads))

    def _candidates(self, expression: dict[str, Any], parameters: dict[int, tuple[str, str]]) -> dict[int, list[int]]:
        """Per parameter: the bounds of its type, and each value it is compared with, one either side."""
        found: dict[int, set[int]] = {index: set() for index in parameters}
        self.calldata = {}
        for node in _nodes(expression):
            if node.get("op") not in _COMPARE:
                continue
            for side, other in ((node.get("left"), node.get("right")), (node.get("right"), node.get("left"))):
                touched = _parameters(side)
                if not touched or _parameters(other):
                    continue
                try:
                    value = self._evaluate(other, 0)
                except _Unread:
                    continue
                if value is not None:
                    for index in touched:
                        found[index].update((value.number - 1, value.number, value.number + 1))
        out: dict[int, list[int]] = {}
        for index, (type_, _name) in parameters.items():
            values = found[index] | _type_bounds(type_)
            out[index] = sorted(value for value in values if _fits(value, type_))
        return out

    def _evaluate(self, node: Any, depth: int) -> _Value | None:
        """``None`` only from a connective whose operands were unread but couldn't decide it either way."""
        if depth > 32 or not isinstance(node, dict):
            raise _Unread("reach_condition_malformed")
        op = node.get("op")
        type_ = node.get("type")
        if not isinstance(type_, str) or _family(type_) is None:
            raise _Unread("reach_condition_type_unsupported")
        if op == "const":
            return _Value(type_, _parse_int(node.get("value")), bool(node.get("literal")))
        if op == "self":
            if self.contract is None:
                raise _Unread("reach_condition_subject_unknown")
            return _Value("address", int(self.contract, 16))
        if op == "chainid":
            if not isinstance(self.chain_id, int):
                raise _Unread("reach_condition_chain_unknown")
            return _Value("uint256", self.chain_id)
        if op == "param":
            index = node.get("index")
            if index not in self.calldata:
                raise _Unread("reach_condition_calldata_unassigned")
            return _Value(type_, self.calldata[index])
        if op == "storage":
            return self._storage(node, type_)
        if op == "call":
            return self._call(node, type_, depth)
        if op == "convert":
            inner = self._required(node.get("value"), depth)
            return _Value(type_, _convert(inner, type_))
        if op == "not":
            inner = self._required(node.get("value"), depth)
            if inner.type != "bool":
                raise _Unread("reach_condition_type_mismatch")
            return _Value("bool", 1 - inner.number)
        if op in ("and", "or"):
            return self._connective(op, node, depth)
        if op in _COMPARE:
            left = self._required(node.get("left"), depth)
            right = self._required(node.get("right"), depth)
            return _Value("bool", int(_compare(op, left, right)))
        raise _Unread("reach_condition_operation_unsupported")

    def _required(self, node: Any, depth: int) -> _Value:
        value = self._evaluate(node, depth + 1)
        if value is None:
            raise _Unread("reach_condition_short_circuit_unread")
        return value

    def _connective(self, op: str, node: dict[str, Any], depth: int) -> _Value | None:
        decisive = 0 if op == "and" else 1
        values: list[_Value | None] = []
        for side in (node.get("left"), node.get("right")):
            try:
                value = self._evaluate(side, depth + 1)
            except _Unread:
                value = None
            if value is not None and value.type != "bool":
                raise _Unread("reach_condition_type_mismatch")
            if value is not None and value.number == decisive:
                return _Value("bool", decisive)
            values.append(value)
        if any(value is None for value in values):
            return None
        return _Value("bool", 1 - decisive)

    def _storage(self, node: dict[str, Any], type_: str) -> _Value:
        getter = node.get("getter")
        if isinstance(getter, str) and re.fullmatch(r"0x[0-9a-fA-F]{8}", getter):
            word = self._rpc("eth_call", [{"to": self.contract, "data": getter.lower()}])
            if word is not None:
                return _Value(type_, _decode_word(word, type_))
        slot = node.get("slot")
        offset, size = node.get("offset"), node.get("size")
        if not (isinstance(slot, str) and isinstance(offset, int) and isinstance(size, int) and 0 < size <= 32):
            raise _Unread("reach_condition_storage_unread")
        if offset + size > 32:
            raise _Unread("reach_condition_storage_unread")
        word = self._rpc("eth_getStorageAt", [self.contract, slot])
        if word is None:
            raise _Unread("reach_condition_storage_unread")
        return _Value(type_, _decode_packed(word, offset, size, type_))

    def _call(self, node: dict[str, Any], type_: str, depth: int) -> _Value:
        selector = node.get("selector")
        if not isinstance(selector, str) or not re.fullmatch(r"0x[0-9a-fA-F]{8}", selector):
            raise _Unread("reach_condition_malformed")
        words = [_encode(self._required(argument, depth)) for argument in node.get("arguments") or []]
        data = selector.lower() + "".join(format(word, "064x") for word in words)
        word = self._rpc("eth_call", [{"to": self.contract, "data": data}])
        if word is None:
            raise _Unread("reach_condition_call_unread")
        return _Value(type_, _decode_word(word, type_))

    def _rpc(self, method: str, params: list[Any]) -> int | None:
        if self.rpc_url is None or self.contract is None or self.block is None:
            raise _Unread("reach_condition_no_rpc")
        rpc_url = self.rpc_url
        params = [*params, hex(self.block)]
        raw = memoized(
            self.outer,
            ("reach_rpc", self.key, method, canonical(params)),
            lambda: _rpc_word(rpc_url, method, params, self.chain_id),
        )
        record: dict[str, Any] = {"method": method, "params": params, "block": self.block}
        if raw is None:
            record["error"] = True
            self.reads.append(record)
            return None
        self.reads.append({**record, "result": raw})
        return int(raw[:66], 16)


def _rpc_word(rpc_url: str, method: str, params: list[Any], chain_id: int | None) -> str | None:
    from services.clients.rpc import rpc_request

    try:
        raw = rpc_request(rpc_url, method, params, retries=1, chain_id=chain_id)
    except Exception:
        return None
    if not isinstance(raw, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64,}", raw):
        return None
    return raw.lower()


_MAX_CALLDATA_TRIES = 256


def _nodes(node: Any) -> list[dict[str, Any]]:
    if not isinstance(node, dict):
        return []
    out = [node]
    for key in ("value", "left", "right"):
        out.extend(_nodes(node.get(key)))
    for argument in node.get("arguments") or []:
        out.extend(_nodes(argument))
    return out


def _parameters(node: Any) -> dict[int, tuple[str, str]]:
    return {
        n["index"]: (str(n.get("type")), str(n.get("name")))
        for n in _nodes(node)
        if n.get("op") == "param" and isinstance(n.get("index"), int)
    }


def _render(number: int, type_: str) -> str:
    kind, width = _family(type_) or ("", 0)
    if kind == "address":
        return "0x" + format(number, "040x")
    if kind == "bytes":
        return "0x" + format(number, f"0{2 * width}x")
    return str(number)


def _type_bounds(type_: str) -> set[int]:
    kind, width = _family(type_) or ("", 0)
    if kind == "int":
        return {-(1 << (width - 1)), -1, 0, 1, (1 << (width - 1)) - 1}
    if kind == "uint":
        return {0, 1, (1 << width) - 1}
    if kind == "address":
        return {0, 1, (1 << 160) - 1}
    if kind == "bytes":
        return {0, 1, (1 << (8 * width)) - 1}
    return {0, 1}


_COMPARE = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "lt": lambda a, b: a < b,
    "lte": lambda a, b: a <= b,
    "gt": lambda a, b: a > b,
    "gte": lambda a, b: a >= b,
}


def _family(type_: str) -> tuple[str, int] | None:
    if type_ in ("bool", "address"):
        return (type_, 0)
    match = re.fullmatch(r"(uint|int)(\d+)", type_)
    if match and 8 <= int(match.group(2)) <= 256 and int(match.group(2)) % 8 == 0:
        return (match.group(1), int(match.group(2)))
    match = re.fullmatch(r"bytes(\d+)", type_)
    if match and 1 <= int(match.group(1)) <= 32:
        return ("bytes", int(match.group(1)))
    return None


def _parse_int(raw: Any) -> int:
    try:
        return int(str(raw), 10)
    except ValueError:
        raise _Unread("reach_condition_malformed") from None


def _fits(number: int, type_: str) -> bool:
    family = _family(type_)
    if family is None:
        return False
    kind, width = family
    if kind == "bool":
        return number in (0, 1)
    if kind == "address":
        return 0 <= number < 1 << 160
    if kind == "uint":
        return 0 <= number < 1 << width
    if kind == "int":
        return -(1 << (width - 1)) <= number < 1 << (width - 1)
    return 0 <= number < 1 << (8 * width)


def _signed(number: int, bits: int) -> int:
    number &= (1 << bits) - 1
    return number - (1 << bits) if number >> (bits - 1) else number


def _convert(value: _Value, target: str) -> int:
    if value.literal:
        if not _fits(value.number, target):
            raise _Unread("reach_condition_conversion_unsupported")
        return value.number
    source, into = _family(value.type), _family(target)
    if source is None or into is None:
        raise _Unread("reach_condition_conversion_unsupported")
    if source == into or (source[0] == into[0] == "address"):
        return value.number
    (kind, width), (to_kind, to_width) = source, into
    if kind == "uint" and to_kind == "uint":
        return value.number & ((1 << to_width) - 1)
    if kind == "int" and to_kind == "int":
        return _signed(value.number, to_width) if to_width < width else value.number
    if kind == "uint" and to_kind == "int" and width == to_width:
        return _signed(value.number, width)
    if kind == "int" and to_kind == "uint" and width == to_width:
        return value.number & ((1 << width) - 1)
    if kind == "bytes" and to_kind == "bytes":
        shift = 8 * abs(to_width - width)
        return value.number << shift if to_width > width else value.number >> shift
    if kind == "bytes" and to_kind == "uint" and 8 * width == to_width:
        return value.number
    if kind == "uint" and to_kind == "bytes" and width == 8 * to_width:
        return value.number
    if {kind, to_kind} == {"uint", "address"} and (width or to_width) == 160:
        return value.number
    raise _Unread("reach_condition_conversion_unsupported")


def _compare(op: str, left: _Value, right: _Value) -> bool:
    if left.literal and not right.literal:
        left = _Value(right.type, _convert(left, right.type))
    elif right.literal and not left.literal:
        right = _Value(left.type, _convert(right, left.type))
    left_family, right_family = _family(left.type), _family(right.type)
    if left_family is None or right_family is None:
        raise _Unread("reach_condition_type_unsupported")
    if left.literal and right.literal:
        pass
    elif left_family[0] != right_family[0] or (left_family[0] == "bytes" and left_family != right_family):
        raise _Unread("reach_condition_type_mismatch")
    if left_family[0] == "bool" and op not in ("eq", "ne"):
        raise _Unread("reach_condition_type_mismatch")
    return _COMPARE[op](left.number, right.number)


def _decode_word(word: int, type_: str) -> int:
    """An ABI-encoded return word as a value of ``type_``; a word with bits the type can't hold is malformed."""
    kind, width = _family(type_) or ("", 0)
    if kind == "bytes":
        low = 256 - 8 * width
        if word & ((1 << low) - 1):
            raise _Unread("reach_condition_word_malformed")
        return word >> low
    number = _signed(word, 256) if kind == "int" else word
    if not _fits(number, type_):
        raise _Unread("reach_condition_word_malformed")
    return number


def _decode_packed(word: int, offset: int, size: int, type_: str) -> int:
    """The ``size`` bytes at ``offset`` (from the right) of a storage word, as a value of ``type_``."""
    number = (word >> (8 * offset)) & ((1 << (8 * size)) - 1)
    kind, _ = _family(type_) or ("", 0)
    if kind == "int":
        number = _signed(number, 8 * size)
    if not _fits(number, type_):
        raise _Unread("reach_condition_word_malformed")
    return number


def _encode(value: _Value) -> int:
    kind, width = _family(value.type) or ("", 0)
    if not _fits(value.number, value.type):
        raise _Unread("reach_condition_argument_unsupported")
    if kind == "int":
        return value.number & ((1 << 256) - 1)
    if kind == "bytes":
        return value.number << (256 - 8 * width)
    return value.number
