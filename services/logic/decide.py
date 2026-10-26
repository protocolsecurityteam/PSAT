"""Who satisfies a success formula, read against chain state at one block.

Identities are the roots a formula can differ on: the caller (``msg.sender``, and ``tx.origin`` with it) and a signer
(``ecrecover``). Each candidate identity is substituted, every storage read and view call it leads to is answered from
the chain, and what remains depends only on arguments the caller picks:

* ``passes``: a search over argument values finds one that makes the formula true;
* ``fails``: with every argument unknown, three-valued evaluation already gives false;
* otherwise undecided.

A fresh address stands for "anyone else": its storage entries are really empty and other contracts really answer for
it, so if it passes the function is open. Whether every other address behaves like it is a separate, structural
question (``Coverage``): each way the formula uses an identity must be one we can enumerate, an equality with a value
we read, or a mapping key whose every write emits that key, here or inside a contract we can lower too.

Two facts about values do the rest: a hash never equals zero, and a hash of inputs the caller picks equals a given
nonzero value for whoever holds a preimage (``PREIMAGE``), unless the inputs include an identity, whose membership in
the committed set isn't known.
"""

from __future__ import annotations

import contextlib
import itertools
import os
import re
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field, replace
from typing import Any, cast

from eth_abi.abi import decode, encode
from eth_utils.crypto import keccak

from .taint import singles_out_nobody, split, tainted, unknown_gap, unknown_labels
from .terms import (
    _EXACT,
    CALLDATA,
    FALSE,
    IDENTITY_KINDS,
    TRUE,
    Term,
    cheapest_first,
    conjuncts,
    contains,
    fits,
    mk,
    mk_and,
    mk_not,
    packed_width,
    replace_terms,
    signed,
    stable,
    subterms,
)

UNK = type("Unknown", (), {"__repr__": lambda self: "UNK"})()
PREIMAGE = type("Preimage", (), {"__repr__": lambda self: "PREIMAGE"})()
REVERTED = type("Reverted", (), {"__repr__": lambda self: "REVERTED"})()
ASSUMED = type("Assumed", (), {"__repr__": lambda self: "ASSUMED"})()
# A log query the node refused for its size: more logs in that range alone than any list of holders.
CROWDED = type("Crowded", (), {"__repr__": lambda self: "CROWDED"})()
_CROWDED_ERRORS = re.compile(r"more than (\d+) (?:logs|results)|response size exceeded|too many (?:logs|results)", re.I)
FRESH = int.from_bytes(keccak(text="psat.logic.fresh")[:20], "big")
ANY_KEY = type("AnyKey", (), {"__repr__": lambda self: "ANY_KEY"})()  # an entry key the history leaves unread
_ARITHMETIC = frozenset({"op", "hash"})
_FREE_KINDS = frozenset({"arg", "len", "elem", "callvalue", "calldatasize"})
_STORED_BYTES = 8192  # longest ``bytes`` read back from storage, in bytes
_EARLY_GUESSES = 32  # of them, tried before asking the solver
_MAX_CALLDATA = 2**32  # bytes of call data no transaction reaches (each costs gas)


@dataclass(frozen=True)
class FreeHash:
    """A hash whose inputs aren't all known. ``identity`` when they include a caller or signer; ``choosable`` when
    they are caller-chosen values used nowhere else, so whoever holds a preimage can supply it."""

    identity: bool
    choosable: bool = False


# Logs read per (address, events): enough for any role history, a sample of a token's transfers.
LOG_ROWS = 50_000
# Nodes give up on a whole history in one ``eth_getLogs`` (a timeout, a cap on range or rows): it is read in windows
# of this many blocks from the contract's creation, a refused window split in two down to ``LOG_MIN_WINDOW``, at most
# ``LOG_CALLS`` windows per history and ``LOG_BATCH`` per round trip. Past the cap the history is partial. Log
# indexers answer a million blocks for the price of one (a role history in a round trip of about twenty windows), and
# the cap keeps a provider that refuses wide ranges, or is rate limiting, from being split into thousands of calls.
LOG_WINDOW = 1_000_000
# A window refused even this small is a dense history (a token's transfers): a crowd, not a list of holders, so the
# scan stops there rather than splitting its way through it.
LOG_MIN_WINDOW = LOG_WINDOW // 64
LOG_CALLS = 400
# History scanning, per history read and per function: each history gets up to ``LOG_SECONDS`` of what the
# function has left of ``LOG_TOTAL_SECONDS``, so a crowded one (a token's transfers) read first can't take a short
# one's (its role grants) whole share, and the total stays bounded. A scan stopped either way is partial (cut).
LOG_SECONDS = 20.0
LOG_TOTAL_SECONDS = 90.0
LOG_BATCH = 50
SNAPSHOT_SLOTS = 400_000  # storage dumped whole, at most (Maker's Vat holds about 135k slots)
SNAPSHOT_PAGE = 10_000
CREATION_PROBES = 16  # ``eth_getCode`` probes, in one batch, that place a contract's creation before a window scan


class Offline(BaseException):
    """A read the chain hasn't answered, asked while reading is off (``detached``): never sent. A ``BaseException``,
    so no handler for a failed read takes it for one."""


def _tracked(logs: Callable) -> Callable:
    """``logs`` noting, per read (address and topics), whether that read came back partial: ``truncated`` names the
    address once any of its histories was, which says nothing of another, short one (its role grants beside its
    transfers). Readers mark ``truncated`` only when they first read, so the note is taken then."""

    def read(self: "Chain", address: int, topics: frozenset[str]) -> list:
        key = (address, topics)
        if key in self.partial or not topics:
            return logs(self, address, topics)
        if self.offline:
            raise Offline(key)
        before = address in self.truncated
        self.truncated.discard(address)
        cut = True
        try:
            out = logs(self, address, topics)
            cut = address in self.truncated
        finally:
            if before or cut:
                self.truncated.add(address)
        self.partial.setdefault(key, cut)
        return out

    read.__wrapped__ = logs  # type: ignore[attr-defined]
    return read


class Chain:
    """Reads at one pinned block."""

    failed = 0  # see ``__init__``
    offline = False

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if "logs" in cls.__dict__:
            cls.logs = _tracked(cls.__dict__["logs"])  # type: ignore[method-assign]

    def __init__(
        self,
        rpc: Callable[[str, list], Any],
        block: int,
        batch: Callable[[list[tuple[str, list]]], list[Any]] | None = None,
        history: Callable[[str, list], Any] | None = None,
        debug: Callable[[str, list], Any] | None = None,
    ):
        self.rpc = rpc
        # A node serving ``debug_storageRangeAt`` and ``debug_traceTransaction`` (an archive Geth with preimages):
        # whole-storage dumps and creation traces. Without one, nothing is listed that way.
        self.debug = debug
        # Whole-history ``eth_getLogs``: one attempt, no retries, since a node giving up on a range gives up again.
        self.history = history or rpc
        self.unreadable: set[int] = set()
        self.block = block
        # One round trip for many reads. Each result is the answer, REVERTED (a call that reverted), or ``None`` (any
        # other error), which is left for the single read to classify.
        self.batch = batch
        self._memo: dict = {}
        # While set, an unanswered read is recorded here and reads as unknown instead of costing a round trip.
        self.pending: list[tuple[tuple, str, list]] | None = None
        # While set (``detached``), nothing is read: an unanswered word or call reads as unknown, unrecorded; any
        # other unanswered read (a history, a dump, a trace) raises ``Offline``.
        self.offline = False
        # Reads sent so far, and the most allowed (``None``: no limit); past it, every new read answers unknown.
        self.sent = 0
        # Seconds of history scanning one function may still spend (``function_verdict`` sets it per function):
        # past it a history is partial, so a slow node costs completeness, never the whole verdict.
        self.scan_left: float | None = None
        # When set, the seconds each history scan starts with (``scan_left`` reset per read), out of what is left of
        # ``scan_total`` for the function: see ``LOG_SECONDS``.
        self.history_seconds: float | None = None
        self.scan_total: float | None = None
        self.limit: int | None = None
        # Addresses whose logs were cut to ``LOG_ROWS``: anything enumerated from them is partial.
        self.truncated: set[int] = set()
        # Per read of logs (address, topics): whether it came back partial (see ``_tracked``).
        self.partial: dict[tuple[int, frozenset], bool] = {}
        # Single reads that failed, or weren't sent for the budget: a decision that met one can't drop what it read.
        self.failed = 0

    def cut(self, address: int, topics: frozenset[str]) -> bool:
        """Whether that history was read partial, or not read at all."""
        return self.partial.get((address, topics), True) if topics else address in self.truncated

    def _affordable(self, count: int = 1) -> bool:
        return self.limit is None or self.sent + count <= self.limit

    def gather(self, run: Callable[[], Any], rounds: int = 6) -> None:
        """Run ``run`` with reads deferred, fetch everything it asked for in one batch, and repeat for reads that
        depended on those, so the real run finds them answered."""
        if self.batch is None or self.offline:
            return
        for _ in range(rounds):
            self.pending = []
            try:
                run()
            finally:
                requested, self.pending = self.pending, None
            if not requested:
                return
            self.prefetch(requested)

    def prefetch(self, requests: list[tuple[tuple, str, list]]) -> None:
        """Answer many reads in one batch, keyed as the single reads are."""
        pending = {key: (method, params) for key, method, params in requests if key not in self._memo}
        if self.limit is not None:
            pending = dict(list(pending.items())[: max(0, self.limit - self.sent)])
        if not pending or self.batch is None or self.offline:
            return
        self.sent += len(pending)
        try:
            results = self.batch(list(pending.values()))
        except TimeoutError:
            raise
        except Exception:
            return
        for key, result in zip(pending, results):
            if result is not None:
                self._memo[key] = result  # REVERTED included: a batch reports reverts as the single read would

    def storage_request(self, address: int, slot: int) -> tuple[tuple, str, list]:
        return ("s", address, slot), "eth_getStorageAt", [_hex20(address), hex(slot), hex(self.block)]

    def call_request(
        self, address: int, data: bytes, sender: int, overrides: dict | None = None
    ) -> tuple[tuple, str, list]:
        params = [{"from": _hex20(sender), "to": _hex20(address), "data": "0x" + data.hex()}, hex(self.block)]
        if not overrides:
            return ("c", address, data, sender), "eth_call", params
        # Storage as earlier calls of the same question left it (see ``World.overlay``), for the node to run on.
        diff = {
            _hex20(at): {
                "stateDiff": {"0x" + format(slot, "064x"): "0x" + format(word, "064x") for slot, word in slots}
            }
            for at, slots in sorted(overrides.items())
        }
        key = tuple((at, tuple(slots)) for at, slots in sorted(overrides.items()))
        return ("c", address, data, sender, key), "eth_call", [*params, diff]

    def _get(self, key: tuple, method: str, params: list) -> Any:
        if key not in self._memo and self.offline:
            return UNK
        if key not in self._memo and self.pending is not None and self.batch is not None:
            self.pending.append((key, method, params))
            return UNK
        if key not in self._memo:
            if not self._affordable():
                self.failed += 1
                return UNK
            self.sent += 1
            try:
                self._memo[key] = self.rpc(method, params)
            except TimeoutError:
                raise
            except Exception as exc:  # a revert is a revert; any transport or node error reads as unknown, unremembered
                if not _is_revert(str(exc)):
                    self.failed += 1
                    return UNK
                self._memo[key] = REVERTED
        return self._memo[key]

    def storage(self, address: int, slot: int) -> int | Any:
        raw = self._get(*self.storage_request(address, slot))
        return int(raw, 16) if isinstance(raw, str) else UNK

    def call(self, address: int, data: bytes, sender: int, overrides: dict | None = None) -> bytes | Any:
        raw = self._get(*self.call_request(address, data, sender, overrides))
        return bytes.fromhex(raw[2:]) if isinstance(raw, str) else raw

    def call_value(self, address: int, data: bytes, sender: int, value: int, overrides: dict | None = None) -> Any:
        """``call`` sending ``value`` wei, the sender's balance set to what it sends by a state override (a stranger
        holds none of its own on the node). A node that refuses the override answers with an error: unknown."""
        key, method, params = self.call_request(address, data, sender, overrides)
        params = [{**params[0], "value": hex(value)}, params[1], {**(params[2] if len(params) > 2 else {})}]
        params[2][_hex20(sender)] = {**params[2].get(_hex20(sender), {}), "balance": hex(value)}
        raw = self._get((*key, ("value", value)), method, params)
        return bytes.fromhex(raw[2:]) if isinstance(raw, str) else raw

    def block_field(self, name: str) -> int | Any:
        header = self._get(("b",), "eth_getBlockByNumber", [hex(self.block), False])
        if not isinstance(header, dict):
            return UNK
        if name == "chainid":
            return self._chain_id()
        key = {"basefee": "baseFeePerGas", "prevrandao": "mixHash", "coinbase": "miner", "gaslimit": "gasLimit"}
        raw = header.get(key.get(name, name))
        return int(raw, 16) if isinstance(raw, str) else UNK

    def _chain_id(self) -> int | Any:
        raw = self._get(("chainid",), "eth_chainId", [])
        return int(raw, 16) if isinstance(raw, str) else UNK

    def code(self, address: int) -> bytes | Any:
        raw = self._get(("code", address), "eth_getCode", [_hex20(address), hex(self.block)])
        return bytes.fromhex(raw[2:]) if isinstance(raw, str) else UNK

    def balance(self, address: int) -> int | Any:
        raw = self._get(("bal", address), "eth_getBalance", [_hex20(address), hex(self.block)])
        return int(raw, 16) if isinstance(raw, str) else UNK

    def logs(self, address: int, topics: frozenset[str]) -> list[tuple[list[int], list[int]]]:
        """(topics, data words) of the address's logs with one of ``topics``, in chain order up to the block."""
        if not topics:
            return []
        flt = {"address": _hex20(address), "fromBlock": "0x0", "toBlock": hex(self.block), "topics": [sorted(topics)]}
        key = ("l", address, topics)
        if key not in self._memo and address not in self.unreadable and self._affordable():
            # Read alone and once: a history scan the node gives up on (a busy token's whole range) fails the same
            # way again, for any of the address's events, and in a batch it would take the chunk's other reads down.
            self.sent += 1
            crowded = any(
                k[0] == "l" and k[1] == address and k[2] <= topics and v is None
                for k, v in self._memo.items()
                if isinstance(k, tuple) and len(k) == 3
            )
            if crowded:
                # More events than a history already too crowded to read: as crowded, not read again.
                self._memo[key] = None
            elif self.batch is not None:
                # Partial for these events only: the address's other events (its role grants) are still read.
                self._memo[key] = None  # until read: a scan the budget cuts off stays partial, not re-read
                if self.history_seconds is not None:
                    total = self.scan_total if self.scan_total is not None else self.history_seconds
                    self.scan_left = min(self.history_seconds, total)
                    given = self.scan_left
                self._memo[key] = self._scan_logs(address, flt)
                if self.history_seconds is not None and self.scan_total is not None:
                    self.scan_total -= given - max(self.scan_left, 0.0)
            else:
                try:
                    self._memo[key] = self.history("eth_getLogs", [flt])
                except TimeoutError:
                    raise
                except Exception:
                    self.unreadable.add(address)
        raw = self._memo.get(key)
        if not isinstance(raw, list):
            self.truncated.add(address)  # history unread (a node refusing the range): whatever it names is unknown
            return []
        raw = self._bounded(address, raw)
        out = []
        for log in raw:
            data = log.get("data", "0x")[2:]
            out.append(
                (
                    [int(t, 16) for t in log.get("topics", [])],
                    [int(data[i : i + 64] or "0", 16) for i in range(0, len(data), 64)],
                )
            )
        return out

    def storage_dump(self, address: int) -> dict[int, int] | None:
        """Every nonzero storage word of the address as the block leaves it, slot -> word; ``None`` without a debug
        node, for storage past ``SNAPSHOT_SLOTS`` (judged from how far the first page reaches into the hashed key
        space), or when any page fails: a dump is whole or nothing."""
        key = ("dump", address)
        if key in self._memo:
            return self._memo[key]
        if self.offline:
            raise Offline(key)
        self._memo[key] = None
        header = self._get(("b",), "eth_getBlockByNumber", [hex(self.block), False]) if self.debug else None
        if not isinstance(header, dict) or not isinstance(header.get("hash"), str):
            return None
        # After the block's last transaction: the state ``eth_getStorageAt`` reads at the block.
        at = [header["hash"], len(header.get("transactions") or ())]
        out: dict[int, int] = {}
        seen = 0
        start: str | None = "0x" + "00" * 32
        while start:
            if not self._affordable():
                return None
            self.sent += 1
            try:
                page = self.debug("debug_storageRangeAt", [*at, _hex20(address), start, SNAPSHOT_PAGE])
            except TimeoutError:
                raise
            except Exception:
                return None
            storage = page.get("storage") if isinstance(page, dict) else None
            if not isinstance(storage, dict):
                return None
            for entry in storage.values():
                slot, word = entry.get("key"), entry.get("value")
                if not isinstance(slot, str) or not isinstance(word, str):
                    return None  # a node without preimages: the slots can't be told apart
                if int(word, 16):
                    out[int(slot, 16)] = int(word, 16)
            seen += len(storage)
            start = page.get("nextKey")
            if start and seen * 2**256 // max(int(start, 16), 1) > SNAPSHOT_SLOTS:
                return None
        self._memo[key] = out
        return out

    def creation_tx(self, address: int) -> str | None:
        """The hash of the transaction that created the address, when whoever reads the chain knows it (an
        explorer's record); ``None`` otherwise."""
        return None

    def creation_trace(self, address: int) -> tuple[frozenset[int], dict[int, int]] | None:
        """Of the transaction that created the address: every word its calls carry (senders, targets, inputs), and
        the storage it left at the address (slot -> word). ``None`` when either isn't known."""
        key = ("created_trace", address)
        if key in self._memo:
            return self._memo[key]
        if self.offline:
            raise Offline(key)
        self._memo[key] = None
        tx = self.creation_tx(address) if self.debug else None
        if tx is None or not self._affordable(2):
            return None
        self.sent += 2
        try:
            calls = self.debug("debug_traceTransaction", [tx, {"tracer": "callTracer"}])
            prestate = {"tracer": "prestateTracer", "tracerConfig": {"diffMode": True}}
            diff = self.debug("debug_traceTransaction", [tx, prestate])
        except TimeoutError:
            raise
        except Exception:
            return None
        if not isinstance(calls, dict) or not isinstance(diff, dict) or not isinstance(diff.get("post"), dict):
            return None
        words = _frame_words(calls)
        post = next((v for k, v in diff["post"].items() if int(k, 16) == address), {}) or {}
        storage = {int(k, 16): int(v, 16) for k, v in (post.get("storage") or {}).items() if int(v, 16)}
        self._memo[key] = (frozenset(words), storage)
        return self._memo[key]

    def slot_writers(self, address: int, slots: list[int]) -> dict[int, frozenset[int] | None]:
        """Per slot, every word the calls carry of a transaction that wrote it nonzero (``None`` when a read fails or
        no writer shows): the block each turned nonzero at, bisected over ``eth_getStorageAt`` from the address's
        creation with every slot's read of a round in one batch; then those blocks' writes (``prestateTracer``
        diffs) and each writer's calls, each block and transaction traced once."""
        out: dict[int, frozenset[int] | None] = {}
        todo = [s for s in slots if ("slot_writer", address, s) not in self._memo]
        for s in slots:
            if s not in todo:
                out[s] = self._memo[("slot_writer", address, s)]
        if not todo:
            return out
        if self.offline:
            raise Offline(("slot_writer", address))
        for s in todo:
            self._memo[("slot_writer", address, s)] = None
            out[s] = None
        if self.debug is None:
            return out

        def stored(pairs: list[tuple[int, int]]) -> dict[tuple[int, int], int | None]:
            requests = [
                (("s_at", address, s, b), "eth_getStorageAt", [_hex20(address), hex(s), hex(b)]) for s, b in pairs
            ]
            self.prefetch(requests)
            answers = {}
            for (key, method, params), pair in zip(requests, pairs):
                raw = self._get(key, method, params)
                answers[pair] = int(raw, 16) if isinstance(raw, str) else None
            return answers

        start = max(self._created(address) - 1, 0)
        ends = stored([(s, b) for s in todo for b in (start, self.block)])
        bounds = {s: [start, self.block] for s in todo if ends[(s, start)] == 0 and ends[(s, self.block)]}
        while any(high - low > 1 for low, high in bounds.values()):
            probes = {s: (low + high) // 2 for s, (low, high) in bounds.items() if high - low > 1}
            answers = stored(list(probes.items()))
            for s, middle in probes.items():
                value = answers[(s, middle)]
                if value is None:
                    bounds.pop(s)
                else:
                    bounds[s][0 if not value else 1] = middle
        prestate = {"tracer": "prestateTracer", "tracerConfig": {"diffMode": True}}
        writers: dict[int, list[str]] = {}
        for block in sorted({high for _, high in bounds.values()}):
            if not self._affordable():
                return out
            self.sent += 1
            try:
                diffs = self.debug("debug_traceBlockByNumber", [hex(block), prestate])
            except TimeoutError:
                raise
            except Exception:
                continue
            for item in diffs if isinstance(diffs, list) else ():
                post = (item.get("result") or {}).get("post") or {}
                storage = next((v.get("storage") or {} for k, v in post.items() if int(k, 16) == address), {})
                for k, v in storage.items():
                    if int(k, 16) in bounds and bounds[int(k, 16)][1] == block and int(v, 16):
                        writers.setdefault(int(k, 16), []).append(item.get("txHash"))
        carried: dict[str, frozenset[int] | None] = {}
        for s, txs in writers.items():
            words: set[int] = set()
            for tx in txs:
                if not isinstance(tx, str):
                    words = set()
                    break
                if tx not in carried:
                    carried[tx] = None
                    if self._affordable():
                        self.sent += 1
                        try:
                            calls = self.debug("debug_traceTransaction", [tx, {"tracer": "callTracer"}])
                        except TimeoutError:
                            raise
                        except Exception:
                            calls = None
                        carried[tx] = _frame_words(calls) if isinstance(calls, dict) else None
                if carried[tx] is None:
                    words = set()
                    break
                words |= carried[tx]
            if words:
                self._memo[("slot_writer", address, s)] = out[s] = frozenset(words)
        return out

    def creation_block(self, address: int) -> int | None:
        """The block the address got its code in, when whoever reads the chain already knows it (an explorer's
        record); ``None`` otherwise."""
        return None

    def _created(self, address: int) -> int:
        """A block at or before the address got its code: its recorded creation, else the last of
        ``CREATION_PROBES`` evenly spaced blocks without it (0 when any probe fails, or the code was there from the
        first: old state is often served by fewer nodes)."""
        key = ("created", address)
        if key not in self._memo and self.offline:
            raise Offline(key)
        if key not in self._memo:
            known = self.creation_block(address)
            if known is not None:
                self._memo[key] = known
                return known
            points = [self.block * i // CREATION_PROBES for i in range(1, CREATION_PROBES)]
            try:
                codes = self.batch([("eth_getCode", [_hex20(address), hex(b)]) for b in points])
            except TimeoutError:
                raise
            except Exception:
                codes = [None] * len(points)
            start = 0
            for b, code in zip(points, codes):
                if not isinstance(code, str):
                    start = 0
                    break
                if code in ("0x", ""):
                    start = b
            self._memo[key] = start
        return self._memo[key]

    def _scan_logs(self, address: int, flt: dict) -> list | None:
        """The logs ``flt`` matches up to the block, read window by window in batches; ``None`` for a crowd (a window
        refusing even at ``LOG_MIN_WINDOW`` blocks, more than ``LOG_ROWS``). Past ``LOG_CALLS`` or the scanning time,
        the windows read so far, with the address marked truncated: what they name is a lower bound, never the list.
        Refused windows wait while the earliest is halved until a width answers, then are all cut to that width: one
        descent, not a split of every one."""

        def cut(lo: int, hi: int, width: int) -> list[tuple[int, int]]:
            return [(a, min(a + width - 1, hi)) for a in range(lo, hi + 1, width)]

        def partial() -> list:
            self.truncated.add(address)
            return in_order(found)

        def in_order(logs: list) -> list:
            return sorted(
                logs, key=lambda log: (int(log.get("blockNumber", "0x0"), 16), int(log.get("logIndex", "0x0"), 16))
            )

        self.crowded = False  # set when the scan stops for a crowd, not for a refusal or the clock
        width = LOG_WINDOW
        todo = cut(self._created(address), self.block, width)
        refused: list[tuple[int, int]] = []
        probing = False
        found: list = []
        calls = 0
        while todo or refused:
            if self.scan_left is not None and self.scan_left <= 0:
                return partial()  # this function's scanning time spent: the rest of the history stays unread
            if not todo:
                if not probing:
                    width //= 2
                    if width < LOG_MIN_WINDOW:
                        return None
                    todo, refused, probing = cut(*refused[0], width), refused[1:], True
                else:
                    todo, refused, probing = [w for lo, hi in refused for w in cut(lo, hi, width)], [], False
            chunk, todo = todo[:LOG_BATCH], todo[LOG_BATCH:]
            calls += len(chunk)
            if calls > LOG_CALLS:
                return partial()
            started = time.monotonic()
            try:
                answers = self.batch(
                    [("eth_getLogs", [{**flt, "fromBlock": hex(lo), "toBlock": hex(hi)}]) for lo, hi in chunk]
                )
            except TimeoutError:
                raise
            except Exception:
                answers = [None] * len(chunk)
            if self.scan_left is not None:
                self.scan_left -= time.monotonic() - started
            failed = []
            if any(answer is CROWDED for answer in answers):
                self.crowded = True
                return None  # one window already holds more than any list of holders: the scan can stop
            for window, answer in zip(chunk, answers):
                if isinstance(answer, list):
                    found.extend(answer)
                    if len(found) > LOG_ROWS:
                        self.crowded = True
                        return None  # more than any list of holders: read no further
                else:
                    failed.append(window)
            if failed:
                refused = sorted(refused + failed)
                if probing:
                    probing = False  # this width is refused too: halve again
                    refused, todo = sorted(refused + todo), []
        return in_order(found)

    def _bounded(self, address: int, rows: list) -> list:
        """The earliest and latest ``LOG_ROWS`` halves of a history too long to read whole (a token's transfers):
        deployment-time grants and recent changes, with the address marked partial."""
        if len(rows) <= LOG_ROWS:
            return rows
        self.truncated.add(address)
        return rows[: LOG_ROWS // 2] + rows[-(LOG_ROWS // 2) :]

    def all_log_words(self, address: int) -> set[int]:
        """Words of every log already recorded for the address; none over RPC, where that's a full history scan."""
        return set()

    def log_addresses(
        self, address: int, events: dict[int, list[tuple[str, bool]]], require: frozenset = frozenset()
    ) -> set[int]:
        """Address-typed arguments (``address`` and ``address[]``) of the address's logs of ``events``: topic0 ->
        the event's (ABI type, indexed) parameters. ``require``: only logs carrying every one of these words (a
        role's id, for that role's holders)."""
        topics = frozenset("0x" + format(t, "064x") for t in events)
        out: set[int] = set()
        logs = self.logs(address, topics)
        if require:
            # Only the keys these events record (a hashed key's constant tag never appears): logs naming them all.
            require = require & {w for log_topics, data in logs for w in (*log_topics[1:], *data)}
        for log_topics, data in logs:
            params = events.get(log_topics[0]) if log_topics else None
            if params is None:
                continue
            if require and not require <= {*log_topics[1:], *data}:
                continue
            indexed = iter(log_topics[1:])
            plain = [t for t, is_indexed in params if not is_indexed]
            for type_, is_indexed in params:
                if is_indexed:
                    word = next(indexed, None)
                    if word is not None and type_ == "address":
                        out.add(word % 2**160)
            if any(t.startswith("address") for t in plain):
                try:
                    values = decode(plain, b"".join(w.to_bytes(32, "big") for w in data))
                except Exception as exc:
                    if isinstance(exc, TimeoutError):
                        raise
                    continue
                for type_, value in zip(plain, values):
                    if type_ == "address":
                        out.add(int(value, 16))
                    elif type_.startswith("address["):
                        out.update(int(v, 16) for v in value)
        return out

    def log_words(self, address: int, topics: frozenset[str]) -> set[int]:
        """Every 32-byte word (topics and data) in those logs."""
        words: set[int] = set()
        for log_topics, data in self.logs(address, topics):
            words.update(log_topics[1:])
            words.update(data)
        return words


Chain.logs = _tracked(Chain.logs)  # type: ignore[method-assign]


def _frame_words(calls: dict) -> frozenset[int]:
    """Every word a ``callTracer`` tree carries: each frame's sender and target, and its input's aligned words after
    a selector (a call's arguments) and from the end (a constructor's, after its code): a key handed over is one."""
    words: set[int] = set()
    frames = [calls]
    while frames:
        frame = frames.pop()
        for name in ("from", "to"):
            if isinstance(frame.get(name), str):
                words.add(int(frame[name], 16))
        data = (frame.get("input") or "0x")[2:]
        for start in (8, len(data) % 64):
            words.update(int(data[i : i + 64], 16) for i in range(start, len(data) - 63, 64))
        frames.extend(c for c in frame.get("calls") or () if isinstance(c, dict))
    return frozenset(words)


def batch_results(classified: list[tuple[Any, str]]) -> list[Any]:
    """``rpc_batch_request_classified(..., keep_errors=True)`` slots as ``Chain`` takes them: the answer, REVERTED for
    an execution error, ``None`` for anything else (a node or transport error stays unknown)."""
    out = []
    for result, status in classified:
        if status == "ok":
            out.append(result)
        elif status == "error" and isinstance(result, dict) and _is_revert(str(result.get("message", ""))):
            out.append(REVERTED)
        elif status == "error" and isinstance(result, dict) and _crowded(str(result.get("message", ""))):
            out.append(CROWDED)
        else:
            out.append(None)
    return out


def _crowded(message: str) -> bool:
    """A node refusing a log range for how much it holds, at a count no smaller than ``LOG_ROWS``."""
    found = _CROWDED_ERRORS.search(message)
    return found is not None and (found.group(1) is None or int(found.group(1)) >= LOG_ROWS)


# How nodes word a call that failed in the EVM (a revert, an ``assert``'s invalid opcode, running out of gas), as
# opposed to the node or the transport failing: the former is the call's answer, the same every time it is asked.
_EVM_FAILURES = ("revert", "execution", "evm error", "invalid opcode", "invalidfeopcode", "out of gas", "invalid jump")


def _is_revert(message: str) -> bool:
    message = message.lower()
    return any(marker in message for marker in _EVM_FAILURES)


def _hex20(value: int) -> str:
    return "0x" + format(value % 2**160, "040x")


# Storage layout -------------------------------------------------------------------------------------------------------


def _size(type_: Any) -> int | None:
    """Bytes a value of ``type_`` occupies in a slot; ``None`` for types that take whole slots (structs, arrays,
    mappings)."""
    from slither.core.declarations import Contract, Enum
    from slither.core.solidity_types import ElementaryType, UserDefinedType

    if isinstance(type_, ElementaryType):
        name = type_.name
        if name in ("address", "address payable"):
            return 20
        if name == "bool":
            return 1
        for prefix in ("uint", "int"):
            if name.startswith(prefix):
                return int(name[len(prefix) :] or 256) // 8
        if name.startswith("bytes") and name != "bytes":
            return int(name[5:])
        return None
    if isinstance(type_, UserDefinedType):
        if isinstance(type_.type, Contract):
            return 20
        if isinstance(type_.type, Enum):
            return 1
    underlying = getattr(type_, "underlying_type", None)  # a user-defined value type (``type Duration is uint32``)
    if underlying is not None:
        return _size(underlying)
    return None


def _struct_fields(structure: Any) -> dict[str, tuple[int, int, Any]]:
    """Field -> (slot offset, byte offset, type), packed as the compiler packs; remembered on the structure."""
    cached = structure.__dict__.get("_psat_fields")
    if cached is None:
        cached = structure.__dict__["_psat_fields"] = _pack_fields(structure)
    return cached


def _pack_fields(structure: Any) -> dict[str, tuple[int, int, Any]]:
    out: dict[str, tuple[int, int, Any]] = {}
    slot, used = 0, 0
    for member in structure.elems_ordered:
        size = _size(member.type)
        if size is None:
            if used:
                slot, used = slot + 1, 0
            out[member.name] = (slot, 0, member.type)
            slot += _slots(member.type)
            continue
        if used + size > 32:
            slot, used = slot + 1, 0
        out[member.name] = (slot, used, member.type)
        used += size
    return out


def _slots(type_: Any) -> int:
    from slither.core.declarations import Structure
    from slither.core.solidity_types import ArrayType, UserDefinedType

    if isinstance(type_, UserDefinedType) and isinstance(type_.type, Structure):
        fields = _struct_fields(type_.type)
        last = max(fields.values(), key=lambda f: f[0], default=(0, 0, None))
        return last[0] + (_slots(last[2]) if _size(last[2]) is None and last[2] is not None else 1)
    if isinstance(type_, ArrayType) and type_.length is not None:
        size = _size(type_.type)
        literal = getattr(type_, "length_value", None)  # ``bytes32[TREE_DEPTH]``: the constant, evaluated
        length = int(str(literal.value if literal is not None else type_.length), 0)
        if size is None:
            return length * _slots(type_.type)
        per = 32 // size
        return (length + per - 1) // per
    return 1


def _key_bytes(value: Any, type_: Any) -> bytes | None:
    if isinstance(value, bool):
        value = int(value)
    if isinstance(value, int):
        name = str(type_)
        if name.startswith("bytes") and name not in ("bytes", "bytes32"):
            return (value % 2 ** (8 * int(name[5:]))).to_bytes(int(name[5:]), "big").ljust(32, b"\0")
        return (value % 2**256).to_bytes(32, "big")
    if isinstance(value, str):
        return value.encode()
    return None


_LOCATED = 100_000  # slot computations remembered per contract, at most


def locate(contract: Any, var_name: Any, path: tuple) -> tuple[int, int, Any] | None:
    """(slot, byte offset, type) of ``contract.var_name`` followed by concrete ``path`` steps; remembered per
    contract, since every guess at the arguments asks again."""
    memo = contract.__dict__.setdefault("_psat_located", {})
    key = (var_name, path)
    try:
        return memo[key]
    except KeyError:
        pass
    except TypeError:
        return _locate(contract, var_name, path)  # an unhashable step: computed every time
    if len(memo) >= _LOCATED:
        memo.clear()
    memo[key] = _locate(contract, var_name, path)
    return memo[key]


def _locate(contract: Any, var_name: Any, path: tuple) -> tuple[int, int, Any] | None:

    # ``state_variables`` leaves out a parent's private variables; the storage layout doesn't.
    if isinstance(var_name, tuple) and var_name[0] == "slot":
        # A pointer rooted at a raw slot (namespaced storage): ``var_name`` is ("slot", slot, struct name), already
        # evaluated to an int slot by the caller.
        slot, offset, type_ = var_name[1], 0, _named_type(contract, var_name[2])
        if not isinstance(slot, int) or type_ is None:
            return None
        return _walk(contract, slot, offset, type_, path)
    var = next((v for v in contract.state_variables_ordered if v.name == var_name), None)
    if var is None:
        return None
    try:
        slot, offset = contract.compilation_unit.storage_layout_of(contract, var)
    except KeyError:
        # Slither has no layout for this contract (several compilation units): packed here, as the compiler does.
        found = _layout(contract).get(id(var))
        if found is None:
            return None
        slot, offset = found
    return _walk(contract, slot, offset, var.type, path)


def _layout(contract: Any) -> dict[int, tuple[int, int]]:
    """id(variable) -> (slot, byte offset) of the contract's storage, in declaration order (bases first), packed."""
    cached = contract.__dict__.get("_psat_layout")
    if cached is None:
        try:
            cached = _pack_layout(contract)
        except ValueError:
            cached = {}  # a size the types don't give (an unevaluated array length): no layout, reads unknown
        contract.__dict__["_psat_layout"] = cached
    return cached


def _pack_layout(contract: Any) -> dict[int, tuple[int, int]]:
    out: dict[int, tuple[int, int]] = {}
    slot, used = 0, 0
    for var in contract.state_variables_ordered:
        if var.is_constant or var.is_immutable:
            continue
        size = _size(var.type)
        if size is None:
            if used:
                slot, used = slot + 1, 0
            out[id(var)] = (slot, 0)
            slot += _slots(var.type)
            continue
        if used + size > 32:
            slot, used = slot + 1, 0
        out[id(var)] = (slot, used)
        used += size
    return out


def _named_type(contract: Any, name: str) -> Any:
    from slither.core.declarations import Structure
    from slither.core.solidity_types import UserDefinedType

    unit = contract.compilation_unit
    for structure in [*unit.structures_top_level, *(s for c in unit.contracts for s in c.structures)]:
        if structure.canonical_name == name or structure.name == name:
            return UserDefinedType(structure) if isinstance(structure, Structure) else None
    # Any other type (``mapping(uint256 => Request)`` at an unstructured position): as some declaration spells it.
    declared = contract.__dict__.get("_psat_declared_types")
    if declared is None:
        declared = {}
        for c in unit.contracts:
            for v in [*c.state_variables, *(x for f in c.functions_and_modifiers for x in f.variables)]:
                declared.setdefault(str(v.type), v.type)
        contract.__dict__["_psat_declared_types"] = declared
    return declared.get(name)


def _walk(contract: Any, slot: int, offset: int, type_: Any, path: tuple) -> tuple[int, int, Any] | None:
    from slither.core.declarations import Structure
    from slither.core.solidity_types import ArrayType, MappingType, UserDefinedType

    for kind, step in path:
        if kind == "k" and isinstance(type_, MappingType):
            key = _key_bytes(step, type_.type_from)
            if key is None:
                return None
            slot = int.from_bytes(keccak(key + slot.to_bytes(32, "big")), "big")
            offset, type_ = 0, type_.type_to
        elif kind == "k" and isinstance(type_, ArrayType):
            if not isinstance(step, int):
                return None
            base = slot if type_.length is not None else int.from_bytes(keccak(slot.to_bytes(32, "big")), "big")
            size = _size(type_.type)
            if size is None:
                slot, offset = (base + step * _slots(type_.type)) % 2**256, 0
            else:
                per = 32 // size
                slot, offset = (base + step // per) % 2**256, (step % per) * size
            type_ = type_.type
        elif kind == "f" and step == "length" and isinstance(type_, ArrayType) and type_.length is None:
            return slot, 0, None
        elif kind == "f" and isinstance(type_, UserDefinedType) and isinstance(type_.type, Structure):
            fields = _struct_fields(type_.type)
            if step not in fields:
                return None
            extra, offset, type_ = fields[step]
            slot = (slot + extra) % 2**256
        else:
            return None
    return slot, offset, type_


def _decode_word(word: int, offset: int, type_: Any) -> Any:
    size = _size(type_) if type_ is not None else 32
    if size is None:
        return word
    value = (word >> (8 * offset)) % 2 ** (8 * size)
    if str(type_) == "bool":
        return value != 0
    if str(type_).startswith("int"):
        bits = 8 * size
        return value - 2**bits if value >= 2 ** (bits - 1) else value
    return value


# Evaluation -----------------------------------------------------------------------------------------------------------


@dataclass
class World:
    """What evaluation can read: the chain at a block, the evaluated contract, and lowerable contracts by address."""

    chain: Chain
    this: int
    selector: int
    contracts: dict[int, Any] = field(default_factory=dict)  # address -> Slither contract
    values: dict[str, Any] = field(default_factory=dict)  # immutables and unresolved constants, by name
    named: set[int] = field(default_factory=set)  # address literals anywhere in the contract's code
    hashed_only: frozenset = frozenset()  # caller-chosen values the formula uses only inside hashes
    deadline: float = float("inf")  # time.monotonic() past which decisions stop and answer unknown (a safety net)
    work: float = 0.0  # decision steps spent on this function: a deterministic budget, unlike the clock
    work_limit: float = float("inf")
    # Per solver question (formula, free conditions): how often z3 gave up on it, and how often it settled it.
    solver_record: dict = field(default_factory=dict)
    # The function's arguments in order, as terms: what its own ``msg.data`` encodes after the selector.
    parameters: tuple = ()
    # Conditions on a caller's own entries that any caller can bring about through code open to it (a position a
    # ``supply`` opens, an allowance an ``approve`` sets): chosen like arguments by whoever is asked about, where the
    # entry is theirs (the condition each maps to holds), read from state elsewhere.
    arranged: dict = field(default_factory=dict)
    # Finds them for a formula (see ``verdict.arranged_atoms``); asked only once a stranger has failed.
    arrange: Callable[[Term], dict] = lambda formula: {}

    def exhausted(self) -> bool:
        return self.work > self.work_limit or time.monotonic() > self.deadline

    recorded: dict | None = None  # per formula: argument -> keys its mapping's writers recorded
    # Every key tuple an entry of (contract, variable, key count, fields) was ever set at, from the events that log
    # each write's keys; ``None`` when not known whole (see ``verdict.entries``).
    entries: Callable[..., list[tuple[int, ...]] | None] = lambda contract, var, keys, fields, whole=True: None
    latched: frozenset = frozenset()  # ``when`` conditions the code can never flip: read as they are
    cut: set = field(default_factory=set)  # addresses of lookups whose writer histories were read partial
    # ``coverage`` of a subformula (see ``_decisive``).
    cover: Callable[[Term], Any] | None = None
    # A call's callee lowered in its caller's terms: (returns-condition, return values), or None when not lowerable.
    callee: Callable[..., tuple[Term, tuple] | None] = lambda call, address=None: None
    # Whether a call made by followed code answers the same whoever makes it (``verdict.asker_free``): then it is
    # asked of the chain as this contract, an answer any asker shares.
    asker_free: Callable[[Term], bool] = lambda call: False
    # Bytes of return data a call's callee at an address declares it returns, when its declaration fixes them.
    declared_size: Callable[[Term, int], int | None] = lambda call, address: None
    # Why a view call handed nothing of the caller may still answer otherwise for another caller (``origin``,
    # ``hidden``, ``unfollowed``, ...), else ``None``: see ``verdict.caller_bound``. ``None`` where no such check is
    # supplied: then only the callees' lowerings are read (``_reads_origin``).
    caller_bound: Callable[[Term], str | None] | None = None
    # Whether a state-changing call its callee refuses for the caller (as that condition, in caller terms) fails only
    # on the caller's own entries there, which open code lets the caller bring about (see ``verdict.action_open``).
    action_open: Callable[[Term, Term], bool | frozenset] = lambda call, refused: True
    # Whether a view call handed the caller reads only holdings the callee's open code lets anyone be given (a
    # token balance a transfer moves in); see ``verdict.arranged_atoms``.
    credited: Callable[[Term], bool] = lambda call: False
    # Arranged conditions resting on what the caller holds rather than who it is: atom -> the holdings it reads; an
    # action taking from the caller (``transferFrom(msg.sender, ...)``) -> (its target, the balances it moves).
    requirements: dict = field(default_factory=dict)
    held_actions: dict = field(default_factory=dict)
    # The entry points that bring the caller's own entries about (``verdict._arrangeable``): entry shape -> (the
    # function, the arguments it passed with), for the chain to run as each stranger.
    arrangers: dict = field(default_factory=dict)
    # What an "open now" this decision reached rests on beyond the stranger's own call as the chain stands
    # (``_confirmed_open``): ``assumed`` (an action not handed the caller), ``action`` (an action handed it, refusing
    # only on entries the caller brings about: each (call, entries, arrangers) in ``brought``), ``arranged`` (the
    # caller's own entries here, brought about first).
    rests_on: set = field(default_factory=set)
    brought: list = field(default_factory=list)
    # Whether an "open" this decision reached rests on strangers' calls run on the chain (``strangers_run``,
    # ``runs``) where the formula alone left the stranger unsettled or rested on a callee's code: what five addresses
    # showed, a sample (``Verdict.witnessed``).
    sampled: bool = False
    # Conditions on records the caller names (``decide``), and whether questions leave them free (all but "now").
    records: frozenset = frozenset()
    records_free: bool = True
    # Storage words earlier calls of the question wrote, (address, slot) -> word (UNK where what they wrote is
    # unknown): read before the chain, and handed to the node for the calls it runs (see ``verdict.after_own_call``).
    overlay: dict = field(default_factory=dict)
    # How many answers that came out false only through a followed callee's code standing in for a call came out
    # unknown once asked without it (``Evaluator.truth``, ``solve``): ``decide`` names the gap.
    code_refuted: int = 0
    # Likewise for answers that came out true only through a followed callee's code: unknown once asked without it.
    code_passed: int = 0
    # Reads the chain may still be sent to confirm passes only a callee's code showed (``confirming``); past them such
    # a pass is unknown, unasked (``budget:confirm``).
    confirm_left: float = float("inf")
    # The stranger's own calls that, made first, let it through (see ``verdict.after_own_call``): the function's
    # signature and the arguments of each, or ``None``.
    prior: Callable[..., Any] = lambda formula, owned=False, states=None: None
    # The success formula narrowed to calls with an effect (a write that changes storage, a call out); ``None``
    # when unknown, as for a callee.
    effective: Term | None = None
    # An ``_arrangeable`` question the chain's answers left open: a stranger's own entries may yet be its to set.
    arrange_unknown: bool = False
    # (contract, variable, key count, fields) -> every value that field has held at any key (zero and each value its
    # complete value events recorded), or ``None`` when not known that way.
    values_of: Callable[[Term, Any, int, tuple], frozenset | None] = lambda contract, var, keys, fields: None
    written: frozenset = frozenset()  # (contract, variable) the function itself may write
    # Topic0s of the events that write (address, variable): where candidate keys of an identity lookup appear.
    writer_topics: Callable[[int, str], frozenset[str]] = lambda address, var: frozenset()
    # The same events with their parameters: topic0 -> [(ABI type, indexed)], to read only address arguments.
    writer_events: Callable[[int, str], dict[int, list[tuple[str, bool]]]] = lambda address, var: {}
    # Whether every write to (contract, variable, key count, fields) emits its key (see ``coverage``).
    complete: Callable[[Term, str, int, tuple], bool] = lambda contract, var, keys, fields: False
    # An immutable of the code at an address, read from that code.
    immutable: Callable[[int, str], Any] = lambda address, name: UNK
    # Whether a storage read can never hold anything but what it holds now: this contract's slot that no entry point
    # can leave otherwise from here (``verdict.constant_load``).
    constant_load: Callable[[Term], bool] = lambda load: False
    # Addresses the constructor keyed entries by, from the creating transaction (see ``snapshot.creation_keys``).
    created: dict = field(default_factory=dict)
    # The address holding the code that runs at an address (a proxy's implementation).
    code_of: Callable[[int], int] = lambda address: address
    # Keys whose current value at (address, variable, fields) is ``value``, from the writer events' history.
    # ``proof=False``: keys only to try, each checked on the chain (see ``verdict.inverse``).
    inverse: Callable[..., set[int] | None] = lambda address, var, fields, value, proof=True: set()
    # Key -> the value it was last left holding at (address, variable, fields), from the value events' history;
    # ``None`` when that history was cut or isn't complete.
    latest: Callable[[int, str, tuple], dict[int, int] | None] = lambda address, var, fields: None
    # Per candidate the builder listed (``holders.listed``): the argument bindings it may pass under.
    hints: dict = field(default_factory=dict)
    # Candidate -> its place in the order they are asked about (``_built``): the order only, never a cut.
    ranking: dict = field(default_factory=dict)
    # What a storage dump accounted for (``_snapshot_plan``): the lookups and cut histories it lists whole, and the
    # addresses that are all their holders who may pass; read by the builder where the events don't list them.
    dumped: dict = field(default_factory=dict)
    # Whose positions the function's effects touch (``scope.Scope``), when known.
    scope: Any = None
    # The chain's failed reads before this function began (``verdict`` reads callees' addresses before ``decide``):
    # a decision that met a later one sets nothing aside.
    failed_at: int | None = None


class _Reads(dict):
    """An assignment noting every entry evaluation consults (``seen``); anything that walks it whole reads it all."""

    def __init__(self, *args: Any) -> None:
        super().__init__(*args)
        self.seen: set = set()

    def get(self, key: Any, default: Any = None) -> Any:
        self.seen.add(key)
        return super().get(key, default)

    def __getitem__(self, key: Any) -> Any:
        self.seen.add(key)
        return super().__getitem__(key)

    def __contains__(self, key: object) -> bool:
        self.seen.add(key)
        return super().__contains__(key)

    def _whole(self) -> None:
        self.seen.update(super().keys())

    def keys(self) -> Any:
        self._whole()
        return super().keys()

    def items(self) -> Any:
        self._whole()
        return super().items()

    def values(self) -> Any:
        self._whole()
        return super().values()

    def __iter__(self) -> Any:
        self._whole()
        return super().__iter__()

    def copy(self) -> dict:
        self._whole()
        return dict(super().items())


class Evaluator:
    def __init__(
        self,
        world: World,
        identity: dict[str, int],
        assignment: dict[Term, Any] | None = None,
        blind: frozenset = frozenset(),
        when: frozenset = frozenset(),
        settled: dict[Term, Any] | None = None,
    ):
        self.world = world
        self.identity = identity
        self.assignment = assignment if assignment is not None else {}
        # Conditions read as free rather than from state (``when`` atoms, see ``when_atoms``).
        # The solver leaves arranged conditions free; a witness it finds is checked here, where they are free only
        # on the caller's own entries.
        self.when = when | frozenset(world.arranged) if world.arranged else when
        # Lookups keyed by an identity whose members can't be listed: read as unknown, as if anything had been written.
        self.blind = blind
        self._memo: dict[Term, Any] = dict(settled) if settled else {}
        # Whether a view call over arguments the caller picks is answered by its followed callee's code before the
        # chain (each guess a call of its own), and whether any answer so far rested on a callee's code: shared with
        # the evaluators this one makes, with how deep in an evaluation they are, so a pass resting on it is asked of
        # the chain again (``confirmed``) and a failure resting on it is asked without it (``truth``).
        self.code_first = True
        self.callee_code = True  # whether a followed callee's code may answer a call at all
        self.coded = [False, 0]
        self._coded_terms: set = set()  # memoized values some callee's code went into

    def nested(self, when: frozenset) -> "Evaluator":
        """An evaluator over the same identity and arguments with ``when`` free, sharing how calls are answered."""
        inner = Evaluator(self.world, self.identity, self.assignment, self.blind, when)
        inner.code_first, inner.callee_code, inner.coded = self.code_first, self.callee_code, self.coded
        return inner

    def truth(self, term: Term) -> Any:
        """True, False or UNK (``PREIMAGE`` and ``ASSUMED`` count as true; a path that reverts, as false).

        Callee code never refutes on its own: asked from outside any evaluation, a False that some followed callee's
        code went into (a call over guessed or unknown arguments answered by it, an action's return value) is asked
        again without any callee code, every such call put to the chain or left unknown. What still fails stands;
        what passes there passes; what is left unknown is unknown (counted, ``world.code_refuted``). A pass is asked
        again where a decision rests on it (``passes``, ``confirmed``). Inside an evaluation, and for ranking
        (``ranked``), the code's answer is used as it is."""
        if self.coded[1] or not self.callee_code:
            return self.ranked(term)
        outer, self.coded[0] = self.coded[0], False
        try:
            value = self.ranked(term)
            used = self.coded[0]
        finally:
            self.coded[0] = outer or self.coded[0]
        if value is False and used:
            value = self._without_code(term)
        return value

    def passes(self, term: Term) -> Any:
        """``truth``, with a True that some followed callee's code went into asked again without any callee code too
        (within the reads left for confirming, ``confirming``): what a decision says passes never rests on the code."""
        if self.coded[1] or not self.callee_code:
            return self.ranked(term)
        outer, self.coded[0] = self.coded[0], False
        try:
            value = self.truth(term)
            used = self.coded[0]
        finally:
            self.coded[0] = outer or self.coded[0]
        if value is True and used:
            value = self._without_code(term, True)
        return value

    def ranked(self, term: Term) -> Any:
        """``truth`` with whatever a callee's code answered taken as it is: for ordering and skipping guesses only,
        never for a refutation."""
        self.coded[1] += 1
        try:
            value = self._test(term)
        finally:
            self.coded[1] -= 1
        return False if value is REVERTED else value

    def _without_code(self, term: Term, passed: bool = False) -> Any:
        again = self.without_code()
        value = confirming(self.world, lambda: again.truth(term)) if passed else again.truth(term)
        if value is UNK and passed:
            self.world.code_passed += 1
        elif value is UNK:
            self.world.code_refuted += 1
        return value

    def without_code(self) -> "Evaluator":
        """This evaluator with no callee code answering any call, keeping what it read that no callee's code went
        into."""
        kept = {t: v for t, v in self._memo.items() if t not in self._coded_terms}
        again = Evaluator(self.world, self.identity, self.assignment, self.blind, self.when, kept)
        again.code_first = again.callee_code = False
        return again

    def _test(self, term: Term) -> Any:
        """``truth``, keeping REVERTED apart from False: negating a revert doesn't make it pass."""
        value = self.eval(term)
        if value in (PREIMAGE, ASSUMED):
            return True
        if isinstance(value, bool) or value is REVERTED:
            return value
        if isinstance(value, int):
            return value != 0
        return UNK

    def eval(self, t: Term) -> Any:
        if t in self._memo:
            if t in self._coded_terms:
                self.coded[0] = True
            return self._memo[t]
        outer, self.coded[0] = self.coded[0], False
        self.coded[1] += 1
        try:
            value = self._eval_new(t)
        finally:
            self.coded[1] -= 1
            used = self.coded[0]
            self.coded[0] = outer or used
        if used and t in self._memo:
            self._coded_terms.add(t)
        return value

    def _eval_new(self, t: Term) -> Any:
        if self.world.arranged and t in self.world.arranged and t not in self.assignment and t in self.when:
            # Unassigned: free wherever the entry may be the caller's own.
            mine = self.truth(self.world.arranged[t])
            if mine is not False:
                return UNK
            value = self._eval(t)
            self._memo[t] = value
            return value
        if self.world.arranged and t in self.world.arranged and t in self.assignment:
            mine = self.truth(self.world.arranged[t])
            if mine is True:
                return self.assignment[t]
            if mine is UNK:
                return UNK
            value = self._eval(t)
            self._memo[t] = value
            return value
        if t in self.when:
            return self.assignment.get(t, UNK)
        value = self._eval(t)
        self._memo[t] = value
        return value

    def _eval(self, t: Term) -> Any:
        self.world.work += NODE_WORK
        kind = t[0]
        if kind == "const":
            return t[1]
        if kind in ("caller", "origin"):
            who = self.identity["caller"]
            if kind == "origin" and self._coded(who):
                return UNK  # a contract calling: the origin is some account behind it, never the contract itself
            return who
        if kind == "signer":
            return self.identity["signer"]
        if kind == "this":
            return self.world.this
        if kind == "sig":
            return self.world.selector
        if kind == "len" and t[1][0] == "enc":
            return self._encoded_length(t[1])
        if kind == "len" and t[1][0] == "load":
            stored = self.eval(t[1])
            if isinstance(stored, bytes):
                return len(stored)
            where = self.storage_cell(t[1]) if isinstance(stored, int) and not isinstance(stored, bool) else None
            if where is not None and str(where[3]).endswith("[]"):
                return stored  # a dynamic storage array (copied to memory): its slot holds its length
            if stored == 0 and contains(t[1], IDENTITY_KINDS):
                return 0  # under a stranger's key: never written
            return UNK
        if kind == "len" and t[1][0] == "assumed":
            return 32  # what an arranged call returns: a standard success, one word (``true``)
        if kind in ("elem", "len", "calldatasize") and (t[1] == CALLDATA or kind == "calldatasize"):
            return self._own_data(t)
        if kind in _FREE_KINDS:
            return self.assignment.get(t, UNK) if _caller_chosen(t) else UNK
        if kind == "time":
            return self.world.chain.block_field(str(t[1]))
        if kind == "immutable":
            address = self.eval(t[1])
            if not isinstance(address, int) or isinstance(address, bool):
                return UNK
            if address == self.world.this and t[2] in self.world.values:
                return self.world.values[t[2]]
            return self.world.immutable(address, t[2])
        if kind == "constant":
            return self.world.values.get(t[1], UNK)
        if kind == "opaque" and str(t[1]).split("(")[0] in ("mulmod", "addmod") and len(t[2]) == 3:
            # Pure EVM arithmetic (OpenZeppelin's ``mulDiv`` reads ``mulmod``): exact once its inputs are known.
            a, b, m = (self.eval(x) for x in t[2])
            if all(isinstance(v, int) and not isinstance(v, bool) for v in (a, b, m)):
                if m == 0:
                    return 0
                return (a * b) % m if str(t[1]).startswith("mulmod") else (a + b) % m
            return UNK
        if kind in ("unknown", "opaque"):
            return UNK
        if kind == "assumed":
            return ASSUMED
        if kind == "retsize":
            return self._returned_size(t[1])
        if kind in ("codesize", "balance", "codehash", "code"):
            address = self.eval(t[1])
            if not isinstance(address, int) or isinstance(address, bool):
                return UNK
            if kind == "balance":
                return self.world.chain.balance(address % 2**160)
            code = self.world.chain.code(address % 2**160)
            if code is UNK:
                return UNK
            if kind == "codehash":
                return int.from_bytes(keccak(code), "big") if code else 0
            return len(code)
        if kind == "not":
            a = self._test(t[1])
            return a if a is UNK or a is REVERTED else not a
        if kind == "and":
            # A conjunct that reverts fails the conjunction; one guarded behind another (``a && f()``) was lowered
            # under that guard, so it can't revert where the code wouldn't have reached it.
            out: Any = True
            for item in cheapest_first(t):
                v = self._test(item)
                if v is False:
                    return False
                if v is REVERTED and out is not UNK:
                    out = REVERTED
                elif v is UNK:
                    out = UNK
            return out
        if kind == "or":
            out = False
            for item in cheapest_first(t):
                v = self._test(item)
                if v is True:
                    return True
                if v is REVERTED and out is not UNK:
                    out = REVERTED
                elif v is UNK:
                    out = UNK
            return out
        if kind == "ite":
            c = self._test(t[1])
            if c is REVERTED:
                return REVERTED
            if c is UNK:
                a, b = self.eval(t[2]), self.eval(t[3])
                return a if a == b and a is not UNK else UNK
            return self.eval(t[2] if c else t[3])
        if kind == "cmp" and t[1] == "eq":
            for side, other in ((t[2], t[3]), (t[3], t[2])):
                if _strip_conv(side)[0] == "origin" and self._coded(self.eval(other)):
                    return False  # a transaction's origin is an account with no code
        if kind == "cmp":
            value = self._compare(t[1], self.eval(t[2]), self.eval(t[3]))
            if value is UNK and t[1] == "eq":
                return self._owned(t)
            return value
        if kind == "load":
            return self._load(t)
        if kind == "rawload":
            keys = _identity_keys(t[2]) if contains(t[2], IDENTITY_KINDS) else None
            if keys is not None and (t[1], RAW_SLOT) in self.blind:
                return UNK
            if keys is not None and any(self.eval(k) in _STRANGERS for k in keys) and not self.world.overlay:
                return 0  # nothing was ever written under an address made up for the question
            address, slot = self.eval(t[1]), self.eval(t[2])
            if not isinstance(address, int) or not isinstance(slot, int):
                return UNK
            return self.word(address, slot)
        if kind == "hash":
            return self._hash(t)
        if kind == "call":
            return self._call(t, 0)
        if kind == "ok" and t[1][0] == "call" and not t[1][4]:
            # An action's return: assumed, unless the callee refuses this caller there (see ``_action``).
            return True if self._action(t[1]) is ASSUMED else UNK
        if kind in ("ok", "caught"):
            outcome = self._try_outcome(t[1], t[2])
            return UNK if outcome is UNK else outcome == ("returned" if kind == "ok" else "reverted")
        if kind == "item":
            inner = t[1]
            return self._call(inner, t[2]) if inner[0] == "call" else UNK
        if kind == "op":
            args = [self.eval(a) for a in t[2]]
            return REVERTED if any(a is REVERTED for a in args) else self._op(t[1], args)
        if kind == "slice":
            v = self.eval(t[1])
            if not isinstance(v, int):
                return v if v is REVERTED else UNK
            whole = (int(v) % 2**256).to_bytes(32, "big")
            return int.from_bytes(whole[t[2] : t[2] + t[3]], "big")
        if kind == "conv":
            v = self.eval(t[2])
            if isinstance(v, bool) or not isinstance(v, int):
                return v
            return converted(t[1], v)
        return UNK

    def _coded(self, value: Any) -> bool:
        """Whether ``value`` is this contract or an address with code (an EIP-7702 designator aside): never a
        transaction's origin."""
        if not isinstance(value, int) or isinstance(value, bool) or value in _STRANGERS:
            return False
        if value % 2**160 == self.world.this:
            return True
        code = self.world.chain.code(value % 2**160)
        # An account delegating by EIP-7702 holds only its designator (0xef0100 and an address) and still sends.
        return isinstance(code, bytes) and bool(code) and not (len(code) == 23 and code[:3] == b"\xef\x01\x00")

    def _compare(self, op: str, a: Any, b: Any) -> Any:
        for x, y in ((a, b), (b, a)):
            if isinstance(x, FreeHash) and op == "eq":
                if y == 0 or y is False:
                    return False  # no preimage hashes to zero
                if isinstance(y, int) and not isinstance(y, bool) and not x.identity and x.choosable:
                    return PREIMAGE
                return UNK
        if a is REVERTED or b is REVERTED:
            return REVERTED
        for x, y in ((a, b), (b, a)):
            if x is ASSUMED and op == "eq" and y in (0, 1) and not isinstance(y, FreeHash):
                return y == 1  # an arranged success is true: ``success == false`` doesn't hold
        if a is ASSUMED or b is ASSUMED or a is UNK or b is UNK or isinstance(a, FreeHash) or isinstance(b, FreeHash):
            return UNK
        if op == "eq" and isinstance(a, str) != isinstance(b, str):
            return UNK  # text against a number: a constant this reading couldn't place as either
        if op == "eq":
            return a == b
        if not isinstance(a, int) or not isinstance(b, int):
            return UNK
        return a < b if op == "lt" else a <= b

    def _owned(self, t: Term) -> Any:
        """``identity == m[k]`` with ``k`` unknown: false when the identity is the value at no key, and every write to
        ``m`` is logged."""
        for side, other in ((t[2], t[3]), (t[3], t[2])):
            if not _is_identity(side) or other[0] != "load":
                continue
            who, address = self.eval(side), self.eval(other[1])
            if who in _STRANGERS:
                # Nothing ever stored a made-up address, save its own earlier calls (``World.overlay``).
                return UNK if self.world.overlay else False
            if not isinstance(who, int) or not isinstance(address, int) or isinstance(address, bool):
                return UNK
            var, path = _named_lookup(other[2], other[3])
            keys = [step for kind, step in path if kind == "k"]
            fields = tuple(step for kind, step in path if kind == "f")
            if not self.world.complete(other[1], var, len(keys), fields):
                return UNK
            keys = self.world.inverse(address, var, fields, who)
            return UNK if keys is None or keys else False
        return UNK

    def _load(self, t: Term) -> Any:
        _, contract_term, name, path = t
        # Lookups are named either way: as read (a namespaced slot) or as their writers name them (``_roles``).
        unlisted = self.blind and (
            (contract_term, name) in self.blind or (contract_term, _named_lookup(name, path)[0]) in self.blind
        )
        if unlisted and (contains(t, IDENTITY_KINDS) or _chosen_keys(t)):
            return UNK  # an unlisted lookup, or entries whoever they name passes, at a key the caller picks
        keys = [step for kind, step in path if kind == "k"]
        hashed = [i for k in keys if k[0] == "hash" for i in (_identity_keys(k) or ())]
        stranger = any(self.eval(k) in _STRANGERS for k in keys) or any(self.eval(k) in _STRANGERS for k in hashed)
        where = self.storage_cell(t) if stranger and self.world.overlay else None
        if stranger and (where is None or (where[0], where[1]) not in self.world.overlay):
            # A stranger is an address made up for the question: nothing was ever written under it, however the key
            # comes to be it (``owner == 0 ? msg.sender : owner``), save by its own earlier calls.
            return 0
        where = where or self.storage_cell(t)
        if where is None:
            return UNK
        address, slot, offset, type_ = where
        word = self.word(address, slot)
        if word is UNK:
            return UNK
        if str(type_) in ("bytes", "string"):
            return self._stored_bytes(address, slot, word)
        return _decode_word(word, offset, type_)

    def _stored_bytes(self, address: int, slot: int, word: int) -> Any:
        """A ``bytes`` or ``string`` in storage: short ones in the slot itself (length doubled in the last byte),
        long ones in the slots from ``keccak256(slot)`` (the slot holding ``2 * length + 1``)."""
        if not word & 1:
            length = (word & 0xFF) // 2
            return word.to_bytes(32, "big")[:length] if length <= 31 else UNK
        length = (word - 1) // 2
        if length > _STORED_BYTES:
            return UNK
        base = int.from_bytes(keccak(slot.to_bytes(32, "big")), "big")
        words = [self.word(address, (base + i) % 2**256) for i in range(-(-length // 32))]
        if any(w is UNK or not isinstance(w, int) for w in words):
            return UNK
        return b"".join(w.to_bytes(32, "big") for w in words)[:length]

    def word(self, address: int, slot: int) -> Any:
        """The storage word at ``slot``: as the question's earlier calls left it, else as the chain has it."""
        if self.world.overlay and (address, slot) in self.world.overlay:
            return self.world.overlay[(address, slot)]
        return self.world.chain.storage(address, slot)

    def _callee(self, call: Term) -> tuple[Term, tuple] | None:
        """``world.callee`` at the address the target comes to under this question's arguments (a reserve's hub,
        picked by the reserve the caller names)."""
        address = self.eval(call[1])
        if isinstance(address, int) and not isinstance(address, bool):
            return self.world.callee(call, address % 2**160)
        return self.world.callee(call)

    def sender(self, call: Term) -> Any:
        """Who makes ``call``: this contract, or the callee whose own code makes it (``Lowerer._from_here``)."""
        if len(call) <= 5 or self.world.asker_free(call):
            return self.world.this
        who = self.eval(call[5])
        return who % 2**160 if isinstance(who, int) and not isinstance(who, bool) else UNK

    def _chain_call(self, call: Term, address: int, data: bytes, overrides: dict | None) -> Any:
        sender = self.sender(call)
        if sender is UNK:
            return UNK
        if overrides is None:
            return self.world.chain.call(address, data, sender)
        return self.world.chain.call(address, data, sender, overrides)

    def overrides(self) -> dict | None:
        """The overlay as state overrides for the node, per address; ``None`` without one. An overlay word that is
        unknown can't be handed over: ``False``."""
        if not self.world.overlay:
            return None
        out: dict[int, list] = {}
        for (address, slot), word in sorted(self.world.overlay.items()):
            if not isinstance(word, int) or isinstance(word, bool):
                return False
            out.setdefault(address, []).append((slot, word))
        return out

    def storage_cell(self, t: Term) -> tuple[int, int, int, Any] | None:
        """(address, slot, byte offset, type) a load reads, when every key is known."""
        _, contract_term, name, path = t
        address = self.eval(contract_term)
        if not isinstance(address, int) or isinstance(address, bool):
            return None
        contract = self.world.contracts.get(address)
        if contract is None:
            return None
        steps = []
        for kind, step in path:
            if kind == "k":
                v = self.eval(step)
                if v is UNK or isinstance(v, FreeHash) or v in (PREIMAGE, ASSUMED, REVERTED):
                    return None
                steps.append((kind, v))
            else:
                steps.append((kind, step))
        if isinstance(name, tuple) and name and name[0] == "slot":
            root = self.eval(name[1])
            if not isinstance(root, int) or isinstance(root, bool):
                return None
            name = ("slot", root, name[2])
        located = locate(contract, name, tuple(steps))
        if located is None:
            return None
        return (address, *located)

    def _hash(self, t: Term) -> Any:
        _, kind, inputs = t
        if any(contains(i, _FREE_KINDS | {"unknown", "opaque"}) for i in inputs):
            free = {s for kind in _FREE_KINDS for i in inputs for s in subterms(i, kind) if _caller_chosen(s)}
            choosable = (
                not any(contains(i, frozenset({"unknown", "opaque"})) for i in inputs)
                and free <= self.world.hashed_only
            )
            return FreeHash(identity=any(contains(i, IDENTITY_KINDS) for i in inputs), choosable=choosable)
        data = b""
        for item in inputs:
            chunk = self._encoded(item)
            if chunk is None:
                return FreeHash(identity=any(contains(i, IDENTITY_KINDS) for i in inputs))
            data += chunk
        if kind == "keccak256":
            return int.from_bytes(keccak(data), "big")
        import hashlib

        if kind == "sha256":
            return int.from_bytes(hashlib.sha256(data).digest(), "big")
        return FreeHash(identity=False)

    def _encoded_length(self, enc: Term) -> Any:
        """Bytes ``abi.encode``/``abi.encodePacked`` of these arguments takes: fixed by the static types, plus each
        dynamic argument's length."""
        total = 0
        for arg in enc[2]:
            type_ = arg[2] if arg[0] in ("arg", "const") else None
            if isinstance(type_, str) and (type_ in ("bytes", "string") or type_.endswith("[]")):
                length = (
                    self.eval(mk("len", arg)) if arg[0] == "arg" else (len(arg[1]) if isinstance(arg[1], str) else UNK)
                )
                if not isinstance(length, int) or isinstance(length, bool):
                    return UNK
                total += length if enc[1] == "abi.encodePacked" else 64 + -(-length // 32) * 32
            elif enc[1] == "abi.encodePacked":
                width = packed_width(arg)
                if width is None:
                    return UNK
                total += width
            elif packed_width(arg) is None:
                return UNK  # a value whose type isn't known: not known to be one word
            else:
                total += 32
        return total

    def _encoded(self, item: Term) -> bytes | None:
        if item[0] == "const" and isinstance(item[1], str):
            return item[1].encode()
        if item[0] == "enc":
            kind, args = item[1], list(item[2])
            words = []
            if kind in ("abi.encodeWithSelector", "abi.encodeWithSignature"):
                # Four selector bytes, then the arguments as ``abi.encode`` lays them out.
                head = args.pop(0) if args else None
                if head is None or head[0] != "const":
                    return None
                if kind == "abi.encodeWithSignature":
                    if not isinstance(head[1], str):
                        return None
                    words.append(keccak(text=head[1])[:4])
                else:
                    selector = self.eval(head)
                    if isinstance(selector, str):
                        selector = int(selector, 0) if selector[:2] in ("0x", "0X") else int(selector)
                    if not isinstance(selector, int) or isinstance(selector, bool):
                        return None
                    words.append((selector % 2**32).to_bytes(4, "big"))
            elif kind not in ("abi.encode", "abi.encodePacked"):
                return None  # an encoding not laid out here (``abi.encodeCall`` left unresolved)
            for arg in args:
                if kind == "abi.encodePacked" and arg[0] == "const" and isinstance(arg[1], str):
                    words.append(arg[1].encode())  # a string packs as its bytes (Aragon's ``"PERMISSION"`` tag)
                    continue
                v = self.eval(arg)
                if isinstance(v, bool):
                    v = int(v)
                if not isinstance(v, int):
                    return None
                width = packed_width(arg)
                fixed = _fixed_bytes_type(arg)
                if width is None:
                    return None  # a value of unknown or dynamic type: its word, or words, aren't known
                if kind == "abi.encodePacked":
                    words.append((v % 2 ** (8 * width)).to_bytes(width, "big"))
                elif fixed is not None:
                    # A ``bytesN`` sits at the left of its word; its value here is right-aligned in N bytes.
                    words.append((v % 2 ** (8 * fixed)).to_bytes(fixed, "big").ljust(32, b"\0"))
                else:
                    words.append((v % 2**256).to_bytes(32, "big"))
            return b"".join(words)
        v = self.eval(item)
        if isinstance(v, int) and not isinstance(v, bool):
            return (v % 2**256).to_bytes(32, "big")
        return None

    def _action(self, t: Term) -> Any:
        """A state-changing call: an action the caller arranges (a transfer, a deposit), unless it is handed the
        caller. Then its callee's code, over these arguments, decides: refusing this caller for entries the caller
        can't bring about there (a supply controller list only an admin fills), whether it passes is unknown, never
        assumed; letting it through, the pass rests on that code (marked, and unknown with no callee code answering,
        where a decision rests on it). A callee not followed leaves it unknown: only every stranger's own call, run
        on the chain, shows it passes (``decide``)."""
        if not any(contains(a, IDENTITY_KINDS) for a in t[3]):
            self.world.rests_on.add("assumed")  # assumed: whatever it needs, the caller arranges first
            return ASSUMED
        if self.eval(t[1]) is UNK:
            return UNK  # handed the caller by a contract whose address went unread: whose check it is is unknown
        lowered = self._callee(t)
        if lowered is None:
            return UNK
        refused = self.truth(lowered[0])
        if refused is UNK:
            # Unsettled there (a read failed, business logic): what involves who calls decides, the rest left free.
            loosened = relaxed_atoms(lowered[0])
            refused = self.nested(loosened).truth(lowered[0])
            if refused is UNK:
                return UNK
        if refused is not False:
            if not self.callee_code:
                return UNK
            self.coded[0] = True
            return ASSUMED
        # Refused there only on entries the caller can bring about (a balance, an allowance) is no pass but what the
        # caller must hold (``requires``), asked as it stands with or without callee code answering.
        opened = self.world.action_open(t, lowered[0])
        if opened is not False:
            self.world.rests_on.add("action")  # a pass on entries the caller brings about first
        if isinstance(opened, frozenset):
            # Some of the entries it reads the caller can bring about, not all (a balance, not a blacklist): an action
            # the caller arranges if those alone, set as needed, let it through, the rest as they stand.
            values = tuple(self.eval(a) for a in t[3])
            memo = self.world.__dict__.setdefault("_brought", {})
            fixed = frozenset((k, v) for k, v in self.assignment.items() if k[0] != "arg")
            overlay = tuple(sorted(self.world.overlay.items())) if self.world.overlay else ()
            key = (
                t,
                values,
                tuple(sorted(self.identity.items())),
                frozenset(self.when),
                fixed,
                overlay,
                self.code_first,
            )
            if key not in memo:
                free = frozenset(a for a in _atoms_of(lowered[0]) if any(contains_term(a, load) for load in opened))
                loosened = self.nested(free)
                if not free or loosened.truth(lowered[0]) is False:
                    memo[key] = UNK
                else:
                    memo[key] = ASSUMED if isinstance(solve(lowered[0], loosened), dict) else UNK
            return memo[key]
        return ASSUMED if opened else UNK

    def _call(self, t: Term, index: int) -> Any:
        _, target, signature, args, view = t[:5]
        if (target, signature) in self.blind and any(contains(a, IDENTITY_KINDS) for a in args):
            address = self.eval(target) if view else UNK
            if isinstance(address, int) and self.world.chain.code(address) == b"":
                return REVERTED  # whatever it would answer, a call into no code reverts this contract
            return UNK
        if not view:
            acted = self._action(t)
            if acted is not ASSUMED:
                return acted
            # Taken to succeed: what it returns is what its own code returns when it does (Aave's ``hub.add``
            # returning the shares a ``SafeCast`` then bounds), when that can be worked out.
            lowered = self._callee(t) if self.callee_code else None
            if lowered is not None and index < len(lowered[1]):
                value = self.eval(lowered[1][index])
                if isinstance(value, (int, bool)) and value not in (REVERTED,):
                    self.coded[0] = True
                    return value
            return ASSUMED
        request = self.call_input(t)
        if request is not None and self._guessed(t):
            # Over arguments the caller picks, each guess would be a call of its own: the callee's own code, where it
            # is followed and settles the answer, then the chain. A pass resting on it is asked again of the chain.
            lowered = self._callee(t)
            if lowered is not None and index < len(lowered[1]):
                returned = self.truth(lowered[0])
                if returned is False:
                    self.coded[0] = True
                    return REVERTED
                value = self.eval(lowered[1][index]) if returned is True else UNK
                if isinstance(value, (int, bool)) and not isinstance(value, FreeHash):
                    self.coded[0] = True
                    return value
        if request is None:
            # Not every argument is known: answer with the callee's own code, lowered over these arguments.
            lowered = self._callee(t) if self.callee_code else None
            if lowered is None or index >= len(lowered[1]):
                return UNK
            self.coded[0] = True
            if self.truth(lowered[0]) is False:
                return REVERTED
            return self.eval(lowered[1][index])
        address, data = request
        overrides = self.overrides()
        if overrides is False:
            return UNK
        raw = self._chain_call(t, address, data, overrides)
        if raw is REVERTED or raw is UNK:
            return raw
        if not raw and self.world.chain.code(address) == b"":
            return REVERTED  # a high-level call into an address with no code reverts this contract
        if len(raw) < 32 * (index + 1):
            return UNK
        return int.from_bytes(raw[32 * index : 32 * (index + 1)], "big")

    def _guessed(self, call: Term) -> bool:
        """Whether a view call's input depends on arguments the caller picks, and its callee's code answers first."""
        return self.code_first and any(contains(a, _FREE_KINDS) for a in call[3])

    def _returned_size(self, call: Term) -> Any:
        """Bytes of return data ``call`` leaves when it returns: a view call's as the chain answers, an action's as
        its callee's function declares (USDT's ``transferFrom``, returning nothing; ``World.declared_size``), never as
        its lowered code returns."""
        if call[0] != "call":
            return UNK  # the call inlined as what its callee returns: how many bytes came back goes unread
        if call[4]:
            request = self.call_input(call)
            overrides = self.overrides()
            if request is None or overrides is False:
                return UNK
            raw = self._chain_call(call, request[0], request[1], overrides)
            return len(raw) if isinstance(raw, bytes) else UNK
        address = self.eval(call[1])
        if not isinstance(address, int) or isinstance(address, bool):
            return UNK
        size = self.world.declared_size(call, address % 2**160)
        return UNK if size is None else size

    def _try_outcome(self, call: Term, returns: int | None) -> Any:
        """How a ``try`` on ``call`` ends: ``returned``, ``reverted`` (in the callee: a catch clause runs), or
        ``failed`` (in this contract: no code at the target, which no clause catches); UNK when unknown."""
        if call[0] != "call" or not call[4]:
            return UNK  # an action: whether it reverts depends on what the callee does with state
        if (call[1], call[2]) in self.blind and any(contains(a, IDENTITY_KINDS) for a in call[3]):
            address = self.eval(call[1])
            return "failed" if isinstance(address, int) and self.world.chain.code(address) == b"" else UNK
        request = self.call_input(call)
        if request is not None and self._guessed(call):
            lowered = self._callee(call)
            returned = self.truth(lowered[0]) if lowered is not None else UNK
            if returned is not UNK:
                self.coded[0] = True
                return "returned" if returned else "reverted"
        if request is None:
            lowered = self._callee(call) if self.callee_code else None
            if lowered is None:
                return UNK
            self.coded[0] = True
            returned = self.truth(lowered[0])
            return UNK if returned is UNK else ("returned" if returned else "reverted")
        overrides = self.overrides()
        if overrides is False:
            return UNK
        raw = self._chain_call(call, request[0], request[1], overrides)
        if raw is UNK:
            return UNK
        if raw is REVERTED:
            return "reverted"
        if not raw:
            # Empty return data: from an address with no code, a high-level call refuses it here (an extcodesize
            # check, or decoding nothing); from code, fine when nothing was expected.
            code = self.world.chain.code(request[0])
            return "failed" if code == b"" else ("returned" if returns == 0 else UNK)
        return "returned"

    def _array_words(self, array: Term) -> list[int] | Any:
        """A memory array this call made: its items' values, zeros when none were written."""
        if len(array) == 3:
            words = [self.eval(item) for item in array[2]]
            if any(isinstance(w, bool) or not isinstance(w, int) for w in words):
                return UNK
            return [w % 2**256 for w in words]
        length = self.eval(array[1])
        if isinstance(length, bool) or not isinstance(length, int) or not 0 <= length <= 1024:
            return UNK
        return [0] * length

    def _bytes_of(self, array: Term) -> Any:
        """A memory array reaching a ``bytes`` parameter, which only an in-place cast (assembly rewriting its length,
        Aragon's ``dangerouslyCastUintArrayToBytes``) allows: its words as bytes."""
        words = self._array_words(array)
        return UNK if words is UNK else b"".join(w.to_bytes(32, "big") for w in words)

    def _calldata(self) -> bytes | Any:
        """This call's own ``msg.data``: the selector, then its arguments as chosen, ABI-encoded."""
        types = [p[2] for p in self.world.parameters]
        values = [self._argument(p, t) for p, t in zip(self.world.parameters, types)]
        if any(v is UNK or not isinstance(v, (int, bool, bytes, list)) for v in values):
            return UNK
        try:
            body = encode(types, [_abi_value(v, t) for v, t in zip(values, types)])
        except Exception as exc:  # a type eth_abi can't encode (a struct); never the decision's own timeout
            if isinstance(exc, TimeoutError):
                raise
            return UNK
        return self.world.selector.to_bytes(4, "big") + body

    def _own_data(self, t: Term) -> Any:
        """A word of this call's own ``msg.data``, or its size. Inside the encoding of the arguments a word is what the
        guessed arguments put there; past it, bytes the caller may append (ABI decoding ignores them), guessed like
        an argument. The size is guessed too, never below what the arguments take."""
        data = self._calldata()
        guess = self.assignment.get(t, UNK)
        if t[0] != "elem":
            if not isinstance(data, bytes) or not isinstance(guess, int) or isinstance(guess, bool):
                return UNK
            return guess if guess >= len(data) else UNK
        offset = self.eval(t[2])
        if not isinstance(offset, int) or isinstance(offset, bool) or not isinstance(data, bytes):
            return UNK
        if offset + 32 <= len(data):
            return int.from_bytes(data[offset : offset + 32], "big")
        if offset >= _MAX_CALLDATA:
            return 0  # past any data a transaction can carry: the zeros reading past the end gives
        return guess if offset >= len(data) else UNK

    def _argument(self, a: Term, type_: str) -> Any:
        if a == CALLDATA and type_ == "bytes":
            return self._calldata()
        if a[0] == "const" and isinstance(a[1], str) and type_.startswith("bytes") and type_[5:].isdigit():
            raw = a[1].encode()  # a string literal for a ``bytesN`` (Maple's ``"P:deposit"``): left-aligned
            return int.from_bytes(raw.ljust(int(type_[5:]), b"\0"), "big") if len(raw) <= int(type_[5:]) else UNK
        if a[0] == "array" and type_ == "bytes":
            return self._bytes_of(a)
        if a[0] == "enc" and type_ == "bytes":
            # ``abi.encode(assets, receiver)`` handed on as ``bytes``: its bytes, where every item is a known static
            # value (``_encoded``), so the call is the chain's to answer.
            data = self._encoded(a)
            return data if data is not None else UNK
        if a[0] == "array" and type_.endswith("[]") and type_[:-2] in ("uint256", "bytes32", "address"):
            words = self._array_words(a)
            return UNK if words is UNK else words
        return self.eval(a)

    def call_input(self, t: Term) -> tuple[int, bytes] | None:
        """(target, calldata) of a view call whose target and arguments are all known."""
        _, target, signature, args, _ = t[:5]
        address = self.eval(target)
        types = signature[signature.index("(") + 1 : -1].split(",") if "()" not in signature else []
        if len(types) != len(args):
            return None
        values = [self._argument(a, ty) for a, ty in zip(args, types)]
        if not isinstance(address, int) or any(v is UNK or not isinstance(v, (int, bool, bytes, list)) for v in values):
            return None
        try:
            return address, keccak(text=signature)[:4] + encode(
                types, [_abi_value(v, ty) for v, ty in zip(values, types)]
            )
        except Exception as exc:  # eth_abi's encoding errors; never the decision's own timeout
            if isinstance(exc, TimeoutError):
                raise
            return None

    @staticmethod
    def _op(name: str, args: list[Any]) -> Any:
        if name == "fits":
            # Checked arithmetic's range: the operation computed exactly, within its type.
            if len(args) == 5 and all(isinstance(a, int) and not isinstance(a, bool) for a in args[1:3]):
                return fits(str(args[0]), int(args[1]), int(args[2]), int(args[3]), bool(args[4]))
            return UNK
        if name in ("and", "or") and any(a is ASSUMED for a in args):
            # An assembly call's success the caller arranges is the word 1: ``and(success, ok)``.
            args = [1 if a is ASSUMED else a for a in args]
        if any(not isinstance(a, int) for a in args):
            return UNK
        a = [int(x) for x in args]
        try:
            return {
                "add": lambda: (a[0] + a[1]) % 2**256,
                "sub": lambda: (a[0] - a[1]) % 2**256,
                "mul": lambda: (a[0] * a[1]) % 2**256,
                "div": lambda: a[0] // a[1] if a[1] else 0,
                "mod": lambda: a[0] % a[1] if a[1] else 0,
                "and": lambda: a[0] & a[1],
                "or": lambda: a[0] | a[1],
                "xor": lambda: a[0] ^ a[1],
                "shl": lambda: (a[0] << a[1]) % 2**256 if a[1] < 256 else 0,
                "shr": lambda: a[0] >> a[1] if a[1] < 256 else 0,
                "pow": lambda: pow(a[0], a[1], 2**256),
                "bnot": lambda: 2**256 - 1 - a[0],
                "sdiv": lambda: _EXACT["sdiv"](a[0], a[1]),
                "smod": lambda: _EXACT["smod"](a[0], a[1]),
                "sar": lambda: _EXACT["sar"](a[0], a[1]),
                "byte": lambda: _EXACT["byte"](a[0], a[1]),
                "signextend": lambda: _EXACT["signextend"](a[0], a[1]),
                "clz": lambda: 256 - (a[0] % 2**256).bit_length(),
            }[name]()
        except (KeyError, IndexError):
            return UNK


def _fixed_bytes_type(term: Term) -> int | None:
    """N when ``term`` is typed ``bytesN`` (N < 32): a value the ABI left-aligns in its word."""
    type_ = (
        term[2]
        if term[0] in ("const", "arg")
        else term[1]
        if term[0] == "conv"
        else "bytes4"
        if term[0] == "sig"
        else None
    )
    found = re.fullmatch(r"bytes(\d+)", type_) if isinstance(type_, str) else None
    return int(found.group(1)) if found and int(found.group(1)) < 32 else None


def conversion_width(type_: str) -> tuple[int, bool] | None:
    """(bits, signed) a conversion to ``type_`` keeps: an integer type's width, an address's 160 bits, a ``bytesN``'s
    ``8N`` (its value right-aligned); ``None`` for a type whose values pass through (a contract, an enum, a value type
    alias)."""
    found = re.fullmatch(r"(u?)int(\d*)", type_)
    if found:
        return int(found.group(2) or 256), found.group(1) == ""
    if type_ in ("address", "address payable"):
        return 160, False
    found = re.fullmatch(r"bytes(\d+)", type_)
    if found and 1 <= int(found.group(1)) <= 32:
        return 8 * int(found.group(1)), False
    return None


def converted(type_: str, value: int) -> int:
    """``value`` converted to the integer-like ``type_``: kept to its width, read as signed for a signed type."""
    width = conversion_width(type_)
    if width is None:
        return value
    bits, is_signed = width
    return signed(value, bits) if is_signed else value % 2**bits


def _abi_value(value: Any, type_: str) -> Any:
    if isinstance(value, bytes):
        return value.decode("latin-1") if type_ == "string" else value
    if isinstance(value, list):
        return [_abi_value(v, type_[:-2]) for v in value]
    if type_ == "bool":
        return bool(value)
    if type_.startswith("address"):
        return "0x" + format(int(value) % 2**160, "040x")
    if type_.startswith("bytes") and type_ != "bytes":
        return (int(value) % 2 ** (8 * int(type_[5:]))).to_bytes(int(type_[5:]), "big")
    if type_.startswith("int") and type_[3:].isdigit() or type_ == "int":
        bits = int(type_[3:] or 256)
        signed = int(value) % 2**bits  # a negative value as its two's complement word, or as itself
        return signed - 2**bits if signed >= 2 ** (bits - 1) else signed
    return int(value)


# Decision -------------------------------------------------------------------------------------------------------------


@dataclass
class Verdict:
    openness: str  # open | restricted | not_determined
    principals: frozenset[int]  # callers shown to pass, exactly
    complete: bool  # the principals and signers are everyone who passes
    undecided: frozenset[int] = frozenset()
    signers: frozenset[int] = frozenset()  # identities whose signature lets any caller through
    # Arguments (by name) that let each principal through, and an unconfigured address (``FRESH``) when open.
    witnesses: dict[int, dict[str, Any]] = field(default_factory=dict)
    # Why the list isn't complete or the answer isn't settled: unlisted lookups, cut history, undecided candidates.
    gaps: tuple[str, ...] = ()
    # What a caller must hold rather than be, where it rests on that: (contract, the call or lookup read, the least
    # amount needed: ``"any"`` for some, ``"chosen"`` for what the caller's own arguments ask, else a number).
    requires: tuple[tuple[int | None, str, Any], ...] = ()
    # For an open function: ``now`` when a stranger's call goes through as the chain stands, ``later`` when only once
    # its conditions allow (unpaused, a vote passed and waiting, a hash scheduled and its timelock run out);
    # ``conditional`` (``later_conditional``) when that holds only with conditions every caller faces alike set
    # aside, unsettled (``decide``'s second pass), until a stranger's call is run and goes through.
    allowed: str = "now"
    # Calls a stranger makes first for an open function to let it through: (signature, arguments) each.
    after: tuple[tuple[str, dict], ...] = ()
    # For an open function: ``True`` when the open rests on samples, what five strangers' calls showed on the chain or
    # the formula evaluated at those five addresses where its form doesn't make every unconfigured address alike
    # (``uint160(msg.sender) % 10 != 0`` lets nine in ten through), never on a proof that any unconfigured address
    # passes; ``False`` for an open proved for every one (``decide._alike_for_strangers``). Reported as
    # ``open_witnessed`` (``report.openness_label``); always ``False`` for a verdict that isn't "open".
    witnessed: bool = False
    # Callers singled out by who they are, kept apart from ``principals``: their call was shown to pass only with
    # some conditions freed, by what was freed: ``business`` (every condition not about who calls), ``arguments``
    # (what the arguments decide), ``holdings`` (and the amounts in their own entries). A complete list is these
    # and the principals together.
    conditions: dict[int, str] = field(default_factory=dict)
    # Whose positions its effects touch (``scope.py``): ``self`` when every write stays in entries the caller holds,
    # ``none`` when it writes nothing, else ``shared``; with each write's class and where (``("own", "balances")``).
    scope: str = "shared"
    scope_writes: tuple[tuple[str, str], ...] = ()
    # For a self-scoped function, whose holders aren't tested one by one: what a caller must satisfy, as read, and
    # how many the builder's list names when it is shown whole (``None`` otherwise).
    gate: tuple[str, ...] = ()
    members: int | None = None
    # The success condition split by who calls (``taint.py``): what depends on the caller (``core``), as read, and
    # what holds for every caller alike, as (level, reading): ``business`` for such a conjunct, with each unknown in
    # it by its label (``unknown:<label>``). ``conditions`` says which holders passed only with them freed.
    core: tuple[str, ...] = ()
    condition_terms: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        # Several parts can name the same reason (one callee asked three times): each once, in order.
        self.gaps = tuple(dict.fromkeys(self.gaps))
        if self.openness != "open":
            self.witnessed = False
        if self.openness == "not_determined" and not self.gaps:
            if os.environ.get("PSAT_LOGIC_STRICT_GAPS") == "1":
                raise ValueError("a not_determined verdict must say why")
            self.gaps = ("unexplained",)


def decide(formula: Term, world: World, coverage: Coverage) -> Verdict:
    """``_decide``, with the formula's core and the conditions every caller faces alike reported beside it.

    Who may call is decided on the core: a conjunct no caller's identity reaches is the same for everyone, so where
    the engine can't settle it (an unknown, a callee whose code isn't followed), it is a condition on the call rather
    than a reason not to say who. Such conjuncts are dropped only when the whole formula left the answer open, and
    only those that read unknown for what the lowering couldn't express: one false now (a pause) stays and decides
    as before, and one a failed read or the budget left open keeps blocking."""
    failed = world.chain.failed if world.failed_at is None else world.failed_at
    refuted, passed = world.code_refuted, world.code_passed
    verdict = _state_blocked(formula, world, coverage, _decide(formula, world, coverage))
    core, free = split(formula)
    if verdict.openness == "not_determined":
        opaque = _opaque_conditions(free, world, failed)
        if opaque:
            verdict = _on_conditions(formula, world, coverage, opaque) or verdict
    shown = verdict.openness == "open" and verdict.allowed == "conditional"
    if shown or (
        verdict.openness == "not_determined"
        and (
            world.code_passed > passed
            or any(subterms(c, "unknown") or subterms(c, "opaque") or _handed_actions(c) for c in core)
        )
    ):
        # What the lowering couldn't express, a pass only a callee's code showed, or an action handed the caller
        # (its callee unfollowed, or its code only proposing), keeps the stranger undecided, or open only on
        # conditions: its call, run once on the chain, settles it when every stranger's goes through. One that fails
        # proves nothing (other arguments, another state) and changes nothing.
        found = _executes(formula, world, FRESH, set(), tries=1)
        if found is not None and strangers_run(formula, world, found, tries=1):
            world.sampled = True
            verdict = Verdict("open", frozenset(), True, witnesses={FRESH: found})
        elif found is not None and verdict.openness == "not_determined":
            verdict = replace(verdict, gaps=(*verdict.gaps, "strangers_differ"))
    if verdict.openness == "not_determined" and free:
        # What only the conditions leave open is theirs to report, not a reason the answer is open; a failed read and
        # a callee not followed (never set aside as a condition) always are.
        probe = Evaluator(world, {"caller": FRESH, "signer": FRESH})
        theirs = {r for c in free for r in _open_parts(c, probe)} - {r for c in core for r in _open_parts(c, probe)}
        kept = tuple(g for g in verdict.gaps if g not in theirs or g.startswith(("read_failed:", "unfollowed:")))
        verdict = replace(verdict, gaps=kept or verdict.gaps)
    if verdict.openness == "not_determined":
        tainted_unknowns = [u for c in core for u in subterms(c, "unknown") if not singles_out_nobody(u)]
        tainted_unknowns += [o for c in core for o in subterms(c, "opaque") if contains(o, IDENTITY_KINDS)]
        verdict = replace(verdict, gaps=verdict.gaps + tuple(unknown_gap(u[1]) for u in tainted_unknowns))
    if world.code_refuted > refuted and not verdict.complete and "callee_code_refutation" not in verdict.gaps:
        # A failure only a followed callee's code showed, unknown without it (``Evaluator.truth``, ``solve``).
        verdict = replace(verdict, gaps=verdict.gaps + ("callee_code_refutation",))
    if world.code_passed > passed and not verdict.complete and "callee_code_pass" not in verdict.gaps:
        # A pass only a followed callee's code showed, unknown without it.
        verdict = replace(verdict, gaps=verdict.gaps + ("callee_code_pass",))
    if world.__dict__.get("confirm_spent") and not verdict.complete:
        verdict = replace(verdict, gaps=verdict.gaps + ("budget:confirm",))
    verdict = _confirmed_open(formula, world, verdict)
    if verdict.openness == "open":
        # Proved only where nothing sampled it: no stranger's run settled it, no assumption or arrangement it rests on,
        # no call of its own first, and a formula whose form makes every unconfigured address meet it as ``FRESH`` did.
        witnessed = (
            world.sampled or bool(world.rests_on) or bool(verdict.after) or not _alike_for_strangers(formula, world)
        )
        verdict = replace(verdict, witnessed=witnessed)
    chosen = tuple(("arguments", name) for name in _quantified(core))
    return replace(verdict, core=_readings(core), condition_terms=_business(free) + chosen)


def _confirmed_open(formula: Term, world: World, verdict: Verdict) -> Verdict:
    """``verdict``, unless it is "open now" with nothing to hold first (no ``requires``) and the chain doesn't confirm
    it: every stranger's own call must go through as the chain stands (``runs`` with the witness, else a search of its
    own, then ``strangers_run``), with the ether its witness sends (its balance set to that by a state override).
    Where the open rests on calls of the stranger's own first (``after``), each stranger's first call must go through
    as the chain stands and then this one on the words that call leaves, handed to the node as state overrides; where
    it rests on an action handed the caller that refuses only on entries the caller brings about there, the calls
    that bring them about must go through as each stranger, and this one with those entries set by state overrides.
    Otherwise whatever the lowering said, a callee's code or a mis-lowered construct of the contract's own, is not
    determined: ``open_value_unconfirmed`` (ether sent), ``open_arranged_unconfirmed`` (the stranger's own entries
    arranged first), ``open_assumed_action_unconfirmed`` (an action assumed or handed the caller), else
    ``open_unconfirmed``; the proposal stays, as data."""
    rests_on, brought = world.rests_on, world.brought
    prior_runs = world.__dict__.pop("_prior_runs", None)
    if verdict.openness != "open" or verdict.allowed != "now" or verdict.requires:
        return verdict
    witness = verdict.witnesses.get(FRESH, {})
    if verdict.after:
        if prior_runs is not None and _after_runs(world, witness, *prior_runs):
            world.sampled = True
            return verdict
        gap = "open_arranged_unconfirmed"
    else:
        if runs(world, FRESH, witness) is True:
            if strangers_run(formula, world, witness):
                return verdict
        elif not witness.get("msg.value"):
            found = _executes(formula, world, FRESH, set(), tries=2)
            if found is not None and strangers_run(formula, world, found):
                world.sampled = True
                return replace(verdict, witnesses={**verdict.witnesses, FRESH: found})
        if "action" in rests_on and brought and _brought_runs(world, witness, brought):
            world.sampled = True
            return verdict
        if "action" in rests_on and any(c in world.requirements for c in subterms(formula, "call")):
            # An action taking what the caller holds (``transferFrom(msg.sender, ...)`` of a balance holders move to
            # anyone), no stranger holding it: open to whoever holds it, which ``requires`` names.
            requires = _requirements(formula, world)
            if requires and all(isinstance(need, str) and need != "unknown" for _, _, need in requires):
                return replace(verdict, requires=requires)
        gap = (
            "open_value_unconfirmed"
            if witness.get("msg.value")
            else "open_arranged_unconfirmed"
            if "arranged" in rests_on
            else "open_assumed_action_unconfirmed"
            if rests_on & {"assumed", "action"}
            else "open_unconfirmed"
        )
    return replace(verdict, openness="not_determined", complete=False, gaps=(gap,))


def _overrides(words: dict) -> dict | None:
    """Storage words, (address, slot) -> word, as state overrides per address; ``None`` where one is unknown."""
    out: dict[int, list] = {}
    for (address, slot), word in sorted(words.items()):
        if not isinstance(word, int) or isinstance(word, bool):
            return None
        out.setdefault(address, []).append((slot, word))
    return out


def _after_runs(world: World, witness: dict[str, Any], first: bytes | None, made_by: dict[int, dict]) -> bool:
    """Whether, for each stranger, its first call (``first``) goes through as the chain stands, and this call with
    ``witness`` then goes through on the words that call leaves (``made_by``), handed to the node as overrides."""
    if first is None:
        return False
    for who in (FRESH, *_OTHER_STRANGERS):
        words = made_by.get(who)
        overrides = _overrides(words) if words is not None else None
        if overrides is None or not isinstance(world.chain.call(world.this, first, who), bytes):
            return False
        own = {k: who if v == FRESH else v for k, v in witness.items()}
        if runs(world, who, own, overrides) is not True:
            return False
    return True


def _brought_runs(world: World, witness: dict[str, Any], brought: list) -> bool:
    """Whether, for each stranger, every call that brings its entries about in an action's callee (``brought``: each
    action's call, and (target, the entries, the calls that bring them about)) goes through as the chain stands, and
    this call with ``witness`` then goes through on the words those calls leave there (worked out from their lowering,
    ``verdict.writer_words``), handed to the node as state overrides."""
    from .verdict import call_data, writer_words

    if any(makers is None for _, (_, _, makers) in brought):
        return False
    for who in (FRESH, *_OTHER_STRANGERS):
        words: dict = {}
        for _, (target, _entries, makers) in brought:
            for function, arguments in makers:
                own = {k: who if v == FRESH else v for k, v in arguments.items()}
                data = call_data(function, own)
                if data is None or not isinstance(world.chain.call(target, data, who), bytes):
                    return False
                made = writer_words(world, target, function, own, who)
                if made is None:
                    return False
                words.update(made)
        overrides = _overrides(words)
        own = {k: who if v == FRESH else v for k, v in witness.items()}
        if not overrides or runs(world, who, own, overrides) is not True:
            return False
    return True


def _handed_actions(t: Term) -> list[Term]:
    """The state-changing calls in ``t`` handed the caller's identity."""
    return [c for c in subterms(t, "call") if not c[4] and any(contains(a, IDENTITY_KINDS) for a in c[3])]


def _quantified(core: tuple[Term, ...]) -> list[str]:
    """Arguments the caller picks that key an identity lookup (``ops[id].manager == msg.sender``,
    ``approved[id][msg.sender]``): who may call is whoever is stored there for some value of them, a condition on
    the arguments rather than on who calls."""
    out: list[str] = []
    for atom in sorted({a for c in core for a in _identity_atoms(c)}, key=stable):
        loads = [x for x in subterms(atom, "load") if contains(x, IDENTITY_KINDS)]
        if atom[0] == "cmp" and atom[1] == "eq":
            loads += [
                _strip_conv(other)
                for side, other in ((atom[2], atom[3]), (atom[3], atom[2]))
                if _is_identity(side) and _strip_conv(other)[0] == "load" and not contains(other, IDENTITY_KINDS)
            ]
        for load in loads:
            out += [k[1] for k in _chosen_steps(_named_lookup(load[2], load[3])[1]) if k[0] == "arg"]
    return list(dict.fromkeys(out))


def _opaque_conditions(free: tuple[Term, ...], world: World, failed: int) -> list[Term]:
    """The conjuncts every caller faces alike that read unknown now only for what the lowering couldn't express,
    here or in a callee followed into: none once any read of the decision failed (``failed``: the chain's count when
    it began) or the work or the reads ran out, where the whole formula's answer stands. A callee not followed is
    never one: its code may read ``tx.origin``, which every callee sees as the caller's."""
    chain = world.chain
    if world.exhausted() or chain.failed > failed or (chain.limit is not None and chain.sent >= chain.limit):
        return []
    probe = Evaluator(world, {"caller": FRESH, "signer": FRESH})
    out = []
    for part in free:
        if probe.truth(part) is not UNK:
            continue
        reasons = _open_parts(part, probe)
        if reasons and all(r.startswith("unknown:") for r in reasons):
            out.append(part)
    return out


def _on_conditions(formula: Term, world: World, coverage: Coverage, opaque: list[Term]) -> Verdict | None:
    """The verdict on ``formula`` without the ``opaque`` conjuncts, as holding only on them: ``allowed`` reads
    ``conditional``, the list is never complete, and a gap names each condition dropped (``conditional:<why>``).
    Whoever it lists is shown to pass with those conditions freed (``conditions``), and an open answer names no
    witness, since no call was shown to go through. ``None`` when that too is left open."""
    reduced = mk_and([c for c in conjuncts(formula) if c not in opaque])
    effective = world.effective
    if effective is not None:
        world.effective = replace_terms(effective, {c: TRUE for c in opaque})
    try:
        again = _decide(reduced, world, world.cover(reduced) if world.cover is not None else coverage)
    finally:
        world.effective = effective
    if again.openness == "not_determined":
        return None
    shown = again.principals | again.signers | set(again.conditions)
    freed = {who: again.conditions.get(who, "business") for who in shown}
    probe = Evaluator(world, {"caller": FRESH, "signer": FRESH})
    dropped = tuple(f"conditional:{r}" for c in opaque for r in _open_parts(c, probe))
    return replace(
        again,
        principals=frozenset(),
        signers=frozenset(),
        conditions=freed,
        witnesses={} if again.openness == "open" else again.witnesses,
        complete=False,
        allowed="conditional" if again.allowed == "now" else f"{again.allowed}_conditional",
        gaps=again.gaps + dropped,
    )


# What reads state a transaction may change, besides storage: another contract's answer, ether, code, the clock.
_CHANGING_READS = ("call", "balance", "code", "codesize", "codehash", "time")


def _changing_reads(t: Term, world: World) -> list[str]:
    """What in ``t`` reads state a transaction may yet change, each by name (a storage variable, a call's signature,
    ``balance``, ``time``, ...); nothing for what is provably constant: constants, immutables, ``this``, and a slot of
    this contract no entry point can leave holding anything else from here (``World.constant_load``)."""
    out = []
    for kind in ("load", "rawload"):
        for x in subterms(t, kind):
            if not world.constant_load(x):
                out.append(x[2] if kind == "load" and isinstance(x[2], str) else "storage")
    for kind in _CHANGING_READS:
        out += [x[2] if kind == "call" else kind for x in subterms(t, kind)]
    return out


def _state_blocked(formula: Term, world: World, coverage: Coverage, verdict: Verdict) -> Verdict:
    """``verdict``, unless it claims "nobody, ever" (restricted, complete, nobody listed) on conditions not about who
    calls that read state a transaction may change (``amount >= lo && amount <= hi`` with ``lo > hi`` now, both
    owner-settable): "nobody" then holds only as things stand. With those conditions set aside, whoever the rest
    (the identity core) lets through is named, as holding only on them (``conditions``, ``allowed`` conditional);
    with no such core, or nobody named there either for a reason other than who they are, not determined. Each such
    variable is named, ``state_blocks_everyone:<variable>``. Conditions that read only what is provably constant
    (``_changing_reads``) or latched leave the claim standing."""
    if not (
        verdict.openness == "restricted"
        and verdict.complete
        and not (verdict.principals or verdict.signers or verdict.conditions)
        and formula != FALSE
    ):
        return verdict
    blocking: list[Term] = []
    names: set[str] = set()
    for part in conjuncts(formula):
        if contains(part, IDENTITY_KINDS):
            continue
        read = [n for atom in _atoms_of(part) if atom not in world.latched for n in _changing_reads(atom, world)]
        if read:
            blocking.append(part)
            names.update(str(n) for n in read)
    if not blocking:
        return verdict
    gaps = tuple(f"state_blocks_everyone:{n}" for n in sorted(names))
    reduced = mk_and([c for c in conjuncts(formula) if c not in blocking])
    effective = world.effective
    if effective is not None:
        world.effective = replace_terms(effective, {c: TRUE for c in blocking})
    try:
        again = _decide(reduced, world, world.cover(reduced) if world.cover is not None else coverage)
    finally:
        world.effective = effective
    shown = again.principals | again.signers | set(again.conditions)
    if again.openness == "restricted" and again.complete and not shown:
        return verdict  # nobody even with them set aside: who they are refutes them
    if contains(reduced, IDENTITY_KINDS) and again.openness == "restricted" and shown:
        # Whoever passes the whole formula passes it with those conditions set aside: a list complete there is
        # complete here, each holding on them (as a holder freed of business conditions is in ``_decide``).
        return replace(
            again,
            principals=frozenset(),
            signers=frozenset(),
            conditions={who: again.conditions.get(who, "business") for who in shown},
            allowed="conditional",
            gaps=again.gaps + gaps,
        )
    return Verdict("not_determined", frozenset(), False, gaps=gaps)


def _readings(parts: tuple[Term, ...]) -> tuple[str, ...]:
    from .report import render

    return tuple(dict.fromkeys(render(c) for c in parts))


def _business(parts: tuple[Term, ...]) -> tuple[tuple[str, str], ...]:
    """Conjuncts that hold for every caller alike, as business conditions: each as read, then each unknown in it."""
    from .report import render

    out: list[tuple[str, str]] = []
    for part in parts:
        out.append(("business", render(part)))
        out.extend(("business", label) for label in unknown_labels(part))
    return tuple(dict.fromkeys(out))


def _decide(formula: Term, world: World, coverage: Coverage) -> Verdict:
    """Who and whether anyone, separating the ``when`` conditions (pauses, deadlines, flags) from who holds power.

    Principals are identities singled out: in some state of the ``when`` conditions they pass where an unconfigured
    address doesn't, so a paused owner-only function still names its owner. Open means an unconfigured address passes
    now, or would once the ``when`` conditions allow while nobody known passes now either (a paused public function).
    The stranger's own entries arranged for the question are put back before it returns, and an open once the
    conditions allow that rests on them is confirmed (``_arranged_later``).
    """
    arranged = world.arranged
    world.__dict__.pop("_arranged_later", None)
    try:
        verdict = _decide_arranged(formula, world, coverage)
    finally:
        world.arranged = arranged
    return _arranged_later(formula, world, verdict)


def _arranged_later(formula: Term, world: World, verdict: Verdict) -> Verdict:
    """``verdict``, unless it is an open once the conditions allow (or only with some set aside) that rests on the
    stranger's own entries arranged first, and no call of its own brings them about: each stranger's call that
    writes them must go through on the chain as it stands, and this one then pass on the words it leaves in a state
    of the conditions that lets a stranger through (``World.prior`` with those states). Then it is open after that
    call, witnessed; otherwise not determined, ``open_arranged_later_unconfirmed``, the proposal kept as data."""
    states = world.__dict__.pop("_arranged_later", None)
    if states is None or verdict.openness != "open" or verdict.allowed == "now":
        return verdict
    world.__dict__.pop("_prior_runs", None)
    prior = world.prior(formula, owned=True, states=states)
    first, _ = world.__dict__.pop("_prior_runs", (None, None))
    if (
        prior is not None
        and first is not None
        and all(isinstance(world.chain.call(world.this, first, who), bytes) for who in (FRESH, *_OTHER_STRANGERS))
    ):
        signature, before, arguments = prior
        world.sampled = True
        return replace(verdict, witnesses={FRESH: arguments}, after=((signature, before),))
    return replace(verdict, openness="not_determined", complete=False, gaps=("open_arranged_later_unconfirmed",))


def _decide_arranged(formula: Term, world: World, coverage: Coverage) -> Verdict:
    world.rests_on = set()
    world.brought = []
    world.sampled = False
    world.__dict__.pop("_prior_runs", None)
    if formula == FALSE:
        return Verdict("restricted", frozenset(), True)  # always reverts: nobody, ever
    world.deadline = time.monotonic() + DECISION_SECONDS
    world.work, world.work_limit = 0.0, DECISION_WORK
    when = when_atoms(formula) - world.latched
    # Records the caller names (a vote, a proposal, an operation's timestamp): each caller names one in the state its
    # call needs, so they are free for every caller alike rather than states to set; so is a count the lowering
    # couldn't follow (approvals over a member list). Only "does a stranger get through now" reads them as stored.
    world.records = frozenset(a for a in when if contains(a, _FREE_KINDS | {"unknown"}))
    when = when - world.records
    # The state as it is (``{}``) is always one of them: someone passing now where a stranger doesn't is singled out.
    states = _when_states(when)
    if {} not in states:
        states.append({})
    anyone = {"caller": FRESH, "signer": FRESH}
    world.hashed_only = _hashed_only(formula)
    # Conditions whose current value couldn't be read (storage, code, a call): whether they can still change (a
    # consumed initializer, deployed code) is unknown, so "open once they allow" can't be claimed on them.
    probe = Evaluator(world, anyone)
    records = world.records
    unread = any(probe.truth(atom) is UNK for atom in when)
    if not _may_single_out(formula, world):
        # Nobody is singled out: open unless no state of the conditions lets anyone through. Where only a callee's
        # code, handed the caller, says it reads the caller alike for everyone, that rests on the code alone (a
        # callee mis-lowered reads alike for everyone): the stranger's failure stands, "nobody" isn't shown.
        coded = _singling_code(formula, world)
        if all(_outcome(formula, world, anyone, set(), fixed=state) is False for state in states):
            gaps = tuple(f"callee_unsingled:{signature}" for signature in coded)
            return Verdict("restricted", frozenset(), not coded, gaps=gaps)
        found: dict[Term, Any] = {}
        world.records_free = False
        try:
            now = _outcome(formula, world, anyone, set(), fixed={}, witness=found)
        finally:
            world.records_free = True
        # Open without a passing call rests on the conditions failing now (a pause): a call not known to fail now
        # (a read the node failed, a question left open) shows nothing. A record the caller names may or may not
        # exist in the state that passes (a vote ready to execute): open once one does, shown by a state of them
        # that lets a stranger through.
        if now is not True and (unread or (now is not False and not records)):
            gaps = _unread_gaps(when, probe) if unread else _unsettled(formula, world, anyone, {})
            return Verdict("not_determined", frozenset(), False, gaps=tuple(gaps))
        if now is not True:
            fresh = [_outcome(formula, world, anyone, set(), fixed=state) for state in states]
            if now is not False and not any(f is True for f in fresh):
                gaps = [g for st, f in zip(states, fresh) if f is UNK for g in _unsettled(formula, world, anyone, st)]
                return Verdict("not_determined", frozenset(), False, gaps=tuple(gaps or ["now_unknown"]))
            later: list[str] = []
            acts = _acts_once_allowed(formula, world, anyone, set(), states, fresh, later)
            if acts is not True:
                # Allowed only where it does nothing (disabling what is already disabled): no power to anyone.
                if not any(f is True for f in fresh):
                    gaps = [
                        g for st, f in zip(states, fresh) if f is UNK for g in _unsettled(formula, world, anyone, st)
                    ]
                else:
                    gaps = ["inert_when_allowed"] if acts is False else later or ["effect_unknown"]
                if acts is UNK and world.effective is not None:
                    gaps += _unsettled(world.effective, world, anyone, None)
                return Verdict("not_determined", frozenset(), False, gaps=tuple(gaps))
        unsingled = tuple(f"callee_unsingled:{signature}" for signature in coded)
        if now is True:
            witness = _argument_values(found)
            if coded and not (runs(world, FRESH, witness) is True and strangers_run(formula, world, witness)):
                # Every stranger alike only on a callee's code: open only where each one's own call goes through.
                return Verdict("not_determined", frozenset(), False, gaps=(*unsingled, "strangers_differ"))
            world.sampled = world.sampled or bool(coded)
            return Verdict("open", frozenset(), True, witnesses={FRESH: witness})
        if coded:
            # Open once the conditions allow, for every stranger alike only on a callee's code: no call shows it.
            return Verdict("not_determined", frozenset(), False, gaps=unsingled)
        return Verdict("open", frozenset(), True, allowed="later")
    if Evaluator(world, anyone, {}, frozenset(), when | records | _identity_atoms(formula)).truth(formula) is False:
        # Fails whoever calls, whatever the arguments and adjustable conditions: nobody, ever (a consumed initializer).
        return Verdict("restricted", frozenset(), True)
    # The cheap question first: a stranger getting through now makes it open, whoever else can.
    found_early: dict[Term, Any] = {}
    passed = world.code_passed
    allowed = _strangers_allowed(formula, world, found_early)
    if allowed is not None:
        return Verdict("open", frozenset(), True, witnesses={FRESH: _argument_values(found_early)}, allowed=allowed)
    if world.code_passed > passed:
        # A stranger's pass only a callee's code showed, unknown without it: its own call, run on the chain, settles
        # it before every candidate is asked about.
        ran = _executes(formula, world, FRESH, set(), tries=2)
        if ran is not None and strangers_run(formula, world, ran, tries=2):
            world.sampled = True
            return Verdict("open", frozenset(), True, witnesses={FRESH: ran})
    arranged = world.arrange(formula)
    arranged_open: Verdict | None = None
    if arranged:
        # What failed it may be the stranger's own entries, which open code lets anyone fill (a position to withdraw
        # from): chosen from here on, for strangers and candidates alike.
        before_arranged = world.arranged
        world.arranged = {**world.arranged, **arranged}
        # Whatever this reaches from here rests on them: an open now is confirmed on the chain (``_confirmed_open``),
        # an open once the conditions allow by a call of the stranger's own that brings them about
        # (``_arranged_later``).
        world.rests_on.add("arranged")
        world.__dict__["_arranged_later"] = states
        found_early.clear()
        allowed = _strangers_allowed(formula, world, found_early)
        if allowed is not None:
            requires = _requirements(formula, world)
            if any(need == "unknown" for _, _, need in requires):
                return Verdict("not_determined", frozenset(), False, gaps=("holding_unread",), requires=requires)
            if any(not isinstance(need, str) for _, _, need in requires):
                # Anyone holding enough passes, and holding enough is what decides: a gate on holdings, whose
                # holders no list names.
                return Verdict("restricted", frozenset(), False, gaps=("holders",), requires=requires)
            proposed = Verdict(
                "open",
                frozenset(),
                True,
                witnesses={FRESH: _argument_values(found_early)},
                requires=requires,
                allowed=allowed,
            )
            if requires or allowed != "now":
                return proposed
            # Open on entries each stranger brings about here first: only a call of its own that brings them about,
            # run on the chain before this one (below), shows it. The entries are no longer chosen for that.
            world.arranged = before_arranged
            world.__dict__.pop("_arranged_later", None)
            arranged_open = proposed
    # What failed it may be entries of the stranger's own that one of its calls here writes first (a delegate it
    # assigns before it can unassign one): run that call's writes, then this one.
    prior = world.prior(formula, owned=True) if arranged_open is not None else world.prior(formula)
    if prior is not None:
        signature, before, arguments = prior
        return Verdict("open", frozenset(), True, witnesses={FRESH: arguments}, after=((signature, before),))
    if arranged_open is not None:
        # No call of the stranger's own shown to bring them about: the proposal stays, as data.
        return replace(arranged_open, openness="not_determined", complete=False, gaps=("open_arranged_unconfirmed",))
    if SKIP_SELF_SCOPED and world.scope is not None and world.scope.kind == "self" and not world.arrange_unknown:
        # Its effects stay in the caller's own positions: the gate is the answer, not who holds it. A stranger
        # failing in every state, with unseen addresses failing alike, is all "restricted" needs; anything less
        # is decided in full below. The label is unverified (``SCOPE.md``): skipping only loses holders, into a
        # list never complete that says ``self_scoped``, and never stands where a stranger's own call goes through.
        fresh = [_outcome(formula, world, anyone, set(), fixed=state) for state in states]
        if all(f is False for f in fresh) and (coverage.representative or _decisive(formula, world)):
            members, proven, _ = _built(formula, world)
            # A list shown empty (nobody, ever) costs nothing to decide in full below: no skip.
            if members or not proven:
                if any(_executes(formula, world, who, set()) is not None for who in (FRESH, *_OTHER_STRANGERS)):
                    # The chain lets a stranger through where the formula refuses every one: the formula is wrong.
                    return Verdict("not_determined", frozenset(), False, gaps=("self_scoped", "self_scoped_ran"))
                return Verdict(
                    "restricted",
                    frozenset(),
                    False,
                    gaps=("self_scoped",),
                    gate=gate_of(formula),
                    members=len(members) if proven else None,
                )
    # Precompiles and sentinels (``address(1)``) never send a transaction.
    # Who may be singled out, built from the identity checks (``holders``): a list shown to hold everyone, one
    # drawn from what the chain shows without that proof, or none, each with why.
    candidates, proven, gaps = _built(formula, world)
    truncated = bool(world.cut)
    capped = not proven
    if proven:
        # Nobody outside the list can pass, by construction: the lookups' blind spots don't apply.
        coverage = replace(coverage, representative=True, blind=frozenset(), values=frozenset())
        _prefetch(formula, world, set(_ranked(candidates, world)[:_CANDIDATE_BATCH]))
    roots = ["caller"] + (["signer"] if contains(formula, frozenset({"signer"})) else [])
    fresh = [_outcome(formula, world, anyone, candidates, fixed=state) for state in states]
    # An unproven list with no state refusing a stranger: candidates only lengthen a list never complete
    # (``UNPROVEN_CANDIDATES``). The stranger's own call is asked first, every stranger's, and settles it if it passes.
    limited = not proven and not any(f is False for f in fresh)
    if limited:
        ran = _executes(formula, world, FRESH, set(), tries=2)
        if ran is not None and strangers_run(formula, world, ran, tries=2):
            world.sampled = True
            return Verdict("open", frozenset(), True, witnesses={FRESH: ran})
    if not proven:
        _prefetch(formula, world, set(_ranked(candidates, world)[: UNPROVEN_BATCH if limited else _CANDIDATE_BATCH]))
    # Lookups the events can't list, or whose histories were cut: listed from storage when a dump accounts for them,
    # with whoever it names asked about like the rest.
    snapshot = (
        _snapshot_plan(formula, world, coverage, candidates, states, fresh)
        if (coverage.blind or world.cut) and any(f is False for f in fresh)
        else None
    )
    if snapshot is not None and snapshot.found:
        candidates |= snapshot.found
        _prefetch(formula, world, set(_ranked(snapshot.found, world)[:_CANDIDATE_BATCH]))
    if not proven and snapshot is not None and (snapshot.listed or snapshot.cleared):
        # The dump lists what the events couldn't: the builder again, with those lookups' holders in hand.
        world.dumped = {
            "lookups": snapshot.listed,
            "addresses": snapshot.cleared,
            "members": frozenset(candidates | snapshot.found),
        }
        rebuilt, proven, gaps = _built(formula, world)
        candidates |= rebuilt
        truncated, capped = bool(world.cut) and not proven, not proven
        _prefetch(formula, world, set(_ranked(candidates, world)[:_CANDIDATE_BATCH]))
    # Proving a candidate fails only matters for a complete list, which needs an unconfigured address proven to fail.
    refutable = any(f is False for f in fresh)
    passes: dict[str, set[int]] = {root: set() for root in roots}
    known: dict[str, set[int]] = {root: set() for root in roots}
    undecided: set[int] = set()
    witnesses: dict[int, dict[str, Any]] = {}
    now_passes = False
    # A candidate whether passing now went unanswered (a read failed, the budget ran out): "nobody known passes now"
    # isn't known, so neither is "open once the conditions allow".
    now_maybe = False
    loosened = relaxed_atoms(formula)
    loose_stranger: list[Any] = []
    # The decision's own work limit; each candidate's questions get a share of what is left of it (``_SHARE``), so
    # one candidate's search never spends what the rest are owed. What every candidate shares (the stranger's
    # chances) is asked under the decision's limit, never one candidate's share.
    limit = world.work_limit

    def uncapped(ask: Callable[[], Any]) -> Any:
        capped_at, world.work_limit = world.work_limit, limit
        try:
            return ask()
        finally:
            world.work_limit = capped_at

    def stranger_loose() -> Any:
        if not loose_stranger:
            loose_stranger.append(uncapped(lambda: _outcome(formula, world, anyone, candidates, relaxed=True)))
        return loose_stranger[0]

    freed_stranger: dict[str, Any] = {}
    conditions: dict[int, str] = {}

    def stranger_freed(level: str) -> Any:
        """A stranger's chance with only what the arguments decide freed (and at ``holdings``, the amounts in its
        own entries), stored state read as it is."""
        if level not in freed_stranger:
            freed_stranger[level] = uncapped(lambda: _outcome(formula, world, anyone, candidates, relaxed=level))
        return freed_stranger[level]

    # A batch of candidates' first questions at once, so their reads go out in a few batches rather than one round trip
    # per candidate: the state as it is, then the guessed arguments' reads for those it leaves open.
    identities: list[dict[str, int]] = []
    unsettled: list[dict[str, int]] = []
    # Candidates never asked about because the budget ran out first: the list is partial, by this many.
    untested: set[int] = set()

    loose_open: list[dict[str, int]] = []

    def as_they_are() -> None:
        unsettled.clear()
        loose_open.clear()
        for identity in identities:
            if Evaluator(world, identity, {}, frozenset(), loosened).ranked(formula) is UNK:
                loose_open.append(identity)
            if _decide_one(formula, world, identity, candidates, fixed={}, refute_ok=False, base_only=True) is UNK:
                unsettled.append(identity)

    def guessed() -> None:
        spent = world.work  # reads the relaxed question will want: fetched here, charged when it is asked
        for identity in loose_open:
            _decide_one(formula, world, identity, candidates, refute_ok=False, relaxed=True, reads_only=True)
        world.work = spent
        for identity in unsettled:
            _decide_one(formula, world, identity, candidates, fixed={}, refute_ok=False, reads_only=True)

    order = _screened(formula, world, candidates, loosened)
    size, phase_reads, whole_limit = _CANDIDATE_BATCH, world.chain.sent, world.chain.limit
    if limited:
        untested.update(order[UNPROVEN_CANDIDATES:])
        order, size = order[:UNPROVEN_CANDIDATES], UNPROVEN_BATCH
        # One candidate's own search can spend hundreds of reads: past the sub-budget its reads answer unknown, the
        # candidate left undecided, until the candidates' calls run below are done.
        sub = phase_reads + UNPROVEN_READS
        world.chain.limit = sub if whole_limit is None else min(whole_limit, sub)

    def spent() -> bool:
        return world.exhausted() or (limited and world.chain.sent - phase_reads >= UNPROVEN_READS)

    batches = [order[i : i + size] for i in range(0, len(order), size)]
    for number, batch in enumerate(batches):
        if spent():
            untested.update(batch)
            continue
        if number:
            _prefetch(formula, world, set(batch))
        identities[:] = [{**anyone, root: candidate} for root in roots for candidate in batch]
        world.chain.gather(as_they_are)
        world.chain.gather(guessed, rounds=2)
        pairs = [(root, candidate) for root in roots for candidate in batch]
        for root, candidate in pairs:
            world.work_limit = limit
            if spent():
                untested.add(candidate)
                continue
            world.work_limit = min(limit, world.work + max(_MIN_SHARE, (limit - world.work) * _SHARE))
            identity = {**anyone, root: candidate}
            # Every condition not about who calls left open, and still failing: refused whatever the arguments, the
            # state or the business logic, so no search is owed (the cheap answer for most candidates).
            screen = Evaluator(world, identity, {}, frozenset(), loosened)
            loose = screen.ranked(formula)
            if loose is False and screen.coded[0]:
                # Refused only through a callee's code: asked without it (``Evaluator.truth``). Still refused, it is;
                # otherwise it is undecided, and the code's refusal only spares it the search.
                loose = screen.without_code().truth(formula)
                if loose is not False and loose is not True:
                    world.code_refuted += 1
                    undecided.add(candidate)
                    continue
            if loose is UNK:
                # Still open with the arguments left to choose: search them, before the exact questions below
                # spend the budget on business logic.
                loose_found: dict[Term, Any] = {}
                loose = _outcome(formula, world, identity, candidates, witness=loose_found, relaxed=True)
            if loose is False:
                continue
            # Anyone known passing now keeps a currently blocked stranger from making it "open when allowed".
            passes_now = _outcome(formula, world, identity, candidates, fixed={}, refute_ok=False)
            now_passes = now_passes or passes_now is True
            now_maybe = now_maybe or passes_now is UNK
            singled = False
            for index, (state, fresh_outcome) in enumerate(zip(states, fresh)):
                if fresh_outcome is True:
                    continue
                found: dict[Term, Any] = {}
                # Where a stranger fails, the builder's bindings are every argument value it can be singled out under.
                bound = _exact_bindings(world, candidate) if fresh_outcome is False else None
                # Asked of every candidate, whatever earlier ones left open: skipping it after a few unanswered ones
                # would make who is found depend on the order they are asked in (z3 itself still gives up early, in
                # ``solve``, while the guesses are tried for each).
                outcome = _outcome(
                    formula,
                    world,
                    identity,
                    candidates,
                    fixed=state,
                    refute_ok=refutable,
                    witness=found,
                    bound=bound,
                )
                freed = None
                if outcome is UNK and fresh_outcome is False and stranger_loose() is False:
                    # Business logic the engine can't settle (memory structures, external data): free it, and see
                    # whether this identity passes every check that involves who calls. Only where a stranger fails
                    # the same: freed, a condition not about who calls may let anyone through (an open role's flag).
                    outcome, freed = loose, "business"
                for level in ("arguments", "holdings"):
                    if outcome is not UNK or fresh_outcome is not False or state != {}:
                        break
                    if stranger_freed(level) is not False:
                        continue
                    # The same as things stand: only what the arguments decide freed (an instance the argument must
                    # be), stored state read as it is, so a flag that would let anyone in, read set, keeps them out.
                    # Then the caller's own amounts too (a spoke's cap and shares): it is in the lookup that singles
                    # it out, what it may move a condition on it, not on who it is.
                    if _outcome(formula, world, identity, candidates, relaxed=level, witness=found) is True:
                        outcome, freed = True, level
                if outcome is True and fresh_outcome is False:
                    singled = True
                    witnesses[candidate] = _argument_values(found)
                    if freed is not None:
                        conditions[candidate] = freed
                    break
                if outcome is True and fresh_outcome is UNK:
                    # Passes, though whether a stranger would too isn't known: a known holder of the power, not
                    # proof it is singled out.
                    known[root].add(candidate)
                    witnesses[candidate] = _argument_values(found)
                if outcome is not False:
                    undecided.add(candidate)
            if singled and candidate not in conditions:
                passes[root].add(candidate)
    world.work_limit = limit
    if untested:
        # Someone never asked about may pass now: neither "nobody known passes now" nor a complete list holds.
        now_maybe = True
        gaps.append(f"untested_candidates:{len(untested)}")
    now_index = next((i for i, state in enumerate(states) if state == {}), None)
    if now_index is not None and fresh[now_index] is False:
        # Undecided where the reasoning stops (a callee's check it can't settle): the call itself, run from the
        # candidate on the chain as it is, settles whether it passes now.
        for candidate in sorted(undecided - passes["caller"])[:_EXECUTED_CANDIDATES]:
            found_args = _executes(formula, world, candidate, candidates)
            if found_args is not None:
                passes["caller"].add(candidate)
                witnesses[candidate] = found_args
                undecided.discard(candidate)
        # Those listed on who they are alone: a call of theirs that goes through on the chain shows it exactly.
        for candidate in sorted(conditions)[:_EXECUTED_CANDIDATES]:
            found_args = _executes(formula, world, candidate, candidates)
            if found_args is not None:
                passes["caller"].add(candidate)
                witnesses[candidate] = found_args
                del conditions[candidate]
    elif now_index is not None and fresh[now_index] is UNK:
        # Whether a stranger passes is unknown, so none is singled out; a candidate left undecided whose own call
        # goes through on the chain still holds the power (a pass only a callee's code showed, confirmed).
        for candidate in sorted(undecided - known["caller"])[:_EXECUTED_CANDIDATES]:
            found_args = _executes(formula, world, candidate, candidates)
            if found_args is not None:
                known["caller"].add(candidate)
                witnesses[candidate] = found_args
                undecided.discard(candidate)
    if limited:
        if world.chain.sent >= world.chain.limit:
            gaps.append("budget:unproven_reads")
        world.chain.limit = whole_limit
    callers, signers = frozenset(passes["caller"]), frozenset(passes.get("signer", ()))
    decided = callers | signers | frozenset(conditions)
    undecided -= decided
    found_now: dict[Term, Any] = {}
    if now_index is not None and fresh[now_index] is False:
        now = False  # asked before the candidates spent the budget: the same question
    else:
        now = _outcome(formula, world, anyone, candidates, fixed={}, witness=found_now)
    if now is True:
        now = UNK  # strangers differ (``_strangers_pass`` said not all of them pass): not open, not a list
    if now is False and not now_passes and not unread and any(f is True for f in fresh):
        # "Nobody known passes now" is only "nobody passes now" when the lookups that could hold someone were all read
        # (a role in namespaced storage, its holders unlisted) and the list wasn't cut short.
        unlisted = coverage.lookups if capped else coverage.blind
        now_passes = bool(unlisted) and _outcome(formula, world, anyone, candidates, unlisted, fixed={}) is not False
    allowed: Any = None  # asked only where a stranger gets through in some state of the conditions
    later: list[str] = []
    if now is False and not now_passes and any(f is True for f in fresh):
        # A stranger gets through in some state of the conditions: open once they allow it, unless that call does
        # nothing; with a condition unread, whether it can come about at all is unknown.
        allowed = (
            UNK if unread or now_maybe else _acts_once_allowed(formula, world, anyone, candidates, states, fresh, later)
        )
    if now is True:
        return Verdict("open", frozenset(), True, witnesses={FRESH: _argument_values(found_now)})
    if allowed is True:
        return Verdict("open", frozenset(), True, allowed="later")
    if allowed is False:
        # Strangers get through once the conditions allow, only where the call does nothing or a condition it consumes
        # itself is back: "nobody, ever" only where no entry point can write that back, which latching would have
        # shown (it would read as it stands, never get here). As where nobody can be singled out: not determined.
        gaps.append("inert_when_allowed")
        return Verdict(
            "not_determined",
            callers,
            False,
            frozenset(undecided - callers),
            signers,
            witnesses,
            tuple(gaps),
            conditions=conditions,
        )
    if allowed is UNK:
        # Strangers get through once the conditions allow, and whether that call does anything is unknown.
        gaps.append("now_unknown")
        gaps += later
        return Verdict(
            "not_determined",
            callers,
            False,
            frozenset(undecided - callers),
            signers,
            witnesses,
            tuple(gaps),
            conditions=conditions,
        )
    if now is False and not now_passes and any(f is UNK for f in fresh):
        # Nobody known passes now, and whether a stranger would in some state of the conditions is unknown: "open
        # once they allow" can't be ruled out.
        gaps.append("now_unknown")
        gaps += [g for state, f in zip(states, fresh) if f is UNK for g in _unsettled(formula, world, anyone, state)]
        return Verdict(
            "not_determined",
            callers,
            False,
            frozenset(undecided - callers),
            signers,
            witnesses,
            tuple(gaps),
            conditions=conditions,
        )
    if now is False and world.arrange_unknown:
        # A stranger fails as things stand, but whether it could bring about its own entries first is unknown.
        gaps.append("now_unknown")
        return Verdict(
            "not_determined",
            callers,
            False,
            frozenset(undecided - callers),
            signers,
            witnesses,
            tuple(gaps),
            conditions=conditions,
        )
    if now is False and not coverage.representative and _decisive(formula, world):
        coverage = replace(coverage, representative=True)
    if now is False and coverage.representative:
        # Unseen addresses are singled out nowhere either if an unconfigured one isn't, even with every
        # unenumerable lookup read as unknown.
        # An unconfigured address is the value of no entry, so it fails those reads unlisted too: but their holders
        # aren't listed.
        def unseen_fail(unlisted: frozenset) -> bool:
            return not coverage.values and all(
                _outcome(formula, world, anyone, candidates, unlisted, fixed=state) is False
                for state, f in zip(states, fresh)
                if f is not True
            )

        blind = unseen_fail(coverage.blind)
        if snapshot is not None and (not blind or truncated) and not undecided:
            # What the events can't list, the storage did, with the holders it found decided too.
            if snapshot.listed:
                coverage = replace(coverage, blind=coverage.blind - snapshot.listed)
                blind = blind or unseen_fail(coverage.blind)
            if snapshot.cleared:
                world.cut -= snapshot.cleared
                truncated = bool(world.cut)
                if not truncated:
                    gaps = [g for g in gaps if g != "history_truncated"]
        # Complete only as built from the identity checks (``holders``): candidates gathered any other way may miss
        # whoever no source named, whatever the stranger's failure shows.
        complete = proven and blind and not undecided and not untested
        if not blind:
            gaps += _blind_gaps(coverage.blind, formula, world) or ["others_unproven"]
        if undecided:
            gaps.append("undecided_candidates")
        return Verdict(
            "restricted",
            callers,
            complete,
            frozenset(undecided),
            signers,
            witnesses,
            tuple(gaps),
            conditions=conditions,
        )
    callers |= frozenset(known["caller"])
    signers |= frozenset(known.get("signer", ()))
    gaps.append("now_unknown" if now is UNK else "unrepresentative" if not coverage.representative else "other")
    if now is UNK:
        gaps += _unsettled(formula, world, anyone, {})
    return Verdict(
        "not_determined",
        callers,
        False,
        frozenset(undecided - callers - signers),
        signers,
        witnesses,
        tuple(gaps),
        conditions=conditions,
    )


def _unsettled(formula: Term, world: World, identity: dict[str, int], fixed: dict[Term, bool] | None) -> list[str]:
    """Why ``formula`` reads neither true nor false for ``identity`` (``fixed`` sets ``when`` conditions, ``None``
    leaves them all free): each condition still open, by what in it went unread. ``budget`` when the work or the
    reads ran out, ``unsolved`` when only the arguments are left and no search settled them."""
    out: list[str] = []
    if world.exhausted():
        out.append("budget")
    chain = world.chain
    if chain.limit is not None and chain.sent >= chain.limit:
        out.append("budget:reads")
    when = frozenset(fixed) if fixed is not None else when_atoms(formula)
    probe = Evaluator(world, identity, dict(fixed or {}), frozenset(), when)
    for atom in sorted(_atoms_of(formula), key=stable):
        if atom in when or probe.truth(atom) is not UNK:
            continue
        out.extend(_open_parts(atom, probe))
    return list(dict.fromkeys(out)) or ["unsolved"]


def _unread_gaps(when: frozenset, probe: "Evaluator") -> list[str]:
    """The ``when`` conditions whose current value couldn't be read, by what in each went unread."""
    out = [g for atom in sorted(when, key=stable) if probe.truth(atom) is UNK for g in _open_parts(atom, probe)]
    return list(dict.fromkeys(out)) or ["read_failed:condition"]


def _open_parts(atom: Term, probe: "Evaluator", depth: int = 0) -> list[str]:
    """What leaves ``atom`` unknown: a term the lowering couldn't express (``unknown:<its label>``), a call whose
    callee isn't followed and whose arguments the caller picks (``call:...`` when the caller's identity reaches it,
    see ``call_gap``, else ``unfollowed:<signature>``), a read the chain didn't answer (``read_failed:<what>``). A
    followed callee left unknown is looked into the same way, a few contracts deep (past that, ``depth:<sig>``)."""
    out = [unknown_gap(u[1]) for u in subterms(atom, "unknown")]
    out += [f"unknown:{o[1]}" for o in subterms(atom, "opaque")]
    for call in subterms(atom, "call"):
        address = probe.eval(call[1])
        if not isinstance(address, int) or isinstance(address, bool):
            out.append(f"read_failed:target:{call[2]}")
        elif not call[4]:
            if probe.eval(call) is UNK and probe.world.callee(call, address % 2**160) is None:
                out.append(call_gap(call, probe))  # an action handed the caller, its callee not followed
            elif probe.eval(call) is UNK:
                out.append(f"action:{call[2]}")  # an action handed the caller, its callee's check unsettled
        elif probe.call_input(call) is not None:
            if probe.eval(call) is UNK:
                out.append(f"read_failed:call:{call[2]}")
        else:
            lowered = probe.world.callee(call, address % 2**160)
            if lowered is None:
                out.append(call_gap(call, probe) if tainted(call) else f"unfollowed:{call[2]}")
            elif probe.eval(call) is UNK:
                if depth >= IDENTITY_DEPTH:
                    out.append(f"depth:{call[2]}")
                    continue
                out += [
                    g
                    for part in (lowered[0], *lowered[1])
                    if isinstance(part, tuple) and part and isinstance(part[0], str)
                    for g in _open_parts(part, probe, depth + 1)
                ]
    for load in subterms(atom, "load"):
        where = probe.storage_cell(load)
        if where is not None and probe.word(where[0], where[1]) is UNK:
            out.append(f"read_failed:storage:{_named_lookup(load[2], load[3])[0]}")
    if any(t[1] for t in subterms(atom, "time")) and probe.world.chain.block_field("timestamp") is UNK:
        out.append("read_failed:block")
    return out


_SNAPSHOT_TRIES = 128  # stranger entries tried from a storage dump's unaccounted words (all lookups combined)
_RESOLVE_SLOTS = 16  # unaccounted slots whose word lets a stranger through, traced to their writer, at most


@dataclass(frozen=True)
class _Snapshot:
    """What a storage dump lists: the unlisted lookups (``coverage.blind`` entries) and the cut histories
    (addresses) it lists whole, once the holders it found (``found``) are decided too."""

    listed: frozenset
    cleared: frozenset
    found: frozenset


def _snapshot_plan(
    formula: Term, world: World, coverage: Coverage, candidates: set[int], states: list, fresh: list
) -> _Snapshot | None:
    """Every identity lookup the formula makes where a lookup is unlisted or a history was cut, accounted for in a
    dump of that storage (``snapshot.Accounting``): each slot no known key reaches is tried as the stranger's own
    entry, and each whose word lets the stranger through is traced to a transaction that wrote it, whose words name
    its key (a holder to ask about, or another variable's entry). ``None`` when any lookup there can't be placed, a
    dump or trace is missing, there are too many words to try, or a slot stays unexplained."""
    from .snapshot import Accounting, code_constants

    if world.chain.debug is None or world.exhausted():
        return None
    anyone = {"caller": FRESH, "signer": FRESH}
    probe = Evaluator(world, anyone)
    loads: dict[int, list[Term]] = {}
    entries: dict[int, set] = {}
    for term in _with_callees(formula, world, IDENTITY_KINDS):
        for t in subterms(term, "load"):
            if not any(contains(step, IDENTITY_KINDS) for kind, step in t[3] if kind == "k"):
                continue
            named = _named_lookup(t[2], t[3])[0]
            entry = next((e for e in ((t[1], t[2]), (t[1], named)) if e in coverage.blind), None)
            address = probe.eval(t[1])
            if not isinstance(address, int) or isinstance(address, bool):
                if entry is not None:
                    return None
                continue
            if entry is None and address not in world.cut:
                continue
            loads.setdefault(address, []).append(t)
            entries.setdefault(address, set()).update(e for e in ((t[1], t[2]), (t[1], named)) if e in coverage.blind)
    if not loads:
        return None
    dimensions: list[tuple[int, int, dict[int, list[int]]]] = []  # (address, slot, word to try -> slots holding it)
    accounted: dict[int, tuple[Any, list[Term], set[int], set]] = {}
    held: set[int] = set()  # keys whose own entry of a lookup asked about holds a word: holders, asked about too
    for address, found in loads.items():
        contract = world.contracts.get(address)
        dump = world.chain.storage_dump(address)
        if contract is None or dump is None:
            return None
        cells: dict[int, list[tuple[int, Any]]] = {}
        roots: list[tuple[int, Any]] = []
        for t in found:
            cell = probe.storage_cell(t)
            if cell is None:
                return None
            cells.setdefault(cell[1], []).append((cell[2], cell[3]))
            if isinstance(t[2], tuple) and t[2] and t[2][0] == "slot":
                root, struct = probe.eval(t[2][1]), _named_type(contract, t[2][2])
                if isinstance(root, int) and not isinstance(root, bool) and struct is not None:
                    roots.append((root, struct))
        targets = {_named_lookup(t[2], t[3])[0] for t in found} | {t[2] for t in found if isinstance(t[2], str)}
        keys = set(candidates) | {w for w in dump.values() if w < 2**160}
        keys |= {c[1] for c in subterms(formula, "const") if type(c[1]) is int}
        keys |= world.chain.all_log_words(address)
        for var in targets:
            if isinstance(var, str):
                keys |= world.chain.log_words(address, world.writer_topics(address, var))
        constants = code_constants(_runtime_code(contract))
        for holder in {address, world.code_of(address)}:
            code = world.chain.code(holder)
            if isinstance(code, bytes):
                constants |= code_constants(code)
        # Keys too low to be anyone's address (a list's sentinel, ``address(1)``) are never a caller: theirs too.
        sentinels = {k for k in keys if k < _LOWEST_SENDER}
        # The lookups asked about at every address known, not the candidates only: an entry reached by a key that
        # isn't a candidate is a holder's, asked about below; left unreached, a stranger holding its word may still
        # fail where the holder passes (a loan whose own code answers the callback).
        addresses = {k for k in keys if k < 2**160}
        accounting = Accounting(contract, dump, keys, set(candidates) | sentinels | addresses, targets)
        reached = accounting.run(roots, constants)
        for key in accounting.used:
            who = key % 2**160
            if key >= 2**160 or who < _LOWEST_SENDER or who in candidates:
                continue
            own = Evaluator(world, {"caller": who, "signer": who})
            if any((cell := own.storage_cell(t)) is not None and cell[1] in dump for t in found):
                held.add(who)
        for candidate in candidates:
            # The candidates' own entries, however the lookup is placed (namespaced, hashed): theirs, and asked about.
            known = Evaluator(world, {"caller": candidate, "signer": candidate})
            for t in found:
                cell = known.storage_cell(t)
                if cell is not None:
                    reached.add(cell[1])
        left = {slot: word for slot, word in dump.items() if slot not in reached}
        accounted[address] = (contract, found, keys, targets)
        for slot, fields in cells.items():
            tried: dict[tuple, int] = {}
            holding: dict[int, list[int]] = {}
            for at, word in left.items():
                read = tuple(_decode_word(word, offset, type_) for offset, type_ in fields)
                if not any(read):
                    continue
                if read not in tried:
                    tried[read] = word
                    if len(tried) > _SNAPSHOT_TRIES:
                        return None
                holding.setdefault(tried[read], []).append(at)
            dimensions.append((address, slot, holding))
    combinations = 1
    for _, _, holding in dimensions:
        combinations *= len(holding) + 1
    if combinations - 1 > _SNAPSHOT_TRIES:
        return None
    listed = frozenset().union(*entries.values())
    unlisted = coverage.blind - listed
    suspects: set[tuple[int, int]] = set()  # (address, slot) whose word lets a stranger through
    saved = world.overlay
    try:
        for choice in itertools.product(*([None, *holding] for _, _, holding in dimensions)):
            if all(w is None for w in choice):
                continue
            world.overlay = {
                **saved,
                **{(address, slot): w for (address, slot, _), w in zip(dimensions, choice) if w is not None},
            }
            passes = any(
                _outcome(formula, world, anyone, candidates, unlisted, fixed=state) is not False
                for state, f in zip(states, fresh)
                if f is not True
            )
            if passes:
                for (address, _, holding), w in zip(dimensions, choice):
                    if w is not None:
                        suspects.update((address, at) for at in holding[w])
            if len(suspects) > _RESOLVE_SLOTS:
                return None
    finally:
        world.overlay = saved
    named: set[int] = set()
    writers = {
        address: world.chain.slot_writers(address, sorted(s for a, s in suspects if a == address))
        for address in {a for a, _ in suspects}
    }
    for address, slot in sorted(suspects):
        contract, found, keys, targets = accounted[address]
        words = writers[address].get(slot)
        if words is None:
            return None
        holders = {
            w % 2**160
            for w in words
            for t in found
            if (cell := Evaluator(world, {"caller": w % 2**160, "signer": w % 2**160}).storage_cell(t)) is not None
            and cell[1] == slot
        }
        if holders:
            named |= {w for w in holders if w >= _LOWEST_SENDER}
            continue
        # Not the lookup's under any word the writer carried: another variable's entry, if one reaches it.
        if slot not in Accounting(contract, {slot: 1}, set(words) | keys, set(), targets).run():
            return None
    return _Snapshot(listed, frozenset(a for a in loads if a in world.cut), frozenset((named | held) - candidates))


def _runtime_code(contract: Any) -> bytes:
    """The contract's compiled runtime code, when the compilation kept it."""
    try:
        unit = contract.compilation_unit.crytic_compile_compilation_unit
        source = unit.source_units[contract.source_mapping.filename]
        return bytes.fromhex(source.bytecode_runtime(contract.name) or "")
    except Exception as exc:
        if isinstance(exc, TimeoutError):
            raise
        return b""


def _blind_gaps(blind: frozenset, formula: Term, world: World) -> list[str]:
    """Each unlisted lookup as ``storage:<variable>`` (``namespaced:`` for ERC-7201 storage) or, for a call handed
    the caller whose callee can't be listed, as ``call_gap`` names it."""
    out = []
    calls = [c for part in _with_callees(formula, world, IDENTITY_KINDS) for c in subterms(part, "call")]
    probe = Evaluator(world, {"caller": FRESH, "signer": FRESH})
    for target, what in sorted(blind, key=repr):
        if isinstance(what, tuple) and what and what[0] == "slot":
            out.append(f"namespaced:{what[-1]}")
        elif isinstance(what, str) and "(" in what:
            named = [call_gap(c, probe) for c in calls if c[1] == target and c[2] == what and tainted(c)]
            out.extend(named or [f"call:{what}"])
        else:
            out.append(f"storage:{what}")
    return out


def call_gap(call: Term, probe: "Evaluator") -> str:
    """A call the caller's identity reaches, whose callee isn't followed: ``call:<signature>``, then each argument
    the identity reaches (``:arg<i>``, ``:target`` for the address called), then ``@<address>`` once it is read."""
    text = f"call:{call[2]}" + "".join(f":arg{i}" for i, a in enumerate(call[3]) if tainted(a))
    if tainted(call[1]):
        text += ":target"
    address = probe.eval(call[1])
    if isinstance(address, int) and not isinstance(address, bool):
        text += f"@0x{address % 2**160:040x}"
    return text


def _acts_once_allowed(
    formula: Term, world: World, anyone: dict, candidates: set, states: list, fresh: list, reasons: list | None = None
) -> bool:
    """Whether a stranger, in some state of the conditions that lets it through, gets a call with an effect through:
    "open once allowed" means the power, not a no-op (``disableConsensus`` once consensus is already disabled). A
    condition the function writes itself (``disableConsensus`` setting the quorum it checks, an initializer its flag)
    is where its holders leave it, not a gate that may open: it stays as it is. ``False`` is no "nobody, ever": that
    holds only where no entry point can write the condition back, which latching shows (such a condition reads as it
    stands and never gets here); ``_decide`` reports it as not determined (``inert_when_allowed``), in both branches.

    Nor does "open once allowed" rest on a callee's answer: a state that lets the stranger through only with a
    condition reading a call answering otherwise than it does now (``require(g.ok())`` with ``ok()`` false) claims the
    callee can come to answer so, which nothing here shows (it may be a flag nothing writes, a ``pure`` false). Such
    a state shows nothing: unknown, each call named in ``reasons`` (``later_on_callee:<signature>``); with every
    condition free, those conditions read as they stand."""

    def own(atom: Term) -> bool:
        return any(
            (("raw", t[1]) if t[0] == "rawload" else (t[1], t[2])) in world.written
            for kind in ("load", "rawload")
            for t in subterms(atom, kind)
        )

    probe = Evaluator(world, anyone)
    plain = probe.without_code()
    # A record the caller names is each created in its own state, not left by the function where it found it.
    owned = frozenset(a for a in when_atoms(formula) if own(a) and not contains(a, _FREE_KINDS | {"unknown"}))
    answered = frozenset(a for a in when_atoms(formula) if subterms(a, "call"))
    answer: Any = False
    for state, passes in zip(states, fresh):
        if passes is not True:
            continue
        if state is None:
            # Every condition free: those the function writes, and those a callee answers, are read as they are.
            saved = world.latched
            world.latched = saved | owned | answered
            try:
                through = True if not owned | answered else _outcome(formula, world, anyone, candidates, fixed=None)
                acts = through
                if through is True and world.effective is not None:
                    acts = _outcome(world.effective, world, anyone, candidates, fixed=None)
            finally:
                world.latched = saved
        else:
            # A record the caller names has no one current value: each one is created in its own state.
            flipped = [
                a
                for a, value in state.items()
                if not contains(a, _FREE_KINDS | {"unknown"})
                and (plain if a in answered else probe).truth(a) is not value
            ]
            on_callee = [a for a in flipped if a in answered]
            acts = False if any(a in owned for a in flipped) else UNK if on_callee else True
            if on_callee and reasons is not None:
                reasons += [f"later_on_callee:{c[2]}" for a in on_callee for c in subterms(a, "call")]
            if acts is True and world.effective is not None:
                acts = _outcome(world.effective, world, anyone, candidates, fixed=state)
        if acts is True:
            return True
        if acts is not False:
            answer = UNK
    return answer


_EXECUTED_CANDIDATES = 8  # undecided candidates per function whose call is run on the chain


def _executes(
    formula: Term, world: World, candidate: int, candidates: set, tries: int | None = None
) -> dict[str, Any] | None:
    """The arguments with which a call from ``candidate`` returns when the chain runs it (``eth_call``), else
    ``None``: guesses from the search with the conditions the engine can't settle left free, then all zero; the
    first ``tries`` of them only, when given."""
    identity = {"caller": candidate, "signer": FRESH}
    found: dict[Term, Any] = {}
    # Plausible values besides: an amount of one, a flag set, the candidate's own address, a short name.
    plausible = {}
    for parameter in world.parameters:
        if parameter[0] != "arg":
            continue
        type_ = parameter[2]
        plausible[parameter] = (
            True
            if type_ == "bool"
            else candidate
            if type_.startswith("address") and "[" not in type_
            else b"a"
            if type_ in ("bytes", "string")
            else 1
            if type_.startswith(("uint", "int")) and "[" not in type_
            else []
            if type_.endswith("[]")
            else 0
        )
    guesses = [{}, plausible]
    if _outcome(formula, world, identity, candidates, relaxed=True, witness=found) is True and found:
        guesses.insert(0, {**plausible, **found})
    for guess in guesses[:tries]:
        if any(t[0] == "callvalue" and v for t, v in guess.items()):
            continue  # a call sending value the candidate may not hold: not run
        assignment = dict(guess)
        for parameter in world.parameters:
            if parameter not in assignment and parameter[0] == "arg":
                type_ = parameter[2]
                assignment[parameter] = (
                    False
                    if type_ == "bool"
                    else b""
                    if type_ in ("bytes", "string")
                    else []
                    if type_.endswith("[]")
                    else 0
                )
        data = Evaluator(world, identity, assignment)._calldata()
        if not isinstance(data, bytes):
            continue
        answer = world.chain.call(world.this, data, candidate)
        if isinstance(answer, bytes):
            return _argument_values(guess)
    return None


def strangers_run(formula: Term, world: World, witness: dict[str, Any], tries: int | None = None) -> bool:
    """Whether every other stranger's own call goes through on the chain, as ``FRESH``'s did with ``witness``: one
    passing proves little where the caller's address (or the origin a callee reads) feeds arithmetic, so each of
    ``_OTHER_STRANGERS`` must pass too (``_strangers_pass``), with ``FRESH``'s arguments, its own address where they
    held ``FRESH``'s, or a search of its own."""
    for other in _OTHER_STRANGERS:
        own = {k: other if v == FRESH else v for k, v in witness.items()}
        if runs(world, other, own) is not True and _executes(formula, world, other, set(), tries=tries) is None:
            return False
    return True


def runs(world: World, who: int, arguments: dict[str, Any], overrides: dict | None = None) -> bool | None:
    """Whether this function, called by ``who`` with ``arguments`` (by name, as a verdict's witnesses give them; zero
    for the rest) as the chain stands, goes through: an ``eth_call`` of the whole call, with the ether the arguments
    send (``msg.value``, its sender's balance set to it) and storage as ``overrides`` set it (address -> [(slot,
    word)]). ``None`` where that can't be asked (an argument that can't be encoded, a failed read, a node that
    refuses the overrides)."""
    value = arguments.get("msg.value") or 0
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    assignment: dict[Term, Any] = {}
    for parameter in world.parameters:
        if parameter[0] != "arg":
            continue
        type_ = parameter[2]
        default: Any = 0
        if type_ == "bool":
            default = False
        elif type_ in ("bytes", "string"):
            default = b""
        elif type_.endswith("[]"):
            default = []
        assignment[parameter] = arguments.get(parameter[1], default)
    data = Evaluator(world, {"caller": who, "signer": FRESH}, assignment)._calldata()
    if not isinstance(data, bytes):
        return None
    if value:
        send = getattr(world.chain, "call_value", None)
        if send is None:
            return None
        answer = send(world.this, data, who, value, overrides)
    elif overrides:
        answer = world.chain.call(world.this, data, who, overrides)
    else:
        answer = world.chain.call(world.this, data, who)
    if isinstance(answer, bytes):
        return True
    return False if answer is REVERTED else None


def _argument_values(found: dict[Term, Any]) -> dict[str, Any]:
    return {t[1]: v for t, v in found.items() if t[0] == "arg" and t != CALLDATA} | {
        "msg.value": v for t, v in found.items() if t[0] == "callvalue"
    }


_MAX_WHEN = 4
_GATHER_GUESSES = 4
_SEARCH_BATCH = 32  # guesses whose reads go out together
_SOLVER_GIVE_UPS = 3
_LOWEST_SENDER = 2**16
_OTHER_STRANGERS = tuple(FRESH ^ bit for bit in (1, 2, 4, 8))
_STRANGERS = frozenset({FRESH, *_OTHER_STRANGERS})
_CANDIDATE_BATCH = 256  # candidates whose reads are fetched and questions asked together; all are asked in turn
# Where the holder list is unproven (hints, never all) and no state shows a stranger refused, no candidate can be
# singled out and the list can never be complete: asking about candidates can only lengthen an incomplete list. There
# at most ``UNPROVEN_CANDIDATES`` are asked about, the likeliest first, within ``UNPROVEN_READS`` reads, in batches of
# ``UNPROVEN_BATCH`` (a batch's reads go out together, so it overshoots by at most one batch's); the rest are
# reported (``untested_candidates:<n>``). A proven list keeps the whole budget, where completeness is reachable.
UNPROVEN_CANDIDATES = 48
UNPROVEN_READS = 300
UNPROVEN_BATCH = 8
_CALLEE_DEPTH = 3  # contracts deep that callees handed the arguments are read for the keys to try
# Contracts deep that a check handed the caller is followed. Depth is spent only on calls the identity reaches: a
# callee handed none of it is a condition every caller faces alike and is never followed for who may call.
IDENTITY_DEPTH = 4
# Wall-clock budget for one function's decision; past it every open question is answered "unknown".
DECISION_SECONDS = 120.0  # a safety net only: the work budget decides, so a busy machine doesn't change verdicts
# Deterministic effort, a unit being roughly 13ms: every term evaluated or encoded (so a formula a thousand times
# larger runs out a thousand times sooner instead of taking a thousand times as long), z3's own resource count, and a
# little per question asked.
DECISION_WORK = 1200.0
# Whether a self-scoped function's holders go unenumerated (``scope.py``). Off by default: scope and gate are still
# reported, and holders are enumerated as for any function.
SKIP_SELF_SCOPED = os.environ.get("PSAT_LOGIC_SCOPE_SKIP", "0") == "1"
NODE_WORK = 1 / 1000
RLIMIT_PER_WORK = 300_000  # z3 spends about as long on this many units as evaluation does on one work unit
QUESTION_WORK = 0.1
SOLVER_RLIMIT = 2_000_000
_MAX_OWNED_KEYS = 16


def _when_states(when: frozenset) -> list[dict[Term, bool] | None]:
    """Every assignment of the ``when`` conditions; past a few, one state where they are all free (``None``)."""
    if not when:
        return [{}]
    if len(when) > _MAX_WHEN:
        return [None]
    atoms = sorted(when, key=stable)
    return [dict(zip(atoms, values)) for values in itertools.product([False, True], repeat=len(atoms))]


def _hashed_only(formula: Term) -> frozenset:
    """Caller-chosen values that occur only inside hash inputs: a preimage holder can pick them freely."""
    inside: set[tuple] = set()
    outside: set[tuple] = set()
    seen: set[tuple[int, bool]] = set()

    def walk(t: Any, hashed: bool) -> None:
        if (id(t), hashed) in seen:
            return
        seen.add((id(t), hashed))
        if isinstance(t, frozenset):
            for item in t:
                walk(item, hashed)
            return
        if not isinstance(t, tuple) or not t:
            return
        if not isinstance(t[0], str):
            for item in t:
                walk(item, hashed)
            return
        if t[0] in _FREE_KINDS and _caller_chosen(t):
            (inside if hashed else outside).add(t)
            return
        for part in t[1:]:
            walk(part, hashed or t[0] == "hash")

    walk(formula, False)
    return frozenset(inside - outside)


def _outcome(
    formula: Term, world: World, identity: dict[str, int], candidates: set[int], *args: Any, **kwargs: Any
) -> Any:
    """``_decide_one`` with its storage reads and calls fetched in batches first: those of the state as it is, round
    by round until the answer stops asking (each answer can settle a check and spare the rest), then, only if
    arguments must still be guessed, those of the guesses."""
    quiet = {**kwargs, "refute_ok": False, "witness": None}
    world.chain.gather(lambda: _decide_one(formula, world, identity, candidates, *args, **quiet, base_only=True))
    if _decide_one(formula, world, identity, candidates, *args, **quiet, base_only=True) is not UNK:
        return _decide_one(formula, world, identity, candidates, *args, **kwargs)
    # Guesses without the keys recorded in the mappings' histories first (any spender approves): those histories are
    # read only when the guesses need them (a role id from ``RoleGranted``), since a token's is a crowd.
    for recorded_ok in (False, True):
        if recorded_ok and not _keys_chosen(formula, world):
            break
        # A few rounds: a guess's reads can depend on earlier ones (``pools[pid]``, then what that entry points at).
        world.chain.gather(
            lambda: _decide_one(
                formula, world, identity, candidates, *args, **quiet, reads_only=True, recorded_ok=recorded_ok
            ),
            rounds=3,
        )
        answer = _decide_one(formula, world, identity, candidates, *args, **kwargs, recorded_ok=recorded_ok)
        if answer is True:
            break
    return answer


def _decide_one(
    formula: Term,
    world: World,
    identity: dict[str, int],
    candidates: set[int],
    blind: frozenset = frozenset(),
    fixed: dict[Term, bool] | None = None,
    refute_ok: bool = True,
    witness: dict[Term, Any] | None = None,
    relaxed: bool | str = False,
    base_only: bool = False,
    reads_only: bool = False,
    recorded_ok: bool = True,
    bound: tuple[dict, ...] | None = None,
) -> Any:
    """True when some arguments let ``identity`` through, False when none can, else UNK. ``fixed`` sets ``when``
    conditions instead of reading them from state; ``None`` leaves every one of them free. On True, ``witness``
    receives the arguments that did it (empty when any do). ``bound``: the only argument values it can be singled
    out under (``holders``' bindings for it, where a stranger fails), each asked in turn."""
    if bound:
        # A case per binding, the arguments it names fixed: settled exactly, or refuted case by case.
        answers = []
        for binding in bound:
            case = replace_terms(formula, {t: mk("const", v, t[2]) for t, v in binding.items()})
            found: dict[Term, Any] = {}
            answer = _decide_one(
                case,
                world,
                identity,
                candidates,
                blind,
                fixed,
                refute_ok,
                found,
                relaxed,
                base_only,
                reads_only,
                recorded_ok,
            )
            if answer is True:
                if witness is not None:
                    witness.update({**binding, **found})
                return True
            answers.append(answer)
        return False if all(a is False for a in answers) else UNK
    if world.exhausted():
        return UNK
    world.work += QUESTION_WORK
    if fixed is not None:
        free_when = frozenset()
    elif relaxed == "arguments":
        # Only what the arguments decide is left free; stored state (a consumed initializer) reads as it is.
        free_when = relaxed_atoms(formula) - when_atoms(formula)
    elif relaxed == "holdings":
        free_when = (relaxed_atoms(formula) - when_atoms(formula)) | held_atoms(formula)
    elif relaxed:
        free_when = relaxed_atoms(formula)
    else:
        free_when = when_atoms(formula) - world.latched
    if relaxed and free_when:
        free_when = _jointly_freed(formula, free_when)
    if world.records_free and world.records and relaxed != "arguments":
        free_when = free_when | (world.records & _atoms_of(formula))  # see ``decide``: named, never set
    fixed = fixed or {}
    when = frozenset(fixed) | free_when
    base = Evaluator(world, identity, dict(fixed), blind, when)
    # Gathering reads or asking only whether the state settles it: callee code answers as it is (``Evaluator.ranked``).
    passed = world.code_passed
    unknown_args = base.ranked(formula) if base_only or reads_only else base.passes(formula)
    # A pass a callee's code showed whatever the arguments, unknown without it: the likeliest guess alone, asked of the
    # chain first, settles most (one read, before a batch of guesses each asks the chain).
    coded_pass = unknown_args is UNK and world.code_passed > passed
    if unknown_args is UNK and relaxed:
        # Business logic freed: once the identity's own conditions are read, whether the freed ones can let it
        # through is a question of the connectives, not of guessing each one.
        unknown_args = _free_sat(formula, base, free_when)
    if unknown_args is not UNK or base_only:
        return unknown_args
    chosen = free_when | (frozenset(world.arranged) & _atoms_of(formula)) if world.arranged else free_when
    if relaxed:
        # Only what the conditions still read decides: arguments a freed condition alone reads can be anything.
        kept = [a for a in _atoms_of(formula) if a not in free_when]
        chosen = chosen - free_when
        free = sorted(
            _with_encoded({x for a in kept for x in (*subterms(a, "arg"), *_free_compounds(a))}, world), key=stable
        ) + sorted(chosen, key=stable)
    else:
        free = sorted(_with_encoded(set(subterms(formula, "arg")) | _free_compounds(formula), world), key=stable)
        free += sorted(chosen, key=stable)
    owned = _owned_keys(formula, world, identity)
    recorded = _recorded_keys(formula, world) if recorded_ok else {}
    compared = comparands(formula, base, frozenset(free))
    targets = _call_targets(formula, base, frozenset(free))
    # An argument that keys an identity lookup is only worth the keys where that identity is stored, when the
    # history shows any; one that keys any other mapping, first the keys its writers recorded (role ids from
    # ``RoleGranted``).
    domains = [
        [False, True]
        if term in chosen
        else sorted(owned[term])[:_MAX_OWNED_KEYS] + [0]
        if owned.get(term)
        else _first_zero(
            compared.get(term, [])
            + [v for v in identity.values() if isinstance(v, int) and _domain_takes(term, v)]
            + targets.get(term, [])
            + recorded.get(term, [])[:_MAX_OWNED_KEYS]
            + _domain(term, formula, candidates | set(identity.values()))
        )
        for term in free
    ]
    hinted = world.hints.get(identity.get("caller"), ())
    if hinted:
        # The keys the history listed this identity at (an operator's id, a spoke's asset): tried first.
        domains = [list(dict.fromkeys([b[t] for b in hinted if t in b] + d)) for t, d in zip(free, domains)]
    # A guess the argument's type can't hold is no call anyone can make (ABI decoding rejects it).
    domains = [[v for v in domain if _fits(term, v)] for term, domain in zip(free, domains)]
    # What no guessed value feeds is the same under every guess: evaluated once.
    settled = _independent(base, frozenset(free))
    guesses = _ranked_product(domains)

    def search(count: int) -> bool:
        while count > 0:
            batch = list(itertools.islice(guesses, min(count, _SEARCH_BATCH)))
            count -= _SEARCH_BATCH
            if not batch:
                return False
            if not reads_only and len(batch) > 1 and not coded_pass:
                # Their reads in one round trip (each guess may ask the chain about its own keys), then the answers.
                world.chain.gather(lambda: [assess(values) for values in batch], rounds=2)
            for values in batch:
                if world.exhausted():
                    return False
                if assess(values) is True:
                    if witness is not None:
                        witness.update(zip(free, values))
                    return True
        return False

    # A conjunct a guess fails, over the guessed values its evaluation read, fails every guess that agrees on those
    # values (``amount <= balance`` refuting an amount whatever the recipient): such guesses are skipped, not asked
    # again. What was read is what the evaluation consulted, not what the conjunct names: ``msg.data`` reads every
    # argument, and a callee's code reads whatever its frame is handed.
    nogoods: list[tuple] = []
    place = {t: i for i, t in enumerate(free)}

    def assess(values: tuple) -> Any:
        if any(all(values[i] == v for i, v in nogood) for nogood in nogoods):
            return False
        guess = Evaluator(world, identity, {**fixed, **dict(zip(free, values))}, blind, when, settled)
        # A guess a callee's code refuses is skipped, never a refutation: only the solver below answers "nobody".
        answer = guess.ranked(formula)
        if answer is not False:
            return confirmed(guess, formula, free_when if relaxed else None, answer)
        if answer is False and formula[0] == "and" and not world.chain.pending:
            for conjunct in cheapest_first(formula):
                if guess.ranked(conjunct) is not False:
                    continue
                consulted = _Reads({**fixed, **dict(zip(free, values))})
                if Evaluator(world, identity, consulted, blind, when, settled).ranked(conjunct) is False:
                    read = sorted(place[t] for t in consulted.seen if t in place)
                    nogoods.append(tuple((i, values[i]) for i in read))
                break
        return answer

    # The likeliest guesses (zeros, the identity itself, recorded keys) first: they settle most questions outright.
    if reads_only:
        # Gathering reads ahead of the real question: the likeliest few guesses' are what it will want first, and a
        # pass over every candidate can't spend the budget the questions themselves need.
        return True if search(_GATHER_GUESSES) else UNK
    if coded_pass and search(1):
        return True
    if search(_EARLY_GUESSES):
        return True
    # Then the solver, far cheaper than guessing on when nothing passes (a whole domain each argument can't satisfy).
    ground = Evaluator(world, identity, dict(fixed), blind, when)
    if formula[0] == "and":
        # Conjuncts without arithmetic alone may already contradict each other (``0 < amount <= allowance`` with no
        # allowance): a small question that spares z3 the 256-bit sums the rest carry.
        plain = [c for c in formula[1] if not contains(c, _ARITHMETIC)]
        if 0 < len(plain) < len(formula[1]) and solve(mk_and(plain), ground) is None:
            return False if refute_ok else UNK
    solved = solve(formula, ground)
    if solved is None:
        return False if refute_ok else UNK
    if isinstance(solved, dict):
        if witness is not None:
            witness.update(solved)
        return True
    if not refute_ok:
        return UNK
    # Valid whatever the arguments and every unknown are (``(not (a and m) or a) and m`` with ``m`` true).
    return True if solve(mk_not(formula), ground) is None else UNK


_CALL_KINDS = frozenset({"call", "item", "ok", "caught", "retsize"})


def confirmed(ev: Evaluator, formula: Term, free: frozenset | None = None, answer: Any = None) -> Any:
    """``ev``'s answer on ``formula`` (``answer``, when already asked), with the ``free`` atoms left to the
    connectives when given (``_free_sat``). A pass that rests on a followed callee's code standing in for a call over
    guessed arguments is asked again with every such call put to the chain: the code ranks and skips guesses, the
    chain proves the one that passes."""

    def ask(e: Evaluator, given: Any = None) -> Any:
        result = e.truth(formula) if given is None else given
        return _free_sat(formula, e, free) if result is UNK and free is not None else result

    result = ask(ev, answer)
    if result is True and ev.coded[0]:
        # What reads no call is the same however calls are answered: kept, so only the calls are asked again.
        kept = {t: v for t, v in ev._memo.items() if not contains(t, _CALL_KINDS) and t not in ev._coded_terms}
        again = Evaluator(ev.world, ev.identity, ev.assignment, ev.blind, ev.when, kept)
        # No callee code at all: a call whose input isn't known whole is unknown there, never its code's answer again.
        again.code_first = again.callee_code = False
        result = confirming(ev.world, lambda: ask(again))
        if result is UNK:
            ev.world.code_passed += 1
    return result


def confirming(world: World, ask: Callable[[], Any]) -> Any:
    """``ask()``, a pass only a callee's code showed asked again of the chain, within the reads left for that
    (``World.confirm_left``): the reads it sends, or leaves pending for a batch, are spent; none left, it is unknown
    and unasked."""
    chain = world.chain
    if world.confirm_left <= 0:
        world.__dict__["confirm_spent"] = True
        return UNK

    def reads() -> int:
        return chain.sent + (len(chain.pending) if chain.pending is not None else 0)

    before = reads()
    try:
        return ask()
    finally:
        world.confirm_left -= max(reads() - before, 0)


def _decisive(formula: Term, world: World) -> bool:
    """Whether a stranger fails a conjunct that uses the caller only through lookups: every unconfigured address fails
    that conjunct too, whatever the rest of the formula does with the caller."""
    if formula[0] != "and" or world.cover is None:
        return False
    probe = Evaluator(world, {"caller": FRESH, "signer": FRESH})
    for conjunct in formula[1]:
        if not contains(conjunct, IDENTITY_KINDS) or probe.truth(conjunct) is not False:
            continue
        if world.cover(conjunct).representative:
            return True
    return False


def _strangers_allowed(formula: Term, world: World, witness: dict[Term, Any]) -> str | None:
    """``now`` when strangers get through with the records they name as stored, ``later`` when only once such a
    record is in the state they need (a vote open, an operation ready), else ``None``."""
    if world.records:
        world.records_free = False
        try:
            if _strangers_pass(formula, world, witness):
                return "now"
        finally:
            world.records_free = True
        witness.clear()
        return "later" if _strangers_pass(formula, world, witness) else None
    return "now" if _strangers_pass(formula, world, witness) else None


def _strangers_pass(formula: Term, world: World, witness: dict[Term, Any]) -> bool:
    """Whether every stranger gets through now. One passing proves little if the caller's address feeds arithmetic
    (``caller % 3``), so a few with different low bits must all pass."""
    if _outcome(formula, world, {"caller": FRESH, "signer": FRESH}, set(), fixed={}, witness=witness) is not True:
        return False
    return all(
        _outcome(formula, world, {"caller": other, "signer": other}, set(), fixed={}) is True
        for other in _OTHER_STRANGERS
    )


# Conversions that keep every address apart (to an address, a word of 160 bits or more, 20 bytes or more).
_KEEPS_ADDRESSES = re.compile(r"address( payable)?|u?int(16\d|1[7-9]\d|2[0-4]\d|25[0-6])|bytes(2\d|3[0-2])")
# Kinds whose answer, handed an identity, isn't read off the formula: code that runs, an encoding, a hash.
_IDENTITY_OPAQUE = frozenset({"call", "delegate", "hash", "enc", "opaque", "unknown", "assumed"})


def _kept_identity(t: Term) -> bool:
    """Whether ``t`` is the caller (origin, signer) itself, through conversions that keep every address apart."""
    while isinstance(t, tuple) and t and t[0] == "conv":
        if not (isinstance(t[1], str) and _KEEPS_ADDRESSES.fullmatch(t[1])):
            return False
        t = t[2]
    return isinstance(t, tuple) and bool(t) and t[0] in IDENTITY_KINDS


def _alike_for_strangers(formula: Term, world: World) -> bool:
    """Whether every unconfigured address meets ``formula`` as ``FRESH`` does, by its form alone: the caller (origin,
    signer) appears only as a mapping key, or as one side of an equality whose other side no identity reaches (or is
    that same identity: never the origin against the caller), each through conversions that keep every address
    apart; no call, hash or encoding is handed it; no view call reaches code reading ``tx.origin``; no unknown may
    single anyone out. An unconfigured address holds no entry and equals
    no address the contract names, so each such reading is the same for every one of them. Anything else
    (``uint160(msg.sender) % 10 != 0``, an ordering of addresses, a callee handed the caller) is met at the five
    strangers only as a sample (``Verdict.witnessed``)."""
    if any(not singles_out_nobody(u) for u in subterms(formula, "unknown")) or subterms(formula, "delegate"):
        return False
    memo: dict[int, bool] = {}

    def items(t: Any) -> list:
        # A term's operands, through the plain tuples and sets that hold several (a lookup's path, a call's arguments).
        out: list = []
        for x in t[1:]:
            if isinstance(x, frozenset) or (isinstance(x, tuple) and x and not isinstance(x[0], str)):
                out.extend(y for y in x if isinstance(y, tuple))
            elif isinstance(x, tuple) and x:
                out.append(x)
        return out

    def alike(t: Any) -> bool:
        if not isinstance(t, tuple) or not t or not isinstance(t[0], str) or not contains(t, IDENTITY_KINDS):
            return True
        if id(t) in memo:
            return memo[id(t)]
        kind = t[0]
        if kind in IDENTITY_KINDS or kind in _IDENTITY_OPAQUE:
            answer = False  # an identity's value itself, or handed to what isn't read off the formula
        elif kind == "load":
            answer = not contains(t[1], IDENTITY_KINDS) and all(
                _kept_identity(step) or alike(step) for _, step in t[3] if isinstance(step, tuple)
            )
        elif kind == "cmp" and t[1] == "eq":
            a, b = t[2], t[3]
            if _kept_identity(a) or _kept_identity(b):
                mine, other = (a, b) if _kept_identity(a) else (b, a)
                if _kept_identity(other):
                    # ``msg.sender == msg.sender`` holds for everyone; ``msg.sender == tx.origin`` only for a
                    # stranger calling from its own account, never a contract it calls through.
                    answer = _strip_conv(mine) == _strip_conv(other)
                else:
                    answer = not contains(other, IDENTITY_KINDS)
            else:
                answer = alike(a) and alike(b)
        else:
            answer = all(not _kept_identity(x) and alike(x) for x in items(t))
        memo[id(t)] = answer
        return answer

    return alike(formula) and _origin_unread(formula, world, 0)


def _origin_unread(term: Term, world: World, depth: int) -> bool:
    """Whether no view call in ``term`` that no identity is handed to may reach code reading ``tx.origin``, shown:
    ``World.caller_bound`` where supplied, else each callee lowered and read, a few contracts deep. A callee not
    followed, or past that depth, may read it."""
    if world.caller_bound is not None:
        return not _reads_origin(term, world, depth)
    for call in subterms(term, "call"):
        if not call[4] or any(contains(a, IDENTITY_KINDS) for a in call[3]):
            continue
        lowered = world.callee(call) if depth < IDENTITY_DEPTH else None
        if lowered is None:
            return False
        parts = [p for p in (lowered[0], *lowered[1]) if isinstance(p, tuple)]
        if any(contains(p, frozenset({"origin"})) or not _origin_unread(p, world, depth + 1) for p in parts):
            return False
    return True


def _prefetch(formula: Term, world: World, candidates: set[int]) -> None:
    """Fetch, in one batch, every identity-keyed storage slot and identity-argument view call the candidates need."""
    loads = [t for t in subterms(formula, "load") if contains(t, IDENTITY_KINDS)]
    calls = [t for t in subterms(formula, "call") if t[4] and any(contains(a, IDENTITY_KINDS) for a in t[3])]
    if not loads and not calls:
        return

    def requested() -> list:
        requests = []
        for candidate in [*sorted(candidates), FRESH]:
            if world.exhausted():
                break
            for identity in ({"caller": candidate, "signer": FRESH}, {"caller": FRESH, "signer": candidate}):
                probe = Evaluator(world, identity)
                for t in loads:
                    cell = probe.storage_cell(t)
                    if cell is not None:
                        requests.append(world.chain.storage_request(cell[0], cell[1]))
                for t in calls:
                    call = probe.call_input(t)
                    sender = probe.sender(t)
                    if call is not None and sender is not UNK:
                        requests.append(world.chain.call_request(call[0], call[1], sender))
        return requests

    # The keys and arguments themselves may need reads (a call's argument read from another call): batched first,
    # off the decision's budget, which the questions themselves need.
    spent = world.work
    world.chain.gather(requested, rounds=3)
    world.work = spent
    world.chain.prefetch(requested())


def _chosen_steps(path: tuple) -> list[Term]:
    """The keys of ``path`` that are caller-chosen arguments, as passed (``lenderAllowlist[pm][address(receiver)]``)."""
    return [
        key
        for kind, step in path
        if kind == "k"
        for key in (_strip_conv(step),)
        if key[0] in _FREE_KINDS and _caller_chosen(key)
    ]


def _keys_chosen(formula: Term, world: World) -> bool:
    """Whether a caller-chosen argument keys a mapping ``formula`` or its callees read: where ``_recorded_keys`` has
    words to add."""
    for part in _with_callees(formula, world, _FREE_KINDS):
        for t in subterms(part, "load"):
            if _chosen_steps(_named_lookup(t[2], t[3])[1]):
                return True
    return False


def _recorded_keys(formula: Term, world: World) -> dict[Term, list[int]]:
    """For each caller-chosen argument that keys a mapping, the words its writers' events recorded, likeliest first:
    those of the logs naming the read's other keys (this pool's lenders, not every pool's), and words its type can be
    an address in before small ones. A mapping another contract's check reads counts too (a pool's lender,
    allowlisted in its permission manager)."""
    if world.recorded is None:
        world.recorded = {}
        probe = Evaluator(world, {"caller": FRESH, "signer": FRESH})
        loads = {t for part in _with_callees(formula, world, _FREE_KINDS) for t in subterms(part, "load")}
        for t in sorted(loads, key=stable):
            var, path = _named_lookup(t[2], t[3])
            keys = _chosen_steps(path)
            if not keys:
                continue
            address = probe.eval(t[1])
            if not isinstance(address, int) or isinstance(address, bool):
                continue
            others = {
                v % 2**256
                for kind, step in path
                if kind == "k" and _strip_conv(step) not in keys
                for v in (probe.eval(step),)
                if isinstance(v, int) and not isinstance(v, bool)
            }
            logs = world.chain.logs(address, world.writer_topics(address, var))
            named = [[*topics[1:], *data] for topics, data in logs if others & {*topics[1:], *data}]
            rest = [[*topics[1:], *data] for topics, data in logs]
            for key in keys:
                found = world.recorded.setdefault(key, [])
                had = set(found)
                address_like = _fits(key, 2**159) and not _fits(key, 2**160)
                for group in (named, rest):
                    words = {w for log in group for w in log} - had
                    found.extend(sorted(words, key=lambda w: (not (address_like and _LOWEST_SENDER <= w < 2**160), w)))
                    had |= words
    return world.recorded


def _owned_keys(formula: Term, world: World, identity: dict[str, int]) -> dict[Term, set[int]]:
    """For ``identity == m[arg]``: the keys at which the identity is the value, as values to try for ``arg``."""
    out: dict[Term, set[int]] = {}
    probe = Evaluator(world, identity)
    for t in subterms(formula, "cmp"):
        if t[1] != "eq":
            continue
        for side, other in ((t[2], t[3]), (t[3], t[2])):
            if not _is_identity(side) or other[0] != "load":
                continue
            keys = [step for kind, step in other[3] if kind == "k"]
            free = [k for k in keys if k[0] in _FREE_KINDS and _caller_chosen(k)]
            address, who = probe.eval(other[1]), probe.eval(side)
            if len(free) != 1 or not isinstance(address, int) or not isinstance(who, int):
                continue
            # Named as its writers name it: a namespaced root's first field (``$.nodeOperators[id].manager``).
            var, path = _named_lookup(other[2], other[3])
            fields = tuple(step for kind, step in path if kind == "f")
            out.setdefault(free[0], set()).update(world.inverse(address, var, fields, who, proof=False) or ())
    return out


def _with_encoded(free: set[Term], world: World) -> set[Term]:
    """``free`` with every argument of the function where it holds ``msg.data``, which encodes them all: what such a
    guess passes along is the whole call, so each of them is guessed with it."""
    if CALLDATA not in free and not any(t[0] == "calldatasize" for t in free):
        return free
    return free | {p for p in world.parameters if p[0] == "arg"}


def _free_compounds(formula: Term) -> set[Term]:
    out: set[Term] = set()
    for kind in ("len", "elem", "callvalue", "calldatasize"):
        out.update(t for t in subterms(formula, kind) if _caller_chosen(t))
    # The length of a dynamic argument inside an encoding whose length is checked.
    for t in subterms(formula, "len"):
        if t[1][0] == "enc":
            out.update(mk("len", a) for a in t[1][2] if a[0] == "arg" and _dynamic(a[2]))
    return out


def _dynamic(type_: str) -> bool:
    return type_ in ("bytes", "string") or type_.endswith("[]")


def _first_zero(values: list[Any]) -> list[Any]:
    """The neutral value first (an amount of 0 passes most balance checks), then the rest in order, once each: the
    caller's own address next, which no list (a blacklist, a frozen set) names unless it names the caller."""
    is_zero = [v == 0 and not isinstance(v, bool) for v in values]
    head = [0] if any(is_zero) else []
    return head + list(dict.fromkeys(v for v, z in zip(values, is_zero) if not z))


def _domain_takes(term: Term, value: int) -> bool:
    """Whether an identity's address is a value of ``term``'s type (an address or a full word)."""
    type_ = term[2] if term[0] == "arg" else ""
    return type_.startswith("address") or type_ in ("uint256", "bytes32")


def _independent(evaluator: Evaluator, free: frozenset) -> dict[Term, Any]:
    """The evaluator's values of terms none of ``free`` occurs in."""
    varies: dict[int, bool] = {}

    def walk(t: Any) -> bool:
        if isinstance(t, frozenset):
            return any([walk(x) for x in t])
        if not isinstance(t, tuple) or not t:
            return False
        key = id(t)
        if key not in varies:
            varies[key] = t in free or any([walk(x) for x in (t[1:] if isinstance(t[0], str) else t)])
        return varies[key]

    return {t: v for t, v in evaluator._memo.items() if not walk(t) and t not in evaluator._coded_terms}


def _ranked_product(domains: list[list[Any]]) -> Iterator[tuple]:
    """Every combination, those whose values sit earliest in their domains first, so a budget spent on guesses goes
    to each argument's likeliest values together instead of the last argument's whole domain."""
    if any(not d for d in domains):
        return
    if not domains:
        yield ()
        return
    sizes = [len(d) for d in domains]

    def ranks(i: int, left: int) -> Iterator[tuple[int, ...]]:
        if i == len(sizes) - 1:
            if left < sizes[i]:
                yield (left,)
            return
        for r in range(min(left, sizes[i] - 1) + 1):
            for rest in ranks(i + 1, left - r):
                yield (r, *rest)

    for total in range(sum(sizes) - len(sizes) + 1):
        for index in ranks(0, total):
            yield tuple(d[r] for d, r in zip(domains, index))


def _small(value: Any, low: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and low < value < 2**20


def _caller_chosen(t: tuple) -> bool:
    """Arguments, their lengths and elements, and msg.value: what the caller picks. A memory array's contents aren't."""
    while t[0] in ("len", "elem"):
        t = t[1]
    return t[0] in ("arg", "callvalue", "calldatasize")


def _domain(term: Term, formula: Term, addresses: set[int]) -> list[Any]:
    type_ = term[2] if term[0] == "arg" else "uint256"
    if type_ == "bool":
        return [False, True]
    if term[0] == "len":
        return [0, 1, 2]
    if term[0] == "calldatasize":
        # At least the arguments' encoding, and any longer: the caller can append bytes.
        lengths = {term[1], term[1] + 1, term[1] + 32}
        lengths.update(c[1] + d for c in subterms(formula, "const") for d in (-1, 0, 1) if _small(c[1], term[1]))
        return sorted(lengths)
    numbers = {0, 1, 2}
    for c in subterms(formula, "const"):
        if isinstance(c[1], int) and not isinstance(c[1], bool):
            numbers.update({c[1], c[1] + 1, max(c[1] - 1, 0)})
    if type_.startswith("address"):
        return sorted(addresses | {0})
    return sorted(numbers | addresses | {2**256 - 1})


def comparands(formula: Term, ground: Evaluator, free: frozenset) -> dict[Term, list[int]]:
    """For each caller-chosen term compared with something it can't change (``deadline >= block.timestamp``,
    ``signature.length == 65``, ``nonce == nonces[owner]``): that value and its neighbours, the guesses most likely to
    meet the comparison either way. A value an equality names comes first, since only it can meet it; an
    inequality's value and neighbours follow in order, each as likely as the next."""
    equal: dict[Term, list[int]] = {}
    near: dict[Term, set[int]] = {}
    for t in subterms(formula, "cmp"):
        for side, other in ((t[2], t[3]), (t[3], t[2])):
            if side not in free or contains(other, _FREE_KINDS | IDENTITY_KINDS | {"unknown"}):
                continue
            value = ground.eval(other)
            if isinstance(value, int) and not isinstance(value, bool):
                if t[1] == "eq":
                    equal.setdefault(side, []).append(value % 2**256)
                near.setdefault(side, set()).update(v % 2**256 for v in (value, value + 1, value - 1))
    return {side: list(dict.fromkeys(sorted(set(equal.get(side, ()))) + sorted(near[side]))) for side in near}


_HELD_ADDRESSES = 16  # addresses the code holds, tried for an address the caller picks to be called


def _call_targets(formula: Term, ground: Evaluator, free: frozenset) -> dict[Term, list[int]]:
    """For each caller-chosen address a call is made to (``_core.isGovernor(caller)``): the contracts the formula
    calls at addresses the caller can't change, those asked the same question first, then the addresses it holds
    (an implementation slot, an immutable): what it names is a contract to ask, and those are the contracts the code
    already knows."""
    calls = subterms(formula, "call")
    fixed = _FREE_KINDS | IDENTITY_KINDS | {"unknown"}
    held: list[int] | None = None
    out: dict[Term, list[int]] = {}
    for call in calls:
        target = _strip_conv(call[1])
        if target not in free:
            continue
        found: list[int] = []
        for other in sorted(calls, key=lambda c: (c[2] != call[2], stable(c))):
            if contains(other[1], fixed):
                continue
            value = ground.eval(other[1])
            if isinstance(value, int) and not isinstance(value, bool) and value % 2**160 not in found:
                found.append(value % 2**160)
        if held is None:
            held = []
            stored = [t for kind in ("load", "rawload", "immutable") for t in subterms(formula, kind)]
            for t in sorted(stored, key=stable):
                if contains(t, fixed):
                    continue
                value = ground.eval(t)
                if isinstance(value, int) and not isinstance(value, bool) and _LOWEST_SENDER <= value < 2**160:
                    held.append(value)
                if len(held) >= _HELD_ADDRESSES:
                    break
        found.extend(v for v in held if v not in found)
        out.setdefault(target, []).extend(v for v in found if v not in out.get(target, []))
    return out


def _exact_bindings(world: World, candidate: int) -> tuple[dict, ...] | None:
    """The builder's bindings for ``candidate`` when each names its arguments (none is "any")."""
    bindings = world.hints.get(candidate)
    if not bindings or any(not b for b in bindings):
        return None
    return tuple(bindings)


def _unlisted(world: World, contract_term: Term, var: Any) -> tuple[set[int], str]:
    """For a lookup the events don't list whole: the addresses its writers' logs name (and the constructor's keys a
    creating trace showed), else, where it has no writer events at all, the address-shaped words of all its
    contract's logs; with why it isn't whole. A writer history read partial is reported as cut and stands as read:
    what it names is a lower bound, and another contract-wide sample in its place would be no more the list."""
    probe = Evaluator(world, {"caller": FRESH, "signer": FRESH})
    address = probe.eval(contract_term)
    name = f"namespaced:{var[-1]}" if isinstance(var, tuple) else f"storage:{var}"
    if not isinstance(address, int) or isinstance(address, bool):
        return set(), name
    events = world.writer_events(address, var)
    found = set(world.chain.log_addresses(address, events)) if events else set()
    found |= world.created.get(address, set())
    topics = frozenset("0x" + format(t, "064x") for t in events)
    cut = bool(events) and world.chain.cut(address, topics)
    if not found and not cut:
        found = {w for w in world.chain.all_log_words(address) if 2**150 <= w < 2**160}
        cut = address in world.chain.truncated
    if cut:
        world.cut.add(address)
    return found, "history_truncated" if cut else name


def _built(formula: Term, world: World) -> tuple[set[int], bool, list[str]]:
    """The callers the identity checks may single out (``holders.listed``), with the bindings each may pass under
    kept as hints for the search: (them, whether they're shown to be all, why not). When the checks leave everyone,
    the addresses likely among them (a lookup's log words, the code's constants), not shown to be all."""
    from .holders import _join, listed

    roots = [listed(formula, world)]
    if contains(formula, frozenset({"signer"})):
        roots.append(listed(formula, world, "signer"))
    who = roots[0]
    for other in roots[1:]:
        # Either root's list: complete only when both are.
        who = _join(who, other)
    proven = who.finite
    found = set(who.members) if who.finite else set(who.hints)
    members = {m for m in found if m >= _LOWEST_SENDER} - {FRESH}
    why = [] if proven else sorted(who.why) or ["unlisted"]
    # Every member is asked about, the likeliest first, so a budget that runs out leaves the unlikeliest untested
    # (and says how many): named by the code, then by the sources naming fewest (a role's 31 over a lender list's 277).
    fewest: dict[int, int] = {}
    for group in who.groups:
        for c in group:
            fewest[c] = min(fewest.get(c, len(group)), len(group))
    world.ranking = {c: (c not in world.named, fewest.get(c, len(members)), c) for c in members}
    hinted: dict[int, list[dict]] = {}
    for member, binding in sorted(who.hinted, key=repr) if not who.finite else ():
        hinted.setdefault(member, []).append(dict(binding))
    world.hints = dict(who.members) if who.finite else {m: tuple(b) for m, b in hinted.items()}
    return members, proven, why


def gate_of(formula: Term) -> tuple[str, ...]:
    """What a caller must satisfy, as read (``report.render``): every conjunct of ``formula`` but the pure ``when``
    conditions (a pause, a deadline: none reads what the caller sends), which hold for everyone alike."""
    from .report import render

    when = frozenset(a for a in when_atoms(formula) if not contains(a, _FREE_KINDS))
    parts = formula[1] if formula[0] == "and" else (formula,)
    kept = [c for c in parts if c not in when and not (c[0] == "not" and c[1] in when)]
    return tuple(sorted(render(c) for c in kept))


def _ranked(candidates: set[int], world: World) -> list[int]:
    """``candidates`` in the order they are asked about (see ``_built``)."""
    return sorted(candidates, key=lambda c: world.ranking.get(c, (True, len(candidates), c)))


_SHARE = 0.5  # of the work left, the most one candidate's questions may spend
_MIN_SHARE = 10.0
_SCREEN_WORK = 100.0  # evaluation the screen of the candidates may spend, off the decision's own budget


def _screened(formula: Term, world: World, candidates: set[int], loosened: frozenset) -> list[int]:
    """``candidates`` in the order they are asked about, by what the state as it stands says of each: first those
    it already lets through (the formula, or it with every condition not about who calls freed), then those it
    leaves open, then those it refuses; within each, those holding more of the formula's lookups keyed by who calls
    (an entry, a balance, an allowance: nonzero), then ``_ranked``'s order. The screen reads nothing new: what the
    chain hasn't answered yet (a candidate not prefetched) reads unknown, so it costs no read the questions wouldn't
    make, and leaves no trace (``detached``): what it evaluated is remembered nowhere the questions read. The order
    only: every candidate is asked about in turn."""
    ranked = _ranked(candidates, world)
    if len(ranked) < 2:
        return ranked
    keyed = [t for t in subterms(formula, "load") if contains(t, IDENTITY_KINDS)]
    keyed += [t for t in subterms(formula, "call") if t[4] and any(contains(a, IDENTITY_KINDS) for a in t[3])]
    screen: dict[int, tuple[int, int]] = {}
    spent = world.work

    def look(chunk: list[int]) -> None:
        for candidate in chunk:
            if world.work - spent > _SCREEN_WORK:
                return  # the rest keep ``_ranked``'s order, among those the screen left open
            identity = {"caller": candidate, "signer": FRESH}
            try:
                exact = Evaluator(world, identity).ranked(formula)
                loose = Evaluator(world, identity, {}, frozenset(), loosened).ranked(formula)
                probe = Evaluator(world, identity)
                held = 0
                for t in keyed:
                    value = probe.eval(t)
                    held += isinstance(value, int) and not isinstance(value, bool) and value != 0
            except Offline:
                continue  # it needs a read not made yet: left where ``_ranked`` puts it, among the open ones
            screen[candidate] = (0 if True in (exact, loose) else 2 if loose is False else 1, -held)

    with detached(world):
        look(ranked)
    place = {c: i for i, c in enumerate(ranked)}
    return sorted(ranked, key=lambda c: (screen.get(c, (1, 0)), place[c]))


@contextlib.contextmanager
def detached(world: World) -> Iterator[None]:
    """A block that evaluates anything and leaves no trace: the chain reads nothing (``Chain.offline``), and the
    world and chain are put back as they were, every memo, count and budget (``solver_record``, ``_brought``,
    ``work``, ``code_refuted``, ``truncated``, ``failed``) included, so nothing remembered from it, an unknown read
    among them, reaches a later question."""
    chain = world.chain
    saved, saved_chain, memo = dict(world.__dict__), dict(chain.__dict__), chain._memo
    world.__dict__.update({k: _copied(v) for k, v in saved.items()})
    chain.__dict__.update({k: _copied(v) for k, v in saved_chain.items() if k != "_memo"})
    chain._memo = dict(memo)
    chain.offline = True
    try:
        yield
    finally:
        world.__dict__.clear()
        world.__dict__.update(saved)
        chain.__dict__.clear()
        chain.__dict__.update(saved_chain)


def _copied(value: Any) -> Any:
    """A container's copy deep enough that changing what it holds (a solver record's counts) leaves the original."""
    if isinstance(value, dict):
        return {k: list(v) if isinstance(v, list) else set(v) if isinstance(v, set) else v for k, v in value.items()}
    if isinstance(value, (set, list)):
        return type(value)(value)
    return value


def _requirements(formula: Term, world: World) -> tuple:
    """The holdings the arranged conditions of ``formula`` ask the caller for (``world.requirements``), each with
    the least amount that passes: ``0 < balanceOfAt(caller, ...)`` asks for any, ``balance >= amount`` for what the
    caller's own argument names, ``votes >= proposalThreshold`` for that number now."""
    atoms = _atoms_of(formula)
    negated = {c[1] for c in (formula[1] if formula[0] == "and" else (formula,)) if c[0] == "not"}
    probe = Evaluator(world, {"caller": FRESH, "signer": FRESH})
    out: set = set()
    calls = frozenset(subterms(formula, "call"))
    for atom, held in world.requirements.items():
        if isinstance(held, tuple) and atom in calls:
            # An action that takes what the caller holds: as much as the caller's own arguments ask.
            target, names = held
            out.update((target, name, "chosen") for name in names)
            continue
        if atom not in atoms:
            continue
        need = _least_held(atom, frozenset(held), probe, atom in negated)
        if need is None:
            continue
        for h in held:
            where = probe.eval(h[1]) if h[0] == "call" else world.this
            what = h[2] if h[0] == "call" else str(_named_lookup(h[2], h[3])[0])
            out.add((where if isinstance(where, int) and not isinstance(where, bool) else None, what, need))
    return tuple(sorted(out, key=repr))


def _least_held(atom: Term, held: frozenset, probe: "Evaluator", negated: bool) -> Any:
    """The least holding ``atom`` lets through, when it is a lower bound on one: ``"any"`` (more than zero),
    ``"chosen"`` (bounded by the caller's own arguments), a number, or ``None`` (an upper bound, an equality)."""
    if atom[0] != "cmp" or atom[1] not in ("lt", "le"):
        return None
    op, low, high = atom[1], atom[2], atom[3]
    if negated:
        # ``!(held < t)`` is ``t <= held``; ``!(held <= t)`` is ``t < held``.
        op, low, high = ("le" if op == "lt" else "lt"), high, low
    if not any(contains_term(high, h) for h in held) or any(contains_term(low, h) for h in held):
        return None
    if any(_caller_chosen(t) for kind in _FREE_KINDS for t in subterms(low, kind)):
        return "chosen"
    bound = probe.eval(low)
    if not isinstance(bound, int) or isinstance(bound, bool):
        return "unknown"
    least = bound + 1 if op == "lt" else bound
    return "any" if least <= 1 else least


def contains_term(term: Term, part: Term) -> bool:
    """Whether ``part`` occurs in ``term``."""
    seen: set[int] = set()
    stack = [term]
    while stack:
        t = stack.pop()
        if t == part:
            return True
        if not isinstance(t, (tuple, frozenset)) or id(t) in seen:
            continue
        seen.add(id(t))
        stack.extend(c for c in t if isinstance(c, (tuple, frozenset)))
    return False


def _atoms_of(formula: Term) -> frozenset:
    """The boolean conditions ``formula`` combines with and/or/not/ite, remembered on the term."""
    cache = formula.__dict__ if isinstance(formula, Term) else None
    if cache is not None and "_atoms" in cache:
        return cache["_atoms"]
    out: set[Term] = set()
    seen: set[int] = set()
    stack = [formula]
    while stack:
        t = stack.pop()
        if id(t) in seen:
            continue
        seen.add(id(t))
        if t[0] in ("and", "or"):
            stack.extend(t[1])
        elif t[0] == "not":
            stack.append(t[1])
        elif t[0] == "ite":
            stack.extend(t[1:])
        elif t[0] != "const":
            out.add(t)
    result = frozenset(out)
    if cache is not None:
        cache["_atoms"] = result
    return result


_FREE_SAT_MS = 200  # z3's time for one propositional question over freed atoms


def _free_sat(formula: Term, ev: "Evaluator", free: frozenset) -> Any:
    """Whether some values of the ``free`` atoms make ``formula`` true, the rest read by ``ev``: a question of the
    connectives alone, each free atom any value of its own (what business logic decides, freed). True only when no
    atom outside ``free`` is left unread; False when no values at all, even of those, make it true."""
    import z3

    atoms: dict[Term, Any] = {}
    unread = [False]
    memo: dict[int, Any] = {}

    def enc(t: Term) -> Any:
        if id(t) in memo:
            return memo[id(t)]
        kind = t[0]
        if kind in ("and", "or"):
            parts = [enc(x) for x in t[1]]
            out = z3.And(parts) if kind == "and" else z3.Or(parts)
        elif kind == "not":
            out = z3.Not(enc(t[1]))
        elif kind == "ite":
            out = z3.If(enc(t[1]), enc(t[2]), enc(t[3]))
        else:
            value = ev.truth(t)
            if value is True or value is False:
                out = z3.BoolVal(value)
            else:
                if t not in free:
                    unread[0] = True
                if t not in atoms:
                    atoms[t] = z3.Bool(f"a{len(atoms)}")
                out = atoms[t]
        memo[id(t)] = out
        return out

    try:
        encoded = enc(formula)
    except (RecursionError, z3.Z3Exception):
        return UNK
    solver = z3.Solver()
    solver.set("timeout", _FREE_SAT_MS)
    solver.add(encoded)
    answer = solver.check()
    if answer == z3.unsat:
        return False
    if answer == z3.sat and not unread[0]:
        return True
    return UNK


def _may_single_out(formula: Term, world: World, depth: int = 0) -> bool:
    """Whether who calls can matter: the caller or signer appears, other than as an argument of a view call whose code,
    lowered over its arguments, doesn't use it either (Maple's ``canCall(id, msg.sender, data)`` checking only the
    deposit's receiver), a followed callee reads ``tx.origin`` (the caller's, whatever it is handed), or something
    unknown appears that the lowering didn't mark as the same for everyone. Remembered per world, unless a callee's
    address was still unread (asked again once it is); a "no" resting on a callee's code is remembered with the calls
    it rests on (``_singling_code``)."""
    memo = world.__dict__.setdefault("_singling", {})
    key = (formula, depth)
    if key in memo:
        return memo[key][0]
    unread: list[bool] = []
    coded: list[str] = []
    answer = _singles_out(formula, world, depth, unread, coded)
    if not unread:
        memo[key] = (answer, tuple(dict.fromkeys(coded)) if not answer else ())
    return answer


def _singling_code(formula: Term, world: World) -> tuple[str, ...]:
    """The signatures of the calls handed the caller whose code alone says ``formula`` singles out nobody."""
    if _may_single_out(formula, world):
        return ()
    held = world.__dict__.get("_singling", {}).get((formula, 0))
    return held[1] if held is not None else ()


def _singles_out(formula: Term, world: World, depth: int, unread: list[bool], coded: list[str]) -> bool:
    if any(not singles_out_nobody(u) for u in subterms(formula, "unknown")):
        return True
    calls = [c for c in subterms(formula, "call") if any(contains(a, IDENTITY_KINDS) for a in c[3])]
    outside = replace_terms(formula, {c: mk("const", 0, "uint256") for c in calls})
    if contains(outside, IDENTITY_KINDS) or contains(formula, frozenset({"signer"})):
        return True
    for call in calls:
        if not call[4] or contains(call[1], IDENTITY_KINDS) or depth >= IDENTITY_DEPTH:
            return True  # an action, or a check on a contract the caller picks
        lowered = world.callee(call)
        if lowered is None:
            unread.append(True)
            return True
        if any(isinstance(p, tuple) and _may_single_out(p, world, depth + 1) for p in (lowered[0], *lowered[1])):
            return True
        # Its code, handed the caller, reads it alike for everyone: that rests on the code alone.
        coded.append(call[2])
    return _reads_origin(formula, world, depth)


def _reads_origin(term: Term, world: World, depth: int) -> bool:
    """Whether a view call in ``term`` that no identity is handed to reaches code reading ``tx.origin``, through
    followed callees a few contracts deep: as ``World.caller_bound`` says (which asks the callee's runtime code too,
    and names a call whose code it can't show reads nothing of the origin), where it is supplied."""
    if world.caller_bound is not None:
        return any(
            call[4] and not any(contains(a, IDENTITY_KINDS) for a in call[3]) and world.caller_bound(call) is not None
            for call in subterms(term, "call")
        )
    if depth >= IDENTITY_DEPTH:
        return False
    for call in subterms(term, "call"):
        if not call[4] or any(contains(a, IDENTITY_KINDS) for a in call[3]):
            continue
        lowered = world.callee(call)
        if lowered is None:
            continue
        parts = [p for p in (lowered[0], *lowered[1]) if isinstance(p, tuple)]
        if any(contains(p, frozenset({"origin"})) or _reads_origin(p, world, depth + 1) for p in parts):
            return True
    return False


def _with_callees(formula: Term, world: World, kinds: frozenset) -> list[Term]:
    """``formula``, and the code of the view calls it makes on values of ``kinds`` (the caller, the arguments), in
    this call's terms: a check another contract makes (``manager.canCall(msg.sender, msg.data[4:])``) reads storage
    and is keyed as this contract's own would be. A few contracts deep."""
    out: list[Term] = [formula]
    seen: set[Term] = set()
    frontier = [(formula, 0)]
    limit = IDENTITY_DEPTH if kinds <= IDENTITY_KINDS else _CALLEE_DEPTH
    while frontier:
        term, depth = frontier.pop()
        if depth >= limit:
            continue
        for call in subterms(term, "call"):
            if call in seen or not any(contains(a, kinds) for a in call[3]):
                continue
            seen.add(call)
            lowered = world.callee(call)
            if lowered is None:
                continue
            for part in (lowered[0], *lowered[1]):
                if isinstance(part, tuple) and part and isinstance(part[0], str):
                    out.append(part)
                    frontier.append((part, depth + 1))
    return out


def _identity_atoms(formula: Term) -> frozenset:
    """The boolean conditions that involve the caller or signer: ``relaxed_atoms``' complement."""
    out: set[Term] = set()
    seen: set[int] = set()

    def walk(t: Term) -> None:
        if id(t) in seen:
            return
        seen.add(id(t))
        if t[0] in ("and", "or"):
            for item in t[1]:
                walk(item)
        elif t[0] == "not":
            walk(t[1])
        elif t[0] == "ite":
            for part in t[1:]:
                walk(part)
        elif _names_identity(t):
            out.add(t)

    walk(formula)
    return frozenset(out)


def _hash_inputs(key: Term) -> list[Term]:
    """The inputs of a hashed key, packed or not (``keccak256(abi.encodePacked(who, app, role))``)."""
    if key[0] != "hash":
        return []
    return [x for i in key[2] for x in (i[2] if i[0] == "enc" else (i,))]


def _chosen_reads(atom: Term) -> frozenset:
    """The values the caller chooses that ``atom`` reads: its arguments, the ether it sends, the call data's size."""
    return frozenset(x for kind in ("arg", "callvalue", "calldatasize") for x in subterms(atom, kind))


def _jointly_freed(formula: Term, free: frozenset) -> frozenset:
    """``free`` less every condition reading a value the caller chooses that a condition kept reads too: a condition
    on an argument is set aside only with every other condition on that argument, never on its own while the same
    argument is chosen to satisfy the rest (``a > 0`` freed while ``balance >= a`` is met with ``a = 0``)."""
    kept: set[Term] = set()
    for atom in _atoms_of(formula):
        if atom not in free:
            kept |= _chosen_reads(atom)
    if not kept:
        return free
    out = set(free)
    changed = True
    while changed:
        changed = False
        for atom in sorted(out, key=stable):
            reads = _chosen_reads(atom)
            if reads & kept:
                out.discard(atom)
                kept |= reads
                changed = True
    return frozenset(out)


def relaxed_atoms(formula: Term) -> frozenset:
    """Every boolean condition that doesn't involve the caller or signer, arguments and unknowns included: what
    business logic decides, left free when asking only whether an identity is singled out."""
    out: set[Term] = set()
    seen: set[int] = set()

    def walk(t: Term) -> None:
        if id(t) in seen:
            return
        seen.add(id(t))
        if t[0] in ("and", "or"):
            for item in t[1]:
                walk(item)
        elif t[0] == "not":
            walk(t[1])
        elif t[0] == "ite":
            for part in t[1:]:
                walk(part)
        elif t[0] != "const" and not _names_identity(t):
            out.add(t)

    walk(formula)
    return frozenset(out)


def held_atoms(formula: Term) -> frozenset:
    """Conditions on amounts in the identity's own entries (``shares + amount <= cap`` of
    ``_spokes[asset][caller]``): arithmetic over what it holds, not a test of who it is. An equality naming the
    identity itself (``caller == owner + 0``) stays one."""
    return frozenset(
        a
        for a in _identity_atoms(formula)
        if contains(a, frozenset({"op"}))
        and not (a[0] == "cmp" and a[1] == "eq" and (_is_identity(a[2]) or _is_identity(a[3])))
    )


def _names_identity(t: Any) -> bool:
    """Whether the caller or signer appears in ``t`` other than inside an opaque value (where it only may matter)."""
    if isinstance(t, frozenset):
        return any(_names_identity(x) for x in t)
    if not isinstance(t, tuple) or not t:
        return False
    cache = t.__dict__ if isinstance(t, Term) else None
    if cache is not None and "_names_identity" in cache:
        return cache["_names_identity"]
    if isinstance(t[0], str):
        if t[0] in IDENTITY_KINDS:
            result = True
        elif t[0] == "opaque":
            result = False
        else:
            result = any(_names_identity(x) for x in t[1:])
    else:
        result = any(_names_identity(x) for x in t)
    if cache is not None:
        cache["_names_identity"] = result
    return result


def when_atoms(formula: Term) -> frozenset:
    """The boolean conditions that single out no one: no caller or signer and no argument in them. Pause flags,
    deadlines, a registry's ``paused()``."""
    out: set[Term] = set()
    seen: set[int] = set()

    def walk(t: Term) -> None:
        if id(t) in seen:
            return
        seen.add(id(t))
        kind = t[0]
        if kind in ("and", "or"):
            for item in t[1]:
                walk(item)
        elif kind == "not":
            walk(t[1])
        elif kind == "ite":
            for part in t[1:]:
                walk(part)
        elif (
            kind != "const"
            and not contains(t, IDENTITY_KINDS)
            and all(singles_out_nobody(u) for u in subterms(t, "unknown"))
            and _record_state(t)
        ):
            # A clock comparison too: a start not yet reached comes true by waiting (``latched_atoms`` keeps a deadline
            # already passed as it reads). Nothing unknown but what singles out nobody (a count over a stored list):
            # an unknown may hide who it singles out. A record the caller
            # names (``votes[_voteId].executed``, ``_hashStates[hash(proposalId)]``) is state like any other: whoever
            # its writers let create one in this state, a call naming it passes.
            out.add(t)

    walk(formula)
    return frozenset(out)


def _record_state(t: Term) -> bool:
    """Whether ``t`` uses what the caller chooses only to pick the storage it reads: no caller-chosen value but as
    (part of) a storage key."""
    if not contains(t, _FREE_KINDS):
        return True
    seen: set[int] = set()
    stack = [t]
    while stack:
        x = stack.pop()
        if not isinstance(x, (tuple, frozenset)) or id(x) in seen or not contains_any_free(x):
            continue
        seen.add(id(x))
        if isinstance(x, frozenset) or not (x and isinstance(x[0], str)):
            stack.extend(x)  # a set of terms, or a tuple of them (a call's arguments)
            continue
        if x[0] in _FREE_KINDS:
            return False
        if x[0] == "load":
            stack.append(x[1])  # the keys may be chosen; where the record lives may not
            continue
        stack.extend(c for c in x[1:] if isinstance(c, (tuple, frozenset)))
    return True


def contains_any_free(t: Any) -> bool:
    if isinstance(t, frozenset) or (isinstance(t, tuple) and t and not isinstance(t[0], str)):
        return any(contains_any_free(x) for x in t)
    return isinstance(t, tuple) and bool(t) and contains(t, _FREE_KINDS)


def _contains_any(t: Term, targets: frozenset) -> bool:
    if not targets:
        return False
    kinds = frozenset(x[0] for x in targets)
    return any(s in targets for kind in kinds for s in subterms(t, kind))


# Refutation -----------------------------------------------------------------------------------------------------------


_W = 2**256


def refute(formula: Term, ground: Evaluator, timeout_ms: int = 300) -> bool:
    """Whether no choice of arguments satisfies ``formula`` (see ``solve``)."""
    return solve(formula, ground, timeout_ms) is None


def solve(formula: Term, ground: Evaluator, timeout_ms: int = 300, attempts: int = 3) -> Any:
    """``_solve``, skipped once z3 has given up on the same question for several identities and settled it for none:
    the identity only changes the values read, rarely what makes the question too hard."""
    record = ground.world.solver_record.setdefault((id(formula), ground.when), [0, 0])
    if record[0] >= _SOLVER_GIVE_UPS and not record[1]:
        return UNK
    inlined = [False]
    outer, ground.coded[0] = ground.coded[0], False
    try:
        result = _solve(formula, ground, timeout_ms, attempts, inlined)
        inlined[0] = inlined[0] or ground.coded[0]
    finally:
        ground.coded[0] = outer or ground.coded[0]
    if result is None and inlined[0] and ground.callee_code:
        # "Nothing satisfies it" resting on a followed callee's code standing in for a call (``Evaluator.truth``):
        # asked again with each view call a value of its own, tied to what the chain answers for the inputs the
        # models reach (``_solve``'s ``chain_calls``). Still nothing: refuted by the chain, not the code. A model
        # every answer agrees with is checked like any other; anything else is unknown.
        result = _solve(formula, ground.without_code(), timeout_ms, attempts, [False], chain_calls=True)
        if result is UNK:
            ground.world.code_refuted += 1
    record[0 if result is UNK else 1] += 1
    return result


def _solve(
    formula: Term,
    ground: Evaluator,
    timeout_ms: int = 300,
    attempts: int = 3,
    inlined: list | None = None,
    chain_calls: bool = False,
) -> Any:
    """``None`` when no choice of arguments (and no value of anything unknown) satisfies ``formula``; else argument
    values that make it true when checked against the chain, or UNK.

    What the identity's state leaves is handed to z3 as integer arithmetic modulo 2**256 over the arguments. Linear
    arithmetic, and division, remainders and shifts by constants, are exact; anything else (a product of two unknowns,
    bitwise logic between them, a hash) becomes a fresh bounded integer, which only adds models, so ``True`` stays a
    proof.
    """
    import z3

    fresh = itertools.count()
    side: list[Any] = []
    memo: dict[tuple[Term, str], Any] = {}
    arguments: dict[str, Term] = {}
    conditions: dict[str, Term] = {}  # free ``when`` conditions, read back from the model like arguments
    varying: dict[int, bool] = {}
    labels: dict[Term, str] = {}

    def label(prefix: str, t: Term) -> str:
        """A short z3 name per distinct term (a ``repr`` would expand a shared term exponentially)."""
        if t not in labels:
            labels[t] = f"{prefix}{len(labels)}"
        return labels[t]

    def varies(t: Any) -> bool:
        """Whether ``t`` mentions a caller-chosen value or a free condition: once per shared node."""
        key = id(t)
        if key in varying:
            return varying[key]
        if t in ground.when:
            result = True
        elif isinstance(t, frozenset):
            result = any(varies(x) for x in t)
        elif not isinstance(t, tuple) or not t:
            result = False
        elif isinstance(t[0], str):
            result = (t[0] in _FREE_KINDS and _caller_chosen(t)) or any(varies(x) for x in t[1:])
        else:
            result = any(varies(x) for x in t)
        varying[key] = result
        return result

    def bounded(name: str, low: int = 0, high: int = _W) -> Any:
        v = z3.Int(name)
        side.append(z3.And(v >= low, v < high))
        return v

    products: list[tuple[Any, Any, Any]] = []  # (x, y, x * y) left free
    # With ``chain_calls``: each view call's value, with the call, its inputs (target, arguments, and the callee
    # making it where its answer may depend on who asks) and their z3 terms.
    answered: list[tuple[Term, str, Any, Term, tuple, list]] = []
    escapes: list[Any] = []  # values nothing here models (an opaque builtin, an unknown): free, so only adding models
    strangers = {v for v in ground.identity.values() if v in _STRANGERS}

    def var(sort: str, escape: bool = False) -> Any:
        name = f"u{next(fresh)}"
        v = z3.Bool(name) if sort == "bool" else bounded(name)
        if escape:
            escapes.append(v)
        return v

    def as_int(b: Any) -> Any:
        return z3.If(b, z3.IntVal(1), z3.IntVal(0))

    def lit(value: Any, sort: str) -> Any:
        if isinstance(value, bool) or value in (PREIMAGE, ASSUMED):
            b = value is True or value in (PREIMAGE, ASSUMED)
            return z3.BoolVal(b) if sort == "bool" else z3.IntVal(int(b))
        if isinstance(value, int):
            return z3.BoolVal(value != 0) if sort == "bool" else z3.IntVal(value % _W)
        if value is REVERTED:
            return z3.BoolVal(False) if sort == "bool" else var(sort)
        if isinstance(value, FreeHash):
            h = bounded(f"h{next(fresh)}", 1)  # no preimage hashes to zero
            return h if sort == "int" else z3.BoolVal(True)
        return var(sort, escape=True)

    def go(t: Term, sort: str) -> Any:
        key = (t, sort)
        if key not in memo:
            memo[key] = build(t, sort)
        return memo[key]

    def number(t: Term) -> int | None:
        value = ground.eval(t) if not varies(t) else None
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    def arith(name: str, a: Term, b: Term) -> Any:
        x, y = go(a, "int"), go(b, "int")
        ka, kb = number(a), number(b)
        if name == "add":
            return (x + y) % _W
        if name == "sub":
            return (x - y + _W) % _W
        if name == "mul" and (ka is not None or kb is not None):
            return (x * y) % _W
        if name == "div" and kb is not None:
            return x / kb if kb else z3.IntVal(0)
        if name == "mod" and kb is not None:
            return x % kb if kb else z3.IntVal(0)
        if name == "shl" and kb is not None:
            return (x * 2**kb) % _W if kb < 256 else z3.IntVal(0)
        if name == "shr" and kb is not None:
            return x / 2**kb if kb < 256 else z3.IntVal(0)
        if name == "and":
            mask = kb if kb is not None else ka
            other = x if kb is not None else y
            if mask is not None and mask & (mask + 1) == 0:
                return other % (mask + 1)  # a low-bit mask is a remainder
        if name == "mul":
            # Free; a model the check refutes is followed by one with the product exact (see ``sliced``).
            product = var("int")
            products.append((x, y, product))
            return product
        return var("int")

    def build(t: Term, sort: str) -> Any:
        ground.world.work += 4 * NODE_WORK  # a z3 node costs a few evaluated ones
        kind = t[0]
        if t in ground.when:
            fixed = ground.assignment.get(t)
            if isinstance(fixed, bool):
                b = z3.BoolVal(fixed)
            else:
                name = label("w", t)
                b = z3.Bool(name)
                conditions[name] = t
            return b if sort == "bool" else as_int(b)
        if kind in IDENTITY_KINDS:
            return lit(ground.eval(t), sort)  # whoever is asked about, whatever was signed
        if kind == "ok" and t[1][0] == "call" and not t[1][4] and ground._action(t[1]) is ASSUMED:
            return lit(ASSUMED, sort)  # an action returns as the evaluator assumes it, whatever the arguments
        if kind == "len" and t[1][0] == "enc":
            # The encoding's length: constant per static argument, plus each dynamic argument's (free) length.
            total: Any = z3.IntVal(0)
            for arg in t[1][2]:
                type_ = arg[2] if arg[0] in ("arg", "const") else None
                if (
                    isinstance(type_, str)
                    and (type_ in ("bytes", "string") or type_.endswith("[]"))
                    and arg[0] == "arg"
                ):
                    n = go(mk("len", arg), "int")
                    total = total + (n if t[1][1] == "abi.encodePacked" else 64 + 32 * ((n + 31) / 32))
                elif t[1][1] == "abi.encodePacked":
                    width = packed_width(arg)
                    if width is None:
                        return var(sort)
                    total = total + width
                else:
                    total = total + 32
            return total if sort == "int" else total != 0
        if kind in _FREE_KINDS and _caller_chosen(t):
            name = label("a", t)
            arguments[name] = t
            if t[0] == "arg" and t[2] == "bool":
                b = z3.Bool(name)
                return b if sort == "bool" else as_int(b)
            bits = _bits(t[2]) if t[0] == "arg" else 32 if t[0] == "calldatasize" else 256
            v = z3.Int(name)
            side.append(z3.And(v >= (t[1] if t[0] == "calldatasize" else 0), v < 2**bits))
            return v if sort == "int" else v != 0
        if not varies(t):
            return lit(ground.eval(t), sort)
        if kind in ("load", "rawload"):
            # Storage read at keys the caller picks. A stranger is an address made up for the question: nothing was
            # written under it (the read is zero), and no slot holds it.
            keys = [k for step, k in t[3] if step == "k"] if kind == "load" else (_identity_keys(t[2]) or [])
            if any(_is_identity(k) and ground.eval(k) in _STRANGERS for k in keys):
                return lit(0, sort)
            v = var(sort, escape=True)
            if sort == "int":
                side.extend(v != who for who in strangers)
            return v
        if kind == "not":
            b = z3.Not(go(t[1], "bool"))
            return b if sort == "bool" else as_int(b)
        if kind in ("and", "or"):
            parts = [go(item, "bool") for item in cheapest_first(t)]
            b = z3.And(*parts) if kind == "and" else z3.Or(*parts)
            return b if sort == "bool" else as_int(b)
        if kind == "cmp":
            a, b = go(t[2], "int"), go(t[3], "int")
            r = a == b if t[1] == "eq" else (a < b if t[1] == "lt" else a <= b)
            return r if sort == "bool" else as_int(r)
        if kind == "ite":
            return z3.If(go(t[1], "bool"), go(t[2], sort), go(t[3], sort))
        if kind == "op" and len(t[2]) == 2:
            r = arith(t[1], t[2][0], t[2][1])
            return r if sort == "int" else r != 0
        if kind == "op" and t[1] == "bnot":
            r = _W - 1 - go(t[2][0], "int")
            return r if sort == "int" else r != 0
        if kind == "conv":
            inner = go(t[2], "int")
            width = conversion_width(t[1])
            if width is None:
                r = inner
            elif width[1]:
                low = inner % 2 ** width[0]
                r = z3.If(low >= 2 ** (width[0] - 1), low - 2 ** width[0], low)
            else:
                r = inner % 2 ** width[0]
            return r if sort == "int" else r != 0
        if kind == "op" and t[1] == "fits" and len(t[2]) == 5 and t[2][0][0] == "const":
            # Checked arithmetic's range, exact where the operation is linear.
            name, bits, is_signed = t[2][0][1], t[2][3][1], t[2][4][1]
            x, y = go(t[2][1], "int"), go(t[2][2], "int")
            exact = {"add": lambda: x + y, "sub": lambda: x - y}.get(name)
            if exact is None and name == "mul" and (number(t[2][1]) is not None or number(t[2][2]) is not None):
                exact = lambda: x * y  # noqa: E731
            if exact is not None and isinstance(bits, int):
                lo, hi = (-(2 ** (bits - 1)), 2 ** (bits - 1) - 1) if is_signed else (0, 2**bits - 1)
                r = exact()
                inside = z3.And(r >= lo, r <= hi)
                return inside if sort == "bool" else as_int(inside)
        if kind == "hash":
            return lit(FreeHash(identity=True), sort)
        if kind in ("call", "item"):
            # A view call over arguments the caller picks: the callee's own code, in these terms.
            call, index = (t, 0) if kind == "call" else (t[1], t[2])
            if call[0] == "call" and (call[1], call[2]) in ground.blind and contains(call, IDENTITY_KINDS):
                return var(sort, escape=True)  # whoever it lets through can't all be listed: unknown, as evaluated
            if chain_calls and call[0] == "call" and call[4]:
                # A value of its own, tied to the chain's answer at each input a model reaches.
                value = var(sort)
                asker = (call[5],) if len(call) > 5 and not ground.world.asker_free(call) else ()
                inputs = (call[1], *call[3], *asker)
                answered.append((t, sort, value, call, inputs, [go(x, "int") for x in inputs]))
                return value
            lowered = ground.world.callee(call) if call[0] == "call" and call[4] and ground.callee_code else None
            if lowered is not None and index < len(lowered[1]):
                if inlined is not None:
                    inlined[0] = True
                return go(lowered[1][index], sort)
        return var(sort, escape=True)

    goal = go(formula, "bool")
    query = cast(Any, z3.And(goal, *side))
    ground.world.work += QUESTION_WORK
    blocked: list[Any] = []
    # First through what is modelled only: every unmodelled value pinned (false, zero), so a model can't pass on an
    # opaque branch the check then can't confirm (an ERC-1271 path beside a plain signature). Only a search without
    # the pins proves nothing passes.
    pins = [z3.Not(v) if z3.is_bool(v) else v == 0 for v in escapes]
    sliced: list[Any] = []
    unsettled = False  # a model blocked whose check came back unknown: it may pass, so no refutation after it
    attempt, rounds = 0, 0
    while attempt < attempts + (1 if pins else 0):
        pinned = bool(pins) and attempt == 0
        attempt += 1
        # A fresh solver each time: one checked again runs z3's incremental core, without the preprocessing that
        # makes 256-bit modular arithmetic cheap (seconds instead of milliseconds).
        solver = z3.Solver()
        # A deterministic resource limit decides; the clock only backstops it.
        solver.set("rlimit", SOLVER_RLIMIT)
        solver.set("timeout", timeout_ms * 10)
        solver.add(query, *blocked, *(pins if pinned else ()), *sliced)
        spent = _rlimit_count(solver)
        verdict = solver.check()
        ground.world.work += max(_rlimit_count(solver) - spent, 0.0) / RLIMIT_PER_WORK
        if verdict != z3.sat and (pinned or sliced):
            sliced = []
            continue
        if verdict == z3.unsat:
            return UNK if unsettled else None
        if verdict != z3.sat:
            return UNK
        model = solver.model()
        values: dict[Term, Any] = {}
        blocking = []
        for name, term in arguments.items():
            ref = z3.Bool(name) if term[0] == "arg" and term[2] == "bool" else z3.Int(name)
            value = model.eval(ref, model_completion=True)
            values[term] = z3.is_true(value) if z3.is_bool(value) else cast(Any, value).as_long()
            blocking.append(ref != value)
        for name, term in conditions.items():
            value = model.eval(z3.Bool(name), model_completion=True)
            values[term] = z3.is_true(value)
            blocking.append(z3.Bool(name) != value)  # these arguments may pass with the conditions otherwise
        check = Evaluator(ground.world, ground.identity, {**ground.assignment, **values}, ground.blind, ground.when)
        if chain_calls:
            check.code_first = check.callee_code = False
            lemmas = _chain_lemmas(answered, check, model, lit)
            if lemmas is None or (lemmas and rounds >= _CHAIN_ROUNDS):
                return UNK  # an input the chain can't answer, or more inputs than are asked about
            if lemmas:
                # What the chain answers at the inputs this model reaches, which it got wrong: kept, and asked again.
                blocked.extend(lemmas)
                rounds += 1
                attempt -= 1
                continue
        checked = confirmed(check, formula)
        if checked is True:
            return values
        unsettled = unsettled or checked is not False
        # The next model keeps each product's first factor where this one had it, which makes the product exact
        # (linear in the other): a slice of the models, so finding none there proves nothing.
        sliced = []
        for x, y, product in products:
            vx = model.eval(x, model_completion=True).as_long()
            sliced += [x == vx, product == (vx * y) % _W]
        if not blocking:
            return UNK
        blocked.append(z3.Or(*blocking))
    return UNK


_CHAIN_ROUNDS = 8  # inputs of calls answered by the chain while a refutation is checked without callee code


def _chain_lemmas(answered: list, check: Evaluator, model: Any, lit: Callable) -> list | None:
    """For each view call left a value of its own (``_solve``'s ``chain_calls``): what the chain answers at the input
    ``model`` gives it (its target, arguments and, where the answer may depend on who asks, the callee making it,
    evaluated), as "at this input, this value" (or "never this input", where the call reverts, which fails the whole
    call), for each the model contradicts. ``None`` when an input or an answer isn't known: an input that isn't one
    number (a ``bytes`` argument) included, so such a refutation is left unknown."""
    import z3

    lemmas = []
    for term, sort, value, call, terms, parts in answered:
        inputs = [check.eval(x) for x in terms]
        if any(not isinstance(v, int) for v in inputs):
            return None
        answer = check.eval(term)
        if answer is not REVERTED and not isinstance(answer, int):
            return None
        same = z3.And(*[p == int(v) % 2**256 for p, v in zip(parts, inputs)])
        lemma = z3.Not(same) if answer is REVERTED else z3.Implies(same, value == lit(answer, sort))
        if not z3.is_true(model.eval(lemma, model_completion=True)):
            lemmas.append(lemma)
    return lemmas


def _rlimit_count(solver: Any) -> float:
    """z3's resource count, cumulative over the whole process (not per solver): only differences mean anything."""
    stats = solver.statistics()
    return next((float(stats.get_key_value(k)) for k in stats.keys() if k == "rlimit count"), 0.0)


def _fits(term: Term, value: Any) -> bool:
    """Whether a caller-chosen ``term`` can take ``value``, by its ABI type."""
    if term[0] != "arg" or not isinstance(term[2], str) or not isinstance(value, int):
        return True
    type_ = term[2]
    if type_ == "bool":
        return value in (0, 1)
    if type_.startswith(("uint", "address")) or (type_.startswith("bytes") and type_[5:].isdigit()):
        return 0 <= value < 2 ** _bits(type_)
    return True


def _bits(type_: str) -> int:
    if type_.startswith("address"):
        return 160
    for prefix in ("uint", "bytes"):
        if type_.startswith(prefix) and type_[len(prefix) :].isdigit():
            n = int(type_[len(prefix) :])
            return n if prefix == "uint" else 8 * n
    return 256


# Coverage -------------------------------------------------------------------------------------------------------------


@dataclass
class Coverage:
    """``representative``: every identity use is a lookup (an equality, a storage key, a call argument), so an
    unconfigured address stands for all of them. ``blind``: the lookups whose members can't be listed, as
    (contract, variable) and (target, signature) pairs."""

    representative: bool
    blind: frozenset = frozenset()
    lookups: frozenset = frozenset()  # (contract, variable) of every identity-keyed storage read, callees' included
    # Per lookup, the keys besides the identity every read of it uses (a role id, an app): its events' filter.
    fixed: dict = field(default_factory=dict)
    # Lookups whose stored values let their holders through (``delegates[voter] == msg.sender``), none listed: an
    # unconfigured address is in none of them, and the holders aren't all known.
    values: frozenset = frozenset()


def coverage(
    formula: Term,
    complete: Callable[[Any, Any, int, tuple], bool],
    lower_call: Callable[[Any], Term | None],
    listed: Callable[[Any, Any, tuple, Any], bool] | None = None,
    settled: Callable[[Term], bool] | None = None,
    valued: Callable[[Any, Any, int, tuple], bool] | None = None,
) -> Coverage:
    """``complete(contract_term, var, key_count, fields)`` says whether every write to that storage emits its key;
    ``lower_call(call)`` gives the callee's return formula with the identity arguments in place, or ``None``;
    ``listed(contract_term, var, fields, slot)`` whether a lookup keyed by a hash of the identity (a mapping, or a
    raw ``slot``) has every write logged with the hash's parts; ``settled(formula)`` whether a callee's formula is
    already true or false for an unconfigured caller, whatever the code the lowering couldn't follow does."""
    listed = listed or (lambda *_: False)
    settled = settled or (lambda _: False)
    valued = valued or (lambda *_: False)
    state = {"representative": True}
    blind: set = set()
    lookups: set = set()
    values: set = set()
    fixed: dict = {}
    seen: set[tuple] = set()

    def visit(t: Any) -> None:
        if isinstance(t, frozenset):
            for item in t:
                visit(item)
            return
        if not isinstance(t, tuple) or not t or t in seen:
            return
        if not isinstance(t[0], str):
            for item in t:
                visit(item)
            return
        seen.add(t)
        kind = t[0]
        if kind in IDENTITY_KINDS and kind != "signer":
            state["representative"] = False
            return
        if kind == "signer":
            for item in t[1:]:
                visit(item)
            state["representative"] = False
            return
        if kind == "cmp" and t[1] == "eq":
            for side, other in ((t[2], t[3]), (t[3], t[2])):
                if _is_identity(side) and not contains(other, IDENTITY_KINDS):
                    held = _strip_conv(other)
                    if held[0] == "load" and _chosen_keys(held):
                        # ``delegates[_voter].delegate == msg.sender``: whoever any entry names passes, so the entries'
                        # values are the lookup, listed only when every write logs the value it leaves.
                        var, path = _named_lookup(held[2], held[3])
                        keys = [step for k, step in path if k == "k"]
                        fields = tuple(step for k, step in path if k == "f")
                        lookups.add((held[1], var))
                        if not valued(held[1], var, len(keys), fields):
                            blind.add((held[1], held[2]))
                            values.add((held[1], held[2]))
                    visit(other)
                    return
        if kind == "load":
            var, path = _named_lookup(t[2], t[3])
            fields = tuple(step for k, step in path if k == "f")
            keys = [step for k, step in path if k == "k"]
            # A key read from an identity's own lookup (``params[permissions[hash(who, ...)]]``) is that lookup's
            # entry: for every address nothing names, the same zero entry. The inner lookup lists the holders. So is a
            # key the identity only picks between fixed ones by (``poolBitmaps[pm][allowed ? 0 : id]``).
            if any(
                contains(k, IDENTITY_KINDS) and k[0] not in ("load", "rawload") and not _fixed_choice(k) for k in keys
            ):
                hashed = [
                    k
                    for k in keys
                    if contains(k, IDENTITY_KINDS) and not _is_identity(k) and k[0] not in ("load", "rawload")
                ]
                if any(_identity_keys(k) is None for k in hashed):
                    state["representative"] = False
                    return
                lookups.add((t[1], var))
                parts = frozenset(
                    p
                    for k in keys
                    for p in ([k] if not contains(k, IDENTITY_KINDS) else _hash_inputs(k))
                    if not contains(p, IDENTITY_KINDS)
                )
                fixed[(t[1], var)] = parts if (t[1], var) not in fixed else fixed[(t[1], var)] & parts
                # A key hashed from the identity (Aragon's ``permissions[hash(who, app, role)]``) is a lookup too,
                # listed whole only when every write logs the hash's parts, not just the hash.
                known = listed(t[1], var, fields, None) if hashed else complete(t[1], var, len(keys), fields)
                if not known:
                    blind.add((t[1], t[2]))
                for k in keys:
                    if k in hashed:
                        visit(frozenset(x for x in _hash_inputs(k) if not _is_identity(x)))
                    elif not _is_identity(k):
                        visit(k)
                visit(t[1])
                return
        if kind == "call" and any(contains(a, IDENTITY_KINDS) for a in t[3]):
            if not all(_handed_whole(a) for a in t[3]):
                state["representative"] = False
                return
            inner = lower_call(t)
            if inner is None:
                blind.add((t[1], t[2]))
            else:
                sub = coverage(inner, complete, lower_call, listed, settled, valued)
                state["representative"] &= sub.representative
                lookups.update(sub.lookups)  # where to look for who it lets through, even when not everyone
                values.update(sub.values)
                for key, parts in sub.fixed.items():
                    fixed[key] = parts if key not in fixed else fixed[key] & parts
                if sub.blind or (
                    any(not singles_out_nobody(u) for u in subterms(inner, "unknown")) and not settled(inner)
                ):
                    # Code the lowering couldn't follow: whoever it lets through can't all be listed. Unless an
                    # address no lookup names is already decided without it (Aragon's parameter checks run only
                    # for an entity holding the permission): it decides only for those listed.
                    blind.add((t[1], t[2]))
            visit(t[1])
            return
        if kind == "rawload" and contains(t[2], IDENTITY_KINDS):
            if _identity_keys(t[2]) is None:
                state["representative"] = False
                return
            # A slot hashed from the identity is a lookup like a mapping's, listed when every write that may land on
            # a slot of its shape logs the parts.
            lookups.add((t[1], RAW_SLOT))
            if not listed(t[1], RAW_SLOT, (), t[2]):
                blind.add((t[1], RAW_SLOT))
            visit(t[1])
            return
        if kind == "hash" and contains(t, IDENTITY_KINDS):
            state["representative"] = False
            return
        for item in t[1:]:
            visit(item)

    visit(formula)
    return Coverage(state["representative"], frozenset(blind), frozenset(lookups), fixed, frozenset(values))


def _handed_whole(arg: Term) -> bool:
    """A call argument that is the identity, free of it, or a memory array of such (``[msg.sender, recipient]``)."""
    if _is_identity(arg) or not contains(arg, IDENTITY_KINDS):
        return True
    return (
        arg[0] == "array" and len(arg) == 3 and all(_is_identity(a) or not contains(a, IDENTITY_KINDS) for a in arg[2])
    )


def _fixed_choice(key: Term) -> bool:
    """``c ? a : b`` whose values name no identity, whatever ``c`` reads."""
    if key[0] != "ite":
        return not contains(key, IDENTITY_KINDS)
    return _fixed_choice(key[2]) and _fixed_choice(key[3])


def _strip_conv(t: Term) -> Term:
    while t[0] == "conv":
        t = t[2]
    return t


def _chosen_keys(load: Term) -> bool:
    """Whether some key of ``load`` is one the caller picks, and none is an identity."""
    keys = [step for kind, step in load[3] if kind == "k"]
    return any(_caller_chosen(x) for k in keys for kind in _FREE_KINDS for x in subterms(k, kind)) and not any(
        contains(k, IDENTITY_KINDS) for k in keys
    )


def _named_lookup(var: Any, path: tuple) -> tuple[Any, tuple]:
    """A namespaced-storage read (``$._roles[r].hasRole[a]``) as the variable its writers are named by (``_roles``)
    and the path below it; a plain variable unchanged."""
    if isinstance(var, tuple) and var and var[0] == "slot" and path and path[0][0] == "f":
        return path[0][1], tuple(path[1:])
    return var, path


def _is_identity(t: Term) -> bool:
    while t[0] == "conv":
        t = t[2]
    return t[0] in IDENTITY_KINDS


# The lookup a raw storage slot keyed by an identity stands for (``sload(keccak256(role, seed, holder))``).
RAW_SLOT = "<raw slot>"


def _identity_keys(slot: Term) -> list[Term] | None:
    """The identities a hashed storage slot is keyed by, when it uses them only as hashed inputs (directly or packed);
    ``None`` when an identity takes part any other way."""
    if slot[0] != "hash":
        return None
    inputs = [x for i in slot[2] for x in (i[2] if i[0] == "enc" else (i,))]
    keys = [x for x in inputs if _is_identity(x)]
    if not keys or any(contains(x, IDENTITY_KINDS) for x in inputs if not _is_identity(x)):
        return None
    return keys


__all__ = ["Chain", "Coverage", "Evaluator", "FRESH", "Verdict", "World", "coverage", "decide", "decode"]
