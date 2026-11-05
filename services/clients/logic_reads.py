"""Pinned chain inputs for formula analysis. Operational failures abort the job.

No eth_call, state overrides, signatures, or verdict logic live in this provider.
Trace preimages are checked by the engine; incomplete hints can only cost enumeration.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from typing import Any, Callable

import rlp
from eth_utils.crypto import keccak
from trie import HexaryTrie

from services.logic.model import BudgetExceeded, ReadError


class ChainReads:
    def __init__(
        self,
        rpc: Callable,
        block: int,
        *,
        debug: Callable | None = None,
        read_limit: int = 10_000,
        retries: int = 2,
        log_window: int = 1_000_000,
        deployment_block: Callable[[int], int] | None = None,
        trace_preimages: Callable[[int, set[int]], dict[int, bytes]] | None = None,
        trace_reader: Callable[[str, list], dict[int, bytes]] | None = None,
        word_limit: int = 100_000,
    ):
        self.rpc, self.debug, self.block = rpc, debug or rpc, block
        self.read_limit, self.retries, self.log_window = read_limit, retries, log_window
        self.deployment_block = deployment_block or (lambda address: 0)
        self.trace_preimages = trace_preimages
        self.trace_reader = trace_reader
        self.word_limit = word_limit
        self.sent = 0
        self.memo: dict[tuple, Any] = {}
        self._trace_hash_cache: OrderedDict[str, tuple[dict[int, bytes], int]] = OrderedDict()
        self._trace_words = 0

    def _read(self, method: str, params: list, *, debug: bool = False, fetch=None, cache: bool = True) -> Any:
        if debug and self.debug is not self.rpc and method != "eth_chainId":
            primary = self._read("eth_chainId", [])
            archive = self._read("eth_chainId", [], debug=True)
            try:
                same_chain = int(primary, 16) == int(archive, 16)
            except (ValueError, TypeError):
                raise ReadError("malformed debug-provider chain identity") from None
            if not same_chain:
                raise ReadError("debug provider is on a different chain")
        key = (debug, method, repr(params))
        if cache and key in self.memo:
            return self.memo[key]
        last = None
        for attempt in range(self.retries + 1):
            if self.sent >= self.read_limit:
                raise BudgetExceeded("chain reads")
            self.sent += 1
            try:
                value = (fetch or (self.debug if debug else self.rpc))(method, params)
                if value is None or (isinstance(value, dict) and "error" in value):
                    raise ValueError("unanswered RPC")
                if cache:
                    self.memo[key] = value
                return value
            except BudgetExceeded:
                raise
            except (TimeoutError, ConnectionError, ValueError, RuntimeError, OSError) as exc:
                last = exc
                if attempt < self.retries:
                    time.sleep(0.1 * 2**attempt)
        raise ReadError(f"{method} failed after {self.retries + 1} attempts") from last

    @staticmethod
    def address(address: int) -> str:
        return f"0x{address:040x}"

    def storage(self, address: int, slot: int) -> int:
        raw = self._read("eth_getStorageAt", [self.address(address), hex(slot), hex(self.block)])
        try:
            return int(raw, 16)
        except (TypeError, ValueError) as exc:
            raise ReadError("malformed storage response") from exc

    def code(self, address: int) -> bytes:
        raw = self._read("eth_getCode", [self.address(address), hex(self.block)])
        try:
            return bytes.fromhex(raw.removeprefix("0x"))
        except (AttributeError, ValueError) as exc:
            raise ReadError("malformed code response") from exc

    def balance(self, address: int) -> int:
        return int(self._read("eth_getBalance", [self.address(address), hex(self.block)]), 16)

    def block_field(self, name: str) -> int:
        if name in ("chainid", "chainid()", "chain.id"):
            return int(self._read("eth_chainId", []), 16)
        header = self._read("eth_getBlockByNumber", [hex(self.block), False])
        key = name.removeprefix("block.")
        key = {"coinbase": "miner", "prevrandao": "mixHash", "gaslimit": "gasLimit", "basefee": "baseFeePerGas"}.get(
            key, key
        )
        if key not in header:
            raise ReadError(f"block field missing: {name}")
        return int(header[key], 16)

    def snapshot_identity(self) -> dict:
        """Pin durable compilation work to a chain state, not just a reorg-sensitive height."""
        header = self._read("eth_getBlockByNumber", [hex(self.block), False])
        try:
            if int(header["number"], 16) != self.block:
                raise ValueError()
            if any(len(bytes.fromhex(header[key][2:])) != 32 for key in ("hash", "stateRoot")):
                raise ValueError()
            return {
                "chain_id": int(self._read("eth_chainId", []), 16),
                "block_hash": header["hash"].lower(),
                "state_root": header["stateRoot"].lower(),
            }
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ReadError("malformed checkpoint snapshot identity") from exc

    def storage_dump(self, address: int) -> dict[int, int]:
        header = self._read("eth_getBlockByNumber", [hex(self.block), False])
        try:
            if int(header["number"], 16) != self.block or not isinstance(header["transactions"], list):
                raise ValueError()
            if any(len(bytes.fromhex(header[k][2:])) != 32 for k in ("hash", "stateRoot")):
                raise ValueError()
        except (KeyError, TypeError, ValueError):
            raise ReadError("malformed pinned block header") from None
        proof = self._read("eth_getProof", [self.address(address), [], header["hash"]], debug=True)
        try:
            account = HexaryTrie.get_from_proof(
                bytes.fromhex(header["stateRoot"][2:]),
                keccak(address.to_bytes(20, "big")),
                tuple(rlp.decode(bytes.fromhex(node[2:])) for node in proof["accountProof"]),
            )
            expected = rlp.decode(account)[2] if account else HexaryTrie({}).root_hash
            if expected != bytes.fromhex(proof["storageHash"][2:]):
                raise ValueError("account/storage proof disagree")
        except Exception as exc:
            raise ReadError("account proof does not verify against pinned state root") from exc
        start, result, seen = "0x" + "00" * 32, {}, set()
        while start:
            if start in seen:
                raise ReadError("storage pagination repeated a cursor")
            seen.add(start)
            page = self._read(
                "debug_storageRangeAt",
                [header["hash"], len(header["transactions"]), self.address(address), start, 1000],
                debug=True,
            )
            if (
                not isinstance(page, dict)
                or "storage" not in page
                or (page["storage"] is not None and not isinstance(page["storage"], dict))
            ):
                raise ReadError("malformed storage dump")
            for hashed, item in (page["storage"] or {}).items():
                if not isinstance(item, dict) or not isinstance(item.get("key"), str):
                    raise ReadError("storage trie key preimages unavailable")
                try:
                    slot, value = int(item["key"], 16), int(item["value"], 16)
                    if not isinstance(hashed, str):
                        raise ValueError()
                except (KeyError, ValueError, TypeError):
                    raise ReadError("malformed storage entry") from None
                if not 0 <= slot < 2**256 or not 0 <= value < 2**256:
                    raise ReadError("malformed storage word")
                if keccak(slot.to_bytes(32, "big")).hex() != hashed.removeprefix("0x").lower():
                    raise ReadError("storage slot preimage does not match trie key")
                if slot in result:
                    raise ReadError("storage pagination repeated a slot")
                if not value:
                    raise ReadError("noncanonical zero storage leaf")
                result[slot] = value
                if len(result) > self.word_limit:
                    raise BudgetExceeded("storage dump words")
            start = page.get("nextKey")
            if start is not None:
                try:
                    if not isinstance(start, str) or not start.startswith("0x") or len(bytes.fromhex(start[2:])) != 32:
                        raise ValueError()
                except ValueError:
                    raise ReadError("malformed storage cursor") from None
        # Providers differ on transaction-index semantics. Accept only a complete dump whose
        # reconstructed root matches the account proof at the exact requested block hash.
        try:
            trie = HexaryTrie({})
            for slot, value in result.items():
                trie[keccak(slot.to_bytes(32, "big"))] = rlp.encode(value)
            if trie.root_hash != expected:
                raise ValueError("incomplete or different-block storage dump")
        except Exception as exc:
            raise ReadError("storage dump does not verify against pinned state root") from exc
        return result

    def key_words(self, address: int) -> set[int]:
        words = set()
        for lo in range(self.deployment_block(address), self.block + 1, self.log_window):
            hi = min(lo + self.log_window - 1, self.block)
            logs = self._read(
                "eth_getLogs", [{"address": self.address(address), "fromBlock": hex(lo), "toBlock": hex(hi)}]
            )
            for log in logs:
                words.update(int(t, 16) for t in log.get("topics", ())[1:])
                data = bytes.fromhex(log.get("data", "0x")[2:])
                words.update(int.from_bytes(data[i : i + 32], "big") for i in range(0, len(data) - 31, 32))
                if len(words) > self.word_limit:
                    raise BudgetExceeded("event key words")
        return words

    def preimages(self, address: int, slots: set[int]) -> dict[int, bytes]:
        if self.trace_preimages is not None:
            return self.trace_preimages(address, slots)
        # Find a zero -> nonzero boundary for each live slot. The search maintains those endpoint
        # facts; it does not assume the slot was written only once or claim the earliest writer.
        blocks = set()
        for slot in sorted(slots):
            lo, hi = max(self.deployment_block(address) - 1, 0), self.block

            def word(block):
                return int(self._read("eth_getStorageAt", [self.address(address), hex(slot), hex(block)]), 16)

            if word(lo) != 0 or word(hi) == 0:
                continue
            while hi - lo > 1:
                mid = (lo + hi) // 2
                if word(mid):
                    hi = mid
                else:
                    lo = mid
            blocks.add(hi)
        result = {}
        for block in sorted(blocks):
            diff = self._read(
                "debug_traceBlockByNumber",
                [hex(block), {"tracer": "prestateTracer", "tracerConfig": {"diffMode": True}}],
                debug=True,
                cache=False,
            )
            header = self._read("eth_getBlockByNumber", [hex(block), False])
            if not isinstance(diff, list):
                raise ReadError("malformed block trace")
            for index, entry in enumerate(diff):
                if entry.get("error"):
                    raise ReadError("unanswered transaction trace")
                post = entry.get("result", {}).get("post", {})
                state = next((value for key, value in post.items() if int(key, 16) == address), {})
                if not any(int(key, 16) in slots for key in state.get("storage", {})):
                    continue
                tx = entry.get("txHash") or header["transactions"][index]
                if self.trace_reader is not None:
                    result.update(self._transaction_hashes(tx))
                    if sum(max(1, (len(v) + 31) // 32) for v in result.values()) > self.word_limit:
                        raise BudgetExceeded("trace preimage words")
                    continue
                trace = self._read(
                    "debug_traceTransaction",
                    [tx, {"enableMemory": True, "disableStorage": True}],
                    debug=True,
                    cache=False,
                )
                if not isinstance(trace, dict) or "structLogs" not in trace:
                    raise ReadError("opcode trace unavailable")
                result.update(hash_preimages(trace))
        return result

    def _transaction_hashes(self, tx: str) -> dict[int, bytes]:
        if tx in self._trace_hash_cache:
            self._trace_hash_cache.move_to_end(tx)
            return self._trace_hash_cache[tx][0]
        result = self._read(
            "debug_traceTransaction",
            [tx, {"enableMemory": True, "disableStorage": True}],
            debug=True,
            fetch=self.trace_reader,
            cache=False,
        )
        weight = sum(max(1, (len(v) + 31) // 32) for v in result.values())
        if weight > self.word_limit:
            raise BudgetExceeded("trace preimage words")
        while self._trace_hash_cache and self._trace_words + max(1, weight) > self.word_limit:
            _, (_, evicted) = self._trace_hash_cache.popitem(last=False)
            self._trace_words -= evicted
        if self.word_limit:
            self._trace_hash_cache[tx] = result, max(1, weight)
            self._trace_words += max(1, weight)
        return result


def hash_preimages(trace: dict) -> dict[int, bytes]:
    """Exact KECCAK256 memory inputs from an opcode trace, including nested call frames."""
    result = {}
    for step in trace.get("structLogs", ()):
        if step.get("op") not in ("KECCAK256", "SHA3"):
            continue
        stack, words = step.get("stack", ()), step.get("memory")
        if len(stack) < 2 or words is None:
            continue
        offset, length = int(stack[-1], 16), int(stack[-2], 16)
        memory = bytes.fromhex("".join(w.removeprefix("0x") for w in words))
        if offset + length > len(memory):
            continue
        raw = memory[offset : offset + length]
        result[int.from_bytes(keccak(raw), "big")] = raw
    return result
