"""Wire-level stubs for the effects harness, the fork recipes and the seeder.

Extracted verbatim from ``test_effects_harness`` (the ``Simulate`` stubs),
``test_effects_anvil`` (``StubAnvil``) and ``test_effects_input_seeding``
(``FakeChain``), which between them were imported by 13 other test modules.
"""

from __future__ import annotations

from collections.abc import Sequence

from eth_utils.crypto import keccak

from services.effects.harness import SimContext
from services.effects.seeding import SEED_ETH_VALUE, AnchorSlot
from services.effects.simulate import (
    TRANSFER_TOPIC,
    SimCall,
    SimCallResult,
    SimLog,
    SimResult,
)
from utils.rpc import EthCallResult

CONTRACT = "0x" + "11" * 20
PRINCIPAL = "0x" + "22" * 20
SENTINEL = "0x" + "ee" * 20
TOKEN = "0x" + "33" * 20
CTX = SimContext(chain_id=1, block=1000, hardfork="prague")

_REVERT_A = "0x08c379a0" + "00" * 4


# --- the Simulate wire ------------------------------------------------------


class ScriptedSimulate:
    """Returns pre-programmed ``SimResult``s in order; records every block."""

    def __init__(self, *results: SimResult) -> None:
        self._results = list(results)
        self.blocks: list[tuple[Sequence[SimCall], str, dict | None]] = []
        self._i = 0

    def __call__(self, calls, block_tag, overrides):
        self.blocks.append((list(calls), block_tag, overrides))
        res = self._results[self._i]
        self._i += 1
        return res


class RecordingStore:
    """Injected transcript store: records each dict, hands back a fake key."""

    def __init__(self) -> None:
        self.stored: list[dict] = []

    def __call__(self, transcript: dict) -> str:
        self.stored.append(transcript)
        return f"artifact://transcript/{len(self.stored)}"


def transfer_log(token: str, frm: str, to: str, value: int) -> SimLog:
    return SimLog(
        address=token.lower(),
        topics=(TRANSFER_TOPIC, _addr_topic(frm), _addr_topic(to)),
        data="0x" + value.to_bytes(32, "big").hex(),
    )


def _addr_topic(addr: str) -> str:
    return "0x" + addr[2:].rjust(64, "0").lower()


def ok(ret: str = "0x", logs=()) -> SimCallResult:
    return SimCallResult(True, ret, None, tuple(logs))


def rv(data: str = _REVERT_A) -> SimCallResult:
    return SimCallResult(False, "0x", data, ())


def uint_ret(n: int) -> str:
    return "0x" + n.to_bytes(32, "big").hex()


# --- the fork transport -----------------------------------------------------

GUARDED = "0xc2985578"  # foo()
UNGATED = "0xffffffff"
PAUSE = "0x8456cb59"


class StubAnvil:
    """Models a pausable contract on a fork: ``guarded`` entry points revert while
    paused-and-unexpired; ``send(pause_calldata)`` flips the latch; ``increase_time``
    past the duration auto-expires it. snapshot/revert restore the latch state."""

    def __init__(
        self, *, guarded: set[str], pause_calldata: str, duration: int | None, hardfork: str = "prague"
    ) -> None:
        self._guarded = guarded
        self._pause_calldata = pause_calldata
        self._duration = duration
        self._hf = hardfork
        self.paused = False
        self.time = 0
        self.expiry: int | None = None
        self._snaps: dict[str, tuple] = {}
        self._n = 0
        self.impersonated: list[str] = []
        self.log: list[str] = []
        self.balances: dict[str, str] = {}
        self.storage: dict[tuple[str, str], str] = {}
        self.warped = 0

    def hardfork(self) -> str:
        return self._hf

    def versions(self) -> dict[str, str]:
        return {"anvil": "anvil 1.5.1-stable", "foundry": "anvil 1.5.1-stable"}

    def snapshot(self) -> str:
        self._n += 1
        sid = f"0x{self._n}"
        self._snaps[sid] = (self.paused, self.time, self.expiry)
        return sid

    def revert(self, snapshot_id: str) -> bool:
        self.paused, self.time, self.expiry = self._snaps[snapshot_id]
        return True

    def impersonate(self, address: str) -> None:
        self.impersonated.append(address)

    def stop_impersonate(self, address: str) -> None:
        self.log.append(f"stop:{address}")

    def call(self, tx: dict) -> EthCallResult:
        data = tx.get("data", "")
        frozen = self.paused and (self.expiry is None or self.time < self.expiry)
        if data in self._guarded and frozen:
            return EthCallResult(False, "0x", "0x" + "paused".encode().hex(), "paused")
        return EthCallResult(True, "0x", None, None)

    def send(self, tx: dict) -> str:
        if tx.get("data") == self._pause_calldata:
            self.paused = True
            self.expiry = None if self._duration is None else self.time + self._duration
        return "0xhash"

    def increase_time(self, seconds: int) -> None:
        self.time += seconds
        # Counted, not just applied: "the recipe did not warp at all" is a distinct
        # assertion from "it warped and nothing expired" (A7's two None states).
        self.warped += 1

    def mine(self) -> None:
        pass

    def set_balance(self, address: str, value: str) -> None:
        self.balances[address.lower()] = value

    def set_storage_at(self, address: str, slot: str, value: str) -> None:
        self.storage[(address.lower(), slot.lower())] = value


# --- the slot-faithful ERC-20 + vault ---------------------------------------

VAULT = "0x" + "11" * 20
ASSET = "0x" + "44" * 20

BAL_BASE = 3
ALLOW_BASE = 4
ASSET_GETTER = "underlying()"


def sel(sig: str) -> str:
    return "0x" + keccak(text=sig).hex()[:8]


def _arg(data: str, index: int) -> str:
    """The address at word ``index`` of a calldata payload."""
    start = 10 + index * 64
    return "0x" + data[start + 24 : start + 64].lower()


def _slot(base: int, arity: int, holder: str, spender: str) -> str:
    return AnchorSlot(signature="x", arity=arity, ordering="solidity", base=base).slot(holder, spender)


class FakeChain:
    """A slot-faithful ERC-20 plus a vault that wraps it.

    ``balance_scale`` > 1 models a rebasing token whose ``balanceOf`` is COMPUTED
    from the stored word — the shape whose read-back must never match.
    """

    def __init__(
        self,
        *,
        balance_base: int | None = BAL_BASE,
        allowance_base: int | None = ALLOW_BASE,
        decimals: int = 18,
        balance_scale: int = 1,
        vault_pulls: bool = True,
        vault_needs_eth: bool = False,
        vault_needs_asset: bool = True,
        total_supply: int = 10**24,
        readback_liar: bool = False,
        asset_total_supply: int | None = None,
    ) -> None:
        # ``None`` = the asset does not answer ``totalSupply()`` at all, which is
        # the shape every pre-existing test here assumes.
        self.asset_total_supply = asset_total_supply
        self.balance_base = balance_base
        self.allowance_base = allowance_base
        self.decimals = decimals
        self.balance_scale = balance_scale
        self.vault_pulls = vault_pulls
        self.vault_needs_eth = vault_needs_eth
        self.vault_needs_asset = vault_needs_asset
        self.total_supply = total_supply
        self.readback_liar = readback_liar
        self.blocks: list[tuple[list, str, dict | None]] = []

    # -- helpers ------------------------------------------------------------
    def _diff(self, overrides, address):
        entry = (overrides or {}).get(address.lower()) or {}
        return entry.get("stateDiff") or {}

    def _stored(self, overrides, holder, spender, *, arity):
        base = self.balance_base if arity == 1 else self.allowance_base
        if base is None:
            return None
        diff = self._diff(overrides, ASSET)
        raw = diff.get(_slot(base, arity, holder, spender))
        return int(raw, 16) if raw else 0

    # -- the wire seam ------------------------------------------------------
    def __call__(self, calls, block_tag, overrides):
        self.blocks.append((list(calls), block_tag, overrides))
        results = []
        minted = self.total_supply
        for call in calls:
            results.append(self._one(call, overrides))
            if call.to.lower() == VAULT.lower() and call.data.startswith(sel("wrap(uint256)")):
                if results[-1].success:
                    minted = self.total_supply = self.total_supply + int(call.data[10:74], 16)
        del minted
        return SimResult(calls=tuple(results))

    def _one(self, call, overrides) -> SimCallResult:
        to = call.to.lower()
        data = call.data
        if to == ASSET.lower():
            return self._asset_call(data, overrides)
        if to == VAULT.lower():
            return self._vault_call(call, data, overrides)
        return ok()

    def _asset_call(self, data, overrides) -> SimCallResult:
        if data.startswith(sel("decimals()")):
            return ok(uint_ret(self.decimals))
        if data.startswith(sel("totalSupply()")):
            if self.asset_total_supply is None:
                return SimCallResult(False, "0x", "0x", ())
            return ok(uint_ret(self.asset_total_supply))
        if data.startswith(sel("balanceOf(address)")):
            stored = self._stored(overrides, _arg(data, 0), VAULT, arity=1)
            if stored is None:
                return SimCallResult(False, "0x", "0x", ())
            if self.readback_liar:
                return ok(uint_ret(stored + 1))
            return ok(uint_ret((stored * self.balance_scale) % 2**256))
        if data.startswith(sel("allowance(address,address)")):
            stored = self._stored(overrides, _arg(data, 0), _arg(data, 1), arity=2)
            if stored is None:
                return SimCallResult(False, "0x", "0x", ())
            return ok(uint_ret(stored))
        # shares()/sharesOf() are absent on this token.
        return SimCallResult(False, "0x", "0x", ())

    def _vault_call(self, call, data, overrides) -> SimCallResult:
        if data.startswith(sel("totalSupply()")):
            return ok(uint_ret(self.total_supply))
        if data.startswith(sel(ASSET_GETTER)):
            return ok("0x" + ASSET[2:].rjust(64, "0"))
        if data.startswith(sel("wrap(uint256)")):
            amount = int(data[10:74], 16)
            held = self._stored(overrides, PRINCIPAL, VAULT, arity=1) or 0
            allowed = self._stored(overrides, PRINCIPAL, VAULT, arity=2) or 0
            if self.vault_needs_asset and (held < amount or allowed < amount):
                return SimCallResult(False, "0x", "0x08c379a0", ())
            if self.vault_needs_eth and call.value < SEED_ETH_VALUE:
                return SimCallResult(False, "0x", "0x08c379a0", ())
            logs = []
            if self.vault_pulls and self.vault_needs_asset:
                logs.append(transfer_log(ASSET, PRINCIPAL, VAULT, amount))
            logs.append(transfer_log(VAULT, "0x" + "00" * 20, PRINCIPAL, amount))
            return ok(logs=logs)
        if data.startswith(sel("unwrap(uint256)")):
            # Same precondition shape as ``wrap``; the observable difference is
            # that value LEAVES the vault (the §4.2 witness).
            amount = int(data[10:74], 16)
            held = self._stored(overrides, PRINCIPAL, VAULT, arity=1) or 0
            if held < amount:
                return SimCallResult(False, "0x", "0x08c379a0", ())
            return ok(logs=[transfer_log(ASSET, VAULT, PRINCIPAL, amount)])
        return SimCallResult(False, "0x", "0x", ())
