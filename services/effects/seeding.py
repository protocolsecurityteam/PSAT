"""Input-asset state seeding for Tier-1 probes (EFFECTS_RESOLUTION_SPEC §4.2/§4.5).

A deposit-backed conversion (``WeETH.wrap``, a vault ``deposit``) begins by
PULLING an input asset from the caller. The simulated principal holds none of it,
and ``eth_simulateV1`` with ``validation:false`` skips ETH balance/nonce checks
but NOT ERC-20 balance state — so the probe reverts at the precondition, the
verdict is ``unknown``, and the function drops out of the mint population
entirely. That is why ``supply.mint`` backing came back empty on 100% of rows:
the only mints that could prove were the input-less admin/reward mints.

This module gives the acting principal the input asset it needs, and nothing
else. Three properties carry the witness bar:

1. **Seeding is a RETRY, never the first attempt.** The unseeded probe runs
   first; seeding is attempted only after it reverted. That ordering is not a
   perf trick — it is the soundness argument. Because the value/asset-free call
   provably failed, an asset the seeded call then consumes was genuinely
   REQUIRED. Without it we could hand a payable admin mint some ETH and read the
   resulting ``msg.value`` inflow as "backed" when a real caller could mint with
   zero.
2. **Read-back or nothing.** A slot is only seeded after the token's own direct
   view getter echoed a written magic word (:func:`discover_token_layout`), and
   the probe block itself re-reads that getter and requires the exact seeded
   value. A rebasing / computed / proxy-backed / exotic-layout token never
   echoes, so it is never seeded — the probe stays exactly as unseeded as it is
   today. An unseeded ``unknown`` is honest; a wrongly-seeded "backed" is a lie
   about solvency.
3. **Seeding never manufactures a witness.** Writing storage emits no logs, so
   every ``Transfer`` the recipe observes was emitted by the contract's own
   execution. Seeding an asset the function does not pull produces no inflow at
   all. ``inflow_observed`` keeps its exact meaning either way.

The seeded state is deliberately narrow: the principal's balance/shares/allowance
of a candidate input token, plus (only on the second attempt) an ETH balance for
an attached ``msg.value``. No roles, no gate flags, no unrelated storage.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from eth_utils.crypto import keccak

from services.effects.simulate import SimCall, Simulate, StateOverride

logger = logging.getLogger(__name__)

_TRUTHY = {"1", "true", "yes", "on"}


def input_seeding_enabled() -> bool:
    """Kill-valve for the whole feature. Default ON; setting it off restores the
    exact pre-seeding probe (one unseeded call, no discovery RPCs)."""
    return os.getenv("PSAT_EFFECTS_INPUT_SEEDING", "1").strip().lower() in _TRUTHY


# Balance / shares / allowance handed to the principal. Same constant the pause
# recipe seeds with: far above any probe amount so a ``>=`` precondition always
# clears, far below 2**256 so a ``balance + amount`` path cannot overflow.
SEED_AMOUNT = 2**128

# Attached ``msg.value`` on the payable retry, and the ETH balance the principal
# is given to pay it. One whole ether clears the minimum-deposit checks real
# pools use (0.1 ETH is the common floor) without being large enough to trip a
# deposit cap.
SEED_ETH_VALUE = 10**18
SEED_ETH_BALANCE = 10**19

# Solidity base slots scanned for a mapping. 256 is not arbitrary: OZ-upgradeable
# inheritance chains push the balance mapping deep behind ``__gap`` arrays —
# measured on mainnet, weETH's ``_balances`` is at slot 101 and eETH's ``shares``
# at slot 203. A shallower scan silently misses exactly the deposit-backed
# conversions this exists for.
MAX_BASE_SLOT = 256
# Vyper folds mapping keys the other way round. Vyper tokens declare their
# balance mapping near the top of storage, so a short scan is enough.
MAX_VYPER_BASE_SLOT = 16

# Distinguishes a candidate's echo from any real token value. The low bits carry
# the candidate index, so ONE read identifies WHICH candidate slot the getter
# reads — the whole scan costs a single call. Placed at 2**128 rather than near
# 2**255: high enough that no real supply can collide, low enough that a getter
# which SCALES the stored word (the shape we want to detect and refuse) computes
# a distinct value rather than silently wrapping back into the magic range.
_MAGIC_PREFIX = 0x5EED5EED << 128
_MAGIC_MASK = 0xFFFF

# ERC-7201 namespaced storage: OZ v5 keeps ``_balances`` at the ``ERC20Storage``
# base and ``_allowances`` at base + 1. Derived, not hardcoded.
_OZ_ERC20_NAMESPACE = (int.from_bytes(keccak(text="openzeppelin.storage.ERC20"), "big") - 1).to_bytes(32, "big")
OZ_V5_ERC20_BASE = int.from_bytes(keccak(_OZ_ERC20_NAMESPACE), "big") & ~0xFF

# Read-back anchors. Each MUST be a direct read of the mapping it anchors: the
# read-back compares with strict equality, so a computed getter (a rebasing
# ``balanceOf = shares * rate``) simply never matches and its token is left
# unseeded. ``arity`` is the mapping's key count.
_ANCHORS: tuple[tuple[str, int], ...] = (
    ("balanceOf(address)", 1),
    ("shares(address)", 1),
    ("sharesOf(address)", 1),
    ("allowance(address,address)", 2),
)

_DECIMALS_SIG = "decimals()"
_DEFAULT_DECIMALS = 18
# Probe amounts pre-encoded by the synthesizer, one whole unit per common token
# scale. The recipe picks by the decimals the discovery block read back.
SEED_UNIT_DECIMALS: tuple[int, ...] = (18, 8, 6)


def selector_of(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


def _word(value: int) -> str:
    return "0x" + format(value & (2**256 - 1), "064x")


def _pad(value: int | str) -> bytes:
    if isinstance(value, str):
        value = int(value, 16)
    return value.to_bytes(32, "big")


def _solidity_slot(base: int, keys: Sequence[int | str]) -> str:
    """``m[k1][k2] = keccak(pad(k2) ++ keccak(pad(k1) ++ base))``."""
    slot = base.to_bytes(32, "big")
    for key in keys:
        slot = keccak(_pad(key) + slot)
    return "0x" + slot.hex()


def _vyper_slot(base: int, keys: Sequence[int | str]) -> str:
    """Vyper's ``HashMap`` folds the other way: ``keccak(base ++ pad(k))``."""
    slot = base.to_bytes(32, "big")
    for key in keys:
        slot = keccak(slot + _pad(key))
    return "0x" + slot.hex()


_SLOT_FNS: dict[str, Callable[[int, Sequence[int | str]], str]] = {
    "solidity": _solidity_slot,
    "vyper": _vyper_slot,
}


@dataclass(frozen=True)
class AnchorSlot:
    """One read-back-verified mapping the principal's precondition lives in.
    ``base`` + ``ordering`` reconstruct the concrete slot for any holder, so the
    layout is holder-independent and memoizable per (chain, token)."""

    signature: str
    arity: int
    ordering: str  # solidity | vyper
    base: int

    def slot(self, holder: str, spender: str) -> str:
        keys: list[int | str] = [holder] if self.arity == 1 else [holder, spender]
        return _SLOT_FNS[self.ordering](self.base, keys)

    def readback_calldata(self, holder: str, spender: str) -> str:
        args = _pad(holder).hex() if self.arity == 1 else _pad(holder).hex() + _pad(spender).hex()
        return selector_of(self.signature) + args


@dataclass(frozen=True)
class TokenLayout:
    """What a token's storage proved to be, or nothing. ``anchors`` empty means
    discovery failed — the caller must leave the token unseeded."""

    token: str
    decimals: int = _DEFAULT_DECIMALS
    anchors: tuple[AnchorSlot, ...] = ()


@dataclass(frozen=True)
class SeedRequest:
    """What a probe needs seeded. ``token_hints`` are zero-arg getter signatures
    on ``spender`` naming the input asset (``"__self__"`` means the probe target
    itself — a withdrawal burning the caller's own share token)."""

    spender: str
    principal: str
    token_hints: tuple[str, ...]
    block_tag: str


@dataclass(frozen=True)
class Seeding:
    """A confirmed seed. ``readback_calls`` are prepended to the probe block and
    each MUST return ``readback_expected`` for the probe to count."""

    overrides: StateOverride
    readback_calls: tuple[SimCall, ...]
    readback_expected: tuple[str, ...]
    tokens: tuple[str, ...]
    decimals: int
    detail: dict[str, Any] = field(default_factory=dict)


Seeder = Callable[[SeedRequest], "Seeding | None"]


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _candidate_bases() -> list[tuple[str, int]]:
    """``(ordering, base)`` candidates, deterministic."""
    seen: set[tuple[str, int]] = set()
    out: list[tuple[str, int]] = []
    for base in (OZ_V5_ERC20_BASE, OZ_V5_ERC20_BASE + 1):
        key = ("solidity", base)
        if key not in seen:
            seen.add(key)
            out.append(key)
    for base in range(MAX_BASE_SLOT):
        key = ("solidity", base)
        if key not in seen:
            seen.add(key)
            out.append(key)
    for base in range(MAX_VYPER_BASE_SLOT):
        key = ("vyper", base)
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def discover_token_layout(
    simulate: Simulate,
    *,
    token: str,
    holder: str,
    spender: str,
    block_tag: str,
    narrow: bool = False,
) -> TokenLayout:
    """Identify ``token``'s balance/shares/allowance base slots by READ-BACK.

    One simulated block writes a DISTINCT magic word to every candidate slot and
    calls each anchor getter once. A getter that returns magic ``n`` is, by
    construction, a direct read of candidate ``n`` — the identification and its
    verification are the same observation. A getter that returns anything else
    (a computed/rebasing balance, an unsupported layout) yields no anchor and the
    token stays unseeded.

    The wide write is safe precisely because this block's ONLY calls are view
    getters whose results are used for identification and then discarded; no
    verdict is derived from a block in this state. ``narrow`` retries with a
    handful of low slots for a token the wide perturbation made revert.
    """
    bases = _candidate_bases()
    if narrow:
        keep = {OZ_V5_ERC20_BASE, OZ_V5_ERC20_BASE + 1, 0, 1, 2, 3}
        bases = [b for b in bases if b[1] in keep]
    overrides: dict[str, str] = {}
    tag: dict[int, tuple[str, int, int]] = {}
    index = 0
    for ordering, base in bases:
        for arity in (1, 2):
            if index > _MAGIC_MASK:
                break
            magic = _MAGIC_PREFIX | index
            keys: list[int | str] = [holder] if arity == 1 else [holder, spender]
            overrides[_SLOT_FNS[ordering](base, keys)] = _word(magic)
            tag[magic] = (ordering, base, arity)
            index += 1

    calls = [SimCall(to=token, data=selector_of(sig) + _anchor_args(arity, holder, spender)) for sig, arity in _ANCHORS]
    calls.append(SimCall(to=token, data=selector_of(_DECIMALS_SIG)))
    try:
        result = simulate(calls, block_tag, {token.lower(): {"stateDiff": overrides}})
    except Exception:  # noqa: BLE001 - a failed discovery only means "do not seed"
        logger.debug("effects seeding: discovery simulate failed for %s", token, exc_info=True)
        return TokenLayout(token=token.lower())
    if result is None or len(result.calls) < len(calls):
        return TokenLayout(token=token.lower())

    anchors: list[AnchorSlot] = []
    reverted = False
    for (sig, arity), call_result in zip(_ANCHORS, result.calls, strict=False):
        if not call_result.success:
            reverted = True
            continue
        value = _to_int(call_result.return_data)
        hit = tag.get(value) if value is not None else None
        if hit is None:
            continue
        ordering, base, hit_arity = hit
        if hit_arity != arity:
            # The getter read a slot derived with a different key count than its
            # own signature implies — the layout is not what it looks like, so
            # this anchor is not trustworthy. Drop it rather than guess.
            continue
        anchors.append(AnchorSlot(signature=sig, arity=arity, ordering=ordering, base=base))

    decimals = _to_int(result.calls[len(_ANCHORS)].return_data) if result.calls[len(_ANCHORS)].success else None
    if decimals is None or not (0 < decimals <= 36):
        decimals = _DEFAULT_DECIMALS

    if not anchors and reverted and not narrow:
        # Every anchor reverted: the wide write probably clobbered a slot the
        # getter itself depends on. Retry with a much smaller perturbation.
        return discover_token_layout(
            simulate, token=token, holder=holder, spender=spender, block_tag=block_tag, narrow=True
        )
    return TokenLayout(token=token.lower(), decimals=decimals, anchors=tuple(anchors))


def _anchor_args(arity: int, holder: str, spender: str) -> str:
    return _pad(holder).hex() if arity == 1 else _pad(holder).hex() + _pad(spender).hex()


def _to_int(hexval: str | None) -> int | None:
    if not hexval or not isinstance(hexval, str) or hexval == "0x":
        return None
    try:
        return int(hexval, 16)
    except ValueError:
        return None


def _to_address(hexval: str | None) -> str | None:
    """Last 20 bytes of a 32-byte return word, when it is a plausible address."""
    if not isinstance(hexval, str) or not hexval.startswith("0x"):
        return None
    body = hexval[2:]
    if len(body) < 40:
        return None
    # A 32-byte word whose high 12 bytes are non-zero is not an address.
    if len(body) >= 64 and int(body[-64:-40], 16) != 0:
        return None
    addr = "0x" + body[-40:].lower()
    if int(addr, 16) == 0:
        return None
    return addr


# ---------------------------------------------------------------------------
# The Seeder seam
# ---------------------------------------------------------------------------


class SimulateSeeder:
    """Default :data:`Seeder`, backed by the Tier-1 ``eth_simulateV1`` seam.

    Memoized twice over its lifetime (one per job): token identity per
    ``spender`` and storage layout per token. A protocol's many candidates on one
    vault therefore pay discovery once, and its handful of distinct input assets
    pay layout discovery once each."""

    def __init__(self, simulate: Simulate, *, chain_id: int = 0, max_tokens: int = 3) -> None:
        self._simulate = simulate
        self._chain_id = chain_id
        self._max_tokens = max_tokens
        self._tokens: dict[tuple[str, tuple[str, ...]], tuple[str, ...]] = {}
        self._layouts: dict[str, TokenLayout] = {}
        self.request_count = 0

    def __call__(self, request: SeedRequest) -> Seeding | None:
        tokens = self._resolve_tokens(request)
        if not tokens:
            return None
        overrides: dict[str, dict[str, Any]] = {}
        readback_calls: list[SimCall] = []
        readback_expected: list[str] = []
        seeded: list[str] = []
        decimals = _DEFAULT_DECIMALS
        for token in tokens:
            layout = self._layout(token, request)
            if not layout.anchors:
                continue
            diff: dict[str, str] = {}
            for anchor in layout.anchors:
                diff[anchor.slot(request.principal, request.spender)] = _word(SEED_AMOUNT)
                readback_calls.append(
                    SimCall(to=token, data=anchor.readback_calldata(request.principal, request.spender))
                )
                readback_expected.append(_word(SEED_AMOUNT))
            overrides[token.lower()] = {"stateDiff": diff}
            if not seeded:
                # The probe amount follows the FIRST seeded token's scale — the
                # highest-priority hint, i.e. the asset static said flows in.
                decimals = layout.decimals
            seeded.append(token.lower())
        if not seeded:
            return None
        return Seeding(
            overrides=overrides,
            readback_calls=tuple(readback_calls),
            readback_expected=tuple(readback_expected),
            tokens=tuple(seeded),
            decimals=decimals,
            detail={
                "tokens": seeded,
                "anchors": [
                    {"token": token, "getter": a.signature, "ordering": a.ordering, "base_slot": a.base}
                    for token in seeded
                    for a in self._layouts[token].anchors
                ],
            },
        )

    def _resolve_tokens(self, request: SeedRequest) -> tuple[str, ...]:
        key = (request.spender.lower(), request.token_hints)
        cached = self._tokens.get(key)
        if cached is not None:
            return cached
        getters = [h for h in request.token_hints if h != "__self__"]
        resolved: list[str] = []
        if "__self__" in request.token_hints:
            resolved.append(request.spender.lower())
        if getters:
            calls = [SimCall(to=request.spender, data=selector_of(sig)) for sig in getters]
            try:
                self.request_count += 1
                result = self._simulate(calls, request.block_tag, None)
            except Exception:  # noqa: BLE001 - no identity ⇒ no seeding
                logger.debug("effects seeding: token-getter probe failed on %s", request.spender, exc_info=True)
                result = None
            for call_result in (result.calls if result is not None else ())[: len(getters)]:
                if not call_result.success:
                    continue
                address = _to_address(call_result.return_data)
                if address and address not in resolved:
                    resolved.append(address)
        tokens = tuple(resolved[: self._max_tokens])
        self._tokens[key] = tokens
        return tokens

    def _layout(self, token: str, request: SeedRequest) -> TokenLayout:
        cached = self._layouts.get(token)
        if cached is not None:
            return cached
        self.request_count += 1
        layout = discover_token_layout(
            self._simulate,
            token=token,
            holder=request.principal,
            spender=request.spender,
            block_tag=request.block_tag,
        )
        self._layouts[token] = layout
        return layout


def eth_value_override(principal: str, overrides: StateOverride | None = None) -> StateOverride:
    """Add the principal's ETH balance to ``overrides`` (never replacing an
    existing token diff). Only the balance field is set, so a contract
    principal's code and storage are untouched."""
    merged: dict[str, dict[str, Any]] = {k: dict(v) for k, v in (overrides or {}).items()}
    account = merged.setdefault(principal.lower(), {})
    account["balance"] = _word(SEED_ETH_BALANCE)
    return merged
