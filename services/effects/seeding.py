"""Input-asset seeding for Tier-1 probes.

Deposit-backed conversions (``WeETH.wrap``, vault ``deposit``) pull an input asset the simulated principal doesn't hold.
``eth_simulateV1`` with ``validation:false`` skips ETH checks but not ERC-20 state, so the probe reverts and the
function drops out of the mint population (``supply.mint`` backing was empty on every row).

This gives the principal the input asset and nothing else:

1. Seeding is a retry, never the first attempt: the unseeded call must have failed, so any asset the seeded call
consumes was genuinely required (otherwise a payable admin mint could bank our ETH as "backing").
2. Read-back or nothing: a slot is seeded only after the token's own getter echoed a magic word
(:func:`discover_token_layout`), and the probe block re-reads it. Rebasing, computed or exotic tokens never echo and
stay unseeded.
3. Seeding never manufactures a witness: storage writes emit no logs, so every observed Transfer came from the contract.

Only the principal's balance/shares/allowance of a candidate token, plus (second attempt only) ETH for ``msg.value``.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from eth_utils.crypto import keccak

from services.effects.simulate import SimCall, Simulate, StateOverride

logger = logging.getLogger(__name__)

_TRUTHY = {"1", "true", "yes", "on"}

_RESOLVED_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


def input_seeding_enabled() -> bool:
    """Kill switch; default on. Off restores the exact pre-seeding probe."""
    return os.getenv("PSAT_EFFECTS_INPUT_SEEDING", "1").strip().lower() in _TRUTHY


# Per-job cost ceiling. The seeded retry runs on the common path (most probes revert), and each costs an identity block,
# a layout-discovery block (hundreds of overrides, plus a ``narrow`` retry), up to two seeded attempts and a seeded
# sentinel. Memoization is per distinct spender/token with no ceiling, so many vaults scale linearly. Exceeding a cap
# degrades to exactly the unseeded probe and is logged; raise via env when needed.
_DEFAULT_MAX_IDENTITY_PROBES = 16
_DEFAULT_MAX_LAYOUT_DISCOVERIES = 8
_DEFAULT_MAX_PROBE_RETRIES = 24

# Sample size for the log line; counters carry totals.
_SKIP_SAMPLE = 8


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return max(0, int(raw))
    except ValueError:
        return default


@dataclass
class SeedBudget:
    """Per-job ceiling and counters for the seeded-retry path.

    Each ``take_*`` is called right before the work it authorizes, so a refusal skips exactly one RPC block. A cap of
    ``0`` disables that work.
    """

    max_identity_probes: int = _DEFAULT_MAX_IDENTITY_PROBES
    max_layout_discoveries: int = _DEFAULT_MAX_LAYOUT_DISCOVERIES
    max_probe_retries: int = _DEFAULT_MAX_PROBE_RETRIES

    identity_probes: int = 0
    layout_discoveries: int = 0
    probe_retries: int = 0
    # Yield counters, so the next run measures results and not just cost.
    probes_executed: int = 0
    verdicts_proven_seeded: int = 0

    skipped_identity_probes: int = 0
    skipped_layout_discoveries: int = 0
    skipped_probe_retries: int = 0
    skipped_names: list[str] = field(default_factory=list)
    # Failure reasons, so ``executed=0`` says which precondition failed.
    attempt_outcomes: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "SeedBudget":
        return cls(
            max_identity_probes=_int_env("PSAT_EFFECTS_SEED_MAX_IDENTITY_PROBES", _DEFAULT_MAX_IDENTITY_PROBES),
            max_layout_discoveries=_int_env("PSAT_EFFECTS_SEED_MAX_DISCOVERIES", _DEFAULT_MAX_LAYOUT_DISCOVERIES),
            max_probe_retries=_int_env("PSAT_EFFECTS_SEED_MAX_RETRIES", _DEFAULT_MAX_PROBE_RETRIES),
        )

    def _deny(self, kind: str, name: str, used: int, cap: int, skipped: int) -> None:
        if len(self.skipped_names) < _SKIP_SAMPLE:
            self.skipped_names.append(f"{kind}:{name}")
        # WARNING only on the first denial; ``used`` stops at the cap, so the skip counter tells them apart.
        level = logging.WARNING if skipped == 1 else logging.DEBUG
        logger.log(
            level,
            "effects seeding: %s budget exhausted (%d/%d) — skipping %s; probe degrades to unseeded",
            kind,
            used,
            cap,
            name,
        )

    def take_identity(self, spender: str) -> bool:
        if self.identity_probes >= self.max_identity_probes:
            self.skipped_identity_probes += 1
            self._deny(
                "identity", spender, self.identity_probes, self.max_identity_probes, self.skipped_identity_probes
            )
            return False
        self.identity_probes += 1
        return True

    def take_layout(self, token: str) -> bool:
        if self.layout_discoveries >= self.max_layout_discoveries:
            self.skipped_layout_discoveries += 1
            self._deny(
                "layout", token, self.layout_discoveries, self.max_layout_discoveries, self.skipped_layout_discoveries
            )
            return False
        self.layout_discoveries += 1
        return True

    def take_retry(self, target: str) -> bool:
        if self.probe_retries >= self.max_probe_retries:
            self.skipped_probe_retries += 1
            self._deny("retry", target, self.probe_retries, self.max_probe_retries, self.skipped_probe_retries)
            return False
        self.probe_retries += 1
        return True

    def record_executed(self) -> None:
        self.probes_executed += 1

    def record_proven(self) -> None:
        self.verdicts_proven_seeded += 1

    def record_outcome(self, outcome: str) -> None:
        self.attempt_outcomes[outcome] = self.attempt_outcomes.get(outcome, 0) + 1

    def metrics(self) -> dict[str, int]:
        return {
            "seed_identity_probes": self.identity_probes,
            "seed_layout_discoveries": self.layout_discoveries,
            "seed_probe_retries": self.probe_retries,
            "seed_probes_executed": self.probes_executed,
            "seed_verdicts_proven": self.verdicts_proven_seeded,
            "seed_budget_skips": (
                self.skipped_identity_probes + self.skipped_layout_discoveries + self.skipped_probe_retries
            ),
            **{f"seed_outcome_{reason}": count for reason, count in sorted(self.attempt_outcomes.items())},
        }

    @property
    def exhausted_any(self) -> bool:
        return bool(self.skipped_identity_probes or self.skipped_layout_discoveries or self.skipped_probe_retries)

    def summary(self) -> str:
        return (
            f"identity={self.identity_probes}/{self.max_identity_probes} "
            f"layout={self.layout_discoveries}/{self.max_layout_discoveries} "
            f"retries={self.probe_retries}/{self.max_probe_retries} "
            f"executed={self.probes_executed} proven={self.verdicts_proven_seeded} "
            f"skipped(identity/layout/retry)="
            f"{self.skipped_identity_probes}/{self.skipped_layout_discoveries}/{self.skipped_probe_retries} "
            f"outcomes={dict(sorted(self.attempt_outcomes.items()))} "
            f"sample={self.skipped_names}"
        )


def budget_of(seeder: object) -> "SeedBudget | None":
    """The :class:`SeedBudget` a seeder carries, read structurally since ``Seeder`` is a plain callable seam."""
    budget = getattr(seeder, "budget", None)
    return budget if isinstance(budget, SeedBudget) else None


# Far above any probe amount, far below overflow.
SEED_AMOUNT = 2**128

# One ether clears common minimum deposits (0.1 ETH) without tripping caps.
SEED_ETH_VALUE = 10**18
SEED_ETH_BALANCE = 10**19

# ETH given to the target contract (never the caller) on the last, most synthetic retry: a payout that reverts on a
# short treasury says nothing about the function.
SEED_CONTRACT_ETH_BALANCE = 10**20

# OZ-upgradeable ``__gap`` arrays push balances deep (weETH ``_balances`` at 101, eETH ``shares`` at 203).
MAX_BASE_SLOT = 256
# Vyper hashes keys the other way and declares balances near the top.
MAX_VYPER_BASE_SLOT = 16

# Low bits carry the candidate index, so one read identifies which slot the getter reads. At 2**128: above any real
# supply, low enough that a scaling getter produces a distinct value rather than wrapping into the magic range.
_MAGIC_PREFIX = 0x5EED5EED << 128
_MAGIC_MASK = 0xFFFF

# OZ v5 ERC-7201: ``_balances`` at the ``ERC20Storage`` base, ``_allowances`` at base + 1.
_OZ_ERC20_NAMESPACE = (int.from_bytes(keccak(text="openzeppelin.storage.ERC20"), "big") - 1).to_bytes(32, "big")
OZ_V5_ERC20_BASE = int.from_bytes(keccak(_OZ_ERC20_NAMESPACE), "big") & ~0xFF

# Each anchor must directly read its mapping; strict equality means computed getters never match. ``arity`` is the key
# count.
_ANCHORS: tuple[tuple[str, int], ...] = (
    ("balanceOf(address)", 1),
    ("shares(address)", 1),
    ("sharesOf(address)", 1),
    ("allowance(address,address)", 2),
)

_DECIMALS_SIG = "decimals()"
_TOTAL_SUPPLY_SIG = "totalSupply()"
_DEFAULT_DECIMALS = 18
# One whole unit per common scale; the recipe picks by discovered decimals.
SEED_UNIT_DECIMALS: tuple[int, ...] = (18, 8, 6)

# Floor for a capped holder seed: one unit at the largest probe scale. See :func:`balance_seed_amount`.
MIN_BALANCE_SEED = 10 ** max(SEED_UNIT_DECIMALS)


def selector_of(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


def _word(value: int) -> str:
    return "0x" + format(value & (2**256 - 1), "064x")


def _pad(value: int | str) -> bytes:
    if isinstance(value, str):
        value = int(value, 16)
    return value.to_bytes(32, "big")


def _solidity_slot(base: int, keys: Sequence[int | str]) -> str:
    slot = base.to_bytes(32, "big")
    for key in keys:
        slot = keccak(_pad(key) + slot)
    return "0x" + slot.hex()


def _vyper_slot(base: int, keys: Sequence[int | str]) -> str:
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
    """One read-back-verified mapping.

    ``base`` and ``ordering`` rebuild the slot for any holder, so it memoizes per (chain, token).
    """

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
    """A token's proven storage layout; empty ``anchors`` means discovery failed and the token stays unseeded."""

    token: str
    decimals: int = _DEFAULT_DECIMALS
    anchors: tuple[AnchorSlot, ...] = ()
    # Keeps a seeded holder balance within supply; see :func:`balance_seed_amount`.
    total_supply: int | None = None


@dataclass(frozen=True)
class SeedRequest:
    """What a probe needs seeded.

    ``token_hints`` are zero-arg getters on ``spender`` naming the input asset, or resolved addresses (``"__self__"`` is
    the probe target itself, for withdrawals burning the caller's shares).
    """

    spender: str
    principal: str
    token_hints: tuple[str, ...]
    block_tag: str


@dataclass(frozen=True)
class Seeding:
    """A confirmed seed.

    ``readback_calls`` are prepended to the probe block and must each return ``readback_expected``.
    """

    overrides: StateOverride
    readback_calls: tuple[SimCall, ...]
    readback_expected: tuple[str, ...]
    tokens: tuple[str, ...]
    decimals: int
    detail: dict[str, Any] = field(default_factory=dict)


Seeder = Callable[[SeedRequest], "Seeding | None"]


def _candidate_bases() -> list[tuple[str, int]]:
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
    """Find ``token``'s balance/shares/allowance base slots by read-back.

    One simulated block writes a distinct magic word to every candidate slot and calls each anchor getter; returning
    magic ``n`` both identifies and verifies candidate ``n``. Anything else yields no anchor.

    The wide write is safe because this block only makes view calls used for identification. ``narrow`` retries with a
    few low slots when the wide write made the getters revert.
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
    # Rides the discovery block; only mapping slots were perturbed, so a scalar supply reads true.
    calls.append(SimCall(to=token, data=selector_of(_TOTAL_SUPPLY_SIG)))
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
            # Slot derived with a different key count than the signature implies: untrustworthy, drop it.
            continue
        anchors.append(AnchorSlot(signature=sig, arity=arity, ordering=ordering, base=base))

    decimals = _to_int(result.calls[len(_ANCHORS)].return_data) if result.calls[len(_ANCHORS)].success else None
    if decimals is None or not (0 < decimals <= 36):
        decimals = _DEFAULT_DECIMALS

    supply_call = result.calls[len(_ANCHORS) + 1]
    total_supply = _to_int(supply_call.return_data) if supply_call.success else None

    if not anchors and reverted and not narrow:
        # The wide write probably clobbered something the getter needs.
        return discover_token_layout(
            simulate, token=token, holder=holder, spender=spender, block_tag=block_tag, narrow=True
        )
    return TokenLayout(token=token.lower(), decimals=decimals, anchors=tuple(anchors), total_supply=total_supply)


def balance_seed_amount(anchor: AnchorSlot, layout: TokenLayout) -> int:
    """How much to write into one seeded slot.

    A holder balance is capped at ``totalSupply``: more shares than exist makes a burn wrap ``unchecked { totalSupply -=
    amount }`` and read as a huge mint, a state no real chain reaches. Zero or unanswered supply leaves the full seed.

    Allowances aren't capped (``type(uint256).max`` is ordinary).

    The cap never goes below :data:`MIN_BALANCE_SEED`, because the probe amount follows the first seeded token's
    decimals while the cap follows each token's own supply (an 18-decimal first token plus a USDC cap would underseed
    and revert). Below the floor the wrap is still caught downstream.
    """
    if anchor.arity != 1:
        return SEED_AMOUNT
    supply = layout.total_supply
    if supply is None or supply <= 0:
        return SEED_AMOUNT
    return max(min(SEED_AMOUNT, supply), MIN_BALANCE_SEED)


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
    """Last 20 bytes of a 32-byte word, when it's a plausible address."""
    if not isinstance(hexval, str) or not hexval.startswith("0x"):
        return None
    body = hexval[2:]
    if len(body) < 40:
        return None
    if len(body) >= 64 and int(body[-64:-40], 16) != 0:
        return None
    addr = "0x" + body[-40:].lower()
    if int(addr, 16) == 0:
        return None
    return addr


class SimulateSeeder:
    """Default :data:`Seeder`, backed by ``eth_simulateV1``.

    Memoizes token identity per ``spender`` and layout per token for the job; :class:`SeedBudget` caps how many distinct
    ones it pays for.
    """

    def __init__(
        self,
        simulate: Simulate,
        *,
        chain_id: int = 0,
        max_tokens: int = 3,
        budget: SeedBudget | None = None,
    ) -> None:
        self._simulate = simulate
        self._chain_id = chain_id
        self._max_tokens = max_tokens
        self._tokens: dict[tuple[str, tuple[str, ...]], tuple[str, ...]] = {}
        self._layouts: dict[str, TokenLayout] = {}
        self.request_count = 0
        self.budget = budget if budget is not None else SeedBudget.from_env()

    def __call__(self, request: SeedRequest) -> Seeding | None:
        tokens = self._resolve_tokens(request)
        if not tokens:
            return None
        overrides: dict[str, dict[str, Any]] = {}
        readback_calls: list[SimCall] = []
        readback_expected: list[str] = []
        seeded: list[str] = []
        decimals = _DEFAULT_DECIMALS
        # An address hint is a holding of the deployment, not an asset the code pulls, so too weak to replace the
        # self-seed below.
        literals = {h.lower() for h in request.token_hints if _RESOLVED_ADDRESS.match(h)}
        for token in tokens:
            if token == request.spender.lower() and any(t not in literals for t in seeded):
                # ``__self__`` resolves for free, so every reverting probe would pay a layout discovery for the target.
                # Skip it once a getter-named hint (the asset static saw flow in) has anchors. A function that also
                # burns its caller's shares may stay ``unknown`` (fail-closed).
                continue
            layout = self._layout(token, request)
            if not layout.anchors:
                continue
            diff: dict[str, str] = {}
            for anchor in layout.anchors:
                amount = balance_seed_amount(anchor, layout)
                diff[anchor.slot(request.principal, request.spender)] = _word(amount)
                readback_calls.append(
                    SimCall(to=token, data=anchor.readback_calldata(request.principal, request.spender))
                )
                readback_expected.append(_word(amount))
            overrides[token.lower()] = {"stateDiff": diff}
            if not seeded:
                # Amount follows the first seeded token (the asset static said flows in).
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
        # Address hints come from measured holdings and need no getter call.
        literals = [h.lower() for h in request.token_hints if _RESOLVED_ADDRESS.match(h)]
        getters = [
            h for h in request.token_hints if h != "__self__" and h not in literals and not _RESOLVED_ADDRESS.match(h)
        ]
        resolved: list[str] = []
        if getters and self.budget.take_identity(request.spender.lower()):
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
        # After getters: a getter names what the code pulls, stronger than a holding.
        for literal in literals:
            if literal not in resolved:
                resolved.append(literal)
        # ``__self__`` last so it doesn't set the probe's decimals and can be skipped once a real hint has anchors;
        # appended after the cap so it isn't crowded out.
        resolved = resolved[: self._max_tokens]
        if "__self__" in request.token_hints:
            self_token = request.spender.lower()
            if self_token not in resolved:
                resolved.append(self_token)
        tokens = tuple(resolved)
        self._tokens[key] = tokens
        return tokens

    def _layout(self, token: str, request: SeedRequest) -> TokenLayout:
        cached = self._layouts.get(token)
        if cached is not None:
            return cached
        if not self.budget.take_layout(token):
            # Memoized as no-layout; this token stays unseeded for the rest of the job.
            self._layouts[token] = TokenLayout(token=token)
            return self._layouts[token]
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
    """Add the principal's ETH balance to ``overrides`` (balance only; code and storage untouched)."""
    merged: dict[str, dict[str, Any]] = {k: dict(v) for k, v in (overrides or {}).items()}
    account = merged.setdefault(principal.lower(), {})
    account["balance"] = _word(SEED_ETH_BALANCE)
    return merged


def contract_balance_override(contract: str, overrides: StateOverride | None = None) -> StateOverride:
    """Add the target contract's own ETH balance to ``overrides``.

    Unlike caller seeds, this answers "could the function pay out if the contract held funds": a capability, not current
    state. Hence ``contract_balance_seeded`` on the witness and running this attempt last. Balance only.
    """
    merged: dict[str, dict[str, Any]] = {k: dict(v) for k, v in (overrides or {}).items()}
    account = merged.setdefault(contract.lower(), {})
    account["balance"] = _word(SEED_CONTRACT_ETH_BALANCE)
    return merged
