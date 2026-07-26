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
    """Kill-valve for the whole feature. Default ON; setting it off restores the
    exact pre-seeding probe (one unseeded call, no discovery RPCs)."""
    return os.getenv("PSAT_EFFECTS_INPUT_SEEDING", "1").strip().lower() in _TRUTHY


# --------------------------------------------------------------------------
# Per-job cost ceiling
# --------------------------------------------------------------------------
# The seeded retry fires on the COMMON path, not the rare one: it runs whenever
# an unseeded value_out/supply probe reverted, and reverting is what most probes
# do (5 of 34 value_out probes proved on the last live run). Each retry costs a
# token-identity block, a layout-discovery block (548 storage overrides, ~70KB of
# JSON, plus a ``narrow`` retry when the wide write breaks the getter), up to two
# seeded attempts and a seeded sentinel re-run. Memoization bounds identity and
# layout per DISTINCT spender/token, which is the right shape but has no ceiling:
# a protocol with many distinct vaults scales all of it linearly, on a branch
# whose other half exists to cut effects wall time.
#
# These caps are that ceiling. Exceeding one degrades the probe to EXACTLY its
# pre-seeding behavior (unseeded call, no discovery) — never to a guess — and
# says so in the log and the stage metrics. Raise them per-deployment via env
# when a protocol genuinely needs more.
_DEFAULT_MAX_IDENTITY_PROBES = 16
_DEFAULT_MAX_LAYOUT_DISCOVERIES = 8
_DEFAULT_MAX_PROBE_RETRIES = 24

# How many distinct skipped identities to keep for the log line. The counters
# carry the totals; this is only so the message names something concrete.
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
    """Per-job ceiling + counters for the seeded-retry path.

    One instance per job (the seeder is memoized per ``ProbeContext``). Every
    ``take_*`` is called immediately before the wire work it authorizes, so a
    refusal is exactly one skipped RPC block. A cap of ``0`` disables that kind
    of work outright.
    """

    max_identity_probes: int = _DEFAULT_MAX_IDENTITY_PROBES
    max_layout_discoveries: int = _DEFAULT_MAX_LAYOUT_DISCOVERIES
    max_probe_retries: int = _DEFAULT_MAX_PROBE_RETRIES

    identity_probes: int = 0
    layout_discoveries: int = 0
    probe_retries: int = 0
    # Retries whose seeded attempt actually EXECUTED the target call the unseeded
    # attempt could not, and the subset of those that ended in a proven verdict.
    # Without these the next live run can only re-measure the cost, not the yield.
    probes_executed: int = 0
    verdicts_proven_seeded: int = 0

    skipped_identity_probes: int = 0
    skipped_layout_discoveries: int = 0
    skipped_probe_retries: int = 0
    skipped_names: list[str] = field(default_factory=list)
    # Why individual seeded attempts (and whole retry paths) came to nothing,
    # counted by reason. Without this a run reporting ``executed=0`` says only
    # that seeding failed, never which precondition failed — which is the whole
    # difference between a bug and an honest non-observation.
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
        # WARNING on the FIRST denial of this kind only. ``used`` cannot express
        # that — it stops incrementing once the cap is reached, so it equals
        # ``cap`` for every subsequent denial. The skip counter is what
        # distinguishes them, and a large protocol would otherwise flood the very
        # log this truncation notice exists to make readable.
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
        """Count one attempt/skip outcome by reason (see ``recipes._OUTCOME_*``)."""
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
    """The :class:`SeedBudget` a seeder carries, if any.

    ``Seeder`` is a plain callable seam (tests inject lambdas), so the budget is
    read structurally rather than widening the alias into a Protocol every stub
    would then have to satisfy."""
    budget = getattr(seeder, "budget", None)
    return budget if isinstance(budget, SeedBudget) else None


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

# ETH handed to the TARGET CONTRACT (never the caller) on the last, most
# synthetic retry. A redemption/sweep pays out of the contract's own balance and
# reverts before its send when that balance is short — the revert is about this
# block's treasury, not about what the function can do. 100 ETH clears a realistic
# single redemption while staying far below any overflow concern.
SEED_CONTRACT_ETH_BALANCE = 10**20

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
_TOTAL_SUPPLY_SIG = "totalSupply()"
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
    # The token's own ``totalSupply`` at the discovery block, when it answered.
    # Used to keep a seeded holder balance inside the supply that backs it; see
    # :func:`balance_seed_amount`.
    total_supply: int | None = None


@dataclass(frozen=True)
class SeedRequest:
    """What a probe needs seeded. ``token_hints`` are zero-arg getter signatures
    on ``spender`` naming the input asset, or already-resolved token addresses
    (``"__self__"`` means the probe target itself — a withdrawal burning the
    caller's own share token)."""

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
    # Rides the discovery block rather than costing a round trip of its own. The
    # perturbation above writes only keccak-derived MAPPING slots, so a scalar
    # ``totalSupply`` reads its true value here.
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
            # The getter read a slot derived with a different key count than its
            # own signature implies — the layout is not what it looks like, so
            # this anchor is not trustworthy. Drop it rather than guess.
            continue
        anchors.append(AnchorSlot(signature=sig, arity=arity, ordering=ordering, base=base))

    decimals = _to_int(result.calls[len(_ANCHORS)].return_data) if result.calls[len(_ANCHORS)].success else None
    if decimals is None or not (0 < decimals <= 36):
        decimals = _DEFAULT_DECIMALS

    supply_call = result.calls[len(_ANCHORS) + 1]
    total_supply = _to_int(supply_call.return_data) if supply_call.success else None

    if not anchors and reverted and not narrow:
        # Every anchor reverted: the wide write probably clobbered a slot the
        # getter itself depends on. Retry with a much smaller perturbation.
        return discover_token_layout(
            simulate, token=token, holder=holder, spender=spender, block_tag=block_tag, narrow=True
        )
    return TokenLayout(token=token.lower(), decimals=decimals, anchors=tuple(anchors), total_supply=total_supply)


def balance_seed_amount(anchor: AnchorSlot, layout: TokenLayout) -> int:
    """How much to write into one seeded slot.

    A HOLDER BALANCE is capped at the token's own ``totalSupply``, because
    ``totalSupply >= balanceOf(holder)`` is an invariant every real token
    maintains and this seed writes storage directly, with nothing to enforce it.
    Handing a caller more shares than exist makes a burn arithmetically
    impossible: ``unchecked { totalSupply -= amount }`` wraps past zero, and the
    supply recipe then reads a burn as an enormous INCREASE. The recipe now
    survives that on its own, but a fork state no real chain can reach is not a
    sound thing to derive a verdict from in the first place.

    One whole token unit is the largest amount any probe attaches, so capping at
    the live supply still clears every balance precondition on a token with a
    non-trivial supply. A supply of zero, or a token that would not answer
    ``totalSupply()``, leaves the seed at its full value — there is no invariant
    to respect and the alternative is seeding nothing at all.

    An ALLOWANCE is not capped: approvals above the supply are ordinary (the
    ``type(uint256).max`` idiom) and bound nothing that could wrap."""
    if anchor.arity != 1:
        return SEED_AMOUNT
    supply = layout.total_supply
    if supply is None or supply <= 0:
        return SEED_AMOUNT
    return min(SEED_AMOUNT, supply)


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
    pay layout discovery once each. :class:`SeedBudget` caps how many DISTINCT
    ones a single job may pay for at all."""

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
        # A hint that is already an address is a HOLDING of the acting deployment,
        # not an asset the code was seen to pull. It is therefore too weak to stand
        # in for the self-seed below.
        literals = {h.lower() for h in request.token_hints if _RESOLVED_ADDRESS.match(h)}
        for token in tokens:
            if token == request.spender.lower() and any(t not in literals for t in seeded):
                # ``__self__`` is the always-appended fallback candidate (the
                # withdrawal-burns-your-own-shares shape) and it resolves without
                # a wire call, so EVERY reverting probe would otherwise pay a
                # layout discovery for the probe target itself. A GETTER-named hint
                # that already yielded anchors is the asset static actually saw
                # flow in, so the fallback adds a discovery block for a seed the
                # call has no evidence of needing. Ordered last by
                # ``_resolve_tokens``, so ``seeded`` here holds only non-self
                # candidates. Cost: a function that pulls one asset AND burns the
                # caller's own shares gets only the former seeded and may stay
                # ``unknown`` — the fail-closed direction.
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
        # A hint that is already an address needs no getter call: it came from the
        # acting deployment's own measured holdings, not from a name.
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
        # After the getters: a getter names the asset the CODE pulls, which is
        # stronger evidence than "the deployment happens to hold it".
        for literal in literals:
            if literal not in resolved:
                resolved.append(literal)
        # ``__self__`` LAST, not first: it costs no wire call to resolve, but it
        # sets the seeded probe's decimals when it is seeded first — and the
        # amount is meant to be one whole unit of the INPUT asset static named,
        # not of the probe target. Ordering it last also lets ``__call__`` drop
        # its discovery once a specific hint has produced anchors. It is appended
        # AFTER the cap so a long candidate list cannot crowd out the one seed a
        # share-burning withdrawal needs.
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
            # Memoized as "no layout" so the refusal costs one check, not one per
            # candidate. A capped job seeds nothing further for this token and
            # its probes stay exactly as unseeded as they were before seeding
            # existed.
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
    """Add the principal's ETH balance to ``overrides`` (never replacing an
    existing token diff). Only the balance field is set, so a contract
    principal's code and storage are untouched."""
    merged: dict[str, dict[str, Any]] = {k: dict(v) for k, v in (overrides or {}).items()}
    account = merged.setdefault(principal.lower(), {})
    account["balance"] = _word(SEED_ETH_BALANCE)
    return merged


def contract_balance_override(contract: str, overrides: StateOverride | None = None) -> StateOverride:
    """Add the TARGET CONTRACT's own ETH balance to ``overrides``.

    Semantically distinct from every other seed here, and the distinction has to
    travel with the verdict: seeding the caller answers "could a caller reach this
    function", seeding the contract answers "could this function pay out IF the
    contract held funds". A verdict proven under this override is a CAPABILITY
    claim about the code, not a statement that the money is there today — which is
    why the recipes stamp ``contract_balance_seeded`` on the witness and run this
    attempt LAST, after every less synthetic one has failed.

    Only the balance field is set, so the contract's code and storage are
    untouched (and any token seeding on the same account survives)."""
    merged: dict[str, dict[str, Any]] = {k: dict(v) for k, v in (overrides or {}).items()}
    account = merged.setdefault(contract.lower(), {})
    account["balance"] = _word(SEED_CONTRACT_ETH_BALANCE)
    return merged
