"""Plan-input dataclasses and probe constants."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # typing-only: the effects plane stays off static's runtime import graph
    pass


from services.effects.anvil import EntryPoint, ForkFixture
from services.effects.config import (
    DURATION_BOUND_NOT_DETERMINED,
)
from services.effects.selection import AssetHolding

logger = logging.getLogger(__name__)

# The attacker identity substituted at a taint-identified address param.
SENTINEL_ADDRESS = "0x" + "ee" * 20

# Caller for a blast-radius entry point with no resolved principal — a plain
# identity, kept distinct from the sentinel so a transfer landing on the attacker
# can never be confused with one landing on a prober.
NEUTRAL_CALLER = "0x" + "11" * 20

# Numeric filler for value-carrying params. 1 (wei / smallest unit) rather than 0
# because a zero-amount transfer moves nothing observable, and rather than a large
# amount because real contracts gate on rate limiters and balances — a 1-wei call
# is the one that got through on the 2026-07-21 live run.
ARG_AMOUNT = 1

# Filler for an integer param whose role is an ID / index, not a quantity.
# Deliberately equal to :data:`ARG_AMOUNT` and NEVER scaled by token decimals:
# the seeded retry raises the AMOUNT to one whole unit, and one whole unit
# substituted into a token id is what made every claim/redeem probe revert on its
# own argument (``ERC721: invalid token ID``, measured 2026-07-22). It also has to
# equal the key :func:`_seed_fixture_for_role` writes an ownership seed at, or the
# seeded owner would sit at a token id no probe ever asks about.
ARG_IDENTIFIER = 1

ROLE_AMOUNT = "amount"
ROLE_IDENTIFIER = "identifier"

# Roles for an ADDRESS parameter. ``ROLE_RECIPIENT`` is where the principal
# belongs (it is what makes a payout observable); ``ROLE_TOKEN`` is a slot the
# principal must NEVER occupy — a token/asset argument is dereferenced as a
# contract, so an EOA there reverts the call before any effect (measured:
# ``BoringVault.enter``'s ``asset`` slot, ``TRANSFER_FROM_FAILED``, 8/8 supply
# probes, 2026-07-25 run).
ROLE_RECIPIENT = "recipient"
ROLE_TOKEN = "token"

# Balance handed to every impersonated entry-point caller on the fork so gas can
# never masquerade as a pause revert.
FIXTURE_BALANCE_WEI = 10**19

# Token balance / allowance / shares seeded into a prober's slot so a
# balance/allowance precondition can never make an entry point revert pre-pause
# (which the diff would misread as "the pause froze it"). A clean power of two far
# above ARG_AMOUNT (the 1-unit transfer/mint amount) so amount args always clear
# the check, and far below 2**256 so a ``balance + amount`` path cannot overflow.
SEED_AMOUNT = 2**128

# Upper sanity bound for a pause duration read out of a guard constant: a value
# above this is not a freeze window (it is a chain-id, an amount, a role hash).
_MAX_PLAUSIBLE_DURATION_S = 365 * 24 * 3600


_AUTHORITY_ROLES = ("caller_authority", "delegated_authority")


# ---------------------------------------------------------------------------
# Plan inputs — one dataclass per effect class
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ValueOutPlanInputs:
    """Value-out inputs: call F as the resolved principal, plus a sentinel variant that
    puts the attacker identity at the taint-identified address param."""

    contract_address: str
    principal: str
    calldata: str
    gate_ref: str
    taint_param_reaches_sink: bool = False
    sentinel_address: str | None = None
    sentinel_calldata: str | None = None
    # Downstream value-reach: the protocol's witnessed value-holders the recipe
    # measures against, and the acting deployment's own balance floor. ``None`` on
    # the floor is "no balance row was witnessed for the acting deployment", which
    # the recipe publishes as an absent floor key — not as a zero.
    value_holders: tuple[AssetHolding, ...] = ()
    acting_balance_usd: float | None = None
    protocol_tvl_usd: float | None = None
    # Input-asset seeding: candidate getters naming the asset F pulls, and the
    # whole-unit calldata the SEEDED retry uses. Empty ⇒ no retry, today's probe.
    input_token_hints: tuple[str, ...] = ()
    # Address slots proved to carry a TOKEN. They hold no principal; the seeded
    # retry writes a resolved token address into each, or leaves them at the
    # encoder's default and records why.
    token_param_indexes: tuple[int, ...] = ()
    seeded_calldata: Mapping[int, str] = field(default_factory=dict)
    seeded_sentinel_calldata: Mapping[int, str] = field(default_factory=dict)
    # ABI payability of F, or ``None`` on an artifact that predates the fact.
    # ``False`` suppresses the ``msg.value`` retry, which such a target rejects
    # with an empty revert before its body runs.
    target_payable: bool | None = None
    # Static says F sends native ETH out of the CONTRACT's own balance, so a
    # contract-balance seed could unblock it (see ``has_native_payout``).
    native_payout: bool = False
    # The destination shape static PROVES for every out-flow of F, or ``None``
    # (see :func:`static_destination_shape`). The recipe uses it only where the
    # sentinel did not already prove ``caller_arbitrary``.
    static_shape: str | None = None
    # An argument the effect depends on was left at the encoder's default (see
    # :class:`ProbeArgs`). A call that RAN and observed nothing on such inputs is
    # a fact about the arguments, not about F — so the recipe must name it as one
    # and it must never enter the code-plane behaviour cache.
    inputs_vacuous: bool = False
    # ERC-20 analogue of the native ``contract_balance`` seed: assets the acting
    # deployment PROVABLY holds, so a payout the contract's live balance
    # cannot cover can be reached by seeding the CONTRACT's own token balance. A
    # verdict proven under it is a CAPABILITY claim (would move IF funded) and
    # carries the same weaker ``contract_balance_seeded`` qualifier.
    contract_holdings: tuple[str, ...] = ()
    # The DECLARED NAME of the parameter ``sentinel_calldata`` substituted the
    # sentinel address into (see :func:`_sentinel_param_name`). ``None`` when no
    # sentinel variant was built, or when the slot's name is not recorded on the
    # static plane — an unnamed subject is not a weaker proof, it is a proof
    # about a parameter nothing can join on.
    sentinel_param: str | None = None


@dataclass(frozen=True)
class SupplyPlanInputs:
    """Supply inputs: the recipe reads ``totalSupply`` around a call to F made as
    the resolved principal."""

    token_address: str
    principal: str
    mint_calldata: str
    gate_ref: str
    taint_param_reaches_sink: bool = False
    sentinel_address: str | None = None
    sentinel_calldata: str | None = None
    # Input-asset seeding — see :class:`ValueOutPlanInputs`.
    input_token_hints: tuple[str, ...] = ()
    token_param_indexes: tuple[int, ...] = ()
    seeded_calldata: Mapping[int, str] = field(default_factory=dict)
    seeded_sentinel_calldata: Mapping[int, str] = field(default_factory=dict)
    target_payable: bool | None = None
    native_payout: bool = False
    # See :class:`ValueOutPlanInputs`.
    inputs_vacuous: bool = False
    # See :class:`ValueOutPlanInputs`.
    contract_holdings: tuple[str, ...] = ()
    # NO ``sentinel_param``, for the same reason there is no ``static_shape``: the
    # supply recipe discards the destination shape it resolves, so it publishes no
    # ``caller_arbitrary`` for the parameter name to be the subject OF. A name
    # beside no claim is a field a consumer could only misread.
    #
    # NO ``static_shape``. The supply recipe reads a destination shape only to
    # collect a discrepancy and discards the shape itself, and the supply
    # DIRECTIONS (``mint``/``burn``) are a legacy ``semantic_control`` vocabulary
    # the effects artifact never emits — so threading one here computed nothing
    # and then dropped it.


@dataclass(frozen=True)
class TimelockPlanInputs:
    """Tier-2 timelock inputs: schedule an operation, advance past the delay, execute
    it — the sequence Tier 1 cannot reach, because ``eth_simulateV1`` issues one
    block with no ``blockOverrides`` and so can never satisfy a
    ``block.timestamp`` gate.

    The scheduled operation and the executed one must be the SAME tuple: OZ's
    ``execute`` recomputes the operation id from its own arguments
    (``hashOperation(target, value, payload, predecessor, salt)``), so nothing
    here has to hash anything — it only has to encode the same values twice, once
    with the delay appended.

    The delay is the only argument not knowable offline. It is the contract's own
    ``getMinDelay()``, read on the fork (``delay_calldata``) because OZ rejects a
    schedule below it and the value is per-deployment."""

    contract_address: str
    principal: str
    execute_calldata: str
    schedule_selector: str
    schedule_signature: str
    # The shared tuple, by parameter index, with the trailing delay left out.
    schedule_arguments: Mapping[int, Any]
    delay_index: int
    # Validated at synthesis, so a plan always has a call to make. Also the
    # honest input when the delay cannot be read: the contract's own check
    # rejects a zero delay, and the recipe records that revert verbatim.
    schedule_calldata_zero: str
    # ``getMinDelay()`` — read, never assumed.
    delay_calldata: str
    gate_ref: str
    sentinel_address: str | None = None
    # The asset the value witness is read against, or ``None`` when the timelock
    # provably holds nothing to move. That absence is a FACT about the contract,
    # and the recipe reports it as its own reason rather than as "moved nothing".
    witness_token: str | None = None
    witness_calldata: str | None = None
    fixtures: tuple[ForkFixture, ...] = ()

    def schedule_calldata(self, delay: int) -> str:
        from .encoding import encode_calldata

        subs = dict(self.schedule_arguments)
        subs[self.delay_index] = int(delay)
        return encode_calldata(self.schedule_selector, self.schedule_signature, substitutions=subs) or (
            self.schedule_calldata_zero
        )


@dataclass(frozen=True)
class AuthorityPlanInputs:
    """Authority-change inputs: ``probe_calldata`` exercises the gate G that F mutates;
    ``mutate_calldata`` is the call to F itself."""

    contract_address: str
    principal: str
    mutate_calldata: str
    probe_calldata: str
    probe_function: str
    gate_ref: str


@dataclass(frozen=True)
class PausePlanInputs:
    """Freeze/pause inputs. ``predicted_guard_set`` is static's set — the SCORED
    denominator; ``entry_points`` are the probes we could actually synthesize for
    it (a subset), and the observed blast radius stays a lower bound."""

    contract_address: str
    principal: str
    pause_calldata: str
    entry_points: tuple[EntryPoint, ...]
    predicted_guard_set: tuple[str, ...]
    max_pause_duration: int | None
    gate_ref: str
    fixtures: tuple[ForkFixture, ...] = ()
    # Which of the three ``DURATION_BOUND_*`` states produced
    # ``max_pause_duration``. ``None`` there is two different facts — the latch
    # cannot expire, or we could not find its window — and only this field tells
    # them apart. Defaulted to ``not_determined`` so a caller that omits it can
    # never assert the indefinite reading by accident.
    duration_bound_source: str = DURATION_BOUND_NOT_DETERMINED


@dataclass(frozen=True)
class CandidatePlanInputs:
    """Everything the prober can build for one candidate. Any field may be
    ``None`` — that class simply gets no plan."""

    value_out: ValueOutPlanInputs | None = None
    supply: SupplyPlanInputs | None = None
    authority: AuthorityPlanInputs | None = None
    pause: PausePlanInputs | None = None
    timelock: TimelockPlanInputs | None = None
