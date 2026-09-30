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

logger = logging.getLogger("services.effects.calldata")

SENTINEL_ADDRESS = "0x" + "ee" * 20

# Caller for entry points with no resolved principal; distinct from the sentinel so a transfer to the attacker is never
# confused with one to a prober.
NEUTRAL_CALLER = "0x" + "11" * 20

# 1 unit: zero moves nothing observable, and large amounts trip rate limiters and balance checks.
ARG_AMOUNT = 1

# Filler for ID/index params. Never scaled by decimals (a whole unit as a token id reverted every claim/redeem probe),
# and must equal the key :func:`_seed_fixture_for_role` seeds ownership at.
ARG_IDENTIFIER = 1

ROLE_AMOUNT = "amount"
ROLE_IDENTIFIER = "identifier"

# ``ROLE_RECIPIENT`` is where the principal belongs. ``ROLE_TOKEN`` must never hold the principal: an EOA there reverts
# before any effect (e.g. ``BoringVault.enter``'s ``asset``).
ROLE_RECIPIENT = "recipient"
ROLE_TOKEN = "token"

# Gas for impersonated callers, so it never looks like a pause revert.
FIXTURE_BALANCE_WEI = 10**19

# Seeded so balance/allowance preconditions never make an entry point revert pre-pause. Far above ARG_AMOUNT, far below
# overflow.
SEED_AMOUNT = 2**128

# Anything larger isn't a freeze window (a chain id, amount or role hash).
_MAX_PLAUSIBLE_DURATION_S = 365 * 24 * 3600


_AUTHORITY_ROLES = ("caller_authority", "delegated_authority")


@dataclass(frozen=True)
class ValueOutPlanInputs:
    """Value-out inputs: call F as the principal, plus a sentinel variant at the taint-identified address param."""

    contract_address: str
    principal: str
    calldata: str
    gate_ref: str
    taint_param_reaches_sink: bool = False
    sentinel_address: str | None = None
    sentinel_calldata: str | None = None
    # Value-reach inputs. A ``None`` floor means no balance row was witnessed and is published as an absent key, not
    # zero.
    value_holders: tuple[AssetHolding, ...] = ()
    acting_balance_usd: float | None = None
    protocol_tvl_usd: float | None = None
    # Getters naming the asset F pulls, and the whole-unit retry calldata. Empty means no retry.
    input_token_hints: tuple[str, ...] = ()
    # Slots proved to carry a token: never the principal; the retry writes a resolved token or records why not.
    token_param_indexes: tuple[int, ...] = ()
    seeded_calldata: Mapping[int, str] = field(default_factory=dict)
    seeded_sentinel_calldata: Mapping[int, str] = field(default_factory=dict)
    # ``False`` suppresses the ``msg.value`` retry (rejected before the body). ``None`` on older artifacts.
    target_payable: bool | None = None
    # See ``has_native_payout``.
    native_payout: bool = False
    # Static's proven shape (:func:`static_destination_shape`), used only when the sentinel didn't prove
    # ``caller_arbitrary``.
    static_shape: str | None = None
    # See :class:`ProbeArgs`; such a non-observation must stay out of the behaviour cache.
    inputs_vacuous: bool = False
    # Assets the deployment provably holds, for seeding the contract's own token balance; carries
    # ``contract_balance_seeded``.
    contract_holdings: tuple[str, ...] = ()
    # The declared name of the sentinel's parameter (:func:`_sentinel_param_name`), or ``None`` when no sentinel was
    # built or the slot is unnamed.
    sentinel_param: str | None = None


@dataclass(frozen=True)
class SupplyPlanInputs:
    """Supply inputs: the recipe reads ``totalSupply`` around a call to F as the principal."""

    token_address: str
    principal: str
    mint_calldata: str
    gate_ref: str
    taint_param_reaches_sink: bool = False
    sentinel_address: str | None = None
    sentinel_calldata: str | None = None
    # See :class:`ValueOutPlanInputs`.
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
    # No ``sentinel_param`` or ``static_shape``: the supply recipe publishes no destination shape, and its mint/burn
    # directions never appear as artifact flow directions.


@dataclass(frozen=True)
class TimelockPlanInputs:
    """Tier-2 timelock inputs: schedule, advance past the delay, execute (Tier 1 can't pass a timestamp gate).

    OZ's ``execute`` recomputes the id from its own arguments, so the same tuple is just encoded twice (once with the
    delay). The delay is the contract's ``getMinDelay()``, read on the fork.
    """

    contract_address: str
    principal: str
    execute_calldata: str
    schedule_selector: str
    schedule_signature: str
    # The shared tuple by parameter index, without the trailing delay.
    schedule_arguments: Mapping[int, Any]
    delay_index: int
    # Always a call to make; also the input when the delay can't be read (the contract rejects zero and the recipe
    # records it).
    schedule_calldata_zero: str
    delay_calldata: str
    gate_ref: str
    sentinel_address: str | None = None
    # ``None`` when the timelock provably holds nothing to move; reported as its own reason.
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
    """Authority-change inputs: ``probe_calldata`` exercises the gate G that F mutates; ``mutate_calldata`` calls F."""

    contract_address: str
    principal: str
    mutate_calldata: str
    probe_calldata: str
    probe_function: str
    gate_ref: str


@dataclass(frozen=True)
class PausePlanInputs:
    """Freeze/pause inputs.

    ``predicted_guard_set`` is static's scored denominator; ``entry_points`` are the probes we could synthesize (a
    subset).
    """

    contract_address: str
    principal: str
    pause_calldata: str
    entry_points: tuple[EntryPoint, ...]
    predicted_guard_set: tuple[str, ...]
    max_pause_duration: int | None
    gate_ref: str
    fixtures: tuple[ForkFixture, ...] = ()
    # Which ``DURATION_BOUND_*`` state produced ``max_pause_duration``. Defaults to ``not_determined`` so an omission
    # can't assert indefinite.
    duration_bound_source: str = DURATION_BOUND_NOT_DETERMINED


@dataclass(frozen=True)
class CandidatePlanInputs:
    """Everything buildable for one candidate; ``None`` fields get no plan."""

    value_out: ValueOutPlanInputs | None = None
    supply: SupplyPlanInputs | None = None
    authority: AuthorityPlanInputs | None = None
    pause: PausePlanInputs | None = None
    timelock: TimelockPlanInputs | None = None
