"""Claim type vocabulary. ``tier`` records how a claim was proven and has no heuristic value by design."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, TypedDict, get_args

from typing_extensions import NotRequired

SCHEMA_VERSION = "claims/1"

Tier = Literal["behavioral_observed", "standard_exact", "idiom_structural", "policy_derived"]
TIERS: frozenset[str] = frozenset(get_args(Tier))

# Strongest first; when two witnesses assert the same claim on a function, the strongest tier wins.
# ``behavioral_observed`` is a transition witnessed on forked state.
TIER_PRECEDENCE: dict[str, int] = {
    "behavioral_observed": 4,
    "standard_exact": 3,
    "idiom_structural": 2,
    "policy_derived": 1,
}

# ``fact`` claims carry no semantic weight.
ConsumerFamily = Literal["control_plane", "flow", "exec", "user_plane", "fact"]
CONSUMER_FAMILIES: frozenset[str] = frozenset(get_args(ConsumerFamily))

# What holding a gated function's permission grants. ``control.*`` changes who controls, the code, the pause state,
# enforced policy, or value the caller doesn't own; ``operational`` moves only the caller's own value or others' on
# terms they set. ``exemption`` is reserved: no claim proves a bypassed check yet.
GrantClass = Literal[
    "control.gate",
    "control.code",
    "control.pause",
    "control.config",
    "control.funds",
    "operational",
    "exemption",
    "user",
    "fact",
]
GRANT_CLASSES: frozenset[str] = frozenset(get_args(GrantClass))
CONTROL_GRANT_CLASSES: frozenset[str] = frozenset(
    {"control.gate", "control.code", "control.pause", "control.config", "control.funds"}
)

# Tiers minted from one contract's own static facts; ``policy_derived`` needs a sibling's facts and
# ``behavioral_observed`` a fork run.
SINGLE_CONTRACT_STATIC_TIERS: frozenset[str] = frozenset({"standard_exact", "idiom_structural"})

# Stamped on an observed claim's witness when it supersedes a static one: the superseded claim's tier.
STATIC_TIER_WITNESS_KEY = "static_tier"

# A replayable pointer to the evidence (tree leaf path, sink id, selector plus gate...), shaped per tier.
Witness = dict[str, Any]


class Claim(TypedDict):
    claim_id: str
    tier: Tier
    witness: Witness


class ClaimsArtifact(TypedDict):
    schema_version: str
    contract_name: str | None
    functions: dict[str, list[Claim]]
    errors: NotRequired[list[str]]
    # Canonical selector per function. Present means proven; absent means the signature couldn't be lowered (not a
    # proof); fallback/receive never appear.
    abi_selectors: NotRequired[dict[str, str]]


@dataclass(frozen=True)
class ClaimEvidence:
    """A trigger's hit: the tier and the replayable witness."""

    tier: Tier
    witness: Witness
