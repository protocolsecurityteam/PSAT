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
    # Canonical selector per function. Present means proven; absent means the signature couldn't be lowered (not a
    # proof); fallback/receive never appear.
    abi_selectors: NotRequired[dict[str, str]]


@dataclass(frozen=True)
class ClaimEvidence:
    """A trigger's hit: the tier and the replayable witness."""

    tier: Tier
    witness: Witness
