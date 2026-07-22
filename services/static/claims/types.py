"""Type vocabulary for the two-plane claims subsystem (Plane 1).

A CLAIM is a typed, machine-checkable statement about a function, minted only
through the registry. Its ``tier`` records how the claim was proven and has no
heuristic/guess value: introducing one would require editing this Literal, the
registry contract, and the CI gate together, not a silent ``labels.add(...)``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, TypedDict, get_args

SCHEMA_VERSION = "claims/1"

Tier = Literal["behavioral_observed", "standard_exact", "idiom_structural", "policy_derived"]
TIERS: frozenset[str] = frozenset(get_args(Tier))

# Provenance strength, strongest first. When two witnesses would assert the SAME
# claim on one function, the registry's precedence rule keeps the strongest tier:
# a witnessed on-chain/forked state transition supersedes a standard proof, which
# supersedes a structural idiom, which supersedes a policy derivation. Distinct
# claims (including sibling operations within a namespace) are never collapsed —
# they are different sentences, not the same claim. ``behavioral_observed`` is
# the effects plane's provenance (EFFECTS_RESOLUTION_SPEC §5.2): a state
# transition observed on real forked state is the strongest evidence an
# existential claim can carry.
TIER_PRECEDENCE: dict[str, int] = {
    "behavioral_observed": 4,
    "standard_exact": 3,
    "idiom_structural": 2,
    "policy_derived": 1,
}

# Which downstream decision family keys off a claim. ``fact`` marks a claim that
# carries no semantic weight (present for provenance only); the others map onto
# the lane/severity/principal-tag consumers.
ConsumerFamily = Literal["control_plane", "flow", "exec", "user_plane", "fact"]
CONSUMER_FAMILIES: frozenset[str] = frozenset(get_args(ConsumerFamily))

# A replayable pointer to the Plane-0 evidence for a claim: a leaf path into a
# predicate tree, a sink id, a (var, member) pair, a selector + corroborating
# gate, etc. Kept open (``dict``) so each tier records the shape its
# witness-replay test re-verifies.
Witness = dict[str, Any]


class Claim(TypedDict):
    claim_id: str
    tier: Tier
    witness: Witness


class ClaimsArtifact(TypedDict):
    schema_version: str
    contract_name: str | None
    # Function full-name -> its claims (empty list is valid and common).
    functions: dict[str, list[Claim]]


@dataclass(frozen=True)
class ClaimEvidence:
    """What a matcher trigger returns on a hit: the tier it proved the claim at
    and the replayable witness. A trigger returns ``None`` for no claim."""

    tier: Tier
    witness: Witness
