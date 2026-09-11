"""Positive matcher results and detector receipts for static effects.

The registry's successful matcher result is a compact internal effect match,
then converted into canonical assessment Evidence and Claim records. ``tier``
has no heuristic/guess value:
introducing one requires editing the Literal, registry contract, and CI gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, TypedDict, get_args

from typing_extensions import NotRequired

SCHEMA_VERSION = "claims/1"

Tier = Literal["behavioral_observed", "standard_exact", "idiom_structural", "policy_derived"]
TIERS: frozenset[str] = frozenset(get_args(Tier))

# Provenance strength, strongest first. When two witnesses would assert the SAME
# claim on one function, the registry's precedence rule keeps the strongest tier:
# a witnessed on-chain/forked state transition supersedes a standard proof, which
# supersedes a structural idiom, which supersedes a policy derivation. Distinct
# claims (including sibling operations within a namespace) are never collapsed —
# they are different sentences, not the same claim. ``behavioral_observed`` is
# the effects plane's provenance: a state
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


class EffectMatch(TypedDict):
    """A positive matcher hit awaiting canonical evidence construction."""

    claim_id: str
    tier: Tier
    witness: Witness


class MatchResults(TypedDict):
    schema_version: str
    contract_name: str | None
    # Function full-name -> its claims (empty list is valid and common).
    functions: dict[str, list[EffectMatch]]
    # Function full-name -> the 4-byte selector of its CANONICAL ABI signature
    # (enum/interface/struct params lowered) — the value a caller puts in
    # ``msg.sig``. Three states per function, and consumers must keep them
    # apart: present = lowered and proven; ABSENT from the map = the signature
    # could not be lowered (not determined — never a proof); fallback/receive
    # never appear (they have no selector by construction). The whole key is
    # absent on artifacts minted before it existed.
    abi_selectors: NotRequired[dict[str, str]]
    # One receipt per registered matcher. A clean miss is completed work; only
    # an exception creates an omission. These receipts, not missing claims,
    # carry failure and coverage semantics into the canonical Assessment.
    analyses: NotRequired[dict[str, "MatchAnalysis"]]
    diagnostics: NotRequired[list["MatchDiagnostic"]]


class MatchOmission(TypedDict):
    function: str
    reason: str


class MatchAnalysis(TypedDict):
    detector: str
    status: Literal["completed", "partial", "failed"]
    targets_total: int
    targets_completed: int
    omissions: list[MatchOmission]


class MatchDiagnostic(TypedDict):
    claim_id: str
    function: str | None
    exc_type: str
    message: str


@dataclass(frozen=True)
class MatchedEvidence:
    """What a matcher trigger returns on a hit: the tier it proved the claim at
    and the replayable witness. A trigger returns ``None`` for no claim."""

    tier: Tier
    witness: Witness
