"""The claim registry: claims are only constructible through :func:`emit_claim`, and an unregistered ``claim_id`` is
a hard error, so an unevidenced label is unrepresentable.

Each entry pairs a claim sentence with its ``gate`` and ``trigger`` evidence predicates, its legacy label, and its
consumer family. Matchers register through ``@claim_matcher``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .context import ClaimContext
from .types import (
    CONSUMER_FAMILIES,
    TIER_PRECEDENCE,
    TIERS,
    Claim,
    ClaimEvidence,
    ConsumerFamily,
    Tier,
    Witness,
)

Gate = Callable[[ClaimContext], bool]
Trigger = Callable[[ClaimContext, str], ClaimEvidence | None]


@dataclass(frozen=True)
class RegistryEntry:
    claim_id: str
    sentence: str
    gate: Gate
    trigger: Trigger
    legacy_projection: str | None
    consumer_family: ConsumerFamily


_REGISTRY: dict[str, RegistryEntry] = {}


def register(entry: RegistryEntry) -> RegistryEntry:
    """Add ``entry``; raises on a malformed or duplicate registration."""
    if not entry.claim_id:
        raise ValueError("claim_id must be non-empty")
    if entry.claim_id in _REGISTRY:
        raise ValueError(f"duplicate claim registration: {entry.claim_id!r}")
    if not entry.sentence or not entry.sentence.strip():
        raise ValueError(f"claim {entry.claim_id!r} must declare a written sentence")
    if entry.consumer_family not in CONSUMER_FAMILIES:
        raise ValueError(
            f"claim {entry.claim_id!r} has unknown consumer_family {entry.consumer_family!r}; "
            f"must be one of {sorted(CONSUMER_FAMILIES)}"
        )
    if not callable(entry.gate) or not callable(entry.trigger):
        raise TypeError(f"claim {entry.claim_id!r} gate/trigger must be callables")
    _REGISTRY[entry.claim_id] = entry
    return entry


def registry() -> Mapping[str, RegistryEntry]:
    return MappingProxyType(_REGISTRY)


def is_registered(claim_id: str) -> bool:
    return claim_id in _REGISTRY


def entry_for(claim_id: str) -> RegistryEntry:
    return _REGISTRY[claim_id]


def legacy_projections() -> dict[str, str | None]:
    return {claim_id: entry.legacy_projection for claim_id, entry in _REGISTRY.items()}


def emit_claim(claim_id: str, tier: Tier, witness: Witness) -> Claim:
    """Mint a claim; an unregistered ``claim_id`` or unknown tier is a hard error."""
    if claim_id not in _REGISTRY:
        raise ValueError(f"unregistered claim_id {claim_id!r}; register it in a claims matcher module before emitting")
    if tier not in TIERS:
        raise ValueError(f"invalid claim tier {tier!r}; must be one of {sorted(TIERS)}")
    return {"claim_id": claim_id, "tier": tier, "witness": dict(witness)}


def _tier_rank(tier: str) -> int:
    return TIER_PRECEDENCE.get(tier, 0)


def resolve_claim_precedence(claims: Iterable[Claim]) -> list[Claim]:
    """Keep only the strongest tier per ``claim_id`` on a function, sorted deterministically.

    Keyed on the exact id: sibling claims (``pause.set`` vs ``pause.unset``) are distinct operations.
    """
    best: dict[str, Claim] = {}
    for claim in claims:
        claim_id = claim["claim_id"]
        incumbent = best.get(claim_id)
        if incumbent is None or _tier_rank(claim["tier"]) > _tier_rank(incumbent["tier"]):
            best[claim_id] = claim
    return sorted(best.values(), key=lambda claim: (claim["claim_id"], claim["tier"]))
