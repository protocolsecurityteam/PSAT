"""The claim registry — the structural anti-creep mechanism.

Claims are constructible only through :func:`emit_claim`, and a ``claim_id`` not
present here is a hard error, so an unevidenced label is *unrepresentable*
rather than reviewable-away. Each :class:`RegistryEntry` pairs a written claim
sentence with the machine-checkable evidence predicates a witness-replay test
re-verifies — a contract-level ``gate`` and a per-function ``trigger`` over the
Plane-0 facts — the legacy label string it projects to (or ``None``), and the
consumer family that keys off it.

Matcher modules do not populate this dict directly; they use the
``@claim_matcher`` decorator (``decorator.py``), which registers the entry and
its trigger together. Auto-discovery (``matchers/__init__.py``) imports every
matcher module so those decorators run.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .context import ClaimContext
from .types import CONSUMER_FAMILIES, TIERS, Claim, ClaimEvidence, ConsumerFamily, Tier, Witness

# Contract-level corroboration (sibling selectors / views / sink shapes a
# standard mandates). ``True`` means "this claim may apply to this contract".
Gate = Callable[[ClaimContext], bool]
# Per-function evidence check. Returns the tier + witness on a hit, else ``None``.
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
    """Add ``entry`` to the registry, enforcing the entry contract. Raises on a
    malformed or duplicate registration (loud at import time)."""
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
    """Read-only view of the registered claims."""
    return MappingProxyType(_REGISTRY)


def is_registered(claim_id: str) -> bool:
    return claim_id in _REGISTRY


def entry_for(claim_id: str) -> RegistryEntry:
    return _REGISTRY[claim_id]


def legacy_projections() -> dict[str, str | None]:
    """``claim_id -> legacy effect_labels string`` so consumers migrate on their
    own schedule."""
    return {claim_id: entry.legacy_projection for claim_id, entry in _REGISTRY.items()}


def emit_claim(claim_id: str, tier: Tier, witness: Witness) -> Claim:
    """Mint a claim, or fail closed. An unregistered ``claim_id`` or a ``tier``
    outside the Literal is a hard error — the whole point of the registry."""
    if claim_id not in _REGISTRY:
        raise ValueError(f"unregistered claim_id {claim_id!r}; register it in a claims matcher module before emitting")
    if tier not in TIERS:
        raise ValueError(f"invalid claim tier {tier!r}; must be one of {sorted(TIERS)}")
    return {"claim_id": claim_id, "tier": tier, "witness": dict(witness)}
