"""Exception shapes the effects stage introduces.

Classified type-only by ``workers.retry_policy`` (never by message substring).
Fork/anvil failures are classified by ``retry_policy._TRANSIENT_TYPES`` so
transient transport failures can retry before the effects stage advances to
coverage on retry exhaustion.
"""

from __future__ import annotations


class EffectsProbeError(Exception):
    """Base for effects-stage simulation failures."""


class AnvilSpawnError(EffectsProbeError):
    """Anvil fork process failed to start / became unavailable — transient."""


class ForkRpcTimeoutError(EffectsProbeError):
    """A fork-backing RPC round-trip timed out — transient."""


class BehaviorHashUnavailable(EffectsProbeError):
    """No behavioral hash could be resolved for a candidate — no cached bytecode,
    or a proxy row whose implementation is unresolved. Constructed for
    ``record_degraded``, never raised: the candidate is skipped (fail-forward),
    not failed. The ONE witness for that skip, and it is capped at the worker's
    receiving arm — the refusing helper does not record a second one per
    candidate (the dedup race produces these in bulk)."""


class AnvilRssUnmeasured(EffectsProbeError):
    """The fork's RSS read did not answer (process gone, ``/proc`` unreadable).
    Constructed for ``record_degraded``, never raised — the peak stays
    unpublished rather than being published as zero."""
