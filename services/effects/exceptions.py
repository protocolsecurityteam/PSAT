"""Effects-stage exception types, classified by type (never message) in ``workers.retry_policy``."""

from __future__ import annotations


class EffectsProbeError(Exception): ...


class AnvilSpawnError(EffectsProbeError):
    """Anvil failed to start or became unavailable (transient)."""


class ForkRpcTimeoutError(EffectsProbeError):
    """A fork-backing RPC timed out (transient)."""


class BehaviorHashUnavailable(EffectsProbeError):
    """No behavioural hash for a candidate (no cached bytecode, or an unresolved proxy implementation).

    Only constructed for ``record_degraded``: the candidate is skipped, recorded once at the worker (capped).
    """


class AnvilRssUnmeasured(EffectsProbeError):
    """The fork's RSS couldn't be read.

    Only constructed for ``record_degraded``; the peak stays unpublished rather than zero.
    """
