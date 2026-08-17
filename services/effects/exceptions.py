"""Exception shapes the effects stage introduces.

Classified type-only by ``workers.retry_policy`` (never by message substring).
The fork/anvil transports these represent are Phase 2 work; the classes exist
now so ``retry_policy._TRANSIENT_TYPES`` can name them and the fail-forward
semantics (inv. 15) are wired before the harness lands.
"""

from __future__ import annotations


class EffectsProbeError(Exception):
    """Base for effects-stage simulation failures."""


class AnvilSpawnError(EffectsProbeError):
    """Anvil fork process failed to start / became unavailable — transient."""


class ForkRpcTimeoutError(EffectsProbeError):
    """A fork-backing RPC round-trip timed out — transient."""


class UnresolvedProxyImplementation(EffectsProbeError):
    """A proxy contract row carries function rows but names no implementation, so
    there is no code to hash. Constructed for ``record_degraded``, never raised:
    the candidate is skipped (fail-forward), not failed."""


class BehaviorHashUnavailable(EffectsProbeError):
    """No behavioral hash could be resolved for a candidate (no cached bytecode,
    or the proxy refusal above). Constructed for ``record_degraded``, never
    raised — same fail-forward skip."""
