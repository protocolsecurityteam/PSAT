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
