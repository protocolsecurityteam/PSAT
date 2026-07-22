"""``eth_simulateV1`` capability preflight (EFFECTS_RESOLUTION_SPEC §3 / inv. 14).

Support is *probed, never assumed*: at stage init the worker issues one trivial
``eth_simulateV1`` per chain and PERSISTS the result. Recipes that need it (§4.2
value-out, §4.5 supply) consult the persisted capability; where unsupported they
route to their declared Tier-2 fallback — an explicit cost-model change, never a
silent degradation.

Persistence is behind an INJECTABLE :class:`CapabilityStore` seam. Phase 2 ships
the in-memory implementation (all the offline suite needs); the DB-backed store
that survives worker restarts is Phase 3's wiring, so the harness stays pure and
the stage boundary (no Phase-2 DB persistence) holds.
"""

from __future__ import annotations

from typing import Protocol

from services.effects.simulate import SimCall, Simulate, SimulateUnsupportedError

# A well-formed no-op call: read-only, no state, no value. A node that implements
# eth_simulateV1 answers with a structured (possibly reverting) result; one that
# doesn't raises SimulateUnsupportedError from the real wrapper.
_ZERO_ADDR = "0x" + "00" * 20


class CapabilityStore(Protocol):
    """Per-chain ``eth_simulateV1`` support persistence seam."""

    def get_simulate_support(self, chain_id: int) -> bool | None: ...

    def set_simulate_support(self, chain_id: int, supported: bool) -> None: ...


class InMemoryCapabilityStore:
    """Process-local capability store (offline suite + single-run default)."""

    def __init__(self) -> None:
        self._support: dict[int, bool] = {}

    def get_simulate_support(self, chain_id: int) -> bool | None:
        return self._support.get(chain_id)

    def set_simulate_support(self, chain_id: int, supported: bool) -> None:
        self._support[chain_id] = supported


def probe_simulate_support(
    simulate: Simulate,
    chain_id: int,
    store: CapabilityStore,
    *,
    block: str = "latest",
    force: bool = False,
) -> bool:
    """Probe + persist ``eth_simulateV1`` support for ``chain_id`` (inv. 14).

    Idempotent: a persisted answer is reused unless ``force``. A structured
    response (even an all-reverting one) proves support; only
    :class:`SimulateUnsupportedError` — the real wrapper's signal that the node
    rejected the METHOD — records ``False``. Any other transport error
    propagates (a flake must not be cached as "unsupported").
    """
    if not force:
        cached = store.get_simulate_support(chain_id)
        if cached is not None:
            return cached
    try:
        simulate([SimCall(to=_ZERO_ADDR, data="0x")], block, None)
        supported = True
    except SimulateUnsupportedError:
        supported = False
    store.set_simulate_support(chain_id, supported)
    return supported


def require_simulate_or_fallback(store: CapabilityStore, chain_id: int) -> bool:
    """Whether a Tier-1 simulate recipe may run on ``chain_id``. ``False`` is a
    fail-closed default (unprobed ⇒ do not assume support): the caller routes to
    the explicit Tier-2 fallback and records that in the verdict reason."""
    return store.get_simulate_support(chain_id) is True
