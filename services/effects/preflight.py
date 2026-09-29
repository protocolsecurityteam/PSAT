"""``eth_simulateV1`` capability preflight.

Support is *probed, never assumed*: worker preflight issues one trivial
``eth_simulateV1`` per chain when the injected store has no cached answer.
Value-out and supply recipes consult that capability; where unsupported they
route to their declared Tier-2 fallback — an explicit cost-model change, never a
silent degradation.

Persistence is behind an injectable :class:`CapabilityStore` seam. The local
implementation keeps answers in memory and is the worker default. Callers can
inject another store; this module does not provide durable DB persistence.
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
    """Probe + persist ``eth_simulateV1`` support for ``chain_id``.

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
