"""``eth_simulateV1`` capability preflight.

Support is probed per chain at stage init and persisted; recipes needing it route to their declared Tier-2 fallback when
unsupported. Persistence is behind the injectable :class:`CapabilityStore` (in-memory for now).
"""

from __future__ import annotations

from typing import Protocol

from services.effects.simulate import SimCall, Simulate, SimulateUnsupportedError

# A read-only no-op call: supporting nodes answer (maybe reverting); others raise SimulateUnsupportedError.
_ZERO_ADDR = "0x" + "00" * 20


class CapabilityStore(Protocol):
    def get_simulate_support(self, chain_id: int) -> bool | None: ...

    def set_simulate_support(self, chain_id: int, supported: bool) -> None: ...


class InMemoryCapabilityStore:
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
    """Probe and persist ``eth_simulateV1`` support for ``chain_id``. Reused unless ``force``. Any structured
    response proves support; only :class:`SimulateUnsupportedError` records
    ``False``; other errors propagate so flakes aren't cached.
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
