"""Canned JSON-RPC wire stub for the one-shot latch tests.

Lived in ``tests/resolution/test_one_shot_probe.py`` and was imported cross-module by
``tests/resolution/test_one_shot_latch_witness.py``; hoisted here so neither test module
imports the other.
"""

from __future__ import annotations

_ZERO = "0x" + "0" * 64


def _word(value: int) -> str:
    return "0x" + format(value, "064x")


class FakeRpc:
    """Canned JSON-RPC: ``storage[(address, slot)]`` and ``calls[(address,
    selector)]`` drive eth_getStorageAt / eth_call; everything else reads
    zero / empty."""

    def __init__(self, storage=None, calls=None):
        self.storage = storage or {}
        self.calls = calls or {}
        self.log: list[tuple] = []

    def __call__(self, rpc_url, method, params, retries=1):
        if method == "eth_getStorageAt":
            address, slot, _block = params
            self.log.append(("storage", address.lower(), slot.lower()))
            return self.storage.get((address.lower(), slot.lower()), _ZERO)
        if method == "eth_call":
            address = params[0]["to"].lower()
            data = params[0]["data"].lower()
            self.log.append(("call", address, data))
            return self.calls.get((address, data), "0x")
        raise AssertionError(f"unexpected method {method}")
