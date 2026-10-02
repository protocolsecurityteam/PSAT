from typing import Any

import pytest

from services.policy.capability_surface import capability_surface_status, project_capability_surface
from services.resolution.capabilities import CapabilityExpr
from services.resolution.capability_resolver import capability_to_dict


class _Outer:
    def __init__(self, rpc_url: str | None, contract_address: str | None, block: int | None = None) -> None:
        self.rpc_url = rpc_url
        self.contract_address = contract_address
        self.block = block


class _Adapter:
    def __init__(self, outer: _Outer | None) -> None:
        if outer is not None:
            self._outer_ctx = outer

    def enumerate(self, descriptor: Any, contract_address: str | None) -> CapabilityExpr:
        return CapabilityExpr.finite_set([], quality="lower_bound", confidence="partial")


def _status(cap: CapabilityExpr) -> str | None:
    cap_dict = capability_to_dict(cap)
    return capability_surface_status(cap_dict, project_capability_surface(cap_dict))


def _stub_rpc_map(monkeypatch: pytest.MonkeyPatch, returns: dict[str, str | None], recorder: list) -> None:
    def fake(rpc_url: str, method: str, params: list, retries: int = 1, **_: Any) -> str:
        selector = params[0]["data"]
        recorder.append(selector)
        value = returns.get(selector)
        if value is None:
            raise RuntimeError("execution reverted")
        return "0x" + value[2:].rjust(64, "0")

    monkeypatch.setattr("services.clients.rpc.rpc_request", fake)


def _stub(monkeypatch: pytest.MonkeyPatch, *, slot: str, getter: str = "revert", recorder: list | None = None) -> None:
    def fake(rpc_url: str, method: str, params: list, retries: int = 1, **_: Any) -> str:
        if recorder is not None:
            recorder.append((method, params))
        if method == "eth_getStorageAt":
            if slot == "revert":
                raise RuntimeError("execution reverted")
            return slot
        if getter == "revert":
            raise RuntimeError("execution reverted")
        return getter

    monkeypatch.setattr("services.clients.rpc.rpc_request", fake)
