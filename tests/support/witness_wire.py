"""Wire stubs for the indexer's enrolment seed (Etherscan creation block) and its three-read floor witness."""

from __future__ import annotations

from typing import Any


class SeedWitnessWire:
    """``rpc_request`` answering the witness reads for one creation block: empty code at ``creation - 1``, code after.

    ``prior_logs`` is the genesis-anchored ``eth_getLogs`` answer (non-empty means a prior incarnation); ``fail`` makes
    every read raise.
    """

    def __init__(self, creation_block: int, *, prior_logs: list[Any] | None = None, fail: bool = False) -> None:
        self.seed = creation_block - 1
        self.prior_logs = [] if prior_logs is None else prior_logs
        self.fail = fail
        self.calls: list[tuple[str, Any]] = []

    def __call__(self, url, method, params, chain_id=None, **_kw):
        self.calls.append((method, params))
        if self.fail:
            raise RuntimeError("stubbed upstream failure")
        if method == "eth_getCode":
            return "0x" if int(params[1], 16) <= self.seed else "0x6080604052"
        if method == "eth_getLogs":
            return self.prior_logs
        raise AssertionError(f"unexpected method {method}")


def stub_seed_witness(
    monkeypatch,
    *,
    creation_block: int | None,
    prior_logs: list[Any] | None = None,
    fail: bool = False,
) -> SeedWitnessWire:
    """Stub the indexer's Etherscan lookup and witness wire; ``creation_block=None`` is an unresolvable creation."""
    import workers.event_log_indexer as eli

    wire = SeedWitnessWire(creation_block or 1, prior_logs=prior_logs, fail=fail)
    monkeypatch.setattr(eli, "get_contract_creation_block", lambda *_a, **_k: creation_block)
    monkeypatch.setattr(eli, "require_rpc_url", lambda **_kw: "http://witness.stub")
    monkeypatch.setattr(eli, "rpc_request", wire)
    return wire
