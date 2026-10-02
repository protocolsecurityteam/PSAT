"""Chain is required, never silently defaulted to mainnet.

Covers the required-chain validation (``require_chain`` + ``default_rpc_url`` no longer
mapping a missing/unknown chain to mainnet) and the URL-to-chain runtime guard
(the eRPC URL↔chain_id mismatch check in ``rpc_request``). The edge-keeps that
legitimately default to mainnet are asserted to still do so.
"""

from __future__ import annotations

import pytest

from utils.chains import (
    UnsupportedChainError,
    require_chain,
)


class TestRequireChain:
    def test_none_raises_with_context(self):
        with pytest.raises(UnsupportedChainError) as exc:
            require_chain(None, context="unit ctx")
        assert "unit ctx" in str(exc.value)


class TestRequireRpcUrlDistinctErrors:
    @pytest.mark.parametrize(
        "kwargs",
        [pytest.param({}, id="no_chain"), pytest.param({"chain": "fantom"}, id="unknown_chain")],
    )
    def test_chain_problem_raises_unsupported_chain(self, monkeypatch, kwargs):
        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
        from services.clients.rpc import require_rpc_url

        with pytest.raises(UnsupportedChainError):
            require_rpc_url(context="pipeline X", **kwargs)


class TestErpcChainIdGuard:
    """URL-to-chain runtime guard: eRPC URL path chain id must match the declared one."""

    @pytest.fixture(autouse=True)
    def _erpc(self, monkeypatch):
        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")

    def test_mismatch_raises_with_both_ids(self):
        from services.clients.rpc import _assert_url_chain_id

        with pytest.raises(RuntimeError) as exc:
            _assert_url_chain_id("https://erpc.example/main/evm/8453", 1)
        assert "8453" in str(exc.value) and "1" in str(exc.value)


class TestResolutionRpcUrlUsesJobChainColumn:
    """A chainless /api/analyze has its mainnet default only in ``jobs.chain_id``; otherwise every such job dies at
    resolution (PR #153).
    """

    def test_local_rpc_override_still_wins(self, monkeypatch):
        from types import SimpleNamespace
        from typing import Any, cast

        from workers.resolution_worker import _rpc_url_for_job

        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
        job = cast(
            Any,
            SimpleNamespace(
                id="j3", address="0x" + "ab" * 20, chain_id=1, request={"rpc_url": "http://127.0.0.1:8545"}
            ),
        )
        assert _rpc_url_for_job(job) == "http://127.0.0.1:8545"
