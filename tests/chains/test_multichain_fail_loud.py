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

    @pytest.mark.parametrize(
        ("args", "kwargs", "needle"),
        [
            pytest.param((), {"chain": ""}, "", id="empty_string"),
            pytest.param((), {"chain": "   "}, "", id="whitespace_string"),
            pytest.param((), {"chain": "unknown"}, "unit ctx", id="unknown_sentinel"),
            pytest.param((999999,), {}, "999999", id="unregistered_id_with_value"),
            pytest.param((), {"chain": "fantom"}, "fantom", id="unregistered_name_with_value"),
        ],
    )
    def test_rejects(self, args, kwargs, needle):
        with pytest.raises(UnsupportedChainError) as exc:
            require_chain(*args, context="unit ctx", **kwargs)
        assert needle in str(exc.value)

    @pytest.mark.parametrize(
        ("args", "kwargs", "field", "expected"),
        [
            pytest.param((1,), {}, "name", "ethereum", id="valid_id_mainnet"),
            pytest.param((8453,), {}, "name", "base", id="valid_id_base"),
            pytest.param(("1",), {}, "chain_id", 1, id="decimal_string_id"),
            pytest.param((), {"chain": "base"}, "chain_id", 8453, id="name"),
            pytest.param((), {"chain": "mainnet"}, "chain_id", 1, id="alias"),
        ],
    )
    def test_resolves(self, args, kwargs, field, expected):
        assert getattr(require_chain(*args, context="ctx", **kwargs), field) == expected

    def test_chain_id_wins_over_name(self):
        assert require_chain(8453, chain="ethereum", context="ctx").chain_id == 8453


class TestDefaultRpcUrlNoSilentMainnet:
    @pytest.fixture(autouse=True)
    def _erpc(self, monkeypatch):
        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")

    @pytest.mark.parametrize(
        "kwargs",
        [
            pytest.param({}, id="none_not_mainnet"),
            pytest.param({"chain": ""}, id="empty_chain"),
            pytest.param({"chain": "unknown"}, id="unknown_sentinel"),
            pytest.param({"chain": "fantom"}, id="unregistered_name"),
        ],
    )
    def test_returns_none(self, kwargs):
        from services.clients.rpc import default_rpc_url

        assert default_rpc_url(**kwargs) is None

    def test_explicit_mainnet_still_resolves(self):
        from services.clients.rpc import default_rpc_url

        assert default_rpc_url(chain_id=1) == "https://erpc.example/main/evm/1"

    def test_local_rpc_still_wins_without_chain(self):
        from services.clients.rpc import default_rpc_url

        assert default_rpc_url(explicit_rpc_url="http://127.0.0.1:8545") == "http://127.0.0.1:8545"


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

    def test_erpc_unconfigured_raises_runtime_error_not_chain_error(self, monkeypatch):
        # A distinct error class, so the two failure modes aren't conflated.
        monkeypatch.delenv("ERPC_BASE_URL", raising=False)
        from services.clients.rpc import require_rpc_url

        with pytest.raises(RuntimeError) as exc:
            require_rpc_url(chain_id=1, context="pipeline X")
        assert not isinstance(exc.value, UnsupportedChainError)
        assert "ERPC_BASE_URL" in str(exc.value)


class TestErpcChainIdGuard:
    """URL-to-chain runtime guard: eRPC URL path chain id must match the declared one."""

    @pytest.fixture(autouse=True)
    def _erpc(self, monkeypatch):
        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")

    def test_parses_chain_id_from_url(self):
        from services.clients.rpc import _erpc_chain_id_from_url

        assert _erpc_chain_id_from_url("https://erpc.example/main/evm/8453") == 8453

    def test_mismatch_raises_with_both_ids(self):
        from services.clients.rpc import _assert_url_chain_id

        with pytest.raises(RuntimeError) as exc:
            _assert_url_chain_id("https://erpc.example/main/evm/8453", 1)
        assert "8453" in str(exc.value) and "1" in str(exc.value)

    @pytest.mark.parametrize(
        ("url", "chain_id"),
        [
            pytest.param("https://erpc.example/main/evm/8453", 8453, id="match_is_silent"),
            pytest.param("https://erpc.example/main/evm/8453", None, id="none_chain_id"),
            pytest.param("http://127.0.0.1:8545", 1, id="local_url"),
            pytest.param("https://some.provider/rpc", 8453, id="non_erpc_host"),
        ],
    )
    def test_assert_url_chain_id_noop(self, url, chain_id):
        from services.clients.rpc import _assert_url_chain_id

        _assert_url_chain_id(url, chain_id)

    def test_rpc_request_raises_on_mismatch_before_wire(self, monkeypatch):
        from services.clients import rpc

        def _boom(*a, **k):  # pragma: no cover - must never be reached
            raise AssertionError("wire call must not happen on a guard mismatch")

        monkeypatch.setattr(rpc, "_get_session", _boom)
        with pytest.raises(RuntimeError):
            rpc.rpc_request("https://erpc.example/main/evm/8453", "eth_blockNumber", [], chain_id=1)


class TestResolutionRpcUrlUsesJobChainColumn:
    """A chainless /api/analyze has its mainnet default only in ``jobs.chain_id``; otherwise every such job dies at
    resolution (PR #153).
    """

    def test_chainless_request_resolves_via_column(self, monkeypatch):
        from types import SimpleNamespace
        from typing import Any, cast

        from workers.resolution_worker import _rpc_url_for_job

        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
        job = cast(Any, SimpleNamespace(id="j1", address="0x" + "ab" * 20, chain_id=1, request={}))
        assert _rpc_url_for_job(job) == "https://erpc.example/main/evm/1"

    def test_second_chain_column_wins(self, monkeypatch):
        from types import SimpleNamespace
        from typing import Any, cast

        from workers.resolution_worker import _rpc_url_for_job

        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
        job = cast(Any, SimpleNamespace(id="j2", address="0x" + "ab" * 20, chain_id=8453, request={}))
        assert _rpc_url_for_job(job) == "https://erpc.example/main/evm/8453"

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


class TestWorkerRpcHelpersUseJobChainColumn:

    def test_policy_rpc_chainless_request_resolves_via_column(self, monkeypatch):
        from types import SimpleNamespace
        from typing import Any, cast

        from workers.policy_worker import _rpc_url_for_job

        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
        job = cast(Any, SimpleNamespace(id="p1", address="0x" + "ab" * 20, chain_id=1, request={}))
        assert _rpc_url_for_job(job) == "https://erpc.example/main/evm/1"

    def test_static_rpc_chainless_request_resolves_via_column(self, monkeypatch):
        from types import SimpleNamespace
        from typing import Any, cast

        from workers.static_worker import _request_rpc_url

        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
        job = cast(Any, SimpleNamespace(id="s1", address="0x" + "ab" * 20, chain_id=8453, request={}))
        assert _request_rpc_url(job) == "https://erpc.example/main/evm/8453"
