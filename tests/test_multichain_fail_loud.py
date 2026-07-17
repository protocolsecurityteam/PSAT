"""M1.2 fail-loud flip: chain is required, never silently defaulted to mainnet.

Covers the invariant-6 kill (``require_chain`` + ``default_rpc_url`` no longer
mapping a missing/unknown chain to mainnet) and the invariant-7 runtime guard
(the eRPC URL↔chain_id mismatch check in ``rpc_request``). The edge-keeps that
legitimately default to mainnet are asserted to still do so.
"""

from __future__ import annotations

import pytest

from utils.chains import (
    UnknownChainError,
    UnsupportedChainError,
    chain_by_id,
    require_chain,
)


class TestRequireChain:
    def test_none_raises_with_context(self):
        with pytest.raises(UnsupportedChainError) as exc:
            require_chain(None, context="unit ctx")
        assert "unit ctx" in str(exc.value)

    def test_empty_string_raises(self):
        with pytest.raises(UnsupportedChainError):
            require_chain(chain="", context="unit ctx")

    def test_whitespace_string_raises(self):
        with pytest.raises(UnsupportedChainError):
            require_chain(chain="   ", context="unit ctx")

    def test_unknown_sentinel_raises(self):
        # The discovery "unknown" sentinel is never resolvable — it fails loud.
        with pytest.raises(UnsupportedChainError) as exc:
            require_chain(chain="unknown", context="unit ctx")
        assert "unit ctx" in str(exc.value)

    def test_unregistered_id_raises_with_value(self):
        with pytest.raises(UnsupportedChainError) as exc:
            require_chain(999999, context="unit ctx")
        assert "999999" in str(exc.value)

    def test_unregistered_name_raises_with_value(self):
        with pytest.raises(UnsupportedChainError) as exc:
            require_chain(chain="fantom", context="unit ctx")
        assert "fantom" in str(exc.value)

    def test_is_a_valueerror_subclass(self):
        # Existing ValueError handlers keep catching it (like UnknownChainError).
        assert issubclass(UnsupportedChainError, ValueError)
        with pytest.raises(ValueError):
            require_chain(None, context="unit ctx")

    def test_valid_id_resolves(self):
        assert require_chain(1, context="ctx").name == "ethereum"
        assert require_chain(8453, context="ctx").name == "base"

    def test_decimal_string_id_resolves(self):
        assert require_chain("1", context="ctx").chain_id == 1

    def test_valid_name_and_alias_resolve(self):
        assert require_chain(chain="base", context="ctx").chain_id == 8453
        assert require_chain(chain="mainnet", context="ctx").chain_id == 1

    def test_chain_id_wins_over_name(self):
        assert require_chain(8453, chain="ethereum", context="ctx").chain_id == 8453


class TestDefaultRpcUrlNoSilentMainnet:
    """``default_rpc_url`` no longer maps a missing/unknown chain to mainnet."""

    @pytest.fixture(autouse=True)
    def _erpc(self, monkeypatch):
        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")

    def test_none_returns_none_not_mainnet(self):
        from utils.rpc import default_rpc_url

        assert default_rpc_url() is None

    def test_empty_chain_returns_none(self):
        from utils.rpc import default_rpc_url

        assert default_rpc_url(chain="") is None

    def test_unknown_sentinel_returns_none(self):
        from utils.rpc import default_rpc_url

        assert default_rpc_url(chain="unknown") is None

    def test_unregistered_name_returns_none(self):
        from utils.rpc import default_rpc_url

        assert default_rpc_url(chain="fantom") is None

    def test_explicit_mainnet_still_resolves(self):
        from utils.rpc import default_rpc_url

        assert default_rpc_url(chain_id=1) == "https://erpc.example/main/evm/1"

    def test_explicit_l2_resolves(self):
        from utils.rpc import default_rpc_url

        assert default_rpc_url(chain_id=8453) == "https://erpc.example/main/evm/8453"

    def test_local_rpc_still_wins_without_chain(self):
        from utils.rpc import default_rpc_url

        assert default_rpc_url(explicit_rpc_url="http://127.0.0.1:8545") == "http://127.0.0.1:8545"


class TestRequireRpcUrlDistinctErrors:
    def test_no_chain_raises_unsupported_chain(self, monkeypatch):
        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
        from utils.rpc import require_rpc_url

        with pytest.raises(UnsupportedChainError):
            require_rpc_url(context="pipeline X")

    def test_unknown_chain_raises_unsupported_chain(self, monkeypatch):
        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")
        from utils.rpc import require_rpc_url

        with pytest.raises(UnsupportedChainError):
            require_rpc_url(chain="fantom", context="pipeline X")

    def test_erpc_unconfigured_raises_runtime_error_not_chain_error(self, monkeypatch):
        # Chain resolves fine; the failure is the missing eRPC config — a distinct
        # error class + message, so the two failure modes aren't conflated.
        monkeypatch.delenv("ERPC_BASE_URL", raising=False)
        from utils.rpc import require_rpc_url

        with pytest.raises(RuntimeError) as exc:
            require_rpc_url(chain_id=1, context="pipeline X")
        assert not isinstance(exc.value, UnsupportedChainError)
        assert "ERPC_BASE_URL" in str(exc.value)

    def test_local_url_wins_without_chain(self):
        from utils.rpc import require_rpc_url

        assert require_rpc_url(explicit_rpc_url="http://127.0.0.1:8545") == "http://127.0.0.1:8545"


class TestErpcChainIdGuard:
    """Invariant-7 runtime guard: eRPC URL path chain id must match the declared one."""

    @pytest.fixture(autouse=True)
    def _erpc(self, monkeypatch):
        monkeypatch.setenv("ERPC_BASE_URL", "https://erpc.example")

    def test_parses_chain_id_from_url(self):
        from utils.rpc import _erpc_chain_id_from_url

        assert _erpc_chain_id_from_url("https://erpc.example/main/evm/8453") == 8453

    def test_mismatch_raises_with_both_ids(self):
        from utils.rpc import _assert_url_chain_id

        with pytest.raises(RuntimeError) as exc:
            _assert_url_chain_id("https://erpc.example/main/evm/8453", 1)
        assert "8453" in str(exc.value) and "1" in str(exc.value)

    def test_match_is_silent(self):
        from utils.rpc import _assert_url_chain_id

        _assert_url_chain_id("https://erpc.example/main/evm/8453", 8453)

    def test_none_chain_id_is_noop(self):
        from utils.rpc import _assert_url_chain_id

        _assert_url_chain_id("https://erpc.example/main/evm/8453", None)

    def test_local_url_is_noop(self):
        from utils.rpc import _assert_url_chain_id

        _assert_url_chain_id("http://127.0.0.1:8545", 1)

    def test_non_erpc_host_is_noop(self):
        from utils.rpc import _assert_url_chain_id

        _assert_url_chain_id("https://some.provider/rpc", 8453)

    def test_rpc_request_raises_on_mismatch_before_wire(self, monkeypatch):
        # The guard fires before any network call: a declared chain_id that
        # disagrees with the eRPC URL path raises rather than reading the wrong chain.
        from utils import rpc

        def _boom(*a, **k):  # pragma: no cover - must never be reached
            raise AssertionError("wire call must not happen on a guard mismatch")

        monkeypatch.setattr(rpc, "_get_session", _boom)
        with pytest.raises(RuntimeError):
            rpc.rpc_request("https://erpc.example/main/evm/8453", "eth_blockNumber", [], chain_id=1)


class TestEdgeKeepsStillDefaultMainnet:
    """The sanctioned user-facing edges keep their explicit mainnet defaults."""

    def test_analyze_request_defaults(self):
        from schemas.api_requests import AnalyzeRequest

        req = AnalyzeRequest(address="0x" + "ab" * 20)
        # chain/chain_id are None at the schema; the /api/analyze handler applies
        # the mainnet edge default — the field itself stays permissive.
        assert req.chain is None
        assert req.chain_id is None

    def test_re_enroll_defaults_to_mainnet(self):
        import inspect

        from routers.protocols import re_enroll_protocol

        assert inspect.signature(re_enroll_protocol).parameters["chain"].default == "ethereum"

    def test_upsert_monitored_contract_defaults_to_mainnet(self):
        from schemas.api_requests import UpsertMonitoredContractRequest

        req = UpsertMonitoredContractRequest(address="0x" + "ab" * 20)
        assert req.chain == "ethereum"

    def test_predicate_capabilities_probe_request_defaults_to_mainnet(self):
        from routers.predicate_capabilities import _ProbeMembershipRequest

        req = _ProbeMembershipRequest(function_signature="f()", predicate_index=0, member="0x" + "ab" * 20)
        assert req.chain_id == 1


def test_registry_still_resolves_all_supported_chains():
    # Sanity: the kill didn't perturb the registry the guard/require_chain read.
    assert chain_by_id(1).name == "ethereum"
    with pytest.raises(UnknownChainError):
        chain_by_id(999999)


class TestResolutionRpcUrlUsesJobChainColumn:
    """Regression: a chainless /api/analyze request carries its mainnet edge
    default only in the first-class ``jobs.chain_id`` column — the request
    JSONB has no chain keys. ``_rpc_url_for_job`` must resolve through the
    column, or every such job dies terminal at the resolution stage (the
    PR #153 live-suite failure)."""

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
