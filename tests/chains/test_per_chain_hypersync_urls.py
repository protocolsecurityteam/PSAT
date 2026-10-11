"""Per-chain HyperSync resolver.

URL selection in the resolution repos is driven by the evaluation's chain (registry), not a hardcoded
mainnet literal: chain 1 still resolves to the mainnet endpoint; a chain with ``hypersync_url=None`` is
UNAVAILABLE (scan skipped, never redirected to mainnet); per-chain URLs thread to the client builder.

Wire seam is ``build_hypersync_client``; we stub it and the registry lookup, never the repo classes.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, cast

import pytest

import services.resolution.hypersync_bound as hb
from services.resolution.hypersync_bound import hypersync_url_for_chain

MAINNET_URL = "https://eth.hypersync.xyz"
BASE_URL = "https://base.hypersync.xyz"
# Arbitrum is still indexer-disabled; Base gained HyperSync in Phase 2.
UNAVAILABLE_CHAIN_ID = 42161  # arbitrum

EVENT_ADDRESS = "0x00000000000000000000000000000000c0ffee19"
TOPIC_ADD = "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d"


class _EmptyResponse(SimpleNamespace):
    def __init__(self) -> None:
        super().__init__(data=None, logs=[], next_block=None)


class _FakeClient:
    async def get(self, _query: Any) -> _EmptyResponse:
        return _EmptyResponse()


@pytest.fixture
def _capture_build_url(monkeypatch):
    captured: dict[str, Any] = {}

    def _fake_build(_module: Any, *, url: str, bearer_token: str | None) -> _FakeClient:
        captured["url"] = url
        captured["bearer_token"] = bearer_token
        return _FakeClient()

    monkeypatch.setattr(hb, "build_hypersync_client", _fake_build)
    return captured


def test_registry_drives_per_chain_hypersync_availability():
    assert hypersync_url_for_chain(1) == MAINNET_URL
    # Base has a HyperSync URL in the registry and is enabled here.
    assert hypersync_url_for_chain(8453) == BASE_URL
    assert hypersync_url_for_chain(UNAVAILABLE_CHAIN_ID) is None
    # Unknown chain id degrades to unavailable, not a raise (unknown-chain validation is separate).
    assert hypersync_url_for_chain(999999) is None


def _stub_floor_defer(monkeypatch):
    import services.resolution.creation_block_floor as floor_mod

    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: None)
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", lambda *_a, **_k: None)


def test_external_check_chain1_scans_mainnet_registry_url(monkeypatch, _capture_build_url):
    import services.resolution.external_check_materializer as mod

    monkeypatch.delenv("PSAT_HYPERSYNC_URL", raising=False)
    monkeypatch.setenv("ENVIO_API_TOKEN", "tok")
    _stub_floor_defer(monkeypatch)

    out = asyncio.run(
        mod._candidate_addresses_from_hypersync_async(checker_address="0x" + "11" * 20, limit=8, chain_id=1)
    )
    assert out == []  # floor deferred → no candidates, but the URL was selected
    assert _capture_build_url["url"] == MAINNET_URL


def test_external_check_unavailable_chain_skips_scan(monkeypatch, _capture_build_url):
    import services.resolution.external_check_materializer as mod

    monkeypatch.delenv("PSAT_HYPERSYNC_URL", raising=False)
    monkeypatch.setenv("ENVIO_API_TOKEN", "tok")
    _stub_floor_defer(monkeypatch)

    out = asyncio.run(
        mod._candidate_addresses_from_hypersync_async(
            checker_address="0x" + "11" * 20, limit=8, chain_id=UNAVAILABLE_CHAIN_ID
        )
    )
    assert out == []
    assert "url" not in _capture_build_url  # no coverage → client never built


def _observed(outer: Any):
    from services.resolution.predicate_evaluator import _observed_event_key_words_from_hypersync

    descriptor = {"key_sources": [{"source": "msg_sender"}]}
    hints = [{"topic0": "0x" + "ab" * 32, "event_address": EVENT_ADDRESS, "topics_to_keys": {1: 0}}]
    return _observed_event_key_words_from_hypersync(
        outer_ctx=outer, descriptor=cast(Any, descriptor), event_hints=hints, key_index=0
    )


def test_observed_keys_chain1_scans_mainnet_registry_url(monkeypatch, _capture_build_url):
    import services.resolution.creation_block_floor as floor_mod

    monkeypatch.delenv("PSAT_HYPERSYNC_URL", raising=False)
    monkeypatch.setenv("ENVIO_API_TOKEN", "tok")
    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: None)
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", lambda *_a, **_k: 7_000_000)

    _observed(SimpleNamespace(meta={}, chain_id=1, block=8_000_000))
    assert _capture_build_url["url"] == MAINNET_URL


def test_observed_keys_unavailable_chain_skips_scan(monkeypatch, _capture_build_url):
    monkeypatch.delenv("PSAT_HYPERSYNC_URL", raising=False)
    monkeypatch.setenv("ENVIO_API_TOKEN", "tok")

    out = _observed(SimpleNamespace(meta={}, chain_id=UNAVAILABLE_CHAIN_ID, block=8_000_000))
    assert out.words == [] and not out.complete
    assert "url" not in _capture_build_url  # registry None → no scan, no mainnet fallback


def test_observed_keys_meta_url_overrides_registry(monkeypatch, _capture_build_url):
    import services.resolution.creation_block_floor as floor_mod

    monkeypatch.delenv("PSAT_HYPERSYNC_URL", raising=False)
    monkeypatch.setenv("ENVIO_API_TOKEN", "tok")
    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: None)
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", lambda *_a, **_k: 7_000_000)

    _observed(SimpleNamespace(meta={"hypersync_url": BASE_URL}, chain_id=UNAVAILABLE_CHAIN_ID, block=8_000_000))
    assert _capture_build_url["url"] == BASE_URL
