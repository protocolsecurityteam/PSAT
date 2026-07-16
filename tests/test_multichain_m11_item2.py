"""M1.1 item 2 — per-chain HyperSync resolver.

Proves the HyperSync-URL selection in the resolution repos is driven by the
evaluation's chain (via the registry, inv. 5), not a hardcoded mainnet literal:

  * chain 1 still resolves to the mainnet endpoint (byte-identical);
  * a chain the registry marks ``hypersync_url=None`` (no proven coverage, e.g.
    Base/8453 today) is UNAVAILABLE — the scan is skipped, never silently
    redirected to mainnet;
  * a per-chain URL threads end-to-end to the client builder.

The wire seam is ``build_hypersync_client`` (where every consumer constructs its
client); we stub that and the registry lookup, never the repo classes.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, cast

import pytest

import services.resolution.hypersync_bound as hb
from services.resolution.repos.event_logs_hypersync import (
    HyperSyncEventLogRepo,
    _hypersync_url_for_chain,
)

MAINNET_URL = "https://eth.hypersync.xyz"
BASE_URL = "https://base.hypersync.xyz"

EVENT_ADDRESS = "0x00000000000000000000000000000000c0ffee19"
TOPIC_ADD = "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d"
KEY_SOURCES = [{"source": "msg_sender"}]
TOPICS_TO_KEYS = {1: 0}


class _EmptyResponse(SimpleNamespace):
    def __init__(self) -> None:
        super().__init__(data=None, logs=[], next_block=None)


class _FakeClient:
    async def get(self, _query: Any) -> _EmptyResponse:
        return _EmptyResponse()


@pytest.fixture
def _capture_build_url(monkeypatch):
    """Stub the shared client builder; record the URL every consumer passes it."""
    captured: dict[str, Any] = {}

    def _fake_build(_module: Any, *, url: str, bearer_token: str | None) -> _FakeClient:
        captured["url"] = url
        captured["bearer_token"] = bearer_token
        return _FakeClient()

    monkeypatch.setattr(hb, "build_hypersync_client", _fake_build)
    return captured


# --------------------------------------------------------------------------- #
# registry anchor                                                             #
# --------------------------------------------------------------------------- #


def test_registry_gives_mainnet_url_and_marks_base_unavailable():
    assert _hypersync_url_for_chain(1) == MAINNET_URL
    # Base has no proven HyperSync coverage yet → indexer/repo disabled there.
    assert _hypersync_url_for_chain(8453) is None
    # Unknown chain id degrades to unavailable, not a raise (fail-loud is M1.2).
    assert _hypersync_url_for_chain(999999) is None


# --------------------------------------------------------------------------- #
# HyperSyncEventLogRepo                                                        #
# --------------------------------------------------------------------------- #


def _fold_writes(repo: HyperSyncEventLogRepo, chain_id: int):
    return repo.fold_event_writes(
        chain_id=chain_id,
        event_address=EVENT_ADDRESS,
        topic0=TOPIC_ADD,
        topics_to_keys=TOPICS_TO_KEYS,
        data_to_keys={},
        key_sources=KEY_SOURCES,
        direction="add",
        block=5_000_000,
    )


def test_repo_chain1_scans_mainnet_registry_url(_capture_build_url):
    repo = HyperSyncEventLogRepo(from_block=0, bearer_token="tok")
    result = _fold_writes(repo, chain_id=1)
    assert _capture_build_url["url"] == MAINNET_URL
    # A completed pinned scan with no logs is exact-but-empty.
    assert result.members == []


def test_repo_unavailable_chain_skips_scan(_capture_build_url):
    repo = HyperSyncEventLogRepo(from_block=0, bearer_token="tok")
    result = _fold_writes(repo, chain_id=8453)
    assert result.confidence == "partial"
    assert result.partial_reason == "hypersync_unavailable_for_chain"
    # The chain has no scan surface — the client is never built.
    assert "url" not in _capture_build_url


def test_repo_history_unavailable_chain_skips_scan(_capture_build_url):
    repo = HyperSyncEventLogRepo(from_block=0, bearer_token="tok")
    result = repo.fold_event_history(
        chain_id=8453,
        event_address=EVENT_ADDRESS,
        event_hints=[{"topic0": TOPIC_ADD, "direction": "add", "topics_to_keys": TOPICS_TO_KEYS, "data_to_keys": {}}],
        key_sources=KEY_SOURCES,
        block=5_000_000,
    )
    assert result.confidence == "partial"
    assert result.partial_reason == "hypersync_unavailable_for_chain"
    assert "url" not in _capture_build_url


def test_repo_threads_per_chain_url_to_client(monkeypatch, _capture_build_url):
    """When the registry has a per-chain endpoint, the repo threads THAT url — the
    chain_id drives the selection, not a construction-time default."""
    import services.resolution.repos.event_logs_hypersync as repo_mod

    monkeypatch.setattr(repo_mod, "_hypersync_url_for_chain", lambda cid: BASE_URL if cid == 8453 else None)
    repo = HyperSyncEventLogRepo(from_block=0, bearer_token="tok")
    _fold_writes(repo, chain_id=8453)
    assert _capture_build_url["url"] == BASE_URL


# --------------------------------------------------------------------------- #
# external_check_materializer candidate scan                                  #
# --------------------------------------------------------------------------- #


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
        mod._candidate_addresses_from_hypersync_async(checker_address="0x" + "11" * 20, limit=8, chain_id=8453)
    )
    assert out == []
    assert "url" not in _capture_build_url  # no coverage → client never built


def test_external_check_threads_per_chain_url(monkeypatch, _capture_build_url):
    import services.resolution.external_check_materializer as mod
    import services.resolution.repos.event_logs_hypersync as repo_mod

    monkeypatch.delenv("PSAT_HYPERSYNC_URL", raising=False)
    monkeypatch.setenv("ENVIO_API_TOKEN", "tok")
    monkeypatch.setattr(repo_mod, "_hypersync_url_for_chain", lambda cid: BASE_URL if cid == 8453 else None)
    _stub_floor_defer(monkeypatch)

    asyncio.run(mod._candidate_addresses_from_hypersync_async(checker_address="0x" + "11" * 20, limit=8, chain_id=8453))
    assert _capture_build_url["url"] == BASE_URL


# --------------------------------------------------------------------------- #
# predicate_evaluator view-key membership scan                                #
# --------------------------------------------------------------------------- #


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

    _observed(SimpleNamespace(meta={}, chain_id=1, block=None))
    assert _capture_build_url["url"] == MAINNET_URL


def test_observed_keys_unavailable_chain_skips_scan(monkeypatch, _capture_build_url):
    monkeypatch.delenv("PSAT_HYPERSYNC_URL", raising=False)
    monkeypatch.setenv("ENVIO_API_TOKEN", "tok")

    out = _observed(SimpleNamespace(meta={}, chain_id=8453, block=None))
    assert out == []
    assert "url" not in _capture_build_url  # registry None → no scan, no mainnet fallback


def test_observed_keys_meta_url_overrides_registry(monkeypatch, _capture_build_url):
    """The meta override still wins (byte-identical precedence) — even on an
    otherwise-unavailable chain an explicit endpoint is honored."""
    import services.resolution.creation_block_floor as floor_mod

    monkeypatch.delenv("PSAT_HYPERSYNC_URL", raising=False)
    monkeypatch.setenv("ENVIO_API_TOKEN", "tok")
    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: None)
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", lambda *_a, **_k: 7_000_000)

    _observed(SimpleNamespace(meta={"hypersync_url": BASE_URL}, chain_id=8453, block=None))
    assert _capture_build_url["url"] == BASE_URL


# --------------------------------------------------------------------------- #
# mapping_enumerator default                                                   #
# --------------------------------------------------------------------------- #


def test_mapping_enumerator_default_url_is_registry_mainnet():
    from services.resolution.mapping_enumerator import DEFAULT_HYPERSYNC_URL

    assert DEFAULT_HYPERSYNC_URL == MAINNET_URL
