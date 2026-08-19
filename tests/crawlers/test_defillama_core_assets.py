"""Tests for core assets loading and address-to-chain mapping."""

import json
import tempfile
from pathlib import Path

from services.crawlers.defillama.core_assets import build_address_to_chain_map, load_core_assets


def _make_repo_with_core_assets(tmp: str, assets: dict) -> Path:
    """Create a mock repo directory with a coreAssets.json file."""
    repo = Path(tmp) / "repo"
    helper = repo / "projects" / "helper"
    helper.mkdir(parents=True)
    (helper / "coreAssets.json").write_text(json.dumps(assets))
    return repo


def test_load_core_assets_basic():
    with tempfile.TemporaryDirectory() as tmp:
        repo = _make_repo_with_core_assets(
            tmp,
            {
                "ethereum": {
                    "WETH": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                    "USDC": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                },
                "arbitrum": {
                    "WETH": "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
                },
            },
        )
        result = load_core_assets(repo)

    assert "ethereum" in result
    assert "arbitrum" in result
    assert result["ethereum"]["WETH"] == "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
    assert len(result["ethereum"]) == 2
    assert len(result["arbitrum"]) == 1


def test_load_core_assets_filters_invalid():
    with tempfile.TemporaryDirectory() as tmp:
        repo = _make_repo_with_core_assets(
            tmp,
            {
                "ethereum": {
                    "WETH": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                    "bad": "not-an-address",
                    "short": "0x1234",
                },
            },
        )
        result = load_core_assets(repo)

    assert len(result["ethereum"]) == 1


def test_load_core_assets_missing_file():
    with tempfile.TemporaryDirectory() as tmp:
        result = load_core_assets(Path(tmp))
    assert result == {}


def test_build_address_to_chain_map():
    core_assets = {
        "ethereum": {"WETH": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"},
        "arbitrum": {"WETH": "0x82af49447d8a07e3bd95bd0d56f35241523fbab1"},
    }
    addr_map = build_address_to_chain_map(core_assets)

    assert addr_map["0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"] == "ethereum"
    assert addr_map["0x82af49447d8a07e3bd95bd0d56f35241523fbab1"] == "arbitrum"
    assert len(addr_map) == 2


def test_build_address_to_chain_map_empty():
    assert build_address_to_chain_map({}) == {}
