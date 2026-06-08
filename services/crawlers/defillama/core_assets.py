"""
Parse DefiLlama's coreAssets.json — a master mapping of well-known
token addresses organized by chain.
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def load_core_assets(repo_path: Path) -> dict[str, dict[str, str]]:
    """
    Load coreAssets.json and return a normalized structure:
    {
        "ethereum": {"WETH": "0x...", "USDC": "0x...", ...},
        "arbitrum": {...},
        ...
    }
    """
    path = repo_path / "projects" / "helper" / "coreAssets.json"
    if not path.exists():
        logger.error("DefiLlama coreAssets.json not found at %s", path)
        raise FileNotFoundError(f"DefiLlama coreAssets.json not found at {path}")

    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Failed to load DefiLlama coreAssets.json at %s: %s", path, exc)
        raise RuntimeError(f"Failed to load DefiLlama coreAssets.json at {path}") from exc

    result = {}
    for chain, assets in raw.items():
        if not isinstance(assets, dict):
            continue
        normalized = {}
        for name, addr in assets.items():
            if isinstance(addr, str) and addr.startswith("0x") and len(addr) == 42:
                normalized[name] = addr.lower()
        if normalized:
            result[chain] = normalized

    return result


def build_address_to_chain_map(core_assets: dict) -> dict[str, str]:
    """
    Build a reverse map: address -> chain, for quick lookups.
    """
    addr_map = {}
    for chain, assets in core_assets.items():
        for name, addr in assets.items():
            addr_map[addr.lower()] = chain
    return addr_map
