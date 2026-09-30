import json
from pathlib import Path


def load_core_assets(repo_path: Path) -> dict[str, dict[str, str]]:
    """``{chain: {symbol: address}}`` from coreAssets.json."""
    path = repo_path / "projects" / "helper" / "coreAssets.json"
    if not path.exists():
        return {}

    raw = json.loads(path.read_text())

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
    addr_map = {}
    for chain, assets in core_assets.items():
        for name, addr in assets.items():
            addr_map[addr.lower()] = chain
    return addr_map
