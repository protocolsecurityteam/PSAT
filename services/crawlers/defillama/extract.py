"""Extract addresses from DefiLlama adapter source: string literals, object values, function args, arrays."""

import re
from pathlib import Path

# Word-bounded so partial hashes don't match.
ADDR_RE = re.compile(r"\b(0x[a-fA-F0-9]{40})\b")

IGNORE_ADDRS = {
    "0x" + "0" * 40,
    "0x" + "f" * 40,
    "0x" + "F" * 40,
    "0x000000000000000000000000000000000000dead",
    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "0xffffffffffffffffffffffffffffffffffffffff",
}

CHAIN_ALIASES = {
    "avax": "avalanche",
    "bsc": "bsc",
    "xdai": "gnosis",
    "okexchain": "okx",
    "heco": "heco",
    "matic": "polygon",
}


def extract_addresses_from_file(filepath: Path) -> list[str]:
    try:
        text = filepath.read_text(errors="ignore")
    except Exception:
        return []

    raw = ADDR_RE.findall(text)
    seen = set()
    result = []
    for addr in raw:
        lower = addr.lower()
        if lower in seen or lower in IGNORE_ADDRS:
            continue
        seen.add(lower)
        result.append(lower)
    return result


def infer_chain_from_context(filepath: Path, text: str, addr: str) -> str | None:
    for m in re.finditer(re.escape(addr), text, re.IGNORECASE):
        start = max(0, m.start() - 300)
        end = min(len(text), m.end() + 100)
        context = text[start:end].lower()

        chain_keywords = {
            "ethereum": "ethereum",
            "arbitrum": "arbitrum",
            "optimism": "optimism",
            "polygon": "polygon",
            "matic": "polygon",
            "avax": "avalanche",
            "avalanche": "avalanche",
            "bsc": "bsc",
            "fantom": "fantom",
            "base": "base",
            "gnosis": "gnosis",
            "xdai": "gnosis",
            "moonbeam": "moonbeam",
            "moonriver": "moonriver",
            "celo": "celo",
            "harmony": "harmony",
            "cronos": "cronos",
            "aurora": "aurora",
            "metis": "metis",
            "linea": "linea",
            "scroll": "scroll",
            "zksync": "zksync",
            "blast": "blast",
            "mantle": "mantle",
            "manta": "manta",
            "solana": "solana",
        }
        for keyword, chain in chain_keywords.items():
            if keyword in context:
                return chain

    return None


def extract_protocol(project_dir: Path) -> dict:
    """``{protocol, files_scanned, addresses: [{address, chain, source}]}`` for one adapter directory."""
    protocol_name = project_dir.name
    addresses = []
    seen = set()

    patterns = ["*.js", "*.ts", "*.mjs"]
    files = []
    for pat in patterns:
        files.extend(project_dir.glob(pat))
        files.extend(project_dir.glob(f"**/{pat}"))

    for filepath in sorted(set(files)):
        try:
            text = filepath.read_text(errors="ignore")
        except Exception:
            continue

        rel_path = filepath.relative_to(project_dir)
        raw_addrs = ADDR_RE.findall(text)

        for addr in raw_addrs:
            lower = addr.lower()
            if lower in seen or lower in IGNORE_ADDRS:
                continue
            seen.add(lower)

            chain = infer_chain_from_context(filepath, text, addr)

            line_num = None
            for i, line in enumerate(text.splitlines(), 1):
                if addr.lower() in line.lower():
                    line_num = i
                    break

            addresses.append(
                {
                    "address": lower,
                    "chain": chain,
                    "source": f"{rel_path}:{line_num}" if line_num else str(rel_path),
                }
            )

    return {
        "protocol": protocol_name,
        "files_scanned": len(set(files)),
        "addresses": addresses,
    }
