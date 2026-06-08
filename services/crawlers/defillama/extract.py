"""
Extract Ethereum contract addresses from DefiLlama adapter source files.

Handles multiple patterns:
  - String literals: "0xAbC..."
  - Object values: { contract: "0xAbC..." }
  - Function args: staking("0xAbC...", ...)
  - Array entries: markets: ["0xAbC...", "0xDeF..."]
  - coreAssets.json references (resolved separately)
"""

import logging
import re
from pathlib import Path

from utils.rpc import require_chain_id_for_evidence_label

logger = logging.getLogger(__name__)

# Matches 0x followed by exactly 40 hex chars, bounded so we don't
# grab partial hashes or other hex strings
ADDR_RE = re.compile(r"\b(0x[a-fA-F0-9]{40})\b")

# Common non-contract addresses to filter out
IGNORE_ADDRS = {
    "0x" + "0" * 40,
    "0x" + "f" * 40,
    "0x" + "F" * 40,
    "0x000000000000000000000000000000000000dead",
    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "0xffffffffffffffffffffffffffffffffffffffff",
}

# Known chain identifiers from directory names and code patterns
CHAIN_ALIASES = {
    "avax": "avalanche",
    "bsc": "bsc",
    "xdai": "gnosis",
    "okexchain": "okx",
    "heco": "heco",
    "matic": "polygon",
}


def extract_addresses_from_file(filepath: Path) -> list[str]:
    """Extract all Ethereum addresses from a single JS/TS file."""
    try:
        text = filepath.read_text(errors="ignore")
    except OSError as exc:
        logger.error("Failed to read DefiLlama adapter file %s: %s", filepath, exc)
        raise RuntimeError(f"Failed to read DefiLlama adapter file {filepath}") from exc

    raw = ADDR_RE.findall(text)
    # Deduplicate, lowercase, filter junk
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
    """
    Try to figure out which chain an address belongs to based on
    surrounding code context.
    """
    # Find all occurrences of this address and look at nearby code
    for m in re.finditer(re.escape(addr), text, re.IGNORECASE):
        start = max(0, m.start() - 300)
        end = min(len(text), m.end() + 100)
        context = text[start:end].lower()

        # Check for chain name in the surrounding context
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
    """
    Extract all addresses from a protocol's adapter directory.

    Returns:
        {
            "protocol": "aave",
            "files_scanned": 3,
            "addresses": [
                {"address": "0x...", "chain_id": 1, "raw_chain_label": "ethereum", "source": "index.js:12"},
                ...
            ]
        }
    """
    protocol_name = project_dir.name
    addresses = []
    seen = set()

    # Scan all JS/TS files in the protocol directory
    patterns = ["*.js", "*.ts", "*.mjs"]
    files = []
    for pat in patterns:
        files.extend(project_dir.glob(pat))
        files.extend(project_dir.glob(f"**/{pat}"))

    for filepath in sorted(set(files)):
        try:
            text = filepath.read_text(errors="ignore")
        except OSError as exc:
            logger.error("Failed to read DefiLlama adapter file %s: %s", filepath, exc)
            raise RuntimeError(f"Failed to read DefiLlama adapter file {filepath}") from exc

        rel_path = filepath.relative_to(project_dir)
        raw_addrs = ADDR_RE.findall(text)

        for addr in raw_addrs:
            lower = addr.lower()
            if lower in seen or lower in IGNORE_ADDRS:
                continue
            seen.add(lower)

            raw_chain_label = infer_chain_from_context(filepath, text, addr)
            chain_id = (
                require_chain_id_for_evidence_label(
                    raw_chain_label,
                    context=f"DefiLlama adapter {project_dir.name}/{rel_path} {lower}",
                )
                if raw_chain_label
                else None
            )

            # Find line number
            line_num = None
            for i, line in enumerate(text.splitlines(), 1):
                if addr.lower() in line.lower():
                    line_num = i
                    break

            addresses.append(
                {
                    "address": lower,
                    "chain_id": chain_id,
                    "raw_chain_label": raw_chain_label,
                    "source": f"{rel_path}:{line_num}" if line_num else str(rel_path),
                }
            )

    return {
        "protocol": protocol_name,
        "files_scanned": len(set(files)),
        "addresses": addresses,
    }
