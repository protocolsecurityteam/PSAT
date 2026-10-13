"""Publisher-declared Ethereum core deployments, independently of research nominations.

Sources and selectors are reviewed configuration, never URLs or tags supplied by an LLM.
This is evidence of the publisher's declaration, not proof of exclusive governance or safety.
No deployment addresses are embedded here. On-chain code remains a separate admission gate.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests

from services.discovery.inventory_extract import extract_inventory_entries_from_page_text

SOURCE_TAG = "publisher_registry"
WITNESS_RULE = "w7_publisher_registry"
_MAX_BYTES = 5_000_000
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_SHA = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class Registry:
    key: str
    protocol: str
    url: str
    repo: str | None = None
    path: str | None = None
    containers: tuple[str, ...] = ()


REGISTRIES = (
    Registry(
        "maple_eth",
        "maple",
        "https://github.com/maple-labs/address-registry",
        "maple-labs/address-registry",
        "contracts/MapleAddressRegistryETH.sol",
        ("MapleAddressRegistryETH",),
    ),
    Registry(
        "aave_v3_eth",
        "aave",
        "https://github.com/aave-dao/aave-address-book",
        "aave-dao/aave-address-book",
        "src/AaveV3Ethereum.sol",
        ("AaveV3Ethereum",),
    ),
    Registry(
        "aave_v4_eth",
        "aave",
        "https://github.com/aave-dao/aave-address-book",
        "aave-dao/aave-address-book",
        "src/AaveV4Ethereum.sol",
        (
            "AaveV4Ethereum",
            "AaveV4EthereumHubs",
            "AaveV4EthereumSpokes",
            "AaveV4EthereumPositionManagers",
            "AaveV4EthereumTokenizationSpokes",
        ),
    ),
    Registry("lido_eth", "lido", "https://docs.lido.fi/deployed-contracts/"),
)
_BY_KEY = {source.key: source for source in REGISTRIES}
# Reviewed publisher-family aliases, not a generic version/prefix match. DefiLlama's
# family identity is a versioned slug; these all use the same Aave publisher registries.
_PUBLISHER_FAMILIES = {
    "aavev1": "aave",
    "aavev2": "aave",
    "aavev3": "aave",
    "aavev4": "aave",
}
_MAPLE_ROOTS = {
    "daoMultisig",
    "governor",
    "securityAdmin",
    "operationalAdmin",
    "globalAdmin",
    "permissionsAdmin",
    "mapleGlobals",
    "globals",
    "poolDeployer",
    "mapleTreasury",
}
_MAPLE_FACTORIES = {
    "fixedTermLoanFactory",
    "fixedTermLoanFactoryV2",
    "fixedTermLoanManagerFactory",
    "poolManagerFactory",
    "withdrawalManagerCyclicalFactory",
    "liquidatorFactory",
    "openTermLoanFactory",
    "openTermLoanManagerFactory",
    "withdrawalManagerQueueFactory",
    "aaveStrategyFactory",
    "skyStrategyFactory",
    "basicStrategyFactory",
}
_MAPLE_POOL = re.compile(
    r"(?:syrup(?:USDC|USDT|USDG)|securedLending\d*USDC)(?:Pool|PoolManager|"
    r"FixedTermLoanManager|OpenTermLoanManager|WithdrawalManagerQueue|PoolDelegateCover|"
    r"SyrupRouter|AaveStrategy|SkyStrategy)$"
)
_LIDO_CORE = re.compile(
    r"core protocol|oracle contracts|dao contracts|dual governance|"
    r"circuit.?breaker|execution delegation framework",
    re.I,
)
_EXTERNAL = re.compile(r"external|integration|testnet|holesky|sepolia|hoodi|bridge|deprecated|proposed|planned", re.I)


def protocol_key(name: str | None) -> str:
    """Publisher identity shared by registry selection and membership validation."""
    normalized = re.sub(r"[^a-z0-9]", "", (name or "").lower())
    return _PUBLISHER_FAMILIES.get(normalized, normalized)


def _get(url: str, *, token: str | None = None) -> bytes:
    headers = {"User-Agent": "PSAT-publisher-registry"}
    if token and urlsplit(url).hostname == "api.github.com":
        headers["Authorization"] = f"Bearer {token}"
    # Refuse redirects: a trusted host must not silently delegate this trust decision.
    with requests.get(url, headers=headers, timeout=30, allow_redirects=False, stream=True) as response:
        if response.status_code != 200:
            raise ValueError(f"publisher registry HTTP {response.status_code}")
        chunks, size = [], 0
        for chunk in response.iter_content(65536):
            size += len(chunk)
            if size > _MAX_BYTES:
                raise ValueError("publisher registry exceeds size limit")
            chunks.append(chunk)
        return b"".join(chunks)


def parse_solidity(source: Registry, text: str) -> list[dict[str, str]]:
    # Do not admit commented-out declarations, imports, examples or arbitrary address literals.
    text = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
    rows = []
    for container in re.finditer(r"\b(?:library|contract)\s+(\w+)\s*\{([^{}]*)\}", text, re.S):
        if container[1] not in source.containers:
            continue
        for declaration in container[2].split(";"):
            match = re.fullmatch(
                r"\s*\w+\s+(?:(?:public|internal|private|constant)\s+)+"
                r"(\w+)\s*=\s*(?:\w+\s*\(\s*)?(0x[0-9a-fA-F]{40})\s*\)?\s*",
                declaration,
            )
            if not match or not re.search(r"\bconstant\b", declaration):
                continue
            name, address = match.groups()
            if source.protocol == "maple" and not (
                name in _MAPLE_ROOTS or name in _MAPLE_FACTORIES or _MAPLE_POOL.fullmatch(name)
            ):
                continue
            rows.append({"name": name, "address": address.lower(), "selector": f"{container[1]}.{name}"})
    return rows


def parse_lido(source: Registry, text: str) -> list[dict[str, str]]:
    text = re.sub(r"<(script|style|noscript)\b.*?</\1>", "", text, flags=re.S | re.I)
    headings = list(re.finditer(r"<h([1-6])\b[^>]*>(.*?)</h\1>", text, re.S | re.I))
    stack: list[tuple[int, str]] = []
    rows = []
    for index, heading in enumerate(headings):
        level = int(heading[1])
        title = re.sub(r"<[^>]+>", " ", heading[2])
        stack = [(depth, name) for depth, name in stack if depth < level] + [(level, title)]
        section = " / ".join(name for _, name in stack)
        if not _LIDO_CORE.search(section) or _EXTERNAL.search(section):
            continue
        fragment = text[heading.end() : headings[index + 1].start() if index + 1 < len(headings) else len(text)]
        # The explorer link must itself establish mainnet; a requested chain is never evidence.
        for row in extract_inventory_entries_from_page_text(source.url, fragment, None):
            link = urlsplit(row.get("explorer_url") or "")
            if link.hostname != "etherscan.io" or row.get("chain") != "ethereum":
                continue
            if not re.fullmatch(r"/address/0x[0-9a-fA-F]{40}/?", link.path):
                continue
            name = row.get("name") or ""
            if not name or _EXTERNAL.search(name):
                continue
            rows.append({"name": name, "address": row["address"], "selector": f"{section}: {name}"})
    return rows


def fetch_registries(protocol: str, chain: str | None) -> tuple[list[dict], list[dict]]:
    """Each source succeeds or fails independently; retain exact bounded content for replay."""
    import json

    if chain not in (None, "ethereum"):
        return [], []
    snapshots, failures, revisions = [], [], {}
    for source in REGISTRIES:
        if source.protocol != protocol_key(protocol):
            continue
        try:
            url = source.url
            if source.repo:
                if source.repo not in revisions:
                    commit = json.loads(
                        _get(
                            f"https://api.github.com/repos/{source.repo}/commits/main", token=os.getenv("GITHUB_TOKEN")
                        )
                    )
                    revision = commit.get("sha", "")
                    if not isinstance(revision, str) or not _SHA.fullmatch(revision):
                        raise ValueError("publisher revision is not a full commit SHA")
                    revisions[source.repo] = revision
                url = f"https://raw.githubusercontent.com/{source.repo}/{revisions[source.repo]}/{source.path}"
            body = _get(url)
            text = body.decode("utf-8")
            digest = hashlib.sha256(body).hexdigest()
            revision = revisions[source.repo] if source.repo else f"sha256:{digest}"
            rows = parse_solidity(source, text) if source.repo else parse_lido(source, text)
            if not rows:
                raise ValueError("publisher registry has no supported core declarations")
            snapshots.append(
                {
                    "registry": source.key,
                    "protocol": source.protocol,
                    "chain_id": 1,
                    "url": url,
                    "revision": revision,
                    "sha256": digest,
                    "retrieved_at": datetime.now(timezone.utc).isoformat(),
                    "content": text,
                    "deployments": rows,
                }
            )
        except (requests.RequestException, ValueError, UnicodeError) as exc:
            failures.append(
                {
                    "registry": source.key,
                    "error_type": type(exc).__name__,
                    "reason": "Publisher content unavailable or invalid; no admission from this source.",
                }
            )
    return snapshots, failures


def registry_evidence(snapshot: dict, row: dict) -> dict:
    return {
        key: snapshot[key] for key in ("registry", "protocol", "chain_id", "url", "revision", "sha256", "retrieved_at")
    } | {"address": row["address"], "selector": row["selector"]}


def validate_evidence(evidence: dict) -> dict:
    source = _BY_KEY.get(str(evidence.get("registry", "")))
    if source is None or evidence.get("protocol") != source.protocol or evidence.get("chain_id") != 1:
        raise ValueError("registry identity/chain mismatch")
    address = evidence.get("address", "")
    digest = evidence.get("sha256", "")
    revision = evidence.get("revision", "")
    if not isinstance(address, str) or not _ADDRESS.fullmatch(address) or address != address.lower():
        raise ValueError("invalid registry address")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise ValueError("invalid publisher content digest")
    expected_url = source.url
    if source.repo:
        if not isinstance(revision, str) or not _SHA.fullmatch(revision):
            raise ValueError("invalid publisher revision")
        expected_url = f"https://raw.githubusercontent.com/{source.repo}/{revision}/{source.path}"
    elif revision != f"sha256:{digest}":
        raise ValueError("unbound publisher snapshot")
    if evidence.get("url") != expected_url or not isinstance(evidence.get("selector"), str) or not evidence["selector"]:
        raise ValueError("invalid publisher location")
    if (
        not isinstance(evidence.get("retrieved_at"), str)
        or datetime.fromisoformat(evidence["retrieved_at"]).tzinfo is None
    ):
        raise ValueError("publisher retrieval time needs timezone")
    return {
        key: evidence[key]
        for key in (
            "registry",
            "protocol",
            "chain_id",
            "url",
            "revision",
            "sha256",
            "retrieved_at",
            "address",
            "selector",
        )
    }


def validate_membership_evidence(evidence: dict) -> dict:
    """One membership row can retain independent assertions from several publisher registries."""
    assertions = evidence.get("assertions")
    if not isinstance(assertions, list) or not 1 <= len(assertions) <= len(REGISTRIES):
        raise ValueError("publisher membership requires bounded source assertions")
    checked = [validate_evidence(assertion) for assertion in assertions]
    keys = [item["registry"] for item in checked]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate publisher registry assertion")
    identity = {key: evidence.get(key) for key in ("protocol", "chain_id", "address")}
    if any(any(item[key] != value for key, value in identity.items()) for item in checked):
        raise ValueError("publisher assertions disagree on deployment identity")
    return {**identity, "assertions": sorted(checked, key=lambda item: item["registry"])}
