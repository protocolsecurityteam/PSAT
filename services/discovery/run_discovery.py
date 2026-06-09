"""Production discovery orchestrator (Premium + Deps tier).

Single entry point that runs the best audit- and address-discovery
pipelines and conditionally triggers dependency-audit two-pass.

Target recall: ~75% audit URLs, ~82% address URLs, plus dependency
audits for protocols with third-party components. Target cost:
~$1.40 per protocol cold, ~$0.05 cached re-run.

Output shape keeps the existing `search_audit_reports()` and
`search_protocol_inventory()` return dicts so workers can persist without
schema changes.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import yaml

from services.discovery import audit_reports as audit_reports_mod
from services.discovery import inventory as inventory_mod
from services.discovery.audit_enrichment import enrich_audit_reports
from services.discovery.audit_reports_llm import _parse_json_object
from services.discovery.inventory_domain import SearchFn
from utils import exa, llm

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[2]
KNOWN_DOCS_PATH = ROOT / "config" / "known_docs.yaml"

# Budget guardrails (per-protocol); abort + alert if exceeded.
MAX_SEARCH_CALLS_PER_PROTOCOL = 10
MAX_RESEARCH_CALLS_PER_PROTOCOL = 5
BUDGET_CIRCUIT_BREAKER_USD = 2.00

# Deep Research output is stable for 24-48h; cache aggressively.
RESEARCH_CACHE_TTL_SECONDS = 24 * 3600

_DEPENDENCY_CLASSIFIER_PROMPT = """\
You are deciding whether PSAT should run a follow-up dependency-audit search for \
the {protocol} protocol.

Run the follow-up only when the evidence indicates {protocol} likely integrates \
third-party smart contract systems, vault frameworks, bridge/adaptor systems, \
or infrastructure components that may have independent security audits separate \
from {protocol}'s own core audits.

Do not trigger for generic protocol contracts, tokens, routers, factories, \
registries, managers, OpenZeppelin/Solmate-style libraries, or vague words \
without concrete third-party integration evidence.

Return exactly one JSON object:
{{
  "should_run_dependency_pass": true | false,
  "confidence": 0.0-1.0,
  "rationale": "short reason",
  "suspected_dependencies": ["name or system", "..."]
}}

Evidence:
{evidence}
"""


def _load_known_docs() -> dict[str, dict[str, list[str]]]:
    if not KNOWN_DOCS_PATH.exists():
        return {}
    data = yaml.safe_load(KNOWN_DOCS_PATH.read_text()) or {}
    return data.get("protocols", {}) or {}


_research_cache: dict[tuple, tuple[float, dict]] = {}


def _cached_deep_research(instructions: str, schema: dict | None = None) -> dict:
    """TTL-cached wrapper around exa.deep_research for re-run savings."""
    import hashlib
    import json as _json

    schema_hash = hashlib.sha1(_json.dumps(schema or {}, sort_keys=True).encode()).hexdigest()
    key = (instructions, schema_hash)
    now = time.monotonic()
    if key in _research_cache:
        ts, result = _research_cache[key]
        if now - ts < RESEARCH_CACHE_TTL_SECONDS:
            logger.info("deep_research cache hit for %r", instructions[:60])
            return result
    result = exa.deep_research(instructions, schema=schema, timeout_seconds=900)
    _research_cache[key] = (now, result)
    return result


class _Budget:
    """Per-protocol call + spend tracker."""

    def __init__(self) -> None:
        self.search_calls = 0
        self.research_calls = 0
        self.estimated_cost_usd = 0.0

    def charge_search(self, mode: str) -> None:
        self.search_calls += 1
        self.estimated_cost_usd += 0.012 if mode in ("deep-lite", "deep", "deep-reasoning") else 0.007
        if self.search_calls > MAX_SEARCH_CALLS_PER_PROTOCOL:
            raise RuntimeError(f"search budget exceeded: {self.search_calls}")
        if self.estimated_cost_usd > BUDGET_CIRCUIT_BREAKER_USD:
            raise RuntimeError(f"cost circuit breaker tripped at ${self.estimated_cost_usd:.2f}")

    def charge_research(self) -> None:
        self.research_calls += 1
        self.estimated_cost_usd += 0.20
        if self.research_calls > MAX_RESEARCH_CALLS_PER_PROTOCOL:
            raise RuntimeError(f"research budget exceeded: {self.research_calls}")
        if self.estimated_cost_usd > BUDGET_CIRCUIT_BREAKER_USD:
            raise RuntimeError(f"cost circuit breaker tripped at ${self.estimated_cost_usd:.2f}")

    def remaining_research_calls(self) -> int:
        return max(0, MAX_RESEARCH_CALLS_PER_PROTOCOL - self.research_calls)


def _make_exa_search_fn(mode: str, budget: _Budget) -> SearchFn:
    """Return a discovery search function routed through Exa."""

    def fn(
        query: str,
        max_results: int,
        queries_used: list[int],
        max_queries: int,
        errors: list[dict[str, Any]],
        debug: bool = False,
    ) -> list[dict[str, Any]]:
        if queries_used[0] >= max_queries:
            return []
        queries_used[0] += 1
        try:
            budget.charge_search(mode)
            return exa.search(query, max_results=max_results, mode=mode)
        except Exception as exc:
            errors.append({"provider": "exa", "error": str(exc), "query": query[:120]})
            logger.error("Exa search failed mode=%s query=%r: %s", mode, query[:120], exc)
            raise RuntimeError(f"Exa search failed for discovery query {query[:120]!r}") from exc

    return fn


def _audit_research_instructions(protocol: str) -> str:
    return (
        f"Find all third-party smart contract security audit reports published for the "
        f"{protocol} protocol. Include pre-launch audits, formal verification reports, "
        f"contest reports (Code4rena/Sherlock/Cantina), audit-firm blog posts, and PDF "
        f"reports on GitHub or auditor websites."
    )


def _address_research_instructions(protocol: str) -> str:
    return (
        f"Find the main deployed smart contract addresses for the {protocol} protocol. "
        f"List core production contracts with their names and 0x-prefixed on-chain addresses. "
        f"Do not infer or emit chain IDs; the pipeline probes addresses across supported networks."
    )


_AUDIT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["auditReports"],
    "additionalProperties": False,
    "properties": {
        "auditReports": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["auditor", "url"],
                "additionalProperties": False,
                "properties": {
                    "auditor": {"type": "string"},
                    "url": {"type": "string"},
                    "pdf_url": {"type": "string"},
                    "source_repo": {"type": "string"},
                    "reviewed_commits": {"type": "array", "items": {"type": "string"}},
                    "referenced_repos": {"type": "array", "items": {"type": "string"}},
                    "title": {"type": "string"},
                    "date": {"type": "string"},
                },
            },
        }
    },
}

_ADDRESS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["contracts"],
    "additionalProperties": False,
    "properties": {
        "contracts": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "address"],
                "additionalProperties": False,
                "properties": {
                    "name": {"type": "string"},
                    "address": {"type": "string"},
                    "role": {"type": "string"},
                },
            },
        }
    },
}

_DEPS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["components"],
    "additionalProperties": False,
    "properties": {
        "components": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "author"],
                "additionalProperties": False,
                "properties": {
                    "name": {"type": "string"},
                    "author": {"type": "string"},
                    "purpose": {"type": "string"},
                },
            },
        }
    },
}


def _dependency_classifier_evidence(contracts: list[dict], audits: list[dict]) -> dict[str, list[dict[str, Any]]]:
    contract_evidence: list[dict[str, Any]] = []
    for contract in contracts[:25]:
        name = str(contract.get("name") or "").strip()
        address = str(contract.get("address") or "").strip()
        if not name and not address:
            continue
        contract_evidence.append(
            {
                "name": name,
                "address": address,
                "source": contract.get("source") or [],
            }
        )

    audit_evidence: list[dict[str, Any]] = []
    for audit in audits[:25]:
        title = str(audit.get("title") or "").strip()
        auditor = str(audit.get("auditor") or "").strip()
        url = str(audit.get("url") or "").strip()
        if not title and not auditor and not url:
            continue
        audit_evidence.append({"title": title, "auditor": auditor, "url": url})

    return {"contracts": contract_evidence, "audits": audit_evidence}


def _audit_metadata_from_ai(item: dict[str, Any], *, provenance: str) -> dict[str, Any]:
    out: dict[str, Any] = {"metadata_provenance": provenance}
    for key in ("pdf_url", "source_repo", "date", "title", "auditor"):
        value = item.get(key)
        if value:
            out[key] = value
    reviewed = [str(v).strip() for v in item.get("reviewed_commits") or [] if str(v).strip()]
    refs = [str(v).strip() for v in item.get("referenced_repos") or [] if str(v).strip()]
    if reviewed:
        out["reviewed_commits"] = reviewed
    if refs:
        out["referenced_repos"] = refs
    return out


def _audit_key(url: str | None) -> str:
    return str(url or "").strip().rstrip("/").lower()


def _merge_ai_audit_metadata(audit_result: dict[str, Any], metadata_by_url: dict[str, dict[str, Any]]) -> None:
    if not metadata_by_url:
        return
    for report in audit_result.get("reports", []) or []:
        if not isinstance(report, dict):
            continue
        keys = [_audit_key(report.get("url")), _audit_key(report.get("pdf_url")), _audit_key(report.get("source_url"))]
        metadata = next((metadata_by_url[key] for key in keys if key in metadata_by_url), None)
        if not metadata:
            continue
        for key, value in metadata.items():
            if key in {"reviewed_commits", "referenced_repos"}:
                existing = [str(v) for v in report.get(key) or [] if v]
                for item in value:
                    if item not in existing:
                        existing.append(item)
                if existing:
                    report[key] = existing
            elif value and not report.get(key):
                report[key] = value


def _needs_dependency_pass(protocol: str, contracts: list[dict], audits: list[dict]) -> bool:
    evidence = _dependency_classifier_evidence(contracts, audits)
    if not evidence["contracts"] and not evidence["audits"]:
        return False

    prompt = _DEPENDENCY_CLASSIFIER_PROMPT.format(
        protocol=protocol,
        evidence=json.dumps(evidence, indent=2, sort_keys=True),
    )
    try:
        response = llm.chat([{"role": "user", "content": prompt}], max_tokens=700, temperature=0.0)
    except Exception as exc:
        logger.error("dependency classifier failed for %s: %s", protocol, exc)
        raise RuntimeError(f"dependency classifier failed for {protocol}") from exc

    parsed = _parse_json_object(response)
    if not parsed:
        logger.error("dependency classifier returned unparseable response for %s", protocol)
        raise RuntimeError(f"dependency classifier returned unparseable response for {protocol}")

    try:
        confidence = float(parsed.get("confidence") or 0)
    except (TypeError, ValueError) as exc:
        logger.error("dependency classifier returned invalid confidence for %s: %r", protocol, parsed.get("confidence"))
        raise RuntimeError(f"dependency classifier returned invalid confidence for {protocol}") from exc

    decision = parsed.get("should_run_dependency_pass")
    if isinstance(decision, str):
        normalized = decision.strip().lower()
        if normalized in {"true", "yes", "1"}:
            should_run = True
        elif normalized in {"false", "no", "0"}:
            should_run = False
        else:
            logger.error("dependency classifier returned invalid decision for %s: %r", protocol, decision)
            raise RuntimeError(f"dependency classifier returned invalid decision for {protocol}")
    elif isinstance(decision, bool):
        should_run = bool(decision)
    else:
        logger.error("dependency classifier returned missing/non-boolean decision for %s: %r", protocol, decision)
        raise RuntimeError(f"dependency classifier returned missing/non-boolean decision for {protocol}")
    return should_run and confidence >= 0.5


def _dependency_research(protocol: str, budget: _Budget) -> list[dict]:
    """Two-pass: identify deps, then audit-search each."""
    pass1 = (
        f"For the {protocol} protocol, list the main third-party smart contract systems, "
        f"vaults, libraries, or infrastructure components {protocol} integrates with or uses "
        f"in production. Do NOT include general-purpose dev libraries (OpenZeppelin, Solmate). "
        f"Focus on components commissioned/audited separately from {protocol}'s core code "
        f"(e.g., BoringVault by Veda Labs, EigenLayer, LayerZero OFT adapter)."
    )
    budget.charge_research()
    try:
        r1 = _cached_deep_research(pass1, schema=_DEPS_SCHEMA)
    except Exception as exc:
        logger.error("dep pass 1 failed for %s: %s", protocol, exc)
        raise RuntimeError(f"dependency research pass 1 failed for {protocol}") from exc
    components = r1.get("data", {}).get("components", []) or []
    remaining = budget.remaining_research_calls()
    if remaining <= 0:
        logger.warning(
            "dependency research skipped follow-up audit searches for %s: research budget exhausted",
            protocol,
        )
        return []
    selected_components = components[:remaining]
    if len(components) > len(selected_components):
        logger.warning(
            "dependency research truncated follow-up audit searches for %s: components=%d remaining_budget=%d",
            protocol,
            len(components),
            remaining,
        )

    dep_audits: list[dict] = []
    for c in selected_components:
        inst = f"Find smart contract security audit reports for {c.get('name')} by {c.get('author')}."
        try:
            budget.charge_research()
        except RuntimeError as exc:
            logger.error("dep pass 2 budget exhausted for %s/%s: %s", c.get("name"), c.get("author"), exc)
            raise
        try:
            r2 = _cached_deep_research(inst, schema=_AUDIT_SCHEMA)
        except Exception as exc:
            logger.error("dep pass 2 failed for %s/%s: %s", c.get("name"), c.get("author"), exc)
            raise RuntimeError(f"dependency research pass 2 failed for {c.get('name')}") from exc
        for a in r2.get("data", {}).get("auditReports", []):
            url = str(a.get("url") or "").strip()
            if not url:
                continue
            dep_audits.append(
                {
                    "url": url,
                    "pdf_url": a.get("pdf_url"),
                    "auditor": a.get("auditor"),
                    "title": f"[dep: {c.get('name')}] {a.get('title', '')}".strip(),
                    "date": a.get("date"),
                    "source_repo": a.get("source_repo"),
                    "reviewed_commits": a.get("reviewed_commits") or [],
                    "referenced_repos": a.get("referenced_repos") or [],
                    "metadata_provenance": "ai_returned",
                    "discovery_source": "dependency_two_pass",
                    "dependency_component": c.get("name"),
                    "dependency_author": c.get("author"),
                    "confidence": 1.0,
                }
            )
    return dep_audits


def _apply_spa_overrides(protocol: str, inventory_result: dict, audit_result: dict) -> None:
    """Fold hardcoded known-docs URLs into results for SPA-bait protocols."""
    known = _load_known_docs().get(protocol.lower()) or {}
    if not known:
        return
    # For addresses: add known contract_docs_urls as notes so a downstream
    # worker can fetch them directly (pipeline can't index the SPA).
    for url in known.get("contract_docs_urls", []):
        inventory_result.setdefault("notes", []).append(f"SPA override: fetch {url} manually")
    for url in known.get("contract_docs_raw_urls", []):
        inventory_result.setdefault("notes", []).append(f"SPA override (raw): {url}")
    # For audits: inject the known audit_urls as pre-approved audit reports.
    for url in known.get("audit_urls", []):
        audit_result.setdefault("reports", []).append(
            {
                "url": url,
                "auditor": "SPA override (see config/known_docs.yaml)",
                "title": f"{protocol} audits (known-docs override)",
                "confidence": 1.0,
                "discovery_source": "spa_override",
            }
        )


def run_discovery(protocol: str, *, official_domain: str | None = None) -> dict[str, Any]:
    """Premium+Deps discovery for one protocol.

    Returns ``{audits: <search_audit_reports shape>, addresses: <search_protocol_inventory shape>,
    meta: {...}}`` so existing workers can slot it in with minimal plumbing changes.
    """
    budget = _Budget()
    started_at = time.monotonic()

    # ---- Audits ----
    # 1a. Deep Research for audit seeds
    audit_seeds: list[dict] = []
    audit_seed_metadata: dict[str, dict[str, Any]] = {}
    try:
        budget.charge_research()
        r = _cached_deep_research(_audit_research_instructions(protocol), schema=_AUDIT_SCHEMA)
        for item in r.get("data", {}).get("auditReports", []):
            url = str(item.get("url") or "").strip()
            if not url:
                continue
            snippet = f"{item.get('auditor') or ''} audit report for {protocol}. {item.get('date') or ''}".strip()
            metadata = _audit_metadata_from_ai(item, provenance="ai_returned")
            audit_seed_metadata[_audit_key(url)] = metadata
            if item.get("pdf_url"):
                audit_seed_metadata[_audit_key(item.get("pdf_url"))] = metadata
            audit_seeds.append(
                {
                    "url": url,
                    "title": f"{item.get('auditor') or 'Audit'} — {protocol}",
                    "content": snippet,
                    "score": 1.0,
                }
            )
    except Exception as exc:
        logger.error("deep research (audit seeds) failed for %s: %s", protocol, exc)
        raise RuntimeError(f"deep research audit seeds failed for {protocol}") from exc

    # 1b. Full pipeline: Exa/deep-lite search + explicit Deep Research seeds.
    audit_result = audit_reports_mod.search_audit_reports(
        protocol,
        search_fn=_make_exa_search_fn("deep-lite", budget),
        seed_results=audit_seeds,
        official_domain=official_domain,
        max_queries=4,
        debug=False,
    )
    _merge_ai_audit_metadata(audit_result, audit_seed_metadata)

    # ---- Addresses ----
    inventory_result = inventory_mod.search_protocol_inventory(
        protocol,
        search_fn=_make_exa_search_fn("auto", budget),
        limit=500,
        max_queries=4,
        debug=False,
    )

    # Attach address-side Deep Research output as additional evidence.
    try:
        budget.charge_research()
        r_addr = _cached_deep_research(_address_research_instructions(protocol), schema=_ADDRESS_SCHEMA)
        for item in r_addr.get("data", {}).get("contracts", []):
            addr = str(item.get("address") or "").strip().lower()
            if not addr.startswith("0x") or len(addr) != 42:
                continue
            inventory_result.setdefault("contracts", []).append(
                {
                    "name": item.get("name"),
                    "address": addr,
                    "confidence": 1.0,
                    "source": ["exa_deep_research"],
                    "evidence": {"deep_research": 1},
                }
            )
    except Exception as exc:
        logger.error("deep research (addresses) failed for %s: %s", protocol, exc)
        raise

    # ---- Dependency two-pass (conditional) ----
    dependency_pass_triggered = _needs_dependency_pass(
        protocol,
        inventory_result.get("contracts", []),
        audit_result.get("reports", []),
    )
    if dependency_pass_triggered:
        logger.info("dependency classifier selected %s for two-pass", protocol)
        for dep_audit in _dependency_research(protocol, budget):
            audit_result.setdefault("reports", []).append(dep_audit)
    else:
        logger.info("dependency classifier skipped two-pass for %s", protocol)

    # ---- SPA override (gmx, etc.) ----
    _apply_spa_overrides(protocol, inventory_result, audit_result)
    enrich_audit_reports(audit_result, protocol, debug=False)

    elapsed_ms = int((time.monotonic() - started_at) * 1000)
    return {
        "audits": audit_result,
        "addresses": inventory_result,
        "meta": {
            "protocol": protocol,
            "elapsed_ms": elapsed_ms,
            "search_calls": budget.search_calls,
            "research_calls": budget.research_calls,
            "estimated_cost_usd": round(budget.estimated_cost_usd, 3),
            "dependency_pass_triggered": dependency_pass_triggered,
        },
    }


def reset_cache() -> None:
    """Clear the deep_research cache (for tests)."""
    _research_cache.clear()
