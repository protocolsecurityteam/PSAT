"""Production discovery orchestrator (Premium + Deps tier).

Single entry point that runs the best audit- and address-discovery
pipelines and conditionally triggers dependency-audit two-pass.

Target recall: ~75% audit URLs, ~82% address URLs, plus dependency
audits for protocols with third-party components. Target cost:
~$1.40 per protocol cold, ~$0.05 cached re-run.

Output shape mirrors the legacy `search_audit_reports()` and
`search_protocol_inventory()` return dicts so the existing workers
(`workers/discovery.py`) can persist without schema changes.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

import yaml

from services.clients import exa
from services.discovery import audit_reports as audit_reports_mod
from services.discovery import inventory as inventory_mod
from services.discovery import inventory_domain as inventory_domain_mod
from services.discovery.audit_enrichment import enrich_audit_reports
from services.discovery.audit_reports_llm import _parse_json_object
from services.discovery.chain_resolver import validate_claimed_chains
from utils import llm
from utils.chains import canonical_chain
from utils.logging import log_timed_phase, record_degraded, record_stage_metric

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


# Process-wide cache keyed on (instructions, schema_hash). Values are
# ``(monotonic_ts, result)``: the 24h TTL serves re-run savings, the size
# cap bounds the entry count across protocols in a long-lived worker.
_research_cache: dict[tuple, tuple[float, dict]] = {}
_research_cache_lock = threading.Lock()
_RESEARCH_CACHE_MAX = 256


def _evict_research_if_needed() -> None:
    """Drop the oldest 25% of _research_cache entries when the bound is reached (caller holds the lock)."""
    if len(_research_cache) < _RESEARCH_CACHE_MAX:
        return
    cutoff = sorted(_research_cache.values(), key=lambda v: v[0])[len(_research_cache) // 4][0]
    for k in [k for k, v in _research_cache.items() if v[0] <= cutoff]:
        _research_cache.pop(k, None)


def _log_research_pressure() -> None:
    """Log when _research_cache crosses 50/75/95% of its bound (caller holds the lock)."""
    from utils.memory import cache_pressure_message

    msg = cache_pressure_message("research", len(_research_cache), _RESEARCH_CACHE_MAX)
    if msg:
        logger.info("[CACHE_PRESSURE] %s", msg)


def _cached_deep_research(instructions: str, schema: dict | None = None) -> dict:
    """TTL-cached wrapper around exa.deep_research for re-run savings."""
    import hashlib
    import json as _json

    schema_hash = hashlib.sha1(_json.dumps(schema or {}, sort_keys=True).encode()).hexdigest()
    key = (instructions, schema_hash)
    now = time.monotonic()
    with _research_cache_lock:
        cached = _research_cache.get(key)
        if cached is not None:
            ts, result = cached
            if now - ts < RESEARCH_CACHE_TTL_SECONDS:
                logger.info("deep_research cache hit for %r", instructions[:60])
                return result
            del _research_cache[key]
    # exa.deep_research runs outside the lock (it can block up to 900s); concurrent
    # misses for the same key may both fetch, matching the _GETCODE_CACHE pattern.
    result = exa.deep_research(instructions, schema=schema, timeout_seconds=900)
    with _research_cache_lock:
        _evict_research_if_needed()
        _research_cache[key] = (now, result)
        _log_research_pressure()
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


def _make_search_fn(mode: str, budget: _Budget, research_seeds: list[dict] | None = None):
    """Backend-agnostic _tavily_search replacement routed to Exa."""
    call_count = [0]

    def fn(
        query: str,
        max_results: int,
        queries_used: list[int],
        max_queries: int,
        errors: list[dict],
        debug: bool = False,
    ) -> list[dict]:
        if queries_used[0] >= max_queries:
            return []
        queries_used[0] += 1
        call_count[0] += 1
        try:
            if mode == "research_plus" and call_count[0] == 1 and research_seeds is not None:
                return research_seeds[:max_results]
            budget.charge_search(mode if mode != "research_plus" else "auto")
            effective_mode = "auto" if mode == "research_plus" else mode
            return exa.search(query, max_results=max_results, mode=effective_mode)
        except Exception as exc:
            errors.append({"provider": "exa", "error": str(exc), "query": query[:120]})
            return []

    return fn


def _patch_search(fn):
    audit_reports_mod._tavily_search = fn
    inventory_mod._tavily_search = fn
    inventory_domain_mod._tavily_search = fn


def _restore_search(original):
    audit_reports_mod._tavily_search = original
    inventory_mod._tavily_search = original
    inventory_domain_mod._tavily_search = original


def _patch_classify_with_seeds(research_seeds: list[dict]):
    """Bypass stage 1b classifier for Deep Research seeds."""
    original = audit_reports_mod.classify_search_results

    def wrapped(results, company, debug=False):
        classified = original(results, company, debug=debug)
        seen = {c.get("url", "").strip() for c in classified}
        for cit in research_seeds:
            url = cit.get("url", "").strip()
            if url and url not in seen:
                classified.append(
                    {
                        "url": url,
                        "title": cit.get("title"),
                        "auditor": None,
                        "date": None,
                        "type": None,
                        "confidence": 1.0,
                    }
                )
                seen.add(url)
        return classified

    audit_reports_mod.classify_search_results = wrapped
    return original


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
        f"List core production contracts with their names and 0x-prefixed on-chain addresses "
        f"and the chain each is deployed on."
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
                    "chain": {"type": "string"},
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
                "chains": contract.get("chains") or contract.get("chain") or [],
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
        record_degraded(phase="dependency_classifier", exc=exc, context={"protocol": protocol})
        logger.warning("dependency classifier failed for %s: %s", protocol, exc)
        return False

    parsed = _parse_json_object(response)
    if not parsed:
        logger.warning("dependency classifier returned unparseable response for %s", protocol)
        return False

    try:
        confidence = float(parsed.get("confidence") or 0)
    except (TypeError, ValueError):
        confidence = 0.0

    decision = parsed.get("should_run_dependency_pass")
    if isinstance(decision, str):
        should_run = decision.strip().lower() in {"true", "yes", "1"}
    else:
        should_run = bool(decision)
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
        record_degraded(phase="dependency_pass_1", exc=exc, context={"protocol": protocol})
        logger.warning("dep pass 1 failed for %s: %s", protocol, exc)
        return []
    components = r1.get("data", {}).get("components", []) or []

    dep_audits: list[dict] = []
    for c in components[:5]:  # cap at 5 components for cost control
        inst = f"Find smart contract security audit reports for {c.get('name')} by {c.get('author')}."
        try:
            budget.charge_research()
        except RuntimeError:
            break
        try:
            r2 = _cached_deep_research(inst, schema=_AUDIT_SCHEMA)
        except Exception as exc:
            record_degraded(
                phase="dependency_pass_2",
                exc=exc,
                context={"component": c.get("name"), "author": c.get("author")},
            )
            logger.warning("dep pass 2 failed for %s/%s: %s", c.get("name"), c.get("author"), exc)
            continue
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


def run_discovery(
    protocol: str,
    *,
    official_domain: str | None = None,
    chain: str | None = None,
    declared_chains: list[str] | None = None,
) -> dict[str, Any]:
    """Premium+Deps discovery for one protocol.

    Returns ``{audits: <search_audit_reports shape>, addresses: <search_protocol_inventory shape>,
    meta: {...}}`` so existing workers can slot it in with minimal plumbing changes.
    """
    budget = _Budget()
    started_at = time.monotonic()

    # ---- Audits ----
    original_search = inventory_domain_mod._tavily_search
    original_classify = audit_reports_mod.classify_search_results

    with log_timed_phase(logger, "discovery_audits") as ph_audit:
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
            record_degraded(phase="deep_research_audit_seeds", exc=exc, context={"protocol": protocol})
            logger.warning("deep research (audit seeds) failed for %s: %s", protocol, exc)

        # 1b. Full pipeline: exa/deep-lite search + research_plus classifier bypass
        _patch_search(_make_search_fn("deep-lite", budget, research_seeds=audit_seeds))
        _patch_classify_with_seeds(audit_seeds)
        try:
            audit_result = audit_reports_mod.search_audit_reports(
                protocol,
                official_domain=official_domain,
                max_queries=4,
                debug=False,
            )
        finally:
            _restore_search(original_search)
            audit_reports_mod.classify_search_results = original_classify
        _merge_ai_audit_metadata(audit_result, audit_seed_metadata)
        ph_audit["audit_seeds"] = len(audit_seeds)
        ph_audit["reports"] = len(audit_result.get("reports", []))

    # ---- Addresses ----
    with log_timed_phase(logger, "discovery_addresses") as ph_addr:
        _patch_search(_make_search_fn("auto", budget))  # exa/regular
        try:
            inventory_result = inventory_mod.search_protocol_inventory(
                protocol,
                chain=chain,
                limit=500,
                max_queries=4,
                run_deployer=True,
                debug=False,
                declared_chains=declared_chains,
            )
        finally:
            _restore_search(original_search)

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
                        "chains": [chain_key] if (chain_key := canonical_chain(item.get("chain"))) else [],
                        "confidence": 1.0,
                        "source": ["exa_deep_research"],
                        "evidence": {"deep_research": 1},
                    }
                )
        except Exception as exc:
            record_degraded(phase="deep_research_addresses", exc=exc, context={"protocol": protocol})
            logger.warning("deep research (addresses) failed for %s: %s", protocol, exc)
        ph_addr["contracts"] = len(inventory_result.get("contracts", []))

    try:
        inventory_result["contracts"] = validate_claimed_chains(
            inventory_result.get("contracts", []),
            source_names=("exa_deep_research",),
            debug=False,
        )
    except Exception as exc:
        record_degraded(phase="claimed_chain_check", exc=exc, context={"protocol": protocol})
        logger.warning("claimed-chain sanity check failed for %s: %s", protocol, exc)

    # ---- Dependency two-pass (conditional) ----
    dependency_pass_triggered = _needs_dependency_pass(
        protocol,
        inventory_result.get("contracts", []),
        audit_result.get("reports", []),
    )
    if dependency_pass_triggered:
        logger.info("dependency classifier selected %s for two-pass", protocol)
        with log_timed_phase(logger, "discovery_dependency_pass") as ph_dep:
            dep_audits = _dependency_research(protocol, budget)
            for dep_audit in dep_audits:
                audit_result.setdefault("reports", []).append(dep_audit)
            ph_dep["dependency_audits"] = len(dep_audits)
    else:
        logger.info("dependency classifier skipped two-pass for %s", protocol)

    # ---- SPA override (gmx, etc.) ----
    _apply_spa_overrides(protocol, inventory_result, audit_result)
    enrich_audit_reports(audit_result, protocol, debug=False)

    elapsed_ms = int((time.monotonic() - started_at) * 1000)

    # Fold the per-protocol budget counters into the stage_timing artifact so
    # the monitor UI can attribute discovery cost/call-volume per job (a no-op
    # outside a worker job context, e.g. standalone runs / tests).
    record_stage_metric("search_calls", budget.search_calls)
    record_stage_metric("research_calls", budget.research_calls)
    record_stage_metric("estimated_cost_usd", round(budget.estimated_cost_usd, 3))
    record_stage_metric("dependency_pass_triggered", dependency_pass_triggered)

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
    """Clear the deep_research cache + its pressure state (for tests)."""
    from utils.memory import reset_cache_pressure_state

    with _research_cache_lock:
        _research_cache.clear()
    reset_cache_pressure_state("research")
