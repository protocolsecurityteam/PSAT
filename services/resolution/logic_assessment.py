"""Assess saved formulas with deterministic access analysis and required Jev judgments.

This orchestrator does not enumerate. Model availability, uncertainty and source coverage
remain distinct from the access relation. Only assessed recommendations enter its plan.
"""

from __future__ import annotations

from collections import Counter

from services.clients.jev import DEFAULT_MODEL, JevClient
from services.logic.expansion import formula_hash
from services.logic.model import decode_formula
from services.resolution.logic_impact import JudgmentCache, enrich_impact
from services.resolution.logic_selection import ReportLimits, selection_report

LEVELS = ("none", "low", "medium", "high")


def assess_formulas(
    artifact: dict,
    *,
    cache: JudgmentCache,
    client: JevClient | None = None,
    model: str = DEFAULT_MODEL,
    reads=None,
    contracts=None,
    limits: ReportLimits = ReportLimits(),
) -> dict:
    """Cache-only calls are allowed, but missing judgments never count as assessed."""
    selected = selection_report(artifact, reads=reads, contracts=contracts, limits=limits)
    report = enrich_impact(artifact, selected, model=model, cache=cache, client=client)
    functions = {}
    requests = {}
    for name, encoded in artifact["functions"].items():
        formula = decode_formula(encoded)
        rows = [row for row in report["rows"] if row["function"] == name]
        effects = [row for row in rows if row["effect_index"] is not None]
        levels = [row["impact"]["level"] for row in rows]
        unassessed = [row["effect_index"] for row in effects if row["impact"].get("model_status") != "rated"]
        function_pending = not effects and any(row["impact"].get("model_status") != "rated" for row in rows)
        missing = sorted(set(range(len(formula.effects))) - {row["effect_index"] for row in effects})
        unresolved = bool(unassessed or missing or function_pending or not rows or "unknown" in levels)
        known = [LEVELS.index(level) for level in levels if level in LEVELS]
        # A known high effect establishes high potential impact even if others are unresolved.
        # Otherwise unknown effects could exceed the largest estimate already available.
        severity = "high" if 3 in known else "unknown" if unresolved else LEVELS[max(known)]
        for row in effects:
            if row["decision"] == "expand" and (
                row["impact"].get("model_status") != "rated" or row["impact"]["level"] not in ("medium", "high")
            ):
                row["decision"] = "review"
                row["reason"] = "assessment does not establish material impact; review before enumeration"
            if row["decision"] == "expand":
                requests.setdefault(name, []).append(row["effect_index"])
        source_complete = artifact.get("contexts", {}).get(name, {}).get("source_complete", False)
        functions[name] = {
            "formula_hash": formula_hash(formula),
            "severity": severity,
            "basis": "model estimate: maximum effect impact, or whole-function judgment when no effects are reported",
            "judgments_complete": not unassessed and not missing and not function_pending and bool(rows),
            "needs_review": unresolved or not source_complete or any(row["decision"] == "review" for row in rows),
            "unassessed_effects": sorted(set(unassessed + missing)),
            "whole_function_judgment_pending": function_pending,
            "source_complete": source_complete,
        }
    report["suggested_expansions"] = [
        {
            "function": name,
            "formula_hash": functions[name]["formula_hash"],
            "callers": False,
            "effect_indices": sorted(indices),
        }
        for name, indices in sorted(requests.items())
    ]
    complete = bool(functions) and all(value["judgments_complete"] for value in functions.values())
    report["assessment"] = {
        "schema": 1,
        "judgments_complete": complete,
        "status": "assessed" if complete else "incomplete",
        "functions": functions,
        "scope": "potential function impact from its assessed effects and captured associated source",
        "automatic_execution": False,
    }
    report["summary"] = dict(Counter(row["decision"] for row in report["rows"]))
    return report
