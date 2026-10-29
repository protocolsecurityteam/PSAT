"""Join access evidence and whole-function impact ratings; select expansion once."""

from __future__ import annotations

from collections import Counter

from services.clients.jev import DEFAULT_MODEL, JevClient
from services.logic.source_context import artifact_hash
from services.resolution.logic_impact import JudgmentCache, rate_functions
from services.resolution.logic_selection import ReportLimits, selection_report


def _decision(row: dict, impact: dict) -> tuple[str, str]:
    access = row["access"]
    if row["effect_index"] is None:
        return "review", "no reported effects; not a harmlessness proof"
    if access["activity"] == "inactive_at_block":
        return "review", "blocked now; inspect enabling conditions"
    if access["status"] == "unrestricted":
        return "report_unrestricted", "keep visible; universal callers need no list"
    if any(d != "caller" for d in access["identity_dimensions"]):
        return "review", "origin or signing authority must not be projected away"
    supported = (access["status"] == "restricted" and not access["issues"]) or (
        access["status"] == "unresolved"
        and access["issues"]
        and all(issue["kind"] == "state_required" for issue in access["issues"])
    )
    if supported and impact["model_status"] == "rated" and impact["level"] in ("medium", "high"):
        return "expand", "material function impact; enumerate this effect's supported caller relation"
    return "review", "access or material function impact unresolved; no automatic deferral"


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
    report = selection_report(artifact, reads=reads, contracts=contracts, limits=limits)
    ratings = rate_functions(artifact, cache=cache, client=client, model=model)
    requests = {}
    for row in report["rows"]:
        row["decision"], row["reason"] = _decision(row, ratings["functions"][row["function"]])
        if row["decision"] == "expand":
            request = requests.setdefault(
                row["function"],
                {
                    "function": row["function"],
                    "formula_hash": row["formula_hash"],
                    "callers": False,
                    "effect_indices": [],
                },
            )
            request["effect_indices"].append(row["effect_index"])
    verified = artifact.get("status") != "not_verified"
    complete = verified and all(r["model_status"] == "rated" for r in ratings["functions"].values())
    status = (
        "not_verified"
        if not verified
        else "nothing_to_assess"
        if not artifact["functions"]
        else "assessed"
        if complete
        else "incomplete"
    )
    report.update(
        kind="expansion_selection",
        artifact_hash=artifact_hash(artifact),
        suggested_expansions=[requests[k] for k in sorted(requests)],
        summary=dict(Counter(r["decision"] for r in report["rows"])),
        assessment={"schema": 2, "status": status, "judgments_complete": complete, **ratings},
    )
    return report
