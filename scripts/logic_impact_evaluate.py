"""Compare saved impact estimates with independently supplied labels; makes no API requests.

python -m scripts.logic_impact_evaluate impact.json expected.json --output evaluation.json
Unknown estimates count as abstentions, never as correct predictions or safe deferrals.
"""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path

LEVELS = {"none": 0, "low": 1, "medium": 2, "high": 3}


def legacy_pilot_summary(paths: list[Path]) -> dict:
    """Historical outputs have no independent severity labels; do not report accuracy."""
    rows = [json.loads(line) for path in paths for line in path.read_text().splitlines() if line.strip()]
    confidence = [
        r["jev"]["answers"]["severity"]["confidence"] for r in rows if "severity" in r.get("jev", {}).get("answers", {})
    ]
    return {
        "records": len(rows),
        "unique_functions": len({(r["address"], r["function"]) for r in rows}),
        "models": sorted({r["jev"]["model"] for r in rows if "model" in r.get("jev", {})}),
        "median_severity_confidence": statistics.median(confidence) if confidence else None,
        "at_source_character_cap": sum(r.get("source_chars") == 24_000 for r in rows),
        "accuracy": None,
        "note": "No independent severity labels; different rubric, context and model. "
        "These outputs cannot establish accuracy or an improvement percentage.",
    }


def evaluate(report: dict, expected: list[dict]) -> dict:
    ratings = report["assessment"]["functions"]
    cases, correct, abstained, missed_high, abstained_high = [], 0, 0, 0, 0
    seen = set()
    for label in expected:
        if not all(k in label for k in ("function", "effect_index", "formula_hash")):
            raise ValueError("expected labels require function, effect_index and formula_hash")
        index = label["effect_index"]
        if type(index) is not int or index < 0:
            raise ValueError("invalid expected effect index")
        key = label["function"], index
        if key in seen:
            raise ValueError("duplicate expected case")
        seen.add(key)
        if not 0 <= label["expected_min"] <= label["expected_max"] <= 3:
            raise ValueError("invalid expected impact range")
        group = ratings.get(label["function"], {})
        if not label["formula_hash"] or label["formula_hash"] != group.get("formula_hash"):
            raise ValueError("expected case formula hash does not match report")
        row = group.get("effects", {}).get(str(index))
        if row is None:
            raise ValueError("expected case missing from report")
        level = row["level"]
        value = LEVELS.get(level)
        passed = value is not None and label["expected_min"] <= value <= label["expected_max"]
        correct += int(passed)
        abstained += int(value is None)
        missed_high += int(label["expected_min"] >= 2 and value is not None and value < label["expected_min"])
        abstained_high += int(label["expected_min"] >= 2 and value is None)
        cases.append(
            {
                **label,
                "estimated_level": level,
                "matched": passed,
                "abstained": value is None,
                "raw_ranking_signal": row.get("estimate", {}).get("ranking_signal"),
                "uncertainty": row.get("estimate", {}).get("uncertainty", []),
                "model_status": row.get("model_status"),
            }
        )
    return {
        "cases": cases,
        "total": len(cases),
        "matched": correct,
        "abstained": abstained,
        "incorrect": len(cases) - correct - abstained,
        "high_impact_underestimates": missed_high,
        "high_impact_abstentions": abstained_high,
        "note": "Development labels, not proof of general accuracy or a calibration guarantee.",
        "assessment": report.get("assessment"),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("expected", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--legacy-pilot", type=Path, action="append", default=[])
    args = parser.parse_args(argv)
    if args.output.resolve() in (args.report.resolve(), args.expected.resolve()):
        parser.error("evaluation must not overwrite either input")
    result = evaluate(json.loads(args.report.read_text()), json.loads(args.expected.read_text()))
    if args.legacy_pilot:
        result["legacy_pilot"] = legacy_pilot_summary(args.legacy_pilot)
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
