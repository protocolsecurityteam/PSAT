"""Offline driver: distil every contract in memory, fold, and diff.

Two feeding modes share one distillation and one fold (strategy §7.5). This CLI
is the second: it never writes a signal row, so the differential oracle runs
against a database it only reads. The persisted pipeline path uses the identical
code with the signals written to ``function_score_signals`` in between.

    python -m services.scoring.cli score --protocol 1 [--out FILE]
    python -m services.scoring.cli differential --protocol 1 \
        --against scoring_prototype/score_v3.json [--out FILE]
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from sqlalchemy.orm import Session

from services.scoring.distill import distill_contract_signals
from services.scoring.fold import compute_protocol_score
from services.scoring.population import order_signals
from services.scoring.schema import FunctionSignal, ScoreDocument


def distill_protocol_in_memory(session: Session, protocol_id: int) -> list[FunctionSignal]:
    """Every contract's signals, distilled without persistence, in fold order."""
    from db.models import Contract

    contracts = session.query(Contract).filter(Contract.protocol_id == protocol_id).order_by(Contract.id).all()
    signals: list[FunctionSignal] = []
    for contract in contracts:
        signals.extend(distill_contract_signals(session, contract, job_id=contract.job_id))
    return order_signals(signals)


def score(session: Session, protocol_id: int) -> ScoreDocument:
    signals = distill_protocol_in_memory(session, protocol_id)
    return compute_protocol_score(session, protocol_id, signals=signals)


def document_json(document: ScoreDocument) -> dict[str, Any]:
    payload = document.document()
    payload["protocol_id"] = document.protocol_id
    payload["computed_at"] = document.computed_at.isoformat()
    payload["trigger"] = document.trigger
    payload["provenance"] = document.provenance
    return payload


# ---------------------------------------------------------------- differential


def _keys_for(row: dict[str, Any], unit_field: str) -> set[str]:
    """Every address that could identify this row's unit, lowercased.

    A merged Safe unit is named by an arbitrary member, and this scorer and the
    prototype pick different ones, so matching on the published unit id alone
    reports one disappearance plus one appearance for a row that never moved.
    The member set and the gating principal are the identifiers that survive a
    re-key.
    """
    keys: set[str] = set()
    unit = str(row.get(unit_field) or "").lower()
    if unit:
        keys.add(unit.split("::", 1)[-1])
    for member in row.get("unit_members") or []:
        keys.add(str(member).lower().split("::", 1)[-1])
    for address in row.get("principal_addresses") or []:
        keys.add(str(address).lower())
    principal = str(row.get("principal") or "")
    if "0x" in principal:
        keys.add("0x" + principal.split("0x")[-1].lower())
    return {k for k in keys if k}


def _causes(previous: dict[str, Any], row: dict[str, Any]) -> list[str]:
    """What moved between two rows for the same (unit, capability).

    Analysed for EVERY matched pair, including rows matched only after a unit
    re-key or an access-path split: a re-key that also changed the arithmetic
    would otherwise be filed as a cosmetic relabel and its delta never explained.
    """
    causes: list[str] = []
    if abs((row.get("raw_points") or 0) - (previous.get("raw_points") or 0)) > 1e-9:
        if abs((row.get("weakness") or 0) - (previous.get("weakness") or 0)) > 1e-9:
            causes.append(f"weakness {previous.get('weakness')} -> {row.get('weakness')}")
        if abs((row.get("severity_proven") or 0) - (previous.get("severity_proven") or 0)) > 1e-9:
            causes.append(
                f"severity {previous.get('severity_proven')} -> {row.get('severity_proven')} "
                f"({';'.join(row.get('severity_basis') or [])})"
            )
        if row.get("value_band") != previous.get("value_band"):
            causes.append(
                f"value_band {previous.get('value_band')} -> {row.get('value_band')} "
                f"({row.get('value_at_stake_basis')})"
            )
        if not causes:
            causes.append(f"raw_points {previous.get('raw_points')} -> {row.get('raw_points')}")
    return causes


def differential(document: ScoreDocument, oracle: dict[str, Any]) -> dict[str, Any]:
    """Row-level diff against the prototype oracle, each delta with its cause.

    Not byte-equality by design: this scorer consumes planes the prototype
    predates and removes its defects, so every delta must be attributable to a
    named divergence rather than explained away by a version bump.
    """
    new_rows = list(document.findings) + list(document.provenance.get("subsumed_rows", []))
    old_rows = list(oracle.get("findings", [])) + list(oracle.get("subsumed_rows", []))

    new_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in new_rows:
        for key in _keys_for(row, "principal_unit"):
            new_by_key.setdefault((key, str(row.get("capability"))), []).append(row)

    matched_new: set[int] = set()
    changed, removed, split = [], [], []
    for previous in old_rows:
        capability = str(previous.get("capability"))
        candidates: list[dict[str, Any]] = []
        for key in _keys_for(previous, "principal_unit"):
            for row in new_by_key.get((key, capability), []):
                if id(row) not in {id(c) for c in candidates}:
                    candidates.append(row)
        if not candidates:
            removed.append(
                {
                    "principal": previous.get("principal"),
                    "capability": capability,
                    "raw_before": previous.get("raw_points"),
                    "severity_basis": previous.get("severity_basis"),
                    "value_band": previous.get("value_band"),
                }
            )
            continue
        for row in candidates:
            matched_new.add(id(row))
        top = max(candidates, key=lambda r: r.get("raw_points") or 0.0)
        causes = _causes(previous, top)
        if len(candidates) > 1:
            split.append(
                {
                    "principal": previous.get("principal"),
                    "capability": capability,
                    "raw_before": previous.get("raw_points"),
                    "rows_after": [
                        {
                            "access_path": r.get("access_path"),
                            "principal": r.get("principal"),
                            "weakness": r.get("weakness"),
                            "raw_points": r.get("raw_points"),
                            "value_band": r.get("value_band"),
                        }
                        for r in sorted(candidates, key=lambda r: -(r.get("raw_points") or 0.0))
                    ],
                    "cause": "one row per ACCESS PATH: delayed value is charged at the delayed rung",
                    # Computed against the top row as well: a split that ALSO
                    # moved weakness, severity or the band must not hide behind
                    # the split label.
                    "caused_by": causes,
                    "arithmetic_changed": bool(causes),
                }
            )
        elif causes:
            changed.append(
                {
                    "principal": top.get("principal"),
                    "capability": capability,
                    "raw_before": previous.get("raw_points"),
                    "raw_after": top.get("raw_points"),
                    "caused_by": causes,
                    "witness_notes": top.get("witness_notes"),
                }
            )

    added = [
        {
            "principal": row.get("principal"),
            "capability": row.get("capability"),
            "access_path": row.get("access_path"),
            "raw_points": row.get("raw_points"),
            "severity_basis": row.get("severity_basis"),
            "value_basis": row.get("value_at_stake_basis"),
            "witness_notes": row.get("witness_notes"),
        }
        for row in new_rows
        if id(row) not in matched_new
    ]

    return {
        "grade_lambda": {"oracle": oracle.get("grade_lambda"), "scorer": document.grade_lambda},
        "grade_exposure": {"oracle": oracle.get("grade_exposure"), "scorer": document.grade_exposure},
        "confidence_pct": {"oracle": oracle.get("confidence_pct"), "scorer": document.confidence_pct},
        "counts": {
            "rows": {"oracle": len(old_rows), "scorer": len(new_rows)},
            "findings": {"oracle": len(oracle.get("findings", [])), "scorer": len(document.findings)},
            "earned_negatives": {
                "oracle": len(oracle.get("earned_negatives", [])),
                "scorer": len(document.earned_negatives),
            },
            "added": len(added),
            "changed": len(changed),
            "removed": len(removed),
            "split_by_access_path": len(split),
        },
        "added": added,
        "changed": changed,
        "removed": removed,
        "split_by_access_path": split,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="services.scoring.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    score_parser = sub.add_parser("score", help="distil in memory and fold")
    score_parser.add_argument("--protocol", type=int, required=True)
    score_parser.add_argument("--out")

    diff_parser = sub.add_parser("differential", help="diff the fold against a prototype document")
    diff_parser.add_argument("--protocol", type=int, required=True)
    diff_parser.add_argument("--against", required=True)
    diff_parser.add_argument("--out")

    args = parser.parse_args(argv)

    from db.models import SessionLocal

    with SessionLocal() as session:
        document = score(session, args.protocol)

    if args.command == "score":
        payload: dict[str, Any] = document_json(document)
    else:
        with open(args.against) as handle:
            oracle = json.load(handle)
        payload = differential(document, oracle)

    text = json.dumps(payload, indent=2, sort_keys=True, default=str)
    if args.out:
        with open(args.out, "w") as handle:
            handle.write(text)
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    sys.exit(main())
