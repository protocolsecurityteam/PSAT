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


def _index(rows: list[dict[str, Any]], key: str) -> dict[tuple[str, str], dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        unit = str(row.get(key) or "").lower()
        # The prototype's units are bare addresses; ours are chain-scoped. Diff
        # on the address so a chain-scoping change does not read as a protocol
        # that lost every finding.
        address = unit.split("::", 1)[-1]
        out[(address, str(row.get("capability")))] = row
    return out


def _principal_index(rows: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    """Secondary index on the GATING principal, not the unit it was folded into.

    A merged Safe unit is named by an arbitrary member, so two scorers can fold
    the same set of Safes into the same unit and still label it differently. Diffing
    on the unit alone would report every such row as one disappearance plus one
    appearance, hiding whichever rows really did change.
    """
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        principal = str(row.get("principal") or "")
        address = principal.split("0x")[-1]
        if address:
            out[("0x" + address.lower(), str(row.get("capability")))] = row
    return out


def _causes(previous: dict[str, Any], row: dict[str, Any]) -> list[str]:
    """What moved between two rows for the same (principal, capability).

    Analysed for EVERY matched pair, including rows matched only after a unit
    re-key: a re-key that also changed the arithmetic would otherwise be filed as
    a cosmetic relabel and its delta would never be explained.
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
    new_index = _index(new_rows, "principal_unit")
    old_index = _index(old_rows, "principal_unit")
    new_by_principal = _principal_index(new_rows)
    old_by_principal = _principal_index(old_rows)

    added, changed, removed, rekeyed = [], [], [], []
    for key in sorted(new_index):
        row = new_index[key]
        if key not in old_index:
            principal_key = next((k for k, v in sorted(new_by_principal.items()) if v is row), None)
            counterpart = old_by_principal.get(principal_key) if principal_key else None
            if counterpart is not None:
                causes = _causes(counterpart, row)
                rekeyed.append(
                    {
                        "principal": row.get("principal"),
                        "capability": row.get("capability"),
                        "unit_before": counterpart.get("principal_unit"),
                        "unit_after": row.get("principal_unit"),
                        "raw_before": counterpart.get("raw_points"),
                        "raw_after": row.get("raw_points"),
                        "cause": "unit id relabelled (lowest member key, not the union-find root)",
                        "caused_by": causes,
                        "arithmetic_changed": bool(causes),
                    }
                )
                continue
            added.append(
                {
                    "principal": row.get("principal"),
                    "capability": row.get("capability"),
                    "raw_points": row.get("raw_points"),
                    "severity_basis": row.get("severity_basis"),
                    "value_basis": row.get("value_at_stake_basis"),
                    "witness_notes": row.get("witness_notes"),
                }
            )
            continue
        previous = old_index[key]
        causes = _causes(previous, row)
        if causes:
            changed.append(
                {
                    "principal": row.get("principal"),
                    "capability": row.get("capability"),
                    "raw_before": previous.get("raw_points"),
                    "raw_after": row.get("raw_points"),
                    "caused_by": causes,
                    "witness_notes": row.get("witness_notes"),
                }
            )
    rekeyed_units = {(r["capability"], str(r["unit_before"]).split("::", 1)[-1].lower()) for r in rekeyed}
    for key in sorted(old_index):
        if key in new_index:
            continue
        previous = old_index[key]
        if (str(previous.get("capability")), key[0]) in rekeyed_units:
            continue
        removed.append(
            {
                "principal": previous.get("principal"),
                "capability": previous.get("capability"),
                "raw_before": previous.get("raw_points"),
                "severity_basis": previous.get("severity_basis"),
                "value_band": previous.get("value_band"),
            }
        )
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
            "rekeyed": len(rekeyed),
            "rekeyed_with_arithmetic_change": sum(1 for r in rekeyed if r["arithmetic_changed"]),
        },
        "added": added,
        "changed": changed,
        "removed": removed,
        "rekeyed": rekeyed,
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
