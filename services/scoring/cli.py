"""Offline driver: distil every contract in memory, fold, and diff.

Never writes signal rows (except ``dirty``, which queues a re-fold), so the differential oracle runs against a read-only
database.

    python -m services.scoring.cli score --protocol 1 [--out FILE]
    python -m services.scoring.cli differential --protocol 1 \
        --against scoring_prototype/score_v3.json [--out FILE]
    python -m services.scoring.cli dirty --protocol 1
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any

from sqlalchemy.orm import Session

from services.scoring.distill import distill_contract_signals
from services.scoring.fold import compute_protocol_score
from services.scoring.population import order_signals
from services.scoring.schema import FunctionSignal, ScoreDocument
from utils.logging import configure_logging

logger = logging.getLogger(__name__)


def distill_protocol_in_memory(session: Session, protocol_id: int) -> list[FunctionSignal]:
    from db.models import Contract

    contracts = session.query(Contract).filter(Contract.protocol_id == protocol_id).order_by(Contract.id).all()
    signals: list[FunctionSignal] = []
    for contract in contracts:
        signals.extend(distill_contract_signals(session, contract, job_id=contract.job_id))
    return order_signals(signals)


def score(session: Session, protocol_id: int) -> ScoreDocument:
    # Lazy so library use of the differential helpers doesn't import monitoring and the job queue.
    from services.scoring.loop import document_summary

    signals = distill_protocol_in_memory(session, protocol_id)
    document = compute_protocol_score(session, protocol_id, signals=signals)
    # Same summary line as the score loop, so CLI and persisted folds are comparable.
    logger.info("score document summary", extra=document_summary(document))
    return document


def document_json(document: ScoreDocument) -> dict[str, Any]:
    payload = document.document()
    payload["protocol_id"] = document.protocol_id
    payload["computed_at"] = document.computed_at.isoformat()
    payload["trigger"] = document.trigger
    payload["provenance"] = document.provenance
    return payload


def _keys_for(row: dict[str, Any], unit_field: str) -> set[str]:
    """Every address that could identify this row's unit, lowercased.

    Merged Safe units are named by an arbitrary member, and the scorer and prototype pick different ones.
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


def _identity_key(row: dict[str, Any]) -> tuple[str, str, str]:
    """The ``(principal_unit, capability, access_path)`` triple, unique per document.

    Rows sharing it are never sent to the address-set recovery match.
    """
    return (
        str(row.get("principal_unit") or "").lower(),
        str(row.get("capability")),
        str(row.get("access_path") or ""),
    )


def _oracle_subsumed_rows(oracle: dict[str, Any]) -> tuple[list[dict[str, Any]], str, int | None]:
    """The oracle's subsumed rows, which shape they came from, and what was left.

    Prototype documents carry them at top level; ``document_json`` puts them under ``provenance``. ``absent`` is
    distinct from empty. When both exist the top-level list wins, but the dropped count is published so lost rows don't
    masquerade as ``added``.
    """
    top = oracle.get("subsumed_rows")
    nested = (oracle.get("provenance") or {}).get("subsumed_rows")
    if top is not None:
        if nested:
            return list(top), "top_level_over_provenance", len(nested)
        return list(top), "top_level", None
    if nested is not None:
        return list(nested), "provenance", None
    return [], "absent", None


def _causes(previous: dict[str, Any], row: dict[str, Any]) -> list[str]:
    """What moved between two rows for the same (unit, capability, access path).

    Run for every matched pair, including re-keys and splits, so arithmetic changes aren't filed as relabels.
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

    Not byte-equality: every delta must be attributable to a named divergence. Rows match on ``(principal_unit,
    capability, access_path)``; the address-set match is only a recovery for differently-named units. A document diffed
    against itself reports nothing.
    """
    new_rows = list(document.findings) + list(document.provenance.get("subsumed_rows", []))
    oracle_subsumed, subsumed_source, subsumed_ignored = _oracle_subsumed_rows(oracle)
    old_rows = list(oracle.get("findings", [])) + oracle_subsumed

    new_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    new_by_identity: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in new_rows:
        for key in _keys_for(row, "principal_unit"):
            new_by_key.setdefault((key, str(row.get("capability"))), []).append(row)
        new_by_identity.setdefault(_identity_key(row), []).append(row)

    matched_new: set[int] = set()
    changed, removed, split = [], [], []

    # Identity matching first, so a row present in both can't be taken as another row's fuzzy candidate.
    identical: dict[int, dict[str, Any]] = {}
    identity_claimed: set[int] = set()
    for previous in old_rows:
        for row in new_by_identity.get(_identity_key(previous), []):
            if id(row) not in matched_new:
                matched_new.add(id(row))
                identity_claimed.add(id(row))
                identical[id(previous)] = row
                break

    for previous in old_rows:
        capability = str(previous.get("capability"))
        prev_identity = _identity_key(previous)
        twin = identical.get(id(previous))
        if twin is not None:
            causes = _causes(previous, twin)
            if causes:
                changed.append(
                    {
                        "principal": twin.get("principal"),
                        "principal_unit": twin.get("principal_unit"),
                        "capability": capability,
                        "access_path": twin.get("access_path"),
                        "raw_before": previous.get("raw_points"),
                        "raw_after": twin.get("raw_points"),
                        "caused_by": causes,
                        "witness_notes": twin.get("witness_notes"),
                        "matched_by": "row_identity",
                    }
                )
            continue
        candidates: list[dict[str, Any]] = []
        seen: set[int] = set()
        for key in _keys_for(previous, "principal_unit"):
            for row in new_by_key.get((key, capability), []):
                if id(row) in seen:
                    continue
                # A row claimed by identity is only offered to an old row with the same identity; otherwise a shared
                # unit address would hide a real disappearance.
                if id(row) in identity_claimed and _identity_key(row) != prev_identity:
                    continue
                seen.add(id(row))
                candidates.append(row)
        if not candidates:
            removed.append(
                {
                    "principal": previous.get("principal"),
                    "principal_unit": previous.get("principal_unit"),
                    "capability": capability,
                    "access_path": previous.get("access_path"),
                    "raw_before": previous.get("raw_points"),
                    "severity_basis": previous.get("severity_basis"),
                    "value_band": previous.get("value_band"),
                }
            )
            continue
        for row in candidates:
            matched_new.add(id(row))
        # Compare against the identity twin when present; max by raw_points would compare against a different row.
        identity_twin = next((r for r in candidates if _identity_key(r) == prev_identity), None)
        top = identity_twin or max(candidates, key=lambda r: r.get("raw_points") or 0.0)
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
                    # So a split that also moved weakness, severity or band isn't hidden by the split label.
                    "caused_by": causes,
                    "arithmetic_changed": bool(causes),
                    "cause_computed_against": {
                        "access_path": top.get("access_path"),
                        "principal": top.get("principal"),
                        "chosen_by": "row identity" if identity_twin is not None else "highest raw_points",
                    },
                }
            )
        elif causes:
            changed.append(
                {
                    "principal": top.get("principal"),
                    "principal_unit": top.get("principal_unit"),
                    "capability": capability,
                    "access_path": top.get("access_path"),
                    "raw_before": previous.get("raw_points"),
                    "raw_after": top.get("raw_points"),
                    "caused_by": causes,
                    "witness_notes": top.get("witness_notes"),
                    "matched_by": "row_identity" if identity_twin is not None else "unit_address_set",
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
        "oracle_subsumed_rows_source": subsumed_source,
        "oracle_subsumed_rows_ignored_under_provenance": subsumed_ignored,
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
    # First, before any session import, so degraded-read logs go somewhere. stdout is the document; diagnostics go to
    # stderr as JSON.
    configure_logging()
    parser = argparse.ArgumentParser(prog="services.scoring.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    score_parser = sub.add_parser("score", help="distil in memory and fold")
    score_parser.add_argument("--protocol", type=int, required=True)
    score_parser.add_argument("--out")

    diff_parser = sub.add_parser("differential", help="diff the fold against a prototype document")
    diff_parser.add_argument("--protocol", type=int, required=True)
    diff_parser.add_argument("--against", required=True)
    diff_parser.add_argument("--out")

    dirty_parser = sub.add_parser("dirty", help="queue the protocol for a persisted re-fold")
    dirty_parser.add_argument("--protocol", type=int, required=True)

    args = parser.parse_args(argv)

    from db.models import SessionLocal

    if args.command == "dirty":
        from services.scoring.dirty import SCORE_DIRTY_MANUAL, mark_protocol_score_dirty

        with SessionLocal() as session:
            written = mark_protocol_score_dirty(session, args.protocol, SCORE_DIRTY_MANUAL)
            session.commit()
        print(f"protocol {args.protocol} dirty mark {'written' if written else 'NOT written (see log)'}")
        return 0 if written else 1

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
