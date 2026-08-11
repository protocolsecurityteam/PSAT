"""Offline driver: distil every contract in memory, fold, and diff.

Two feeding modes share one distillation and one fold (strategy §7.5). This CLI
is the second: it never writes a signal row, so the differential oracle runs
against a database it only reads. The persisted pipeline path uses the identical
code with the signals written to ``function_score_signals`` in between.

    python -m services.scoring.cli score --protocol 1 [--out FILE]
    python -m services.scoring.cli differential --protocol 1 \
        --against scoring_prototype/score_v3.json [--out FILE]
    python -m services.scoring.cli dirty --protocol 1

``dirty`` is the one persisting command: it queues the protocol so the score
loop's next pass re-folds and persists. ``score`` never consumes the mark.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from sqlalchemy.orm import Session

from services.scoring.distill import distill_contract_signals, load_protocol_universe
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
    # Built here and not in the fold: assembling it reads source artifacts out of
    # object storage, which the fold's planes may not do. ``None`` — an
    # unreadable artifact body — disposes nothing anywhere downstream.
    universe = load_protocol_universe(session, protocol_id)
    return compute_protocol_score(session, protocol_id, signals=signals, universe=universe)


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


def _identity_key(row: dict[str, Any]) -> tuple[str, str, str]:
    """The triple that names one row of one document.

    ``(principal_unit, capability, access_path)`` is unique across a document's
    findings and subsumed rows, so two rows carrying it are the same row and the
    address-set match below — which is a *recovery* for units this scorer and the
    prototype name differently — must never be asked about them.
    """
    return (
        str(row.get("principal_unit") or "").lower(),
        str(row.get("capability")),
        str(row.get("access_path") or ""),
    )


def _oracle_subsumed_rows(oracle: dict[str, Any]) -> tuple[list[dict[str, Any]], str, int | None]:
    """The oracle's subsumed rows, which shape they came from, and what was left.

    The prototype documents in ``scoring_prototype/`` carry them at top level;
    every document ``document_json`` writes carries them under ``provenance``.
    Reading one place only mis-reads the other silently — as a whole population
    of rows that are "added" because they were never looked for. ``absent`` is a
    third state: an oracle with no subsumed rows is a different fact from one
    this code failed to find them in, and the two must not spell the same.

    A document carrying BOTH is answered by the top-level list — it is the
    author's explicit statement about this document — but the population that
    lost is counted and published, because rows dropped in silence come back as
    ``added``, and the reader would have no way to tell that from a real one.
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

    Two rows are the same row when ``(principal_unit, capability, access_path)``
    matches; only where no such twin exists does the address-set match run, and
    it is a recovery for units the two documents name differently, not the
    identity test. A document diffed against itself therefore reports nothing —
    every delta published here is one the evidence moved.
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

    # Identity first, over ALL old rows, before any address-set match is tried:
    # a row that is present in both documents must not be consumed as some other
    # row's fuzzy candidate just because that row came first in the list.
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
                # A row the identity pass claimed belongs to the old row that IS
                # it. Offering it to a different old row as a recovery candidate
                # publishes that row as changed — or split — on the strength of a
                # shared unit address, and hides the disappearance of the row
                # that actually went away. It stays available only to an old row
                # carrying the same identity, which is the one case where two old
                # rows can both name it.
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
        # The causes belong to the row this one IS, when one of the candidates
        # carries its identity; ``max`` by raw_points otherwise compares against
        # a different row and reports movement neither row made.
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
                    # Computed against one named row as well: a split that ALSO
                    # moved weakness, severity or the band must not hide behind
                    # the split label.
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
