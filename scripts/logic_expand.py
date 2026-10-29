"""Expand selected rows from a saved formula artifact in a separate process.

python -m scripts.logic_expand formulas.json --function 'setOwner(address)' --rpc-url URL --output addresses.json
Use --effect 'setOwner(address):0' to request only a particular effect's callers.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path

from services.logic.expansion import Selection
from services.logic.model import Limits


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--function", action="append", default=[], help="expand callers of this exact signature")
    parser.add_argument("--effect", action="append", default=[], help="expand only SIGNATURE:ZERO_BASED_INDEX")
    parser.add_argument(
        "--selection-report", type=Path, help="explicitly execute the recommendations in a reviewed report"
    )
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--members", type=int, default=Limits().members)
    parser.add_argument("--solver-ms", type=int, default=Limits().solver_ms)
    args = parser.parse_args(argv)
    if args.selection_report and (args.function or args.effect):
        parser.error("use a selection report or explicit functions/effects, not both")
    if not (args.function or args.effect or args.selection_report):
        parser.error("select --function or --effect; expansion is never automatic")
    if args.members < 0 or args.solver_ms < 0:
        parser.error("budgets cannot be negative")
    if args.output.resolve() == args.artifact.resolve() or (
        args.selection_report and args.output.resolve() == args.selection_report.resolve()
    ):
        parser.error("expansion output must not overwrite the formula artifact")
    selections = {signature: Selection() for signature in args.function}
    for entry in args.effect:
        try:
            signature, number = entry.rsplit(":", 1)
            index = int(number)
            if index < 0:
                raise ValueError()
        except ValueError:
            parser.error("--effect must be SIGNATURE:ZERO_BASED_INDEX")
        selection = selections.get(signature, Selection(callers=False))
        selections[signature] = replace(selection, effect_indices=tuple(sorted({*selection.effect_indices, index})))

    artifact = json.loads(args.artifact.read_text())
    if args.selection_report:
        from services.resolution.logic_selection import selections_from_report

        selections = selections_from_report(artifact, json.loads(args.selection_report.read_text()))

    from db.models import SessionLocal
    from services.logic.deployment import deployment_expansions

    with SessionLocal() as session:
        expanded = deployment_expansions(
            session, artifact, args.rpc_url, selections, limits=Limits(members=args.members, solver_ms=args.solver_ms)
        )
    args.output.write_text(json.dumps(expanded, indent=2) + "\n")


if __name__ == "__main__":
    main()
