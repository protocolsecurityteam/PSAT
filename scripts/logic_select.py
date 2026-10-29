"""Create an inspectable selection report; never execute expansion or call Jev.

python -m scripts.logic_select formulas.json --output selection.json
Add --rpc-url URL to allow bounded direct reads at the saved block.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from services.resolution.logic_selection import ReportLimits, artifact_identity, selection_report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rpc-url", help="optional: permit bounded reads at the artifact's block")
    parser.add_argument("--direct-reads", type=int, default=ReportLimits().direct_reads)
    parser.add_argument("--solver-ms", type=int, default=ReportLimits().solver_ms)
    parser.add_argument("--solver-queries", type=int, default=ReportLimits().solver_queries)
    args = parser.parse_args(argv)
    if args.output.resolve() == args.artifact.resolve():
        parser.error("selection output must not overwrite formulas")
    if min(args.direct_reads, args.solver_ms, args.solver_queries) < 0:
        parser.error("budgets cannot be negative")
    artifact = json.loads(args.artifact.read_text())
    artifact_identity(artifact)
    limits = ReportLimits(direct_reads=args.direct_reads, solver_ms=args.solver_ms, solver_queries=args.solver_queries)
    if args.rpc_url:
        from db.models import SessionLocal
        from services.logic.deployment import _deployment_inputs

        with (
            SessionLocal() as session,
            _deployment_inputs(session, artifact["chain_id"], args.rpc_url, artifact["block"]) as (reads, contracts),
        ):
            result = selection_report(artifact, reads=reads, contracts=contracts, limits=limits)
    else:
        result = selection_report(artifact, limits=limits)
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
