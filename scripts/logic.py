"""Three explicit jobs: generate deployed-code formulas, assess impact, enumerate selected addresses.

python -m scripts.logic generate ADDRESS --chain-id 1 --rpc-url URL --output formulas.json
python -m scripts.logic assess formulas.json --cache .jev-cache --output assessment.json
python -m scripts.logic enumerate formulas.json --assessment assessment.json --rpc-url URL --output addresses.json
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import replace
from functools import partial
from pathlib import Path

from services.clients.jev import DEFAULT_MODEL, JevClient
from services.logic.expansion import Selection
from services.logic.model import Limits
from services.resolution.logic_assessment import assess_formulas
from services.resolution.logic_impact import JudgmentCache
from services.resolution.logic_selection import ReportLimits, artifact_identity, selections_from_report


def _address(value):
    if not value.startswith("0x") or len(value) != 42:
        raise argparse.ArgumentTypeError("expected a 20-byte hex address")
    try:
        valid = 0 < int(value, 16) < 2**160
    except ValueError:
        valid = False
    if not valid:
        raise argparse.ArgumentTypeError("invalid deployment address")
    return value.lower()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    jobs = parser.add_subparsers(dest="job", required=True)
    generate = jobs.add_parser("generate", help="fetch verified code and save formulas; no enumeration")
    generate.add_argument("address", type=_address)
    generate.add_argument("--chain-id", type=int, required=True)
    generate.add_argument("--block", type=int)
    generate.add_argument("--rpc-url", required=True)
    generate.add_argument("--related-address", action="append", default=[], type=_address)
    generate.add_argument("--context-chars", type=int, default=48_000)
    generate.add_argument("--output", type=Path, required=True)

    assess = jobs.add_parser("assess", help="evaluate access and run or reuse pinned Jev impact judgments")
    assess.add_argument("artifact", type=Path)
    assess.add_argument("--rpc-url", help="optional direct state reads at the saved block, never enumeration")
    assess.add_argument("--cache", type=Path, required=True)
    assess.add_argument("--cache-only", action="store_true", help="missing judgments leave assessment incomplete")
    assess.add_argument("--model", default=DEFAULT_MODEL)
    assess.add_argument("--max-requests", type=int, default=8)
    assess.add_argument("--direct-reads", type=int, default=ReportLimits().direct_reads)
    assess.add_argument("--output", type=Path, required=True)

    enumerate_ = jobs.add_parser("enumerate", help="explicitly execute assessed expansion recommendations")
    enumerate_.add_argument("artifact", type=Path)
    mode = enumerate_.add_mutually_exclusive_group(required=True)
    mode.add_argument("--assessment", type=Path)
    mode.add_argument("--manual", action="store_true", help="explicitly expand without an impact assessment")
    enumerate_.add_argument("--effect", action="append", default=[], help="manual: SIGNATURE:ZERO_BASED_INDEX")
    enumerate_.add_argument("--function", action="append", default=[], help="restrict plan to exact signatures")
    enumerate_.add_argument("--rpc-url", required=True)
    enumerate_.add_argument("--members", type=int, default=Limits().members)
    enumerate_.add_argument("--solver-ms", type=int, default=Limits().solver_ms)
    enumerate_.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    for field in ("block", "max_requests", "direct_reads", "members", "solver_ms"):
        value = getattr(args, field, None)
        if value is not None and value < 0:
            parser.error(f"{field} cannot be negative")
    inputs = [getattr(args, key, None) for key in ("artifact", "assessment")]
    if args.output.resolve() in [path.resolve() for path in inputs if path is not None]:
        parser.error("output must not replace an input artifact")

    if args.job == "generate":
        if args.chain_id <= 0 or args.context_chars <= 0 or len(args.related_address) > 32:
            parser.error("positive chain/context size and at most 32 related addresses required")
        from db.models import SessionLocal
        from services.logic.deployment import deployment_formulas

        with SessionLocal() as session:
            result = deployment_formulas(
                session,
                args.address,
                args.chain_id,
                args.rpc_url,
                block=args.block,
                related_addresses=tuple(args.related_address),
                context_chars=args.context_chars,
            )
    else:
        artifact = json.loads(args.artifact.read_text())
        chain, block, _ = artifact_identity(artifact)
        if args.job == "assess":
            key = os.environ.get("TYPESAFE_API_KEY") or os.environ.get("JEV_API_KEY", "")
            # A fully cached assessment needs no credential. A miss without a client stays incomplete.
            client = (
                JevClient(key, model=args.model, max_requests=args.max_requests)
                if key and not args.cache_only
                else None
            )
            assess_saved = partial(
                assess_formulas,
                artifact,
                cache=JudgmentCache(args.cache),
                client=client,
                model=args.model,
                limits=ReportLimits(direct_reads=args.direct_reads),
            )
            if args.rpc_url:
                from db.models import SessionLocal
                from services.logic.deployment import _deployment_inputs

                with (
                    SessionLocal() as session,
                    _deployment_inputs(session, chain, args.rpc_url, block) as (reads, contracts),
                ):
                    result = assess_saved(reads=reads, contracts=contracts)
            else:
                result = assess_saved()
        else:
            if args.manual:
                selections = {name: Selection() for name in args.function}
                for entry in args.effect:
                    try:
                        name, number = entry.rsplit(":", 1)
                        index = int(number)
                        if index < 0:
                            raise ValueError()
                    except ValueError:
                        parser.error("--effect must be SIGNATURE:ZERO_BASED_INDEX")
                    selection = selections.get(name, Selection(callers=False))
                    selections[name] = replace(
                        selection, effect_indices=tuple(sorted({*selection.effect_indices, index}))
                    )
                if not selections:
                    parser.error("manual enumeration requires --function or --effect")
            else:
                if args.effect:
                    parser.error("--effect is only for explicit --manual enumeration")
                report = json.loads(args.assessment.read_text())
                selections = selections_from_report(artifact, report)
                if args.function:
                    if set(args.function) - selections.keys():
                        parser.error("requested function has no assessed expansion recommendation")
                    selections = {name: selections[name] for name in sorted(set(args.function))}
            from db.models import SessionLocal
            from services.logic.deployment import deployment_expansions

            with SessionLocal() as session:
                result = deployment_expansions(
                    session,
                    artifact,
                    args.rpc_url,
                    selections,
                    limits=Limits(members=args.members, solver_ms=args.solver_ms),
                )
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    if args.job == "assess" and result["assessment"]["status"] == "not_verified":
        print("Contract source is not verified; no assessment or enumeration was performed.")
        raise SystemExit(4)
    if args.job == "assess" and not result["assessment"]["judgments_complete"]:
        print(f"Assessment incomplete; saved pending judgments to {args.output}. No enumeration was started.")
        raise SystemExit(3)


if __name__ == "__main__":
    main()
