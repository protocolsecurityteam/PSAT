"""Enrich selection with cached or explicitly requested Jev impact estimates.

python -m scripts.logic_impact formulas.json selection.json --cache .jev-cache --output impact.json
Add --live --max-requests N to permit new API requests. Set TYPESAFE_API_KEY or JEV_API_KEY server-side.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from services.clients.jev import DEFAULT_MODEL, JevClient
from services.resolution.logic_impact import JudgmentCache, enrich_impact


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("formulas", type=Path)
    parser.add_argument("selection", type=Path)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--live", action="store_true", help="permit bounded new Jev API requests")
    parser.add_argument("--max-requests", type=int, default=8)
    args = parser.parse_args(argv)
    if args.output.resolve() in (args.formulas.resolve(), args.selection.resolve()):
        parser.error("output must not replace either input")
    if args.max_requests < 0:
        parser.error("request limit cannot be negative")
    artifact = json.loads(args.formulas.read_text())
    report = json.loads(args.selection.read_text())
    client = (
        JevClient(
            os.environ.get("TYPESAFE_API_KEY") or os.environ.get("JEV_API_KEY", ""),
            model=args.model,
            max_requests=args.max_requests,
        )
        if args.live
        else None
    )
    result = enrich_impact(artifact, report, model=args.model, cache=JudgmentCache(args.cache), client=client)
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
