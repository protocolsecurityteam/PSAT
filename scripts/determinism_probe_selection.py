"""String-hash determinism probe (class A).

Runs real candidate selection over the corpus DB and prints the whole queue canonically; bytes must match under every
``PYTHONHASHSEED``, because queue order decides which candidates a ``resource_cap`` run reaches.

* ordered containers serialize in emitted order (the thing under test);
* sets serialize sorted: ``repr(frozenset)`` compares CPython hashing, and ``restrict_families`` (the only set field) is
only read with ``in``. A set-order leak that reaches a decision still shows up as a different order or value.

``unordered_control`` recomputes the removed float fold (verbatim from pre-fix ``services/effects/selection.py``). The
gate requires it to vary across seeds; if it stops, the corpus has lost its discriminating power and the gate must say
so.

Needs ``DATABASE_URL`` at the corpus DB (protocol 1); no synthetic fallback.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

# Positive control: ``sweepDust`` sits in the largest tied value cluster (84 at $4,024,163,604.46), so a wrong tiebreak
# moves it first.
ANCHOR_FUNCTION_ID = 2771
ANCHOR_NAME = "sweepDust"
ANCHOR_VALUE = Decimal("4024163604.46")


def canonical(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return ["<set>"] + sorted(canonical(v) for v in value)
    if isinstance(value, (list, tuple)):
        return [canonical(v) for v in value]
    if isinstance(value, dict):
        return {str(k): canonical(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, Decimal):
        return {"__decimal__": str(value)}
    if isinstance(value, float):
        return {"__float__": repr(value)}
    return value


def _prefix_float_fold(graph: Any, seeds: set[str]) -> float:
    """``AuthorityGraph.reachable_value`` before the fix, verbatim (unsorted ``seen``, float ``sum``)."""
    from services.effects.selection import _addr

    stack = [s for s in (_addr(s) for s in seeds) if s]
    seen: set[str] = set()
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        stack.extend(graph.controls.get(node, ()))
    return sum(float(graph.balance.get(a, 0.0)) for a in seen)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol-id", type=int, default=1)
    args = parser.parse_args()

    from utils.logging import configure_logging

    # So library logs go through the JSON handler rather than lastResort (WARNING-only, unscrubbed).
    configure_logging()

    from db.models import SessionLocal
    from services.effects.selection import build_authority_graph, select_candidates

    with SessionLocal() as session:
        candidates = select_candidates(session, args.protocol_id)
        graph = build_authority_graph(session, args.protocol_id)

    control = [
        [c.function_id, repr(_prefix_float_fold(graph, {c.contract_address, *c.principal_addresses}))]
        for c in candidates
    ]

    rows = [canonical(dataclasses.asdict(c)) for c in candidates]

    if not rows:
        print(
            f"EMPTY WORKLOAD: select_candidates(protocol={args.protocol_id}) returned nothing. "
            "An empty payload is byte-identical under every seed and proves nothing.",
            file=sys.stderr,
        )
        return 3

    # Exit 4 still prints the payload: aborting would discard the seed sweep's testimony (pre-fix code moves the anchor
    # on 3 of 8 seeds). Exit 3 means nothing to compare.
    anchor = [
        (i, c)
        for i, c in enumerate(candidates)
        if c.function_id == ANCHOR_FUNCTION_ID and c.function_name == ANCHOR_NAME
    ]
    violation: str | None = None
    rank: int | None = None
    if not anchor:
        violation = f"ANCHOR LOST: function_id={ANCHOR_FUNCTION_ID} ({ANCHOR_NAME}) is not in the emitted queue"
    else:
        rank, candidate = anchor[0]
        # The anchor checks the money, not the type (pinned by selection's own tests).
        if Decimal(str(candidate.value_at_stake_usd)) != ANCHOR_VALUE:
            violation = (
                f"ANCHOR MOVED: {ANCHOR_NAME} value_at_stake_usd = {candidate.value_at_stake_usd!r}, "
                f"expected exactly {ANCHOR_VALUE!r}"
            )

    print(
        json.dumps(
            {
                "anchor": {
                    "name": ANCHOR_NAME,
                    "function_id": ANCHOR_FUNCTION_ID,
                    "rank": rank,
                    "violation": violation,
                },
                "queue": rows,
                "unordered_control": control,
            },
            sort_keys=True,
            indent=1,
        )
    )
    if violation:
        print(violation, file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
