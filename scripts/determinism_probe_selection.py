"""String-hash determinism probe (class A).

Runs the real candidate selection over the local corpus database and prints a
canonical serialization of the whole emitted queue. Under every
``PYTHONHASHSEED`` the bytes must be identical: the queue's ORDER decides which
candidates a ``resource_cap`` run reaches at all, so a seed-dependent order is a
seed-dependent set of probed functions.

Serialization rules, both deliberate:

* ordered containers (list, tuple) are serialized in their emitted order — that
  is the thing under test;
* unordered containers (set, frozenset) are serialized SORTED. Comparing
  ``repr(frozenset)`` compares CPython's string hashing, not this code. The one
  set-typed field on a ``Candidate`` is ``restrict_families``, and both of its
  consumers — ``calldata.py:2295`` and ``orchestrator.py:190`` — read it with
  ``in`` only, so its iteration order reaches no decision. Without this rule the
  gate fails today for a reason nothing downstream can observe, and a gate that
  cries wolf gets ignored. Any set-order leak that DOES reach a decision still
  surfaces here, because it surfaces as a different queue order or a different
  value.

Alongside the queue the probe publishes ``unordered_control``: the *removed*
arithmetic — ``sum(self.balance.get(a, 0.0) for a in seen)``, copied verbatim
from ``services/effects/selection.py`` as it stood before the fix —
recomputed over the same real graph. It is an instrument, never a product: the
gate requires it to **vary** across the seed sweep. If it stops varying, this
corpus no longer contains a closure whose float fold is order-sensitive, the
sweep has lost its discriminating power, and the gate must say so rather than
report a green it has not earned: a control is only evidence while it still
discriminates.

Needs ``DATABASE_URL`` pointed at the corpus database (protocol 1). It is not
optional and there is no synthetic fallback: a gate that quietly degrades to a
toy workload reports green about a workload nobody cared about.
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

# The row this gate refuses to lose — the positive control, carried forward.
# `sweepDust` sits inside the largest tied value cluster in the queue — 84
# members at $4,024,163,604.46 — so it is the row a wrong tiebreak moves first,
# and a payload that no longer contains it cannot testify about ordering at all.
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
        # Exact, and distinguishable from the float that used to stand here.
        return {"__decimal__": str(value)}
    if isinstance(value, float):
        return {"__float__": repr(value)}
    return value


def _prefix_float_fold(graph: Any, seeds: set[str]) -> float:
    """``AuthorityGraph.reachable_value`` as it stood before the fix.

    Verbatim, including the unsorted ``seen`` and the binary-float ``sum`` — that
    is the whole point.
    """
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

    # The probe's own output is the print()s below; this is so the library
    # code it drives logs through the house JSON handler instead of falling
    # to lastResort (WARNING-only, unscrubbed).
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

    # An anchor violation still PRINTS its payload and exits 4, rather than
    # aborting. Exit 3 means "there is nothing here to compare"; exit 4 means
    # "compare it, and also know the anchor moved". Aborting would throw away the
    # seed sweep's own testimony in exactly the runs where it is most
    # interesting — the pre-fix code moves this anchor on 3 of 8 seeds, which IS
    # the seed-dependence, not a separate problem.
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
        # `Decimal(str(...))` rather than a bare `!=` on purpose: the anchor's job
        # is "this row is still here and still holds this money", not "this field
        # is a Decimal" — the type is pinned by the selection module's own tests.
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
