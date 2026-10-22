"""Pass condition for a logic-engine corpus run: compares a previous run's JSON lines with a new run's and exits 1 if
any check fails (0 otherwise). Rows are matched by (corpus, address, function, contract): the corpus is the row's
``corpus`` field, else read from a ``corpus_<name>_...`` file name, since one contract can sit in several corpora.

(a) ``--faulty``: the new run injected read failures (``FAILFRAC``, ``FAILSTORE``). A failed read is unknown, never
    evidence, so no row may gain confidence from it: restricted -> open, partial -> complete, or a complete row the
    old run did not have.
(b) Always: a holder whose own replayed ``eth_call`` succeeded in the old run (``checks[p] is True``) must still be
    listed (principal or conditional) in the new one, unless the new row is open (it subsumes everyone) or the new
    row says the function is self-scoped (``lego_scope == "self"``: its gate is reported as a condition and its
    members aren't enumerated). A new row that errored counts as losing them.
(c) ``--budget-only``: the two runs differ only in budgets (work, history caps, candidate limits). A budget may cost
    completeness, never the answer: openness and the listed set must be identical; ``complete`` and gaps may differ.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys


def load(patterns: list[str]) -> dict[tuple, dict]:
    rows: dict[tuple, dict] = {}
    for pattern in patterns:
        for path in sorted(glob.glob(pattern)) or [pattern]:
            named = re.match(r"corpus_([a-z0-9]+)_", os.path.basename(path))
            with open(path) as handle:
                for line in handle:
                    row = json.loads(line)
                    if "function" in row:
                        corpus = row.get("corpus") or (named.group(1) if named else "")
                        rows[(corpus, row["address"].lower(), row["function"], row.get("contract"))] = row
    return rows


def listed(row: dict) -> set[str]:
    conditional = {"0x" + format(int(q, 16), "040x") for q in row.get("lego_conditions") or {}}
    return {p.lower() for p in row.get("lego_principals") or []} | conditional


def verdict(row: dict) -> str | None:
    return row.get("lego")


def failures(old: dict[tuple, dict], new: dict[tuple, dict], faulty: bool, budget_only: bool) -> list[str]:
    out: list[str] = []
    for key in sorted(old.keys() & new.keys()):
        a, b = old[key], new[key]
        where = f"{key[0]} {a.get('contract')}.{key[2]} @ {key[1]}"
        if faulty:
            if verdict(a) == "restricted" and verdict(b) == "open":
                out.append(f"(a) restricted -> open under failing reads: {where}")
            if b.get("lego_complete") and not a.get("lego_complete") and verdict(b) != "open":
                out.append(f"(a) gained completeness under failing reads: {where}")
        if verdict(b) != "open" and b.get("lego_scope") != "self":
            confirmed = {p for p, ok in (a.get("checks") or {}).items() if ok is True and p != "anyone"}
            lost = sorted((confirmed & listed(a)) - listed(b))
            if lost:
                out.append(f"(b) lost {len(lost)} replay-confirmed holder(s) {lost[:4]}: {where} ({verdict(b)})")
        if budget_only and (verdict(a) != verdict(b) or listed(a) != listed(b)):
            out.append(
                f"(c) budget changed the answer: {where} {verdict(a)}/{len(listed(a))} -> {verdict(b)}/{len(listed(b))}"
            )
    if faulty:
        for key in sorted(new.keys() - old.keys()):
            if new[key].get("lego_complete") and verdict(new[key]) != "open":
                out.append(f"(a) a complete row the old run did not have, under failing reads: {key}")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--old", nargs="+", required=True, help="previous run's jsonl files (globs allowed)")
    parser.add_argument("--new", nargs="+", required=True, help="new run's jsonl files (globs allowed)")
    parser.add_argument("--faulty", action="store_true", help="the new run injected read failures")
    parser.add_argument("--budget-only", action="store_true", help="the runs differ only in budgets")
    parser.add_argument("--only-new", action="store_true", help="compare only rows the new run has")
    args = parser.parse_args(argv)
    old, new = load(args.old), load(args.new)
    if args.only_new:
        old = {k: v for k, v in old.items() if k in new}
    found = failures(old, new, args.faulty, args.budget_only)
    for line in found:
        print(line)
    print(f"compared {len(old.keys() & new.keys())} rows; {len(found)} failure(s)")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
