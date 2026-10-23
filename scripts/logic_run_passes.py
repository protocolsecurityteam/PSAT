"""Pass condition for a logic-engine corpus run: compares a previous run's JSON lines with a new run's and exits 1 if
any check fails (0 otherwise). Rows are matched by (corpus, address, function, contract): the corpus is the row's
``corpus`` field, else read from a ``corpus_<name>_...`` file name, since one contract can sit in several corpora.

(a) ``--faulty``: the new run injected read failures (``FAILFRAC``, ``FAILSTORE``). A failed read is unknown, never
    evidence, so no row may gain confidence from it: any non-open row turning open, partial -> complete, a complete
    row whose listed set changed, or a complete row the old run did not have.
(b) Always: a holder whose own replayed ``eth_call`` succeeded in the old run (``checks[p] is True``) must still be
    listed (principal or conditional) in the new one, unless the new row is open (it subsumes everyone) or, with
    ``--scope-skip`` (both runs skipped enumerating self-scoped functions, ``PSAT_LOGIC_SCOPE_SKIP=1``), both rows
    say the function is self-scoped. Without it a self-scoped row is enumerated like any other and must keep its
    holders. A row that turns self-scoped never hides what it stopped listing. A new row that errored counts as
    losing them.
(c) ``--budget-only``: the two runs differ only in budgets (work, history caps, candidate limits). A budget may cost
    completeness, never the answer: openness and the listed set must be identical; ``complete`` and gaps may differ.
(d) Always: a new row claiming "provably nobody" (restricted, complete, nobody listed) where the harness replayed a
    holder prod names and its call returned (``nobody_refuted``, filled by ``corpus_parity.py``): the chain refutes
    the strongest claim the engine makes. A holder that only reverts differently from a stranger (``nobody_differs``:
    past the access check, stopped later, for the argument shapes tried) fails the row too, unless the engine's
    formula is identically false (``lego_formula_false``: WBTC's ``renounceOwnership``, which always reverts), where
    getting further than a stranger is no way through.
(m) Rows the old run has and the new one lacks fail too, unless ``--only-new`` (a subset run) is given.
A row that appears twice within the old files, or within the new ones, stops the comparison with an error.

Always printed, not a failure by itself: every row whose scope changed (or turned self-scoped, where the old run
recorded none), with how many replay-confirmed holders it stopped listing.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys


class DuplicateRow(SystemExit):
    """The same row twice in one run: which copy counts is undefined, so the comparison refuses to choose."""


def load(patterns: list[str]) -> dict[tuple, dict]:
    rows: dict[tuple, dict] = {}
    seen: dict[tuple, str] = {}
    for pattern in patterns:
        for path in sorted(set(glob.glob(pattern))) or [pattern]:
            named = re.match(r"corpus_([a-z0-9]+)_", os.path.basename(path))
            with open(path) as handle:
                for number, line in enumerate(handle, 1):
                    row = json.loads(line)
                    if "function" not in row:
                        continue
                    corpus = row.get("corpus") or (named.group(1) if named else "")
                    key = (corpus, row["address"].lower(), row["function"], row.get("contract"))
                    if key in rows:
                        raise DuplicateRow(f"duplicate row {key}: {seen[key]} and {path}:{number}")
                    rows[key], seen[key] = row, f"{path}:{number}"
    return rows


def listed(row: dict) -> set[str]:
    conditional = {"0x" + format(int(q, 16), "040x") for q in row.get("lego_conditions") or {}}
    return {p.lower() for p in row.get("lego_principals") or []} | conditional


def verdict(row: dict) -> str | None:
    return row.get("lego")


def _confirmed_lost(a: dict, b: dict) -> list[str]:
    confirmed = {p for p, ok in (a.get("checks") or {}).items() if ok is True and p != "anyone"}
    return sorted((confirmed & listed(a)) - listed(b))


def failures(
    old: dict[tuple, dict], new: dict[tuple, dict], faulty: bool, budget_only: bool, scope_skip: bool = False
) -> list[str]:
    out: list[str] = []
    for key in sorted(old.keys() & new.keys()):
        a, b = old[key], new[key]
        where = f"{key[0]} {a.get('contract')}.{key[2]} @ {key[1]}"
        if faulty:
            if verdict(a) != "open" and verdict(b) == "open":
                out.append(f"(a) {verdict(a)} -> open under failing reads: {where}")
            if b.get("lego_complete") and not a.get("lego_complete") and verdict(b) != "open":
                out.append(f"(a) gained completeness under failing reads: {where}")
            if a.get("lego_complete") and b.get("lego_complete") and listed(a) != listed(b):
                out.append(f"(a) a complete list changed under failing reads: {where}")
        exempt = scope_skip and a.get("lego_scope") == "self" and b.get("lego_scope") == "self"
        if verdict(b) != "open" and not exempt:
            lost = _confirmed_lost(a, b)
            if lost:
                out.append(f"(b) lost {len(lost)} replay-confirmed holder(s) {lost[:4]}: {where} ({verdict(b)})")
        if budget_only and (verdict(a) != verdict(b) or listed(a) != listed(b)):
            out.append(
                f"(c) budget changed the answer: {where} {verdict(a)}/{len(listed(a))} -> {verdict(b)}/{len(listed(b))}"
            )
    for key in sorted(new):
        refuted = new[key].get("nobody_refuted") or []
        where = f"{key[0]} {new[key].get('contract')}.{key[2]} @ {key[1]}"
        if refuted:
            out.append(f"(d) nobody claimed but prod holder passes {refuted[:4]}: {where}")
        differs = new[key].get("nobody_differs") or []
        if differs and new[key].get("lego_formula_false") is not True:
            out.append(f"(d) nobody claimed but prod holder gets past the gate {differs[:4]}: {where}")
    if faulty:
        for key in sorted(new.keys() - old.keys()):
            if new[key].get("lego_complete") and verdict(new[key]) != "open":
                out.append(f"(a) a complete row the old run did not have, under failing reads: {key}")
    return out


def scope_flips(old: dict[tuple, dict], new: dict[tuple, dict]) -> list[str]:
    out = []
    for key in sorted(old.keys() & new.keys()):
        a, b = old[key], new[key]
        # A run that didn't record scope says nothing about it; turning self-scoped always shows.
        if a.get("lego_scope") != b.get("lego_scope") and (
            a.get("lego_scope") is not None or b.get("lego_scope") == "self"
        ):
            lost = _confirmed_lost(a, b) if verdict(b) != "open" else []
            out.append(
                f"{key[0]} {a.get('contract')}.{key[2]} @ {key[1]}: scope {a.get('lego_scope')} -> "
                f"{b.get('lego_scope')}, {len(lost)} replay-confirmed holder(s) no longer listed"
            )
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--old", nargs="+", required=True, help="previous run's jsonl files (globs allowed)")
    parser.add_argument("--new", nargs="+", required=True, help="new run's jsonl files (globs allowed)")
    parser.add_argument("--faulty", action="store_true", help="the new run injected read failures")
    parser.add_argument("--budget-only", action="store_true", help="the runs differ only in budgets")
    parser.add_argument("--only-new", action="store_true", help="compare only rows the new run has")
    parser.add_argument("--scope-skip", action="store_true", help="both runs skipped enumerating self-scoped functions")
    args = parser.parse_args(argv)
    old, new = load(args.old), load(args.new)
    if args.only_new:
        old = {k: v for k, v in old.items() if k in new}
    found = failures(old, new, args.faulty, args.budget_only, args.scope_skip)
    found += [f"(m) missing from the new run: {k}" for k in sorted(old.keys() - new.keys())]
    flips = scope_flips(old, new)
    print(f"scope changes: {len(flips)}")
    for line in flips:
        print("  " + line)
    for line in found:
        print(line)
    print(f"compared {len(old.keys() & new.keys())} rows; {len(found)} failure(s)")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
