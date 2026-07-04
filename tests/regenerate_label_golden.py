#!/usr/bin/env python
"""Regenerate the effect-labels golden from CURRENT producer behavior.

Run this ONLY when a producer change intentionally shifts labels/claims and the
diff has been reviewed:

    uv run python tests/regenerate_label_golden.py

It compiles every corpus contract (all pinned to solc 0.8.27, installed via
solc-select) and overwrites ``tests/fixtures/label_corpus/golden.json``. Commit
the resulting diff alongside the producer change so the A/B gate records the
intended update. ``--check`` recomputes without writing and exits non-zero on any
drift — the same assertion ``tests/test_label_corpus.py`` makes.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.support import label_corpus as harness  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="recompute and diff against the checked-in golden without writing (exit 1 on drift)",
    )
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="label-corpus-regen-") as tmp:
        golden = harness.build_golden(workdir=Path(tmp))

    if args.check:
        diff = harness.unified_diff(harness.load_golden(), golden)
        if diff:
            sys.stdout.write(diff)
            print(f"\nGolden is STALE: {harness.GOLDEN_PATH} does not match current behavior.", file=sys.stderr)
            return 1
        print(f"Golden is up to date ({len(golden['contracts'])} contracts).")
        return 0

    harness.write_golden(golden)
    n_fns = sum(len(c["functions"]) for c in golden["contracts"])
    print(f"Wrote {harness.GOLDEN_PATH} — {len(golden['contracts'])} contracts, {n_fns} functions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
