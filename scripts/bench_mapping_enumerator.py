"""Bench the mapping_enumerator against real contracts.

Times the from-block-0 eRPC event replay for a handful of contracts
chosen across the relevant age + activity matrix:

  - Maker DAI ``wards`` (deployed 2017, very high activity)
  - LinkToken ``isMinter`` (deployed 2017, low-medium activity)
  - USDC FiatTokenV2 ``isMinter`` (deployed 2020, low activity)
  - Aave V3 LendingPool admin role (deployed 2022, low activity)

Reports per-contract: pages, last_block, total wall-clock, status,
principals_returned. Highlights which contracts hit the 60s default
timeout and would need ``PSAT_MAPPING_ENUMERATION_TIMEOUT_S`` bumped.

Run:
  set -a; source .env; set +a
  uv run python scripts/bench_mapping_enumerator.py [--timeout-s 60]
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.resolution.mapping_enumerator import (
    clear_enumeration_cache,
    enumerate_mapping_allowlist_sync,
)
from utils.rpc import require_supported_chain_id

# Each entry mimics the writer-event spec the static-analysis stage produces
# for a contract whose mapping is mutated via Add/Remove-style events.
FIXTURES = [
    {
        "label": "MakerDAO DAI (wards via Rely/Deny, 2017, high activity)",
        "address": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
        "chain_id": 1,
        "specs": [
            {
                "mapping_name": "wards",
                "event_signature": "Rely(address)",
                "direction": "add",
                "key_position": 0,
                "indexed_positions": [0],
            },
            {
                "mapping_name": "wards",
                "event_signature": "Deny(address)",
                "direction": "remove",
                "key_position": 0,
                "indexed_positions": [0],
            },
        ],
    },
    {
        "label": "LinkToken isMinter (RoleGranted/RoleRevoked, 2017, lower activity)",
        "address": "0x514910771AF9Ca656af840dff83E8264EcF986CA",
        "chain_id": 1,
        "specs": [
            {
                "mapping_name": "minters",
                "event_signature": "MinterAdded(address)",
                "direction": "add",
                "key_position": 0,
                "indexed_positions": [0],
            },
        ],
    },
    {
        "label": "USDC FiatTokenV2 minters (MinterConfigured, 2020, low activity)",
        "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "chain_id": 1,
        "specs": [
            {
                "mapping_name": "minters",
                "event_signature": "MinterConfigured(address,uint256)",
                "direction": "add",
                "key_position": 0,
                "indexed_positions": [0],
            },
            {
                "mapping_name": "minters",
                "event_signature": "MinterRemoved(address)",
                "direction": "remove",
                "key_position": 0,
                "indexed_positions": [0],
            },
        ],
    },
]


def _run_one(fixture: dict, *, timeout_s: float, max_pages: int) -> dict:
    clear_enumeration_cache()
    t0 = time.monotonic()
    chain_id = require_supported_chain_id(
        chain_id=fixture["chain_id"],
        context=f"mapping enumerator bench {fixture['label']}",
    )
    result = enumerate_mapping_allowlist_sync(
        fixture["address"],
        fixture["specs"],
        chain_id=chain_id,
        timeout_s=timeout_s,
        max_pages=max_pages,
    )
    elapsed = time.monotonic() - t0
    return {
        "label": fixture["label"],
        "address": fixture["address"],
        "chain_id": chain_id,
        "elapsed_s": round(elapsed, 1),
        "status": result["status"],
        "pages_fetched": result["pages_fetched"],
        "last_block_scanned": result["last_block_scanned"],
        "principals": len(result["principals"]),
        "error": result.get("error"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--timeout-s",
        type=float,
        default=60.0,
        help="Wall-clock budget per contract (default 60s — production default)",
    )
    parser.add_argument(
        "--max-pages", type=int, default=50, help="Page cap per contract (default 50 — production default)"
    )
    parser.add_argument(
        "--filter", type=str, default=None, help="Substring filter on the label (run only matching fixtures)"
    )
    args = parser.parse_args()

    print(f"timeout_s={args.timeout_s}  max_pages={args.max_pages}\n")
    rows = []
    for fixture in FIXTURES:
        if args.filter and args.filter.lower() not in fixture["label"].lower():
            continue
        print(f"→ {fixture['label']}")
        try:
            row = _run_one(
                fixture,
                timeout_s=args.timeout_s,
                max_pages=args.max_pages,
            )
        except Exception as exc:
            row = {
                "label": fixture["label"],
                "address": fixture["address"],
                "elapsed_s": -1,
                "status": "EXCEPTION",
                "pages_fetched": 0,
                "last_block_scanned": 0,
                "principals": 0,
                "error": str(exc),
            }
        rows.append(row)
        print(
            f"   elapsed={row['elapsed_s']}s  status={row['status']}  "
            f"pages={row['pages_fetched']}  principals={row['principals']}  "
            f"last_block={row['last_block_scanned']}"
        )
        if row["error"]:
            print(f"   error: {row['error']}")
        print()

    # Summary table
    print("=" * 100)
    print(f"{'label':<70} {'elapsed_s':>10} {'pages':>6} {'status':>22}")
    print("-" * 100)
    for r in rows:
        print(f"{r['label'][:68]:<70} {r['elapsed_s']:>10} {r['pages_fetched']:>6} {r['status']:>22}")


if __name__ == "__main__":
    main()
