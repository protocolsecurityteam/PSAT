#!/usr/bin/env python3
"""Emit ``site/src/surface/chains.json`` from the chain registry (inv.

5). ``tests/chains/test_chains_json_parity.py`` fails CI if it's stale.

    python scripts/gen_chains_json.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from utils.chains import all_chains  # noqa: E402  (path bootstrap must precede)

CHAINS_JSON_PATH = _REPO_ROOT / "site" / "src" / "surface" / "chains.json"


def build_chains_payload() -> list[dict[str, object]]:
    return [
        {
            "chain_id": info.chain_id,
            "name": info.name,
            "explorer_base_url": info.explorer_base_url,
        }
        for info in sorted(all_chains(), key=lambda c: c.chain_id)
    ]


def render_json() -> str:
    return json.dumps(build_chains_payload(), indent=2) + "\n"


def main() -> None:
    CHAINS_JSON_PATH.write_text(render_json(), encoding="utf-8")
    print(f"wrote {CHAINS_JSON_PATH}")


if __name__ == "__main__":
    main()
