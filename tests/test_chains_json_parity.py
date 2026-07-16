"""Parity-or-die: the committed ``site/src/chains.json`` must match the registry.

If the chain registry changes and ``scripts/gen_chains_json.py`` isn't re-run,
this test fails — so the frontend's generated chain map can never silently drift
from ``utils.chains`` (inv. 5).
"""

from __future__ import annotations

from scripts.gen_chains_json import CHAINS_JSON_PATH, render_json


def test_chains_json_matches_registry():
    committed = CHAINS_JSON_PATH.read_text(encoding="utf-8")
    assert committed == render_json(), (
        "site/src/chains.json is stale — regenerate it with "
        "`python scripts/gen_chains_json.py` after editing the chain registry."
    )
