"""Parity-or-die: committed ``site/src/surface/chains.json`` must match the registry.

Fails if ``scripts/gen_chains_json.py`` isn't re-run after a registry change, so the frontend chain map
can't silently drift from ``utils.chains``.
"""

from __future__ import annotations

from scripts.gen_chains_json import CHAINS_JSON_PATH, render_json


def test_chains_json_matches_registry():
    committed = CHAINS_JSON_PATH.read_text(encoding="utf-8")
    assert committed == render_json(), (
        "site/src/surface/chains.json is stale — regenerate it with "
        "`python scripts/gen_chains_json.py` after editing the chain registry."
    )
