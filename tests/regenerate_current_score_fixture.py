"""Generate a clearly synthetic current-model UI document through the real fold.

Run from repository root: .venv/bin/python -m tests.regenerate_current_score_fixture
The legacy score_etherfi fixture is retained verbatim as historical API input.
This fixture uses no database, provider, production corpus or network.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.scoring.schema import PrincipalRef
from tests.support.scoring_builders import EOA, KEY_C, facts, fold, proven, reaches, sig, value_plane


def current_document():
    with pytest.MonkeyPatch.context() as patch:
        run = fold.__wrapped__(patch)
        signal = sig(
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", EOA),),
            **proven(1.0),
            **reaches(KEY_C),
        )
        document = run(
            [signal], principals={1: facts(1, EOA, "eoa")}, value=value_plane({KEY_C: {"token": 2_000_000.0}})
        )
        return document.document()


if __name__ == "__main__":
    target = Path(__file__).parents[1] / "site/src/test/fixtures/score_current_synthetic.json"
    target.write_text(json.dumps(current_document(), separators=(",", ":")))
    print(f"Regenerated {target.name} from current fold and synthetic inputs")
