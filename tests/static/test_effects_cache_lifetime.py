"""The effects memo must reuse engines within one pass without retaining Slither parses."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.effects import (
    build_effects,  # noqa: E402
    origins,  # noqa: E402
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "contracts" / "label_corpus"


def _subject(filename: str, name: str):
    slither = Slither(str(FIXTURES / filename))
    return slither, next(contract for contract in slither.contracts if contract.name == name)


def test_effects_memo_reuses_each_function_within_a_pass(monkeypatch):
    slither, contract = _subject("value_router.sol", "Teller")
    calls: list[tuple[int, int]] = []
    original_bundle = origins._engine_bundle_for

    def bundle_for(unit):
        bundle = original_bundle(unit)
        calls.append((id(unit), id(bundle)))
        return bundle

    monkeypatch.setattr(origins, "_engine_bundle_for", bundle_for)
    build_effects(contract)
    assert len(calls) > len({unit for unit, _ in calls})
    assert len({bundle for _, bundle in calls}) == len({unit for unit, _ in calls})
    assert origins._ENGINE_BUNDLE_SCOPE.get() is None
