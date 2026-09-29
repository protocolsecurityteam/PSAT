"""The effects memo must reuse engines within one pass without retaining Slither parses."""

from __future__ import annotations

import gc
import threading
import weakref
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.effects import build as effects_build  # noqa: E402
from services.static.contract_analysis_pipeline.effects import (
    build_effects,  # noqa: E402
    origins,  # noqa: E402
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "contracts" / "label_corpus"


def _subject(filename: str, name: str):
    slither = Slither(str(FIXTURES / filename))
    return slither, next(contract for contract in slither.contracts if contract.name == name)


def _analyze_and_release():
    slither, contract = _subject("value_router.sol", "Teller")
    contract_ref = weakref.ref(contract)
    function_ref = weakref.ref(contract.functions[0])
    artifact = build_effects(contract)
    assert artifact["functions"]
    return contract_ref, function_ref


def test_effects_memo_does_not_retain_slither_parse_between_passes():
    for _ in range(4):
        contract_ref, function_ref = _analyze_and_release()
        gc.collect()
        assert origins._ENGINE_BUNDLE_SCOPE.get() is None
        assert contract_ref() is None
        assert function_ref() is None


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


def test_effects_memo_is_released_on_failure(monkeypatch):
    slither, contract = _subject("value_router.sol", "Teller")
    contract_ref = weakref.ref(contract)
    original = effects_build._effect_info_for_function

    def fail_after_analysis(function):
        original(function)
        raise RuntimeError("injected failure")

    monkeypatch.setattr(effects_build, "_effect_info_for_function", fail_after_analysis)
    with pytest.raises(RuntimeError, match="injected failure"):
        build_effects(contract)
    assert origins._ENGINE_BUNDLE_SCOPE.get() is None
    del contract, slither
    gc.collect()
    assert contract_ref() is None


def test_concurrent_effects_passes_have_separate_memos(monkeypatch):
    first_slither, first = _subject("value_router.sol", "Teller")
    second_slither, second = _subject("self_service_payout.sol", "SelfServicePayout")
    expected = (build_effects(first), build_effects(second))
    original = origins._engine_bundle_for
    barrier = threading.Barrier(2)
    local = threading.local()
    scope_ids: dict[int, int] = {}

    def bundle_for(unit):
        scope = origins._ENGINE_BUNDLE_SCOPE.get()
        assert scope is not None
        if not getattr(local, "seen", False):
            local.seen = True
            scope_ids[threading.get_ident()] = id(scope)
            barrier.wait(timeout=10)
        return original(unit)

    monkeypatch.setattr(origins, "_engine_bundle_for", bundle_for)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(build_effects, contract) for contract in (first, second)]
        actual = tuple(future.result() for future in futures)
    assert actual == expected
    assert len(set(scope_ids.values())) == 2
    assert origins._ENGINE_BUNDLE_SCOPE.get() is None
