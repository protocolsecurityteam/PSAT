"""Permanent cases from the independent 82fed813 review; no live model requests."""

import copy
import json
from pathlib import Path

import pytest

from services.clients.jev import JevClient
from services.logic.deployment import Builds
from services.logic.formula import compile_function
from services.logic.model import encode
from services.logic.source_context import build_bundle, build_context, materialize_context
from services.resolution.logic_assessment import assess_formulas
from services.resolution.logic_impact import JudgmentCache, rate_effects
from services.resolution.logic_selection import selection_report, selections_from_report
from tests.logic._anvil import Deployment, anvil  # noqa: F401
from tests.logic.test_formula_engine import FixtureReads, deployed, formula  # noqa: F401
from tests.logic.test_impact import Session, inputs, rehash_bundle


def artifact(f, fn=None, contracts=None):
    result = {
        "schema": 2,
        "kind": "formulas",
        "chain_id": 1,
        "address": f"0x{f.address:040x}",
        "block": f.block,
        "functions": {f.signature: encode(f)},
        "code_locations": {f"0x{at:040x}": f"0x{at:040x}" for at in (contracts or {f.address: None})},
        "entry_code_addresses": {f.signature: f"0x{f.address:040x}"},
    }
    if fn is not None:
        bundle = build_bundle(contracts)
        result.update(source_bundle=bundle, contexts={f.signature: build_context(f, fn, bundle)})
    return result


def test_lazy_production_provider_matches_dictionary(deployed, tmp_path):
    f = formula(deployed, "early")
    provider = Builds(lambda _: None, lambda _: None, tmp_path)
    provider._built = {f"0x{at:040x}": c for at, c in deployed.contracts("C", "Guard").items()}
    assert not provider  # Actual lazy-provider behavior that the dictionary fixtures hid.
    actual = selection_report(artifact(f), reads=FixtureReads(deployed), contracts=provider)
    reference = selection_report(artifact(f), reads=FixtureReads(deployed), contracts=deployed.contracts("C", "Guard"))
    assert actual["rows"][0]["access"] == reference["rows"][0]["access"]
    assert actual["rows"][0]["access"]["status"] == "restricted"


@pytest.fixture(scope="module")
def review_deployment(anvil):
    url, root = anvil
    sub = root / "review"
    sub.mkdir()
    source = Path(__file__).parents[1] / "fixtures/contracts/logic_review_regressions.sol"
    d = Deployment(url, sub, source.read_text())
    d.deploy("Review")
    return d


def saved(d, name):
    fn = next(f for f in d.slither["Review"].functions if f.name == name)
    f = compile_function(d.slither["Review"], fn, d.at["Review"], d.chain(), d.contracts("Review"))
    return f, artifact(f, fn, d.contracts("Review"))


def test_complete_source_contains_global_declarations(review_deployment):
    f, a = saved(review_deployment, "setFee")
    context = materialize_context(a["contexts"][f.signature], f, a["source_bundle"])
    assert context["source_complete"]
    assert any("constant MAXIMUM_FEE=500" in u["source"] for u in context["units"])
    entry = context["entry"]
    raw = a["source_bundle"]["files"][entry["file"]]["source"].encode()
    assert raw[entry["start"] : entry["start"] + entry["length"]].startswith(b"function setFee")


def test_opposite_effect_branches_receive_distinct_questions_with_shared_context(review_deployment, tmp_path):
    f, a = saved(review_deployment, "choose")
    assert len(f.effects) == 2 and len({e.guard for e in f.effects}) == 2
    wire = Session()
    rate_effects(a, cache=JudgmentCache(tmp_path), client=JevClient("fake", session=wire))
    assert len(wire.calls) == 1
    state = json.loads(wire.calls[0][1]["data"])["state"]
    assert "effect_index" not in state["target"] and "program" in state
    questions = json.loads(wire.calls[0][1]["data"])["questions"]
    assert len(questions) == 10 and "effect_0__asset_power" in questions and "effect_1__asset_power" in questions
    entry = state["entry"]
    unit = next(u for u in state["sources"] if u["source_hash"] == entry["file"])
    text = unit["source"].encode()[entry["start"] : entry["start"] + entry["length"]].decode()
    assert "credits[to]+=amount" in text and "credits[msg.sender]+=msg.value" in text


@pytest.mark.parametrize(
    "unverified,status,complete", [(False, "nothing_to_assess", True), (True, "not_verified", False)]
)
def test_empty_and_unverified_are_distinct_terminal_outcomes(tmp_path, unverified, status, complete):
    _, a, _ = inputs()
    a["functions"] = {}
    a["contexts"] = {}
    if unverified:
        a["status"] = "not_verified"
    wire = Session()
    report = assess_formulas(a, cache=JudgmentCache(tmp_path), client=JevClient("fake", session=wire))
    assert report["assessment"]["status"] == status
    assert report["assessment"]["judgments_complete"] is complete
    assert not wire.calls


def test_new_associated_context_invalidates_prior_selection(tmp_path):
    _, a, _ = inputs()
    report = assess_formulas(a, cache=JudgmentCache(tmp_path), client=JevClient("fake", session=Session()))
    assert selections_from_report(a, report)
    changed = copy.deepcopy(a)
    changed["source_bundle"]["source_gaps"].append("unverified:new_authority")
    rehash_bundle(changed)
    with pytest.raises(ValueError, match="source context"):
        selections_from_report(changed, report)


def test_shared_bundle_stores_source_once_for_multiple_function_refs(review_deployment):
    a, b = saved(review_deployment, "setFee")[1], saved(review_deployment, "choose")[1]
    assert a["source_bundle"] == b["source_bundle"]
    a["functions"].update(b["functions"])
    a["contexts"].update(b["contexts"])
    assert len(a["contexts"]) == 2 and len(a["source_bundle"]["files"]) == 1
    assert all("units" not in c and "source" not in c for c in a["contexts"].values())
