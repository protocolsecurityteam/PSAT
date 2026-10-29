"""Model output is advisory, source-bound and budgeted; it never edits the proof."""

import copy
import json
from types import SimpleNamespace

import pytest
import requests

from services.clients.jev import DEFAULT_MODEL, JevBudgetExceeded, JevClient, JevError
from services.logic.model import Effect, Formula, encode
from services.logic.source_context import build_context, digest, validate_context
from services.logic.terms import CALLER, const, mk_cmp
from services.resolution.logic_impact import DIMENSIONS, QUESTIONS, JudgmentCache, enrich_impact, validate_answer
from services.resolution.logic_selection import selection_report
from tests.logic._anvil import anvil  # noqa: F401
from tests.logic.test_formula_engine import deployed  # noqa: F401
from tests.logic.test_selection_report import source_bundle  # noqa: F401


def response(level=3, scope="other_users", confidence=1):
    scores = {
        name: {
            "type": "score",
            "score": level if name == "asset_power" else 0,
            "confidence": confidence,
            "probabilities": {str(i): int(i == (level if name == "asset_power" else 0)) for i in range(4)},
        }
        for name in DIMENSIONS
    }
    scores["scope"] = {
        "type": "choice",
        "choice": scope,
        "confidence": 1,
        "probabilities": {k: int(k == scope) for k in QUESTIONS["scope"]["criteria"]},
    }
    scores["context_sufficient"] = {"type": "noul", "noul": 0.99}
    return {"model": DEFAULT_MODEL, "answers": scores, "usage": {"input_tokens": 100, "output_tokens": 25}}


class Session:
    def __init__(self, answer=None, status=200, error=None):
        self.answer, self.status, self.error, self.calls = answer or response(), status, error, []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        return SimpleNamespace(status_code=self.status, json=lambda: copy.deepcopy(self.answer))


def inputs():
    guard = mk_cmp("eq", CALLER, const(7, "address"))
    f = Formula(
        1,
        123,
        "change(uint256)",
        0,
        (),
        guard,
        (Effect("write", (const(1, "address"), "value", ()), const(3), guard),),
        (),
    )
    fn = SimpleNamespace(
        source_mapping=SimpleNamespace(
            content="function change(uint v) external { require(msg.sender == owner); value=v; }"
        ),
        modifiers=[],
    )
    context = build_context(f, fn, {})
    artifact = {
        "schema": 2,
        "kind": "formulas",
        "chain_id": 1,
        "address": "0x1",
        "block": 123,
        "functions": {f.signature: encode(f)},
        "contexts": {f.signature: context},
    }
    return f, artifact, selection_report(artifact)


def test_model_can_raise_attention_without_changing_access_or_inputs(tmp_path):
    f, artifact, report = inputs()
    originals = copy.deepcopy((artifact, report))
    session = Session()
    client = JevClient("test-secret", session=session, max_requests=1)
    rated = enrich_impact(artifact, report, cache=JudgmentCache(tmp_path), client=client)
    row = rated["rows"][0]
    assert row["impact"]["level"] == "high" and row["impact"]["basis"] == "model_estimate"
    assert row["decision"] == "expand" and row["priority"] == "high"
    assert row["access"] == report["rows"][0]["access"]
    assert (artifact, report) == originals and rated["automatic_execution"] is False
    assert "test-secret" not in json.dumps(rated) and all(
        "test-secret" not in p.read_text() for p in tmp_path.iterdir()
    )
    _, request = session.calls[0]
    assert request["allow_redirects"] is False
    sent = json.loads(request["data"])
    assert "priority" not in sent["state"] and "verdict" not in sent["state"]


def test_cache_replays_without_a_key_or_new_spend(tmp_path):
    _, artifact, report = inputs()
    client = JevClient("secret", session=Session(), max_requests=1)
    cache = JudgmentCache(tmp_path)
    first = enrich_impact(artifact, report, cache=cache, client=client)
    second = enrich_impact(artifact, report, cache=cache)
    assert second["impact_assessment"]["wire_requests"] == 0
    assert second["impact_assessment"]["statistics"]["cache_hits"] == 1
    assert first["rows"][0]["impact"] == second["rows"][0]["impact"]


def test_low_model_score_does_not_suppress_structural_attention(tmp_path):
    _, artifact, report = inputs()
    report["rows"][0].update(priority="high", decision="expand")
    client = JevClient("secret", session=Session(response(0, "own_entitlement")))
    row = enrich_impact(artifact, report, cache=JudgmentCache(tmp_path), client=client)["rows"][0]
    assert row["impact"]["level"] == "none" and row["impact"]["deferral_candidate"]
    assert row["priority"] == "high" and row["decision"] == "expand"


def test_low_confidence_keeps_severity_unknown(tmp_path):
    _, artifact, report = inputs()
    client = JevClient("secret", session=Session(response(confidence=0.2)))
    row = enrich_impact(artifact, report, cache=JudgmentCache(tmp_path), client=client)["rows"][0]
    assert row["impact"]["level"] == "unknown"
    assert row["decision"] == "review" and row["priority"] == "high"


def test_incomplete_source_cannot_support_low_impact(tmp_path):
    f, artifact, report = inputs()
    c = artifact["contexts"][f.signature]
    c.update(source_complete=False, source_gaps=["external code missing"])
    c["context_hash"] = digest({k: v for k, v in c.items() if k != "context_hash"})
    row = enrich_impact(
        artifact,
        report,
        cache=JudgmentCache(tmp_path),
        client=JevClient("secret", session=Session(response(0, "own_entitlement"))),
    )["rows"][0]
    assert row["impact"]["level"] == "unknown" and row["decision"] == "review"


def test_missing_context_does_not_make_a_model_request(tmp_path):
    _, artifact, report = inputs()
    artifact.pop("contexts")
    client = JevClient("secret", session=Session())
    result = enrich_impact(artifact, report, cache=JudgmentCache(tmp_path), client=client)
    assert client.sent == 0 and result["rows"][0]["impact"]["model_status"] == "missing_context"


def test_context_changes_invalidate_cache(tmp_path):
    f, artifact, report = inputs()
    cache = JudgmentCache(tmp_path)
    client = JevClient("secret", session=Session())
    enrich_impact(artifact, report, cache=cache, client=client)
    c = artifact["contexts"][f.signature]
    c["source_gaps"].append("new scope evidence")
    c["context_hash"] = digest({k: v for k, v in c.items() if k != "context_hash"})
    result = enrich_impact(artifact, report, cache=cache)
    assert result["rows"][0]["impact"]["model_status"] == "cache_miss"


def test_source_mismatch_fails_before_spend(tmp_path):
    f, artifact, report = inputs()
    artifact["contexts"][f.signature]["units"][0]["source"] += "changed"
    client = JevClient("secret", session=Session())
    with pytest.raises(ValueError, match="hash"):
        enrich_impact(artifact, report, cache=JudgmentCache(tmp_path), client=client)
    assert client.sent == 0


def test_enrichment_cannot_be_stacked_on_its_own_predictions(tmp_path):
    _, artifact, report = inputs()
    rated = enrich_impact(artifact, report, cache=JudgmentCache(tmp_path))
    with pytest.raises(ValueError, match="original deterministic"):
        enrich_impact(artifact, rated, cache=JudgmentCache(tmp_path))


@pytest.mark.parametrize(
    "change",
    [
        lambda a: a["answers"].pop("scope"),
        lambda a: a["answers"]["asset_power"].update(score=0),
        lambda a: a["answers"]["asset_power"].update(confidence=float("nan")),
        lambda a: a.update(model="jev-latest"),
    ],
)
def test_invalid_responses_never_become_judgments(change):
    answer = response()
    change(answer)
    with pytest.raises(JevError):
        validate_answer(answer, DEFAULT_MODEL)


def test_client_caps_actual_attempts_and_does_not_retry():
    session = Session(error=requests.Timeout("secret could occur in a wire exception"))
    client = JevClient("secret", session=session, max_requests=1)
    with pytest.raises(JevError) as e:
        client.ask({}, QUESTIONS)
    assert "secret" not in str(e.value)
    with pytest.raises(JevBudgetExceeded):
        client.ask({}, QUESTIONS)
    assert len(session.calls) == 1


def test_client_rejects_aliases_and_oversize_requests():
    with pytest.raises(ValueError, match="versioned"):
        JevClient("secret", model="jev-latest")
    client = JevClient("secret", max_request_bytes=1, session=Session())
    with pytest.raises(JevBudgetExceeded):
        client.ask({}, QUESTIONS)
    assert client.sent == 0


def test_source_truncation_is_explicit_and_keeps_target_first():
    f, artifact, _ = inputs()
    fn = SimpleNamespace(source_mapping=SimpleNamespace(content="x" * 100), modifiers=[])
    context = build_context(f, fn, {}, max_chars=10)
    assert context["supplied_chars"] == 10 and context["source_chars"] == 100
    assert not context["source_complete"] and context["units"][0]["truncated"]
    validate_context(context, f)


def test_one_confident_high_dimension_is_not_averaged_away(tmp_path):
    _, artifact, report = inputs()
    answer = response()
    answer["answers"]["authority_power"]["confidence"] = 0.1
    row = enrich_impact(
        artifact, report, cache=JudgmentCache(tmp_path), client=JevClient("secret", session=Session(answer))
    )["rows"][0]
    assert row["impact"]["level"] == "high"


@pytest.mark.parametrize("condition", ["unrestricted", "inactive", "origin", "unsupported"])
def test_model_does_not_override_access_boundaries(tmp_path, condition):
    _, artifact, report = inputs()
    r = report["rows"][0]
    if condition == "unrestricted":
        r["access"]["status"] = "unrestricted"
        r["decision"] = "report_unrestricted"
    elif condition == "inactive":
        r["access"]["activity"] = "inactive_at_block"
    elif condition == "origin":
        r["access"]["identity_dimensions"] = ["origin"]
    else:
        r["access"].update(status="unresolved", issues=[{"kind": "unsupported", "detail": "callee"}])
    before = copy.deepcopy(r["access"])
    rated = enrich_impact(
        artifact, report, cache=JudgmentCache(tmp_path), client=JevClient("secret", session=Session())
    )["rows"][0]
    assert rated["access"] == before
    assert rated["decision"] == ("report_unrestricted" if condition == "unrestricted" else "review")


def test_budget_exhaustion_preserves_the_original_decision(tmp_path):
    _, artifact, report = inputs()
    client = JevClient("secret", session=Session(), max_requests=0)
    result = enrich_impact(artifact, report, cache=JudgmentCache(tmp_path), client=client)
    assert result["rows"][0]["decision"] == report["rows"][0]["decision"]
    assert result["rows"][0]["impact"]["model_status"] == "budget"
    assert result["impact_assessment"]["wire_requests"] == 0


def test_changed_rubric_invalidates_cached_results(tmp_path, monkeypatch):
    import services.resolution.logic_impact as module

    _, artifact, report = inputs()
    cache = JudgmentCache(tmp_path)
    enrich_impact(artifact, report, cache=cache, client=JevClient("secret", session=Session()))
    changed = copy.deepcopy(module.QUESTIONS)
    changed["asset_power"]["instructions"] += " Revised scope."
    monkeypatch.setattr(module, "QUESTIONS", changed)
    result = enrich_impact(artifact, report, cache=cache)
    assert result["rows"][0]["impact"]["model_status"] == "cache_miss"


def test_recorded_live_responses_replay_the_policy_without_inference():
    from pathlib import Path

    from services.resolution.logic_impact import ImpactPolicy, _estimate

    data = json.loads(
        (Path(__file__).parents[1] / "fixtures" / "logic_impact" / "jev_1_14_v2_responses.json").read_text()
    )
    for case in data["cases"]:
        validate_answer(case["response"], data["model"])
        estimate = _estimate(case["response"], {"source_complete": case["source_complete"]}, ImpactPolicy())
        assert estimate["level"] == case["accepted_level"]


def test_formula_generation_saves_loaded_callee_source_without_model_work(deployed, monkeypatch):
    from services.logic import deployment
    from services.logic.model import decode_formula
    from tests.logic.test_formula_engine import FixtureReads
    from tests.logic.test_separate_expansion import install_inputs

    install_inputs(monkeypatch, deployed, FixtureReads(deployed))
    saved = deployment.deployment_formulas(None, f"0x{deployed.at['C']:040x}", 1, "unused", signatures={"delegated()"})
    context = saved["contexts"]["delegated()"]
    validate_context(context, decode_formula(saved["functions"]["delegated()"]))
    assert any("contract Guard" in u["source"] for u in context["units"])
    assert any("contract C" in u["source"] for u in context["units"])


def test_source_statements_are_attributed_before_judging(source_bundle):
    from services.logic.formula import compile_function
    from tests.logic import _oracle as O

    d, _ = source_bundle
    fn = O.function(d, "C", "setOwner")
    f = compile_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C"))
    c = build_context(f, fn, d.contracts("C"))
    assert any("owner = value" in s for site in c["effect_sites"].values() for s in site["statements"])
