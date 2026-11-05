"""Effect ratings preserve proofs; transport, caching and policy are independently checked."""

import copy
import json
from types import SimpleNamespace

import pytest
import requests

from services.clients.jev import DEFAULT_MODEL, JevBudgetExceeded, JevClient, JevError
from services.logic.model import Effect, Formula, encode
from services.logic.source_context import build_bundle, build_context, digest, materialize_context
from services.logic.terms import CALLER, const, mk_cmp
from services.resolution.logic_assessment import assess_formulas
from services.resolution.logic_impact import DIMENSIONS, QUESTIONS, JudgmentCache, rate_effects, validate_answer
from services.resolution.logic_selection import selection_report


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


def uncertain_response():
    answer = response(confidence=0)
    for name in DIMENSIONS:
        answer["answers"][name].update(score=1.5, probabilities={str(i): 0.25 for i in range(4)})
    return answer


class Session:
    def __init__(self, answer=None, status=200, error=None):
        self.answer, self.status, self.error, self.calls = answer or response(), status, error, []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        answer = copy.deepcopy(self.answer)
        asked = json.loads(kwargs["data"])["questions"]
        if asked and all(k.startswith("effect_") for k in asked) and set(answer["answers"]) == set(QUESTIONS):
            answer["answers"] = {key: copy.deepcopy(answer["answers"][key.split("__", 1)[1]]) for key in asked}
        return SimpleNamespace(status_code=self.status, json=lambda: answer)


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
    text = "function change(uint v) external { require(msg.sender == owner); value=v; }"
    unit = SimpleNamespace(core=SimpleNamespace(source_code={"Fixture.sol": text}))
    fn = SimpleNamespace(
        compilation_unit=unit,
        source_mapping=SimpleNamespace(
            filename=SimpleNamespace(absolute="Fixture.sol"), start=0, length=len(text.encode())
        ),
    )
    contract = SimpleNamespace(name="Fixture", compilation_unit=unit)
    bundle = build_bundle({1: contract})
    context = build_context(f, fn, bundle)
    artifact = {
        "schema": 2,
        "kind": "formulas",
        "chain_id": 1,
        "address": "0x1",
        "block": 123,
        "functions": {f.signature: encode(f)},
        "contexts": {f.signature: context},
        "source_bundle": bundle,
    }
    return f, artifact, selection_report(artifact)


def rehash_bundle(artifact):
    bundle = artifact["source_bundle"]
    bundle["bundle_hash"] = digest({k: v for k, v in bundle.items() if k != "bundle_hash"})
    for context in artifact["contexts"].values():
        context["bundle_hash"] = bundle["bundle_hash"]
        context["context_hash"] = digest({k: v for k, v in context.items() if k != "context_hash"})


def rate(artifact, path, answer=None, **kw):
    return rate_effects(
        artifact, cache=JudgmentCache(path), client=JevClient("test-secret", session=Session(answer)), **kw
    )


def test_model_does_not_edit_access_or_proofs(tmp_path):
    _, artifact, evidence = inputs()
    before = copy.deepcopy(artifact)
    wire = Session()
    rated = assess_formulas(artifact, cache=JudgmentCache(tmp_path), client=JevClient("test-secret", session=wire))
    assert rated["rows"][0]["access"] == evidence["rows"][0]["access"]
    assert rated["rows"][0]["decision"] == "expand" and artifact == before
    assert rated["assessment"]["functions"]["change(uint256)"]["effects"]["0"]["level"] == "high"
    assert "test-secret" not in json.dumps(rated)
    assert all("test-secret" not in p.read_text() for p in tmp_path.iterdir())
    assert wire.calls[0][1]["allow_redirects"] is False
    state = json.loads(wire.calls[0][1]["data"])["state"]
    assert "effect_index" not in state["target"] and "priority" not in state and "verdict" not in state
    assert "program" in state and len(json.loads(wire.calls[0][1]["data"])["questions"]) == 5


def test_cache_replays_without_key_or_spend(tmp_path):
    _, artifact, _ = inputs()
    first = rate(artifact, tmp_path)
    second = rate_effects(artifact, cache=JudgmentCache(tmp_path))
    assert second["wire_requests"] == 0 and second["statistics"]["cache_hits"] == 1
    assert first["functions"] == second["functions"]


@pytest.mark.parametrize(
    "answer,expected", [(response(0, "own_entitlement"), "none"), (uncertain_response(), "unknown")]
)
def test_low_or_uncertain_model_never_discards_a_function(tmp_path, answer, expected):
    _, artifact, _ = inputs()
    result = assess_formulas(artifact, cache=JudgmentCache(tmp_path), client=JevClient("key", session=Session(answer)))
    assert result["assessment"]["functions"]["change(uint256)"]["effects"]["0"]["level"] == expected
    assert result["rows"][0]["decision"] == "review"


def test_partial_source_cannot_support_low_and_invalidates_cache(tmp_path):
    _, artifact, _ = inputs()
    rate(artifact, tmp_path)
    artifact["source_bundle"]["source_gaps"].append("missing dependency")
    rehash_bundle(artifact)
    assert (
        rate_effects(artifact, cache=JudgmentCache(tmp_path))["functions"]["change(uint256)"]["model_status"]
        == "cache_miss"
    )
    result = rate(artifact, tmp_path, response(0, "own_entitlement"))
    assert result["functions"]["change(uint256)"]["effects"]["0"]["level"] == "unknown"


def test_missing_context_makes_no_request(tmp_path):
    _, artifact, _ = inputs()
    artifact.pop("contexts")
    client = JevClient("key", session=Session())
    result = rate_effects(artifact, cache=JudgmentCache(tmp_path), client=client)
    assert client.sent == 0 and result["functions"]["change(uint256)"]["model_status"] == "missing_context"


def test_tampered_source_fails_before_spend(tmp_path):
    _, artifact, _ = inputs()
    next(iter(artifact["source_bundle"]["files"].values()))["source"] += "changed"
    client = JevClient("key", session=Session())
    with pytest.raises(ValueError, match="hash"):
        rate_effects(artifact, cache=JudgmentCache(tmp_path), client=client)
    assert client.sent == 0


def test_source_truncation_is_request_only(tmp_path):
    f, artifact, _ = inputs()
    artifact["source_bundle"]["max_chars"] = 10
    rehash_bundle(artifact)
    resolved = materialize_context(artifact["contexts"][f.signature], f, artifact["source_bundle"])
    assert len(resolved["units"][0]["source"]) == 10 and not resolved["source_complete"]
    assert len(next(iter(artifact["source_bundle"]["files"].values()))["source"]) > 10


def test_high_dimension_is_not_averaged_away(tmp_path):
    _, artifact, _ = inputs()
    answer = response()
    answer["answers"]["authority_power"]["confidence"] = 0.1
    assert rate(artifact, tmp_path, answer)["functions"]["change(uint256)"]["effects"]["0"]["level"] == "high"


def test_changed_questions_invalidate_cache(tmp_path, monkeypatch):
    import services.resolution.logic_impact as module

    _, artifact, _ = inputs()
    rate(artifact, tmp_path)
    questions = copy.deepcopy(module.QUESTIONS)
    questions["asset_power"]["instructions"] += "New scope"
    monkeypatch.setattr(module, "QUESTIONS", questions)
    result = rate_effects(artifact, cache=JudgmentCache(tmp_path))
    assert result["functions"]["change(uint256)"]["model_status"] == "cache_miss"


@pytest.mark.parametrize("condition", ["unrestricted", "inactive", "origin", "unsupported"])
def test_rating_does_not_override_access_boundaries(tmp_path, monkeypatch, condition):
    _, artifact, evidence = inputs()
    access = evidence["rows"][0]["access"]
    if condition == "unrestricted":
        access["status"] = "unrestricted"
    elif condition == "inactive":
        access["activity"] = "inactive_at_block"
    elif condition == "origin":
        access["identity_dimensions"] = ["origin"]
    else:
        access.update(status="unresolved", issues=[{"kind": "unsupported", "detail": "callee"}])
    before = copy.deepcopy(access)
    monkeypatch.setattr(
        "services.resolution.logic_assessment.selection_report", lambda *a, **kw: copy.deepcopy(evidence)
    )
    result = assess_formulas(artifact, cache=JudgmentCache(tmp_path), client=JevClient("key", session=Session()))
    assert result["rows"][0]["access"] == before
    assert result["rows"][0]["decision"] == ("report_unrestricted" if condition == "unrestricted" else "review")


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


def test_long_context_is_explicit_and_keeps_a_request_budget():
    large = {"source": "a" * 110_000}
    normal = Session()
    with pytest.raises(JevBudgetExceeded):
        JevClient("secret", session=normal).ask(large, QUESTIONS)
    assert not normal.calls
    extended = Session()
    client = JevClient("secret", session=extended, long_context=True, max_requests=1)
    client.ask(large, QUESTIONS)
    assert extended.calls[0][1]["headers"]["TypeSafe-Danger-Zone-Long-Context"] == "true"
    with pytest.raises(JevBudgetExceeded):
        client.ask(large, QUESTIONS)
    assert len(extended.calls) == 1
    wire = Session()
    JevClient("secret", session=wire).ask({}, QUESTIONS)
    assert "TypeSafe-Danger-Zone-Long-Context" not in wire.calls[0][1]["headers"]


def test_provider_context_limit_is_a_named_budget_without_retry():
    wire = Session(answer={"detail": {"error_type": "max_tokens_exceeded"}}, status=400)
    client = JevClient("secret", session=wire)
    with pytest.raises(JevBudgetExceeded, match="model context limit"):
        client.ask({}, QUESTIONS)
    assert client.sent == len(wire.calls) == 1
