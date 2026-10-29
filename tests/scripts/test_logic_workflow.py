"""The public workflow assesses before expansion and never chains jobs implicitly."""

import copy
import json
from contextlib import nullcontext

import pytest

from scripts.logic import main
from services.clients.jev import JevClient
from services.logic.expansion import Selection
from services.resolution.logic_assessment import assess_formulas
from services.resolution.logic_impact import JudgmentCache
from tests.logic.test_impact import Session, inputs, response


def test_generate_assess_enumerate_are_three_explicit_jobs(tmp_path, monkeypatch):
    _, artifact, _ = inputs()
    source, assessment, addresses = (tmp_path / f"{name}.json" for name in ("formulas", "assessment", "addresses"))
    monkeypatch.setattr("db.models.SessionLocal", lambda: nullcontext(None))
    events = []

    def generate(session, address, chain_id, rpc_url, **kwargs):
        events.append("generate")
        assert address == "0x" + "0" * 39 + "1" and chain_id == 1
        assert kwargs["block"] == 123
        return copy.deepcopy(artifact)

    def expand(session, saved, rpc_url, selections, **kwargs):
        events.append("enumerate")
        assert saved == artifact
        assert selections == {"change(uint256)": Selection(False, (0,))}
        return {"kind": "address_expansions"}

    wire = Session()
    monkeypatch.setenv("JEV_API_KEY", "fake-key")
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.setattr("scripts.logic.JevClient", lambda key, **kwargs: JevClient(key, session=wire, **kwargs))
    monkeypatch.setattr("services.logic.deployment.deployment_formulas", generate)
    monkeypatch.setattr("services.logic.deployment.deployment_expansions", expand)
    main(
        [
            "generate",
            "0x" + "0" * 39 + "1",
            "--chain-id",
            "1",
            "--block",
            "123",
            "--rpc-url",
            "unused",
            "--output",
            str(source),
        ]
    )
    assert events == ["generate"] and not wire.calls
    before = source.read_bytes()
    args = ["assess", str(source), "--cache", str(tmp_path / "cache"), "--output", str(assessment)]
    main(args)
    result = json.loads(assessment.read_text())
    assert events == ["generate"] and len(wire.calls) == 1
    assert result["assessment"]["status"] == "assessed"
    assert result["assessment"]["functions"]["change(uint256)"]["severity"] == "high"
    # Exact cached judgments satisfy the mandatory assessment without keys or new requests.
    monkeypatch.delenv("JEV_API_KEY")
    main(args)
    assert len(wire.calls) == 1
    assert json.loads(assessment.read_text())["impact_assessment"]["statistics"]["cache_hits"] == 1
    main(
        [
            "enumerate",
            str(source),
            "--assessment",
            str(assessment),
            "--function",
            "change(uint256)",
            "--rpc-url",
            "unused",
            "--output",
            str(addresses),
        ]
    )
    assert events == ["generate", "enumerate"]
    assert source.read_bytes() == before and json.loads(addresses.read_text())["kind"] == "address_expansions"


@pytest.mark.parametrize("mode", ["missing_key", "cache_only", "budget"])
def test_missing_judgment_stays_incomplete_and_cannot_recommend_expansion(tmp_path, monkeypatch, mode, capsys):
    _, artifact, _ = inputs()
    source, output = tmp_path / "formulas.json", tmp_path / "assessment.json"
    source.write_text(json.dumps(artifact))
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.delenv("JEV_API_KEY", raising=False)
    if mode != "missing_key":
        monkeypatch.setenv("JEV_API_KEY", "fake-key")

    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected enumeration or inference")

    monkeypatch.setattr("requests.Session.post", forbidden)
    monkeypatch.setattr("services.logic.deployment.deployment_expansions", forbidden)
    extra = ["--cache-only"] if mode == "cache_only" else ["--max-requests", "0"] if mode == "budget" else []
    with pytest.raises(SystemExit) as error:
        main(["assess", str(source), "--cache", str(tmp_path / "cache"), "--output", str(output), *extra])
    assert error.value.code == 3
    result = json.loads(output.read_text())
    assert result["assessment"]["status"] == "incomplete"
    assert result["suggested_expansions"] == []
    assert "incomplete" in capsys.readouterr().out
    with pytest.raises(ValueError, match="no expansions"):
        main(
            [
                "enumerate",
                str(source),
                "--assessment",
                str(output),
                "--rpc-url",
                "unused",
                "--output",
                str(tmp_path / "out"),
            ]
        )


def test_inconclusive_judgment_is_not_material_impact(tmp_path):
    _, artifact, _ = inputs()
    result = assess_formulas(
        artifact, cache=JudgmentCache(tmp_path), client=JevClient("key", session=Session(response(confidence=0.1)))
    )
    assert result["assessment"]["judgments_complete"] is True
    assert result["assessment"]["functions"]["change(uint256)"]["needs_review"] is True
    assert result["suggested_expansions"] == []
    assert result["rows"][0]["decision"] == "review"


def test_legacy_selection_is_not_a_completed_assessment(tmp_path):
    _, artifact, report = inputs()
    source, selection = tmp_path / "f.json", tmp_path / "r.json"
    source.write_text(json.dumps(artifact))
    selection.write_text(json.dumps(report))
    with pytest.raises(SystemExit):
        main(
            [
                "enumerate",
                str(source),
                "--assessment",
                str(selection),
                "--rpc-url",
                "unused",
                "--output",
                str(tmp_path / "out"),
            ]
        )


def test_assess_cannot_replace_formula_artifact(tmp_path):
    path = str(tmp_path / "formulas.json")
    with pytest.raises(SystemExit):
        main(["assess", path, "--cache", str(tmp_path / "cache"), "--output", path])


@pytest.mark.parametrize("level,expected", [(0, "unknown"), (2, "unknown"), (3, "high")])
def test_partial_function_impact_does_not_hide_unassessed_effects(tmp_path, level, expected):
    from dataclasses import replace

    from services.logic.expansion import formula_hash
    from services.logic.model import encode
    from services.logic.source_context import digest

    formula, artifact, _ = inputs()
    formula = replace(formula, effects=formula.effects * 2)
    artifact["functions"][formula.signature] = encode(formula)
    context = artifact["contexts"][formula.signature]
    context["formula_hash"] = formula_hash(formula)
    context["context_hash"] = digest({k: v for k, v in context.items() if k != "context_hash"})
    result = assess_formulas(
        artifact,
        cache=JudgmentCache(tmp_path),
        client=JevClient("key", max_requests=1, session=Session(response(level=level))),
    )
    summary = result["assessment"]["functions"][formula.signature]
    assert summary["severity"] == expected
    assert summary["unassessed_effects"] == [1] and summary["needs_review"]
    assert result["assessment"]["status"] == "incomplete"
    assert all(1 not in request["effect_indices"] for request in result["suggested_expansions"])


def test_function_without_reported_effects_still_gets_a_judgment(tmp_path):
    from dataclasses import replace

    from services.logic.expansion import formula_hash
    from services.logic.model import encode
    from services.logic.source_context import digest

    formula, artifact, _ = inputs()
    formula = replace(formula, effects=())
    artifact["functions"][formula.signature] = encode(formula)
    context = artifact["contexts"][formula.signature]
    context["formula_hash"] = formula_hash(formula)
    context["context_hash"] = digest({k: v for k, v in context.items() if k != "context_hash"})
    wire = Session()
    result = assess_formulas(artifact, cache=JudgmentCache(tmp_path), client=JevClient("key", session=wire))
    assert len(wire.calls) == 1
    state = json.loads(wire.calls[0][1]["data"])["state"]
    assert state["effect"]["kind"] == "whole_function" and state["target"]["effect_index"] is None
    summary = result["assessment"]["functions"][formula.signature]
    assert summary["judgments_complete"] and summary["needs_review"]
    assert summary["severity"] == "high"
    assert result["suggested_expansions"] == []
