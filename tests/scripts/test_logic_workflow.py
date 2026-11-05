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
from tests.logic.test_impact import Session, inputs, uncertain_response


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
        assert kwargs["limits"].storage_steps == 750000
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
    assert result["assessment"]["functions"]["change(uint256)"]["effects"]["0"]["level"] == "high"
    # Exact cached judgments satisfy the mandatory assessment without keys or new requests.
    monkeypatch.delenv("JEV_API_KEY")
    main(args)
    assert len(wire.calls) == 1
    assert json.loads(assessment.read_text())["assessment"]["statistics"]["cache_hits"] == 1
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
            "--storage-steps",
            "750000",
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
        artifact, cache=JudgmentCache(tmp_path), client=JevClient("key", session=Session(uncertain_response()))
    )
    assert result["assessment"]["judgments_complete"] is True
    assert result["assessment"]["functions"]["change(uint256)"]["effects"]["0"]["level"] == "unknown"
    assert result["suggested_expansions"] == []
    assert result["rows"][0]["decision"] == "review"


def test_legacy_selection_is_not_a_completed_assessment(tmp_path):
    _, artifact, report = inputs()
    source, selection = tmp_path / "f.json", tmp_path / "r.json"
    source.write_text(json.dumps(artifact))
    selection.write_text(json.dumps(report))
    with pytest.raises(ValueError):
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


def test_many_effects_cost_one_function_judgment(tmp_path):
    from dataclasses import replace

    from services.logic.expansion import formula_hash
    from services.logic.model import encode
    from services.logic.source_context import digest

    f, artifact, _ = inputs()
    f = replace(f, effects=f.effects * 5)
    artifact["functions"][f.signature] = encode(f)
    context = artifact["contexts"][f.signature]
    context["formula_hash"] = formula_hash(f)
    context["context_hash"] = digest({k: v for k, v in context.items() if k != "context_hash"})
    wire = Session()
    result = assess_formulas(
        artifact, cache=JudgmentCache(tmp_path), client=JevClient("key", max_requests=1, session=wire)
    )
    assert len(wire.calls) == 1 and result["assessment"]["judgments_complete"]
    assert result["suggested_expansions"][0]["effect_indices"] == list(range(5))


def test_function_without_reported_effects_remains_visible_without_a_fabricated_rating(tmp_path):
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
    assert not wire.calls
    summary = result["assessment"]["functions"][formula.signature]
    assert summary["model_status"] == "no_modeled_effects" and summary["effects"] == {}
    assert result["rows"][0]["decision"] == "review"
    assert result["assessment"]["judgments_complete"] and result["assessment"]["status"] == "assessed"
    assert result["suggested_expansions"] == []


def test_manual_enumeration_preserves_explicit_selection(tmp_path, monkeypatch):
    _, artifact, _ = inputs()
    source, out = tmp_path / "formulas.json", tmp_path / "out.json"
    source.write_text(json.dumps(artifact))
    before = source.read_bytes()
    monkeypatch.setattr("db.models.SessionLocal", lambda: nullcontext(None))

    def expand(session, saved, rpc_url, selections, **kwargs):
        assert saved == artifact and selections == {"change(uint256)": Selection(True, (0,))}
        return {"kind": "address_expansions"}

    monkeypatch.setattr("services.logic.deployment.deployment_expansions", expand)
    main(
        [
            "enumerate",
            str(source),
            "--manual",
            "--function",
            "change(uint256)",
            "--effect",
            "change(uint256):0",
            "--rpc-url",
            "unused",
            "--output",
            str(out),
        ]
    )
    assert source.read_bytes() == before and json.loads(out.read_text())["kind"] == "address_expansions"


def test_missing_block_does_not_reach_provider(tmp_path, monkeypatch):
    _, artifact, _ = inputs()
    artifact.pop("block")
    source = tmp_path / "f.json"
    source.write_text(json.dumps(artifact))

    def forbidden(*a, **kw):
        raise AssertionError("invalid artifact reached provider")

    monkeypatch.setattr("services.logic.deployment._deployment_inputs", forbidden)
    with pytest.raises(ValueError, match="block"):
        main(
            [
                "assess",
                str(source),
                "--cache",
                str(tmp_path / "c"),
                "--rpc-url",
                "unused",
                "--output",
                str(tmp_path / "out"),
            ]
        )


@pytest.mark.parametrize("extra", [[], ["--manual"], ["--manual", "--effect", "bad"]])
def test_manual_selection_is_never_implicit(tmp_path, extra):
    _, artifact, _ = inputs()
    source = tmp_path / "f.json"
    source.write_text(json.dumps(artifact))
    with pytest.raises(SystemExit):
        main(["enumerate", str(source), *extra, "--rpc-url", "unused", "--output", str(tmp_path / "out")])


def test_cache_only_mode_never_calls_model_even_with_key(tmp_path, monkeypatch):
    _, artifact, _ = inputs()
    source = tmp_path / "f.json"
    source.write_text(json.dumps(artifact))
    monkeypatch.setenv("JEV_API_KEY", "fake")

    def forbidden(*a, **kw):
        raise AssertionError("cache-only made request")

    monkeypatch.setattr("requests.Session.post", forbidden)
    with pytest.raises(SystemExit) as exc:
        main(["assess", str(source), "--cache-only", "--cache", str(tmp_path / "c"), "--output", str(tmp_path / "out")])
    assert exc.value.code == 3


@pytest.mark.parametrize("unverified,code,status", [(False, 0, "nothing_to_assess"), (True, 4, "not_verified")])
def test_empty_and_unverified_cli_outcomes(tmp_path, monkeypatch, unverified, code, status):
    _, artifact, _ = inputs()
    artifact["functions"] = {}
    artifact["contexts"] = {}
    if unverified:
        artifact["status"] = "not_verified"
    source, out = tmp_path / "f.json", tmp_path / "out.json"
    source.write_text(json.dumps(artifact))

    def forbidden(*a, **kw):
        raise AssertionError("empty deployment attempted inference")

    monkeypatch.setattr("requests.Session.post", forbidden)
    args = ["assess", str(source), "--cache-only", "--cache", str(tmp_path / "c"), "--output", str(out)]
    if code:
        with pytest.raises(SystemExit) as exc:
            main(args)
        assert exc.value.code == code
    else:
        main(args)
    assert json.loads(out.read_text())["assessment"]["status"] == status
