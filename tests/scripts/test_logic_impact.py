import json

import pytest

from scripts.logic_impact import main
from scripts.logic_impact_evaluate import evaluate
from tests.logic.test_impact import inputs


def test_default_cli_is_cache_only_even_with_a_configured_key(tmp_path, monkeypatch):
    _, artifact, report = inputs()
    f, r, out = tmp_path / "formulas.json", tmp_path / "report.json", tmp_path / "impact.json"
    f.write_text(json.dumps(artifact))
    r.write_text(json.dumps(report))
    monkeypatch.setenv("JEV_API_KEY", "test-secret")

    def forbidden(*args, **kwargs):
        raise AssertionError("default command attempted network inference")

    monkeypatch.setattr("requests.Session.post", forbidden)
    main([str(f), str(r), "--cache", str(tmp_path / "cache"), "--output", str(out)])
    result = json.loads(out.read_text())
    assert result["impact_assessment"]["wire_requests"] == 0
    assert result["rows"][0]["impact"]["model_status"] == "cache_miss"
    assert "test-secret" not in out.read_text()


def test_cli_cannot_overwrite_a_proof_input(tmp_path):
    with pytest.raises(SystemExit):
        main(
            [
                str(tmp_path / "f.json"),
                str(tmp_path / "r.json"),
                "--cache",
                str(tmp_path / "c"),
                "--output",
                str(tmp_path / "f.json"),
            ]
        )


def test_evaluation_does_not_count_abstention_as_correct():
    result = evaluate(
        {"rows": [{"function": "f()", "effect_index": 0, "impact": {"level": "unknown"}}]},
        [{"function": "f()", "effect_index": 0, "expected_min": 3, "expected_max": 3}],
    )
    assert result["matched"] == 0 and result["abstained"] == 1
    assert result["high_impact_abstentions"] == 1


def test_evaluation_rejects_duplicate_labels():
    expected = {"function": "f()", "effect_index": 0, "expected_min": 0, "expected_max": 1}
    with pytest.raises(ValueError, match="duplicate expected"):
        evaluate({"rows": [{"function": "f()", "effect_index": 0, "impact": {"level": "none"}}]}, [expected, expected])
