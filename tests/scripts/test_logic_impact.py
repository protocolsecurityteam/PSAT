import pytest

from scripts.logic_impact_evaluate import evaluate


def test_evaluation_does_not_count_abstention_as_correct():
    result = evaluate(
        {"assessment": {"functions": {"f()": {"formula_hash": "fixture", "effects": {"0": {"level": "unknown"}}}}}},
        [{"function": "f()", "effect_index": 0, "formula_hash": "fixture", "expected_min": 3, "expected_max": 3}],
    )
    assert result["matched"] == 0 and result["abstained"] == 1
    assert result["high_impact_abstentions"] == 1


def test_evaluation_rejects_duplicate_labels():
    expected = {"function": "f()", "effect_index": 0, "formula_hash": "fixture", "expected_min": 0, "expected_max": 1}
    with pytest.raises(ValueError, match="duplicate expected"):
        evaluate(
            {"assessment": {"functions": {"f()": {"formula_hash": "fixture", "effects": {"0": {"level": "none"}}}}}},
            [expected, expected],
        )


def test_evaluation_keeps_distinct_effects_and_rejects_stale_identity():
    report = {
        "assessment": {
            "functions": {
                "f()": {"formula_hash": "current", "effects": {"0": {"level": "high"}, "1": {"level": "none"}}}
            }
        }
    }
    labels = [
        {"function": "f()", "effect_index": 0, "formula_hash": "current", "expected_min": 3, "expected_max": 3},
        {"function": "f()", "effect_index": 1, "formula_hash": "current", "expected_min": 0, "expected_max": 0},
    ]
    assert evaluate(report, labels)["matched"] == 2
    labels[0]["formula_hash"] = "old"
    with pytest.raises(ValueError, match="formula hash"):
        evaluate(report, labels)


def test_old_function_only_labels_are_not_treated_as_effect_labels():
    with pytest.raises(ValueError, match="effect_index"):
        evaluate({"assessment": {"functions": {}}}, [{"function": "f()", "expected_min": 0, "expected_max": 3}])
