import pytest

from scripts.logic_impact_evaluate import evaluate


def test_evaluation_does_not_count_abstention_as_correct():
    result = evaluate(
        {"assessment": {"functions": {"f()": {"level": "unknown"}}}},
        [{"function": "f()", "expected_min": 3, "expected_max": 3}],
    )
    assert result["matched"] == 0 and result["abstained"] == 1
    assert result["high_impact_abstentions"] == 1


def test_evaluation_rejects_duplicate_labels():
    expected = {"function": "f()", "expected_min": 0, "expected_max": 1}
    with pytest.raises(ValueError, match="duplicate expected"):
        evaluate({"assessment": {"functions": {"f()": {"level": "none"}}}}, [expected, expected])
