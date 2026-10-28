"""Previously discovered wrong answers, checked with the new production evaluator."""

import json
from pathlib import Path

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401


def source(original, contains):
    records = json.loads((Path(__file__).parent / "fixtures" / "regressions.json").read_text())
    return next(r["solidity"] for r in records if r["source"] == original and contains in r["solidity"])


@pytest.fixture(scope="module")
def legacy(anvil):
    d = O.deployment(*anvil, source("test_lower_shapes.py", "contract LinkToken"), "0.4.19")
    d.deploy("LinkToken")
    return d


@pytest.mark.parametrize("amount", [0, 50, 100, 150])
@pytest.mark.parametrize("sender", [O.OWNER, O.ACCOUNTS[1]])
def test_super_preserves_the_amount_in_the_base_check(legacy, amount, sender):
    fn = O.function(legacy, "LinkToken", "transferAndCall")
    args = [O.ACCOUNTS[2], amount]
    expected = O.chain_says(legacy, fn, args, "LinkToken", sender)
    formula, actual = O.engine_says(legacy, fn, args, "LinkToken", sender)
    O.agrees(formula, actual, expected, (amount, sender))
