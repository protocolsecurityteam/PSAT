"""ABI boundary counterexamples from independent review, checked against local execution."""

import json
from pathlib import Path

import pytest

from services.logic.expansion import expand_formula
from services.logic.formula import compile_function
from tests.logic import _anvil as A
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

CASES = json.loads((Path(__file__).parent / "fixtures/external_abi_regressions.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
@pytest.mark.parametrize("version", ["0.8.10", "0.8.27"])
def test_decoder_semantics_or_named_rejection(anvil, monkeypatch, tmp_path, case, version):
    monkeypatch.setattr(A, "SOLC", version)
    d = A.Deployment(anvil[0], tmp_path, case["source"])
    target = d.deploy("M")
    d.deploy("C", ("address",), (target,))
    contracts = d.contracts(*d.at)
    for name in case["functions"]:
        fn = O.function(d, "C", name)
        f = compile_function(d.slither["C"], fn, d.at["C"], d.chain(), contracts)
        callers = expand_formula(f, d.chain(), contracts).callers
        for sender in (O.OWNER, O.ACCOUNTS[1]):
            assert O.chain_says(d, fn, [], sender=sender) is case["chain_success"]
            _, answer = O.engine_says(d, fn, [], sender=sender, contracts=contracts)
            assert answer is None or answer is case["chain_success"]
        if case["chain_success"]:
            assert not (callers.complete and callers.representation == "finite" and not callers.members)
        elif callers.complete:
            assert callers.representation == "finite" and not callers.members
        else:
            assert callers.issues
