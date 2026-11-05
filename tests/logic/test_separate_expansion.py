"""Formula generation and address expansion are independently executable phases."""

import copy
import json
import subprocess
import sys
from contextlib import contextmanager

import pytest

from services.logic import deployment, expansion
from services.logic.expansion import Selection, expand_formula, formula_hash
from services.logic.linker import Linker
from services.logic.model import Limits, decode_formula, encode
from services.logic.terms import CALLER, const, mk, mk_cmp
from tests.logic._anvil import anvil  # noqa: F401
from tests.logic.test_formula_engine import FixtureReads, deployed, formula  # noqa: F401


def install_inputs(monkeypatch, d, reads):
    class Contracts(dict):
        def code_address(self, address):
            return address

        def own_code(self, address):
            return self.get(address)

    contracts = Contracts(d.contracts("C", "Guard"))

    @contextmanager
    def inputs(session, chain_id, url, block):
        assert chain_id == 1 and block in (None, reads.block)
        yield reads, contracts

    monkeypatch.setattr(deployment, "_deployment_inputs", inputs)
    return contracts


def artifact(d, *names):
    rows = [formula(d, name) for name in names]
    return {
        "schema": 2,
        "kind": "formulas",
        "chain_id": 1,
        "address": f"0x{d.at['C']:040x}",
        "block": rows[0].block,
        "functions": {f.signature: encode(f) for f in rows},
    }


def test_default_deployment_only_builds_formulas(monkeypatch, deployed):
    def forbidden(*args, **kwargs):
        raise AssertionError("formula generation entered address expansion")

    class FormulaReads(FixtureReads):
        storage_dump = key_words = preimages = forbidden

    reads = FormulaReads(deployed)
    install_inputs(monkeypatch, deployed, reads)
    monkeypatch.setattr(expansion, "project", forbidden)
    monkeypatch.setattr("z3.Solver", forbidden)
    result = deployment.deployment_formulas(None, f"0x{deployed.at['C']:040x}", 1, "unused")
    assert result["kind"] == "formulas"
    assert "selected(uint256)" in result["functions"] and "delegated()" in result["functions"]
    for row in result["functions"].values():
        assert "callers" not in row["value"] and "members" not in row["value"]
        assert decode_formula(row).success is not None


def test_linking_does_not_enumerate_a_symbolic_target(monkeypatch, deployed):
    class NoEnumeration(FixtureReads):
        def storage_dump(self, address):
            raise AssertionError("symbolic call target triggered enumeration")

    linker = Linker(NoEnumeration(deployed), deployed.contracts("C"), deployed.at["C"], Limits())
    target = mk("load", const(deployed.at["C"], "address"), "managers", (("k", mk("arg", "id", "uint256")),))
    assert linker.concrete(target) is None


def test_saved_formula_round_trips_with_effects_and_updates(deployed):
    original = formula(deployed, "selected")
    restored = decode_formula(json.loads(json.dumps(encode(original))))
    assert restored == original
    assert formula_hash(restored) == formula_hash(original)


def test_expansion_reuses_saved_formula_and_only_selected_functions(monkeypatch, deployed):
    saved = artifact(deployed, "selected", "early")
    before = copy.deepcopy(saved)
    install_inputs(monkeypatch, deployed, FixtureReads(deployed))

    def forbidden(*args, **kwargs):
        raise AssertionError("expansion re-lowered a saved formula")

    monkeypatch.setattr("services.logic.formula.compile_function", forbidden)
    monkeypatch.setattr("services.logic.lower.Lowerer.success", forbidden)
    result = deployment.deployment_expansions(None, saved, "unused", {"selected(uint256)": Selection()})
    assert result["kind"] == "address_expansions"
    assert result["storage_steps"] == Limits().storage_steps
    assert "callers" in result["functions"]["selected(uint256)"]["storage_accounting"]
    assert set(result["functions"]) == {"selected(uint256)"}
    value = result["functions"]["selected(uint256)"]["expansion"]["value"]
    from tests.logic.test_formula_engine import OWNER

    assert value["callers"]["members"] == {"tuple": [OWNER]}
    assert value["effects"] == {"tuple": []}
    assert saved == before
    assert result["block"] == saved["block"]


def test_effect_only_selection_does_not_expand_success(monkeypatch, deployed):
    f = formula(deployed, "early")
    seen = []
    real = expansion.project

    def record(predicate, translation):
        seen.append(predicate)
        return real(predicate, translation)

    monkeypatch.setattr(expansion, "project", record)
    result = expand_formula(
        f, FixtureReads(deployed), deployed.contracts("C"), selection=Selection(callers=False, effect_indices=(0,))
    )
    assert result.callers is None and result.effect_indices == (0,)
    assert seen == [f.effects[0].guard]


@pytest.mark.parametrize(
    "selections", [{}, {"absent()": Selection()}, {"early()": Selection(False)}, {"early()": Selection(False, (99,))}]
)
def test_invalid_selection_fails_before_reading(monkeypatch, deployed, selections):
    saved = artifact(deployed, "early")

    def forbidden(*args):
        raise AssertionError("invalid request reached the provider")

    monkeypatch.setattr(deployment, "_deployment_inputs", forbidden)
    with pytest.raises(ValueError):
        deployment.deployment_expansions(None, saved, "unused", selections)


def test_expansion_rejects_another_block(deployed):
    f = formula(deployed, "early")
    reads = FixtureReads(deployed)
    reads.block += 1
    with pytest.raises(ValueError, match="pinned block"):
        expand_formula(f, reads, deployed.contracts("C"))


def test_decoder_rejects_cycles(deployed):
    payload = encode(formula(deployed, "early"))
    index = payload["value"]["success"]["term"]
    payload["terms"][index] = ["not", {"term": index}]
    with pytest.raises(ValueError, match="cyclic"):
        decode_formula(payload)


def test_formula_can_be_expanded_in_a_fresh_process():
    from services.logic.model import Formula

    f = Formula(1, 123, "f()", 0, (), mk_cmp("eq", CALLER, const(7)), (), ())
    code = """
import json, sys
from services.logic.model import decode_formula
from services.logic.expansion import expand_formula
class Reads:
    block = 123
formula = decode_formula(json.load(sys.stdin))
result = expand_formula(formula, Reads(), {})
assert result.callers.complete and result.callers.members == (7,)
print("expanded")
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        input=json.dumps(encode(f)),
        text=True,
        capture_output=True,
        timeout=30,
        check=True,
    )
    assert result.stdout.strip() == "expanded"
