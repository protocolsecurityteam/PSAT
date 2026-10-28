"""A writer's call-frame values stay its own when its updates are composed."""

from services.logic.formula import compile_function
from services.logic.solver import Translation, project
from services.resolution.logic_composition import sequence
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """
pragma solidity 0.8.27;
contract C {
    mapping(bytes4 => bool) ready;
    function enable() external { ready[msg.sig] = true; }
    function use() external view { require(ready[bytes4(keccak256("enable()"))]); }
}
"""


def test_a_mapping_key_keeps_the_writers_selector(anvil):
    d = O.deployment(*anvil, SOURCE)
    d.deploy("C")
    contracts = d.contracts("C")
    rows = tuple(
        compile_function(d.slither["C"], O.function(d, "C", name), d.at["C"], d.chain(), contracts)
        for name in ("enable", "use")
    )
    joined = sequence(rows)
    result = project(joined, Translation(d.chain(), contracts, d.at["C"]))
    assert result.representation == "cofinite" and not result.excluded, result
    assert not O.passes(d, "C", O.function(d, "C", "use"))
    assert O.transact(d, "C", "enable()")
    assert O.passes(d, "C", O.function(d, "C", "use"))
