"""Ignoring a call result does not make its reentrant state changes disappear."""

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.logic._oracle import analyze_function

SOURCE = """
pragma solidity 0.8.27;
interface I { function close() external; }
contract Callee {
    function enter() external { I(msg.sender).close(); }
}
contract C {
    bool open = true;
    function close() external { open = false; }
    function run(address target) external {
        target.call(abi.encodeWithSignature("enter()"));
        require(open);
    }
}
"""


def test_discarded_call_result_cannot_hide_a_required_state_transition(anvil):
    d = O.deployment(*anvil, SOURCE)
    d.deploy("Callee")
    d.deploy("C")
    fn = O.function(d, "C", "run")
    assert not O.passes(d, "C", fn, [d.at["Callee"]])
    formula, answer = O.engine_says(d, fn, [d.at["Callee"]], contracts=d.contracts("C", "Callee"))
    O.agrees(formula, answer, False)
    row = analyze_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "Callee"))
    assert not row.callers.complete
    assert any("external_transition" in i.detail for i in row.callers.issues)
