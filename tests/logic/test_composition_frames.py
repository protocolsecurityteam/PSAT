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
    assert result.representation == "cofinite" and result.excluded == (0,), result
    assert not O.passes(d, "C", O.function(d, "C", "use"))
    assert O.transact(d, "C", "enable()")
    assert O.passes(d, "C", O.function(d, "C", "use"))


def test_sequence_does_not_reuse_a_specialized_callee_after_retargeting(anvil, tmp_path):
    source = """pragma solidity ^0.8.10;
interface I {function allowed() external view returns(bool);}
contract Old {function allowed() external pure returns(bool){return false;}}
contract New {function allowed() external pure returns(bool){return true;}}
contract C {I manager;uint value;constructor(address a){manager=I(a);}
function setManager(address a) external {manager=I(a);}
function act() external {require(manager.allowed());value=1;}}
"""
    d = O.deployment(anvil[0], tmp_path, source)
    old = d.deploy("Old")
    new = d.deploy("New")
    d.deploy("C", ("address",), (old,))
    contracts = d.contracts("C", "Old", "New")
    rows = tuple(
        compile_function(d.slither["C"], O.function(d, "C", name), d.at["C"], d.chain(), contracts)
        for name in ("setManager", "act")
    )
    assert rows[1].state_specialized
    result = project(sequence(rows), Translation(d.chain(), contracts, d.at["C"]))
    assert not result.complete
    assert O.transact(d, "C", "setManager(address)", ("address",), (O.hex20(new),))
    assert O.passes(d, "C", O.function(d, "C", "act"))


def test_call_summary_retains_mutable_guard_for_an_earlier_unpause(anvil, tmp_path):
    from eth_utils import to_checksum_address

    target_source = """pragma solidity ^0.8.10;
contract T {bool public paused=true;uint value;
function unpause() external {paused=false;}
function act() external {require(!paused);value=1;}}
"""
    target = O.deployment(anvil[0], tmp_path, target_source).deploy("T")
    source = (
        target_source
        + """
contract C {T constant target=T(TARGET);function act() external {target.act();}}
""".replace("TARGET", to_checksum_address(O.hex20(target)))
    )
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    d.at["T"] = target
    contracts = d.contracts("C", "T")
    rows = tuple(
        compile_function(d.slither[c], O.function(d, c, name), d.at[c], d.chain(), contracts)
        for c, name in (("T", "unpause"), ("C", "act"))
    )
    assert rows[1].state_specialized is False
    result = project(sequence(rows), Translation(d.chain(), contracts, d.at["C"]))
    assert result.representation == "cofinite" and result.excluded == (0,), result
    assert not O.passes(d, "C", O.function(d, "C", "act"))
    assert O.transact(d, "T", "unpause()")
    assert O.passes(d, "C", O.function(d, "C", "act"))


def test_legacy_formula_hash_is_preserved_but_context_is_unproved():
    from services.logic.model import Formula, decode_formula, encode
    from services.logic.terms import TRUE

    row = Formula(1, 2, "f()", 0, (), TRUE, (), ())
    saved = encode(row)
    del saved["value"]["state_specialized"]
    restored = decode_formula(saved)
    assert restored.state_specialized is None
    assert encode(restored) == saved
