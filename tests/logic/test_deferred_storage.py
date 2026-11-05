"""State-independent projection proofs; storage interpretations never become call arguments."""

import pytest

from services.logic.expansion import Selection, expand_formula
from services.logic.formula import compile_function
from services.logic.model import BudgetExceeded
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

SOURCE = """pragma solidity ^0.8.10;
contract C {
 address public owner; mapping(bytes32=>address) public values; mapping(address=>bool) public roles; uint public value;
 constructor(){owner=msg.sender;values[bytes32(0)]=address(5);roles[msg.sender]=true;assembly{sstore(999,77)}}
 function set(bytes32 key,address next) external {require(msg.sender==owner);values[key]=next;}
 function constrained(bytes32 key,address next) external {require(msg.sender==owner);require(next==address(5));
values[key]=next;}
 function unchanged(bytes32 key,address next) external {require(msg.sender==owner);require(next==values[key]);
values[key]=next;}
 function equalKeys(bytes32 a,bytes32 b) external {require(a==b);require(values[a]!=values[b]);value=1;}
 function member() external {require(roles[msg.sender]);value=1;}
 function chosenOwner(bytes32 key) external {require(msg.sender==values[key]);value=1;}
 function fixedKey(address next) external {require(msg.sender==owner);values[bytes32(0)]=next;}
}"""


class NoSnapshot:
    def __init__(self, reads):
        self.reads, self.block, self.dumps = reads, reads.block, 0

    def __getattr__(self, name):
        return getattr(self.reads, name)

    def storage_dump(self, address):
        self.dumps += 1
        raise BudgetExceeded("snapshot deliberately unavailable")


@pytest.fixture
def d(anvil, tmp_path):
    deployed = O.deployment(anvil[0], tmp_path, SOURCE)
    deployed.deploy("C")
    return deployed


def expand(d, name):
    fn = O.function(d, "C", name)
    reads = NoSnapshot(d.chain())
    formula = compile_function(d.slither["C"], fn, d.at["C"], reads, d.contracts("C"))
    result = expand_formula(formula, reads, d.contracts("C"), selection=Selection(False, (0,)))
    return result.effects[0], reads


def test_owner_can_choose_a_change_without_enumerating_the_mapping(d):
    result, reads = expand(d, "set")
    assert result.complete and result.members == (O.OWNER,)
    assert not result.issues and reads.dumps == 0
    fn = O.function(d, "C", "set")
    for sender in (O.OWNER, O.ACCOUNTS[1]):
        assert O.chain_says(d, fn, (0, 7), sender=sender) is (sender == O.OWNER)
    assert O.transact(d, d.at["C"], "set(bytes32,address)", ("bytes32", "address"), (bytes(32), O.hex20(7)))
    # Independent state observation verifies the effect, not merely non-reversion.
    assert int(rpc(d.url, "eth_getStorageAt", [O.hex20(d.at["C"]), hex(O.slot(0, 1)), "latest"]), 16) == 7


@pytest.mark.parametrize("name", ["unchanged", "equalKeys"])
def test_shared_storage_reads_preserve_equalities(d, name):
    result, reads = expand(d, name)
    assert result.complete and result.representation == "finite" and not result.members
    assert reads.dumps == 0
    fn = O.function(d, "C", name)
    if name == "unchanged":
        assert O.chain_says(d, fn, (0, 5), sender=O.OWNER)
        assert not O.chain_says(d, fn, (0, 7), sender=O.OWNER)
    else:
        assert not O.chain_says(d, fn, (0, 0), sender=O.OWNER)


@pytest.mark.parametrize("name", ["constrained", "member", "chosenOwner"])
def test_state_dependent_relations_fall_back_without_false_completeness(d, name):
    result, reads = expand(d, name)
    assert reads.dumps > 0
    assert not result.complete and result.issues


def test_concrete_storage_reads_still_use_actual_chain_values(d):
    result, reads = expand(d, "fixedKey")
    assert result.complete and result.members == (O.OWNER,)
    assert reads.dumps == 0


def test_fixed_storage_function_cannot_adapt_to_each_argument(anvil, tmp_path):
    source = """pragma solidity ^0.8.10;
contract C {mapping(bool=>bool) values;uint value;
constructor(){values[true]=true;}
function act(bool x) external {require(x!=values[x]);value=1;}}
"""
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    result, reads = expand(d, "act")
    # Identity-valued storage admits neither argument. Zero-valued storage admits true.
    # Choosing the storage interpretation inside the argument quantifier would falsely open it.
    assert not result.complete and reads.dumps == 1
    fn = O.function(d, "C", "act")
    for sender in (O.OWNER, O.ACCOUNTS[1]):
        for value in (False, True):
            assert not O.chain_says(d, fn, (value,), sender=sender)
