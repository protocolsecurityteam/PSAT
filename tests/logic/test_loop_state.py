"""Loop bounds use the state at the test, including the final condition's effects."""

import json

import pytest

from services.logic.continuation import PendingCompilation, generate_function
from services.logic.lower import parameter
from services.logic.model import Formula, encode
from services.logic.solver import Translation, number
from services.logic.terms import CALLER, ORIGIN, mk
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """pragma solidity ^0.8.10;
interface I {function change() external;}
contract C {
 uint[] public items; uint public bound=3; uint public result;
 constructor(){items.push(1);items.push(2);items.push(3);}
 function stored() external {uint n;for(uint i=0;i<items.length;i++){n+=items[i];}result=n;require(n==6);}
 function priorWrite() external {bound=1;uint n;for(uint i=0;i<bound;i++){n++;}result=n;require(n==1);}
 function shrink() external {uint n;for(uint i=0;i<items.length;i++){n++;items.pop();}result=n;require(n==2);}
 function grow() external {uint n;for(uint i=0;i<items.length;i++){n++;if(i==0)items.push(4);}result=n;require(n==4);}
 function cleared() external {delete items;uint n;for(uint i=0;i<items.length;i++){n++;}result=n;require(n==0);}
 function postIncrement() external {uint i;while(i++<bound){}result=i;require(i==4);}
 function conditionWrite() external {while(bound-->0){result++;}require(false);}
 function conditionCall() external {while(next()){result++;}require(bound==0 && result==2);}
 function next() internal returns(bool){bound--;return bound>0;}
 function checkedHeader(uint n) external {uint[3] memory a=[uint(1),2,3];uint i;while(a[i++]<n){}result=i;}
 function rawWrite() external {assembly{sstore(1,1)}uint n;for(uint i=0;i<bound;i++){n++;}result=n;require(n==1);}
 function foreign(I other) external {other.change();for(uint i=0;i<bound;i++){result++;}}
 function selector() external {uint n;while(msg.sig==this.selector.selector && n<3){n++;}result=n;require(n==3);}
 function supplied(uint n) external {for(uint i=0;i<n;i++){result++;}}
}
"""


@pytest.fixture
def d(anvil, tmp_path):
    d = O.deployment(anvil[0], tmp_path, SOURCE)
    d.deploy("C")
    return d


def generate(d, name, **kwargs):
    return generate_function(
        d.slither["C"],
        O.function(d, "C", name),
        d.at["C"],
        d.chain(),
        d.contracts("C"),
        steps=10000,
        loop_iterations=6,
        **kwargs,
    )


def evaluate(d, name, f, args=()):
    fn = O.function(d, "C", name)
    tr = Translation(
        d.chain(),
        d.contracts("C"),
        d.at["C"],
        f.selector,
        bindings={
            CALLER: O.OWNER,
            ORIGIN: O.OWNER,
            mk("callvalue"): 0,
            **{parameter(p, i): a for i, (p, a) in enumerate(zip(fn.parameters, args))},
        },
    )
    return tr.truth(f.success), O.chain_says(d, fn, args, sender=O.OWNER), tr


@pytest.mark.parametrize(
    "name,result",
    [
        ("stored", 6),
        ("priorWrite", 1),
        ("shrink", 2),
        ("grow", 4),
        ("cleared", 0),
        ("postIncrement", 4),
        ("conditionCall", 2),
        ("selector", 3),
        ("rawWrite", 1),
    ],
)
def test_state_bounds_and_last_condition_effects_match_chain(d, name, result):
    f = generate(d, name)
    assert isinstance(f, Formula), f
    predicted, actual, tr = evaluate(d, name, f)
    assert predicted is actual is True, tr.issues
    values = [
        number(tr.translate(u.value))
        for t in f.transitions
        if tr.truth(t.guard) is True
        for u in t.updates
        if u.location[1] == "result"
    ]
    assert values and values[-1] == result
    if name == "stored":
        assert f.state_specialized


def test_condition_revert_is_not_elided(d):
    f = generate(d, "conditionWrite")
    assert isinstance(f, Formula)
    predicted, actual, _ = evaluate(d, "conditionWrite", f)
    assert predicted is actual is False


def test_header_bounds_check_is_not_elided(d):
    f = generate(d, "checkedHeader")
    assert isinstance(f, Formula)
    for n in (0, 1, 2, 3, 4):
        predicted, actual, tr = evaluate(d, "checkedHeader", f, (n,))
        assert predicted is actual, tr.issues


@pytest.mark.parametrize("name", ["foreign", "supplied"])
def test_unresolved_effects_and_inputs_do_not_freeze_entry_bound(d, name):
    f = generate(d, name)
    # An unresolved call can reenter. It cannot silently reuse the entry value 3.
    # Unbounded input remains pending too; modeled raw writes are covered above.
    assert isinstance(f, PendingCompilation), f
    if name == "foreign":
        assert f.reason == "call" and f.blocker == "unresolved:call_target"
    else:
        assert f.reason == "loop_iterations"


def test_state_specialization_survives_checkpoint_resume(d):
    fn = O.function(d, "C", "stored")
    checkpoint = None
    f = None
    for _ in range(100):
        f = generate_function(
            d.slither["C"],
            fn,
            d.at["C"],
            d.chain(),
            d.contracts("C"),
            steps=5,
            loop_iterations=6,
            checkpoint=checkpoint,
        )
        if isinstance(f, Formula):
            break
        checkpoint = json.loads(json.dumps(f.checkpoint))
    assert isinstance(f, Formula)
    assert encode(f) == encode(generate(d, "stored"))
    assert f.state_specialized
