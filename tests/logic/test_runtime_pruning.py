"""Unframed caller values cannot refute a live callee branch."""

import pytest

from services.logic.continuation import PendingCompilation, generate_function
from services.logic.formula import compile_function
from services.logic.solver import Translation
from services.logic.terms import CALLER, mk
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SRC = """pragma solidity 0.8.27;
contract B {function check(bytes4 s) external pure returns(bool){
 if(s==bytes4(keccak256("act()"))){uint z;assembly{z:=mload(512)}require(z==0);return true;}
 return false;
}}
contract C {B b;uint saved;constructor(address at){b=B(at);}
function act() external {require(b.check(msg.sig));saved=1;}}
"""


@pytest.mark.parametrize("prune", [False, True])
@pytest.mark.parametrize("runtime", [False, True])
@pytest.mark.parametrize("retained", [False, True])
def test_nested_unframed_sig_does_not_refute_live_branch(anvil, tmp_path, monkeypatch, runtime, retained, prune):
    if not prune:
        from services.logic.calls import CallExecutor

        monkeypatch.setattr(CallExecutor, "_refuted", lambda self, t: False)
    d = O.deployment(anvil[0], tmp_path, SRC)
    d.deploy("C", ("address",), (d.deploy("B"),))
    fn = O.function(d, "C", "act")
    known = d.contracts("B", "C")
    kwargs = {"own_code": known.get} if runtime else {}
    gen = generate_function if retained else compile_function
    f = gen(d.slither["C"], fn, d.at["C"], d.chain(), known, **kwargs)
    actual = O.passes(d, "C", fn, ())
    assert actual is True
    if isinstance(f, PendingCompilation):
        return
    binds = {CALLER: O.OWNER, mk("callvalue"): 0}
    if runtime:
        binds[f.parameters[0]] = b""
    tr = Translation(d.chain(), known, d.at["C"], f.selector, bindings=binds)
    predicted = tr.truth(f.success)
    assert predicted is not False, (runtime, retained, predicted, f.success, tr.issues)


@pytest.mark.parametrize("leaf", [mk("sig"), mk("this"), mk("frame_value", 1, 0)])
def test_unframed_leaves_are_not_default_environment(leaf):
    from services.logic.linker import Linker
    from services.logic.model import Limits
    from services.logic.terms import const, mk_cmp

    linker = Linker(None, {}, 123, Limits())
    assert not linker._refuted(mk_cmp("eq", leaf, const(999)))


@pytest.mark.parametrize("runtime", [False, True])
def test_actual_this_argument_stays_placed(anvil, tmp_path, runtime):
    src = """pragma solidity 0.8.27;
 contract B {function check(address x) external view returns(bool){
 if(x==msg.sender){uint z;assembly{z:=mload(512)}require(z==0);return true;}return false;}}
 contract C {B b;uint saved;constructor(address at){b=B(at);}
function act() external {require(b.check(address(this)));saved=1;}}"""
    d = O.deployment(anvil[0], tmp_path, src)
    d.deploy("C", ("address",), (d.deploy("B"),))
    fn = O.function(d, "C", "act")
    known = d.contracts("B", "C")
    kw = {"own_code": known.get} if runtime else {}
    f = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), known, **kw)
    assert O.passes(d, "C", fn, ())
    if isinstance(f, PendingCompilation):
        return
    bind = {CALLER: O.OWNER, mk("callvalue"): 0}
    if runtime:
        bind[f.parameters[0]] = b""
    tr = Translation(d.chain(), known, d.at["C"], f.selector, bindings=bind)
    assert tr.truth(f.success) is not False
