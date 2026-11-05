"""Decoded delegates execute their bytes; unfinished input retains its exact region."""

import pytest

from services.logic.continuation import PendingCompilation, generate_function
from services.logic.formula import compile_function
from services.logic.model import Formula
from services.logic.solver import Translation
from services.logic.terms import CALLER, mk, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.logic.test_retained_operations import mapping, operation


@pytest.mark.parametrize(
    "offset,size,passes", [(32, 36, True), (32, 4, False), (33, 36, False), (32, 68, True), (None, 36, True)]
)
def test_delegate_region_executes_or_retains_exact_bytes(anvil, tmp_path, offset, size, passes):
    source = (
        """pragma solidity ^0.8.10;
contract D {uint public x;function put(uint n) external {x=n;}}
contract C {uint public x;address d;constructor(address a){d=a;}
function go(PARAMETERS) external {bytes memory data=abi.encodeWithSelector(D.put.selector,uint(7));
address target=d;bool ok;
assembly {ok:=delegatecall(gas(),target,add(data,OFFSET),SIZE,0,0)}
require(ok);require(x==7);}}
""".replace("OFFSET", str(offset) if offset is not None else "offset")
        .replace("SIZE", str(size))
        .replace("PARAMETERS", "" if offset is not None else "uint offset")
    )
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("D"),))
    fn = O.function(d, "C", "go")
    assert O.chain_says(d, fn, [] if offset is not None else [32], sender=O.OWNER) is passes
    f = compile_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "D"))
    if offset is not None:
        complete = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "D"), steps=10000)
        assert isinstance(complete, Formula), complete
        bindings = {CALLER: O.OWNER, mk("callvalue"): 0}
        bindings.update(
            {t: True for t in subterms(complete.success, "unknown") if t[1] == "unsupported:raw_call_resources"}
        )
        tr = Translation(d.chain(), d.contracts("C", "D"), d.at["C"], complete.selector, bindings=bindings)
        assert tr.truth(complete.success) is passes, tr.issues
        return
    delegates = [t for effect in f.effects for t in subterms(effect.target, "delegate")]
    assert delegates
    region = delegates[0][2]
    assert region[:2] == ("opaque", "unsupported:delegate_data")
    start, length = region[2]
    assert length[:2] == ("const", size)
    assert start[:2] == ("op", "add")
    assert subterms(start, "arg")  # The unfinished offset is retained, never replaced with a constant.
    # Numeric pointer identity is separate from its contents. The resumable operation
    # keeps the referenced object, so its exact bytes are still available for execution.
    assert subterms(start, "memory_address")
    pending = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "D"), steps=10000)
    assert isinstance(pending, PendingCompilation) and pending.reason == "call"
    saved = dict(operation(pending))
    state = mapping(saved["state"]["$state"])
    pointers = subterms(saved["calldata"], "memory_address")
    assert pointers and all(p[1] == saved["memory_frame"] for p in pointers)
    object_ids = {t[1] for p in pointers for t in subterms(p, "memory_object")}
    encoded = [v for k, v in state["store"]["$map"] if k["$tuple"][:1] == ["heap"] and k["$tuple"][1] in object_ids]
    assert len(encoded) == 1 and encoded[0][0] == "enc"
    tr = Translation(
        d.chain(), d.contracts("C", "D"), d.at["C"], f.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 0}
    )
    payload = tr.translate(encoded[0])
    assert isinstance(payload, bytes) and len(payload) == 36
    assert int.from_bytes(payload[4:], "big") == 7
    # Retaining input is not evidence of a modeled delegate state transition.
    assert any(t[1] == "unsupported:external_transition" for t in subterms(f.success, "unknown"))
