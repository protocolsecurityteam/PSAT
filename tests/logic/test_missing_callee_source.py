"""Missing verified source is distinct from transport failure and empty runtime."""

import importlib
from types import SimpleNamespace

import pytest

from services.clients.etherscan import VerifiedSourceUnavailable
from services.logic import deployment
from services.logic.calls import CallExecutor
from services.logic.formula import compile_function
from services.logic.linker import Linker
from services.logic.lower import State
from services.logic.model import CallRequest, Limits, ReadError
from services.logic.terms import FALSE, TRUE, const, mk, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401


def session():
    return SimpleNamespace(execute=lambda *a, **kw: SimpleNamespace(first=lambda: None))


def test_actual_unverified_exception_is_a_source_status(monkeypatch):
    def missing(*args, **kwargs):
        raise VerifiedSourceUnavailable("not published")

    monkeypatch.setattr(importlib.import_module("services.discovery.fetch"), "fetch", missing)
    monkeypatch.setattr("services.clients.rpc.rpc_request", lambda *a, **kw: "0x7b")
    result = deployment.deployment_formulas(session(), "0x" + "01" * 20, 1, "unused")
    assert result["status"] == "not_verified" and result["functions"] == {}


def test_source_transport_error_is_still_operational(monkeypatch):
    def failed(*args, **kwargs):
        raise ReadError("source transport failed")

    monkeypatch.setattr(importlib.import_module("services.discovery.fetch"), "fetch", failed)
    monkeypatch.setattr("services.clients.rpc.rpc_request", lambda *a, **kw: "0x7b")
    with pytest.raises(ReadError, match="source transport failed"):
        deployment.deployment_formulas(session(), "0x" + "01" * 20, 1, "unused")


class NoSource:
    def get(self, *args):
        raise AssertionError("empty runtime requested source")


@pytest.mark.parametrize("address", [0, 4, 0xDEAD, 0x2710, 0x123456789])
def test_empty_runtime_is_not_treated_as_a_verified_callee_or_as_failure(address):
    reads = SimpleNamespace(code=lambda at: b"")
    call = mk("call", const(address, "address"), "read()", (), True, const(20, "address"), (("scalar", "uint256"),), ())
    guard, _, _ = Linker(reads, NoSource(), 20, Limits()).callee(call, 0)
    executor = CallExecutor(reads, NoSource(), 20, Limits())
    after, _ = executor.execute(CallRequest(call, (), const(0)), State(TRUE, {}, {}), 0, True)
    for value in (guard, after.pc):
        assert value not in (TRUE, FALSE)
        assert any(t[1] == f"unsupported:empty_runtime_call:{address:#x}" for t in subterms(value, "unknown"))


def test_failed_code_read_is_not_empty_runtime():
    def failed(at):
        raise ReadError("node unavailable")

    reads = SimpleNamespace(code=failed)
    call = mk("call", const(99, "address"), "read()", (), True, const(20, "address"), (), ())
    with pytest.raises(ReadError, match="node unavailable"):
        CallExecutor(reads, NoSource(), 20, Limits()).execute(
            CallRequest(call, (), const(0)), State(TRUE, {}, {}), 0, True
        )


SOURCE = """pragma solidity ^0.8.10;
interface G { function allowed(address) external view returns(bool); }
contract C {
 address public owner; G public guard; uint public value;
 constructor(){owner=msg.sender;}
 function admin() external {require(msg.sender==owner);value=1;}
 function emptyCall() external {require(G(address(0xdead)).allowed(msg.sender));value=2;}
 function identityPrecompile() external view returns(bytes memory) {
  (bool ok,bytes memory result)=address(4).staticcall(hex"123456");require(ok);return result;
 }
}"""


def test_empty_linked_target_does_not_destroy_other_functions(anvil, tmp_path):
    from services.logic.expansion import expand_formula
    from tests.support.anvil import rpc

    d = O.deployment(anvil[0], tmp_path, SOURCE)
    d.deploy("C")
    reads = d.chain()

    class Contracts:
        def get(self, at, default=None):
            if at == d.at["C"]:
                return d.slither["C"]
            raise VerifiedSourceUnavailable(f"unverified {at}")

    for name in ("admin", "emptyCall"):
        fn = O.function(d, "C", name)
        formula = compile_function(d.slither["C"], fn, d.at["C"], reads, Contracts())
        result = expand_formula(formula, reads, Contracts()).callers
        if name == "admin":
            assert result.complete and result.members == (O.OWNER,)
        else:
            assert not result.complete and any("empty_runtime_call" in i.detail for i in result.issues)
        for who in O.ACCOUNTS:
            assert O.chain_says(d, fn, (), sender=who) is (name == "admin" and who == O.OWNER)
    # Real empty-runtime accounts can still execute precompile behavior.
    assert reads.code(4) == b""
    assert rpc(d.url, "eth_call", [{"to": O.hex20(4), "data": "0x123456"}, "latest"]) == "0x123456"


def test_unverified_deployed_callee_qualifies_its_formula_without_aborting(monkeypatch, anvil, tmp_path):
    from tests.support.anvil import rpc

    source = """pragma solidity ^0.8.10;
contract G {function allowed(address) external pure returns(bool){return true;}}
contract C {G guard; uint value; constructor(G g){guard=g;}
function act() external {require(guard.allowed(msg.sender));value=1;}}
"""
    d = O.deployment(anvil[0], tmp_path, source)
    target = d.deploy("G")
    d.deploy("C", ("address",), (target,))
    seen = []

    def unpublished(address, **kwargs):
        seen.append(address)
        raise VerifiedSourceUnavailable("callee source absent")

    monkeypatch.setattr(importlib.import_module("services.discovery.fetch"), "fetch", unpublished)
    monkeypatch.setattr(
        "services.clients.rpc.rpc_request", lambda url, method, params, **kw: rpc(d.url, method, params)
    )
    with deployment._deployment_inputs(session(), 1, "unused", d.chain().block) as (reads, contracts):
        contracts._built[O.hex20(d.at["C"])] = d.slither["C"]
        formula = compile_function(d.slither["C"], O.function(d, "C", "act"), d.at["C"], reads, contracts)
    assert seen == [O.hex20(target)]
    assert any(t[1] == f"unverified:{target:#x}" for t in subterms(formula.success, "unknown"))
