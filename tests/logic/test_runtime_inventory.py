"""Mutability annotations do not establish the effects of a deployed runtime query."""

from contextlib import contextmanager

from eth_utils import keccak

from services.logic import deployment
from services.logic.model import decode_formula
from services.logic.solver import Translation
from services.logic.terms import CALLER, mk, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc


def generate(monkeypatch, d, at, tmp_path):
    reads = d.chain()

    @contextmanager
    def inputs(*args):
        builds = deployment.Builds(lambda a: None, lambda a: None, tmp_path, reads)
        builds._built.update({O.hex20(addr): d.slither[name] for name, addr in d.at.items()})
        yield reads, builds

    monkeypatch.setattr(deployment, "_deployment_inputs", inputs)
    return deployment.deployment_formulas(None, O.hex20(at), 1, "unused", block=reads.block), reads


def test_legacy_constant_assembly_write_is_not_dropped(monkeypatch, anvil, tmp_path):
    source = """pragma solidity 0.4.19;
    contract C {address owner;uint saved;
      function C(){owner=msg.sender;}
      function change() external constant {require(msg.sender==owner);assembly{sstore(1,77)}}
      function()external payable{}
    }"""
    d = O.deployment(anvil[0], tmp_path, source, version="0.4.19")
    at = d.deploy("C")
    assert O.function(d, "C", "change").view
    result, reads = generate(monkeypatch, d, at, tmp_path)
    f = decode_formula(result["functions"]["change()"])
    for sender in O.ACCOUNTS[:2]:
        tr = Translation(
            reads, d.contracts("C"), at, f.selector, bindings={CALLER: sender, mk("callvalue"): 0, f.parameters[0]: b""}
        )
        assert tr.truth(f.success) is (sender == O.OWNER)
        assert any(tr.truth(e.guard) is True for e in f.effects) is (sender == O.OWNER)
        assert O.transact_data(d, at, keccak(text="change()")[:4], sender=sender) is (sender == O.OWNER)
    assert int(rpc(d.url, "eth_getStorageAt", [O.hex20(at), "0x1", "latest"]), 16) == 77


def test_pure_implementation_entry_keeps_proxy_writes(monkeypatch, anvil, tmp_path):
    source = """pragma solidity 0.8.27;
    contract I {function read()external pure returns(uint){return 7;}}
    contract P {uint saved;address target;constructor(address t){target=t;}
      fallback()external {assembly {
        sstore(0,add(sload(0),1))
        calldatacopy(0,0,calldatasize())
        let ok:=delegatecall(gas(),sload(1),0,calldatasize(),0,0)
        if iszero(ok){revert(0,0)}
        returndatacopy(0,0,returndatasize()) return(0,returndatasize())
      }}
    }"""
    d = O.deployment(anvil[0], tmp_path, source)
    at = d.deploy("P", ("address",), (d.deploy("I"),))
    result, reads = generate(monkeypatch, d, at, tmp_path)
    f = decode_formula(result["functions"]["read()"])
    bindings = {CALLER: O.OWNER, mk("callvalue"): 0, f.parameters[0]: b""}
    for t in (f.success, *(e.guard for e in f.effects), *(e.value for e in f.effects)):
        bindings.update({u: True for u in subterms(t, "unknown") if u[1] == "unsupported:raw_call_resources"})
    tr = Translation(reads, d.contracts("P", "I"), at, f.selector, bindings=bindings)
    assert tr.truth(f.success) is True
    effects = [e for e in f.effects if tr.truth(e.guard) is True]
    assert len(effects) == 1 and int(str(tr.translate(effects[0].value))) == 1
    assert O.transact_data(d, at, f.selector.to_bytes(4, "big"))
    assert int(rpc(d.url, "eth_getStorageAt", [O.hex20(at), "0x0", "latest"]), 16) == 1
