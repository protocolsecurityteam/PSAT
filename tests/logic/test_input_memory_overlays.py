"""Modified forwarding calldata is executed and compared with mined EVM storage."""

import pytest
from eth_utils import keccak

from services.logic.continuation import generate_function
from services.logic.model import Formula
from services.logic.solver import Translation
from services.logic.terms import CALLER, mk, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc


@pytest.mark.parametrize("tail", [b"", b"\x01", bytes(31), bytes(32), bytes(range(33))])
@pytest.mark.parametrize("rewrite", ["mstore(4,caller())", "mstore8(35,7)", "mstore(0,shl(224,SELECTOR))"])
def test_mutated_input_retains_actual_bytes_and_length(anvil, tmp_path, tail, rewrite):
    selector = int.from_bytes(keccak(text="other(uint256)")[:4], "big")
    source = """pragma solidity 0.8.27;
    contract I {uint saved;function act(uint x)external{saved=x;}function other(uint x)external{saved=x+1;}}
    contract P {uint saved;address target;constructor(address t){target=t;}
    fallback()external{assembly {
      calldatacopy(0,0,calldatasize()) REWRITE
      let ok:=delegatecall(gas(),sload(1),0,calldatasize(),0,0)
      if iszero(ok){revert(0,0)}
    }}}
    """.replace("REWRITE", rewrite.replace("SELECTOR", str(selector)))
    d = O.deployment(anvil[0], tmp_path, source)
    impl = d.deploy("I")
    at = d.deploy("P", ("address",), (impl,))
    known = d.contracts("P", "I")
    f = generate_function(
        d.slither["I"],
        O.function(d, "I", "act"),
        at,
        d.chain(),
        known,
        code_of=lambda a: impl if a == at else a,
        own_code=known.get,
        steps=30000,
    )
    assert isinstance(f, Formula), f
    binds = {CALLER: O.OWNER, mk("callvalue"): 0, f.parameters[0]: tail}
    for term in (f.success, *(e.guard for e in f.effects), *(e.value for e in f.effects)):
        binds.update({u: True for u in subterms(term, "unknown") if u[1] == "unsupported:raw_call_resources"})
    tr = Translation(d.chain(), known, at, f.selector, bindings=binds)
    predicted = tr.truth(f.success)
    values = [int(str(tr.translate(e.value))) for e in f.effects if tr.truth(e.guard) is True]
    actual = O.transact_data(d, at, f.selector.to_bytes(4, "big") + tail)
    stored = int(rpc(d.url, "eth_getStorageAt", [O.hex20(at), "0x0", "latest"]), 16)
    assert predicted is actual, (predicted, actual, tr.issues)
    assert stored == (values[-1] if values else 0), (stored, values)
    assert not tr.issues


def test_argument_patch_keeps_selector_without_decoding_unrelated_array(anvil, tmp_path):
    source = """pragma solidity 0.8.27;
    contract I {uint saved;
      function act(uint x)external{saved=x;}
      function unrelated(uint[] calldata)external{saved=9;}
    }
    contract P {uint saved;address target;constructor(address t){target=t;}
      fallback()external{assembly{
        calldatacopy(0,0,calldatasize()) mstore(4,7)
        let ok:=delegatecall(gas(),sload(1),0,calldatasize(),0,0)
        if iszero(ok){revert(0,0)}
      }}
    }"""
    d = O.deployment(anvil[0], tmp_path, source)
    impl = d.deploy("I")
    at = d.deploy("P", ("address",), (impl,))
    known = d.contracts("P", "I")
    f = generate_function(
        d.slither["I"],
        O.function(d, "I", "act"),
        at,
        d.chain(),
        known,
        own_code=known.get,
        code_of=lambda a: impl if a == at else a,
        steps=30000,
    )
    assert isinstance(f, Formula), f
    bindings = {CALLER: O.OWNER, mk("callvalue"): 0, f.parameters[0]: bytes(32)}
    for t in (f.success, *(e.guard for e in f.effects), *(e.value for e in f.effects)):
        bindings.update({u: True for u in subterms(t, "unknown") if u[1] == "unsupported:raw_call_resources"})
    tr = Translation(d.chain(), known, at, f.selector, bindings=bindings)
    assert tr.truth(f.success) is True
    assert O.transact_data(d, at, f.selector.to_bytes(4, "big") + bytes(32))
    assert int(rpc(d.url, "eth_getStorageAt", [O.hex20(at), "0x0", "latest"]), 16) == 7


@pytest.mark.parametrize("length", [0, 1, 2, 3, 4, 5])
def test_header_write_does_not_invent_four_input_bytes(anvil, tmp_path, length):
    selector = int.from_bytes(keccak(text="named()")[:4], "big")
    source = """pragma solidity 0.8.27;
    contract I {uint saved;function named()external{saved=11;}
      receive()external payable{saved=22;}fallback()external{saved=33;}}
    contract P {uint saved;address target;constructor(address t){target=t;}
      fallback()external{assembly{
        calldatacopy(0,0,calldatasize()) mstore(0,shl(224,SELECTOR))
        let ok:=delegatecall(gas(),sload(1),0,calldatasize(),0,0)
        if iszero(ok){revert(0,0)}
      }}
    }""".replace("SELECTOR", str(selector))
    d = O.deployment(anvil[0], tmp_path, source)
    at = d.deploy("P", ("address",), (d.deploy("I"),))
    known = d.contracts("P", "I")
    f = generate_function(
        d.slither["P"], O.function(d, "P", "fallback"), at, d.chain(), known, own_code=known.get, steps=30000
    )
    assert isinstance(f, Formula), f
    payload = bytes(length)
    bindings = {CALLER: O.OWNER, mk("callvalue"): 0, f.parameters[0]: payload}
    for t in (f.success, *(e.guard for e in f.effects), *(e.value for e in f.effects)):
        bindings.update({u: True for u in subterms(t, "unknown") if u[1] == "unsupported:raw_call_resources"})
    tr = Translation(d.chain(), known, at, f.selector, bindings=bindings)
    assert tr.truth(f.success) is True
    values = [int(str(tr.translate(e.value))) for e in f.effects if tr.truth(e.guard) is True]
    assert O.transact_data(d, at, payload)
    actual = int(rpc(d.url, "eth_getStorageAt", [O.hex20(at), "0x0", "latest"]), 16)
    assert values == [actual] == [22 if length == 0 else 33 if length < 4 else 11]
