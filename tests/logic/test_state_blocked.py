""" "Nobody, ever" (restricted, complete, nobody listed) only where what refutes everyone reads nothing a transaction
may change: a business condition mixing the arguments with state (``amount >= lo && amount <= hi``, ``lo > hi``
now, both owner-settable) blocks everyone only as things stand. With such conditions set aside, whoever the identity
core lets through is named, holding only on them (``conditions``, ``allowed`` conditional); with no core, not
determined. Each variable is named, ``state_blocks_everyone:<variable>``. A condition on constants or a variable no
entry point writes still refutes everyone. Against anvil."""

from __future__ import annotations

import re

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

SOURCE = """
pragma solidity 0.8.27;

contract C {
    uint256 public lo = 10;
    uint256 public hi = 5;
    uint256 public fixedLo = 10;  // set at deployment, written by no entry point
    uint256 public constant HI = 5;
    address public owner;
    uint256 public x;
    bool public paused = true;
    constructor() { owner = msg.sender; }
    function setRange(uint256 l, uint256 h) external { require(msg.sender == owner); lo = l; hi = h; }
    function setPaused(bool p) external { require(msg.sender == owner); paused = p; }
    function act(uint256 amount) external { require(amount >= lo && amount <= hi); x = amount; }
    function actOwner(uint256 amount) external { require(amount >= lo && amount <= hi && msg.sender == owner); x = 1; }
    function actConstant(uint256 amount) external { require(amount >= 10 && amount <= HI); x = amount; }
    function actFixed(uint256 amount) external { require(amount >= fixedLo && amount <= HI); x = amount; }
    function paus(uint256 amount) external { require(!paused); x = amount; }
}

// The same with an owner-only delegatecall into code the owner names: ``fixedLo`` is no longer fixed.
contract CD is C {
    function exec(address t, bytes calldata d) external {
        require(msg.sender == owner);
        (bool ok,) = t.delegatecall(d);
        require(ok);
    }
}

contract Setter is C {
    function set() external { fixedLo = 0; }
}

// ``fixedLo`` (slot 2) written by no function of ``ViaExt``'s own: an external library's assembly writes it, run by
// ``DELEGATECALL`` in ``ViaExt``'s storage.
library ExtLib {
    function raw(uint256 v) external { assembly { sstore(2, v) } }
}

contract ViaExt {
    uint256 lo = 10;
    uint256 hi = 5;
    uint256 fixedLo = 10;
    address owner;
    uint256 x;
    constructor() { owner = msg.sender; }
    function rawFixed(uint256 v) external { require(msg.sender == owner); ExtLib.raw(v); }
    function actRaw(uint256 amount) external { require(amount >= fixedLo && amount <= 5); x = amount; }
}

// ``C``'s code behind a proxy whose admin may point it at code that writes anything.
contract Proxy {
    uint256 lo = 10;  // ``C``'s layout, as it deployed it
    uint256 hi = 5;
    uint256 fixedLo = 10;
    address owner;
    uint256 x;
    bool paused = true;
    address impl;
    address admin;
    constructor(address i) { impl = i; admin = msg.sender; owner = msg.sender; }
    function upgradeTo(address i) external { require(msg.sender == admin); impl = i; }
    fallback() external payable {
        address i = impl;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let r := delegatecall(gas(), i, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch r case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
}
"""

OWNER = O.OWNER
AMOUNTS = [{"amount": a} for a in (0, 5, 7, 10, 50)]


def _setup(d):
    d.deploy("C")
    d.deploy("CD")
    d.deploy("Setter")
    d.deploy("Proxy", ("address",), (d.at["C"],))
    library = d.deploy("ExtLib")
    d.compiled["ViaExt"]["bin"] = re.sub(r"__\$[0-9a-f]{34}\$__", "%040x" % library, d.compiled["ViaExt"]["bin"])
    d.deploy("ViaExt")


PROBES = [
    O.Probe(
        SOURCE,
        _setup,
        (
            *(("C", f, ()) for f in ("act", "actOwner", "actConstant", "actFixed", "paus")),
            ("CD", "actFixed", ()),
            ("ViaExt", "actRaw", ()),
        ),
    )
]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def _set_range(d):
    assert O.transact(d, "C", "setRange(uint256,uint256)", ("uint256", "uint256"), (0, 100))


def test_a_business_condition_on_settable_state_blocks_everyone_only_as_things_stand(d):
    v = O.check(d, "C", "act", O.verdict(d, "C", "act"), samples=AMOUNTS, open_at=False)
    assert not O.nobody(v), v
    with O.snapshot(d):  # the owner widens the range: every stranger passes
        _set_range(d)
        assert O.strangers_passing(d, "C", O.function(d, "C", "act"), {"amount": 50}) == {True}
    if v.openness == "not_determined":
        assert {"state_blocks_everyone:lo", "state_blocks_everyone:hi"} <= set(v.gaps)


def test_an_identity_core_behind_such_a_condition_names_its_holders_on_it(d):
    v = O.check(d, "C", "actOwner", O.verdict(d, "C", "actOwner"), samples=AMOUNTS, open_at=False)
    O.sound(v, {OWNER})
    assert not O.nobody(v), v
    act_owner = O.function(d, "C", "actOwner")
    with O.snapshot(d):  # the owner widens the range: the owner passes, no stranger does
        _set_range(d)
        assert O.passes(d, "C", act_owner, {"amount": 50}, sender=OWNER)
        assert O.strangers_passing(d, "C", act_owner, {"amount": 50}) == {False}
    if v.conditions:
        assert v.conditions == {OWNER: "business"} and v.allowed == "conditional"


@pytest.mark.parametrize("name", ["actConstant", "actFixed"])
def test_a_condition_on_what_never_changes_still_refutes_everyone(d, name):
    v = O.check(d, "C", name, O.verdict(d, "C", name), samples=AMOUNTS)
    assert O.nobody(v), v
    assert not any(g.startswith("state_blocks_everyone") for g in v.gaps)
    with O.snapshot(d):  # what the owner may set changes nothing here
        _set_range(d)
        for amount in AMOUNTS:
            assert O.strangers_passing(d, "C", O.function(d, "C", name), amount) == {False}


def test_a_pause_is_open_once_it_allows(d):
    v = O.check(d, "C", "paus", O.verdict(d, "C", "paus"), open_at=False, samples=AMOUNTS)
    assert v.openness == "open" and v.allowed == "later"
    with O.snapshot(d):
        assert O.transact(d, "C", "setPaused(bool)", ("bool",), (False,))
        assert O.strangers_passing(d, "C", O.function(d, "C", "paus"), {"amount": 1}) == {True}


def test_a_condition_on_a_slot_a_delegatecall_can_write_is_never_nobody_ever(d):
    # ``CD``'s owner may delegatecall code that writes ``fixedLo``: what reads it can change.
    v = O.check(d, "CD", "actFixed", O.verdict(d, "CD", "actFixed"), samples=AMOUNTS, open_at=False)
    assert not O.nobody(v), v
    with O.snapshot(d):
        data = O.calldata(O.function(d, "Setter", "set"))
        assert O.transact(d, "CD", "exec(address,bytes)", ("address", "bytes"), (d.at["Setter"], data))
        assert O.strangers_passing(d, "CD", O.function(d, "CD", "actFixed"), {"amount": 5}) == {True}


def test_a_condition_behind_a_proxy_is_never_nobody_ever(d):
    # ``C`` run at the proxy's address: its admin may upgrade to code that writes the slot, so nothing in it is fixed.
    proxy = d.at["Proxy"]
    v = O.verdict(d, "C", "actFixed", at=proxy)
    assert not O.nobody(v), v
    O.check(d, "C", "actFixed", v, at=proxy, samples=AMOUNTS, open_at=False)


def test_a_slot_an_external_library_can_write_is_never_nobody_ever(d, monkeypatch):
    # ``ExtLib.raw`` runs by ``DELEGATECALL`` in ``ViaExt``'s storage and writes ``fixedLo`` in assembly. Read as a
    # compilation that kept the linked runtime code would give it (its opcodes then match the deployed code's), the
    # call to an external library function is still a delegatecall of the contract's own.
    import services.logic.decide as decide_module
    import services.logic.verdict as verdict_module

    deployed = bytes.fromhex(rpc(d.url, "eth_getCode", [O.hex20(d.at["ViaExt"]), "latest"])[2:])
    compiled = decide_module._runtime_code

    def linked(contract):
        return deployed if contract.name == "ViaExt" else compiled(contract)

    monkeypatch.setattr(decide_module, "_runtime_code", linked)
    monkeypatch.setattr(verdict_module, "_runtime_code", linked, raising=False)
    v = O.check(d, "ViaExt", "actRaw", O.verdict(d, "ViaExt", "actRaw"), samples=AMOUNTS, open_at=False)
    assert not O.nobody(v), v
    with O.snapshot(d):  # the owner has the library write the slot: every stranger passes
        assert O.transact(d, "ViaExt", "rawFixed(uint256)", ("uint256",), (0,))
        assert O.strangers_passing(d, "ViaExt", O.function(d, "ViaExt", "actRaw"), {"amount": 5}) == {True}
