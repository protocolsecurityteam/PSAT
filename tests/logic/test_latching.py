"""A ``when`` condition is read as it stands ("latched") only when nothing this contract's code writes can flip it, and
a call into an address with no code only when that address is fixed by the code itself. A target read from storage
(or a write around or within what a condition reads: a whole struct over the field it checks, an item pushed onto an
array it reads whole) may change: never latched, so a closed condition is never "nobody, ever"."""

from __future__ import annotations

from eth_abi.abi import encode
from eth_utils import keccak

from services.logic.verdict import function_verdict
from tests.logic._anvil import Deployment, anvil  # noqa: F401
from tests.support.anvil import ACCOUNT0

SOURCE = """
pragma solidity 0.8.27;

interface IPing { function ping() external view returns (uint256); }

contract Ping {
    function ping() external pure returns (uint256) { return 1; }
}

contract C {
    struct Config { bool live; uint64 version; }

    address owner;
    Config config;
    uint256 count;
    address[] list;
    address target;
    address[] targets;
    address constant NOWHERE = address(0xdead);
    address fixedAtDeploy;
    mapping(uint256 => bool) flags;

    constructor() { owner = msg.sender; }

    function setConfig(bool live) external { require(msg.sender == owner); config = Config(live, 1); }
    function add(address item) external { require(msg.sender == owner); list.push(item); }
    function setTarget(address t) external { require(msg.sender == owner); target = t; }
    function addTarget(address t) external { require(msg.sender == owner); targets.push(t); }

    function act() external { require(msg.sender == owner); require(config.live); count += 1; }
    function actOnList() external {
        require(msg.sender == owner);
        address[] memory items = list;
        require(items.length > 0);
        count += 1;
    }
    function pinged() external { require(msg.sender == owner); count += IPing(target).ping(); }
    function pingedEach() external {
        require(msg.sender == owner);
        address[] memory all = targets;
        for (uint256 i; i < all.length; i++) count += IPing(all[i]).ping();
    }
    function setFlags(uint256 n) external { for (uint256 i; i < n; i++) { if (i == 5) flags[0] = true; } }
    function flagged() external { require(msg.sender == owner); require(flags[0]); count += 1; }
    function pingedStored() external { require(msg.sender == owner); count += IPing(fixedAtDeploy).ping(); }
    function pingedNowhere() external { require(msg.sender == owner); count += IPing(NOWHERE).ping(); }
}
"""

OWNER = int(ACCOUNT0, 16)


def _verdict(anvil, name, setup=()):  # noqa: F811
    from services.logic.terms import reset_terms

    url, root = anvil
    d = Deployment(url, root, SOURCE)
    d.deploy("C")
    d.deploy("Ping")
    for signature, who in setup:
        d.send("C", "0x" + (keccak(text=signature)[:4] + encode(["address"], ["0x%040x" % who])).hex())
    reset_terms()
    contract = d.slither["C"]
    fn = next(f for f in contract.functions_entry_points if f.name == name)
    return function_verdict(contract, fn, d.at["C"], d.chain(), d.contracts("C", "Ping"))[0]


def _nobody_ever(verdict) -> bool:
    return verdict.openness == "restricted" and verdict.complete and not (verdict.principals or verdict.conditions)


def test_a_field_written_by_a_whole_struct_write_is_not_latched(anvil):  # noqa: F811
    verdict = _verdict(anvil, "act")  # ``config.live`` false: closed now, reopened by ``setConfig(true)``
    assert not _nobody_ever(verdict)
    assert verdict.openness == "restricted" and verdict.principals == {OWNER}


def test_an_array_read_whole_and_pushed_onto_is_not_latched(anvil):  # noqa: F811
    verdict = _verdict(anvil, "actOnList")  # empty now, an item away from passing
    assert not _nobody_ever(verdict)
    assert verdict.openness == "restricted" and verdict.principals == {OWNER}


def test_a_codeless_target_read_from_writable_storage_is_not_latched(anvil):  # noqa: F811
    # ``target`` is zero now (no code: every call reverts), but the owner can point it at code.
    assert not _nobody_ever(_verdict(anvil, "pinged"))
    # A codeless item of a stored list likewise: the owner can add one with code.
    verdict = _verdict(anvil, "pingedEach", setup=[("addTarget(address)", 0xBEEF)])
    assert not _nobody_ever(verdict)


def test_a_codeless_target_in_storage_no_entry_point_writes_is_not_latched_either(anvil):  # noqa: F811
    # Storage is not code: an upgrade, a delegatecall or a write the lowering didn't place can still change it.
    assert not _nobody_ever(_verdict(anvil, "pingedStored"))


def test_a_flag_only_a_later_loop_iteration_sets_is_not_latched(anvil):  # noqa: F811
    verdict = _verdict(anvil, "flagged")  # ``setFlags(6)`` sets it in its sixth iteration
    assert not _nobody_ever(verdict)


def test_a_codeless_target_fixed_in_the_code_stays_latched(anvil):  # noqa: F811
    assert _nobody_ever(_verdict(anvil, "pingedNowhere"))  # a constant with no code: nobody, ever
