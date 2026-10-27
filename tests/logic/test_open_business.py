"""An open the chain refuses is never kept on an account of what refused it. An action the contract's own code
assumes succeeds (a contract created, ether sent by ``transfer``, a low-level or assembly call whose result it
checks) is a callee's decision, on whatever that callee reads, whoever hands it what: a constructor or a receive hook
checking ``tx.origin`` lets the admin through and nobody else, and no argument the stranger could pick changes that.
So Aragon's ``newAppProxy(kernel, appId)`` (a proxy created for an app id the stranger's guess doesn't name) is not
determined, ``open_assumed_action_unconfirmed``, like every open resting on such an action whose stranger's call the
chain refuses; an action whose outcome the code doesn't require (an unchecked low-level call) is no such condition,
and the function stays open once the strangers' own calls go through. A node that didn't answer the stranger's call
(geth's ``execution aborted (timeout = 5s)``, a transport failure) refused nobody: not determined, ``read_failed:run``,
never a refusal read from the message (``decide._is_revert``). The sweep ranks an open carrying a condition below one
carrying none (``never_bolder``)."""

from __future__ import annotations

import pytest

from services.logic.decide import FRESH, Chain, Verdict, _is_revert
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

SOURCE = """
pragma solidity 0.8.27;

interface IKernel { function getApp(bytes32 ns, bytes32 id) external view returns (address); }

contract Kernel {
    mapping(bytes32 => address) apps;
    function setApp(bytes32 id, address a) external { apps[id] = a; }
    function getApp(bytes32, bytes32 id) external view returns (address) { return apps[id]; }
}

contract AppProxy {
    constructor(IKernel k, bytes32 id) { require(k.getApp(0, id) != address(0)); }
}

contract Factory {
    IKernel kernel;
    bytes32 unregistered = bytes32(uint256(7));
    uint256 public made;
    event NewProxy(address proxy);
    constructor(IKernel k) { kernel = k; }
    function newAppProxy(IKernel k, bytes32 appId) external returns (AppProxy p) {
        p = new AppProxy(k, appId);
        made += 1;
        emit NewProxy(address(p));
    }
    // The same creation handed only stored values that name no app: it reverts for everyone, whatever the arguments.
    function stuck(uint256 x) external {
        x;
        new AppProxy(kernel, unregistered);
        made += 1;
    }
}
"""

# The callee, receive hook and child constructor each check the transaction's origin: only the admin passes, whatever
# is handed them. The engine never follows them (not in the formula): each is an action assumed to succeed.
ORIGIN = """
pragma solidity 0.8.27;

contract OriginGuard {
    address admin;
    constructor() { admin = msg.sender; }
    fallback() external payable { require(tx.origin == admin, "origin"); }
    receive() external payable { require(tx.origin == admin, "origin"); }
}

contract Child {
    constructor(uint256 x) { x; require(tx.origin == 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266, "origin"); }
}

contract Forwarder {
    address guard;
    uint256 public n;
    constructor(address g) { guard = g; }
    function exec(bytes calldata data) external {
        (bool ok,) = guard.call(data);
        require(ok, "refused");
        n += 1;
    }
    function execYul(uint256 x) external {
        address g = guard;
        bool ok;
        assembly {
            mstore(0, x)
            ok := call(gas(), g, 0, 0, 32, 0, 0)
        }
        require(ok, "refused");
        n += 1;
    }
    function pay(uint256 amt) external payable {
        payable(guard).transfer(amt);
        n += 1;
    }
    function spawn(uint256 x) external {
        new Child(x);
        n += 1;
    }
    // Control: the result is not checked, so the function truly is open.
    function fire(bytes calldata data) external {
        guard.call(data);
        n += 1;
    }
}
"""

APP = 1
ORIGIN_CASES = [("exec", {"data": b"\x01"}), ("execYul", {"x": 1}), ("pay", {"amt": 0}), ("spawn", {"x": 1})]


def _setup(d):
    d.deploy("Kernel")
    assert O.transact(d, "Kernel", "setApp(bytes32,address)", ("bytes32", "address"), (APP, O.ACCOUNTS[1]))
    d.deploy("Factory", ("address",), (d.at["Kernel"],))


def _origin(d):
    d.deploy("OriginGuard")
    d.deploy("Forwarder", ("address",), (d.at["OriginGuard"],))


PROBES = [
    O.Probe(SOURCE, _setup, (("Factory", "newAppProxy", ()), ("Factory", "stuck", ()))),
    O.Probe(ORIGIN, _origin, tuple(("Forwarder", name, ()) for name, _ in ORIGIN_CASES) + (("Forwarder", "fire", ()),)),
]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


@pytest.fixture(scope="module")
def origin(anvil):  # noqa: F811
    d = O.deployment(*anvil, ORIGIN)
    _origin(d)
    return d


def test_a_creation_the_stranger_fails_leaves_the_open_not_determined(d):
    v = O.verdict(d, "Factory", "newAppProxy")
    right = {"k": d.at["Kernel"], "appId": APP}
    O.check(d, "Factory", "newAppProxy", v)
    # Honest under-claim: every address passes with the right arguments (the oracle's ``open_at`` would demand "open"
    # here), but the engine, not following the constructor, can't tell its refusal of the stranger's guess from one
    # of the stranger.
    assert v.openness == "not_determined" and not v.requires, v
    assert "open_assumed_action_unconfirmed" in v.gaps and "read_failed:run" not in v.gaps, v
    fn = O.function(d, "Factory", "newAppProxy")
    assert all(O.passes(d, "Factory", fn, right, sender=who) for who in (*O.STRANGERS, *O.UNSEEN[:6]))
    assert not O.passes(d, "Factory", fn, v.witnesses.get(FRESH, {}), sender=FRESH)


def test_a_creation_no_argument_steers_leaves_the_open_not_determined(d):
    v = O.verdict(d, "Factory", "stuck")
    O.check(d, "Factory", "stuck", v, open_at=False, samples=({"x": 1},))
    assert v.openness == "not_determined" and "open_assumed_action_unconfirmed" in v.gaps and not v.requires, v
    fn = O.function(d, "Factory", "stuck")
    assert not any(O.passes(d, "Factory", fn, {"x": 1}, sender=who) for who in (*O.ACCOUNTS, *O.STRANGERS))


@pytest.mark.parametrize(("name", "args"), ORIGIN_CASES)
def test_an_assumed_action_whose_callee_checks_the_origin_is_never_open(origin, name, args):
    v = O.verdict(origin, "Forwarder", name)
    fn = O.function(origin, "Forwarder", name)
    # Truth: the admin passes, no stranger and no unseen address does.
    assert O.passes(origin, "Forwarder", fn, args, sender=O.OWNER)
    assert not any(O.passes(origin, "Forwarder", fn, args, sender=w) for w in (*O.STRANGERS, *O.UNSEEN[:4]))
    O.check(origin, "Forwarder", name, v, open_at=False, samples=(args,))
    assert v.openness == "not_determined" and "open_assumed_action_unconfirmed" in v.gaps, v
    assert not v.requires, v


def test_an_action_whose_outcome_the_code_ignores_leaves_the_function_open(origin):
    v = O.verdict(origin, "Forwarder", "fire")
    O.check(origin, "Forwarder", "fire", v, open_at={"data": b"\x01"})
    assert v.openness == "open" and v.allowed == "now", v


def _timing_out(d, who: set[int]) -> Chain:
    """The deployment's chain, answering the strangers' ``eth_call`` as geth does when it stops a long call."""

    def one(method, params):
        if method == "eth_call" and int(params[0].get("from", "0x0"), 16) in who:
            raise RuntimeError("execution aborted (timeout = 5s)")
        return rpc(d.url, method, params)

    return Chain(one, int(rpc(d.url, "eth_blockNumber", []), 16), None)


@pytest.mark.parametrize("faulty", [lambda d: O.Faulty(d, calls=True), lambda d: _timing_out(d, set(O.STRANGERS))])
def test_an_unanswered_stranger_call_is_no_refusal(d, faulty):
    clean = O.verdict(d, "Factory", "newAppProxy")
    v = O.verdict(d, "Factory", "newAppProxy", chain=faulty(d))
    assert v.openness == "not_determined" and not v.requires, v
    assert "read_failed:run" in v.gaps, v
    O.never_bolder(clean, v)


@pytest.mark.parametrize(
    "message",
    [
        "execution reverted",
        "execution reverted: Ownable: caller is not the owner",
        "Reverted 0x08c379a0",
        "VM execution error.",
        "EVM error InvalidFEOpcode",
        "invalid opcode: INVALID",
        "out of gas",
        "invalid jump destination",
        "stack underflow (0 <=> 1)",
        "VM Exception while processing transaction: revert",
    ],
)
def test_the_nodes_own_words_for_a_failed_call_read_as_a_refusal(message):
    assert _is_revert(message)


@pytest.mark.parametrize(
    "message",
    [
        "execution aborted (timeout = 5s)",
        "execution reverted but the node timed out",  # a node's trouble is never read as the call's answer
        "Read timed out",
        "context deadline exceeded",
        "injected: upstream timeout",
        "gas required exceeds allowance (50000000)",
        "429 Too Many Requests",
        "Internal error",
        "execution",
        "",
    ],
)
def test_a_nodes_trouble_never_reads_as_a_refusal(message):
    assert not _is_revert(message)


def test_an_open_carrying_a_condition_ranks_below_one_carrying_none():
    plain = Verdict("open", frozenset(), True)
    needs = Verdict("open", frozenset(), True, requires=((None, "valid_signature", "business"),))
    O.never_bolder(plain, needs)
    with pytest.raises(AssertionError):
        O.never_bolder(needs, plain)
