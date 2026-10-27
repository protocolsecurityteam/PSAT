"""An open proved from the contract's own code stands though the stranger's own call reverts on the chain, where what
reverted can only be an action that code assumes succeeds and hands the caller's own picks: Aragon's
``newAppProxy(kernel, appId)`` creates a proxy whose constructor asks the kernel for the app, and a stranger's call
with a kernel and an app id nobody registered reverts. That is the call's business, not who makes it: "open", proved
(not ``witnessed``), carrying ``stranger_run_failed`` in ``requires``. With the right arguments every stranger, and
addresses the engine never samples, pass (``_oracle.check``). Where no action steered by the arguments could have
refused the stranger (a creation handed only stored values), or the chain left the stranger's call unanswered, the
open is not determined as before (``open_unconfirmed``), and the sweep ranks an open carrying a condition below one
carrying none (``never_bolder``). A node that didn't answer the stranger's call (geth's ``execution aborted (timeout =
5s)``, a transport failure) refused nobody: not determined, ``read_failed:run``, never a refusal read from the
message (``decide._is_revert``)."""

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

APP = 1
STRANGER_RUN_FAILED = "stranger_run_failed"


def _setup(d):
    d.deploy("Kernel")
    assert O.transact(d, "Kernel", "setApp(bytes32,address)", ("bytes32", "address"), (APP, O.ACCOUNTS[1]))
    d.deploy("Factory", ("address",), (d.at["Kernel"],))


PROBES = [O.Probe(SOURCE, _setup, (("Factory", "newAppProxy", ()), ("Factory", "stuck", ())))]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def test_an_open_proved_from_code_stands_with_the_failed_run_as_its_condition(d):
    v = O.verdict(d, "Factory", "newAppProxy")
    right = {"k": d.at["Kernel"], "appId": APP}
    O.check(d, "Factory", "newAppProxy", v, open_at=right, arrange=lambda d, who: None, open_proven=True)
    assert v.openness == "open" and v.allowed == "now" and not v.witnessed, v
    assert (None, STRANGER_RUN_FAILED, "business") in v.requires
    fn = O.function(d, "Factory", "newAppProxy")
    # Proved for every unconfigured address: ones the engine never samples pass too, given the right arguments...
    assert all(O.passes(d, "Factory", fn, right, sender=who) for who in O.UNSEEN[:6])
    # ...and the stranger's own call at the witness reverts, as the condition says.
    assert not O.passes(d, "Factory", fn, v.witnesses.get(FRESH, {}), sender=FRESH)


def test_an_action_no_argument_steers_leaves_the_open_unconfirmed(d):
    v = O.verdict(d, "Factory", "stuck")
    O.check(d, "Factory", "stuck", v, open_at=False, samples=({"x": 1},))
    assert v.openness == "not_determined" and "open_unconfirmed" in v.gaps, v
    fn = O.function(d, "Factory", "stuck")
    assert not any(O.passes(d, "Factory", fn, {"x": 1}, sender=who) for who in (*O.ACCOUNTS, *O.STRANGERS))


def _timing_out(d, who: set[int]) -> Chain:
    """The deployment's chain, answering the strangers' ``eth_call`` as geth does when it stops a long call."""

    def one(method, params):
        if method == "eth_call" and int(params[0].get("from", "0x0"), 16) in who:
            raise RuntimeError("execution aborted (timeout = 5s)")
        return rpc(d.url, method, params)

    return Chain(one, int(rpc(d.url, "eth_blockNumber", []), 16), None)


@pytest.mark.parametrize("faulty", [lambda d: O.Faulty(d, calls=True), lambda d: _timing_out(d, set(O.STRANGERS))])
def test_an_unanswered_stranger_call_is_no_business_condition(d, faulty):
    clean = O.verdict(d, "Factory", "newAppProxy")
    assert clean.openness == "open" and clean.requires, clean
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
    needs = Verdict("open", frozenset(), True, requires=((None, STRANGER_RUN_FAILED, "business"),))
    O.never_bolder(plain, needs)
    with pytest.raises(AssertionError):
        O.never_bolder(needs, plain)
