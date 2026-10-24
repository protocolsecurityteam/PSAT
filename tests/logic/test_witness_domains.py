"""Where the search for a holder's arguments looks: the keys the running code's events wrote a holder at, even when
an earlier implementation's logging is unknown; a value compared for equality before its neighbours; and for an
address the caller picks to be called, the contracts the code already calls or holds."""

from __future__ import annotations

import pytest
from eth_utils import keccak

from services.logic.decide import Chain
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path
from tests.logic import _oracle as O

SOURCE = """
pragma solidity 0.8.27;

interface ICore {
    function isGovernor(address who) external view returns (bool);
}

interface IRegistry {
    function onlyAdmin(address who) external view;
}

interface IProxiable {
    function proxiableUUID() external view returns (bytes32);
}

// EtherFi's sync pool: whoever is the receiver for the chain id it names, with the ETH it says it sends.
contract Pool {
    address owner;
    mapping(uint32 => address) receivers;
    mapping(uint32 => uint256) handled;
    uint256 total;
    address constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    event ReceiverSet(uint32 indexed eid, address receiver);

    function setReceiver(uint32 eid, address receiver) external {
        require(msg.sender == owner);
        receivers[eid] = receiver;
        emit ReceiverSet(eid, receiver);
    }

    function onMessage(uint32 eid, address tokenIn, uint256 amountIn, uint256 nonce) external payable {
        require(msg.sender == receivers[eid]);
        require(tokenIn == ETH && amountIn == msg.value);
        handled[eid] += amountIn + nonce;
        total += amountIn;
    }
}

// Angle's treasury: a new core whose governors include the caller, who must govern the current one too.
contract Treasury {
    ICore core;
    event CoreUpdated(address core);

    function setCore(ICore next) external {
        require(next.isGovernor(msg.sender) && core.isGovernor(msg.sender));
        core = next;
        emit CoreUpdated(address(next));
    }
}

// A UUPS upgrade: a registry's admin, to code that says it is upgradeable.
contract Upgradeable {
    address implementation;
    IRegistry registry;
    bytes32 constant SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function upgradeTo(address next) external {
        require(implementation != address(0));
        registry.onlyAdmin(msg.sender);
        require(IProxiable(next).proxiableUUID() == SLOT);
        implementation = next;
    }
}
"""

AT, IMPL = 0xA1 << 140, 0xA2 << 140
CORE, REGISTRY, CURRENT = 0xC0 << 152, 0xC1 << 152, 0xC2 << 152
# Address-shaped (from 2**150): log words that small are no one's address.
GOVERNORS = [0xD1 << 152, 0xD2 << 152]
ADMIN, OTHER = 0xE1 << 152, 0xE2 << 152
# Eids past the sixteen smallest recorded words, where a guess from the history alone doesn't reach.
RECEIVERS = {30_000 + 7 * i: (0xB0 << 150) + i for i in range(24)}
_SET = int.from_bytes(keccak(b"ReceiverSet(uint32,address)"), "big")
_SLOT = 0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC
_IS_GOVERNOR = keccak(b"isGovernor(address)")[:4]
_ONLY_ADMIN = keccak(b"onlyAdmin(address)")[:4]
_PROXIABLE = keccak(b"proxiableUUID()")[:4]


class _Deployed(Chain):
    """The three contracts as configured; ``AT`` runs ``IMPL``'s code behind a proxy whose upgrades no event shows."""

    def __init__(self, words: dict, coded: set, sample: dict | None = None):
        self.words, self.coded, self.sample = words, coded, sample or {}
        super().__init__(self._answer, 100, lambda calls: [self._safe(m, p) for m, p in calls])

    def _safe(self, method, params):
        try:
            return self._answer(method, params)
        except RuntimeError:
            return None

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            return hex(self.words.get(int(params[1], 16), 0) if int(params[0], 16) == AT else 0)
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(1_700_000_000), "number": hex(100)}
        if method == "eth_getCode":
            return "0x60" if int(params[0], 16) in self.coded else "0x"
        if method == "eth_call":
            to, data = int(params[0]["to"], 16), bytes.fromhex(params[0]["data"][2:])
            who = int.from_bytes(data[4:36], "big") if len(data) >= 36 else None
            if to == CORE and data[:4] == _IS_GOVERNOR:
                return "0x" + format(int(who in GOVERNORS), "064x")
            if to == REGISTRY and data[:4] == _ONLY_ADMIN and who == ADMIN:
                return "0x"
            if to == CURRENT and data[:4] == _PROXIABLE:
                return "0x" + format(_SLOT, "064x")
        raise RuntimeError("execution reverted")

    def code(self, address):
        return b"\x60" if address in self.coded else b""

    def logs(self, address, topics):
        if address != AT:
            return []
        return [([_SET, eid], [who]) for eid, who in RECEIVERS.items()]

    def all_log_words(self, address):
        return set(self.sample.get(address, ()))


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("domains") / "D.sol"
    path.write_text(SOURCE)
    return {c.name: c for c in Slither(str(path), solc=str(solc)).contracts}


def _verdict(built, name, fn_name, chain, code_of=None):
    from services.logic.terms import reset_terms

    reset_terms()
    contract = built[name]
    fn = next(f for f in contract.functions_entry_points if f.name == fn_name)
    verdict, _ = function_verdict(contract, fn, AT, chain, {AT: contract}, code_of=code_of)
    return verdict


def test_receivers_are_found_at_the_keys_the_running_codes_events_set_them(built):
    words = {O.slot(eid, 1): who for eid, who in RECEIVERS.items()}
    chain = _Deployed(words, {AT, IMPL})
    verdict = _verdict(built, "Pool", "onMessage", chain, code_of=lambda a: IMPL if a == AT else a)
    assert verdict.openness == "restricted"
    assert verdict.principals == set(RECEIVERS.values())
    # Whether an earlier implementation set receivers without an event is unknown: a lower bound.
    assert not verdict.complete


def test_a_core_the_caller_names_is_guessed_among_the_cores_the_code_asks(built):
    chain = _Deployed({0: CORE}, {AT, CORE}, sample={CORE: GOVERNORS})
    verdict = _verdict(built, "Treasury", "setCore", chain)
    assert verdict.openness == "restricted"
    assert verdict.principals == set(GOVERNORS)
    assert all(int(str(verdict.witnesses[g]["next"]), 0) == CORE for g in GOVERNORS)
    assert len(verdict.gaps) == len(set(verdict.gaps))  # ``call:isGovernor(address)`` once, not per call


def test_an_implementation_the_caller_names_is_guessed_among_the_addresses_the_code_holds(built):
    chain = _Deployed({0: CURRENT, 1: REGISTRY}, {AT, REGISTRY, CURRENT}, sample={REGISTRY: [ADMIN, OTHER]})
    verdict = _verdict(built, "Upgradeable", "upgradeTo", chain)
    assert verdict.openness == "restricted"
    assert ADMIN in verdict.principals and ADMIN not in verdict.conditions
    assert OTHER not in verdict.principals
