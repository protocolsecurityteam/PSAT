"""A proxy's lookups are listed by their events only if every implementation it has run logged its writes: entries
an earlier one set stay in storage after an upgrade. Code that delegates to whatever the caller names may write any
entry, so no list is whole."""

from __future__ import annotations

import pytest
from eth_utils import keccak

from services.logic.decide import Chain
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path

SOURCE = """
pragma solidity 0.8.27;

// The first implementation: grants logged under another event, or not at all.
contract FirstLogged {
    mapping(address => bool) minters;
    event Added(address indexed who);
    function add(address who) external { require(minters[msg.sender]); minters[who] = true; emit Added(who); }
}

contract FirstQuiet {
    mapping(address => bool) minters;
    function add(address who) external { require(minters[msg.sender]); minters[who] = true; }
}

// The one running now.
contract Second {
    mapping(address => bool) minters;
    event MinterSet(address indexed who, bool on);
    function set(address who, bool on) external {
        require(minters[msg.sender]);
        minters[who] = on;
        emit MinterSet(who, on);
    }
    function mint() external view { require(minters[msg.sender]); }
}

// Runs whatever code its caller names, on its own storage.
contract Delegating {
    mapping(address => bool) minters;
    event MinterSet(address indexed who, bool on);
    function set(address who, bool on) external {
        require(minters[msg.sender]);
        minters[who] = on;
        emit MinterSet(who, on);
    }
    function run(address code, bytes calldata data) external {
        require(minters[msg.sender]);
        (bool ok, ) = code.delegatecall(data);
        require(ok);
    }
    function mint() external view { require(minters[msg.sender]); }
}
"""

PROXY, FIRST, SECOND, UNLOGGED = 0xA1 << 140, 0xA2 << 140, 0xA3 << 140, 0xA4 << 140
_IMPLEMENTATION_SLOT = int.from_bytes(keccak(b"eip1967.proxy.implementation"), "big") - 1
_CREATED = 50
OLD, NEW = 0xB2 << 140, 0xC3 << 140
_UPGRADED = int.from_bytes(keccak(b"Upgraded(address)"), "big")
_ADDED = int.from_bytes(keccak(b"Added(address)"), "big")
_SET = int.from_bytes(keccak(b"MinterSet(address,bool)"), "big")


def _entry(who: int) -> int:
    return int.from_bytes(keccak(who.to_bytes(32, "big") + (0).to_bytes(32, "big")), "big")


class _Proxy(Chain):
    """``OLD`` made a minter under the first implementation, ``NEW`` under the second; ``upgrades`` is the proxy's
    ``Upgraded`` history."""

    def __init__(self, upgrades: list[int], first_logs: bool, created_with: int | None = None):
        self.upgrades, self.first_logs = upgrades, first_logs
        # What the proxy's implementation slot held at its creation: the first logged one, unless set unlogged.
        self.created_with = created_with if created_with is not None else (upgrades[0] if upgrades else 0)
        batch = lambda calls: [self._safe(m, p) for m, p in calls]  # noqa: E731
        super().__init__(self._answer, 100, batch)

    def _safe(self, method, params):
        try:
            return self._answer(method, params)
        except RuntimeError:
            return None

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            if int(params[1], 16) == _IMPLEMENTATION_SLOT and int(params[2], 16) == _CREATED:
                return hex(self.created_with)
            return hex(1 if int(params[1], 16) in (_entry(OLD), _entry(NEW)) else 0)
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(1_700_000_000), "number": hex(100)}
        if method == "eth_getLogs":
            return []
        raise RuntimeError("execution reverted")

    def code(self, address):
        return b"\x60" if address in (PROXY, FIRST, SECOND) else b""

    def creation_block(self, address):
        return _CREATED if address == PROXY else None

    def logs(self, address, topics):
        if address != PROXY:
            return []
        out = [([_UPGRADED, self.upgrades[0]], [])] if self.upgrades else []
        if self.first_logs:
            out.append(([_ADDED, OLD], []))
        out += [([_UPGRADED, u], []) for u in self.upgrades[1:]]
        out.append(([_SET, NEW], [1]))
        return out


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("versions") / "V.sol"
    path.write_text(SOURCE)
    return {c.name: c for c in Slither(str(path), solc=str(solc)).contracts}


def _verdict(
    built, first: str, upgrades: list[int], first_logs: bool, running: str = "Second", created_with: int | None = None
):
    from services.logic.terms import reset_terms

    reset_terms()
    contract = built[running]
    fn = next(f for f in contract.functions_entry_points if f.name == "mint")
    contracts = {PROXY: contract, FIRST: built[first], SECOND: contract}
    code_of = lambda a: SECOND if a == PROXY else a  # noqa: E731
    chain = _Proxy(upgrades, first_logs, created_with)
    verdict, _ = function_verdict(contract, fn, PROXY, chain, contracts, {}, code_of)
    return verdict


def test_holders_from_every_implementations_events_are_listed(built):
    verdict = _verdict(built, "FirstLogged", [FIRST, SECOND], True)
    assert verdict.openness == "restricted"
    assert verdict.principals == {OLD, NEW}
    assert verdict.complete


def test_an_earlier_implementation_that_logged_nothing_leaves_the_list_partial(built):
    verdict = _verdict(built, "FirstQuiet", [FIRST, SECOND], False)
    assert NEW in verdict.principals
    assert not verdict.complete


def test_an_unread_upgrade_history_leaves_the_list_partial(built):
    verdict = _verdict(built, "FirstLogged", [], True)
    assert not verdict.complete


def test_code_that_delegates_where_its_caller_says_leaves_the_list_partial(built):
    verdict = _verdict(built, "FirstLogged", [SECOND], False, running="Delegating")
    assert NEW in verdict.principals
    assert not verdict.complete


def test_an_implementation_the_proxy_was_made_with_unlogged_leaves_the_list_partial(built):
    # Created running code no ``Upgraded`` names (a constructor writing the slot itself): its writes go unseen.
    verdict = _verdict(built, "FirstLogged", [FIRST, SECOND], True, created_with=UNLOGGED)
    assert not verdict.complete
