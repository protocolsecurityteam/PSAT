"""Holders listed on who they are, with what their call still needs left as conditions on them: amounts in their own
entries (Aave v4's hub spokes and their caps), an argument the code checks against another contract (Maple's
``isInstanceOf``). A stranger still has to fail with those freed, and the stored state reads as it is."""

from __future__ import annotations

import pytest
from eth_utils import keccak

from services.logic.decide import Chain
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """
pragma solidity 0.8.27;

// Aave v4's hub: spokes per asset, each supplying up to its cap; every supply logs a deposit too.
contract Hub {
    struct Spoke { bool active; bool halted; uint40 cap; uint120 added; }
    mapping(uint256 => mapping(address => Spoke)) spokes;
    mapping(uint256 => uint256) liquidity;
    address admin;
    event AddSpoke(uint256 indexed assetId, address indexed spoke);
    event Supplied(uint256 indexed assetId, address indexed spoke, uint256 amount);
    event Accrued(uint256 index);

    function addSpoke(uint256 assetId, address spoke, uint40 cap) external {
        require(msg.sender == admin);
        spokes[assetId][spoke] = Spoke(true, false, cap, 0);
        emit AddSpoke(assetId, spoke);
    }

    function add(uint256 assetId, uint256 amount) external {
        Spoke storage s = spokes[assetId][msg.sender];
        require(s.active && !s.halted && amount > 0);
        require(s.cap == type(uint40).max || mulmod(s.added, amount, 1e27) + amount <= uint256(s.cap) * 1e18);
        s.added += uint120(amount);
        liquidity[assetId] += amount;
        emit Supplied(assetId, msg.sender, amount);
        emit Accrued(liquidity[assetId]);
    }
}

interface IGlobals { function isInstanceOf(bytes32 kind, address what) external view returns (bool); }

// Maple's pool manager: its admins, or anyone until it is configured; the manager set must be a registered one.
contract Manager {
    address globals;
    address admin;
    bool configured;
    address permissionManager;

    function setPermissionManager(address manager) external {
        require(!configured || msg.sender == admin);
        require(IGlobals(globals).isInstanceOf("PERMISSION_MANAGER", manager));
        permissionManager = manager;
    }
}
"""

AT = 0xA1 << 140
ADMIN, ACTIVE, OTHER, HALTED = 0xB2 << 140, 0xC3 << 140, 0xD4 << 140, 0xE5 << 140
GLOBALS = 0xF6 << 140
_ADD = int.from_bytes(keccak(b"AddSpoke(uint256,address)"), "big")
_ACCRUED = "0x" + keccak(b"Accrued(uint256)").hex()


def _word(key: int, base: int) -> int:
    return int.from_bytes(keccak(key.to_bytes(32, "big") + base.to_bytes(32, "big")), "big")


def _spoke(asset: int, who: int) -> int:
    return _word(who, _word(asset, 0))


def _flags(active: bool, halted: bool, cap: int) -> int:
    return int(active) | int(halted) << 8 | cap << 16


class _Deployed(Chain):
    """``words`` as the storage; ``logged`` as the history, which comes back cut whenever a read asks for the hub's
    ``Accrued`` (one per supply, too many to read)."""

    def __init__(self, words: dict, logged: list):
        self.words, self.logged = words, logged
        batch = lambda calls: [self._safe(m, p) for m, p in calls]  # noqa: E731
        super().__init__(self._answer, 100, batch)

    def _safe(self, method, params):
        try:
            return self._answer(method, params)
        except RuntimeError:
            return None

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            return hex(self.words.get(int(params[1], 16), 0))
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(1_700_000_000), "number": hex(100)}
        if method == "eth_getLogs":
            return []
        raise RuntimeError("execution reverted")

    def code(self, address):
        return b"\x60" if address in (AT, GLOBALS) else b""

    def logs(self, address, topics):
        if address != AT:
            return []
        if _ACCRUED in topics:
            self.truncated.add(address)
            return []
        return self.logged


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("conditions") / "C.sol"
    path.write_text(SOURCE)
    return {c.name: c for c in Slither(str(path), solc=str(solc)).contracts}


def _verdict(built, name, fn_name, chain):
    from services.logic.terms import reset_terms

    reset_terms()
    contract = built[name]
    fn = next(f for f in contract.functions_entry_points if f.name == fn_name)
    verdict, _ = function_verdict(contract, fn, AT, chain, {AT: contract})
    return verdict


def test_a_hubs_spokes_are_listed_whatever_their_caps_leave(built):
    words = {
        _spoke(0, ACTIVE): _flags(True, False, 1000),
        _spoke(1, OTHER): _flags(True, False, 2**40 - 1),
        _spoke(0, HALTED): _flags(True, True, 1000),
        2: ADMIN,
    }
    logged = [([_ADD, 0, ACTIVE], []), ([_ADD, 1, OTHER], []), ([_ADD, 0, HALTED], [])]
    verdict = _verdict(built, "Hub", "add", _Deployed(words, logged))
    assert verdict.openness == "restricted"
    assert verdict.principals | set(verdict.conditions) == {ACTIVE, OTHER}
    assert verdict.complete


MANAGED = """
pragma solidity 0.8.27;

interface IGlobals { function isInstanceOf(bytes32 kind, address what) external view returns (bool); }

contract Globals {
    mapping(address => bool) registered;
    constructor(address r) { registered[r] = true; }
    function isInstanceOf(bytes32, address what) external view returns (bool) { return registered[what]; }
}

// ``Manager`` above, configured.
contract Manager {
    address globals;
    address admin;
    bool configured;
    address permissionManager;

    constructor(address g, address a) { globals = g; admin = a; configured = true; }

    function setPermissionManager(address manager) external {
        require(!configured || msg.sender == admin);
        require(IGlobals(globals).isInstanceOf("PERMISSION_MANAGER", manager));
        permissionManager = manager;
    }
}
"""
REGISTERED = 0xF7 << 140


@pytest.mark.parametrize("followed", [("Globals",), ()], ids=["followed", "unfollowed"])
def test_the_admin_sets_a_configured_managers_permission_manager(anvil, followed):  # noqa: F811
    # Configured: only the admin, and only a manager the registry knows.
    d = O.deployment(*anvil, MANAGED)
    d.deploy("Globals", ("address",), (REGISTERED,))
    d.deploy("Manager", ("address", "address"), (d.at["Globals"], O.ACCOUNTS[1]))
    fn = O.function(d, "Manager", "setPermissionManager")
    assert O.passes(d, "Manager", fn, {"manager": REGISTERED}, sender=O.ACCOUNTS[1])
    assert not O.passes(d, "Manager", fn, {"manager": O.OWNER}, sender=O.ACCOUNTS[1])
    v = O.verdict(d, "Manager", "setPermissionManager", *followed)
    O.check(d, "Manager", "setPermissionManager", v, samples=({"manager": REGISTERED}, {}), open_at=False)
    assert v.openness == "restricted"
    assert set(v.principals) | set(v.conditions) == {O.ACCOUNTS[1]}
