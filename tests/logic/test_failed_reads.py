"""A read the node fails is unknown, never a reason: neither "open" nor a holder may rest on it."""

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

// OpenZeppelin's TimelockController shape: an executor role that becomes open to anyone once granted to zero.
contract Timelock {
    bytes32 constant EXECUTOR = keccak256("EXECUTOR_ROLE");
    mapping(bytes32 => mapping(address => bool)) roles;
    mapping(bytes32 => uint256) timestamps;
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    function grant(bytes32 role, address who) external {
        require(roles[0][msg.sender]);
        roles[role][who] = true;
        emit RoleGranted(role, who, msg.sender);
    }

    function revoke(bytes32 role, address who) external {
        require(roles[0][msg.sender]);
        roles[role][who] = false;
        emit RoleRevoked(role, who, msg.sender);
    }

    function execute(bytes32 id) external {
        if (!roles[EXECUTOR][address(0)]) {
            require(roles[EXECUTOR][msg.sender]);
        }
        require(timestamps[id] > 1 && timestamps[id] <= block.timestamp);
        timestamps[id] = 1;
    }
}
"""

AT = 0xA1 << 140
EXECUTOR, FORMER = 0xB2 << 140, 0xC3 << 140
_ROLE = int.from_bytes(keccak(b"EXECUTOR_ROLE"), "big")
_GRANTED = int.from_bytes(keccak(b"RoleGranted(bytes32,address,address)"), "big")
_REVOKED = int.from_bytes(keccak(b"RoleRevoked(bytes32,address,address)"), "big")


def _member(who: int) -> int:
    return O.slot(who, O.slot(_ROLE, 0))


class _Deployed(Chain):
    """``EXECUTOR`` holds the role; ``FORMER`` held it once; reads of ``failing`` slots fail as a node timing out."""

    def __init__(self, failing: frozenset = frozenset()):
        self.failing = failing
        batch = lambda calls: [self._safe(m, p) for m, p in calls]  # noqa: E731
        super().__init__(self._answer, 100, batch)

    def _safe(self, method, params):
        try:
            return self._answer(method, params)
        except RuntimeError:
            return None

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            slot = int(params[1], 16)
            if slot in self.failing:
                raise RuntimeError("timeout")
            return hex(1 if slot == _member(EXECUTOR) else 0)
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(1_700_000_000), "number": hex(100)}
        if method == "eth_getLogs":
            return []
        raise RuntimeError("execution reverted")

    def code(self, address):
        return b"\x60" if address == AT else b""

    def logs(self, address, topics):
        if address != AT:
            return []
        return [
            ([_GRANTED, _ROLE, EXECUTOR, 0], []),
            ([_GRANTED, _ROLE, FORMER, 0], []),
            ([_REVOKED, _ROLE, FORMER, 0], []),
        ]


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("faults") / "T.sol"
    path.write_text(SOURCE)
    return {c.name: c for c in Slither(str(path), solc=str(solc)).contracts}


def _verdict(built, chain):
    from services.logic.terms import reset_terms

    reset_terms()
    contract = built["Timelock"]
    fn = next(f for f in contract.functions_entry_points if f.name == "execute")
    verdict, _ = function_verdict(contract, fn, AT, chain, {AT: contract})
    return verdict


def test_read_as_it_is_the_executor_alone_holds_it(built):
    verdict = _verdict(built, _Deployed())
    assert verdict.openness == "restricted"
    assert verdict.principals == {EXECUTOR}


def test_an_executor_whose_role_read_failed_doesnt_make_it_open_once_allowed(built):
    # Whether the executor passes now is unknown: so is whether nobody does, which "open later" rests on.
    verdict = _verdict(built, _Deployed(frozenset({_member(EXECUTOR)})))
    assert verdict.openness != "open"


def test_a_former_executor_whose_role_read_failed_isnt_listed(built):
    # Freed, the open role's flag lets anyone through: no sign the former executor holds anything.
    verdict = _verdict(built, _Deployed(frozenset({_member(FORMER)})))
    assert FORMER not in verdict.principals
    assert not verdict.complete


DELEGATED = """
pragma solidity 0.8.27;

// Aragon Voting's ``unassignDelegate``: anyone gets through once it has assigned itself a delegate.
contract Delegated {
    struct Delegate { address delegate; uint96 index; }
    mapping(address => Delegate) delegates;
    mapping(address => address[]) voters;

    function assign(address to) external {
        require(to != address(0));
        delegates[msg.sender] = Delegate(to, uint96(voters[to].length));
        voters[to].push(msg.sender);
    }

    function unassign() external {
        Delegate memory d = delegates[msg.sender];
        require(d.delegate != address(0));
        require(voters[d.delegate][d.index] == msg.sender);
        delete delegates[msg.sender];
    }
}
"""


class _Unreadable(Chain):
    """Every storage read fails when ``failing``; otherwise every slot holds zero."""

    def __init__(self, failing: bool):
        self.failing = failing
        batch = lambda calls: [self._safe(m, p) for m, p in calls]  # noqa: E731
        super().__init__(self._answer, 100, batch)

    def _safe(self, method, params):
        try:
            return self._answer(method, params)
        except RuntimeError:
            return None

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            if self.failing:
                raise RuntimeError("timeout")
            return hex(0)
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(1_700_000_000), "number": hex(100)}
        if method == "eth_getLogs":
            return []
        raise RuntimeError("execution reverted")

    def code(self, address):
        return b"\x60" if address == AT else b""

    def logs(self, address, topics):
        return []


def test_a_stranger_its_own_first_call_listed_isnt_refused_when_where_was_unread(tmp_path_factory):
    # The list's length went unread, so where the stranger's own call put it is unknown: not proof it isn't there.
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    from services.logic.terms import reset_terms

    path = tmp_path_factory.mktemp("delegated") / "D.sol"
    path.write_text(DELEGATED)
    contract = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Delegated")
    fn = next(f for f in contract.functions_entry_points if f.name == "unassign")
    reset_terms()
    clean, _ = function_verdict(contract, fn, AT, _Unreadable(False), {AT: contract})
    assert clean.openness == "open"
    reset_terms()
    faulted, _ = function_verdict(contract, fn, AT, _Unreadable(True), {AT: contract})
    assert faulted.openness != "restricted"


OWNED = """
pragma solidity 0.8.27;

// Maple's ``transferOwnedPoolManager``: whoever an entry names, at a key the caller picks.
contract Owned {
    struct Pool { address manager; bool active; }
    address admin;
    mapping(address => Pool) pools;
    event ManagerSet(address indexed pool, address manager);
    event Activated(address indexed pool);

    function activate(address pool) external {
        require(msg.sender == admin);
        pools[pool].active = true;
        emit Activated(pool);
    }

    function setManager(address pool, address manager) external {
        require(msg.sender == admin);
        pools[pool].manager = manager;
        emit ManagerSet(pool, manager);
    }

    function move(address from, address to) external {
        require(pools[from].manager == msg.sender);
        pools[to].manager = msg.sender;
        pools[from].manager = address(0);
        emit ManagerSet(to, msg.sender);
        emit ManagerSet(from, address(0));
    }
}
"""

POOL = 0xD4 << 140
_SET = int.from_bytes(keccak(b"ManagerSet(address,address)"), "big")


class _Managed(Chain):
    """``POOL``'s manager is ``EXECUTOR``, as its one ``ManagerSet`` says; when ``cut``, a read of the managers'
    history alone comes back partial, though the read of every write to ``pools`` doesn't."""

    def __init__(self, cut: bool):
        self.cut_short = cut
        batch = lambda calls: [self._safe(m, p) for m, p in calls]  # noqa: E731
        super().__init__(self._answer, 100, batch)

    def _safe(self, method, params):
        try:
            return self._answer(method, params)
        except RuntimeError:
            return None

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            return hex(EXECUTOR if int(params[1], 16) == O.slot(POOL, 1) else 0)
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(1_700_000_000), "number": hex(100)}
        if method == "eth_getLogs":
            return []
        raise RuntimeError("execution reverted")

    def code(self, address):
        return b"\x60" if address == AT else b""

    def logs(self, address, topics):
        if address != AT:
            return []
        if self.cut_short and len(topics) == 1:
            self.truncated.add(address)
            return []
        return [([_SET, POOL], [EXECUTOR])]


def test_whose_entry_it_is_isnt_settled_by_a_history_cut_short(tmp_path_factory):
    # With the writers' history partial, no key naming the caller among those read isn't proof none does.
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    from services.logic.terms import reset_terms

    path = tmp_path_factory.mktemp("owned") / "O.sol"
    path.write_text(OWNED)
    contract = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Owned")
    fn = next(f for f in contract.functions_entry_points if f.name == "move")
    reset_terms()
    clean, _ = function_verdict(contract, fn, AT, _Managed(False), {AT: contract})
    assert clean.openness == "restricted" and clean.principals == {EXECUTOR} and clean.complete
    reset_terms()
    cut, _ = function_verdict(contract, fn, AT, _Managed(True), {AT: contract})
    assert not (cut.openness == "restricted" and cut.complete)


RENOUNCED = """
pragma solidity 0.8.27;

// OpenZeppelin's AccessControlEnumerable: anyone may renounce its own role, which clears its entry and reorders a
// member list the gate never reads.
contract Renounced {
    mapping(bytes32 => mapping(address => bool)) roles;
    mapping(bytes32 => address[]) members;
    bytes32 constant MINTER = keccak256("MINTER");

    constructor() { roles[MINTER][msg.sender] = true; members[MINTER].push(msg.sender); }

    function renounce(bytes32 role, address account, uint256 at) external {
        require(account == msg.sender);
        roles[role][account] = false;
        address[] storage list = members[role];
        list[at] = list[list.length - 1];
        list.pop();
    }

    function mint() external view {
        require(roles[MINTER][msg.sender]);
    }
}
"""


@pytest.fixture(scope="module")
def renounced(anvil):  # noqa: F811
    d = O.deployment(*anvil, RENOUNCED)
    d.deploy("Renounced")
    return d


def test_renouncing_ones_own_role_is_no_way_in(renounced):
    # Zero written to the stranger's own entry, and a list the gate never reads: neither can let it through. Each
    # stranger renounces for real, and its mint still reverts.
    d = renounced
    v = O.check(d, "Renounced", "mint", O.verdict(d, "Renounced", "mint"), open_at=False)
    assert v.openness == "restricted" and "now_unknown" not in v.gaps
    O.sound(v, {O.OWNER})
    mint = O.function(d, "Renounced", "mint")
    for who in O.STRANGERS:
        with O.snapshot(d):
            assert O.transact(d, "Renounced", "renounce(bytes32,address,uint256)", ("bytes32", "address", "uint256"),
                              (keccak(b"MINTER"), who, 0), sender=who)  # fmt: skip
            assert not O.passes(d, "Renounced", mint, sender=who)
