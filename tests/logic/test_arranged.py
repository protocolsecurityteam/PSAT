"""State a caller can bring about for itself through open code is no privilege; state only others can grant is."""

from __future__ import annotations

import pytest

from services.logic.decide import Chain
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path

SOURCE = """
pragma solidity 0.8.27;

contract C {
    address owner;
    bool initialized;
    mapping(address => uint256) balances;
    mapping(address => bool) members;
    mapping(address => mapping(address => bool)) operators;
    mapping(address => mapping(address => bool)) approved;

    function deposit(uint256 amount) external {
        require(amount > 0);
        balances[msg.sender] += amount;
    }

    function setOperator(address operator, bool on) external {
        operators[msg.sender][operator] = on;
    }

    function approve(address spender) external {
        approved[msg.sender][spender] = true;
    }

    function grant(address who) external {
        require(msg.sender == owner);
        members[who] = true;
    }

    // Already run: the membership it hands its caller is no one's to take now.
    function initialize() external {
        require(!initialized);
        initialized = true;
        members[msg.sender] = true;
    }

    // OpenZeppelin's ``_revokeRole`` shape: written only when held.
    function renounce() external {
        if (members[msg.sender]) {
            members[msg.sender] = false;
        }
    }

    function withdraw(uint256 amount) external {
        require(amount > 0 && balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
    }

    function withdrawFor(address account, uint256 amount) external {
        require(account == msg.sender || operators[account][msg.sender]);
        require(amount > 0 && balances[account] >= amount);
        balances[account] -= amount;
    }

    function membersOnly() external view {
        require(members[msg.sender]);
    }

    // Approval only someone else can give: a caller can't stand in for ``from``.
    function pull(address from) external view {
        require(from != msg.sender && approved[from][msg.sender]);
    }
}
"""

THIS, OWNER = 0xC0DE << 100, 0x0E1E << 100


class _Fresh(Chain):
    """Initialized, and otherwise as deployed: every slot zero but the owner's and the flag packed beside it."""

    def __init__(self):
        super().__init__(self._answer, 1, lambda calls: [self._answer(m, p) for m, p in calls])

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            return hex(OWNER | 1 << 160 if int(params[1], 16) == 0 and int(params[0], 16) == THIS else 0)
        if method == "eth_getLogs":
            return []
        raise RuntimeError("execution reverted")

    def code(self, address):
        return b"\x60" if address == THIS else b""

    def logs(self, address, topics):
        return []


@pytest.fixture(scope="module")
def contract(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("arranged") / "C.sol"
    path.write_text(SOURCE)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "C")


def _verdict(contract, name):
    fn = next(f for f in contract.functions_entry_points if f.name == name)
    verdict, _ = function_verdict(contract, fn, THIS, _Fresh(), {THIS: contract})
    return verdict


def test_withdrawing_what_anyone_may_deposit_is_open(contract):
    assert _verdict(contract, "withdraw").openness == "open"


def test_acting_for_an_account_is_open_to_that_account(contract):
    assert _verdict(contract, "withdrawFor").openness == "open"


def test_membership_only_an_owner_grants_stays_a_gate(contract):
    assert _verdict(contract, "membersOnly").openness != "open"


def test_an_approval_only_someone_else_can_give_stays_a_gate(contract):
    assert _verdict(contract, "pull").openness != "open"


def test_a_gate_stays_a_gate_after_other_analyses_of_the_same_code(contract):
    # Lowered writers are kept per contract across analyses whose terms are interned apart (another deployment of
    # the same code): ``renounce`` still only takes membership away.
    from services.logic.terms import reset_terms

    reset_terms()
    _verdict(contract, "withdraw")
    reset_terms()
    assert _verdict(contract, "membersOnly").openness != "open"


NFTS = """
pragma solidity 0.8.27;

contract Tickets {
    struct Ticket { address owner; bool used; }
    mapping(uint256 => Ticket) tickets;
    mapping(uint256 => address) approvals;
    uint256 last;

    // Open: whoever asks gets a ticket (Lido's withdrawal requests).
    function request(address owner) external returns (uint256 id) {
        id = ++last;
        tickets[id] = Ticket(owner == address(0) ? msg.sender : owner, false);
    }

    function approve(address to, uint256 id) external {
        require(tickets[id].owner == msg.sender && to != msg.sender);
        approvals[id] = to;
    }
}

contract Badges {
    address admin;
    address owner;

    // Anyone may become owner of nothing in particular: still the one owner, taken from whoever held it.
    function claim() external {
        require(owner == address(0));
        owner = msg.sender;
    }

    function ownerOnly() external view {
        require(owner == msg.sender);
    }
    mapping(uint256 => address) owners;
    mapping(uint256 => address) approvals;

    // Only the admin mints (ENS's controllers, a staking manager).
    function mint(uint256 id, address to) external {
        require(msg.sender == admin);
        owners[id] = to;
    }

    function approve(address to, uint256 id) external {
        require(owners[id] == msg.sender);
        approvals[id] = to;
    }
}
"""


@pytest.fixture(scope="module")
def nfts(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("held") / "N.sol"
    path.write_text(NFTS)
    return {c.name: c for c in Slither(str(path), solc=str(solc)).contracts}


def test_a_token_anyone_can_have_minted_to_them_is_theirs_to_approve(nfts):
    from services.logic.terms import reset_terms

    reset_terms()
    fn = next(f for f in nfts["Tickets"].functions_entry_points if f.name == "approve")
    verdict, _ = function_verdict(nfts["Tickets"], fn, THIS, _Fresh(), {THIS: nfts["Tickets"]})
    assert verdict.openness == "open"


def test_a_token_only_an_admin_mints_stays_a_gate(nfts):
    from services.logic.terms import reset_terms

    reset_terms()
    fn = next(f for f in nfts["Badges"].functions_entry_points if f.name == "approve")
    verdict, _ = function_verdict(nfts["Badges"], fn, THIS, _Fresh(), {THIS: nfts["Badges"]})
    assert verdict.openness != "open"


def test_a_lone_owner_anyone_could_once_claim_is_still_a_gate(nfts):
    from services.logic.terms import reset_terms

    reset_terms()
    fn = next(f for f in nfts["Badges"].functions_entry_points if f.name == "ownerOnly")
    verdict, _ = function_verdict(nfts["Badges"], fn, THIS, _Fresh(), {THIS: nfts["Badges"]})
    assert verdict.openness != "open"


class _Unreadable(_Fresh):
    """A node failing every storage read (a timeout under load)."""

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            raise RuntimeError("upstream timeout")
        return super()._answer(method, params)


def test_an_initializer_whose_flag_cannot_be_read_is_never_open(contract):
    from services.logic.terms import reset_terms

    reset_terms()
    fn = next(f for f in contract.functions_entry_points if f.name == "initialize")
    verdict, _ = function_verdict(contract, fn, THIS, _Unreadable(), {THIS: contract})
    assert verdict.openness != "open"


class _Flaky(_Fresh):
    """The owner's slot fails while the candidates are drawn (a node timing out then), and reads at other times."""

    def __init__(self):
        super().__init__()
        self._memo = _Unremembered()

    def _answer(self, method, params):
        import traceback

        drawing = any(frame.name == "_candidates" for frame in traceback.extract_stack())
        if method == "eth_getStorageAt" and int(params[1], 16) == 0 and drawing:
            raise RuntimeError("upstream timeout")
        return super()._answer(method, params)


class _Unremembered(dict):
    """The owner's slot asked again each time, as a node failing intermittently is."""

    def __contains__(self, key):
        return not (isinstance(key, tuple) and key[:1] == ("s",) and key[2:] == (0,)) and super().__contains__(key)


def test_an_owner_the_node_failed_to_read_is_never_left_out_of_a_complete_list(contract):
    from services.logic.terms import reset_terms

    reset_terms()
    fn = next(f for f in contract.functions_entry_points if f.name == "grant")
    verdict, _ = function_verdict(contract, fn, THIS, _Flaky(), {THIS: contract})
    assert OWNER in verdict.principals or not verdict.complete


GATES = """
pragma solidity 0.8.27;

// A role whose holders no event lists, and a start time still to come.
contract Gates {
    uint256 quorum;
    uint256 start;
    mapping(address => bool) managers;
    uint8 initialized;
    uint256 deadline;

    function addManager(address who) external {
        require(managers[msg.sender]);
        managers[who] = true;
    }

    // HashConsensus's ``disableConsensus``: anyone once it is already disabled, a manager otherwise.
    function disable() external {
        if (quorum != type(uint256).max) {
            require(managers[msg.sender]);
            quorum = type(uint256).max;
        }
    }

    function report() external view {
        require(block.timestamp >= start);
        require(managers[msg.sender]);
    }

    function presale() external view {
        require(block.timestamp < deadline);
    }

    // OpenZeppelin's initializer: never run, or run once and still being constructed.
    function initialize() external {
        require(initialized == 0 || (initialized == 1 && address(this).code.length == 0));
        initialized = 1;
    }
}
"""

NOW, LATER = 1_700_000_000, 1_900_000_000


class _Configured(_Fresh):
    """Quorum 5, a start time still to come, a deadline just passed, initialized once; no logs."""

    def _answer(self, method, params):
        if method == "eth_getStorageAt" and int(params[0], 16) == THIS:
            return hex({0: 5, 1: LATER, 3: 1, 4: NOW - 1}.get(int(params[1], 16), 0))
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(NOW), "number": hex(1)}
        return super()._answer(method, params)


class _CodeUnreadable(_Configured):
    def code(self, address):
        from services.logic.decide import UNK

        return UNK


@pytest.fixture(scope="module")
def gates(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("gates") / "G.sol"
    path.write_text(GATES)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Gates")


def _gate(gates, name, chain):
    from services.logic.terms import reset_terms

    reset_terms()
    fn = next(f for f in gates.functions_entry_points if f.name == name)
    verdict, _ = function_verdict(gates, fn, THIS, chain, {THIS: gates})
    return verdict


def test_a_no_op_for_anyone_is_no_proof_nobody_holds_the_role_that_acts(gates):
    # Open "once allowed" needs nobody passing now; holders no event lists may.
    assert _gate(gates, "disable", _Configured()).openness != "open"


def test_a_start_still_to_come_is_a_wait_not_a_refusal_for_ever(gates):
    verdict = _gate(gates, "report", _Configured())
    assert not (verdict.openness == "restricted" and verdict.complete and not verdict.principals)


def test_an_initializer_is_never_open_on_code_that_could_not_be_read(gates):
    assert _gate(gates, "initialize", _CodeUnreadable()).openness != "open"


def test_a_deadline_already_passed_stays_passed(gates):
    verdict = _gate(gates, "presale", _Configured())
    assert verdict.openness == "restricted" and verdict.complete


NAMESPACED = """
pragma solidity 0.8.27;

// OpenZeppelin 5's layout: roles in an ERC-7201 struct, granted without an event.
contract Spaced {
    struct Roles {
        mapping(address => bool) managers;
    }

    uint256 quorum;

    bytes32 private constant SLOT = 0x02dd7bc7dec4dceedda775e58dd541e08a116c6c53815c0bd028192f7b626800;

    function _roles() private pure returns (Roles storage $) {
        assembly {
            $.slot := SLOT
        }
    }

    function add(address who) external {
        require(_roles().managers[msg.sender]);
        _roles().managers[who] = true;
    }

    function act() external view {
        require(_roles().managers[msg.sender]);
    }

    // Anyone once already disabled, a manager otherwise.
    function disable() external {
        if (quorum != type(uint256).max) {
            require(_roles().managers[msg.sender]);
            quorum = type(uint256).max;
        }
    }
}
"""


class _HistoryRefused(_Configured):
    """Quorum 5; the node gives up on the contract's event history."""

    def logs(self, address, topics):
        self.truncated.add(address)
        return []


def test_holders_of_a_namespaced_role_no_event_lists_leave_the_list_partial(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    from services.logic.terms import reset_terms

    path = tmp_path_factory.mktemp("spaced") / "S.sol"
    path.write_text(NAMESPACED)
    spaced = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Spaced")
    reset_terms()
    fn = next(f for f in spaced.functions_entry_points if f.name == "act")
    verdict, _ = function_verdict(spaced, fn, THIS, _Fresh(), {THIS: spaced})
    assert verdict.openness == "restricted" and not verdict.complete
    # Holders the history couldn't list may act now: no "open once allowed".
    reset_terms()
    fn = next(f for f in spaced.functions_entry_points if f.name == "disable")
    verdict, _ = function_verdict(spaced, fn, THIS, _HistoryRefused(), {THIS: spaced})
    assert verdict.openness != "open"


BURNER = """
pragma solidity 0.8.27;

// Lido's ``burnShares``: one address may burn, and only shares it holds; the holders are every staker.
contract Burner {
    address burner;
    mapping(address => uint256) shares;
    uint256 total;
    event TransferShares(address indexed from, address indexed to, uint256 amount);

    function stake() external payable {
        shares[msg.sender] += msg.value;
        emit TransferShares(address(0), msg.sender, msg.value);
    }

    function burn(uint256 amount) external {
        require(msg.sender == burner);
        require(shares[msg.sender] >= amount);
        shares[msg.sender] -= amount;
        total -= amount;
        emit TransferShares(msg.sender, address(0), amount);
    }
}
"""


class _Watched(_Fresh):
    def __init__(self):
        super().__init__()
        self.asked: list = []

    def logs(self, address, topics):
        self.asked.append(topics)
        return []


def test_a_gate_on_one_named_address_reads_no_holder_history(tmp_path_factory):
    # Every passer of ``msg.sender == burner`` is the burner: the stakers' history names nobody else worth asking.
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    from services.logic.terms import reset_terms

    path = tmp_path_factory.mktemp("burner") / "B.sol"
    path.write_text(BURNER)
    burner = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Burner")
    reset_terms()
    chain = _Watched()
    fn = next(f for f in burner.functions_entry_points if f.name == "burn")
    verdict, _ = function_verdict(burner, fn, THIS, chain, {THIS: burner})
    assert verdict.openness == "restricted" and verdict.principals == {OWNER} and verdict.complete
    assert chain.asked == []


COUNTED = """
pragma solidity 0.8.27;

interface ICounter {
    function count() external view returns (uint256);
}

// Lido CSM's ``depositETH``: nobody is singled out, and an id must be below another contract's count.
contract Counted {
    ICounter counter;

    function act(uint256 id) external view {
        require(id < counter.count());
    }
}
"""


class _CountUnread(_Fresh):
    """The counter's code is there, but the node times out on every call to it."""

    def _answer(self, method, params):
        if method == "eth_call":
            raise RuntimeError("timeout")
        return super()._answer(method, params)

    def code(self, address):
        return b"\x60" if address in (THIS, OWNER) else b""


def test_nobody_singled_out_is_not_open_on_a_check_that_could_not_be_read(tmp_path_factory):
    # With no count read, whether any id passes is unknown: "open" needs a call known to pass, or one known to fail
    # only on conditions that can change (a pause).
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    from services.logic.terms import reset_terms

    path = tmp_path_factory.mktemp("counted") / "N.sol"
    path.write_text(COUNTED)
    counted = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Counted")
    reset_terms()
    fn = next(f for f in counted.functions_entry_points if f.name == "act")
    verdict, _ = function_verdict(counted, fn, THIS, _CountUnread(), {THIS: counted})
    assert verdict.openness == "not_determined"


SWITCH = """
pragma solidity 0.8.27;

// A switch only managers turn off, which anyone may "turn off" again once it is off, and a deposit a manager pauses.
contract Switch {
    uint256 quorum;
    bool paused;
    mapping(address => bool) managers;
    mapping(address => uint256) balances;
    event ManagerAdded(address indexed who);

    function addManager(address who) external {
        require(managers[msg.sender]);
        managers[who] = true;
        emit ManagerAdded(who);
    }

    function disable() external {
        if (quorum != type(uint256).max) {
            require(managers[msg.sender]);
        }
        quorum = type(uint256).max;
    }

    function pause(bool on) external {
        require(managers[msg.sender]);
        paused = on;
    }

    function deposit() external payable {
        require(!paused);
        balances[msg.sender] += msg.value;
    }
}
"""


class _Switched(_Fresh):
    """Quorum 5 and paused; no manager ever added."""

    def _answer(self, method, params):
        if method == "eth_getStorageAt" and int(params[0], 16) == THIS:
            return hex({0: 5, 1: 1}.get(int(params[1], 16), 0))
        return super()._answer(method, params)


@pytest.fixture(scope="module")
def switch(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("switch") / "S.sol"
    path.write_text(SWITCH)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Switch")


def test_what_anyone_may_redo_once_holders_did_it_is_not_open(switch):
    # Strangers pass only once the quorum is already off, a state ``disable`` itself brings about: the power to turn
    # it off is the managers', and there are none.
    verdict = _gate(switch, "disable", _Switched())
    assert verdict.openness == "restricted" and not verdict.principals and verdict.complete


def test_a_paused_public_function_is_still_open_once_unpaused(switch):
    assert _gate(switch, "deposit", _Switched()).openness == "open"


WINDOW = """
pragma solidity 0.8.27;

// EtherFi's ``finalizeWithdrawalsWhenStale``: anyone once a block window passes, unless paused or blocked.
contract Window {
    uint256 start;
    bool paused;
    mapping(address => bool) blocked;
    event Blocked(address indexed who);

    function block_(address who) external {
        require(!blocked[msg.sender]);
        blocked[who] = true;
        emit Blocked(who);
    }

    function go() external view {
        require(block.number >= start);
        require(!paused);
        require(!blocked[msg.sender]);
    }
}
"""


class _PauseUnread(_Fresh):
    """A start block still to come; the node times out on the pause flag."""

    def _answer(self, method, params):
        if method == "eth_getStorageAt" and int(params[0], 16) == THIS:
            slot = int(params[1], 16)
            if slot == 1:
                raise RuntimeError("timeout")
            return hex({0: 100}.get(slot, 0))
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(NOW), "number": hex(1)}
        return super()._answer(method, params)


def test_a_wait_with_a_condition_unread_is_undetermined_not_nobody(tmp_path_factory):
    # A stranger gets through once block 100 comes, unless paused: the pause unread, it may or may not; "nobody,
    # and that is everyone" would claim the pause is on.
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("window") / "W.sol"
    path.write_text(WINDOW)
    window = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Window")
    verdict = _gate(window, "go", _PauseUnread())
    assert verdict.openness == "not_determined"


BANK = """
pragma solidity 0.8.27;

// WeETH's ``unwrap``: only a holder may withdraw, and anyone becomes one by depositing, unless deposits are closed.
contract Bank {
    bool closed;
    mapping(address => uint256) balances;
    mapping(address => uint256) paid;

    function deposit() external payable {
        require(!closed);
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(amount > 0 && balances[msg.sender] >= amount && paid[msg.sender] == 0);
        paid[msg.sender] = amount;
    }
}
"""


class _ClosedUnread(_Fresh):
    def _answer(self, method, params):
        if method == "eth_getStorageAt" and int(params[0], 16) == THIS and int(params[1], 16) == 0:
            raise RuntimeError("timeout")
        return super()._answer(method, params)


def test_a_holding_whose_way_in_could_not_be_read_is_undetermined(tmp_path_factory):
    # Whether deposits are closed is unread, so whether a stranger can become a holder is unknown: not "only holders".
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("bank") / "K.sol"
    path.write_text(BANK)
    bank = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Bank")
    assert _gate(bank, "withdraw", _ClosedUnread()).openness == "not_determined"
    assert _gate(bank, "withdraw", _Fresh()).openness == "open"


ROLES_SOURCE = """
pragma solidity 0.8.27;

// OpenZeppelin's AccessControl, trimmed: each role's holders and the role that administers it.
contract Roles {
    struct RoleData {
        mapping(address => bool) members;
        bytes32 adminRole;
    }
    mapping(bytes32 => RoleData) private _roles;
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant MANAGER = keccak256("MANAGER");
    bytes32 public constant OPERATOR = keccak256("OPERATOR");

    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    function initialize(address admin) external {
        require(!_roles[DEFAULT_ADMIN_ROLE].members[admin]);
        _grant(DEFAULT_ADMIN_ROLE, admin);
        _setRoleAdmin(OPERATOR, MANAGER);
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role].members[account];
    }

    function getRoleAdmin(bytes32 role) public view returns (bytes32) {
        return _roles[role].adminRole;
    }

    function grantRole(bytes32 role, address account) external {
        require(hasRole(getRoleAdmin(role), msg.sender));
        _grant(role, account);
    }

    function revokeRole(bytes32 role, address account) external {
        require(hasRole(getRoleAdmin(role), msg.sender));
        _roles[role].members[account] = false;
        emit RoleRevoked(role, account, msg.sender);
    }

    function _grant(bytes32 role, address account) internal {
        _roles[role].members[account] = true;
        emit RoleGranted(role, account, msg.sender);
    }

    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal {
        bytes32 previous = _roles[role].adminRole;
        _roles[role].adminRole = adminRole;
        emit RoleAdminChanged(role, previous, adminRole);
    }
}
"""


def _slot(*words):
    from eth_utils import keccak

    return int.from_bytes(keccak(b"".join(w.to_bytes(32, "big") for w in words)), "big")


class _RolesChain(_Fresh):
    """A holds the default admin role; B holds OPERATOR, whose admin is MANAGER, which nobody holds."""

    def __init__(self, admin, operator, manager_role, operator_role):
        self.who = (admin, operator)
        self.roles = (manager_role, operator_role)
        super().__init__()

    def _storage(self):
        admin, operator = self.who
        manager_role, operator_role = self.roles
        roles = {0: [admin], operator_role: [operator]}
        out = {}
        for role, members in roles.items():
            base = _slot(role, 0)
            for m in members:
                out[_slot(m, base)] = 1
        out[_slot(operator_role, 0) + 1] = manager_role
        return out

    def _answer(self, method, params):
        if method == "eth_getStorageAt" and int(params[0], 16) == THIS:
            return hex(self._storage().get(int(params[1], 16), 0))
        return super()._answer(method, params)

    def logs(self, address, topics):
        from eth_utils import keccak

        admin, operator = self.who
        manager_role, operator_role = self.roles
        granted = int.from_bytes(keccak(text="RoleGranted(bytes32,address,address)"), "big")
        changed = int.from_bytes(keccak(text="RoleAdminChanged(bytes32,bytes32,bytes32)"), "big")
        rows = [
            ([granted, 0, admin, admin], []),
            ([granted, operator_role, operator, admin], []),
            ([changed, operator_role, 0, manager_role], []),
        ]
        wanted = {int(t, 16) for t in topics}
        return [r for r in rows if r[0][0] in wanted]


def test_a_role_held_only_below_its_admin_is_refused_for_every_role(tmp_path_factory):
    # ``grantRole(role, ...)`` needs the role's admin, and a role's admin is zero or one ``RoleAdminChanged`` set:
    # B, holding only OPERATOR, administers no role, so the list of who may grant is complete.
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from eth_utils import keccak
    from slither import Slither

    path = tmp_path_factory.mktemp("roles") / "R.sol"
    path.write_text(ROLES_SOURCE)
    roles = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Roles")
    manager_role = int.from_bytes(keccak(text="MANAGER"), "big")
    operator_role = int.from_bytes(keccak(text="OPERATOR"), "big")
    admin, operator = 0xAD << 140, 0x0B << 152
    verdict = _gate(roles, "grantRole", _RolesChain(admin, operator, manager_role, operator_role))
    assert verdict.openness == "restricted" and verdict.principals == {admin} and verdict.complete


TETHER = """
pragma solidity 0.8.27;

// USDT's ``approve``: an allowance must be zeroed before it is changed.
contract Tether {
    mapping(address => mapping(address => uint256)) allowed;
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function approve(address spender, uint256 value) external {
        require(msg.data.length >= 68);  // ``onlyPayloadSize(2 * 32)``
        require(value == 0 || allowed[msg.sender][spender] == 0);
        allowed[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
    }
}
"""


def test_a_guess_that_already_passes_reads_no_history(tmp_path_factory):
    # Any spender passes: the approvals' history, a token's crowd, is never read for spenders to try.
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("tether") / "T.sol"
    path.write_text(TETHER)
    tether = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Tether")
    chain = _Watched()
    assert _gate(tether, "approve", chain).openness == "open"
    assert chain.asked == []


LOCKED = """
pragma solidity 0.8.27;

// A transient reentrancy lock (OpenZeppelin's ReentrancyGuardTransient) and OpenZeppelin's ``mulDiv`` remainder.
contract Locked {
    address owner;

    modifier nonReentrant() {
        assembly {
            if tload(0x1234) { revert(0, 0) }
            tstore(0x1234, 1)
        }
        _;
        assembly {
            tstore(0x1234, 0)
        }
    }

    function sweep() external nonReentrant {
        require(msg.sender == owner);
    }

    function poke() external nonReentrant {}

    function split(uint256 amount) external view {
        require(amount > 0 && mulmod(amount, 3, 7) == 3);
    }
}
"""


@pytest.fixture(scope="module")
def locked(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("locked") / "L.sol"
    path.write_text(LOCKED)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Locked")


def test_a_transient_lock_reads_unlocked_when_a_transaction_starts(locked):
    assert _gate(locked, "poke", _Fresh()).openness == "open"
    verdict = _gate(locked, "sweep", _Fresh())
    assert verdict.openness == "restricted" and verdict.principals == {OWNER} and verdict.complete


def test_a_remainder_the_evm_computes_is_computed(locked):
    assert _gate(locked, "split", _Fresh()).openness == "open"


GASSY = """
pragma solidity 0.8.27;

interface IRegistry {
    function allowed(address who) external view returns (bool);
}

// The owner's check, beside a registry's check of the caller the node can't answer: only running the call settles it.
contract Gassy {
    address owner;
    IRegistry registry;

    function act(uint256 amount) external view {
        require(msg.sender == owner && amount > 0);
        require(registry.allowed(msg.sender));
    }
}
"""


REGISTRY_AT = 0x7E9 << 140


class _OwnerRuns(_Fresh):
    """The owner's ``act`` returns when the chain runs it; anyone else's reverts."""

    def _answer(self, method, params):
        if method == "eth_getStorageAt" and int(params[0], 16) == THIS and int(params[1], 16) == 1:
            return hex(REGISTRY_AT)
        if method == "eth_call" and int(params[0]["to"], 16) == REGISTRY_AT:
            raise RuntimeError("timeout")
        if method == "eth_call" and int(params[0]["from"], 16) == OWNER and int(params[0]["to"], 16) == THIS:
            return "0x"
        return super()._answer(method, params)

    def code(self, address):
        return b"\x60" if address in (THIS, REGISTRY_AT) else b""


def test_a_candidate_the_reasoning_leaves_open_is_settled_by_running_its_call(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("gassy") / "G.sol"
    path.write_text(GASSY)
    gassy = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Gassy")
    verdict = _gate(gassy, "act", _OwnerRuns())
    assert verdict.openness == "restricted" and verdict.principals == {OWNER}


INBOX = """
pragma solidity 0.8.27;

// LayerZero's ``nilify`` / ``clear``: anyone can mark its own entry nil, but only a payload's hash clears it.
contract Inbox {
    address admin;
    mapping(address => bytes32) stored;

    function nilify() external {
        stored[msg.sender] = bytes32(type(uint256).max);
    }

    function verify(address who, bytes32 hash) external {
        require(msg.sender == admin);
        stored[who] = hash;
    }

    function clear(bytes calldata message) external {
        require(stored[msg.sender] == keccak256(message));
        stored[msg.sender] = 0;
    }
}
"""


def test_an_entry_one_can_only_mark_never_comes_to_hold_a_hash(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("inbox") / "I.sol"
    path.write_text(INBOX)
    inbox = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Inbox")
    assert _gate(inbox, "clear", _Fresh()).openness != "open"


QUEUE = """
pragma solidity 0.8.27;

// Lido's withdrawal queue: a request is its owner's to claim, and anyone files one, unless requests are closed.
contract Queue {
    bool closed;
    uint256 next;
    mapping(uint256 => address) owners;
    mapping(uint256 => bool) claimed;

    function request() external {
        require(!closed);
        next += 1;
        owners[next] = msg.sender;
    }

    function claim(uint256 id) external {
        require(owners[id] == msg.sender && !claimed[id]);
        claimed[id] = true;
    }
}
"""


def test_a_request_whose_filing_could_not_be_read_is_undetermined(tmp_path_factory):
    # Whether requests are closed is unread, so whether a stranger can file one to claim is unknown: not "nobody".
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("queue") / "Q.sol"
    path.write_text(QUEUE)
    queue = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Queue")
    assert _gate(queue, "claim", _ClosedUnread()).openness == "not_determined"
    assert _gate(queue, "claim", _Fresh()).openness == "open"
