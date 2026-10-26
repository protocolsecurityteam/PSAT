"""State a caller can bring about for itself through open code is no privilege; state only others can grant is. Each
probe is deployed on anvil and each verdict checked against ``eth_call`` (``_oracle.check``): an "open" verdict's own
first calls (``after``) run for every stranger before its call; listed holders pass from their own address; the
arrangements a verdict rests on (an unpause, time passing) are run for real. Fault-injected runs (a node failing
reads) must never be bolder than the chain allows."""

from __future__ import annotations

import pytest
from eth_utils import keccak

from services.logic.decide import FRESH
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

OWNER = O.OWNER
ADMIN, OPERATOR = O.ACCOUNTS[1], O.ACCOUNTS[2]

SOURCE = """
pragma solidity 0.8.27;

contract C {
    address owner;
    bool initialized;
    mapping(address => uint256) balances;
    mapping(address => bool) members;
    mapping(address => mapping(address => bool)) operators;
    mapping(address => mapping(address => bool)) approved;

    constructor() { owner = msg.sender; }

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

    constructor(address o) { admin = msg.sender; owner = o; }

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

// The same badges with the owner never set: whoever claims first is it.
contract Unclaimed is Badges {
    constructor() Badges(address(0)) {}
}
"""

GATES = """
pragma solidity 0.8.27;

// A role whose holders no event lists, and a start time still to come.
contract Gates {
    uint256 quorum;
    uint256 start;
    mapping(address => bool) managers;
    uint8 initialized;
    uint256 deadline;

    constructor(uint256 s, uint256 d) {
        quorum = 5; start = s; deadline = d; initialized = 1;
        managers[msg.sender] = true;
    }

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

// OpenZeppelin 5's layout: roles in an ERC-7201 struct, granted without an event.
contract Spaced {
    struct Roles {
        mapping(address => bool) managers;
    }

    uint256 quorum;

    bytes32 private constant SLOT = 0x02dd7bc7dec4dceedda775e58dd541e08a116c6c53815c0bd028192f7b626800;

    constructor() { quorum = 5; _roles().managers[msg.sender] = true; }

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

// Lido's ``burnShares``: one address may burn, and only shares it holds; the holders are every staker.
contract Burner {
    address burner;
    mapping(address => uint256) shares;
    uint256 total;
    event TransferShares(address indexed from, address indexed to, uint256 amount);

    constructor() { burner = msg.sender; }

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

interface ICounter {
    function count() external view returns (uint256);
}

contract Counter {
    function count() external pure returns (uint256) { return 3; }
}

// Lido CSM's ``depositETH``: nobody is singled out, and an id must be below another contract's count.
contract Counted {
    ICounter counter;

    constructor(ICounter c) { counter = c; }

    function act(uint256 id) external view {
        require(id < counter.count());
    }
}

// A switch only managers turn off, which anyone may "turn off" again once it is off, and a deposit a manager pauses.
contract Switch {
    uint256 quorum;
    bool paused;
    mapping(address => bool) managers;
    mapping(address => uint256) balances;
    event ManagerAdded(address indexed who);

    constructor() { quorum = 5; paused = true; managers[msg.sender] = true; emit ManagerAdded(msg.sender); }

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

// EtherFi's ``finalizeWithdrawalsWhenStale``: anyone once a block window passes, unless paused or blocked.
contract Window {
    uint256 start;
    bool paused;
    mapping(address => bool) blocked;
    event Blocked(address indexed who);

    constructor(uint256 s) { start = s; }

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

// A transient reentrancy lock (OpenZeppelin's ReentrancyGuardTransient) and OpenZeppelin's ``mulDiv`` remainder.
contract Locked {
    address owner;

    constructor() { owner = msg.sender; }

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

interface IRegistry {
    function allowed(address who) external view returns (bool);
}

contract Registry {
    address owner;
    constructor() { owner = msg.sender; }
    function allowed(address who) external view returns (bool) { return who == owner; }
}

// The owner's check, beside a registry's check of the caller the node can't answer: only running the call settles it.
contract Gassy {
    address owner;
    IRegistry registry;

    constructor(IRegistry r) { owner = msg.sender; registry = r; }

    function act(uint256 amount) external view {
        require(msg.sender == owner && amount > 0);
        require(registry.allowed(msg.sender));
    }
}

// LayerZero's ``nilify`` / ``clear``: anyone can mark its own entry nil, but only a payload's hash clears it.
contract Inbox {
    address admin;
    mapping(address => bytes32) stored;

    constructor() { admin = msg.sender; }

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
DAY = 86_400


def _now(d) -> int:
    return int(O.rpc(d.url, "eth_getBlockByNumber", ["latest", False])["timestamp"], 16)


def _setup_c(d):
    d.deploy("C")
    assert O.transact(d, "C", "initialize()")


def _setup_nfts(d):
    d.deploy("Tickets")
    d.deploy("Badges", ("address",), (OWNER,))
    d.deploy("Unclaimed")


def _setup_gates(d):
    now = _now(d)
    d.deploy("Gates", ("uint256", "uint256"), (now + 30 * DAY, now - 1))
    d.deploy("Spaced")
    d.deploy("Burner")
    d.deploy("Counter")
    d.deploy("Counted", ("address",), (d.at["Counter"],))
    d.deploy("Switch")
    d.deploy("Window", ("uint256",), (int(O.rpc(d.url, "eth_blockNumber", []), 16) + 100,))
    d.deploy("Bank")
    d.deploy("Roles")
    assert O.transact(d, "Roles", "initialize(address)", ("address",), (ADMIN,))
    for signature, role, who in (("grantRole", _MANAGER, ADMIN), ("grantRole", _OPERATOR, OPERATOR),
                                 ("revokeRole", _MANAGER, ADMIN)):  # fmt: skip
        assert O.transact(d, "Roles", signature + "(bytes32,address)", ("bytes32", "address"), (role, who), ADMIN)
    d.deploy("Tether")
    d.deploy("Locked")
    d.deploy("Registry")
    d.deploy("Gassy", ("address",), (d.at["Registry"],))
    d.deploy("Inbox")
    d.deploy("Queue")


_OPERATOR = keccak(text="OPERATOR")
_MANAGER = keccak(text="MANAGER")

PROBES = [
    O.Probe(SOURCE, _setup_c, tuple(("C", f, ()) for f in ("withdraw", "withdrawFor", "membersOnly", "pull", "grant"))),
    O.Probe(
        NFTS,
        _setup_nfts,
        (
            ("Tickets", "approve", ()),
            ("Badges", "approve", ()),
            ("Badges", "ownerOnly", ()),
            ("Unclaimed", "ownerOnly", ()),
        ),
    ),  # fmt: skip
    O.Probe(
        GATES,
        _setup_gates,
        (
            ("Gates", "disable", ()),
            ("Gates", "report", ()),
            ("Gates", "presale", ()),
            ("Gates", "initialize", ()),
            ("Spaced", "act", ()),
            ("Spaced", "disable", ()),
            ("Burner", "burn", ()),
            ("Counted", "act", ("Counter",)),
            ("Switch", "disable", ()),
            ("Switch", "deposit", ()),
            ("Window", "go", ()),
            ("Bank", "withdraw", ()),
            ("Roles", "grantRole", ()),
            ("Tether", "approve", ()),
            ("Locked", "poke", ()),
            ("Locked", "sweep", ()),
            ("Locked", "split", ()),
            ("Gassy", "act", ("Registry",)),
            ("Inbox", "clear", ()),
            ("Queue", "claim", ()),
        ),
    ),  # fmt: skip
]


@pytest.fixture(scope="module")
def c(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup_c(d)
    return d


@pytest.fixture(scope="module")
def nfts(anvil):  # noqa: F811
    d = O.deployment(*anvil, NFTS)
    _setup_nfts(d)
    return d


@pytest.fixture(scope="module")
def g(anvil):  # noqa: F811
    d = O.deployment(*anvil, GATES)
    _setup_gates(d)
    return d


def test_withdrawing_what_anyone_may_deposit_is_open(c):
    v = O.check(c, "C", "withdraw", O.verdict(c, "C", "withdraw"), arrange=_deposit_c, open_at={"amount": 1})
    assert v.openness == "open"


def test_acting_for_an_account_is_open_to_that_account(c):
    v = O.verdict(c, "C", "withdrawFor")
    O.check(c, "C", "withdrawFor", v, arrange=_deposit_c, open_at={"account": FRESH, "amount": 1})
    assert v.openness == "open"


def test_membership_only_an_owner_grants_stays_a_gate(c):
    v = O.check(c, "C", "membersOnly", O.verdict(c, "C", "membersOnly"), open_at=False)
    assert v.openness != "open"
    assert not O.transact(c, "C", "initialize()", sender=O.STRANGERS[0])  # already spent


def test_an_approval_only_someone_else_can_give_stays_a_gate(c):
    v = O.verdict(c, "C", "pull")
    O.check(c, "C", "pull", v, samples=({"from": OWNER}, {"from": FRESH}, {}), open_at=False)
    assert v.openness != "open"


def test_a_gate_stays_a_gate_after_other_analyses_of_the_same_code(c):
    # Lowered writers are kept per contract across analyses whose terms are interned apart (another deployment of
    # the same code): ``renounce`` still only takes membership away.
    clean = O.verdict(c, "C", "membersOnly")
    O.verdict(c, "C", "withdraw")
    again = O.verdict(c, "C", "membersOnly")
    assert (again.openness, again.principals, again.complete) == (clean.openness, clean.principals, clean.complete)


def _deposit_c(d, who):
    assert O.transact(d, "C", "deposit(uint256)", ("uint256",), (5,), sender=who)


def test_a_token_anyone_can_have_minted_to_them_is_theirs_to_approve(nfts):
    v = O.verdict(nfts, "Tickets", "approve")
    O.check(nfts, "Tickets", "approve", v, arrange=_request_ticket, open_at={"to": OWNER, "id": 1})
    assert v.openness == "open"


def test_a_token_only_an_admin_mints_stays_a_gate(nfts):
    v = O.verdict(nfts, "Badges", "approve")
    O.check(nfts, "Badges", "approve", v, samples=({"id": 0}, {"id": 1}), open_at=False)
    assert v.openness != "open"


def _request_ticket(d, who):
    assert O.transact(d, "Tickets", "request(address)", ("address",), (0,), sender=who)


def test_a_lone_owner_once_claimed_is_still_a_gate(nfts):
    v = O.check(nfts, "Badges", "ownerOnly", O.verdict(nfts, "Badges", "ownerOnly"), open_at=False)
    assert v.openness == "restricted" and set(v.principals) == {OWNER}
    assert not O.transact(nfts, "Badges", "claim()", sender=O.STRANGERS[0])


@pytest.mark.xfail(
    strict=True,
    reason="G4: identity state nobody holds now, which a stranger's own claim() sets, "
    "is reported 'restricted, complete, nobody'",
)
def test_a_lone_owner_anyone_may_still_claim_is_each_strangers_to_take(nfts):
    # Owner never set: every stranger's own ``claim`` lets it through, so "restricted" would be false.
    v = O.check(nfts, "Unclaimed", "ownerOnly", O.verdict(nfts, "Unclaimed", "ownerOnly"))
    O.sound(v, anyone=True)
    for who in O.STRANGERS:
        with O.snapshot(nfts):
            assert O.transact(nfts, "Unclaimed", "claim()", sender=who)
            assert O.passes(nfts, "Unclaimed", O.function(nfts, "Unclaimed", "ownerOnly"), sender=who)


def test_a_lone_owner_verdict_holds_as_the_chain_stands(nfts):
    # The G4 xfail above asks for more than "nobody now"; whatever the verdict says must still hold now.
    v = O.check(nfts, "Unclaimed", "ownerOnly", O.verdict(nfts, "Unclaimed", "ownerOnly"), open_at=False)
    assert O.strangers_passing(nfts, "Unclaimed", O.function(nfts, "Unclaimed", "ownerOnly")) == {False}, v


def test_an_initializer_whose_flag_cannot_be_read_is_never_open(c):
    clean = O.verdict(c, "C", "initialize")
    faulted = O.verdict(c, "C", "initialize", chain=O.Faulty(c, storage=True))
    assert faulted.openness != "open"
    O.never_bolder(clean, faulted)


class _Unremembered(dict):
    """The owner's slot asked again each time, as a node failing intermittently is."""

    def __contains__(self, key):
        return not (isinstance(key, tuple) and key[:1] == ("s",) and key[2:] == (0,)) and super().__contains__(key)


def test_an_owner_the_node_failed_to_read_is_never_left_out_of_a_complete_list(c):
    import traceback

    def drawing(method, params):  # the owner's slot fails while the candidates are drawn, and reads otherwise
        return int(params[1], 16) == 0 and any(f.name == "_candidates" for f in traceback.extract_stack())

    chain = O.Faulty(c, storage=drawing)
    chain._memo = _Unremembered()
    v = O.verdict(c, "C", "grant", chain=chain)
    assert OWNER in v.principals or not v.complete
    O.check(c, "C", "grant", v, samples=({"who": OWNER},))


def test_a_no_op_for_anyone_is_no_proof_nobody_holds_the_role_that_acts(g):
    # Open "once allowed" needs nobody passing now; holders no event lists may (the deployer is a manager).
    v = O.check(g, "Gates", "disable", O.verdict(g, "Gates", "disable"), open_at=False)
    assert v.openness != "open"
    assert O.passes(g, "Gates", O.function(g, "Gates", "disable"), sender=OWNER)


def test_a_start_still_to_come_is_a_wait_not_a_refusal_for_ever(g):
    v = O.check(g, "Gates", "report", O.verdict(g, "Gates", "report"), open_at=False)
    assert not O.nobody(v)
    report = O.function(g, "Gates", "report")
    with O.snapshot(g):  # once the start comes, the manager passes
        O.rpc(g.url, "evm_increaseTime", [31 * DAY])
        O.rpc(g.url, "evm_mine", [])
        assert O.passes(g, "Gates", report, sender=OWNER)
        assert O.strangers_passing(g, "Gates", report) == {False}


def test_an_initializer_is_never_open_on_code_that_could_not_be_read(g):
    clean = O.check(g, "Gates", "initialize", O.verdict(g, "Gates", "initialize"))
    faulted = O.verdict(g, "Gates", "initialize", chain=O.Faulty(g, code=True))
    assert faulted.openness != "open"
    O.never_bolder(clean, faulted)


def test_a_deadline_already_passed_stays_passed(g):
    v = O.check(g, "Gates", "presale", O.verdict(g, "Gates", "presale"))
    assert O.nobody(v)
    with O.snapshot(g):  # time only moves on
        O.rpc(g.url, "evm_increaseTime", [365 * DAY])
        O.rpc(g.url, "evm_mine", [])
        assert O.strangers_passing(g, "Gates", O.function(g, "Gates", "presale")) == {False}


def test_holders_of_a_namespaced_role_no_event_lists_leave_the_list_partial(g):
    v = O.check(g, "Spaced", "act", O.verdict(g, "Spaced", "act"))
    assert v.openness == "restricted" and not v.complete
    assert O.passes(g, "Spaced", O.function(g, "Spaced", "act"), sender=OWNER)  # the unlisted manager
    # Holders the history couldn't list may act now: no "open once allowed".
    clean = O.verdict(g, "Spaced", "disable")
    faulted = O.verdict(g, "Spaced", "disable", chain=O.Faulty(g, logs=True))
    assert faulted.openness != "open"
    O.never_bolder(clean, faulted)


def test_a_gate_on_one_named_address_lists_it_whole(g):
    # Every passer of ``msg.sender == burner`` is the burner: the stakers' history names nobody else worth asking.
    v = O.check(g, "Burner", "burn", O.verdict(g, "Burner", "burn"), samples=({"amount": 0},))
    assert v.openness == "restricted" and set(v.principals) == {OWNER} and v.complete


def test_nobody_singled_out_is_not_open_on_a_check_that_could_not_be_read(g):
    # With no count read, whether any id passes is unknown: "open" needs a call known to pass, or one known to fail
    # only on conditions that can change (a pause).
    clean = O.check(g, "Counted", "act", O.verdict(g, "Counted", "act", "Counter"), open_at={"id": 1})
    faulted = O.verdict(g, "Counted", "act", "Counter", chain=O.Faulty(g, calls=True))
    assert faulted.openness == "not_determined"
    O.never_bolder(clean, faulted)


def test_what_anyone_may_redo_once_holders_did_it_is_not_open(g):
    # Strangers pass only once the quorum is already off, a state ``disable`` itself brings about (for a manager),
    # and then do nothing: never open now, and never "nobody, ever".
    v = O.check(g, "Switch", "disable", O.verdict(g, "Switch", "disable"), open_at=False)
    O.sound(v, {OWNER})
    assert not O.nobody(v)
    disable = O.function(g, "Switch", "disable")
    with O.snapshot(g):
        assert O.transact(g, "Switch", "disable()", sender=OWNER)
        assert O.strangers_passing(g, "Switch", disable) == {True}


def _unpause(g):
    assert O.transact(g, "Switch", "pause(bool)", ("bool",), (False,), sender=OWNER)


def test_a_paused_public_function_is_still_open_once_unpaused(g):
    # Open later: the manager unpauses, and every stranger passes then.
    v = O.check(g, "Switch", "deposit", O.verdict(g, "Switch", "deposit"), open_at=False, later=_unpause)
    assert v.openness == "open" and v.allowed != "now"


def test_a_wait_with_a_condition_unread_is_undetermined_not_nobody(g):
    # A stranger gets through once block 100 comes, unless paused: the pause unread, it may or may not; "nobody,
    # and that is everyone" would claim the pause is on.
    window = g.at["Window"]

    def pause_slot(method, params):
        return int(params[0], 16) == window and int(params[1], 16) == 1

    clean = O.check(g, "Window", "go", O.verdict(g, "Window", "go"), open_at=False)
    faulted = O.verdict(g, "Window", "go", chain=O.Faulty(g, storage=pause_slot))
    assert faulted.openness == "not_determined"
    O.never_bolder(clean, faulted)


def _closed_slot(d, name):
    at = d.at[name]
    return lambda method, params: int(params[0], 16) == at and int(params[1], 16) == 0


def test_a_holding_whose_way_in_could_not_be_read_is_undetermined(g):
    # Whether deposits are closed is unread, so whether a stranger can become a holder is unknown: not "only holders".
    clean = O.check(g, "Bank", "withdraw", O.verdict(g, "Bank", "withdraw"), arrange=_deposit, open_at={"amount": 1})
    assert clean.openness == "open"
    faulted = O.verdict(g, "Bank", "withdraw", chain=O.Faulty(g, storage=_closed_slot(g, "Bank")))
    assert faulted.openness == "not_determined"
    O.never_bolder(clean, faulted)


def _deposit(d, who):
    assert O.transact(d, "Bank", "deposit()", sender=who, value=10)


def test_a_role_held_only_below_its_admin_is_refused_for_every_role(g):
    # ``grantRole(role, ...)`` needs the role's admin, and a role's admin is zero or one ``RoleAdminChanged`` set:
    # the operator, holding only OPERATOR, administers no role, so the list of who may grant is complete.
    samples = [{"role": r, "account": OPERATOR} for r in (bytes(32), _OPERATOR, _MANAGER)]
    v = O.check(g, "Roles", "grantRole", O.verdict(g, "Roles", "grantRole"), samples=samples)
    assert v.openness == "restricted" and set(v.principals) == {ADMIN} and v.complete


def test_a_guess_that_already_passes_is_open(g):
    v = O.verdict(g, "Tether", "approve")
    O.check(g, "Tether", "approve", v, open_at={"spender": OWNER, "value": 5})


def test_a_transient_lock_reads_unlocked_when_a_transaction_starts(g):
    O.check(g, "Locked", "poke", O.verdict(g, "Locked", "poke"), open_at={})
    v = O.check(g, "Locked", "sweep", O.verdict(g, "Locked", "sweep"))
    assert v.openness == "restricted" and set(v.principals) == {OWNER} and v.complete


def test_a_remainder_the_evm_computes_is_computed(g):
    O.check(g, "Locked", "split", O.verdict(g, "Locked", "split"), open_at={"amount": 1})


def test_a_candidate_the_reasoning_leaves_open_is_settled_by_running_its_call(g):
    v = O.verdict(g, "Gassy", "act", "Registry", chain=O.Faulty(g, calls={g.at["Registry"]}))
    O.check(g, "Gassy", "act", v, samples=({"amount": 1},))
    assert v.openness == "restricted" and set(v.principals) == {OWNER}


def test_an_entry_one_can_only_mark_never_comes_to_hold_a_hash(g):
    v = O.verdict(g, "Inbox", "clear")
    O.check(g, "Inbox", "clear", v, samples=({"message": b""}, {"message": b"x"}), open_at=False)
    assert v.openness != "open"
    clear = O.function(g, "Inbox", "clear")
    with O.snapshot(g):  # a stranger's own nilify is no way in
        for who in O.STRANGERS:
            assert O.transact(g, "Inbox", "nilify()", sender=who)
        assert O.strangers_passing(g, "Inbox", clear, {"message": b""}) == {False}


def _file(d, who):
    assert O.transact(d, "Queue", "request()", sender=who)


def test_a_request_whose_filing_could_not_be_read_is_undetermined(g):
    # Whether requests are closed is unread, so whether a stranger can file one to claim is unknown: not "nobody".
    clean = O.check(g, "Queue", "claim", O.verdict(g, "Queue", "claim"), arrange=_file, open_at={"id": 1})
    assert clean.openness == "open"
    faulted = O.verdict(g, "Queue", "claim", chain=O.Faulty(g, storage=_closed_slot(g, "Queue")))
    assert faulted.openness == "not_determined"
    O.never_bolder(clean, faulted)


def test_disabling_what_only_a_manager_may_disable_holds_against_the_chain(g):
    # Quorum is 5: only a manager (the deployer, its role in namespaced storage) passes now.
    v = O.check(g, "Spaced", "disable", O.verdict(g, "Spaced", "disable"), open_at=False)
    O.sound(v, {OWNER})
