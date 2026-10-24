"""Pool shapes: a token pull through assembly to a token with a blacklist, and a deposit gated on the receiver by
another contract's allowlist. Deployed on anvil (the legacy token compiled with solc 0.4.19 beside the rest) and
checked against ``eth_call`` (``_oracle.check``): an "open" pull passes for each stranger once a holder has handed it
tokens and it has approved the puller; a gate fails for every stranger; listed holders pass from their own address."""

from __future__ import annotations

import pytest

from services.logic.terms import reset_terms
from services.logic.verdict import function_verdict
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

ADMIN = O.ACCOUNTS[1]
LENDER = 0xF6 << 140
MANAGERS = {i: (0x5EED << 140) + i for i in range(40)}  # forty operators, each with its manager

SOURCE = """
pragma solidity 0.8.27;

interface IERC20 {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

// USDT's shape: no return value, a blacklist only the owner fills, balances holders move to anyone.
contract Blacklisting {
    address owner;
    mapping(address => bool) isBlackListed;
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;

    constructor() { owner = msg.sender; balances[msg.sender] = 1e24; }

    function addBlackList(address who) external {
        require(msg.sender == owner);
        isBlackListed[who] = true;
    }

    function approve(address spender, uint256 amount) external {
        allowed[msg.sender][spender] = amount;
    }

    function transfer(address to, uint256 amount) external {
        require(!isBlackListed[msg.sender] && balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function transferFrom(address from, address to, uint256 amount) external {
        require(!isBlackListed[from]);
        require(balances[from] >= amount && allowed[from][msg.sender] >= amount);
        allowed[from][msg.sender] -= amount;
        balances[from] -= amount;
        balances[to] += amount;
    }
}

// Only senders the owner listed move tokens.
contract Listing {
    address owner;
    mapping(address => bool) sender;
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;

    constructor() { owner = msg.sender; balances[msg.sender] = 1e24; }

    function list(address who) external {
        require(msg.sender == owner);
        sender[who] = true;
    }

    function approve(address spender, uint256 amount) external {
        allowed[msg.sender][spender] = amount;
    }

    function transfer(address to, uint256 amount) external {
        require(sender[msg.sender] && balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function transferFrom(address from, address to, uint256 amount) external {
        require(sender[from]);
        require(balances[from] >= amount && allowed[from][msg.sender] >= amount);
        allowed[from][msg.sender] -= amount;
        balances[from] -= amount;
        balances[to] += amount;
    }
}

// A token answering ``true``.
contract Answering {
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;

    constructor() { balances[msg.sender] = 1e24; }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowed[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balances[from] >= amount && allowed[from][msg.sender] >= amount);
        allowed[from][msg.sender] -= amount;
        balances[from] -= amount;
        balances[to] += amount;
        return true;
    }
}

// Lido's node operator registry shape: each operator's manager, set by an admin and logged.
contract Managed {
    address admin;
    mapping(uint256 => address) managers;

    constructor() { admin = msg.sender; }

    event ManagerSet(uint256 indexed id, address manager);

    function setManager(uint256 id, address manager) external {
        require(msg.sender == admin);
        managers[id] = manager;
        emit ManagerSet(id, manager);
    }

    function act(uint256 id) external view {
        require(managers[id] == msg.sender);
    }
}

// Aave's ``reserve.cache()``: a memory struct filled field by field, then read.
contract Cached {
    struct Config {
        address admin;
        uint256 cap;
    }

    Config config;

    constructor(address a) { config.admin = a; }

    function _cache() internal view returns (Config memory cached) {
        cached.admin = config.admin;
        cached.cap = config.cap;
    }

    function setCap(uint256 cap) external {
        Config memory cached = _cache();
        require(msg.sender == cached.admin);
        config.cap = cap;
    }

    // A field set on one branch only: the struct merged field by field after.
    function raiseCap(uint256 cap) external {
        Config memory cached = _cache();
        if (cap > cached.cap) cached.cap = cap;
        require(msg.sender == cached.admin);
        config.cap = cached.cap;
    }
}

// OpenZeppelin 5's ``SafeERC20._safeTransferFrom``, as Aave v4's spokes pull.
contract Puller {
    address token;

    constructor(address t) { token = t; }

    function deposit(uint256 amount) external {
        require(amount > 0);
        require(_pull(token, msg.sender, address(this), amount));
    }

    function _pull(address token_, address from, address to, uint256 value) private returns (bool success) {
        bytes4 selector = IERC20.transferFrom.selector;
        assembly ("memory-safe") {
            let fmp := mload(0x40)
            mstore(0x00, selector)
            mstore(0x04, and(from, shr(96, not(0))))
            mstore(0x24, and(to, shr(96, not(0))))
            mstore(0x44, value)
            success := call(gas(), token_, 0, 0x00, 0x64, 0x00, 0x20)
            if iszero(and(success, eq(mload(0x00), 1))) {
                success := and(success, and(iszero(returndatasize()), gt(extcodesize(token_), 0)))
            }
            mstore(0x40, fmp)
            mstore(0x60, 0)
        }
    }
}

// GPv2's ``safeTransferFrom``, as Aave v3's pools pull: the call built at the free memory pointer, its result read
// back in another function.
contract GPv2Puller {
    address token;

    constructor(address t) { token = t; }

    function supply(uint256 amount) external {
        require(amount > 0);
        _safeTransferFrom(token, msg.sender, address(this), amount);
    }

    function _safeTransferFrom(address token_, address from, address to, uint256 value) internal {
        bytes4 selector_ = IERC20.transferFrom.selector;
        assembly {
            let freeMemoryPointer := mload(0x40)
            mstore(freeMemoryPointer, selector_)
            mstore(add(freeMemoryPointer, 4), and(from, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(add(freeMemoryPointer, 36), and(to, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(add(freeMemoryPointer, 68), value)
            if iszero(call(gas(), token_, 0, freeMemoryPointer, 100, 0, 0)) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }
        require(_lastTransferResult(token_), "GPv2: failed transferFrom");
    }

    function _lastTransferResult(address token_) private view returns (bool success) {
        assembly {
            switch returndatasize()
            case 0 {
                if iszero(extcodesize(token_)) { revert(0, 0) }
                success := 1
            }
            case 32 {
                returndatacopy(0, 0, returndatasize())
                success := iszero(iszero(mload(0)))
            }
            default { revert(0, 0) }
        }
    }
}

// Maple's shape: the pool asks its manager, which decodes the arguments and asks its permission manager about the
// receiver, a lender an admin allowlists.
contract Permissions {
    address admin;
    mapping(address => bool) allowlist;

    constructor() { admin = msg.sender; }

    event AllowlistSet(address indexed lender, bool allowed);

    function setAllowed(address lender, bool allowed) external {
        require(msg.sender == admin);
        allowlist[lender] = allowed;
        emit AllowlistSet(lender, allowed);
    }

    function hasPermission(address lender) external view returns (bool) {
        return allowlist[lender];
    }
}

contract Manager {
    Permissions permissions;

    constructor(Permissions p) { permissions = p; }

    function canCall(address, bytes calldata data) external view returns (bool) {
        uint256[3] memory words = _decode(data);
        return permissions.hasPermission(address(uint160(words[1])));
    }

    function _decode(bytes calldata data) internal pure returns (uint256[3] memory words) {
        if (data.length > 64) {
            (words[0], words[1], words[2]) = abi.decode(data, (uint256, uint256, uint256));
        } else {
            (words[0], words[1]) = abi.decode(data, (uint256, uint256));
        }
    }
}

// Maple's permission manager: an allowlist, else the lender's bitmap against the pool's, one per function unless the
// pool is set to one bitmap for all.
contract Bitmaps {
    address admin;
    uint256 level;
    mapping(bytes32 => uint256) poolBitmaps;
    mapping(address => uint256) lenderBitmaps;
    mapping(address => bool) allowlist;

    event LenderBitmapSet(address indexed lender, uint256 bitmap);
    event AllowlistSet(address indexed lender, bool allowed);

    // A bitmap per function, each requiring bit 0.
    constructor() { admin = msg.sender; level = 2; poolBitmaps["P:deposit"] = 1; poolBitmaps["P:transfer"] = 1; }

    function setLenderBitmap(address lender, uint256 bitmap) external {
        require(msg.sender == admin);
        lenderBitmaps[lender] = bitmap;
        emit LenderBitmapSet(lender, bitmap);
    }

    function setAllowed(address lender, bool allowed) external {
        require(msg.sender == admin);
        allowlist[lender] = allowed;
        emit AllowlistSet(lender, allowed);
    }

    function hasPermission(address lender, bytes32 functionId) public view returns (bool) {
        if (allowlist[lender]) return true;
        if (level == 1) functionId = bytes32(0);
        uint256 bitmap = poolBitmaps[functionId];
        return (bitmap & lenderBitmaps[lender]) == bitmap;
    }

    function hasPermissions(address[] calldata lenders, bytes32 functionId) external view returns (bool) {
        for (uint256 i; i < lenders.length; ++i) {
            if (!hasPermission(lenders[i], functionId)) return false;
        }
        return true;
    }
}

contract Router {
    Bitmaps permissions;

    constructor(Bitmaps b) { permissions = b; }

    function deposit() external {
        require(permissions.hasPermission(msg.sender, "P:deposit"));
    }

    // Both ends of a transfer checked in one call, here to the router itself.
    function transferIn() external {
        address[] memory both = new address[](2);
        both[0] = msg.sender;
        both[1] = address(this);
        require(permissions.hasPermissions(both, "P:transfer"));
    }
}

contract Pool {
    Manager manager;
    mapping(address => uint256) shares;

    constructor(Manager m) { manager = m; }

    function deposit(uint256 assets, address receiver) external {
        require(manager.canCall(msg.sender, abi.encode(assets, receiver)));
        shares[receiver] += assets;
    }

    // Three words: the manager's other branch fills ``words`` differently, ``words[1]`` the receiver still.
    function deposit3(uint256 assets, address receiver) external {
        require(manager.canCall(msg.sender, abi.encode(assets, receiver, uint256(0))));
        shares[receiver] += assets;
    }
}

// One puller per token (each keeps its token at deployment).
contract PullerBlacklisting is Puller { constructor(address t) Puller(t) {} }
contract PullerListing is Puller { constructor(address t) Puller(t) {} }
contract PullerTether is Puller { constructor(address t) Puller(t) {} }
contract GPv2Blacklisting is GPv2Puller { constructor(address t) GPv2Puller(t) {} }
contract GPv2Answering is GPv2Puller { constructor(address t) GPv2Puller(t) {} }
contract GPv2Tether is GPv2Puller { constructor(address t) GPv2Puller(t) {} }
contract GPv2Listing is GPv2Puller { constructor(address t) GPv2Puller(t) {} }
"""

LEGACY = """
pragma solidity 0.4.19;

contract Moves {
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;

    function Moves() public { balances[msg.sender] = 10 ** 24; }

    function approve(address spender, uint256 amount) public {
        allowed[msg.sender][spender] = amount;
    }

    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function move(address from, address to, uint256 amount) internal {
        require(balances[from] >= amount && allowed[from][msg.sender] >= amount);
        allowed[from][msg.sender] -= amount;
        balances[from] -= amount;
        balances[to] += amount;
    }
}

// USDT's ``transferFrom``: declared to return nothing, ``return super...`` as solc 0.4 allows.
contract Tether is Moves {
    function transferFrom(address from, address to, uint256 amount) public {
        return move(from, to, amount);
    }
}
"""


def _setup(d):
    tether = O.deployment(d.url, d.root, LEGACY, "0.4.19")
    tether.deploy("Tether")
    d.legacy = tether
    for token in ("Blacklisting", "Listing", "Answering"):
        d.deploy(token)
    tokens = {"Blacklisting": d.at["Blacklisting"], "Listing": d.at["Listing"], "Answering": d.at["Answering"],
              "Tether": tether.at["Tether"]}  # fmt: skip
    for puller in ("PullerBlacklisting", "PullerListing", "PullerTether", "GPv2Blacklisting", "GPv2Answering",
                   "GPv2Tether", "GPv2Listing"):  # fmt: skip
        d.deploy(puller, ("address",), (tokens[puller.removeprefix("Puller").removeprefix("GPv2")],))
    d.deploy("Cached", ("address",), (ADMIN,))
    d.deploy("Managed")
    for i, manager in MANAGERS.items():
        assert O.transact(d, "Managed", "setManager(uint256,address)", ("uint256", "address"), (i, manager))
    d.deploy("Permissions")
    assert O.transact(d, "Permissions", "setAllowed(address,bool)", ("address", "bool"), (LENDER, True))
    d.deploy("Manager", ("address",), (d.at["Permissions"],))
    d.deploy("Pool", ("address",), (d.at["Manager"],))
    d.deploy("Bitmaps")
    d.deploy("Router", ("address",), (d.at["Bitmaps"],))


PROBES = [
    O.Probe(
        SOURCE,
        _setup,
        (
            ("PullerBlacklisting", "deposit", ("Blacklisting",)), ("PullerListing", "deposit", ("Listing",)),
            ("PullerTether", "deposit", ()), ("GPv2Blacklisting", "supply", ("Blacklisting",)),
            ("GPv2Answering", "supply", ("Answering",)), ("GPv2Tether", "supply", ()),
            ("GPv2Listing", "supply", ("Listing",)), ("Cached", "setCap", ()), ("Cached", "raiseCap", ()),
            ("Managed", "act", ()), ("Pool", "deposit", ("Manager", "Permissions")),
            ("Pool", "deposit3", ("Manager", "Permissions")), ("Router", "deposit", ("Bitmaps",)),
            ("Router", "transferIn", ("Bitmaps",)),
        ),
    )
]  # fmt: skip


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def _verdict(d, contract, name, token):
    """``contract.name`` with its token followed (the legacy ``Tether`` from its own compilation)."""
    if token != "Tether":
        return O.verdict(d, contract, name, token)
    reset_terms()
    c, at, tether = d.slither[contract], d.at[contract], d.legacy.at["Tether"]
    contracts = {at: c, tether: d.legacy.slither["Tether"]}
    return function_verdict(c, O.function(d, contract, name), at, d.chain(), contracts)[0]


def _token_at(d, token):
    return d.legacy.at["Tether"] if token == "Tether" else d.at[token]


def _funded(token, puller, amount=5):
    """A stranger handed ``amount`` of ``token`` by its holder, approving ``puller`` for it."""

    def arrange(d, who):
        at = _token_at(d, token)
        assert O.transact(d, at, "transfer(address,uint256)", ("address", "uint256"), (who, amount))
        assert O.transact(d, at, "approve(address,uint256)", ("address", "uint256"), (d.at[puller], amount), who)

    return arrange


@pytest.mark.parametrize("token", ["Blacklisting", "Tether"])
def test_a_pull_from_a_token_whose_blacklist_a_stranger_is_not_on_stays_open(d, token):
    # The stranger can't bring about its blacklist entry, but needn't: its balance and allowance are what it lacks.
    # ``Tether`` returns nothing: OpenZeppelin's pull passes on empty return data from code, whatever its legacy
    # ``return`` statements say.
    puller = "Puller" + token
    v = O.check(d, puller, "deposit", _verdict(d, puller, "deposit", token), arrange=_funded(token, puller),
                open_at={"amount": 5})  # fmt: skip
    assert v.openness == "open"


def test_a_pull_from_a_token_only_listed_senders_move_is_never_open(d):
    v = O.verdict(d, "PullerListing", "deposit", "Listing")
    O.check(d, "PullerListing", "deposit", v, samples=({"amount": 0}, {"amount": 1}), open_at=False)
    assert v.openness != "open"


@pytest.mark.parametrize("token", ["Blacklisting", "Tether", "Answering"])
def test_a_pull_built_at_the_free_memory_pointer_is_the_transfer_it_encodes(d, token):
    # Open to whoever holds and approves the token, whether it returns a bool or nothing.
    puller = "GPv2" + token
    v = O.check(d, puller, "supply", _verdict(d, puller, "supply", token), arrange=_funded(token, puller),
                open_at={"amount": 5})  # fmt: skip
    assert v.openness == "open"


def test_a_pull_built_at_the_free_memory_pointer_from_a_listing_token_is_never_open(d):
    v = O.verdict(d, "GPv2Listing", "supply", "Listing")
    O.check(d, "GPv2Listing", "supply", v, samples=({"amount": 1},), open_at=False)
    assert v.openness != "open"


@pytest.mark.parametrize("name", ["setCap", "raiseCap"])
def test_a_memory_struct_filled_field_by_field_reads_back_what_was_put_there(d, name):
    v = O.check(d, "Cached", name, O.verdict(d, "Cached", name), samples=({"cap": 0}, {"cap": 7}))
    assert v.openness == "restricted" and set(v.principals) == {ADMIN}


def test_a_stranger_failing_is_kept_when_candidates_spend_the_budget(d, monkeypatch):
    # The stranger's question is answered before the candidates'; running out of work on them leaves the list
    # partial, not the verdict unknown.
    from services.logic import decide

    samples = ({"id": 0}, {"id": 39})
    clean = O.check(d, "Managed", "act", O.verdict(d, "Managed", "act"), samples=samples)
    monkeypatch.setattr(decide, "DECISION_WORK", 40 * decide.QUESTION_WORK)
    v = O.check(d, "Managed", "act", O.verdict(d, "Managed", "act"), samples=samples)
    assert v.openness == "restricted" and not v.complete
    O.never_bolder(clean, v)


@pytest.mark.parametrize("name", ["deposit", "deposit3"])
def test_a_deposit_for_a_receiver_another_contract_allowlists_is_open(d, name):
    # Anyone deposits for the allowlisted lender: the receiver is tried from the allowlist's own events. With three
    # words of data, ``words[1]`` is still the receiver, read item by item.
    v = O.verdict(d, "Pool", name, "Manager", "Permissions")
    O.check(d, "Pool", name, v, open_at={"assets": 1, "receiver": LENDER})
    deposit = O.function(d, "Pool", name)
    assert O.strangers_passing(d, "Pool", deposit, {"assets": 1, "receiver": O.STRANGERS[0]}) == {False}


def test_a_bitmap_read_at_a_key_the_lender_only_picks_between_is_a_gate(d):
    # ``poolBitmaps[allowlisted ? ... : level == 1 ? 0 : id]``: the caller picks between fixed keys, the same for
    # every address no lookup names, so a stranger failing stands for them all.
    v = O.check(d, "Router", "deposit", O.verdict(d, "Router", "deposit", "Bitmaps"), open_at=False)
    assert v.openness == "restricted"


def test_a_check_handed_the_caller_in_an_array_is_a_gate(d):
    v = O.check(d, "Router", "transferIn", O.verdict(d, "Router", "transferIn", "Bitmaps"), open_at=False)
    assert v.openness == "restricted"


@pytest.mark.parametrize(("puller", "name"), [("PullerTether", "deposit"), ("GPv2Tether", "supply")])
def test_a_pull_from_a_token_not_followed_holds_against_the_chain(d, puller, name):
    # Nothing shows what the token's ``transferFrom`` checks of the caller it is handed: whatever the verdict, it
    # claims nothing a funded stranger's own call doesn't show.
    v = O.verdict(d, puller, name)
    O.check(d, puller, name, v, arrange=_funded("Tether", puller), samples=({"amount": 5},))
