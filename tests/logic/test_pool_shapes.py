"""Pool shapes: a token pull through assembly to a token with a blacklist, and a deposit gated on the receiver by
another contract's allowlist."""

from __future__ import annotations

import pytest
from eth_utils import keccak

from services.logic.decide import Chain
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path

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

    function deposit(uint256 assets, address receiver) external {
        require(manager.canCall(msg.sender, abi.encode(assets, receiver)));
        shares[receiver] += assets;
    }
}
"""

PULLER, TOKEN = 0xA1 << 140, 0xB2 << 140
POOL, MANAGER, PERMISSIONS, LENDER = 0xC3 << 140, 0xD4 << 140, 0xE5 << 140, 0xF6 << 140
ROUTER, BITMAPS, GPV2, CACHED, ADMIN = 0xA7 << 140, 0xB8 << 140, 0xC9 << 140, 0xDA << 140, 0xEB << 140
MANAGED = 0xFC << 140
_ALLOWED_SLOT = int.from_bytes(keccak(LENDER.to_bytes(32, "big") + (1).to_bytes(32, "big")), "big")
_STORED = {(PULLER, 0): TOKEN, (POOL, 0): MANAGER, (MANAGER, 0): PERMISSIONS, (PERMISSIONS, _ALLOWED_SLOT): 1}
_STORED[(ROUTER, 0)] = BITMAPS
_STORED[(GPV2, 0)] = TOKEN
_STORED[(CACHED, 0)] = ADMIN
_MANAGERS = {i: (0x5EED << 140) + i for i in range(40)}  # forty operators, each with its manager
_MANAGER_SET = int.from_bytes(keccak(b"ManagerSet(uint256,address)"), "big")
for _id, _manager in _MANAGERS.items():
    _STORED[(MANAGED, int.from_bytes(keccak(_id.to_bytes(32, "big") + (1).to_bytes(32, "big")), "big"))] = _manager
_STORED[(BITMAPS, 1)] = 2  # a bitmap per function, each requiring bit 0
for _function in (b"P:deposit", b"P:transfer"):
    _STORED[(BITMAPS, int.from_bytes(keccak(_function.ljust(32, b"\0") + (2).to_bytes(32, "big")), "big"))] = 1


class _Deployed(Chain):
    """Each outer contract's first slot points at its callee; the permission manager allowlists one lender, as its
    one event says; nothing else is stored."""

    def __init__(self):
        super().__init__(self._answer, 1, lambda calls: [self._answer(m, p) for m, p in calls])

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            at, slot = int(params[0], 16), int(params[1], 16)
            return hex(_STORED.get((at, slot), 0))
        if method == "eth_call":
            # The views, as their code answers on this storage: whether the receiver is the allowlisted lender.
            to, data = int(params[0]["to"], 16), bytes.fromhex(params[0]["data"][2:])
            if to == PERMISSIONS:
                return "0x" + (int.from_bytes(data[4:36], "big") == LENDER).to_bytes(32, "big").hex()
            if to == BITMAPS:
                return "0x" + "00" * 32  # no lender holds the bit
            if to == MANAGER:
                receiver = int.from_bytes(data[4 + 128 : 4 + 160], "big")
                return "0x" + (receiver == LENDER).to_bytes(32, "big").hex()
        if method == "eth_getLogs":
            return []
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(1_700_000_000), "number": hex(1)}
        raise RuntimeError("execution reverted")

    def code(self, address):
        return (
            b"\x60"
            if address in (PULLER, TOKEN, POOL, MANAGER, PERMISSIONS, ROUTER, BITMAPS, GPV2, CACHED, MANAGED)
            else b""
        )

    def logs(self, address, topics):
        if address == MANAGED:
            return [([_MANAGER_SET, i], [manager]) for i, manager in _MANAGERS.items()]
        return [([0, LENDER], [1])] if address == PERMISSIONS else []


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("pools") / "P.sol"
    path.write_text(SOURCE)
    return {c.name: c for c in Slither(str(path), solc=str(solc)).contracts}


def _verdict(built, name, fn_name, at, contracts):
    from services.logic.terms import reset_terms

    reset_terms()
    contract = built[name]
    fn = next(f for f in contract.functions_entry_points if f.name == fn_name)
    verdict, _ = function_verdict(contract, fn, at, _Deployed(), contracts)
    return verdict


def test_a_pull_from_a_token_whose_blacklist_a_stranger_is_not_on_stays_open(built):
    # The stranger can't bring about its blacklist entry, but needn't: its balance and allowance are what it lacks.
    contracts = {PULLER: built["Puller"], TOKEN: built["Blacklisting"]}
    assert _verdict(built, "Puller", "deposit", PULLER, contracts).openness == "open"


def test_a_pull_from_a_token_only_listed_senders_move_is_never_open(built):
    contracts = {PULLER: built["Puller"], TOKEN: built["Listing"]}
    assert _verdict(built, "Puller", "deposit", PULLER, contracts).openness != "open"


@pytest.mark.parametrize("token", ["Blacklisting", "Tether", "Answering"])
def test_a_pull_built_at_the_free_memory_pointer_is_the_transfer_it_encodes(built, legacy, token):
    # Open to whoever holds and approves the token, whether it returns a bool or nothing.
    contracts = {GPV2: built["GPv2Puller"], TOKEN: {**built, **legacy}[token]}
    assert _verdict(built, "GPv2Puller", "supply", GPV2, contracts).openness == "open"


def test_a_pull_built_at_the_free_memory_pointer_from_a_listing_token_is_never_open(built):
    contracts = {GPV2: built["GPv2Puller"], TOKEN: built["Listing"]}
    assert _verdict(built, "GPv2Puller", "supply", GPV2, contracts).openness != "open"


@pytest.mark.parametrize("name", ["setCap", "raiseCap"])
def test_a_memory_struct_filled_field_by_field_reads_back_what_was_put_there(built, name):
    verdict = _verdict(built, "Cached", name, CACHED, {CACHED: built["Cached"]})
    assert verdict.openness == "restricted" and set(verdict.principals) == {ADMIN}


def test_a_stranger_failing_is_kept_when_candidates_spend_the_budget(built, monkeypatch):
    # The stranger's question is answered before the candidates'; running out of work on them leaves the list
    # partial, not the verdict unknown.
    from services.logic import decide

    monkeypatch.setattr(decide, "DECISION_WORK", 40 * decide.QUESTION_WORK)
    verdict = _verdict(built, "Managed", "act", MANAGED, {MANAGED: built["Managed"]})
    assert verdict.openness == "restricted" and not verdict.complete


def test_a_deposit_for_a_receiver_another_contract_allowlists_is_open(built):
    # Anyone deposits for the allowlisted lender: the receiver is tried from the allowlist's own events.
    contracts = {POOL: built["Pool"], MANAGER: built["Manager"], PERMISSIONS: built["Permissions"]}
    assert _verdict(built, "Pool", "deposit", POOL, contracts).openness == "open"


def test_a_bitmap_read_at_a_key_the_lender_only_picks_between_is_a_gate(built):
    # ``poolBitmaps[allowlisted ? ... : level == 1 ? 0 : id]``: the caller picks between fixed keys, the same for
    # every address no lookup names, so a stranger failing stands for them all.
    contracts = {ROUTER: built["Router"], BITMAPS: built["Bitmaps"]}
    assert _verdict(built, "Router", "deposit", ROUTER, contracts).openness == "restricted"


def test_a_check_handed_the_caller_in_an_array_is_a_gate(built):
    contracts = {ROUTER: built["Router"], BITMAPS: built["Bitmaps"]}
    assert _verdict(built, "Router", "transferIn", ROUTER, contracts).openness == "restricted"


def test_a_fixed_array_set_per_branch_is_read_back_item_by_item(built):
    # ``uint256[3] memory words`` filled differently per branch: ``words[1]`` is the receiver either way, not an
    # unreadable choice between two arrays.
    from services.logic.lower import Lowerer
    from services.logic.terms import mk, reset_terms, subterms

    reset_terms()
    manager = built["Manager"]
    can_call = next(f for f in manager.functions_entry_points if f.name == "canCall")
    receiver = mk("arg", "receiver", "address")
    data = mk("enc", (mk("arg", "assets", "uint256"), receiver))
    _, returned = Lowerer(manager).returns(can_call, [mk("arg", "caller", "address"), data])
    asked = {c[3][0] for r in returned for c in subterms(r, "call") if c[2] == "hasPermission(address)"}
    assert asked and not any(subterms(a, "array") or subterms(a, "elem") for a in asked)


LEGACY = """
pragma solidity 0.4.19;

contract Moves {
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;

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


@pytest.fixture(scope="module")
def legacy(tmp_path_factory):
    solc = solc_path("0.4.19")
    if solc is None:
        pytest.skip("solc 0.4.19 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("legacy_pools") / "L.sol"
    path.write_text(LEGACY)
    return {c.name: c for c in Slither(str(path), solc=str(solc)).contracts}


def test_a_pull_from_a_token_returning_nothing_reads_its_empty_return_data(built, legacy):
    # OpenZeppelin's pull passes on empty return data from code: a function declared to return nothing returns none,
    # whatever its ``return`` statements say.
    contracts = {PULLER: built["Puller"], TOKEN: legacy["Tether"]}
    assert _verdict(built, "Puller", "deposit", PULLER, contracts).openness == "open"
