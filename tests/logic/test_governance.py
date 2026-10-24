"""Governance shapes: holdings anyone can be given, records the caller names, a stranger's own earlier call."""

from __future__ import annotations

import pytest

from services.logic.decide import Chain
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path

GOV, TOKEN = 0x60F << 100, 0x70C << 100

SOURCE = """
pragma solidity 0.8.27;

uint40 constant MAX_TIMESTAMP = type(uint40).max;

contract Token {
    mapping(address => uint256) balances;
    address minter;

    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }

    // Holders move what they hold to anyone: a balance anyone can be given.
    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}

contract Badge {
    mapping(address => uint256) balances;
    address minter;

    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }

    // Only the minter hands badges out, and they never move.
    function mint(address to) external {
        require(msg.sender == minter);
        balances[to] = 1;
    }
}

interface IHolding {
    function balanceOf(address who) external view returns (uint256);
}

contract Governor {
    IHolding token;
    address owner;
    uint256 threshold;
    struct Proposal { bool passed; bool executed; }
    mapping(uint256 => Proposal) proposals;
    mapping(address => address) delegates;
    mapping(address => address[]) delegated;

    // Lido's ``vote``: any holder, however little it holds.
    function vote() external view {
        require(token.balanceOf(msg.sender) > 0);
    }

    // A proposal threshold: holding enough is the gate.
    function propose() external view {
        require(token.balanceOf(msg.sender) >= threshold);
    }

    function pass(uint256 id) external {
        require(msg.sender == owner);
        proposals[id].passed = true;
    }

    // ``executeVote``: anyone, once a passed proposal waits; none does now.
    function execute(uint256 id) external {
        require(proposals[id].passed && !proposals[id].executed);
        proposals[id].executed = true;
    }

    // A file-level constant is its initializer, not zero.
    function beforeTheEnd() external view {
        require(block.timestamp <= MAX_TIMESTAMP);
    }

    function assign(address delegate) external {
        require(delegate != address(0) && delegate != msg.sender && delegates[msg.sender] == address(0));
        delegates[msg.sender] = delegate;
        address[] storage list = delegated[delegate];
        list.push(msg.sender);
    }

    // Lido's ``unassignDelegate``: open to whoever first assigns one.
    function unassign() external {
        address delegate = delegates[msg.sender];
        require(delegate != address(0));
        address[] storage list = delegated[delegate];
        require(list[list.length - 1] == msg.sender);
        list.pop();
        delete delegates[msg.sender];
    }

    // Lido's ``attemptVoteFor``: whoever a voter named, a list no event here records.
    function voteFor(address voter) external view {
        require(delegates[voter] == msg.sender);
    }
}
"""


class _Chain(Chain):
    """As deployed: the governor's token at slot 0, a threshold of 100, nothing else stored, view calls answering
    zero; the token's code is there."""

    def __init__(self, token: int = TOKEN):
        self.token = token
        super().__init__(self._answer, 1, lambda calls: [self._answer(m, p) for m, p in calls])

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            address, slot = int(params[0], 16), int(params[1], 16)
            if address == GOV and slot == 0:
                return hex(self.token)
            if address == GOV and slot == 2:
                return hex(100)
            return "0x0"
        if method == "eth_call" and int(params[0]["to"], 16) != GOV:
            return "0x" + "00" * 32  # the token's views: nobody holds anything
        if method == "eth_getLogs":
            return []
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(1_700_000_000), "number": "0x1"}
        raise RuntimeError("execution reverted")

    def code(self, address):
        return b"\x60" if address in (GOV, TOKEN) else b""

    def logs(self, address, topics):
        return []


@pytest.fixture(scope="module")
def contracts(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("governance") / "G.sol"
    path.write_text(SOURCE)
    return {c.name: c for c in Slither(str(path), solc=str(solc)).contracts}


def _verdict(contracts, name, token="Token"):
    from services.logic.terms import reset_terms

    reset_terms()
    governor = contracts["Governor"]
    fn = next(f for f in governor.functions_entry_points if f.name == name)
    verdict, _ = function_verdict(governor, fn, GOV, _Chain(), {GOV: governor, TOKEN: contracts[token]})
    return verdict


def test_a_holding_anyone_can_be_given_is_open_with_the_holding_stated(contracts):
    verdict = _verdict(contracts, "vote")
    assert verdict.openness == "open"
    assert verdict.requires == ((TOKEN, "balanceOf(address)", "any"),)


def test_a_holding_only_a_minter_hands_out_stays_a_gate(contracts):
    assert _verdict(contracts, "vote", token="Badge").openness != "open"


def test_holding_a_fixed_amount_is_a_gate_on_holdings(contracts):
    verdict = _verdict(contracts, "propose")
    assert verdict.openness == "restricted" and not verdict.complete
    assert verdict.requires == ((TOKEN, "balanceOf(address)", 100),)


def test_a_record_the_caller_names_opens_once_one_is_ready(contracts):
    verdict = _verdict(contracts, "execute")
    assert verdict.openness == "open" and verdict.allowed == "later"


def test_a_file_level_constant_is_its_initializer(contracts):
    verdict = _verdict(contracts, "beforeTheEnd")
    assert verdict.openness == "open" and verdict.allowed == "now"


def test_a_strangers_own_first_call_opens_what_it_unlocks(contracts):
    verdict = _verdict(contracts, "unassign")
    assert verdict.openness == "open"
    assert [signature for signature, _ in verdict.after] == ["assign(address)"]


def test_a_value_the_caller_picks_the_entry_of_is_no_complete_list(contracts):
    # An unconfigured address is named by no entry, so it fails; whoever voters named isn't listed.
    verdict = _verdict(contracts, "voteFor")
    assert verdict.openness == "restricted" and not verdict.complete
    assert "storage:delegates" in verdict.gaps


LEGACY = """
pragma solidity 0.4.19;

contract Checkpoints {
    struct Checkpoint { uint128 fromBlock; uint128 value; }
    mapping(address => Checkpoint[]) balances;
    mapping(address => address[]) lists;

    // MiniMe's ``updateValueAtNow``: the new checkpoint goes past the length, which the reference raises.
    function record(uint128 value) public {
        Checkpoint[] storage checkpoints = balances[msg.sender];
        Checkpoint storage next = checkpoints[checkpoints.length++];
        next.fromBlock = uint128(block.number);
        next.value = value;
    }

    // Lido's ``_addDelegatedAddressFor``: a storage pointer Slither renders as an array literal.
    function add(address to) public {
        address[] storage list = lists[to];
        list.push(msg.sender);
    }
}
"""


def _written(contract, name):
    from services.logic.verdict import _stores

    fn = next(f for f in contract.functions_entry_points if f.name == name)
    exits = _stores(contract, fn, {})
    return [
        (loc[1], tuple(step for step, _ in loc[2]), tuple(x for k, x in loc[2] if k == "f"))
        for _, store in exits
        for loc in store
        if loc[0] != "emit"
    ]


@pytest.fixture(scope="module")
def legacy(tmp_path_factory):
    solc = solc_path("0.4.19")
    if solc is None:
        pytest.skip("solc 0.4.19 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("legacy") / "L.sol"
    path.write_text(LEGACY)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Checkpoints")


def test_raising_a_storage_arrays_length_writes_it(legacy):
    written = _written(legacy, "record")
    assert ("balances", ("k", "f"), ("length",)) in written
    assert ("balances", ("k", "k", "f"), ("value",)) in written


def test_a_storage_pointer_rendered_as_an_array_literal_points_at_storage(legacy):
    written = _written(legacy, "add")
    assert ("lists", ("k", "f"), ("length",)) in written
    assert ("lists", ("k", "k"), ()) in written


def test_an_enum_name_two_files_declare_resolves_only_where_they_agree():
    from types import SimpleNamespace

    from services.logic.lower import _enum_index

    governance = SimpleNamespace(name="State", values=["Unset", "Normal", "VetoSignalling"])
    escrow = SimpleNamespace(name="State", values=["NotInitialized", "SignallingEscrow", "RageQuitEscrow"])
    clash = SimpleNamespace(name="State", values=["Normal", "Unset"])
    unit = SimpleNamespace(enums_top_level=[governance, escrow], contracts=[])
    contract = SimpleNamespace(compilation_unit=unit)
    # Slither bound the name to the escrow's enum: the member it can't hold is the other's.
    assert _enum_index(contract, escrow, "Normal") == 1
    unit.enums_top_level.append(clash)
    assert _enum_index(contract, escrow, "Normal") is None


def test_a_bytes_value_in_storage_reads_back_whole():
    from services.logic.decide import Evaluator, World

    short = int.from_bytes(b"hi".ljust(31, b"\0") + bytes([4]), "big")
    text = bytes(range(40))
    stored = {0: short, 1: 2 * len(text) + 1}
    from eth_utils.crypto import keccak

    base = int.from_bytes(keccak((1).to_bytes(32, "big")), "big")
    stored[base] = int.from_bytes(text[:32], "big")
    stored[base + 1] = int.from_bytes(text[32:].ljust(32, b"\0"), "big")

    class _Slots(Chain):
        def __init__(self):
            super().__init__(lambda m, p: hex(stored.get(int(p[1], 16), 0)), 1)

    probe = Evaluator(World(_Slots(), GOV, 0), {"caller": 1, "signer": 1})
    assert probe._stored_bytes(GOV, 0, short) == b"hi"
    assert probe._stored_bytes(GOV, 1, stored[1]) == text


SHAPES = """
pragma solidity 0.8.27;

type Duration is uint32;
struct Config { Duration delay; uint256 quorum; }

library Registry {
    event Registered(address indexed who);

    function register(mapping(address => uint256) storage self, address who) internal {
        self[who] = 1;
        emit Registered(who);
    }
}

// OpenZeppelin's EnumerableSet, flattened: a remove moves the last member into the gap and re-indexes it there.
contract Committee {
    address[] values;
    mapping(address => uint256) positions;
    mapping(address => uint256) registered;
    event MemberAdded(address member);
    event MemberRemoved(address member);

    function add(address[] calldata members) external {
        for (uint256 i; i < members.length; ++i) {
            require(positions[members[i]] == 0);
            values.push(members[i]);
            positions[members[i]] = values.length;
            emit MemberAdded(members[i]);
        }
    }

    function remove(address member) external {
        uint256 position = positions[member];
        require(position != 0);
        uint256 last = values.length - 1;
        if (position - 1 != last) {
            address moved = values[last];
            values[position - 1] = moved;
            positions[moved] = position;
        }
        values.pop();
        delete positions[member];
        emit MemberRemoved(member);
    }

    function register(address who) external {
        Registry.register(registered, who);
    }
}

// Lido's ``HashConsensus._addMembers``: the set's ``add`` says whether it added, and the loop refuses a repeat.
contract Checked {
    address[] values;
    mapping(address => uint256) positions;
    event MemberAdded(address member);

    function _add(address member) internal returns (bool) {
        if (positions[member] != 0) return false;
        values.push(member);
        positions[member] = values.length;
        return true;
    }

    function addAll(address[] calldata members) external {
        for (uint256 i; i < members.length; ++i) {
            if (!_add(members[i])) revert();
            emit MemberAdded(members[i]);
        }
    }
}

contract Source {
    function config() external view returns (Config memory) {}
}

contract Uses {
    Source source;
    struct Call { address target; bytes data; }
    mapping(uint256 => Call[]) proposals;

    function quorate() external view {
        require(source.config().quorum > 0);
    }

    // A proposal's calls, run by whoever asks: the loop turns on what is asked, never on who asks.
    function run(uint256 id) external {
        Call[] storage calls = proposals[id];
        for (uint256 i; i < calls.length; ++i) {
            (bool ok, ) = calls[i].target.call(calls[i].data);
            require(ok);
        }
    }
}
"""


@pytest.fixture(scope="module")
def shapes(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("shapes") / "S.sol"
    path.write_text(SHAPES)
    return {c.name: c for c in Slither(str(path), solc=str(solc)).contracts}


def test_a_member_a_remove_reindexes_is_still_one_its_add_logged(shapes):
    from services.logic.logged import logged

    assert ("MemberAdded", 1) in (logged(shapes["Committee"], "positions", 1, (), False) or ())


def test_an_add_whose_success_merges_apart_from_its_event_is_still_logged(shapes):
    from services.logic.logged import logged

    assert ("MemberAdded", 1) in (logged(shapes["Checked"], "positions", 1, (), False) or ())


def test_an_event_emitted_wherever_the_write_is_made_logs_it_however_the_paths_merged():
    # Merged loop iterations leave a write's condition and its event's shaped apart: ``(p or q) and not p`` is
    # where it writes, ``q`` where it emits.
    from services.logic.logged import _implies, _implies_as_logic
    from services.logic.terms import mk, mk_and, mk_cmp, mk_not, mk_or

    p = mk_cmp("eq", mk("arg", "a", "uint256"), mk("const", 1, "uint256"))
    q = mk_cmp("eq", mk("arg", "b", "uint256"), mk("const", 2, "uint256"))
    written = mk_and([mk_or([p, q]), mk_not(p)])
    assert not _implies(written, q) and _implies_as_logic(written, q)
    assert not _implies_as_logic(mk_or([p, q]), q)


def test_an_event_a_library_declares_is_one_the_contract_emits(shapes):
    from services.logic.verdict import _declared_events

    assert "Registered" in {e.name for e in _declared_events(shapes["Committee"])}


def test_a_field_of_a_struct_of_value_types_a_call_returns_is_its_word(shapes):
    from services.logic.lower import Lowerer
    from services.logic.terms import subterms

    uses = shapes["Uses"]
    fn = next(f for f in uses.functions_entry_points if f.name == "quorate")
    formula = Lowerer(uses).success(fn)
    assert [t[2] for t in subterms(formula, "item")] == [1]


def test_a_loop_the_arguments_steer_singles_out_nobody(shapes):
    from services.logic.decide import singles_out_nobody
    from services.logic.lower import Lowerer
    from services.logic.terms import subterms

    uses = shapes["Uses"]
    fn = next(f for f in uses.functions_entry_points if f.name == "run")
    loops = list(subterms(Lowerer(uses).success(fn), "unknown"))
    assert loops and all(singles_out_nobody(u) for u in loops)


def test_code_left_unfollowed_only_past_a_listed_entry_leaves_the_list_whole():
    # Aragon's ACL evaluates a permission's parameters (recursively, past what the lowering follows) only for an
    # entity holding it: an address no event names is refused before.
    from services.logic.decide import coverage
    from services.logic.terms import CALLER, mk, mk_and, mk_cmp, mk_not, unknown

    acl = mk("const", 0xAC1, "address")
    call = mk("call", acl, "hasPermission(address)", (CALLER,), True)
    held = mk("load", acl, "permissions", (("k", mk("hash", "keccak256", (CALLER,))),))
    inner = mk_and([mk_not(mk_cmp("eq", held, mk("const", 0, "uint256"))), unknown("unanalysed:ACL._evalParam")])

    def cover(settled):
        return coverage(call, lambda *a: True, lambda c: inner if c == call else None, lambda *a: True, settled)

    assert not cover(lambda term: True).blind
    assert cover(lambda term: False).blind


POOL = """
pragma solidity 0.8.27;

interface IHub {
    function add(uint256 amount) external returns (uint256 shares);
}

contract Hub {
    uint256 totalShares;

    function add(uint256 amount) external returns (uint256 shares) {
        shares = amount;
        totalShares += shares;
    }
}

// Aave v4's Spoke: the reserve the caller names picks the hub, and the shares it returns are cast down.
contract Pool {
    mapping(uint256 => address) hubs;

    function supply(uint256 reserveId, uint256 amount) external {
        uint256 shares = IHub(hubs[reserveId]).add(amount);
        require(shares <= type(uint120).max);
    }
}
"""

HUB = 0x4B0B << 100


def test_what_a_hub_the_caller_picks_returns_is_what_its_code_returns(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from eth_utils.crypto import keccak
    from slither import Slither

    from services.logic.terms import reset_terms

    path = tmp_path_factory.mktemp("pool") / "P.sol"
    path.write_text(POOL)
    built = {c.name: c for c in Slither(str(path), solc=str(solc)).contracts}
    slot = int.from_bytes(keccak((0).to_bytes(32, "big") + (0).to_bytes(32, "big")), "big")  # hubs[0]

    class _Pool(_Chain):
        def _answer(self, method, params):
            if method == "eth_getStorageAt":
                return hex(HUB) if int(params[0], 16) == GOV and int(params[1], 16) == slot else "0x0"
            if method == "eth_call" and int(params[0]["to"], 16) == GOV:
                # The supply itself, run as the chain runs it: the hub adds the amount and returns it as the shares,
                # well within ``uint120``. The hub's code only proposes the pass; this run confirms it.
                return "0x"
            return super()._answer(method, params)

        def code(self, address):
            return b"\x60" if address in (GOV, HUB) else b""

    reset_terms()
    pool = built["Pool"]
    fn = next(f for f in pool.functions_entry_points if f.name == "supply")
    verdict, _ = function_verdict(pool, fn, GOV, _Pool(), {GOV: pool, HUB: built["Hub"]})
    assert verdict.openness == "open"


ROLES = """
pragma solidity 0.8.27;

// Members hand membership out, keeping their own: a role, not a balance anyone can be given.
contract Roles {
    mapping(address => bool) members;

    function grant(address account) external {
        require(members[msg.sender]);
        members[account] = true;
    }

    function isMember(address account) external view returns (bool) {
        return members[account];
    }
}

interface IRoles {
    function isMember(address account) external view returns (bool);
}

contract Gate {
    IRoles roles;

    function act() external view {
        require(roles.isMember(msg.sender));
    }
}
"""


def test_an_entry_holders_hand_out_without_giving_up_is_no_holding(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    from services.logic.terms import reset_terms

    path = tmp_path_factory.mktemp("roles") / "R.sol"
    path.write_text(ROLES)
    built = {c.name: c for c in Slither(str(path), solc=str(solc)).contracts}
    reset_terms()
    gate = built["Gate"]
    fn = next(f for f in gate.functions_entry_points if f.name == "act")
    verdict, _ = function_verdict(gate, fn, GOV, _Chain(), {GOV: gate, TOKEN: built["Roles"]})
    assert verdict.openness != "open"


MINTER = """
pragma solidity 0.8.27;

// USDC's ``mint``: minters only. A balance anyone can deposit into is beside the point, whichever way in can't be read.
contract Minted {
    address owner;
    bool gated;
    mapping(address => bool) minters;
    mapping(address => uint256) balances;

    function setMinter(address who) external {
        require(msg.sender == owner);
        minters[who] = true;
    }

    function depositGated() external {
        require(gated);
        balances[msg.sender] += 1;
    }

    function deposit() external {
        balances[msg.sender] += 1;
    }

    function mint() external view {
        require(minters[msg.sender] && balances[msg.sender] > 0);
    }
}

// Lido's ``migrateBaselineSnapshot``: once, while the list is empty; it has entries now and only grows.
contract Migrated {
    uint256[] reports;

    function migrate() external {
        require(reports.length == 0);
        reports.push(1);
    }

    function report(uint256 value) external {
        reports.push(value);
    }
}
"""


def test_a_way_in_that_could_not_be_read_beside_one_that_works_leaves_the_list_whole(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    from services.logic.terms import reset_terms

    path = tmp_path_factory.mktemp("minted") / "M.sol"
    path.write_text(MINTER)
    minted = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Minted")

    class _GateUnread(_Chain):
        def _answer(self, method, params):
            if method == "eth_getStorageAt" and int(params[0], 16) == GOV and int(params[1], 16) == 0:
                raise RuntimeError("timeout")  # the owner and the flag packed beside it
            return super()._answer(method, params)

    reset_terms()
    fn = next(f for f in minted.functions_entry_points if f.name == "mint")
    verdict, _ = function_verdict(minted, fn, GOV, _GateUnread(), {GOV: minted})
    assert verdict.openness == "restricted"
    assert "now_unknown" not in verdict.gaps


def test_a_list_that_only_grows_never_comes_back_to_empty(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    from services.logic.terms import reset_terms

    path = tmp_path_factory.mktemp("migrated") / "M.sol"
    path.write_text(MINTER)
    migrated = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Migrated")

    class _Filled(_Chain):
        def _answer(self, method, params):
            if method == "eth_getStorageAt" and int(params[0], 16) == GOV and int(params[1], 16) == 0:
                return hex(88)  # the list's length
            return super()._answer(method, params)

    reset_terms()
    fn = next(f for f in migrated.functions_entry_points if f.name == "migrate")
    verdict, _ = function_verdict(migrated, fn, GOV, _Filled(), {GOV: migrated})
    assert verdict.openness == "restricted" and verdict.complete and not verdict.principals
