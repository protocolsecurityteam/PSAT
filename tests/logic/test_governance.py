"""Governance shapes: holdings anyone can be given, records the caller names, a stranger's own earlier call. Each
verdict is checked against ``eth_call`` on anvil (``_oracle.check``), the arrangements it rests on (a holder handing
tokens over, the owner passing a proposal, a stranger's own first call) run for real first."""

from __future__ import annotations

import pytest

from services.logic.decide import Chain, Evaluator, World
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """
pragma solidity 0.8.27;

uint40 constant MAX_TIMESTAMP = type(uint40).max;

contract Token {
    mapping(address => uint256) balances;
    address minter;

    constructor() { balances[msg.sender] = 1000; }

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

    constructor() { minter = msg.sender; }

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

    constructor(IHolding t, uint256 th) { token = t; owner = msg.sender; threshold = th; }

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

// The same governor over badges only a minter hands out.
contract BadgeGovernor is Governor {
    constructor(IHolding t) Governor(t, 1) {}
}

type Duration is uint32;
struct Config { Duration delay; uint256 quorum; }

contract Source {
    function config() external view returns (Config memory) {}
}

contract Source5 {
    function config() external view returns (Config memory c) { c.quorum = 5; }
}

contract Uses {
    Source source;
    constructor(Source s) { source = s; }
    function quorate() external view {
        require(source.config().quorum > 0);
    }
}

contract Uses5 is Uses {
    constructor(Source s) Uses(s) {}
}

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

    constructor(address hub) { hubs[0] = hub; }

    function supply(uint256 reserveId, uint256 amount) external {
        uint256 shares = IHub(hubs[reserveId]).add(amount);
        require(shares <= type(uint120).max);
    }
}

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
    constructor(IRoles r) { roles = r; }

    function act() external view {
        require(roles.isMember(msg.sender));
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
HOLDER = O.OWNER  # the token's whole supply, and the governors' owner


def _setup(d):
    d.deploy("Token")
    d.deploy("Badge")
    d.deploy("Governor", ("address", "uint256"), (d.at["Token"], 100))
    d.deploy("BadgeGovernor", ("address",), (d.at["Badge"],))
    d.deploy("Source")
    d.deploy("Source5")
    d.deploy("Uses", ("address",), (d.at["Source"],))
    d.deploy("Uses5", ("address",), (d.at["Source5"],))
    d.deploy("Hub")
    d.deploy("Pool", ("address",), (d.at["Hub"],))
    d.deploy("Roles")
    d.deploy("Gate", ("address",), (d.at["Roles"],))
    d.deploy("Migrated")
    assert O.transact(d, "Migrated", "migrate()")


PROBES = [
    O.Probe(
        SOURCE,
        _setup,
        (
            ("Governor", "vote", ("Token",)),
            ("BadgeGovernor", "vote", ("Badge",)),
            ("Governor", "propose", ("Token",)),
            ("Governor", "execute", ()),
            ("Governor", "beforeTheEnd", ()),
            ("Governor", "unassign", ()),
            ("Governor", "voteFor", ()),
            ("Uses", "quorate", ("Source",)),
            ("Uses5", "quorate", ("Source5",)),
            ("Pool", "supply", ("Hub",)),
            ("Gate", "act", ("Roles",)),
            ("Migrated", "migrate", ()),
        ),
    )
]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def _fund(d, who, amount=1):
    assert O.transact(d, "Token", "transfer(address,uint256)", ("address", "uint256"), (who, amount))


def _fund_strangers(d, amount):
    for who in O.STRANGERS:
        assert O.transact(d, "Token", "transfer(address,uint256)", ("address", "uint256"), (who, amount))


def test_a_holding_anyone_can_be_given_is_open_with_the_holding_stated(d):
    v = O.verdict(d, "Governor", "vote", "Token")
    O.check(d, "Governor", "vote", v, arrange=_fund)
    assert v.openness == "open"
    assert v.requires == ((d.at["Token"], "balanceOf(address)", "any"),)
    vote = O.function(d, "Governor", "vote")
    assert O.strangers_passing(d, "Governor", vote) == {False}  # until a holder hands them some
    with O.snapshot(d):
        _fund_strangers(d, 1)
        assert O.strangers_passing(d, "Governor", vote) == {True}


def test_a_holding_only_a_minter_hands_out_stays_a_gate(d):
    v = O.check(d, "BadgeGovernor", "vote", O.verdict(d, "BadgeGovernor", "vote", "Badge"))
    assert v.openness != "open"
    with O.snapshot(d):  # the minter can let one in; no stranger can on its own
        assert not O.transact(d, "Badge", "mint(address)", ("address",), (O.STRANGERS[0],), sender=O.STRANGERS[1])


def test_holding_a_fixed_amount_is_a_gate_on_holdings(d):
    v = O.check(d, "Governor", "propose", O.verdict(d, "Governor", "propose", "Token"))
    assert v.openness == "restricted" and not v.complete
    assert v.requires == ((d.at["Token"], "balanceOf(address)", 100),)
    propose = O.function(d, "Governor", "propose")
    assert O.passes(d, "Governor", propose, sender=HOLDER)
    with O.snapshot(d):
        _fund_strangers(d, 99)
        assert O.strangers_passing(d, "Governor", propose) == {False}
        _fund_strangers(d, 1)
        assert O.strangers_passing(d, "Governor", propose) == {True}


def test_a_record_the_caller_names_opens_once_one_is_ready(d):
    v = O.check(d, "Governor", "execute", O.verdict(d, "Governor", "execute"), samples=({"id": 1}, {"id": 0}))
    assert v.openness == "open" and v.allowed == "later"
    execute = O.function(d, "Governor", "execute")
    with O.snapshot(d):  # the owner passes a proposal: every stranger may then execute it
        assert O.transact(d, "Governor", "pass(uint256)", ("uint256",), (1,), sender=HOLDER)
        assert O.strangers_passing(d, "Governor", execute, {"id": 1}) == {True}


def test_a_file_level_constant_is_its_initializer(d):
    v = O.check(d, "Governor", "beforeTheEnd", O.verdict(d, "Governor", "beforeTheEnd"), open_at={})
    assert v.allowed == "now"


def test_a_strangers_own_first_call_opens_what_it_unlocks(d):
    v = O.check(d, "Governor", "unassign", O.verdict(d, "Governor", "unassign"))
    assert v.openness == "open"
    assert [signature for signature, _ in v.after] == ["assign(address)"]
    # ``check`` ran each stranger's own ``assign`` first; before it, none passes.
    assert O.strangers_passing(d, "Governor", O.function(d, "Governor", "unassign")) == {False}


def test_a_value_the_caller_picks_the_entry_of_is_no_complete_list(d):
    # An unconfigured address is named by no entry, so it fails; whoever voters named isn't listed.
    voter = O.ACCOUNTS[1]
    v = O.check(d, "Governor", "voteFor", O.verdict(d, "Governor", "voteFor"), samples=({"voter": voter}, {}))
    assert v.openness == "restricted" and not v.complete
    assert "storage:delegates" in v.gaps
    vote_for = O.function(d, "Governor", "voteFor")
    with O.snapshot(d):  # a voter names a delegate no list here holds
        assert O.transact(d, "Governor", "assign(address)", ("address",), (O.ACCOUNTS[2],), sender=voter)
        assert O.passes(d, "Governor", vote_for, {"voter": voter}, sender=O.ACCOUNTS[2])


def test_a_bytes_value_in_storage_reads_back_whole():
    from eth_utils.crypto import keccak

    short = int.from_bytes(b"hi".ljust(31, b"\0") + bytes([4]), "big")
    text = bytes(range(40))
    stored = {0: short, 1: 2 * len(text) + 1}
    base = int.from_bytes(keccak((1).to_bytes(32, "big")), "big")
    stored[base] = int.from_bytes(text[:32], "big")
    stored[base + 1] = int.from_bytes(text[32:].ljust(32, b"\0"), "big")

    class _Slots(Chain):
        def __init__(self):
            super().__init__(lambda m, p: hex(stored.get(int(p[1], 16), 0)), 1)

    probe = Evaluator(World(_Slots(), 0x60F << 100, 0), {"caller": 1, "signer": 1})
    assert probe._stored_bytes(0x60F << 100, 0, short) == b"hi"
    assert probe._stored_bytes(0x60F << 100, 1, stored[1]) == text


def test_an_event_emitted_wherever_the_write_is_made_logs_it_however_the_paths_merged():
    # Merged loop iterations leave a write's condition and its event's shaped apart: ``(p or q) and not p`` is
    # where it writes, ``q`` where it emits.
    from services.logic.logged import _implies_as_logic
    from services.logic.terms import mk, mk_and, mk_cmp, mk_not, mk_or

    p = mk_cmp("eq", mk("arg", "a", "uint256"), mk("const", 1, "uint256"))
    q = mk_cmp("eq", mk("arg", "b", "uint256"), mk("const", 2, "uint256"))
    written = mk_and([mk_or([p, q]), mk_not(p)])
    assert _implies_as_logic(written, q)
    assert not _implies_as_logic(mk_or([p, q]), q)


@pytest.mark.parametrize(("uses", "source", "open_now"), [("Uses", "Source", False), ("Uses5", "Source5", True)])
def test_a_field_of_a_struct_of_value_types_a_call_returns_is_its_word(d, uses, source, open_now):
    v = O.check(d, uses, "quorate", O.verdict(d, uses, "quorate", source), open_at={} if open_now else False)
    if open_now:
        assert v.allowed == "now"


def test_what_a_hub_the_caller_picks_returns_is_what_its_code_returns(d):
    v = O.check(d, "Pool", "supply", O.verdict(d, "Pool", "supply", "Hub"), open_at={"reserveId": 0, "amount": 5})
    assert v.allowed == "now"


def test_an_entry_holders_hand_out_without_giving_up_is_no_holding(d):
    v = O.check(d, "Gate", "act", O.verdict(d, "Gate", "act", "Roles"), open_at=False)
    assert v.openness != "open"


def test_a_list_that_only_grows_never_comes_back_to_empty(d):
    v = O.check(d, "Migrated", "migrate", O.verdict(d, "Migrated", "migrate"))
    assert O.nobody(v)
    with O.snapshot(d):  # every other entry point only grows it
        assert O.transact(d, "Migrated", "report(uint256)", ("uint256",), (3,), sender=O.STRANGERS[0])
        assert O.strangers_passing(d, "Migrated", O.function(d, "Migrated", "migrate")) == {False}
