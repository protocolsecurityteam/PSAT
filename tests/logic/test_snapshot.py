"""Storage listing holders no event does: a whole-storage dump accounted for under the keys known, and the constructor's
writes from the creating transaction's trace."""

from __future__ import annotations

import pytest
from eth_utils import keccak

from services.logic.decide import Chain
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path

SOURCE = """
pragma solidity 0.8.27;

// Maker's shape, with a second writer that logs nothing: its events can't list the wards.
contract Warded {
    mapping(address => uint256) public wards;
    mapping(bytes32 => uint256) public ilks;
    event Rely(address indexed usr);

    constructor() { wards[msg.sender] = 1; }

    function rely(address usr) external {
        require(wards[msg.sender] == 1);
        wards[usr] = 1;
        emit Rely(usr);
    }

    function relyQuietly(address usr) external {
        require(wards[msg.sender] == 1);
        wards[usr] = 1;
    }

    function file(bytes32 what, uint256 data) external {
        require(wards[msg.sender] == 1);
        ilks[what] = data;
    }
}

// Every writer logs but the constructor.
contract Logged {
    mapping(address => uint256) public wards;
    event Rely(address indexed usr);

    constructor() { wards[msg.sender] = 1; }

    function rely(address usr) external {
        require(wards[msg.sender] == 1);
        wards[usr] = 1;
        emit Rely(usr);
    }
}

// Every writer logs, the constructor included.
contract Plain {
    mapping(address => uint256) public wards;
    mapping(address => mapping(address => uint256)) public can;
    uint256 public live;
    event Rely(address indexed usr);

    function rely(address usr) external {
        require(wards[msg.sender] == 1);
        wards[usr] = 1;
        emit Rely(usr);
    }
}

// Safe's shape: owners in a list from a sentinel, written by a setup that logs nothing, and a handler kept at a
// fixed slot the code names.
contract Listed {
    address constant SENTINEL = address(1);
    bytes32 constant HANDLER = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    mapping(address => address) owners;

    function setup(address[] calldata list, address handler) external {
        require(owners[SENTINEL] == address(0));
        address previous = SENTINEL;
        for (uint256 i = 0; i < list.length; i++) {
            owners[previous] = list[i];
            previous = list[i];
        }
        owners[previous] = SENTINEL;
        assembly { sstore(HANDLER, handler) }
    }

    function approve() external {
        require(msg.sender != SENTINEL && owners[msg.sender] != address(0));
    }
}

// OpenZeppelin's roles, keyed by a role constant and then the account: the constructor's grants log nothing.
contract Roles {
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    mapping(bytes32 => mapping(address => bool)) hasRole;
    event RoleGranted(bytes32 indexed role, address indexed account);

    constructor() {
        hasRole[0][address(this)] = true;
        hasRole[PROPOSER_ROLE][msg.sender] = true;
    }

    function grantRole(bytes32 role, address account) external {
        require(hasRole[0][msg.sender]);
        hasRole[role][account] = true;
        emit RoleGranted(role, account);
    }

    function schedule() external {
        require(hasRole[PROPOSER_ROLE][msg.sender]);
    }
}

// Maker's ``note``: the selector as topic0, the caller and the argument after it.
contract Noted {
    mapping(address => uint256) public wards;

    constructor() { wards[msg.sender] = 1; }

    function rely(address usr) external {
        require(wards[msg.sender] == 1);
        wards[usr] = 1;
        assembly { log3(0, 0, shl(224, shr(224, calldataload(0))), caller(), calldataload(4)) }
    }
}

// Maple's loan manager: a loan with a payment may claim, if its own code answers; one funded quietly.
interface ILoan { function ready() external view returns (bool); }

contract Loans {
    mapping(address => uint256) public payments;
    address public last;
    event Rely(address indexed usr);

    function fund(address loan) external {
        require(payments[msg.sender] != 0);
        payments[loan] = 1;
        emit Rely(loan);
    }

    function fundQuietly(address loan) external {
        require(payments[msg.sender] != 0);
        payments[loan] = 1;
        last = loan;
    }

    function claim() external {
        require(payments[msg.sender] != 0);
        require(ILoan(msg.sender).ready());
    }
}
"""

AT = 0xA1 << 140
WARD, DEPLOYER, HIDDEN = 0xB2 << 140, 0xC3 << 140, 0xD4 << 140
_RELY = int.from_bytes(keccak(b"Rely(address)"), "big")
_NOTE = int.from_bytes(keccak(b"rely(address)")[:4], "big") << 224
_CREATION = "0x" + "ab" * 32
_HANDLER = 0x6C9A6C4A39284E37ED1CF53D337577D14212A4870FB976A4366C693B939918D5


def _slot(key: int, base: int) -> int:
    return int.from_bytes(keccak(key.to_bytes(32, "big") + base.to_bytes(32, "big")), "big")


class _Deployed(Chain):
    """``AT`` holds ``storage``; one ``Rely`` names ``WARD``; with ``dumps``, a debug node serves the storage whole
    and ``creation`` (calls' words, storage left) as the creating transaction."""

    def __init__(
        self,
        storage: dict[int, int],
        dumps: bool = True,
        creation: tuple | None = None,
        cut: bool = False,
        written: dict | None = None,
    ):
        # ``written``: slot -> (block it was first set at, the words its writer's calls carry).
        self.stored, self.creation, self.cut_short, self.written = storage, creation, cut, written or {}
        batch = lambda calls: [self._answer(m, p) for m, p in calls]  # noqa: E731
        super().__init__(self._answer, 100, batch, debug=self._debug if dumps else None)

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            slot, block = int(params[1], 16), int(params[2], 16)
            if slot in self.written and block < self.written[slot][0]:
                return "0x0"
            return hex(self.stored.get(slot, 0) if int(params[0], 16) == AT else 0)
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(1_700_000_000), "number": hex(1), "hash": "0x" + "11" * 32, "transactions": []}
        if method == "eth_getLogs":
            return []
        raise RuntimeError("execution reverted")

    def _debug(self, method, params):
        if method == "debug_storageRangeAt":
            assert int(params[2], 16) == AT
            entries = {
                "0x" + keccak(slot.to_bytes(32, "big")).hex(): {"key": hex(slot), "value": hex(word)}
                for slot, word in self.stored.items()
            }
            return {"storage": entries, "nextKey": None}
        if method == "debug_traceBlockByNumber":
            block = int(params[0], 16)
            return [
                {"txHash": hex(slot), "result": {"pre": {}, "post": {hex(AT): {"storage": {hex(slot): "0x1"}}}}}
                for slot, (at, _) in self.written.items()
                if at == block
            ]
        if method == "debug_traceTransaction" and int(params[0], 16) in self.written:
            words = self.written[int(params[0], 16)][1]
            data = "0x65fae35e" + "".join(format(w, "064x") for w in words)
            return {"from": hex(WARD), "to": hex(AT), "input": data, "calls": []}
        if method == "debug_traceTransaction" and self.creation is not None and params[0] == _CREATION:
            words, storage = self.creation
            if params[1]["tracer"] == "callTracer":
                return {"from": hex(words[0]), "to": hex(AT), "input": "0x6080", "calls": []}
            return {"pre": {}, "post": {hex(AT): {"storage": {hex(k): hex(v) for k, v in storage.items()}}}}
        raise RuntimeError("unsupported")

    def creation_tx(self, address):
        return _CREATION if address == AT and self.creation is not None else None

    def code(self, address):
        return b"\x7f" + _HANDLER.to_bytes(32, "big") if address == AT else b""

    def logs(self, address, topics):
        if self.cut_short:
            self.truncated.add(address)  # a history too long to read whole
        return [([_RELY, WARD], []), ([_NOTE, DEPLOYER, WARD], [])] if address == AT else []


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("snapshot") / "S.sol"
    path.write_text(SOURCE)
    return {c.name: c for c in Slither(str(path), solc=str(solc)).contracts}


def _verdict(built, name, chain, function="rely"):
    from services.logic.terms import reset_terms

    reset_terms()
    contract = built[name]
    fn = next(f for f in contract.functions_entry_points if f.name == function)
    verdict, _ = function_verdict(contract, fn, AT, chain, {AT: contract})
    return verdict


_ILK = _slot(int.from_bytes(b"ETH-A".ljust(32, b"\0"), "big"), 1)


def test_a_dump_whose_every_other_word_fails_the_check_lists_the_wards(built):
    # ``ilks["ETH-A"] = 5`` is an entry no known key reaches: a stranger whose ward entry held 5 still fails.
    verdict = _verdict(built, "Warded", _Deployed({_slot(WARD, 0): 1, _ILK: 5}))
    assert verdict.openness == "restricted"
    assert verdict.principals == {WARD}
    assert verdict.complete


def test_a_ward_no_known_key_reaches_keeps_the_list_partial(built):
    verdict = _verdict(built, "Warded", _Deployed({_slot(WARD, 0): 1, _slot(HIDDEN, 0): 1, _ILK: 5}))
    assert verdict.principals == {WARD}
    assert not verdict.complete


def test_without_a_dump_an_unlogged_writer_keeps_the_list_partial(built):
    verdict = _verdict(built, "Warded", _Deployed({_slot(WARD, 0): 1, _ILK: 5}, dumps=False))
    assert verdict.principals == {WARD}
    assert not verdict.complete
    assert "storage:wards" in verdict.gaps


def test_the_creating_transaction_names_the_wards_its_constructor_set(built):
    stored = {_slot(WARD, 0): 1, _slot(DEPLOYER, 0): 1}
    chain = _Deployed(stored, creation=((DEPLOYER,), {_slot(DEPLOYER, 0): 1}))
    chain.storage_dump = lambda address: None  # the trace alone: every other writer logs
    verdict = _verdict(built, "Logged", chain)
    assert verdict.principals == {WARD, DEPLOYER}
    assert verdict.complete


def test_a_constructor_write_the_trace_cant_account_for_keeps_the_list_partial(built):
    stored = {_slot(WARD, 0): 1, _slot(HIDDEN, 0): 1}
    chain = _Deployed(stored, creation=((DEPLOYER,), {_slot(HIDDEN, 0): 1}))
    chain.storage_dump = lambda address: None
    verdict = _verdict(built, "Logged", chain)
    assert verdict.principals == {WARD}
    assert not verdict.complete


def test_a_noted_writer_lists_the_wards_beside_the_constructors(built):
    # The constructor's ward from the trace, the rest from the notes: both read, or the list is short.
    stored = {_slot(WARD, 0): 1, _slot(DEPLOYER, 0): 1}
    chain = _Deployed(stored, creation=((DEPLOYER,), {_slot(DEPLOYER, 0): 1}))
    chain.storage_dump = lambda address: None
    verdict = _verdict(built, "Noted", chain)
    assert verdict.principals == {WARD, DEPLOYER}
    assert verdict.complete


def test_the_creating_transaction_names_the_holders_of_a_role_constant_keyed_first(built):
    # The trace's words hold the deployer, never ``PROPOSER_ROLE``: that key is the code's own constant.
    proposer = int.from_bytes(keccak(b"PROPOSER_ROLE"), "big")
    granted = _slot(DEPLOYER, _slot(proposer, 0))
    stored = {granted: 1, _slot(AT, _slot(0, 0)): 1}
    chain = _Deployed(stored, creation=((DEPLOYER,), dict(stored)))
    chain.storage_dump = lambda address: None
    verdict = _verdict(built, "Roles", chain, "schedule")
    assert verdict.principals == {DEPLOYER}
    assert verdict.complete


def test_a_dump_lists_the_wards_a_cut_history_may_have_missed(built):
    verdict = _verdict(built, "Plain", _Deployed({_slot(WARD, 0): 1}, cut=True))
    assert verdict.principals == {WARD}
    assert verdict.complete
    assert "history_truncated" not in verdict.gaps


def test_without_a_dump_a_cut_history_keeps_the_list_partial(built):
    verdict = _verdict(built, "Plain", _Deployed({_slot(WARD, 0): 1}, dumps=False, cut=True))
    assert not verdict.complete
    assert "history_truncated" in verdict.gaps


def test_plain_variables_are_accounted_for_before_mapping_entries_spend_the_budget(built, monkeypatch):
    import services.logic.snapshot as snapshot

    monkeypatch.setattr(snapshot, "_SPENT", 50)
    keys = set(range(2**20, 2**20 + 100))
    reached = snapshot.Accounting(built["Plain"], {3: 1}, keys, keys, {"wards", "can", "live"}).run()
    assert 2 in reached  # ``live``, after two mappings whose entries the budget can't cover


def test_a_ward_no_event_names_is_found_by_the_transaction_that_set_it(built):
    hidden = _slot(HIDDEN, 0)
    chain = _Deployed({_slot(WARD, 0): 1, hidden: 1, _ILK: 5}, written={hidden: (50, [HIDDEN])})
    verdict = _verdict(built, "Warded", chain)
    assert verdict.principals == {WARD, HIDDEN}
    assert verdict.complete


def test_a_slot_whose_writer_names_no_key_for_it_keeps_the_list_partial(built):
    hidden = _slot(HIDDEN, 0)
    chain = _Deployed({_slot(WARD, 0): 1, hidden: 1, _ILK: 5}, written={hidden: (50, [DEPLOYER])})
    verdict = _verdict(built, "Warded", chain)
    assert verdict.principals == {WARD}
    assert not verdict.complete


def test_a_list_from_a_sentinel_beside_a_fixed_slot_the_code_names_is_listed_whole(built):
    # ``owners[1]`` starts the list (a key no caller has), and the handler's slot is a constant in the code: both
    # accounted for, so nothing left over could be an owner.
    stored = {_slot(1, 0): WARD, _slot(WARD, 0): HIDDEN, _slot(HIDDEN, 0): 1, _HANDLER: DEPLOYER}
    verdict = _verdict(built, "Listed", _Deployed(stored), "approve")
    assert verdict.principals == {WARD, HIDDEN}
    assert verdict.complete


class _Lent(_Deployed):
    """Every loan's ``ready()`` answers true; a stranger has no code to answer."""

    def _answer(self, method, params):
        if method == "eth_call" and int(params[0]["to"], 16) in (WARD, HIDDEN):
            return "0x" + format(1, "064x")
        return super()._answer(method, params)

    def code(self, address):
        return b"\x60" if address in (WARD, HIDDEN) else super().code(address)


def test_a_dump_entry_a_known_word_reaches_is_asked_about_though_no_check_named_it(built):
    # ``HIDDEN``'s payment is reached only by a word the dump holds (``last``), never by the candidates: a stranger
    # holding its word still fails (no code answers ``ready()``), the loan itself passes.
    stored = {_slot(WARD, 0): 1, _slot(HIDDEN, 0): 1, 1: HIDDEN}
    verdict = _verdict(built, "Loans", _Lent(stored), "claim")
    assert verdict.principals == {WARD, HIDDEN}
    assert verdict.complete
