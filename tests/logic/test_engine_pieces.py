"""The logic engine's building blocks: witness enumeration, evaluation of calls and encodings, history reading under
node failure, and (against the compiler and anvil) immutables and a check call's empty return."""

from __future__ import annotations

import itertools

import pytest
from eth_utils import keccak

from services.logic.decide import (
    FRESH,
    UNK,
    Chain,
    Evaluator,
    World,
    _ranked_product,
    solve,
)
from services.logic.immutables import immutable_value
from services.logic.lower import _fixed_bytes, _literal_bytes, _memory_bytes, _memory_word
from services.logic.terms import (
    CALLER,
    FALSE,
    THIS,
    TRUE,
    Term,
    mk,
    mk_and,
    mk_cmp,
    mk_not,
    mk_op,
    mk_or,
)
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

X = mk("arg", "x", "uint256")
OWNER = mk("load", THIS, "owner", ())


def test_ranked_product_tries_every_combination_once_earliest_first():
    domains = [[0, 1, 2], ["a", "b"], [False, True]]
    ranked = list(_ranked_product(domains))
    assert sorted(ranked, key=repr) == sorted(itertools.product(*domains), key=repr)
    assert ranked[0] == (0, "a", False)
    sums = [sum(d.index(v) for d, v in zip(domains, combo)) for combo in ranked]
    assert sums == sorted(sums)


def test_ranked_product_of_an_empty_domain_is_empty():
    assert list(_ranked_product([[1], []])) == []
    assert list(_ranked_product([])) == [()]


IMMUTABLE = """
pragma solidity 0.8.27;

contract Held {
    uint256 immutable gate;
    uint256 immutable other;
    constructor(uint256 g) { gate = g; other = g + 1; }
    function both() external view returns (uint256, uint256) { return (gate, other); }
}
"""


def test_an_immutable_is_the_word_every_offset_agrees_on(anvil, tmp_path):  # noqa: F811
    # The compiler's own record of where each immutable sits (``immutableReferences``), against the code the
    # constructor left on the chain: the word read at every offset is the value deployed.
    import json
    import subprocess

    from tests.fuzz.authority import solc_path

    d = O.deployment(*anvil, IMMUTABLE)
    d.deploy("Held", ("uint256",), (0xABC,))
    selection = {"*": {"*": ["evm.deployedBytecode.immutableReferences"]}}
    standard = {"language": "Solidity", "sources": {"H.sol": {"content": IMMUTABLE}},
                "settings": {"outputSelection": selection}}  # fmt: skip
    out = json.loads(
        subprocess.run(
            [str(solc_path("0.8.27")), "--standard-json"],
            input=json.dumps(standard),
            capture_output=True,
            text=True,
            check=True,
        ).stdout  # fmt: skip
    )
    refs = out["contracts"]["H.sol"]["Held"]["evm"]["deployedBytecode"]["immutableReferences"]
    offsets = sorted(tuple(r["start"] for r in places) for places in refs.values())
    code = bytes.fromhex(O.rpc(d.url, "eth_getCode", [O.hex20(d.at["Held"]), "latest"])[2:])
    assert sorted(immutable_value(code, o) for o in offsets) == [0xABC, 0xABD]
    assert immutable_value(code, (offsets[0][0], offsets[1][0])) is None  # disagreeing offsets: not this code
    assert immutable_value(code, (len(code),)) is None  # past the end


class _Chain(Chain):
    """A chain where ``coded`` addresses have code and every call returns ``returned``."""

    def __init__(self, coded: set[int], returned: bytes = b""):
        super().__init__(lambda method, params: None, 1)
        self.coded, self.returned = coded, returned

    def code(self, address: int) -> bytes:
        return b"\x60" if address in self.coded else b""

    def call(self, address: int, data: bytes, sender: int) -> bytes:
        return self.returned if address in self.coded else b""


REGISTRY = 0xBEEF << 100


def _evaluator(chain: Chain) -> Evaluator:
    return Evaluator(World(chain, this=0xC0DE << 100, selector=0), {"caller": FRESH, "signer": FRESH})


def _blocked(target: int) -> Term:
    return mk("call", mk("const", target, "address"), "isBlocked(address)", (CALLER,), True)


def test_a_call_into_no_code_reverts_and_negating_it_does_not_pass():
    probe = _evaluator(_Chain(coded=set()))
    assert probe.truth(_blocked(REGISTRY)) is False
    assert probe.truth(mk_not(_blocked(REGISTRY))) is False  # require(!registry.isBlocked(msg.sender))
    assert probe.truth(mk_or([mk_cmp("eq", CALLER, OWNER), _blocked(REGISTRY)])) is False


CHECKED = """
pragma solidity 0.8.27;

interface ICheck { function onlyAdmin(address who) external view; }
interface ICheckBool { function onlyAdmin(address who) external view returns (bool); }

contract Registry {
    address admin;
    constructor(address a) { admin = a; }
    function onlyAdmin(address who) external view { require(who == admin); }
}

contract Uses {
    address registry;
    constructor(address r) { registry = r; }
    // A check returning nothing, expecting nothing: it passes where the registry's own check does.
    function act() external view { ICheck(registry).onlyAdmin(msg.sender); }
    // The same call read as returning a bool: nothing comes back to decode, so it reverts for everyone.
    function actBool() external view { require(ICheckBool(registry).onlyAdmin(msg.sender)); }
}
"""


@pytest.mark.parametrize("followed", [("Registry",), ()], ids=["followed", "unfollowed"])
@pytest.mark.parametrize("name", ["act", "actBool"])
def test_a_check_call_returning_nothing_passes_only_when_nothing_was_expected(anvil, name, followed):  # noqa: F811
    d = O.deployment(*anvil, CHECKED)
    d.deploy("Registry", ("address",), (O.OWNER,))
    d.deploy("Uses", ("address",), (d.at["Registry"],))
    fn = O.function(d, "Uses", name)
    for who in (O.OWNER, FRESH):
        chain = O.chain_says(d, fn, [], "Uses", sender=who)
        assert chain == (name == "act" and who == O.OWNER)
        formula, engine = O.engine_says(d, fn, [], "Uses", sender=who, contracts=d.contracts("Uses", *followed))
        # Never the other answer; definite where the callee's code shows nothing was expected back.
        assert engine == chain or engine is UNK, (name, hex(who), chain, engine, formula)
        if name == "act" and followed:
            assert engine is not UNK, (name, hex(who), formula)


def test_assembly_memory_hashes_the_bytes_each_store_left():
    # Solady EnumerableRoles: mstore(0x18, holder) mstore(0x04, SEED) mstore(0x00, role) keccak256(0x00, 0x38)
    role, seed = mk("arg", "role", "uint256"), mk("const", 0xEE9A2A3F, "uint256")
    mem = ((0x18, CALLER), (0x04, seed), (0x00, role))
    assert _memory_bytes(mem, 0, 0x38) == (role, mk("const", 0xEE9A2A3F, "uint32"), CALLER)
    assert _memory_bytes(mem, 0, 0x40) is None  # past what was written
    assert _memory_word(mem, 0) == role


def test_a_history_the_node_gives_up_on_is_read_once_and_partial():
    scans = []

    def history(method, params):
        scans.append(params[0]["topics"])
        raise RuntimeError("RPC request failed: read timed out")

    chain = Chain(lambda method, params: None, 1, history=history)
    transfer, approval = frozenset({"0x" + "dd" * 32}), frozenset({"0x" + "8c" * 32})
    assert chain.logs(REGISTRY, transfer) == [] and chain.logs(REGISTRY, transfer) == []
    assert chain.logs(REGISTRY, approval) == []  # another event of the same address: not scanned again
    assert len(scans) == 1 and REGISTRY in chain.truncated


def test_a_literal_typed_as_fixed_bytes_is_its_bytes_left_aligned():
    assert _fixed_bytes(_literal_bytes("\x01", 'hex"01"'), "bytes32") == 1 << 248  # bytes32 PAUSER_ROLE = hex"01"
    # Slither's value for ``hex'deaddead'`` is those bytes read as UTF-8; the source holds them exactly.
    assert _fixed_bytes(_literal_bytes("\u07ad\u07ad", "hex'deaddead'"), "bytes32") == 0xDEADDEAD << 224
    assert _fixed_bytes(_literal_bytes("ab", '"ab"'), "bytes4") == 0x61620000
    assert _fixed_bytes(b"abc", "bytes2") is None  # longer than the type: not this rule
    assert _fixed_bytes(b"ab", "string") is None


def test_a_string_packs_as_its_bytes():
    # Aragon: permissions[keccak256(abi.encodePacked("PERMISSION", who, where, what))]
    who = mk("const", 0xFF, "address")
    key = mk("hash", "keccak256", (mk("enc", "abi.encodePacked", (mk("const", "PERMISSION", "string"), who)),))
    expected = int.from_bytes(keccak(b"PERMISSION" + (0xFF).to_bytes(20, "big")), "big")
    assert _evaluator(_Chain(coded=set())).eval(key) == expected


def test_the_solver_leaves_a_blind_call_unknown():
    # A call whose admitted addresses can't be listed decides nothing about unseen ones, however its code reads.
    call = mk("call", mk("const", REGISTRY, "address"), "canCall(address,uint256)", (CALLER, X), True)
    world = World(_Chain(coded={REGISTRY}), this=0xC0DE << 100, selector=0)
    world.callee = lambda term, address=None: (TRUE, (FALSE,))  # its code: nobody
    blind = Evaluator(world, {"caller": FRESH, "signer": FRESH}, {}, frozenset({(call[1], call[2])}))
    assert solve(call, blind) is not None
    # Nor does the code alone refute it: over every ``x`` the chain can't be asked, so it is unknown, and counted.
    seeing = Evaluator(world, {"caller": FRESH, "signer": FRESH})
    assert solve(call, seeing) is UNK
    assert world.code_refuted == 1


def test_a_model_the_chain_cannot_confirm_never_turns_into_a_refutation():
    # Its only model rests on something unknown: blocking it leaves nothing, which proves nothing either.
    from services.logic.terms import unknown

    formula = mk_and([mk_cmp("eq", X, mk("const", 5, "uint256")), mk_cmp("eq", unknown("memory"), X)])
    world = World(_Chain(coded=set()), this=0xC0DE << 100, selector=0)
    assert solve(formula, Evaluator(world, {"caller": FRESH, "signer": FRESH})) is not None


def test_a_product_of_two_choices_is_solved_exactly():
    # Arbitrum's ``msg.value >= maxSubmissionCost + gasLimit * maxFeePerGas``: the product left free lets z3 pick it
    # apart from its factors, so its models must be brought back to what the factors make.
    gas, fee, cost = (mk("arg", name, "uint256") for name in ("gas", "fee", "cost"))
    two, big = mk("const", 2, "uint256"), mk("const", 10**6, "uint256")
    formula = mk_and(
        [
            mk_cmp("le", two, gas),
            mk_cmp("le", two, fee),
            mk_cmp("le", big, cost),
            mk_cmp("lt", gas, big),
            mk_cmp("lt", fee, big),
            mk_cmp("lt", cost, mk("const", 10**9, "uint256")),
            mk_cmp("le", mk_op("add", (cost, mk_op("mul", (gas, fee)))), X),
            mk_cmp("lt", X, mk("const", 10**12, "uint256")),
        ]
    )
    world = World(_Chain(coded=set()), this=0xC0DE << 100, selector=0)
    found = solve(formula, Evaluator(world, {"caller": FRESH, "signer": FRESH}))
    assert isinstance(found, dict) and found[X] >= found[cost] + found[gas] * found[fee]


def test_two_string_literals_of_one_type_compare_by_their_text():
    deposit, transfer = mk("const", "P:deposit", "bytes32"), mk("const", "P:transfer", "bytes32")
    assert mk_cmp("eq", deposit, transfer) == FALSE
    assert mk_cmp("eq", deposit, mk("const", "P:deposit", "bytes32")) == TRUE
    assert mk_cmp("eq", deposit, mk("const", "P:deposit", "string"))[0] == "cmp"  # other encodings: left as is


def test_a_history_no_node_reads_whole_is_read_window_by_window():
    from services.logic.decide import Chain

    event = "0x" + "11" * 32
    at = {150_000: "0x1", 260_001: "0x2", 299_999: "0x3"}

    def batch(calls):
        out = []
        for method, params in calls:
            assert method == "eth_getLogs"
            lo, hi = int(params[0]["fromBlock"], 16), int(params[0]["toBlock"], 16)
            if hi - lo + 1 > 30_000:
                out.append(None)  # a node refusing the range
            else:
                out.append(
                    [
                        {"topics": [event], "data": d, "blockNumber": hex(b), "logIndex": "0x0"}
                        for b, d in at.items()
                        if lo <= b <= hi
                    ]
                )
        return out

    class Recorded(Chain):
        def creation_block(self, address):
            return 100_000

    chain = Recorded(lambda m, p: (_ for _ in ()).throw(RuntimeError("timeout")), 300_000, batch)
    logs = chain.logs(0xABC, frozenset({event}))
    assert [words for _, words in logs] == [[1], [2], [3]]
    assert 0xABC not in chain.truncated


def test_a_history_scan_the_budget_cut_off_is_partial_and_not_read_again():
    from services.logic.decide import Chain

    event = "0x" + "11" * 32
    sent = []

    def batch(calls):
        sent.extend(calls)
        if any(m == "eth_getLogs" for m, _ in calls):
            raise TimeoutError("function budget")
        return ["0x60"] * len(calls)

    chain = Chain(lambda m, p: None, 1_000_000, batch)
    with pytest.raises(TimeoutError):
        chain.logs(0xABC, frozenset({event}))
    reads = len(sent)
    assert chain.logs(0xABC, frozenset({event})) == [] and 0xABC in chain.truncated
    assert len(sent) == reads


def test_a_slow_node_costs_a_history_its_completeness_not_the_verdict_its_time():
    import time

    from services.logic.decide import Chain

    sent = []

    def batch(calls):
        sent.extend(calls)
        if any(m == "eth_getLogs" for m, _ in calls):
            time.sleep(0.05)
        return ["0x60" if m != "eth_getLogs" else None for m, _ in calls]  # refused: would halve on and on

    chain = Chain(lambda m, p: None, 19_999_999, batch)
    chain.scan_left = 0.01
    assert chain.logs(0xABC, frozenset({"0x" + "11" * 32})) == [] and 0xABC in chain.truncated
    assert sum(1 for m, _ in sent if m == "eth_getLogs") == 20  # one round, then the time is spent


def test_an_action_whose_callee_check_went_unread_is_not_assumed():
    # The callee lets ``ALLOWED`` through, or anyone once a flag it keeps is set; the flag's read failed. A stranger
    # may be refused there: not an action it arranges. ``ALLOWED`` passes whatever the flag holds.
    from services.logic.decide import ASSUMED
    from services.logic.terms import CALLER, mk, mk_cmp, mk_not, mk_or

    allowed = 0xA110 << 100
    target = mk("const", 0xCA11 << 100, "address")
    call = mk("call", target, "pull(address)", (CALLER,), False)
    check = mk_or(
        [
            mk_cmp("eq", CALLER, mk("const", allowed, "address")),
            mk_not(mk_cmp("eq", mk("rawload", target, mk("const", 7, "uint256")), mk("const", 0, "uint256"))),
        ]
    )

    def failing(method, params):
        raise RuntimeError("timeout")

    world = World(Chain(failing, 1), this=0xC0DE << 100, selector=0)
    world.callee = lambda t, address=None: (check, ())
    world.action_open = lambda t, refused: False
    assert Evaluator(world, {"caller": FRESH, "signer": FRESH})._action(call) is UNK
    assert Evaluator(world, {"caller": allowed, "signer": FRESH})._action(call) is ASSUMED
