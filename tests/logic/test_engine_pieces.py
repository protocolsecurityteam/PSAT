"""The logic engine's building blocks that need no chain: witness ordering, formula rewriting, term traversal."""

from __future__ import annotations

import itertools

import pytest
from eth_utils import keccak

from services.logic.decide import (
    FRESH,
    REVERTED,
    UNK,
    Chain,
    Evaluator,
    World,
    _comparands,
    _first_zero,
    _identity_keys,
    _ranked_product,
    batch_results,
    coverage,
    solve,
)
from services.logic.immutables import immutable_value
from services.logic.lower import State, _fixed_bytes, _literal_bytes, _memory_bytes, _memory_word, _ran_under, merge
from services.logic.terms import (
    CALLER,
    FALSE,
    THIS,
    TRUE,
    Term,
    assume_conjuncts,
    contains,
    mk,
    mk_and,
    mk_cmp,
    mk_ite,
    mk_not,
    mk_op,
    mk_or,
)
from services.logic.verdict import _hashed, _value_leaves

X = mk("arg", "x", "uint256")
OWNER = mk("load", THIS, "owner", ())
IS_OWNER = mk_cmp("eq", CALLER, OWNER)


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


def test_first_zero_puts_the_neutral_value_first_and_keeps_booleans():
    assert _first_zero([7, 0, 3, 0, 7]) == [0, 7, 3]
    assert _first_zero([False, True]) == [False, True]


def test_a_conjunct_is_true_wherever_the_others_mention_it():
    # (caller == owner) and (ite(caller == owner, x, 0) < 5): the ite is the merged path condition.
    value = mk_ite(IS_OWNER, X, mk("const", 0, "uint256"))
    formula = mk_and([IS_OWNER, mk_cmp("lt", value, mk("const", 5, "uint256"))])
    simplified = assume_conjuncts(formula)
    assert simplified == mk_and([IS_OWNER, mk_cmp("lt", X, mk("const", 5, "uint256"))])


def test_a_negated_conjunct_is_false_wherever_the_others_mention_it():
    paused = mk("load", THIS, "paused", ())
    formula = mk_and([mk("not", paused), mk_or([paused, IS_OWNER])])
    assert assume_conjuncts(formula) == mk_and([mk("not", paused), IS_OWNER])


def test_contains_is_answered_per_kind_set():
    term = mk_and([IS_OWNER, mk_cmp("lt", X, mk("const", 5, "uint256"))])
    assert contains(term, frozenset({"caller"}))
    assert contains(term, frozenset({"arg"}))
    assert not contains(term, frozenset({"signer"}))
    assert not contains(OWNER, frozenset({"caller"}))


def test_an_immutable_is_the_word_every_offset_agrees_on():
    word = (0xABC).to_bytes(32, "big")
    code = b"\x60" * 3 + word + b"\x00" * 5 + word
    assert immutable_value(code, (3, 40)) == 0xABC
    assert immutable_value(code, (3, 4)) is None  # disagreeing offsets: not the code that was compiled
    assert immutable_value(code, (60,)) is None  # past the end


def test_written_values_are_the_constants_an_ite_can_leave():
    old = mk("load", THIS, "flag", ())
    written = mk_ite(mk_cmp("lt", X, mk("const", 3, "uint256")), TRUE, old)
    assert _value_leaves(written, old) == {True}
    one, two = mk("const", 1, "uint8"), mk("const", 2, "uint8")
    assert _value_leaves(mk_ite(IS_OWNER, one, two), old) == {1, 2}
    assert _value_leaves(X, old) is None


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


def test_a_check_call_returning_nothing_passes_only_when_nothing_was_expected():
    probe = _evaluator(_Chain(coded={REGISTRY}))
    check = mk("call", mk("const", REGISTRY, "address"), "onlyAdmin(address)", (CALLER,), True)
    assert probe.truth(mk("ok", check, 0)) is True
    assert probe.truth(mk("ok", check, None)) is UNK


def test_assembly_memory_hashes_the_bytes_each_store_left():
    # Solady EnumerableRoles: mstore(0x18, holder) mstore(0x04, SEED) mstore(0x00, role) keccak256(0x00, 0x38)
    role, seed = mk("arg", "role", "uint256"), mk("const", 0xEE9A2A3F, "uint256")
    mem = ((0x18, CALLER), (0x04, seed), (0x00, role))
    assert _memory_bytes(mem, 0, 0x38) == (role, mk("const", 0xEE9A2A3F, "uint32"), CALLER)
    assert _memory_bytes(mem, 0, 0x40) is None  # past what was written
    assert _memory_word(mem, 0) == role


def test_a_slot_hashed_from_the_caller_is_a_lookup_keyed_by_it():
    seed = mk("const", 7, "uint32")
    slot = mk("hash", "keccak256", (mk("enc", "abi.encodePacked", (X, seed, CALLER)),))
    assert _identity_keys(slot) == [CALLER]
    mixed = mk("hash", "keccak256", (mk_op("add", (CALLER, X)),))
    assert _identity_keys(mixed) is None


def test_a_batched_revert_is_remembered_and_other_errors_stay_unknown():
    classified = [
        ("0x01", "ok"),
        ({"code": 3, "message": "execution reverted"}, "error"),
        ({"code": -32003, "message": "EVM error: InvalidFEOpcode"}, "error"),  # an assert's invalid opcode
        ({"code": -32602, "message": "invalid argument"}, "error"),
        (None, "transport"),
    ]
    assert batch_results(classified) == ["0x01", REVERTED, REVERTED, None, None]


def test_a_short_circuited_operand_is_itself_wherever_the_operator_reads_it():
    initialized = mk("load", THIS, "initialized", ())
    version_zero = mk_cmp("eq", mk("load", THIS, "version", ()), mk("const", 0, "uint8"))
    merged = mk_ite(initialized, version_zero, mk("unknown", "unset"))  # `initialized && version == 0`, merged
    assert _ran_under(merged, initialized) == version_zero
    assert _ran_under(merged, mk_not(initialized)) == merged  # not the guard it ran under


def test_storage_one_branch_left_alone_keeps_its_old_value_when_branches_merge():
    threshold = (THIS, "threshold", ())
    wrote = State(IS_OWNER, store={threshold: X})
    skipped = State(mk_not(IS_OWNER), store={})
    merged = merge([wrote, skipped])
    assert merged.store[threshold] == mk_ite(IS_OWNER, X, mk("load", THIS, "threshold", ()))


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


def test_a_lookup_keyed_by_an_identitys_own_entry_is_representative():
    # permissionParams[permissions[hash(who, ...)]]: every address nothing names reads the same zero entry.
    hashed = mk("hash", "keccak256", (mk("enc", "abi.encodePacked", (CALLER,)),))
    entry = mk("load", THIS, "permissions", (("k", hashed),))
    params = mk("load", THIS, "permissionParams", (("k", entry),))
    found = coverage(mk_cmp("eq", params, mk("const", 1, "uint256")), lambda *a: True, lambda call: None)
    assert found.representative
    assert found.lookups == {(THIS, "permissions")}


def test_the_solver_leaves_a_blind_call_unknown():
    # A call whose admitted addresses can't be listed decides nothing about unseen ones, however its code reads.
    call = mk("call", mk("const", REGISTRY, "address"), "canCall(address,uint256)", (CALLER, X), True)
    world = World(_Chain(coded={REGISTRY}), this=0xC0DE << 100, selector=0)
    world.callee = lambda term, address=None: (TRUE, (FALSE,))  # its code: nobody
    blind = Evaluator(world, {"caller": FRESH, "signer": FRESH}, {}, frozenset({(call[1], call[2])}))
    assert solve(call, blind) is not None
    seeing = Evaluator(world, {"caller": FRESH, "signer": FRESH})
    assert solve(call, seeing) is None


def test_the_solver_looks_for_a_witness_through_what_it_can_read_first():
    # An opaque branch beside a plain one: a model leaning on the opaque one is never confirmed.
    opaque = mk("opaque", "staticcall(uint256)", (X,))
    formula = mk_or([opaque, mk_cmp("eq", X, mk("const", 5, "uint256"))])
    world = World(_Chain(coded=set()), this=0xC0DE << 100, selector=0)
    assert solve(formula, Evaluator(world, {"caller": FRESH, "signer": FRESH})) == {X: 5}


def test_the_conditions_of_a_merged_guard_are_collected_once_per_shared_node():
    from services.logic.verdict import _atoms

    guard = mk_cmp("lt", X, OWNER)
    for i in range(200):  # each merge shares the whole guard below it twice: a tree walk is 2**200 steps
        flag = mk("load", THIS, f"flag{i}", ())
        guard = mk(
            "ite", mk_cmp("eq", flag, mk("const", 0, "uint256")), mk("and", (guard, flag)), mk("or", (guard, flag))
        )
    found = len(_atoms(guard))
    assert found == 401  # the comparison, and each merge's test and flag


def test_terms_kept_across_a_reset_are_rebuilt_into_the_new_table():
    from services.logic.terms import reintern, reset_terms

    def chain(depth: int) -> Term:
        t = X
        for _ in range(depth):
            t = mk_ite(mk_cmp("lt", t, OWNER), t, mk_op("add", (t, mk("const", 1, "uint256"))))
        return t

    kept = {"guard": [chain(40)]}
    reset_terms()
    fresh = chain(40)
    assert kept["guard"][0] is not fresh
    assert reintern(kept)["guard"][0] is fresh  # identical again: comparing never walks the DAG


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


def test_a_choice_compared_with_a_fixed_value_is_guessed_at_and_around_it():
    deadline = mk("arg", "deadline", "uint256")
    formula = mk_and([mk_cmp("le", mk("const", 1000, "uint256"), deadline), mk_cmp("lt", X, OWNER)])
    world = World(_Chain(coded=set()), this=0xC0DE << 100, selector=0)
    found = _comparands(formula, Evaluator(world, {"caller": FRESH, "signer": FRESH}), frozenset({deadline, X}))
    assert found == {deadline: [999, 1000, 1001]}  # ``owner`` isn't read here: no value to guess around


def test_a_value_an_equality_names_is_guessed_first():
    token = mk("arg", "token", "address")
    formula = mk_and([mk_cmp("eq", token, mk("const", 0xEEEE, "address")), mk_cmp("lt", mk("const", 5, "uint256"), X)])
    world = World(_Chain(coded=set()), this=0xC0DE << 100, selector=0)
    found = _comparands(formula, Evaluator(world, {"caller": FRESH, "signer": FRESH}), frozenset({token}))
    assert found[token][0] == 0xEEEE


def test_a_stranger_is_in_no_slot_and_nothing_is_stored_under_it():
    # ``node`` is the caller's to pick: still, no ``owners[node]`` holds a made-up address, and a stranger has no
    # ``approved[node][stranger]``.
    node = mk("arg", "node", "bytes32")
    owner_of = mk("load", THIS, "owners", (("k", node),))
    approved = mk("load", THIS, "approved", (("k", node), ("k", CALLER)))
    formula = mk_or([mk_cmp("eq", CALLER, owner_of), approved])
    world = World(_Chain(coded=set()), this=0xC0DE << 100, selector=0)
    assert solve(formula, Evaluator(world, {"caller": FRESH, "signer": FRESH})) is None


def test_a_slot_hashed_from_the_arguments_is_never_a_named_variables():
    # Lido's signing keys: sstore(keccak256(SEED, operatorId, index) + offset, key) lands in hashed space.
    keyed = mk("hash", "keccak256", (mk("enc", "abi.encode", (mk("const", 7, "uint256"), X)),))
    assert _hashed(keyed) and _hashed(mk_op("add", (keyed, X)))
    assert not _hashed(X) and not _hashed(mk("const", 3, "uint256"))


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


def test_a_range_cap_is_found_once_not_by_splitting_every_window():
    from services.logic.decide import LOG_CALLS, Chain

    event = "0x" + "11" * 32
    at = {2_000_000: "0x1", 9_123_456: "0x2", 19_999_999: "0x3"}
    sent = []

    def batch(calls):
        out = []
        for method, params in calls:
            lo, hi = int(params[0]["fromBlock"], 16), int(params[0]["toBlock"], 16)
            sent.append(hi - lo + 1)
            if hi - lo + 1 > 300_000:
                out.append(None)  # a node capping the range
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
            return 2_000_000

    chain = Recorded(lambda m, p: None, 19_999_999, batch)
    assert [words for _, words in chain.logs(0xABC, frozenset({event}))] == [[1], [2], [3]]
    assert 0xABC not in chain.truncated
    # 18 refused windows, two probes halving one of them, then every block once at the width that answered.
    refused = sum(1 for width in sent if width > 300_000)
    assert refused == 18 + 2 and len(sent) - refused == 18_000_000 // 250_000 < LOG_CALLS


def test_a_history_that_stays_refused_is_partial_never_empty():
    from services.logic.decide import Chain

    chain = Chain(lambda m, p: None, 300_000, lambda calls: [None] * len(calls))
    assert chain.logs(0xABC, frozenset({"0x" + "11" * 32})) == []
    assert 0xABC in chain.truncated


def test_a_crowded_history_stops_early_and_leaves_the_contracts_other_events_readable():
    from services.logic.decide import LOG_CALLS, Chain

    transfer, granted = "0x" + "22" * 32, "0x" + "33" * 32
    sent = []

    def batch(calls):
        sent.extend(calls)
        out = []
        for method, params in calls:
            if method != "eth_getLogs":
                out.append("0x60")  # code at every probe: history from the start
            elif params[0]["topics"] == [[transfer]]:
                out.append(None)  # too many results, at any range
            else:
                out.append(
                    [{"topics": [granted], "data": "0x" + "00" * 31 + "07", "blockNumber": "0x1", "logIndex": "0x0"}]
                    if int(params[0]["fromBlock"], 16) == 0
                    else []
                )
        return out

    chain = Chain(lambda m, p: None, 1_000_000, batch)
    assert chain.logs(0xABC, frozenset({transfer})) == []
    transfers = sum(1 for method, _ in sent if method == "eth_getLogs")
    assert transfers < 50 < LOG_CALLS
    assert [w for _, w in chain.logs(0xABC, frozenset({granted}))] == [[7]]


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


def test_an_action_returns_in_the_solver_as_the_evaluator_assumes():
    # Aave's ``depositWithSig``: the hub's ``add(id, assets)`` is an action over a chosen amount, beside an ERC-1271
    # branch nothing models. Pinning what isn't modelled must not pin the action to failing: it returns, as evaluated.
    action = mk("ok", mk("call", mk("const", REGISTRY, "address"), "add(uint256)", (X,), False), 1)
    opaque = mk("opaque", "staticcall(uint256)", (X,))
    formula = mk_and([action, mk_or([opaque, mk_cmp("eq", X, mk("const", 5, "uint256"))])])
    world = World(_Chain(coded={REGISTRY}), this=0xC0DE << 100, selector=0)
    assert solve(formula, Evaluator(world, {"caller": FRESH, "signer": FRESH})) == {X: 5}


def test_more_events_than_a_crowded_history_are_not_read_again():
    from services.logic.decide import Chain

    transfer, approval = "0x" + "22" * 32, "0x" + "33" * 32
    sent = []

    def batch(calls):
        sent.extend(calls)
        return ["0x60" if m != "eth_getLogs" else None for m, _ in calls]  # every window refused

    chain = Chain(lambda m, p: None, 1_000_000, batch)
    assert chain.logs(0xABC, frozenset({transfer})) == []
    reads = sum(1 for m, _ in sent if m == "eth_getLogs")
    assert chain.logs(0xABC, frozenset({transfer, approval})) == [] and 0xABC in chain.truncated
    assert sum(1 for m, _ in sent if m == "eth_getLogs") == reads


def test_a_node_refusing_a_range_for_its_size_ends_the_scan_at_once():
    from services.logic.decide import CROWDED, Chain, batch_results

    assert batch_results([({"code": -32005, "message": "More than 50000 logs returned"}, "error")]) == [CROWDED]
    assert batch_results([({"code": -32005, "message": "query returned more than 10 results"}, "error")]) == [None]
    sent = []

    def batch(calls):
        sent.extend(calls)
        return ["0x60" if m != "eth_getLogs" else CROWDED for m, _ in calls]

    chain = Chain(lambda m, p: None, 19_999_999, batch)
    assert chain.logs(0xABC, frozenset({"0x" + "22" * 32})) == [] and 0xABC in chain.truncated
    assert sum(1 for m, _ in sent if m == "eth_getLogs") == 20  # the first round, no halving after it


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


def test_a_crowded_history_leaves_another_history_of_the_same_contract_whole():
    # A token's transfers too many to read take nothing from its role grants, read whole.
    transfers, grants = frozenset({"0x" + "11" * 32}), frozenset({"0x" + "22" * 32})

    class _Indexed(Chain):
        def logs(self, address, topics):
            if topics == transfers:
                self.truncated.add(address)
            return []

    chain = _Indexed(lambda m, p: None, 1)
    chain.logs(0xABC, transfers)
    chain.logs(0xABC, grants)
    chain.logs(0xABC, transfers)  # read again from memory: still the partial one
    assert chain.cut(0xABC, transfers) and not chain.cut(0xABC, grants)
    assert 0xABC in chain.truncated  # the address as a whole, for whoever asks that
    assert chain.cut(0xABC, frozenset({"0x" + "33" * 32}))  # never read: nothing known of it


def test_what_an_arranged_call_returns_is_one_word():
    # SafeERC20's ``returndata.length == 0 || abi.decode(returndata, (bool))`` after a transfer the caller arranges.
    from services.logic.terms import mk

    chain = Chain(lambda m, p: None, 1)
    evaluator = Evaluator(World(chain, this=0xC0DE << 100, selector=0), {"caller": FRESH, "signer": FRESH})
    assert evaluator.eval(mk("len", mk("assumed", "returndata"))) == 32


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
