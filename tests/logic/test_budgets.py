"""What a budget may cost: a smaller one never makes a verdict more open, names only holders the full one names, and
accounts for any it misses with a gap (untested candidates, an undetermined "now"). Batching and windowing alone
change nothing; a candidate list is asked about in batches rather than cut by address, those the state as it stands
lets through first and those it refuses last; a history read partial is reported as cut, its holders a lower bound."""

from __future__ import annotations

import pytest
from eth_utils import keccak

from services.logic import decide
from services.logic.decide import Chain
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path

SOURCE = """
pragma solidity 0.8.27;

contract Roles {
    mapping(bytes32 => mapping(address => bool)) roles;
    uint256 total;
    bytes32 constant MINTER = keccak256("MINTER");
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    function grant(bytes32 role, address who) external {
        require(roles[0][msg.sender]);
        roles[role][who] = true;
        emit RoleGranted(role, who);
    }

    function revoke(bytes32 role, address who) external {
        require(roles[0][msg.sender]);
        roles[role][who] = false;
        emit RoleRevoked(role, who);
    }

    function mint() external {
        require(roles[MINTER][msg.sender]);
        total += 1;
    }
}
"""

AT = 0xA1 << 140
BLOCK = 10_000_000
_MINTER = int.from_bytes(keccak(b"MINTER"), "big")
_GRANTED = int.from_bytes(keccak(b"RoleGranted(bytes32,address)"), "big")
_REVOKED = int.from_bytes(keccak(b"RoleRevoked(bytes32,address)"), "big")
# High addresses first in the grant order: a cut by address would drop the earliest grants' holders.
MINTERS = [(0xF0 << 150) - (i << 100) for i in range(40)]
REVOKED = MINTERS[5]
DECOY = 0xD0 << 150  # holds the role, but only a contract-wide sample of log words names it


def _slot(key: int, base: int) -> int:
    return int.from_bytes(keccak(key.to_bytes(32, "big") + base.to_bytes(32, "big")), "big")


def _hex(word: int) -> str:
    return "0x" + format(word, "064x")


class _Scanned(Chain):
    """Grants spread over the history, read window by window over ``eth_getLogs`` (``Chain._scan_logs``)."""

    def __init__(self, sample: frozenset = frozenset()):
        self.sample = sample
        self.words = {_slot(m, _slot(_MINTER, 0)): 1 for m in [*MINTERS, DECOY] if m != REVOKED}
        self.grants = [((i + 1) * 200_000, [_GRANTED, _MINTER, m]) for i, m in enumerate(MINTERS)] + [
            (9_000_000, [_REVOKED, _MINTER, REVOKED]),
            (9_500_000, [_GRANTED, _MINTER, DECOY]),
        ]
        super().__init__(self._answer, BLOCK, lambda calls: [self._safe(m, p) for m, p in calls])

    def _safe(self, method, params):
        try:
            return self._answer(method, params)
        except RuntimeError:
            return None

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            return hex(self.words.get(int(params[1], 16), 0)) if int(params[0], 16) == AT else "0x0"
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(1_700_000_000), "number": hex(BLOCK)}
        if method == "eth_getCode":
            return "0x60" if int(params[0], 16) == AT else "0x"
        if method == "eth_getLogs":
            flt = params[0]
            lo, hi = int(flt["fromBlock"], 16), int(flt["toBlock"], 16)
            wanted = {int(t, 16) for t in flt["topics"][0]}
            if int(flt["address"], 16) != AT:
                return []
            return [
                {"topics": [_hex(t) for t in topics], "data": "0x", "blockNumber": hex(b), "logIndex": "0x0"}
                for b, topics in self.grants
                if lo <= b <= hi and topics[0] in wanted
            ]
        raise RuntimeError("execution reverted")

    def code(self, address):
        return b"\x60" if address == AT else b""

    def creation_block(self, address):
        return 0

    def all_log_words(self, address):
        return set(self.sample)


@pytest.fixture(scope="module")
def roles(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("budgets") / "R.sol"
    path.write_text(SOURCE)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Roles")


def _verdict(roles, chain=None):
    from services.logic.terms import reset_terms

    reset_terms()
    fn = next(f for f in roles.functions_entry_points if f.name == "mint")
    verdict, _ = function_verdict(roles, fn, AT, chain or _Scanned(), {AT: roles})
    return verdict


def _small_batches(monkeypatch, size: int) -> None:
    monkeypatch.setattr(decide, "_CANDIDATE_BATCH", size)


def test_every_holder_the_history_names_is_found_in_full(roles):
    verdict = _verdict(roles)
    assert verdict.openness == "restricted"
    assert verdict.principals == set(MINTERS) - {REVOKED} | {DECOY}
    assert verdict.complete


def test_batching_and_windowing_alone_change_nothing(roles, monkeypatch):
    full = _verdict(roles)
    _small_batches(monkeypatch, 7)
    monkeypatch.setattr(decide, "LOG_WINDOW", 100_000)
    monkeypatch.setattr(decide, "LOG_MIN_WINDOW", 100_000 // 64)
    monkeypatch.setattr(decide, "LOG_BATCH", 9)
    reduced = _verdict(roles)
    assert (reduced.openness, reduced.principals, reduced.complete) == (full.openness, full.principals, full.complete)


_OPENNESS = {"not_determined": 0, "restricted": 1, "open": 2}


@pytest.mark.parametrize("work", [1, 4, 8, 12, 20, 40, 80])
def test_a_smaller_budget_costs_holders_only_with_a_gap_saying_so(roles, monkeypatch, work):
    full = _verdict(roles)
    assert full.openness == "restricted" and full.complete
    _small_batches(monkeypatch, 4)
    monkeypatch.setattr(decide, "DECISION_WORK", work * decide.QUESTION_WORK)
    reduced = _verdict(roles)
    assert _OPENNESS[reduced.openness] <= _OPENNESS[full.openness]
    assert reduced.principals <= full.principals
    if (reduced.openness, reduced.principals) != (full.openness, full.principals):
        assert not reduced.complete
        assert any(g.startswith(("untested_candidates:", "now_unknown")) for g in reduced.gaps)


def test_candidates_the_state_refuses_are_asked_about_last(roles, monkeypatch):
    # The revoked minter sits among the others by address and by the sources naming it; its entry, read as it
    # stands, refuses it: asked about after every candidate the state lets through.
    asked: list[int] = []
    screened = decide._screened

    def spy(*args):
        order = screened(*args)
        asked.extend(order)
        return order

    monkeypatch.setattr(decide, "_screened", spy)
    full = _verdict(roles)
    assert asked[-1] == REVOKED and set(asked) == set(MINTERS) | {DECOY}
    assert full.principals == set(MINTERS) - {REVOKED} | {DECOY}


class _Unbatched(_Scanned):
    """The same node without batches: nothing defers a read."""

    def __init__(self, sample: frozenset = frozenset()):
        super().__init__(sample)
        self.batch = None


@pytest.mark.parametrize("node", [_Scanned, _Unbatched])
def test_the_screen_reads_nothing_and_leaves_no_trace(roles, monkeypatch, node):
    # The screen only orders the candidates: it sends no read (with batches or without), and nothing it evaluated,
    # an unanswered read among it, stays remembered where the questions look (memos, counts, the budget).
    screened = decide._screened
    unchanged: list[bool] = []

    def spy(formula, world, candidates, loosened):
        chain = world.chain

        def state():
            return (
                chain.sent,
                chain.failed,
                dict(chain._memo),
                set(chain.truncated),
                dict(chain.partial),
                {k: list(v) for k, v in world.solver_record.items()},
                dict(world.__dict__.get("_brought", {})),
                world.work,
                getattr(world, "code_refuted", 0),
            )

        before = state()
        order = screened(formula, world, candidates, loosened)
        unchanged.append(state() == before)
        return order

    monkeypatch.setattr(decide, "_screened", spy)
    verdict = _verdict(roles, node())
    assert verdict.principals == set(MINTERS) - {REVOKED} | {DECOY}
    assert unchanged and all(unchanged)


def test_a_detached_block_reads_nothing_and_puts_every_memo_back():
    from services.logic.decide import UNK, Offline, World, detached

    chain = _Unbatched()
    world = World(chain, this=AT, selector=0)
    world.solver_record[("q", 0)] = [1, 0]
    with detached(world):
        assert chain.storage(AT, 1) is UNK  # unanswered: unknown, never sent
        with pytest.raises(Offline):
            chain.logs(AT, frozenset({"0x" + format(_GRANTED, "064x")}))
        world.solver_record[("q", 0)][0] += 5  # a give-up counted in the block
        world.solver_record[("r", 0)] = [3, 0]
        world.__dict__.setdefault("_brought", {})["k"] = UNK
        world.work += 50
    assert chain.sent == 0 and not chain._memo
    assert world.solver_record == {("q", 0): [1, 0]}
    assert "_brought" not in world.__dict__ and world.work == 0


def test_the_budgets_above_do_bind(roles, monkeypatch):
    # Otherwise the property above would hold vacuously.
    full = _verdict(roles)
    _small_batches(monkeypatch, 4)
    monkeypatch.setattr(decide, "DECISION_WORK", 40 * decide.QUESTION_WORK)
    assert len(_verdict(roles).principals) < len(full.principals)


def test_candidates_past_a_batch_are_asked_about_not_cut_by_address(roles, monkeypatch):
    _small_batches(monkeypatch, 4)
    verdict = _verdict(roles)
    assert verdict.principals == set(MINTERS) - {REVOKED} | {DECOY}
    assert not any(g.startswith(("too_many_candidates", "untested_candidates")) for g in verdict.gaps)


def test_a_budget_spent_before_every_candidate_is_asked_about_says_how_many(roles, monkeypatch):
    _small_batches(monkeypatch, 4)
    monkeypatch.setattr(decide, "DECISION_WORK", 12 * decide.QUESTION_WORK)
    verdict = _verdict(roles)
    untested = [g for g in verdict.gaps if g.startswith("untested_candidates:")]
    assert not verdict.complete
    assert untested and int(untested[0].split(":")[1]) > 0
    assert verdict.principals <= set(MINTERS) | {DECOY}


def test_a_history_cut_short_lists_what_it_read_as_a_lower_bound(roles, monkeypatch):
    # Room for the first windows only: the grants they hold are read, the later ones (and the decoy's) are not.
    monkeypatch.setattr(decide, "LOG_WINDOW", 1_000_000)
    monkeypatch.setattr(decide, "LOG_BATCH", 3)
    monkeypatch.setattr(decide, "LOG_CALLS", 3)
    verdict = _verdict(roles, _Scanned(sample=frozenset({DECOY})))
    early = {m for i, m in enumerate(MINTERS) if (i + 1) * 200_000 < 3_000_000} - {REVOKED}
    assert verdict.openness == "restricted"
    assert early and early <= verdict.principals
    assert not verdict.complete
    assert "history_truncated" in verdict.gaps
    # A contract-wide sample of log words doesn't stand in for the writer history that was cut.
    assert DECOY not in verdict.principals


class _Clock:
    """``time`` as ``decide`` reads it, advanced by the fake node: what a scan spends, without waiting."""

    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now


def _crowded_chain(clock, crowds: set, seconds_per_round: float):
    def batch(calls):
        out = []
        for method, params in calls:
            if method != "eth_getLogs":
                out.append("0x60")
            elif int(params[0]["address"], 16) in crowds:
                out.append(None)  # refused
            else:
                out.append([])
        if any(m == "eth_getLogs" and int(p[0]["address"], 16) in crowds for m, p in calls):
            clock.now += seconds_per_round
        return out

    return Chain(lambda m, p: None, 19_999_999, batch)


def test_a_crowded_history_read_first_takes_no_more_than_its_share(monkeypatch):
    # Which history a function reads first follows set order: a token's transfers refused window after window must
    # not spend the time a role history read after them needs.
    clock = _Clock()
    monkeypatch.setattr(decide, "time", clock)
    crowd, short = 0xC1 << 150, 0xC2 << 150
    transfers, grants = frozenset({"0x" + "11" * 32}), frozenset({"0x" + "22" * 32})
    chain = _crowded_chain(clock, {crowd}, seconds_per_round=5.0)
    chain.scan_left = chain.history_seconds = 20.0
    chain.scan_total = 90.0
    chain.logs(crowd, transfers)
    chain.logs(short, grants)
    assert chain.cut(crowd, transfers) and clock.now <= 25.0
    assert not chain.cut(short, grants)


def test_a_functions_history_scanning_is_bounded_in_total_and_what_it_cuts_is_cut(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(decide, "time", clock)
    crowds = [(0xD0 + i) << 150 for i in range(6)]
    chain = _crowded_chain(clock, set(crowds), seconds_per_round=5.0)
    chain.scan_left = chain.history_seconds = 20.0
    chain.scan_total = 50.0
    for i, crowd in enumerate(crowds):
        chain.logs(crowd, frozenset({"0x" + format(i + 1, "064x")}))
    assert clock.now <= 50.0 + 5.0  # one round past the line at most, never 6 x 20 s
    assert all(chain.cut(c, frozenset({"0x" + format(i + 1, "064x")})) for i, c in enumerate(crowds))


class _SomeUnreadable(_Scanned):
    """The lowest-addressed minters' role entries fail to read, as a node timing out."""

    def __init__(self, failing: set):
        super().__init__()
        self.failing = {_slot(m, _slot(_MINTER, 0)) for m in failing}

    def _answer(self, method, params):
        if method == "eth_getStorageAt" and int(params[1], 16) in self.failing:
            raise RuntimeError("timeout")
        return super()._answer(method, params)


def test_candidates_left_open_first_dont_stop_the_rest_being_asked(roles):
    # Asked lowest address first: a few unanswered ones must not make every later candidate unanswered too.
    failing = set(sorted([*MINTERS, DECOY])[:6])
    verdict = _verdict(roles, _SomeUnreadable(failing))
    assert verdict.principals == (set(MINTERS) | {DECOY}) - {REVOKED} - failing
    assert failing <= verdict.undecided and not verdict.complete
