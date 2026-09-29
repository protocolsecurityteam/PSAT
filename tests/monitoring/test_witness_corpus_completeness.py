"""Corpus completeness for the witness taxonomy (spec Part 6, G3 artifact).

Zero-diff on golden fixtures proves nothing unless the corpus CONTAINS the shapes the
taxonomy separates. One contract carries all five degenerate shapes (reentrancy guard,
open-writer mapping, struct-member mismatch, DenyFrom-class, canonical family); the real
tracking plan is derived and each shape's ``witness_tier`` pinned. Every assertion is paired
with a NON-VACUITY check that the raw ingredient is present in the corpus.
"""

from __future__ import annotations

import textwrap

import pytest
from eth_utils.crypto import keccak

pytest.importorskip("slither")
from slither import Slither

from services.monitoring.event_topics import (
    WITNESS_TIER_ACTIVITY,
    WITNESS_TIER_HINT,
    WITNESS_TIER_SELF_DESCRIBING,
    WITNESS_TIERS,
    extract_governance_topics,
    parse_tracked_log,
)
from services.monitoring.polling_plan import build_polling_plan
from services.resolution.tracking_plan import build_control_tracking_plan
from services.static.contract_analysis_pipeline.effects import build_effects
from services.static.contract_analysis_pipeline.mapping_events import (
    discover_mapping_writer_events,
    member_witness_records,
    multi_entry_writers,
)
from services.static.contract_analysis_pipeline.predicate_artifacts import (
    build_predicate_artifacts,
)
from services.static.contract_analysis_pipeline.summaries import (
    _build_semantic_control_summary,
)
from services.static.contract_analysis_pipeline.tracking import (
    _assembly_log_functions,
    _state_writers_from_effects,
    build_controller_tracking,
)
from utils.scoring_status import OPENNESS_VALUES

CORPUS_SOURCE = """
pragma solidity ^0.8.19;

contract WitnessCorpus {
    struct AccountantState {
        address payoutAddress;
        uint96 exchangeRate;
        uint64 lastUpdate;
        bool isPaused;
    }

    address public owner;
    AccountantState public accountantState;
    mapping(address => bool) public fromDenyList;
    mapping(address => bool) public registered;
    mapping(address => bool) public claimed;
    mapping(address => bool) public wards;
    mapping(address => uint256) public balances;
    mapping(uint256 => uint128) public gasLimits;
    mapping(address => uint64) internal _tokenInfos;
    uint64 public depositLimit;
    uint256 private _status = 1;
    bool public locked;

    event OwnerUpdated(address indexed user, address indexed newOwner);
    event DenyFrom(address indexed user);
    event AllowFrom(address indexed user);
    event Registered(address indexed user);
    event Claimed(address indexed user);
    event WardAdded(address indexed usr, uint256 value);
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event ExchangeRateUpdated(uint96 oldRate, uint96 newRate);
    event PayoutAddressUpdated(address oldPayout, address newPayout);
    event ChainSetGasLimit(uint256 indexed id, uint128 limit);
    event Deposited(address indexed user, uint256 amount);
    event Locked(address indexed by);
    event TokenMaxWeightUpdated(uint64 oldLimit, uint64 newLimit);
    event DepositLimitUpdated(uint64 oldLimit, uint64 newLimit);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier nonReentrant() {
        require(_status == 1, "reentrant");
        _status = 2;
        _;
        _status = 1;
    }

    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
        emit OwnerUpdated(msg.sender, newOwner);
    }

    function denyFrom(address user) external onlyOwner {
        fromDenyList[user] = true;
        emit DenyFrom(user);
    }

    function allowFrom(address user) external onlyOwner {
        fromDenyList[user] = false;
        emit AllowFrom(user);
    }

    function setGasLimit(uint256 id, uint128 limit) external onlyOwner {
        gasLimits[id] = limit;
        emit ChainSetGasLimit(id, limit);
    }

    function register() external {
        require(!registered[msg.sender], "already");
        registered[msg.sender] = true;
        emit Registered(msg.sender);
    }

    // Gated ONLY by a cofinite denylist: every address the owner has not named
    // may call it, so the correspondence must not promote the event.
    function claim() external {
        require(!fromDenyList[msg.sender], "denied");
        claimed[msg.sender] = true;
        emit Claimed(msg.sender);
    }

    function useClaim() external view {
        require(claimed[msg.sender], "unclaimed");
    }

    // ``value`` is an unrelated amount riding along; the write is a flag set,
    // so the record proves NO value for the entry.
    function addWard(address usr, uint256 value) external onlyOwner {
        wards[usr] = true;
        emit WardAdded(usr, value);
    }

    function sweep() external view {
        require(wards[msg.sender], "not ward");
    }

    // One event, TWO entries written. A record can name only one of them.
    function transfer(address to, uint256 amount) external onlyOwner {
        require(balances[msg.sender] >= amount, "funds");
        balances[msg.sender] = balances[msg.sender] - amount;
        balances[to] = balances[to] + amount;
        emit Transfer(msg.sender, to, amount);
    }

    function updateExchangeRate(uint96 rate) external onlyOwner {
        uint96 old = accountantState.exchangeRate;
        accountantState.exchangeRate = rate;
        emit ExchangeRateUpdated(old, rate);
    }

    function setPayout(address payout) external onlyOwner {
        address old = accountantState.payoutAddress;
        accountantState.payoutAddress = payout;
        emit PayoutAddressUpdated(old, payout);
    }

    function claimFees() external view {
        require(msg.sender == accountantState.payoutAddress, "not payee");
    }

    function send(uint256 id) external view {
        require(gasLimits[id] > 0, "no chain");
    }

    function deposit(uint256 amount) external nonReentrant {
        require(!fromDenyList[msg.sender], "denied");
        emit Deposited(msg.sender, amount);
    }

    // Named ``locked``, but a real owner-gated withdrawal pause: set and never
    // restored inside the call.
    function pauseWithdrawals() external onlyOwner {
        locked = true;
        emit Locked(msg.sender);
    }

    function withdraw() external view {
        require(!locked, "paused");
    }

    // The mapping-typed old/new shape (live: LRTSquaredCore
    // TokenMaxPositionWeightLimitUpdated). Owner-gated, writes exactly one
    // slot, and the event states a transition — but it names no KEY, so the
    // pair is about one entry nobody can identify.
    function setTokenMaxWeight(address token, uint64 limit) external onlyOwner {
        uint64 old = _tokenInfos[token];
        _tokenInfos[token] = limit;
        emit TokenMaxWeightUpdated(old, limit);
    }

    function depositToken(address token, uint256 amount) external view {
        require(_tokenInfos[token] > 0, "not whitelisted");
        require(amount <= depositLimit, "cap");
    }

    // The SCALAR old/new shape (live: PriceProviderSet / RebalancerSet /
    // SwapperSet). Same emitter discipline, but the slot holds one value, so
    // the pair can only be about that value.
    function setDepositLimit(uint64 limit) external onlyOwner {
        uint64 old = depositLimit;
        depositLimit = limit;
        emit DepositLimitUpdated(old, limit);
    }
}
"""


def _topic0(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    project_dir = tmp_path_factory.mktemp("witness_corpus")
    source = project_dir / "WitnessCorpus.sol"
    source.write_text(textwrap.dedent(CORPUS_SOURCE).strip() + "\n")
    contract = next(c for c in Slither(str(source)).contracts if c.name == "WitnessCorpus")

    predicate_trees = build_predicate_artifacts(contract)
    effects = build_effects(contract)
    semantic_control = _build_semantic_control_summary(contract, project_dir, predicate_trees, effects)
    targets = build_controller_tracking(contract, project_dir, predicate_trees, effects, semantic_control)
    analysis = {
        "subject": {"address": "0x" + "11" * 20, "name": "WitnessCorpus"},
        "controller_tracking": targets,
    }
    plan = build_control_tracking_plan(analysis)  # pyright: ignore[reportArgumentType]
    specs = extract_governance_topics(dict(plan))
    planned = {tc["controller_id"] for tc in plan["tracked_controllers"]}
    polling = build_polling_plan(contract_type="regular", tracking_plan=plan, tracked_topics=specs)
    return {
        "contract": contract,
        "effects": effects,
        "targets": {target["controller_id"]: target for target in targets},
        "plan": plan,
        "planned": planned,
        "specs": {spec["topic0"]: spec for spec in specs},
        "polling": {entry["field"]: entry for entry in polling},
    }


def _spec(corpus, signature: str) -> dict:
    spec = corpus["specs"].get(_topic0(signature))
    assert spec is not None, f"{signature} produced no tracked-topic spec"
    return spec


# ---------------------------------------------------------------------------
# The corpus carries every shape (non-vacuity of everything below)
# ---------------------------------------------------------------------------


def test_every_spec_carries_the_taxonomy_fields(corpus):
    """Golden pin: tier and openness are on every derived spec, in the vocabulary; a spec
    without a tier would be classified at runtime from whatever the row carried."""
    assert corpus["specs"], "corpus produced no tracked-topic specs at all"
    for spec in corpus["specs"].values():
        assert spec["witness_tier"] in WITNESS_TIERS
        assert spec["writer_openness"] in OPENNESS_VALUES


def test_corpus_covers_all_five_degenerate_shapes(corpus):
    """Reads the tiers as a set so a corpus that lost a shape, or a change collapsing two
    tiers, fails here first."""
    tiers = {}
    for spec in corpus["specs"].values():
        tiers.setdefault(spec["witness_tier"], set()).add(spec["event_type"])

    # 5. canonical family, 4. DenyFrom-class qualified member change
    assert "ownership_transferred" in tiers[WITNESS_TIER_SELF_DESCRIBING]
    assert "member_changed:fromDenyList" in tiers[WITNESS_TIER_SELF_DESCRIBING]
    # 3. struct-member controller, readable through its parent getter
    assert "state_changed:state_variable:accountantState.payoutAddress" in tiers[WITNESS_TIER_HINT]
    # 2. open-writer mapping
    assert "state_changed:state_variable:registered" in tiers[WITNESS_TIER_ACTIVITY]
    # 1. reentrancy guard — no watched controller at all, asserted with its
    #    non-vacuity proof in test_reentrancy_latch_donates_nothing.
    assert "state_variable:_status" not in corpus["planned"]
    # 2b. the same open-writer shape gated by a cofinite DENYLIST rather than a
    #     business condition — the arm that keeps ERC-20 Transfers out.
    assert "state_changed:state_variable:claimed" in tiers[WITNESS_TIER_ACTIVITY]


# ---------------------------------------------------------------------------
# Shape 1 — reentrancy guard
# ---------------------------------------------------------------------------


def test_reentrancy_latch_donates_nothing(corpus):
    """``deposit`` writes ``_status`` and emits ``Deposited``. Before the hygiene filter every
    deposit was a ``state_changed:state_variable:_status`` publication (2 of 446 audited rows,
    unbounded on real traffic)."""
    writers = _state_writers_from_effects(corpus["effects"])
    assert "deposit(uint256)" in writers.get("_status", set()), "corpus lost the latch-write shape"

    # With no writer left the latch has no event watch or address-like read, so it never
    # reaches the plan; the ``Deposited`` topic it used to donate is watched by nothing.
    assert corpus["targets"]["state_variable:_status"]["associated_events"] == []
    assert corpus["targets"]["state_variable:_status"]["writer_functions"] == []
    assert "state_variable:_status" not in corpus["planned"]
    assert _topic0("Deposited(address,uint256)") not in corpus["specs"]


def test_a_var_named_locked_is_not_a_latch_without_the_ir_proof(corpus):
    """``bool public locked`` is an owner-gated withdrawal pause, set and never restored. Its
    NAME-fallback hygiene class is sound only as a suppressor; deleting a controller on it would
    make the name the witness and stop watching a real pause. Only the IR-proven set (written on
    both sides of a modifier's ``_;``) may subtract."""
    writers = _state_writers_from_effects(corpus["effects"])
    assert "pauseWithdrawals()" in writers.get("locked", set())

    assert "state_variable:locked" in corpus["planned"]
    assert _spec(corpus, "Locked(address)")["witness_tier"] == WITNESS_TIER_HINT
    assert "locked" in corpus["polling"]


# ---------------------------------------------------------------------------
# Shape 2 — open-writer mapping
# ---------------------------------------------------------------------------


def test_open_writer_mapping_stays_activity(corpus):
    """``register`` proves emit-write correspondence (``Registered(user)`` names the key) but
    its only gate is ``require(!registered[caller])``, a cofinite denylist admitting every
    unnamed address. Correspondence alone must not promote it, or every ERC-20 ``Transfer`` on
    a denylisted token republishes as a witnessed change."""
    spec = _spec(corpus, "Registered(address)")
    assert spec["witness_tier"] == WITNESS_TIER_ACTIVITY
    assert spec["writer_openness"] == "not_determined"
    assert spec["event_type"] == "state_changed:state_variable:registered"

    # Non-vacuity: the correspondence IS there — only the openness demoted it.
    events = corpus["targets"]["state_variable:registered"]["associated_events"]
    registered_event = next(e for e in events if e["signature"] == "Registered(address)")
    assert registered_event["member_witness"]["mapping_name"] == "registered"
    assert "writer_openness" not in registered_event


def test_a_denylist_gated_writer_is_not_a_restricted_one(corpus):
    """``claim`` proves correspondence but is gated only by ``require(!fromDenyList[msg.sender])``,
    a cofinite denylist. This is what the earned-public arm exists for; without it every
    ERC-20 ``Transfer`` on a denylisted token would qualify (P1b, 444 of 446 audited rows).
    """
    spec = _spec(corpus, "Claimed(address)")
    assert spec["witness_tier"] == WITNESS_TIER_ACTIVITY
    assert spec["writer_openness"] == "not_determined"

    events = corpus["targets"]["state_variable:claimed"]["associated_events"]
    claimed_event = next(e for e in events if e["signature"] == "Claimed(address)")
    assert claimed_event["member_witness"]["mapping_name"] == "claimed"
    assert "writer_openness" not in claimed_event


def test_a_two_entry_write_names_no_single_entry(corpus):
    """``transfer`` writes ``balances[from]`` and ``balances[to]`` under one ``Transfer``. Discovery
    keeps the first, leaving a record that names the sender and says nothing of the recipient,
    a false description rather than a partial one."""
    specs = discover_mapping_writer_events(corpus["contract"])
    assert any(
        spec["mapping_name"] == "balances" and spec["event_signature"] == "Transfer(address,address,uint256)"
        for spec in specs
    ), "corpus lost the multi-entry write shape"

    assert ("balances", "transfer(address,uint256)") in multi_entry_writers(corpus["contract"])
    records = member_witness_records(corpus["contract"])
    assert ("balances", "Transfer(address,address,uint256)") not in records
    # The single-entry writers on the same contract are untouched.
    assert ("fromDenyList", "DenyFrom(address)") in records


# ---------------------------------------------------------------------------
# Shape 3 — struct-member mismatch
# ---------------------------------------------------------------------------


def test_member_controller_drops_a_sibling_members_event(corpus):
    """``updateExchangeRate`` writes ``accountantState`` and so counted as a writer of
    ``accountantState.payoutAddress``; its keeper ``ExchangeRateUpdated`` traffic enrolled under
    the payout controller (75 specs on the live fleet) and would publish as a payout change."""
    writers = _state_writers_from_effects(corpus["effects"])
    assert "updateExchangeRate(uint96)" in writers.get("accountantState", set())

    payout = corpus["targets"]["state_variable:accountantState.payoutAddress"]
    signatures = {e["signature"] for e in payout["associated_events"]}
    assert signatures == {"PayoutAddressUpdated(address,address)"}
    assert _topic0("ExchangeRateUpdated(uint96,uint96)") not in corpus["specs"]


def test_member_controller_is_readable_through_its_parent_getter(corpus):
    """F8: the member is one word of ``accountantState()``'s return, so the controller has a
    verification read and its events become hints instead of bare activity."""
    spec = _spec(corpus, "PayoutAddressUpdated(address,address)")
    assert spec["witness_tier"] == WITNESS_TIER_HINT

    entry = corpus["polling"]["accountantState.payoutAddress"]
    assert entry["kind"] == "getter_call"
    assert entry["target"] == "accountantState"
    assert entry["member_word_index"] == 0
    # The verification-read binding is an identity on this stamp, not a name match.
    assert entry["source"] == "analyzer:state_variable:accountantState.payoutAddress"


# ---------------------------------------------------------------------------
# Shape 4 — DenyFrom-class qualified member change
# ---------------------------------------------------------------------------


def test_denyfrom_class_publishes_as_a_qualified_member_change(corpus):
    """Both facts proven: the event's arg is the written key, and every externally-callable
    path that emits it is caller-gated."""
    for signature, direction in (("DenyFrom(address)", "add"), ("AllowFrom(address)", "remove")):
        spec = _spec(corpus, signature)
        assert spec["witness_tier"] == WITNESS_TIER_SELF_DESCRIBING
        assert spec["writer_openness"] == "restricted"
        assert spec["event_type"] == "member_changed:fromDenyList"
        assert spec["member_witness"]["direction"] == direction
        assert spec["member_witness"]["key_position"] == 0
        # add/remove state no value; ``_value_writer_spec`` would have dropped these specs.
        assert spec["member_witness"]["value_position"] is None


def test_qualified_set_direction_carries_the_value_position(corpus):
    """``gasLimits[id] = limit; emit ChainSetGasLimit(id, limit)``: the event states the new
    value as well as the key, and the record says where."""
    spec = _spec(corpus, "ChainSetGasLimit(uint256,uint128)")
    assert spec["witness_tier"] == WITNESS_TIER_SELF_DESCRIBING
    assert spec["event_type"] == "member_changed:gasLimits"
    assert spec["member_witness"]["direction"] == "set"
    assert spec["member_witness"]["key_position"] == 0
    assert spec["member_witness"]["value_position"] == 1


def test_qualified_member_change_decodes_key_value_and_direction(corpus):
    """Runtime half of the vocabulary: the entry identity rides in ``data``, never the event type."""
    spec = _spec(corpus, "ChainSetGasLimit(uint256,uint128)")
    log = {
        "topics": [_topic0("ChainSetGasLimit(uint256,uint128)"), "0x" + "0" * 63 + "7"],
        "data": "0x" + "0" * 62 + "2a",
        "blockNumber": "0x64",
        "transactionHash": "0x" + "ab" * 32,
        "logIndex": "0x3",
    }
    parsed = parse_tracked_log(log, spec)
    assert parsed is not None
    assert parsed["event_type"] == "member_changed:gasLimits"
    assert parsed["key"] == 7
    assert parsed["value"] == 42
    assert parsed["direction"] == "set"
    assert "7" not in parsed["event_type"]


def test_a_flag_set_publishes_no_value_even_when_an_arg_is_named_value(corpus):
    """``WardAdded(address indexed usr, uint256 value)`` for ``wards[usr] = true``: the event
    states NO value for the entry, so an arg merely named ``value`` must not be published as one
    (on a ``member_changed`` row ``data.value`` is the witnessed new value, nothing else)."""
    spec = _spec(corpus, "WardAdded(address,uint256)")
    assert spec["event_type"] == "member_changed:wards"
    assert spec["member_witness"]["value_position"] is None

    ward = "0x" + "ef" * 20
    log = {
        "topics": [_topic0("WardAdded(address,uint256)"), "0x" + "0" * 24 + "ef" * 20],
        "data": "0x" + "0" * 62 + "09",
        "blockNumber": "0x64",
        "transactionHash": "0x" + "ab" * 32,
        "logIndex": "0x2",
    }
    parsed = parse_tracked_log(log, spec)
    assert parsed is not None
    assert parsed["key"] == ward
    assert parsed["direction"] == "add"
    assert "value" not in parsed


def test_add_remove_events_publish_no_value(corpus):
    """An ``add``/``remove`` event states which entry, not what it holds; a value would be invented."""
    spec = _spec(corpus, "DenyFrom(address)")
    denied = "0x" + "cd" * 20
    log = {
        "topics": [_topic0("DenyFrom(address)"), "0x" + "0" * 24 + "cd" * 20],
        "data": "0x",
        "blockNumber": "0x64",
        "transactionHash": "0x" + "ab" * 32,
        "logIndex": "0x1",
    }
    parsed = parse_tracked_log(log, spec)
    assert parsed is not None
    assert parsed["key"] == denied
    assert parsed["direction"] == "add"
    assert "value" not in parsed


# ---------------------------------------------------------------------------
# Shape 6 — write paths no attribution can see
#
# Each contract carries the SAME clean pair (owner-gated ``allow(user)`` writing ``gated[user]``
# and emitting ``Allowed(user)``, which qualifies alone). One open path writes storage the
# attribution never records, so the differential is the guard and nothing else.
# ---------------------------------------------------------------------------

_CLEAN_PAIR = """
    address public owner;
    mapping(address => bool) public gated;
    event Allowed(address indexed user);

    modifier onlyOwner() { require(msg.sender == owner, "no"); _; }

    function useGated() external view { require(gated[msg.sender], "x"); }

    function allow(address user) external onlyOwner {
        gated[user] = true;
        emit Allowed(user);
    }
"""

_OPAQUE_SOURCES = {
    # (a) Assembly-only writer, recorded against ``assembly_storage:<slot>``, so it is in NO
    #     mapping's writer set and intersecting with an attributed writer set can never catch it.
    "OpaqueAssembly": """
pragma solidity ^0.8.19;
contract OpaqueAssembly {
"""
    + _CLEAN_PAIR
    + """
    function anyoneAsm(address user) external {
        bytes32 slot = keccak256(abi.encode(user, uint256(1)));
        assembly { sstore(slot, 1) }
    }
}
""",
    # (b) Open arbitrary delegatecall: the callee writes THIS contract's storage and is not
    #     in this compilation unit.
    "OpaqueDelegatecall": """
pragma solidity ^0.8.19;
contract OpaqueDelegatecall {
"""
    + _CLEAN_PAIR
    + """
    function anyoneDc(address impl, bytes calldata data) external {
        (bool ok, ) = impl.delegatecall(data);
        require(ok, "dc");
    }
}
""",
    # (c) Library call through a STORAGE pointer: Slither attributes the write to neither
    #     function and ``all_state_variables_written()`` on the caller is empty.
    "OpaqueLibrary": """
pragma solidity ^0.8.19;
library MarkLib {
    function put(mapping(address => bool) storage m, address u) internal { m[u] = true; }
}
contract OpaqueLibrary {
"""
    + _CLEAN_PAIR
    + """
    mapping(address => bool) public sideMap;

    function anyoneLib(address user) external { MarkLib.put(sideMap, user); }
}
""",
    # The guard's NEGATIVE SPACE (Solady shape): the assembly writer is an internal helper
    # reached only from a gated entry point, so the clean pair still qualifies.
    # An ungated function emitting the qualified topic0 from an assembly LOG and writing
    # NOTHING is invisible to both openness quantifiers: no EventCall node, and no storage
    # touched.
    "OpaqueLogOnly": """
pragma solidity ^0.8.19;
contract OpaqueLogOnly {
"""
    + _CLEAN_PAIR
    + """
    function anyoneLog(address user) external {
        bytes32 topic = keccak256("Allowed(address)");
        bytes32 key = bytes32(uint256(uint160(user)));
        assembly { log2(0, 0, topic, key) }
    }
}
""",
    # Round-2 mixed style: a gated EventCall emitter and an open assembly emitter of the same
    # topic0, where the open one also WRITES.
    "OpaqueMixedEmitter": """
pragma solidity ^0.8.19;
contract OpaqueMixedEmitter {
"""
    + _CLEAN_PAIR
    + """
    function anyoneAlso(address user) external {
        gated[user] = true;
        bytes32 topic = keccak256("Allowed(address)");
        bytes32 key = bytes32(uint256(uint160(user)));
        assembly { log2(0, 0, topic, key) }
    }
}
""",
    # A latch var with an owner-controlled setter of the SAME variable: the modifier's
    # set-and-restore is transient, the setter's is real, so the controller stays in the plan.
    "LatchWithAdminSetter": """
pragma solidity ^0.8.19;
contract LatchWithAdminSetter {
"""
    + _CLEAN_PAIR
    + """
    uint256 private _status = 1;
    event StatusSet(uint256 value);

    modifier nonReentrant() { require(_status == 1, "r"); _status = 2; _; _status = 1; }

    function deposit() external nonReentrant {}

    function setStatus(uint256 value) external onlyOwner {
        _status = value;
        emit StatusSet(value);
    }
}
""",
    # Ordinary library use (no storage pointer) cannot write the caller's state.
    "PlainLibrary": """
pragma solidity ^0.8.19;
library MathLib {
    function max(uint256 a, uint256 b) internal pure returns (uint256) { return a > b ? a : b; }
}
contract PlainLibrary {
"""
    + _CLEAN_PAIR
    + """
    uint256 public floor;

    function anyoneMax(uint256 a) external { floor = MathLib.max(a, floor); }
}
""",
    "SoladyShaped": """
pragma solidity ^0.8.19;
contract SoladyShaped {
"""
    + _CLEAN_PAIR
    + """
    function _touch(address user) internal { assembly { sstore(user, 1) } }

    function adminTouch(address user) external onlyOwner { _touch(user); }
}
""",
}


@pytest.fixture(scope="module")
def opaque(tmp_path_factory):
    out = {}
    for name, source in _OPAQUE_SOURCES.items():
        project_dir = tmp_path_factory.mktemp(name.lower())
        path = project_dir / f"{name}.sol"
        path.write_text(textwrap.dedent(source).strip() + "\n")
        contract = next(c for c in Slither(str(path)).contracts if c.name == name)
        predicate_trees = build_predicate_artifacts(contract)
        effects = build_effects(contract)
        semantic_control = _build_semantic_control_summary(contract, project_dir, predicate_trees, effects)
        targets = build_controller_tracking(contract, project_dir, predicate_trees, effects, semantic_control)
        analysis = {
            "subject": {
                "address": "0x" + "22" * 20,
                "name": name,
                "compiler_version": "",
                "source_verified": True,
            },
            "controller_tracking": targets,
        }
        plan = build_control_tracking_plan(analysis)  # pyright: ignore[reportArgumentType]
        out[name] = {
            "contract": contract,
            "effects": effects,
            "targets": {target["controller_id"]: target for target in targets},
            "planned": {tc["controller_id"] for tc in plan["tracked_controllers"]},
            "specs": {spec["topic0"]: spec for spec in extract_governance_topics(dict(plan))},
        }
    return out


def _allowed(derived) -> dict:
    spec = derived["specs"].get(_topic0("Allowed(address)"))
    assert spec is not None, "the clean pair produced no spec at all"
    return spec


def test_the_clean_pair_qualifies_without_an_opaque_path(opaque):
    """The guard's negative space, and the baseline for the three demotions below.
    ``adminTouch`` reaches an internal assembly helper (Solady/OZ-v5 shape) but is owner-gated,
    so it does not survive subtracting the restricted functions."""
    derived = opaque["SoladyShaped"]
    # Non-vacuity: the assembly write really is there and really is opaque.
    assert derived["effects"]["functions"]["adminTouch(address)"]["assembly_state_access"] is True
    assert "adminTouch(address)" not in _state_writers_from_effects(derived["effects"]).get("gated", set())

    spec = _allowed(derived)
    assert spec["witness_tier"] == WITNESS_TIER_SELF_DESCRIBING
    assert spec["writer_openness"] == "restricted"
    assert spec["event_type"] == "member_changed:gated"


def test_an_assembly_only_writer_demotes_the_qualification(opaque):
    derived = opaque["OpaqueAssembly"]
    effects = derived["effects"]
    # Non-vacuity: present as an assembly writer, absent from every attributed writer set.
    assert effects["functions"]["anyoneAsm(address)"]["assembly_state_access"] is True
    writers = _state_writers_from_effects(effects)
    # Attributed to a raw SLOT, never a variable, so no variable-writer-set intersection can
    # catch it; hence the guard cannot be an intersection.
    assert "anyoneAsm(address)" in writers["assembly_storage:slot"]
    assert all("anyoneAsm(address)" not in fns for var, fns in writers.items() if not var.startswith("assembly_"))

    spec = _allowed(derived)
    assert spec["witness_tier"] == WITNESS_TIER_ACTIVITY
    assert spec["writer_openness"] == "not_determined"


def test_an_open_delegatecall_demotes_the_qualification(opaque):
    derived = opaque["OpaqueDelegatecall"]
    effects = derived["effects"]
    sinks = effects["functions"]["anyoneDc(address,bytes)"]["sinks"]
    assert any(sink["kind"] == "delegatecall" for sink in sinks)
    # The callee writes THIS contract's storage outside this compilation unit.
    assert all("anyoneDc(address,bytes)" not in fns for fns in _state_writers_from_effects(effects).values())

    spec = _allowed(derived)
    assert spec["witness_tier"] == WITNESS_TIER_ACTIVITY
    assert spec["writer_openness"] == "not_determined"


def test_a_library_storage_write_demotes_the_qualification(opaque):
    derived = opaque["OpaqueLibrary"]
    contract = derived["contract"]
    caller = next(fn for fn in contract.functions if fn.full_name == "anyoneLib(address)")
    # Non-vacuity: invisible to BOTH attribution routes (effects writer set, Slither accessor).
    assert list(caller.all_state_variables_written()) == []
    assert all("anyoneLib(address)" not in fns for fns in _state_writers_from_effects(derived["effects"]).values())
    callee = next(call.function for call in caller.all_library_calls())
    assert any(getattr(p, "location", None) == "storage" for p in callee.parameters)

    spec = _allowed(derived)
    assert spec["witness_tier"] == WITNESS_TIER_ACTIVITY
    assert spec["writer_openness"] == "not_determined"


def test_an_assembly_log_only_emitter_demotes_the_qualification(opaque):
    """The forging shape: ``anyoneLog`` emits the qualified topic0 from an assembly LOG and
    writes nothing, so it is in neither quantifier's domain. Without the log-opcode arm any
    address could mint a notified ``member_changed`` claim naming an entry of its choosing."""
    derived = opaque["OpaqueLogOnly"]
    effects = derived["effects"]
    # Non-vacuity: invisible to every other signal the qualification reads.
    assert effects["functions"]["anyoneLog(address)"]["assembly_state_access"] is False
    assert effects["functions"]["anyoneLog(address)"]["state_writes"] == []
    assert all("anyoneLog(address)" not in fns for fns in _state_writers_from_effects(effects).values())
    assert "anyoneLog(address)" in _assembly_log_functions(derived["contract"])

    spec = _allowed(derived)
    assert spec["witness_tier"] == WITNESS_TIER_ACTIVITY
    assert spec["writer_openness"] == "not_determined"


def test_a_mixed_style_emitter_demotes_the_qualification(opaque):
    """A gated ``EventCall`` emitter beside an open assembly emitter of the same topic0 that
    also writes. Two arms refuse it: the writers-side quantifier (tested on its own by the
    denylist-gated writer above) and the log-opcode arm."""
    derived = opaque["OpaqueMixedEmitter"]
    effects = derived["effects"]
    assert "anyoneAlso(address)" in _state_writers_from_effects(effects).get("gated", set())
    assert "anyoneAlso(address)" in _assembly_log_functions(derived["contract"])

    spec = _allowed(derived)
    assert spec["witness_tier"] == WITNESS_TIER_ACTIVITY
    assert spec["writer_openness"] == "not_determined"


def test_a_latch_var_keeps_its_admin_setter(opaque):
    """``hygiene_class`` is VARIABLE-granular: once ``_status`` is a proven latch every write of
    it is stamped, including an ``onlyOwner setStatus``. Subtracting on class alone deleted a
    real owner-controlled writer and silently dropped the controller (no watch, no poll). Only
    the modifier's own set-and-restore (``origin == "guard"``) is the write the proof covers."""
    derived = opaque["LatchWithAdminSetter"]
    facts = derived["effects"]["functions"]
    # Non-vacuity: BOTH writes carry the latch class; only origin tells them apart.
    guard_write = facts["deposit()"]["state_writes"][0]
    body_write = next(w for w in facts["setStatus(uint256)"]["state_writes"] if w["var"] == "_status")
    assert guard_write == {
        "var": "_status",
        "declared_type": "uint256",
        "member_path": [],
        "granularity": "var",
        "hygiene_class": "reentrancy_guard",
        "origin": "guard",
    }
    assert body_write["hygiene_class"] == "reentrancy_guard"
    assert body_write["origin"] == "body"

    latch = derived["targets"]["state_variable:_status"]
    assert [w["function"] for w in latch["writer_functions"]] == ["setStatus(uint256)"]
    assert [e["signature"] for e in latch["associated_events"]] == ["StatusSet(uint256)"]
    assert "state_variable:_status" in derived["planned"]
    assert _topic0("StatusSet(uint256)") in derived["specs"]


def test_ordinary_library_use_is_not_opaque(opaque):
    """A library taking no storage pointer cannot write the caller's state; Math/SafeERC20 use
    must leave the qualification alone, or the guard nullifies F3 on most real contracts."""
    from services.static.contract_analysis_pipeline.tracking import _library_storage_write_functions

    derived = opaque["PlainLibrary"]
    contract = derived["contract"]
    caller = next(fn for fn in contract.functions if fn.full_name == "anyoneMax(uint256)")
    # Non-vacuity: an UNGATED entry point really does call a library here.
    assert list(caller.all_library_calls())
    assert _library_storage_write_functions(contract) == frozenset()

    spec = _allowed(derived)
    assert spec["witness_tier"] == WITNESS_TIER_SELF_DESCRIBING
    assert spec["event_type"] == "member_changed:gated"


# ---------------------------------------------------------------------------
# Shape 5 — canonical family
# ---------------------------------------------------------------------------


def test_canonical_family_is_unchanged_by_qualification(corpus):
    """A Solmate ``OwnerUpdated`` keeps its family name; the member vocabulary never overwrites
    an already-earned semantic claim."""
    spec = _spec(corpus, "OwnerUpdated(address,address)")
    assert spec["event_type"] == "ownership_transferred"
    assert spec["witness_tier"] == WITNESS_TIER_SELF_DESCRIBING
    assert "member_witness" not in spec


# ---------------------------------------------------------------------------
# 6. Keyless old/new on a mapping — the P1c wrong-claim shape
# ---------------------------------------------------------------------------


def test_keyless_old_new_on_a_mapping_is_not_self_describing(corpus):
    """An old/new pair naming no key says ONE ENTRY moved, not the mapping.

    Publishing under ``state_changed:state_variable:_tokenInfos`` would put one entry's limit
    into ``last_known_state`` / ``ControllerValue`` as the whole mapping's value, and the
    ``member_changed`` guards downstream never fire. Live case: LRTSquaredCore's
    ``TokenMaxPositionWeightLimitUpdated``.
    """
    spec = _spec(corpus, "TokenMaxWeightUpdated(uint64,uint64)")

    # Non-vacuity: the emitter is a single-write RESTRICTED writer (so the writer is not doing
    # the demoting) and the ABI carries the old/new pair.
    target = corpus["targets"]["state_variable:_tokenInfos"]
    assert str((target.get("read_spec") or {}).get("type_kind")) == "mapping"
    assert spec["effect_tags"]["writes"] == ["_tokenInfos"]
    names = [i.get("name") for i in spec["inputs"]]
    assert names == ["oldLimit", "newLimit"]
    assert "function setTokenMaxWeight(address token, uint64 limit) external onlyOwner" in CORPUS_SOURCE
    # No key rides in the args, so no member witness saves it.
    assert "member_witness" not in spec

    assert spec["witness_tier"] != WITNESS_TIER_SELF_DESCRIBING
    assert not spec["event_type"].startswith("member_changed")


def test_the_same_pair_on_a_scalar_slot_still_qualifies(corpus):
    """The guard refuses the slot shape, not the old/new arm: over a slot holding ONE value the
    pair can only be about that value, so it still publishes. Live cases: LRTSquaredCore's
    PriceProviderSet / RebalancerSet / SwapperSet.
    """
    spec = _spec(corpus, "DepositLimitUpdated(uint64,uint64)")

    target = corpus["targets"]["state_variable:depositLimit"]
    assert str((target.get("read_spec") or {}).get("type_kind")) == "primitive"
    assert spec["effect_tags"]["writes"] == ["depositLimit"]
    assert [i.get("name") for i in spec["inputs"]] == ["oldLimit", "newLimit"]

    assert spec["witness_tier"] == WITNESS_TIER_SELF_DESCRIBING


def test_the_two_old_new_shapes_differ_only_in_the_slot(corpus):
    """The differential: same writer discipline, arg shape and attribution; only the slot's
    ``type_kind`` separates them, so neither test above passes for an unrelated reason."""
    mapping_spec = _spec(corpus, "TokenMaxWeightUpdated(uint64,uint64)")
    scalar_spec = _spec(corpus, "DepositLimitUpdated(uint64,uint64)")

    # Openness is the same on both, so it cannot be what separates them.
    assert mapping_spec["writer_openness"] == scalar_spec["writer_openness"]
    assert [i.get("name") for i in mapping_spec["inputs"]] == [i.get("name") for i in scalar_spec["inputs"]]
    assert len(mapping_spec["effect_tags"]["writes"]) == len(scalar_spec["effect_tags"]["writes"]) == 1
    assert mapping_spec["witness_tier"] != scalar_spec["witness_tier"]


# ---------------------------------------------------------------------------
# Self-service payout — the label corpus actually contains the shapes
# ---------------------------------------------------------------------------


def _label_golden_flow_rows():
    """Every (claim-witness flow entry, value_flows record) pair in the label golden, already
    proved equal to a live compile by the A/B gate."""
    from tests.support import label_corpus as label_harness

    golden = label_harness.load_golden()
    for contract in golden["contracts"]:
        for fn in contract["functions"]:
            witness_flows = [f for c in fn["claims"] for f in (c["witness"].get("flows") or []) if isinstance(f, dict)]
            yield contract["contract"], fn["full_name"], witness_flows, fn["value_flows"]


def test_the_label_corpus_contains_an_element_read_amount():
    """Non-vacuity for W1's amount half: A-fixtures asserting a W1 refusal ("A5 fails W1") only
    gate if the corpus holds an amount that IS an element read (a record cell selected by a
    caller-named key, member path resolved). Before SelfServicePayout the only
    bounded_by_storage amount refused at the root, so those assertions could pass vacuously."""
    element_reads = [
        vf
        for _c, _fn, _wf, value_flows in _label_golden_flow_rows()
        for vf in value_flows
        if vf.get("amount_record_variable") and vf.get("amount_record_member_path")
    ]
    assert element_reads, "no element-read amount anywhere in the label corpus"
    # ...and one is keyed by a whole caller argument (`bids[_bidId]`), with the ordering
    # witness beside it.
    assert any(
        vf.get("amount_record_key_kinds") == ["param"]
        and vf.get("amount_record_key_param_indexes") == [0]
        and isinstance(vf.get("record_ordering"), dict)
        for vf in element_reads
    )


def test_the_label_corpus_contains_a_caller_authority_element_guard():
    """Non-vacuity for W1's guard half: a witness proves the guard and amount name the SAME
    record with the caller's own membership (`owner_guarded_record`), and the full conjunction
    is exercised positively, so a producer that stops resolving the guard goes red rather than
    every refusal holding vacuously."""
    witness_entries = [f for _c, _fn, wf, _vf in _label_golden_flow_rows() for f in wf]
    constrained = [
        f["amount_record_constraint"]
        for f in witness_entries
        if (f.get("amount_record_constraint") or {}).get("state") == "constrained"
    ]
    assert constrained, "no proven W1 (amount_record_constraint) anywhere in the label corpus"
    assert any(v.get("basis") == "owner_guarded_record" for v in constrained)
    proven = [
        f["self_service_payout"]
        for f in witness_entries
        if (f.get("self_service_payout") or {}).get("state") == "proven_self_service"
    ]
    assert proven, "the full W1∧W2 conjunction is never exercised positively in the label corpus"
