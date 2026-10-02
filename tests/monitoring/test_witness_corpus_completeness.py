"""Corpus completeness for the witness taxonomy.

One contract carries all five; each assertion is paired with a non-vacuity check.
"""

from __future__ import annotations

import textwrap

import pytest
from eth_utils.crypto import keccak

pytest.importorskip("slither")
from slither import Slither

from services.monitoring.event_topics import (
    WITNESS_TIER_ACTIVITY,
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


def test_every_spec_carries_the_taxonomy_fields(corpus):
    """A tierless spec would be classified at runtime from whatever the row carried."""
    assert corpus["specs"], "corpus produced no tracked-topic specs at all"
    for spec in corpus["specs"].values():
        assert spec["witness_tier"] in WITNESS_TIERS
        assert spec["writer_openness"] in OPENNESS_VALUES


def test_a_two_entry_write_names_no_single_entry(corpus):
    """Keeping only the first entry would describe the transfer falsely, not partially."""
    specs = discover_mapping_writer_events(corpus["contract"])
    assert any(
        spec["mapping_name"] == "balances" and spec["event_signature"] == "Transfer(address,address,uint256)"
        for spec in specs
    ), "corpus lost the multi-entry write shape"

    assert ("balances", "transfer(address,uint256)") in multi_entry_writers(corpus["contract"])
    records = member_witness_records(corpus["contract"])
    assert ("balances", "Transfer(address,address,uint256)") not in records
    assert ("fromDenyList", "DenyFrom(address)") in records


def test_qualified_member_change_decodes_key_value_and_direction(corpus):
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


# An add/remove event states which entry, not what it holds; an arg merely named ``value`` isn't one.
@pytest.mark.parametrize(
    ("signature", "event_type", "key_byte", "data", "log_index"),
    [
        pytest.param(
            "WardAdded(address,uint256)",
            "member_changed:wards",
            "ef",
            "0x" + "0" * 62 + "09",
            "0x2",
            id="flag-set-with-arg-named-value",
        ),
        pytest.param("DenyFrom(address)", "member_changed:fromDenyList", "cd", "0x", "0x1", id="add-remove"),
    ],
)
def test_add_remove_events_publish_no_value(corpus, signature, event_type, key_byte, data, log_index):
    spec = _spec(corpus, signature)
    assert spec["event_type"] == event_type
    assert spec["member_witness"]["value_position"] is None

    log = {
        "topics": [_topic0(signature), "0x" + "0" * 24 + key_byte * 20],
        "data": data,
        "blockNumber": "0x64",
        "transactionHash": "0x" + "ab" * 32,
        "logIndex": log_index,
    }
    parsed = parse_tracked_log(log, spec)
    assert parsed is not None
    assert parsed["key"] == "0x" + key_byte * 20
    assert parsed["direction"] == "add"
    assert "value" not in parsed


# Each contract carries the same qualifying clean pair plus one open path writing storage the attribution never records.

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
    # Recorded against a raw slot, so no variable-writer intersection can catch it.
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
    # Slither attributes the write to neither function.
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
    # Negative space: an assembly helper reached only from a gated entry point. The log-only function writes nothing and
    # has no EventCall node.
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
    # The modifier's set-and-restore is transient; the setter's is real.
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
    """``adminTouch`` reaches an assembly helper but is owner-gated."""
    derived = opaque["SoladyShaped"]
    assert derived["effects"]["functions"]["adminTouch(address)"]["assembly_state_access"] is True
    assert "adminTouch(address)" not in _state_writers_from_effects(derived["effects"]).get("gated", set())

    spec = _allowed(derived)
    assert spec["witness_tier"] == WITNESS_TIER_SELF_DESCRIBING
    assert spec["writer_openness"] == "restricted"
    assert spec["event_type"] == "member_changed:gated"


def test_a_mixed_style_emitter_demotes_the_qualification(opaque):
    derived = opaque["OpaqueMixedEmitter"]
    effects = derived["effects"]
    assert "anyoneAlso(address)" in _state_writers_from_effects(effects).get("gated", set())
    assert "anyoneAlso(address)" in _assembly_log_functions(derived["contract"])

    spec = _allowed(derived)
    assert spec["witness_tier"] == WITNESS_TIER_ACTIVITY
    assert spec["writer_openness"] == "not_determined"


def test_ordinary_library_use_is_not_opaque(opaque):
    """Otherwise the guard nullifies F3 on most real contracts."""
    from services.static.contract_analysis_pipeline.tracking import _library_storage_write_functions

    derived = opaque["PlainLibrary"]
    contract = derived["contract"]
    caller = next(fn for fn in contract.functions if fn.full_name == "anyoneMax(uint256)")
    assert list(caller.all_library_calls())
    assert _library_storage_write_functions(contract) == frozenset()

    spec = _allowed(derived)
    assert spec["witness_tier"] == WITNESS_TIER_SELF_DESCRIBING
    assert spec["event_type"] == "member_changed:gated"


def _label_golden_flow_rows():
    from tests.support import label_corpus as label_harness

    golden = label_harness.load_golden()
    for contract in golden["contracts"]:
        for fn in contract["functions"]:
            witness_flows = [f for c in fn["claims"] for f in (c["witness"].get("flows") or []) if isinstance(f, dict)]
            yield contract["contract"], fn["full_name"], witness_flows, fn["value_flows"]


def test_the_label_corpus_contains_an_element_read_amount():
    """W1 refusal fixtures only gate if the corpus holds a real element-read amount."""
    element_reads = [
        vf
        for _c, _fn, _wf, value_flows in _label_golden_flow_rows()
        for vf in value_flows
        if vf.get("amount_record_variable") and vf.get("amount_record_member_path")
    ]
    assert element_reads, "no element-read amount anywhere in the label corpus"
    assert any(
        vf.get("amount_record_key_kinds") == ["param"]
        and vf.get("amount_record_key_param_indexes") == [0]
        and isinstance(vf.get("record_ordering"), dict)
        for vf in element_reads
    )


def test_the_label_corpus_contains_a_caller_authority_element_guard():
    """A producer that stops resolving the guard must go red rather than every refusal holding vacuously."""
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
