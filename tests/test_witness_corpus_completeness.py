"""Corpus completeness for the witness taxonomy (spec Part 6, G3 artifact).

A zero-diff on golden fixtures proves nothing unless the corpus actually
CONTAINS the shapes the taxonomy exists to separate. This module compiles one
contract carrying all five degenerate shapes, derives the real tracking plan
from it, and pins the ``witness_tier`` each shape earns:

  1. reentrancy guard      — a latch written and restored in one call
  2. open-writer mapping   — self-registration behind a denylist gate
  3. struct-member mismatch — a sibling member's event under a member controller
  4. DenyFrom-class        — a proven correspondence from a restricted writer
  5. canonical family      — an event whose own signature corroborates it

Every assertion is paired with a NON-VACUITY assertion: the shape's raw
ingredient (the guard write, the sibling writer, the topic) is shown to be
present in the corpus, so an assertion that something is absent cannot pass
because the corpus never had it.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest
from eth_utils.crypto import keccak

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.monitoring.event_topics import (  # noqa: E402
    WITNESS_TIER_ACTIVITY,
    WITNESS_TIER_HINT,
    WITNESS_TIER_SELF_DESCRIBING,
    WITNESS_TIERS,
    WRITER_OPENNESS_VALUES,
    extract_governance_topics,
    parse_tracked_log,
)
from services.monitoring.polling_plan import build_polling_plan  # noqa: E402
from services.resolution.tracking_plan import build_control_tracking_plan  # noqa: E402
from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
)
from services.static.contract_analysis_pipeline.summaries import (  # noqa: E402
    _build_semantic_control_summary,
)
from services.static.contract_analysis_pipeline.tracking import (  # noqa: E402
    _state_writers_from_effects,
    build_controller_tracking,
)

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
    mapping(uint256 => uint128) public gasLimits;
    uint256 private locked = 1;

    event OwnerUpdated(address indexed user, address indexed newOwner);
    event DenyFrom(address indexed user);
    event AllowFrom(address indexed user);
    event Registered(address indexed user);
    event ExchangeRateUpdated(uint96 oldRate, uint96 newRate);
    event PayoutAddressUpdated(address oldPayout, address newPayout);
    event ChainSetGasLimit(uint256 indexed id, uint128 limit);
    event Deposited(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier nonReentrant() {
        require(locked == 1, "reentrant");
        locked = 2;
        _;
        locked = 1;
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

    function claimFees() external {
        require(msg.sender == accountantState.payoutAddress, "not payee");
    }

    function send(uint256 id) external view {
        require(gasLimits[id] > 0, "no chain");
    }

    function deposit(uint256 amount) external nonReentrant {
        require(!fromDenyList[msg.sender], "denied");
        emit Deposited(msg.sender, amount);
    }
}
"""


def _topic0(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    """The derived plan for the corpus contract: targets, plan, specs, polling."""
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
    plan = build_control_tracking_plan(analysis)  # type: ignore[arg-type]
    specs = extract_governance_topics(plan)
    planned = {tc["controller_id"] for tc in plan["tracked_controllers"]}
    polling = build_polling_plan(contract_type="regular", tracking_plan=plan, tracked_topics=specs)
    return {
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
    """Golden pin: the tier and the openness are on every derived spec, in the
    vocabulary. A spec without a tier would be classified at runtime from
    whatever the row happened to carry."""
    assert corpus["specs"], "corpus produced no tracked-topic specs at all"
    for spec in corpus["specs"].values():
        assert spec["witness_tier"] in WITNESS_TIERS
        assert spec["writer_openness"] in WRITER_OPENNESS_VALUES


def test_corpus_covers_all_five_degenerate_shapes(corpus):
    """The differential below is only meaningful if each shape is present. This
    reads the tiers as a set so a corpus that silently lost a shape — or a
    change that collapsed two tiers into one — fails here first."""
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
    assert "state_variable:locked" not in corpus["planned"]


# ---------------------------------------------------------------------------
# Shape 1 — reentrancy guard
# ---------------------------------------------------------------------------


def test_reentrancy_latch_donates_nothing(corpus):
    """``deposit`` writes ``locked`` and emits ``Deposited``. Before the hygiene
    filter that made every deposit a ``state_changed:state_variable:locked``
    publication — 2 of the 446 audited rows, and unbounded on real traffic."""
    writers = _state_writers_from_effects(corpus["effects"])
    assert "deposit(uint256)" in writers.get("locked", set()), "corpus lost the latch-write shape"

    # With no writer left, the latch has no event watch and no address-like
    # read, so it is not a runtime-resolvable controller and never reaches the
    # plan — the ``Deposited`` topic it used to donate is watched by nothing.
    assert corpus["targets"]["state_variable:locked"]["associated_events"] == []
    assert corpus["targets"]["state_variable:locked"]["writer_functions"] == []
    assert "state_variable:locked" not in corpus["planned"]
    assert _topic0("Deposited(address,uint256)") not in corpus["specs"]


# ---------------------------------------------------------------------------
# Shape 2 — open-writer mapping
# ---------------------------------------------------------------------------


def test_open_writer_mapping_stays_activity(corpus):
    """``register`` proves emit-write correspondence — ``Registered(user)``
    names the key it wrote — but its only gate is ``require(!registered[caller])``,
    a cofinite denylist that admits every address it has not named. The
    correspondence alone must not promote it, or every ERC-20 ``Transfer`` on a
    token with a denylist republishes as a witnessed change."""
    spec = _spec(corpus, "Registered(address)")
    assert spec["witness_tier"] == WITNESS_TIER_ACTIVITY
    assert spec["writer_openness"] == "not_determined"
    assert spec["event_type"] == "state_changed:state_variable:registered"

    # Non-vacuity: the correspondence IS there — only the openness demoted it.
    events = corpus["targets"]["state_variable:registered"]["associated_events"]
    registered_event = next(e for e in events if e["signature"] == "Registered(address)")
    assert registered_event["member_witness"]["mapping_name"] == "registered"
    assert "writer_openness" not in registered_event


# ---------------------------------------------------------------------------
# Shape 3 — struct-member mismatch
# ---------------------------------------------------------------------------


def test_member_controller_drops_a_sibling_members_event(corpus):
    """``updateExchangeRate`` writes ``accountantState`` and was therefore a
    writer of ``accountantState.payoutAddress``; its ``ExchangeRateUpdated``
    keeper traffic enrolled under the payout controller (75 specs on the live
    fleet) and would have published as a payout-address change."""
    writers = _state_writers_from_effects(corpus["effects"])
    assert "updateExchangeRate(uint96)" in writers.get("accountantState", set())

    signatures = {e["signature"] for e in corpus["targets"]["state_variable:accountantState.payoutAddress"]["associated_events"]}
    assert signatures == {"PayoutAddressUpdated(address,address)"}
    assert _topic0("ExchangeRateUpdated(uint96,uint96)") not in corpus["specs"]


def test_member_controller_is_readable_through_its_parent_getter(corpus):
    """F8: the member is one word of ``accountantState()``'s return, so the
    controller has a verification read and its events become hints instead of
    bare activity."""
    spec = _spec(corpus, "PayoutAddressUpdated(address,address)")
    assert spec["witness_tier"] == WITNESS_TIER_HINT

    entry = corpus["polling"]["accountantState.payoutAddress"]
    assert entry["kind"] == "getter_call"
    assert entry["target"] == "accountantState"
    assert entry["member_word_index"] == 0
    # The verification-read binding is an identity on this stamp, not a name
    # match — an entry without it is unreachable from the hint path.
    assert entry["source"] == "analyzer:state_variable:accountantState.payoutAddress"


# ---------------------------------------------------------------------------
# Shape 4 — DenyFrom-class qualified member change
# ---------------------------------------------------------------------------


def test_denyfrom_class_publishes_as_a_qualified_member_change(corpus):
    """Both facts proven: the event's arg is the written key, and every
    externally-callable path that emits it is caller-gated."""
    for signature, direction in (("DenyFrom(address)", "add"), ("AllowFrom(address)", "remove")):
        spec = _spec(corpus, signature)
        assert spec["witness_tier"] == WITNESS_TIER_SELF_DESCRIBING
        assert spec["writer_openness"] == "restricted"
        assert spec["event_type"] == "member_changed:fromDenyList"
        assert spec["member_witness"]["direction"] == direction
        assert spec["member_witness"]["key_position"] == 0
        # add/remove state no value; ``_value_writer_spec`` would have dropped
        # these specs entirely for exactly that reason.
        assert spec["member_witness"]["value_position"] is None


def test_qualified_set_direction_carries_the_value_position(corpus):
    """``gasLimits[id] = limit; emit ChainSetGasLimit(id, limit)`` — the event
    states the new value as well as the key, and the record says where."""
    spec = _spec(corpus, "ChainSetGasLimit(uint256,uint128)")
    assert spec["witness_tier"] == WITNESS_TIER_SELF_DESCRIBING
    assert spec["event_type"] == "member_changed:gasLimits"
    assert spec["member_witness"]["direction"] == "set"
    assert spec["member_witness"]["key_position"] == 0
    assert spec["member_witness"]["value_position"] == 1


def test_qualified_member_change_decodes_key_value_and_direction(corpus):
    """The runtime half of the vocabulary: the entry identity rides in ``data``,
    never in the event type."""
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


def test_add_remove_events_publish_no_value(corpus):
    """An ``add``/``remove`` event states which entry, not what it now holds.
    Publishing a value there would be inventing one."""
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
# Shape 5 — canonical family
# ---------------------------------------------------------------------------


def test_canonical_family_is_unchanged_by_qualification(corpus):
    """A Solmate-shaped ``OwnerUpdated`` classifies from its own signature and
    keeps its family name — the member vocabulary never overwrites a semantic
    claim that was already earned."""
    spec = _spec(corpus, "OwnerUpdated(address,address)")
    assert spec["event_type"] == "ownership_transferred"
    assert spec["witness_tier"] == WITNESS_TIER_SELF_DESCRIBING
    assert "member_witness" not in spec
