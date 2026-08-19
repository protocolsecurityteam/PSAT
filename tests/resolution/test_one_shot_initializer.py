"""Real-Slither integration tests for the one-shot initializer projection.

Compiles minimal fixtures with the production Slither toolchain and drives the
real ``build_predicate_artifacts`` → evaluator → policy-surface stack (the same
calls the static worker and resolver make). Pins:

  * the A-spine: an OZ v4 ``initializer`` and an OZ v5 ERC-7201 ``initializer``
    both surface a ``one_shot`` condition kind and stamp a latch location;
  * the transient ``_initializing`` flag — the v5 struct member read through
    the real ``onlyInitializing``/``_isInitializing`` chain — keeps the badge
    role but never carries a latch location (it reads 0 at rest on consumed
    and live deployments alike, so a latch there can only mislead);
  * the structural recall net: a custom ``require(!initialized)`` bool latch is
    a one-shot CANDIDATE (carrying a latch), while a reentrancy guard and a
    capped counter are NOT — the counter/guard FP classes the candidate must
    exclude;
  * polarity: a re-armable toggle (``require(paused); paused = false``) never
    reads as a latch.

Hermetic: no live marker, no RPC. The on-chain consumed/live read is tested
separately (``test_one_shot_probe``) with a stubbed wire.
"""

from __future__ import annotations

import textwrap
from typing import Any

import pytest

slither = pytest.importorskip("slither")
from eth_utils.crypto import keccak  # noqa: E402
from slither import Slither  # noqa: E402

from services.policy.capability_surface import project_capability_surface  # noqa: E402
from services.resolution.capability_resolver import capability_to_dict  # noqa: E402
from services.resolution.one_shot_probe import collect_one_shot_latches  # noqa: E402
from services.resolution.predicate_evaluator import evaluate_tree  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
)
from tests.support.solc import solc_path_for as _solc_path_for  # noqa: E402

# Minimal OZ-style Initializable vendored so the fixtures need no remappings.
OZ_V4_INITIALIZABLE = """
abstract contract Initializable {
    uint8 private _initialized;
    bool private _initializing;
    modifier initializer() {
        bool isTopLevelCall = !_initializing;
        require(
            (isTopLevelCall && _initialized < 1) || (address(this).code.length == 0 && _initialized == 1),
            "Initializable: contract is already initialized"
        );
        _initialized = 1;
        if (isTopLevelCall) { _initializing = true; }
        _;
        if (isTopLevelCall) { _initializing = false; }
    }
}
"""

OZ_V5_INITIALIZABLE = """
abstract contract InitializableV5 {
    struct InitializableStorage { uint64 _initialized; bool _initializing; }
    bytes32 private constant INITIALIZABLE_STORAGE =
        0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;
    error InvalidInitialization();
    error NotInitializing();
    modifier initializer() {
        InitializableStorage storage $ = _getInitializableStorage();
        bool isTopLevelCall = !$._initializing;
        uint64 initialized = $._initialized;
        bool initialSetup = initialized == 0 && isTopLevelCall;
        bool construction = initialized == 1 && address(this).code.length == 0;
        if (!initialSetup && !construction) { revert InvalidInitialization(); }
        $._initialized = 1;
        if (isTopLevelCall) { $._initializing = true; }
        _;
        if (isTopLevelCall) { $._initializing = false; }
    }
    modifier onlyInitializing() {
        _checkInitializing();
        _;
    }
    function _checkInitializing() internal view {
        if (!_isInitializing()) { revert NotInitializing(); }
    }
    function _isInitializing() internal view returns (bool) {
        return _getInitializableStorage()._initializing;
    }
    function _getInitializableStorage() private pure returns (InitializableStorage storage $) {
        assembly { $.slot := INITIALIZABLE_STORAGE }
    }
}
"""

SOURCE = f"""
pragma solidity ^0.8.19;

{OZ_V4_INITIALIZABLE}
{OZ_V5_INITIALIZABLE}

contract OzV4 is Initializable {{
    address public manager;
    function initialize(address m) external initializer {{ manager = m; }}
}}

contract OzV5 is InitializableV5 {{
    address public manager;
    // the real OZ v5 call shape: initialize delegates to an internal
    // onlyInitializing helper, folding a transient `$._initializing` read
    // (through _isInitializing) into the entry point's tree
    function initialize(address m) external initializer {{ __bind_init(m); }}
    function __bind_init(address m) internal onlyInitializing {{ manager = m; }}
}}

contract Custom {{
    bool internal initialized;
    uint256 public depositCount;
    bool internal paused;
    uint256 internal _status;

    modifier nonReentrant() {{
        require(_status != 2, "reentrant");
        _status = 2;
        _;
        _status = 1;
    }}

    // custom one-shot: bool latch, self-written to the falsifying value
    function setup(address owner_) external {{
        require(!initialized, "done");
        initialized = true;
        require(owner_ != address(0), "zero");
    }}

    // capped counter — NOT a one-shot (write is +=, not a constant falsifier)
    function deposit() external {{
        require(depositCount < 100, "cap");
        depositCount += 1;
    }}

    // reentrancy-guarded permissionless fn — NOT a one-shot
    function swap() external nonReentrant {{ depositCount += 0; }}

    // re-armable toggle — NOT a latch (a setter restores the allow state)
    function unpause() external {{
        require(paused, "not paused");
        paused = false;
    }}
}}

// Aragon/Lido-style unstructured storage: the latch lives at a constant keccak
// slot read/written only through assembly helpers — the getter-link and
// modifier-anchor structural candidate paths.
library UnstructuredStorage {{
    function getStorageUint256(bytes32 position) internal view returns (uint256 data) {{
        assembly {{ data := sload(position) }}
    }}
    function setStorageUint256(bytes32 position, uint256 data) internal {{
        assembly {{ sstore(position, data) }}
    }}
}}

contract Unstructured {{
    using UnstructuredStorage for bytes32;
    bytes32 internal constant VERSION_POSITION = keccak256("fixture.version");

    function getContractVersion() public view returns (uint256) {{
        return VERSION_POSITION.getStorageUint256();
    }}

    modifier onlyInit() {{
        require(getContractVersion() == 0, "already");
        _;
    }}

    // getter-link candidate: guard reads getContractVersion()==0, body writes
    // the same constant slot via a mutating assembly helper.
    function initialize(address) external {{
        require(getContractVersion() == 0, "already");
        VERSION_POSITION.setStorageUint256(1);
    }}

    // modifier-anchored candidate: the require-bearing modifier reads the slot
    // the body then writes (the guard leaf saturates in folding).
    function initializeViaModifier(uint256 v) external onlyInit {{
        VERSION_POSITION.setStorageUint256(v + 1);
    }}
}}
"""


@pytest.fixture(scope="module")
def artifacts(tmp_path_factory) -> dict:
    solc = _solc_path_for((0, 8, 19))
    if solc is None:
        pytest.skip("no installed solc satisfies ^0.8.19")
    tmp = tmp_path_factory.mktemp("one_shot")
    source = tmp / "Fixtures.sol"
    source.write_text(textwrap.dedent(SOURCE).strip() + "\n")
    sl = Slither(str(source), solc=solc)
    out = {}
    for name in ("OzV4", "OzV5", "Custom", "Unstructured"):
        contract = next(c for c in sl.contracts if c.name == name)
        out[name] = build_predicate_artifacts(contract)
    return out


def _surface_condition_kinds(tree: Any) -> set[str]:
    cap = evaluate_tree(tree)
    cap_dict = capability_to_dict(cap)
    surface = project_capability_surface(cap_dict)
    return {kind for c in surface.conditions if isinstance((kind := c.get("kind")), str)}


def _fn_tree(artifact: dict, fn_name: str) -> dict:
    trees = artifact.get("trees") or {}
    matches = [tree for full, tree in trees.items() if full.split("(", 1)[0] == fn_name]
    assert len(matches) == 1, f"expected one {fn_name}, got {list(trees)}"
    return matches[0]


def test_oz_v4_initializer_surfaces_one_shot(artifacts):
    tree = _fn_tree(artifacts["OzV4"], "initialize")
    assert "one_shot" in _surface_condition_kinds(tree)
    latches = collect_one_shot_latches(tree)
    assert latches["standard"], "OZ v4 initializer should stamp a standard latch"
    latch = latches["standard"][0]
    assert latch["standard"] == "storage_layout"
    assert latch["slot"] == "0x" + "0" * 64  # _initialized packed at slot 0
    assert latch["expected_version"] == 1
    assert latch["role"] == "version"  # the resolver's decide-invariant anchor


def test_oz_v5_namespaced_initializer_surfaces_one_shot(artifacts):
    """OZ v5 ERC-7201: the latch lives at the fixed namespaced slot, decoded by
    the struct member byte range — NOT slot-0."""
    tree = _fn_tree(artifacts["OzV5"], "initialize")
    assert "one_shot" in _surface_condition_kinds(tree)
    latch = collect_one_shot_latches(tree)["standard"][0]
    assert latch["standard"] == "oz_v5_namespaced"
    # ERC-7201 InitializableStorage slot (validated against canonical preimage
    # in test_one_shot_probe::test_erc7201_slot_matches_canonical_derivation).
    assert latch["slot"] == "0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00"
    assert latch["byte_offset"] == 0 and latch["size_bytes"] == 8  # uint64 _initialized
    assert latch["role"] == "version"  # the resolver's decide-invariant anchor


def test_oz_v5_transient_initializing_member_carries_no_latch(artifacts):
    """The ERC-7201 transient ``_initializing`` member — folded into the entry
    point's tree through the real OZ v5 ``onlyInitializing`` →
    ``_isInitializing`` chain — keeps the ``one_shot`` badge role but must
    carry NO latch location, and nothing collected for resolution may target
    its byte range: at rest the flag reads 0 on consumed and live deployments
    alike, so a latch there reads an initialized proxy as armed."""
    tree = _fn_tree(artifacts["OzV5"], "initialize")
    transient_leaves: list[dict] = []

    def walk(node: Any) -> None:
        if node.get("op") == "LEAF":
            leaf = node.get("leaf") or {}
            members = {
                (op.get("member_path") or [None])[0]
                for op in leaf.get("operands") or []
                if op.get("source") == "state_variable"
            }
            if "_initializing" in members:
                transient_leaves.append(leaf)
            return
        for child in node.get("children") or []:
            walk(child)

    walk(tree)
    assert transient_leaves, "fixture must fold an _initializing read into the tree"
    assert all(leaf.get("authority_role") == "one_shot" for leaf in transient_leaves), "badge role must survive"
    assert all("one_shot_latch" not in leaf for leaf in transient_leaves), "transient member must carry no latch"
    collected = collect_one_shot_latches(tree)["standard"]
    assert collected, "the version member must still stamp a readable latch"
    assert all((latch["byte_offset"], latch["size_bytes"]) == (0, 8) for latch in collected)


def test_custom_bool_latch_is_candidate_not_standard(artifacts):
    """A bool ``require(!initialized); initialized = true`` with NO OZ modifier
    is a structural candidate (carries a latch) but is not stamped role
    one_shot — only the on-chain read may promote it."""
    tree = _fn_tree(artifacts["Custom"], "setup")
    latches = collect_one_shot_latches(tree)
    assert not latches["standard"], "custom latch must not be an A-spine standard"
    assert latches["candidate"], "custom bool latch should be a candidate"
    assert latches["candidate"][0]["standard"] == "structural_scalar_latch"
    # Candidates decide via their guard, never via the version anchor.
    assert "role" not in latches["candidate"][0]
    # Static badge stays generic — no one_shot CONDITION until confirmed.
    assert "one_shot" not in _surface_condition_kinds(tree)


def test_capped_counter_is_not_a_one_shot(artifacts):
    """``require(depositCount < 100); depositCount += 1`` must NOT be flagged —
    the write is not a constant that permanently falsifies the guard."""
    tree = _fn_tree(artifacts["Custom"], "deposit")
    latches = collect_one_shot_latches(tree)
    assert not latches["standard"] and not latches["candidate"]


def test_reentrancy_guard_is_not_a_one_shot(artifacts):
    tree = _fn_tree(artifacts["Custom"], "swap")
    latches = collect_one_shot_latches(tree)
    assert not latches["standard"] and not latches["candidate"]
    # It keeps its reentrancy classification.
    assert "reentrancy" in _surface_condition_kinds(tree)


def test_rearmable_toggle_is_not_a_latch(artifacts):
    """``require(paused); paused = false`` — a setter re-arms it, so it is not a
    consuming one-shot (the monotonic-ascent requirement)."""
    tree = _fn_tree(artifacts["Custom"], "unpause")
    latches = collect_one_shot_latches(tree)
    assert not latches["standard"] and not latches["candidate"]


def test_unstructured_storage_getter_link_candidate(artifacts):
    """Lido/Aragon unstructured-storage one-shot: the guard reads a nullary view
    that loads a constant slot, and the body writes that same slot via assembly —
    a getter-linked structural candidate."""
    tree = _fn_tree(artifacts["Unstructured"], "initialize")
    latches = collect_one_shot_latches(tree)
    assert latches["candidate"], "unstructured-storage init should be a candidate"
    latch = latches["candidate"][0]
    assert latch["standard"] == "unstructured_slot_latch"
    # The slot is the keccak constant, not slot-0.
    assert latch["slot"] == "0x" + keccak(text="fixture.version").hex()


def test_unstructured_storage_modifier_anchor_candidate(artifacts):
    """When the guard leaf saturates in folding, a require-bearing modifier that
    reads exactly the constant slot the body writes anchors the candidate on the
    tree root."""
    trees = artifacts["Unstructured"].get("trees") or {}
    matches = [t for full, t in trees.items() if full.split("(", 1)[0] == "initializeViaModifier"]
    assert len(matches) == 1
    latches = collect_one_shot_latches(matches[0])
    assert latches["candidate"], "modifier-anchored init should be a candidate"
    assert latches["candidate"][0]["standard"] == "unstructured_slot_latch"
