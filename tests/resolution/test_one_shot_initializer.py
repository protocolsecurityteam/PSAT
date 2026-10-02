"""Real-Slither integration for the one-shot initializer projection.

OZ v4 and v5 ``initializer`` both surface ``one_shot`` with a latch location; the transient ``_initializing`` flag
never gets one (it reads 0 at rest on consumed and live deployments). A custom ``require(!initialized)`` is a
candidate, while reentrancy guards, capped counters and re-armable toggles are not latches. The on-chain read is
in ``test_one_shot_probe``.
"""

from __future__ import annotations

import textwrap
from typing import Any

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.policy.capability_surface import project_capability_surface  # noqa: E402
from services.resolution.capability_resolver import capability_to_dict  # noqa: E402
from services.resolution.one_shot_probe import collect_one_shot_latches  # noqa: E402
from services.resolution.predicate_evaluator import evaluate_tree  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
)
from tests.support.solc import solc_path_for as _solc_path_for  # noqa: E402

pytestmark = pytest.mark.compile

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


def test_custom_bool_latch_is_candidate_not_standard(artifacts):
    """Only the on-chain read may promote it."""
    tree = _fn_tree(artifacts["Custom"], "setup")
    latches = collect_one_shot_latches(tree)
    assert not latches["standard"], "custom latch must not be an A-spine standard"
    assert latches["candidate"], "custom bool latch should be a candidate"
    assert latches["candidate"][0]["standard"] == "structural_scalar_latch"
    assert "role" not in latches["candidate"][0]
    assert "one_shot" not in _surface_condition_kinds(tree)
