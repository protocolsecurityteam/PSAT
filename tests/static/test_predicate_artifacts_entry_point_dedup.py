"""Regression gate for the iteration target of
``build_predicate_artifacts_with_pause_info``.

Slither's ``contract.functions`` yields one entry per ``(signature,
declaring_contract)``, so an overridden virtual function appears once for the
override AND once per shadowed base. The builder used to iterate it, ran
``build_predicate_tree`` on all, kept only the last write to ``trees[fn.full_name]``,
and wasted the base's CPU (PR-80, CumulativeMerkleDrop, Loki ``predicate_summary``:
``revokeRole`` base 77 s overwritten, derived 782 s kept).

The fix iterates ``contract.functions_entry_points`` (already deduplicated). Pins:
(1) with an override, the tree builder fires exactly once per externally-callable
``full_name``; (2) on a flat contract the entry-point surface matches
dedup-by-last-wins of ``contract.functions`` filtered by ``_is_externally_callable``
(the fix is a no-op there). If Slither changes ``functions_entry_points`` or the
target is swapped back, an assert breaks before a live test pays a 17-minute stage.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline import predicate_artifacts  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    _is_externally_callable,
    build_predicate_artifacts_with_pause_info,
)


def _compile(tmp_path: Path, source: str) -> Slither:
    """Match the helper in ``tests/static/test_predicate_builder.py``."""
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    return Slither(str(f))


def _select_contract(sl: Slither, name: str):
    return next(c for c in sl.contracts if c.name == name)


# OpenZeppelin AccessControl-shape: a base with virtual ``grantRole`` / ``revokeRole``
# and a derived that ``override``s both (the AccessControlDefaultAdminRules pattern
# that triggered the bug). Self-contained (no OZ import) so it runs offline.
ACCESS_CONTROL_SRC = """
pragma solidity ^0.8.20;

abstract contract AccessControlBase {
    mapping(bytes32 => mapping(address => bool)) internal _roles;
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    function _checkRole(bytes32 role) internal view {
        require(_roles[role][msg.sender], "missing role");
    }

    function _grantRole(bytes32 role, address account) internal virtual {
        _roles[role][account] = true;
    }

    function _revokeRole(bytes32 role, address account) internal virtual {
        _roles[role][account] = false;
    }

    function grantRole(bytes32 role, address account) public virtual {
        _checkRole(DEFAULT_ADMIN_ROLE);
        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) public virtual {
        _checkRole(DEFAULT_ADMIN_ROLE);
        _revokeRole(role, account);
    }
}

contract AccessControlDerived is AccessControlBase {
    function grantRole(bytes32 role, address account) public virtual override {
        require(account != address(0), "zero account");
        super.grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) public virtual override {
        require(account != address(0), "zero account");
        super.revokeRole(role, account);
    }
}
"""

# WETH9-shape flat contract — no inheritance, no overrides. The fix must
# be a no-op here: same iteration count, same output keys.
FLAT_SRC = """
pragma solidity ^0.8.20;

contract WETH9Like {
    mapping(address => uint256) public balanceOf;

    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
    }

    function withdraw(uint256 wad) public {
        require(balanceOf[msg.sender] >= wad, "insufficient");
        balanceOf[msg.sender] -= wad;
        payable(msg.sender).transfer(wad);
    }

    function transfer(address dst, uint256 wad) public returns (bool) {
        require(balanceOf[msg.sender] >= wad, "insufficient");
        balanceOf[msg.sender] -= wad;
        balanceOf[dst] += wad;
        return true;
    }
}
"""


def _no_op_pause_info() -> dict[str, list]:
    return {
        "pause_state_vars": [],
        "pause_toggle_functions": [],
        "reentrancy_state_vars": [],
        "reentrancy_guarded_functions": [],
    }


def test_overridden_functions_iterated_once_not_per_inheritance_depth(tmp_path):
    """With an override, the tree builder must fire exactly once per
    externally-callable ``full_name``.

    Pre-fix it fired ``inheritance_depth + 1`` times per overridden function. The
    eliminated iterations were the *faster* base versions (Slither orders inherited
    fns first), so the saving on CumulativeMerkleDrop was ~146 s, not the
    override's 782 s.
    """
    sl = _compile(tmp_path, ACCESS_CONTROL_SRC)
    derived = _select_contract(sl, "AccessControlDerived")

    # Sanity: Slither's ``functions`` *does* return duplicates here; without this a
    # future upstream fix would make the test vacuous.
    full_names_raw = [fn.full_name for fn in derived.functions if _is_externally_callable(fn)]
    duplicates = {n for n in full_names_raw if full_names_raw.count(n) > 1}
    assert duplicates, (
        "Slither's contract.functions no longer yields duplicates for overridden "
        "virtual functions on this version. The regression scenario this test "
        "guards against no longer reproduces — re-verify the bug premise before "
        "rewriting the assertion below."
    )

    invocations: list[str] = []

    def _counting_build_predicate_tree(fn: Any, **_kwargs: Any) -> Any:
        invocations.append(f"build:{fn.full_name}:{id(fn):#x}")
        return None

    def _counting_build_return_predicate_tree(fn: Any) -> Any:
        invocations.append(f"build_return:{fn.full_name}:{id(fn):#x}")
        return None

    with (
        patch.object(predicate_artifacts, "build_predicate_tree", _counting_build_predicate_tree),
        patch.object(predicate_artifacts, "build_return_predicate_tree", _counting_build_return_predicate_tree),
        patch.object(predicate_artifacts, "apply_writer_gate_pass", lambda c, t: None),
        patch.object(predicate_artifacts, "apply_mapping_event_hint_pass", lambda c, t: None),
        patch.object(predicate_artifacts, "apply_reentrancy_pause_pass", lambda c, t: _no_op_pause_info()),
    ):
        build_predicate_artifacts_with_pause_info(derived)

    build_calls = [inv for inv in invocations if inv.startswith("build:")]
    full_names_built = [call.split(":")[1] for call in build_calls]
    expected_entry_points = {"grantRole(bytes32,address)", "revokeRole(bytes32,address)"}

    assert set(full_names_built) == expected_entry_points, (
        f"unexpected externally-callable surface: built={set(full_names_built)} expected={expected_entry_points}"
    )
    assert len(full_names_built) == len(expected_entry_points), (
        f"build_predicate_tree was invoked {len(full_names_built)} times for "
        f"{len(expected_entry_points)} entry points — shadowed base copies are "
        f"being iterated again. Iteration target should be "
        f"contract.functions_entry_points, not contract.functions.\n"
        f"Full invocation list: {full_names_built}"
    )


def test_inherited_override_iteration_surface_matches_dedup_by_last_wins(tmp_path):
    """The fix relies on Slither emitting the *override* (not the base) in
    ``functions_entry_points``; a reversal would silently analyze the base, a
    correctness regression rather than a perf one."""
    sl = _compile(tmp_path, ACCESS_CONTROL_SRC)
    derived = _select_contract(sl, "AccessControlDerived")

    legacy_dedup: dict[str, Any] = {}
    for fn in derived.functions:
        if _is_externally_callable(fn):
            legacy_dedup[fn.full_name] = fn

    entry_points_by_name = {fn.full_name: fn for fn in derived.functions_entry_points if _is_externally_callable(fn)}

    assert set(legacy_dedup.keys()) == set(entry_points_by_name.keys())
    for full_name in entry_points_by_name:
        legacy_fn = legacy_dedup[full_name]
        entry_fn = entry_points_by_name[full_name]
        assert id(legacy_fn) == id(entry_fn), (
            f"Slither order changed: dedup-by-last-wins picks a different "
            f"Function object than functions_entry_points for {full_name}. "
            f"This means the fix would now analyze "
            f"declarer={legacy_fn.contract_declarer.name} via the legacy path "
            f"but declarer={entry_fn.contract_declarer.name} via the fix. "
            f"Verify which is the intended target before adjusting."
        )
        assert entry_fn.contract_declarer.name == "AccessControlDerived", (
            f"expected override on AccessControlDerived for {full_name}, got declarer={entry_fn.contract_declarer.name}"
        )
