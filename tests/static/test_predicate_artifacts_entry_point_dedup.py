"""``contract.functions`` yields an overridden function once per shadowed base, and the builder kept only the last
tree (CumulativeMerkleDrop: ``revokeRole`` base 77 s wasted). ``functions_entry_points`` is already deduplicated;
this breaks before a live test pays a 17-minute stage.
"""

from __future__ import annotations

from typing import Any

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    _is_externally_callable,
)
from tests.support.slither_compile import _compile  # noqa: E402


def _select_contract(sl: Slither, name: str):
    return next(c for c in sl.contracts if c.name == name)


# The AccessControlDefaultAdminRules pattern, self-contained so it runs offline.
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


def test_inherited_override_iteration_surface_matches_dedup_by_last_wins(tmp_path):
    """A reversal would silently analyze the base."""
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
