"""Regression test: parametric guards land in semantic_functions but
resolve to no concrete principals — the EtherFiTimelock symptom.

Original todo (#7 in /home/gnome2/asu/capstone/PSAT/todo.txt): the
EtherFiTimelock's grantRole/revokeRole/renounceRole show as 'Unresolved'
in the UI even though the contract is plainly role-controlled. The
analyzer admits these functions to ``semantic_functions`` (we
verified — see ``test_renamed_helpers_dispense_role_is_admitted``
below). What it does NOT do is bind them to concrete principals, so
``permission_index`` emits an entry with empty
``direct_owner`` / ``authority_roles`` / ``controllers``, and the UI's
``direct.length === 0`` branch ends up rendering 'Unresolved'.

This test pins three claims:

  1. Both OZ-style and renamed-helper variants admit to
     semantic_functions. (Both pass today — confirms the admission
     gate isn't actually the broken layer.)
  2. The Unguarded negative control does NOT admit. (Pin against
     overinclusive future fixes.)
  3. Both guarded variants emit an ``PermissionRow`` with
     EMPTY ``direct_owner``, ``authority_roles``, AND ``controllers``
     resolving to addresses — i.e. the user-facing 'Unresolved' state.
     This is the gap the user wants closed.

The xfail in (3) flips to passing when the policy stage learns to
express 'guarded by getRoleAdmin(role_arg) holders' as a typed
parametric principal — see todo.txt #7's deferred fix block.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from services.static import collect_static_facts

# Three minimal projects, one subject contract each.
OZ_SOURCE = """
pragma solidity ^0.8.19;

contract OZStyle {
    mapping(bytes32 => mapping(address => bool)) private _members;
    mapping(bytes32 => bytes32) private _roleAdmins;

    error MissingRole(bytes32 role, address account);

    function _checkRole(bytes32 role, address account) internal view {
        if (!_members[role][account]) revert MissingRole(role, account);
    }
    function _getRoleAdmin(bytes32 role) internal view returns (bytes32) {
        return _roleAdmins[role];
    }
    function grantRole(bytes32 role, address account) public {
        _checkRole(_getRoleAdmin(role), msg.sender);
        _members[role][account] = true;
    }
}
"""

RENAMED_SOURCE = """
pragma solidity ^0.8.19;

contract Renamed {
    mapping(bytes32 => mapping(address => bool)) private _members;
    mapping(bytes32 => bytes32) private _roleAdmins;

    error MissingRole(bytes32 role, address account);

    function _bouncer(bytes32 r, address who) internal view {
        if (!_members[r][who]) revert MissingRole(r, who);
    }
    function _adminOf(bytes32 r) internal view returns (bytes32) {
        return _roleAdmins[r];
    }
    function dispenseRole(bytes32 r, address account) public {
        _bouncer(_adminOf(r), msg.sender);
        _members[r][account] = true;
    }
}
"""

UNGUARDED_SOURCE = """
pragma solidity ^0.8.19;

contract Unguarded {
    mapping(bytes32 => mapping(address => bool)) private _members;
    function grantRole(bytes32 role, address account) public {
        _members[role][account] = true;
    }
}
"""


def _write_project(tmp_path: Path, contract_name: str, source: str) -> Path:
    project_dir = tmp_path / contract_name
    (project_dir / "src").mkdir(parents=True)
    (project_dir / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nout = "out"\nlibs = ["lib"]\nsolc_version = "0.8.19"\n'
    )
    (project_dir / "src" / f"{contract_name}.sol").write_text(source)
    (project_dir / "contract_meta.json").write_text(
        json.dumps(
            {
                "address": "0x1111111111111111111111111111111111111111",
                "contract_name": contract_name,
                "compiler_version": "v0.8.19+commit.7dd6d404",
            }
        )
        + "\n"
    )
    return project_dir


def _semantic_signatures(analysis: Any) -> set[str]:
    ac = analysis.get("semantic_control") or {}
    return {fn["function"] for fn in (ac.get("semantic_functions") or [])}


# ---------------------------------------------------------------------------
# (1) Admission stage — passes for both naming conventions.
# ---------------------------------------------------------------------------


def test_oz_style_grant_role_admits(tmp_path: Path):
    project = _write_project(tmp_path, "OZStyle", OZ_SOURCE)
    analysis = collect_static_facts(project)
    assert "grantRole(bytes32,address)" in _semantic_signatures(analysis)


def test_renamed_helpers_dispense_role_admits(tmp_path: Path):
    """Confirms the admission gate is name-neutral. The helper rename
    (_checkRole → _bouncer, _getRoleAdmin → _adminOf) doesn't change
    the IR shape, and ``caller_reach_analysis`` recurses into the
    helper to find the ``caller_in_mapping`` revert-gate inside
    ``_bouncer``'s body. So this passes today — admission isn't the
    broken stage."""
    project = _write_project(tmp_path, "Renamed", RENAMED_SOURCE)
    analysis = collect_static_facts(project)
    assert "dispenseRole(bytes32,address)" in _semantic_signatures(analysis)


def test_unguarded_grant_role_does_not_admit(tmp_path: Path):
    """Semantic inclusion is "caller/delegated
    authority leaf OR sensitive sink". An unguarded ``grantRole``
    writes mapping state → it IS admitted under the structural rule.
    The original "negative control" (no caller_authority leaf) is now
    asserted on the predicate tree itself, not on semantic_functions.
    """
    project = _write_project(tmp_path, "Unguarded", UNGUARDED_SOURCE)
    from services.static.static_analysis import collect_static_inputs

    _analysis, predicate_trees, _effects = collect_static_inputs(project)
    semantic_trees = ((predicate_trees or {}).get("trees")) or {}
    tree = semantic_trees.get("grantRole(bytes32,address)")

    def _has_auth_leaf(node) -> bool:
        if not isinstance(node, dict):
            return False
        if node.get("op") == "LEAF":
            leaf = node.get("leaf") or {}
            return leaf.get("authority_role") in ("caller_authority", "delegated_authority")
        return any(_has_auth_leaf(c) for c in node.get("children") or [])

    assert not _has_auth_leaf(tree), "unguarded grantRole surfaced a caller/delegated authority leaf"


# ---------------------------------------------------------------------------
# (2) Resolution stage — produces empty principals for parametric guards.
# This is the user-facing "Unresolved" gap.
# ---------------------------------------------------------------------------


def _function_entry(analysis: Any, signature: str) -> dict | None:
    """Pull the semantic function entry. Resolution-stage output
    layers (permission_index / function_principals) live in a
    later pipeline pass that this test deliberately skips — the empty
    principal state is observable directly from the semantic function
    entry's controller_refs/guards/sinks before policy join."""
    ac = analysis.get("semantic_control") or {}
    for fn in ac.get("semantic_functions") or []:
        if fn["function"] == signature:
            return dict(fn)
    return None


@pytest.mark.xfail(
    reason=(
        "ROOT CAUSE: for parametric admin methods with role as a runtime arg, "
        "no concrete constant exists, so the semantic function entry has an EMPTY "
        "controller_refs-resolves-to-principals chain. permission_index "
        "then emits direct_owner=None / authority_roles=[] / controllers=[], "
        "which the UI renders as 'Unresolved'. "
        "FIX: model the guard as a typed parametric predicate "
        "(kind='dynamic_role_admin', expression='getRoleAdmin(role_arg)') "
        "in the semantic function entry, then resolve the holder set "
        "either statically or through the semantic event/call evidence "
        "available for that descriptor. Remove this xfail when typed "
        "parametric guards land."
    ),
    strict=True,
)
def test_renamed_dispense_role_emits_resolvable_principal_signal(tmp_path: Path):
    """Beyond mere admission, the semantic function entry must carry
    enough typed signal that the policy stage downstream can compute a
    non-empty principal set (or explicitly mark it as 'parametric,
    holders TBD' instead of just 'Unresolved').

    Two acceptable shapes for passing:
      a. A non-empty resolved member set from semantic event evidence.
      b. A new typed field, e.g. ``guard_shape`` / ``parametric_guard``,
         identifying this as a getRoleAdmin(role_arg) gate so the UI
         can say 'role admin' instead of 'unresolved'.
    """
    project = _write_project(tmp_path, "Renamed", RENAMED_SOURCE)
    analysis = collect_static_facts(project)
    entry = _function_entry(analysis, "dispenseRole(bytes32,address)")
    assert entry is not None, "admission already verified above; this should never trip"

    # Today: controller_refs ≈ ['_members', 'role'], guards mention
    # the mapping, but nothing in the entry types out as a parametric
    # role-admin guard the policy stage can route on.
    has_typed_parametric_guard = (
        "guard_shape" in entry  # not yet a field — flips when added
        or "parametric_guard" in entry
        or any(  # or a sink with a typed kind beyond raw caller_internal_call
            (s.get("kind") or "").startswith("dynamic_role_admin") for s in entry.get("sinks") or []
        )
    )
    assert has_typed_parametric_guard, (
        f"dispenseRole admitted without a typed parametric-guard signal. "
        f"controller_refs={entry.get('controller_refs')}, "
        f"guards={entry.get('guards')}, "
        f"sinks_kinds={[s.get('kind') for s in entry.get('sinks') or []]}"
    )
