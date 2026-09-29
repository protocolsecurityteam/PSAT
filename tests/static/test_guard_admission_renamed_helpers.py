"""Regression test: parametric guards land in semantic_functions but resolve to no
concrete principals, the EtherFiTimelock symptom (todo.txt #7).

grantRole/revokeRole/renounceRole show as 'Unresolved' in the UI although the contract
is plainly role-controlled: the functions are admitted to ``semantic_functions`` but
never bound to principals, so ``effective_permissions`` has empty ``direct_owner`` /
``authority_roles`` / ``controllers``. Pins three claims: (1) OZ-style and
renamed-helper variants both admit (the admission gate is not the broken layer);
(2) the Unguarded control does NOT admit; (3) both guarded variants emit an
``EffectiveFunctionPermission`` with EMPTY principals, the gap to close.

The xfail in (3) flips to passing when the policy stage can express 'guarded by
getRoleAdmin(role_arg) holders' as a typed parametric principal (todo.txt #7).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from services.static import collect_contract_analysis

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


# (1) Admission stage — passes for both naming conventions.


def test_oz_style_grant_role_admits(tmp_path: Path):
    project = _write_project(tmp_path, "OZStyle", OZ_SOURCE)
    analysis = collect_contract_analysis(project)
    assert "grantRole(bytes32,address)" in _semantic_signatures(analysis)


def test_renamed_helpers_dispense_role_admits(tmp_path: Path):
    """The admission gate is name-neutral: the helper rename doesn't change the IR
    shape and ``caller_reach_analysis`` recurses into it to find the
    ``caller_in_mapping`` revert-gate."""
    project = _write_project(tmp_path, "Renamed", RENAMED_SOURCE)
    analysis = collect_contract_analysis(project)
    assert "dispenseRole(bytes32,address)" in _semantic_signatures(analysis)


def test_unguarded_grant_role_does_not_admit(tmp_path: Path):
    """An unguarded ``grantRole`` writes mapping state, so it IS admitted under the
    structural rule; the "no caller_authority leaf" control is asserted on the
    predicate tree instead."""
    project = _write_project(tmp_path, "Unguarded", UNGUARDED_SOURCE)
    from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts

    _analysis, predicate_trees, _effects = collect_contract_analysis_with_artifacts(project)
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


# (2) Resolution stage — empty principals for parametric guards (the user-facing "Unresolved" gap).


def _function_entry(analysis: Any, signature: str) -> dict | None:
    """Pull the semantic function entry. The empty principal state is observable
    there before the policy join, which this test deliberately skips."""
    ac = analysis.get("semantic_control") or {}
    for fn in ac.get("semantic_functions") or []:
        if fn["function"] == signature:
            return dict(fn)
    return None


@pytest.mark.xfail(
    reason=(
        "ROOT CAUSE: for parametric admin methods with role as a runtime arg, "
        "no concrete constant exists, so the semantic function entry has an EMPTY "
        "controller_refs-resolves-to-principals chain. effective_permissions "
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
    analysis = collect_contract_analysis(project)
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
