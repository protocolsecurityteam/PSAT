"""The bottom-up projection must equal expanding the capability tree into its paths and merging rows, field for field
and in the same order, on every small tree; and its budgets must publish not_determined, never a truncated answer.
"""

from __future__ import annotations

import copy
import itertools
import random
import time
from typing import Any

import pytest

import services.policy.capability_surface as cs
from services.policy.capability_surface import (
    PROJECTION_BUDGET_EXCEEDED,
    PUBLIC_PATH_LIST_BUDGET,
    PUBLIC_PATH_LIST_BUDGET_EXCEEDED,
    bounded_capability,
    capability_role_grants,
    capability_surface_openness,
    capability_surface_status,
    project_capability_surface,
    projection_pass,
)
from services.resolution.capabilities import REACH_NOT_DETERMINED

ADDRS = ["0x" + c * 40 for c in "abcd"]
CONDS = [{"kind": "business", "description": f"c{i}"} for i in range(4)] + [
    {"kind": "pause", "description": "whenNotPaused", "dropped": None}
]


# The expansion the projection replaced: every AND multiplies its children's paths and caller rows, and rows are merged
# by (address, origin, principal_type) at the end.


def _reference(cap: dict[str, Any]) -> dict[str, Any]:
    rows, paths, residual, ond = _ref_node(cap)
    rows = _ref_dedupe(rows)
    paths = [cs._unique_conditions(p) for p in paths]
    conditions: list[dict[str, Any]] = []
    for row in rows:
        details = row.get("details")
        if isinstance(details, dict):
            conditions.extend(cs._condition_dicts(details.get("conditions")))
    for path in paths:
        conditions.extend(path)
    if paths:
        openness = "open"
    elif ond:
        openness = "not_determined"
    elif rows or cs._is_resolved_empty_capability(cap):
        openness = "restricted"
    else:
        openness = "not_determined"
    if paths:
        status = "public"
    elif not rows and cs._is_resolved_empty_capability(cap):
        status = "resolved_empty"
    elif cap.get("kind") == "unsupported" and not rows:
        status = "unsupported"
    else:
        status = None
    return {
        "rows": rows,
        "paths": paths,
        "residual": residual,
        "ond": ond,
        "conditions": cs._unique_conditions(conditions),
        "openness": openness,
        "status": status,
    }


def _with(row: dict[str, Any], conditions: list[dict[str, Any]]) -> dict[str, Any]:
    out = dict(row)
    out["details"] = cs._details_with_conditions(dict(out.get("details") or {}), conditions)
    return out


def _ref_node(cap: dict[str, Any]) -> tuple[list, list, list, bool]:
    kind = cap.get("kind")
    nc = cs._condition_dicts(cap.get("conditions"))
    if cs.is_reach_not_determined(cap):
        return [], [], [dict(cap)], True
    if kind == "finite_set":
        return cs._rows_for_finite_set(cap, nc), [], [], False
    if kind == "threshold_group":
        rows = cs._rows_for_threshold_group(cap, conditions=nc, safe_address_lookup=None, function_signature=None)
        return rows, [], [], False
    if kind == "signature_witness":
        return cs._rows_for_signature_witness(cap, nc), [], [], False
    if kind == "conditional_universal":
        return [], [nc], [], False
    if kind == "cofinite_blacklist":
        quality = cap.get("blacklist_quality")
        excluded = len(cap.get("blacklist") or [])
        if quality == "exact":
            description = f"denylist exclusion ({excluded} excluded, exhaustive)"
        elif quality is None:
            description = f"denylist exclusion ({excluded} known excluded; completeness not recorded)"
        else:
            description = f"denylist exclusion (at least {excluded} excluded; not exhaustive)"
        return [], [nc + [{"kind": "denylist", "description": description}]], [], False
    if kind not in ("AND", "OR"):
        return [], [], [dict(cap)], False
    rows: list = []
    paths: list = []
    residual: list = []
    ond = False
    blocked = False
    for child in cs._child_dicts(cap):
        c_rows, c_paths, c_res, c_ond = _ref_node(child)
        if kind == "OR":
            rows, paths, residual, ond = rows + c_rows, paths + c_paths, residual + c_res, ond or c_ond
            continue
        if cs.earned_public_enabled() and not (c_rows or c_paths) and cs._is_root_authority_blocker(child):
            blocked = True
        rows, paths, residual, ond = _ref_and((rows, paths, residual, ond), (c_rows, c_paths, c_res, c_ond))
    if nc:
        rows = [_with(r, nc) for r in rows]
        paths = [cs._unique_conditions(p + nc) for p in paths]
    if blocked:
        paths = []
    return rows, paths, residual, ond


def _ref_and(left: tuple, right: tuple) -> tuple:
    l_rows, l_paths, l_res, l_ond = left
    r_rows, r_paths, r_res, r_ond = right

    def admits(rows, paths, ond):
        return bool(paths) or ond or not (rows or paths)

    ond = (l_ond and admits(r_rows, r_paths, r_ond)) or (r_ond and admits(l_rows, l_paths, l_ond))
    l_valid, r_valid = bool(l_rows or l_paths), bool(r_rows or r_paths)
    if not l_valid and not r_valid:
        return [], [], l_res + r_res, ond
    if not r_valid or not l_valid:
        (v_rows, v_paths, v_res), side = (
            ((l_rows, l_paths, l_res), r_res) if not r_valid else ((r_rows, r_paths, r_res), l_res)
        )
        conditions = [c for res in side for c in cs._residual_as_conditions(res)]
        if conditions:
            v_rows = [_with(r, conditions) for r in v_rows]
            v_paths = [cs._unique_conditions(p + conditions) for p in v_paths]
        return list(v_rows), list(v_paths), v_res + side, ond
    paths = [cs._unique_conditions(lp + rp) for lp in l_paths for rp in r_paths]
    rows = [_with(row, p) for row in l_rows for p in r_paths] + [_with(row, p) for row in r_rows for p in l_paths]
    not_read = [{"kind": "business", "description": "condition not read"}]
    if r_ond:
        rows += [_with(row, not_read) for row in l_rows]
    if l_ond:
        rows += [_with(row, not_read) for row in r_rows]
    residual = l_res + r_res
    if l_rows and r_rows:
        residual.append({"kind": "unsupported", "unsupported_reason": "and_multiple_principal_shapes"})
    return rows, paths, residual, ond


def _ref_dedupe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    by_key: dict[tuple, dict[str, Any]] = {}
    for row in rows:
        key = cs._row_key(row)
        if key not in by_key:
            copied = dict(row)
            copied["details"] = dict(copied.get("details") or {})
            by_key[key] = copied
            out.append(copied)
            continue
        existing = by_key[key]
        details = dict(existing.get("details") or {})
        raw = row.get("details")
        row_details: dict[str, Any] = raw if isinstance(raw, dict) else {}
        details["conditions"] = cs._unique_conditions(
            cs._condition_dicts(details.get("conditions")) + cs._condition_dicts(row_details.get("conditions"))
        )
        trace = list(details.get("trace") or [])
        trace.extend(item for item in row_details.get("trace") or [] if item not in trace)
        if trace:
            details["trace"] = trace
        if "membership_quality" in details or "membership_quality" in row_details:
            details["membership_quality"] = cs.merged_membership_quality(
                details.get("membership_quality"), row_details.get("membership_quality")
            )
        existing["details"] = details
    return out


def _projected(cap: dict[str, Any]) -> dict[str, Any]:
    surface = project_capability_surface(cap)
    listed = surface.public_path_list(budget=10**6)
    assert listed.incomplete_reason is None
    assert len(listed.paths) == surface.public_path_count
    return {
        "rows": surface.principal_rows,
        "paths": listed.paths,
        "residual": surface.residual,
        "ond": surface.open_not_determined,
        "conditions": surface.conditions,
        "openness": capability_surface_openness(cap, surface),
        "status": capability_surface_status(cap, surface),
    }


def _assert_equivalent(cap: dict[str, Any]) -> None:
    expected = _reference(copy.deepcopy(cap))
    got = _projected(cap)
    for field in expected:
        assert got[field] == expected[field], (field, cap)


# Leaves: what the resolver hands the projection. A negated reach condition is decided before projection, by its read:
# read true it is an open path carrying the read, read false it drops out, unread it is a path that may be open.


def _reach_unread(expression: str = "!hasRole(r, 0)") -> dict[str, Any]:
    return {
        "kind": "external_check_only",
        "check": {"target_address": None, "extra": {"basis": [REACH_NOT_DETERMINED], "expression": expression}},
    }


def _reach_read_true(expression: str = "!paused") -> dict[str, Any]:
    return {
        "kind": "conditional_universal",
        "conditions": [{"kind": "business", "description": f"{expression} read true", "reads": [{"slot": "0x0"}]}],
    }


def _set(members: list[str], quality: Any = "exact", conditions: list | None = None, step: str = "s") -> dict:
    cap = {
        "kind": "finite_set",
        "members": members,
        "membership_quality": quality,
        "confidence": "enumerable",
        "trace": [{"step": step}],
    }
    if conditions:
        cap["conditions"] = conditions
    return cap


def _leaf_alphabet() -> list[dict[str, Any]]:
    return [
        _set([ADDRS[0]], "exact", [CONDS[0]]),
        _set([ADDRS[0], ADDRS[1]], "lower_bound", step="t"),
        _set([ADDRS[0]], None, [CONDS[4]]),
        _set([], "exact"),
        _set([], "lower_bound"),
        {"kind": "conditional_universal", "conditions": []},
        {"kind": "conditional_universal", "conditions": [CONDS[1], CONDS[2]]},
        _reach_unread(),
        _reach_read_true(),
        {"kind": "unsupported", "unsupported_reason": "u"},
        {
            "kind": "external_check_only",
            "check": {"target_address": ADDRS[3], "extra": {"basis": ["caller_tainted_authority_unresolved"]}},
        },
        {"kind": "cofinite_blacklist", "blacklist": [ADDRS[2]], "blacklist_quality": "exact"},
    ]


def test_every_two_level_tree_over_the_leaf_alphabet_projects_as_its_expansion():
    leaves = _leaf_alphabet()
    pairs = [{"kind": kind, "children": [a, b]} for kind in ("AND", "OR") for a in leaves for b in leaves]
    for left, right in itertools.product(pairs[::7], pairs[::5]):
        for kind in ("AND", "OR"):
            _assert_equivalent({"kind": kind, "children": [left, right], "conditions": [CONDS[3]]})
    for cap in pairs:
        _assert_equivalent(cap)


def test_a_shared_unread_reach_beside_several_gates_projects_as_its_expansion():
    reach = _reach_unread()
    gates = [_set([address], quality) for address, quality in zip(ADDRS, ["exact", "lower_bound", None, "exact"])]
    shared = {"kind": "AND", "children": [{"kind": "OR", "children": [reach, gate]} for gate in gates]}
    _assert_equivalent(shared)
    nested = {
        "kind": "OR",
        "children": [reach, {"kind": "AND", "children": [shared, {"kind": "OR", "children": [reach]}]}],
    }
    _assert_equivalent(nested)
    read_true = _reach_read_true()
    _assert_equivalent({"kind": "AND", "children": [{"kind": "OR", "children": [read_true, g]} for g in gates]})


def _random_leaf(r: random.Random) -> dict[str, Any]:
    k = r.random()
    conditions = r.sample(CONDS, r.randint(0, 2)) if r.random() < 0.5 else []
    if k < 0.3:
        members = r.sample(ADDRS, r.randint(0, 3)) + ([ADDRS[0]] if r.random() < 0.1 else [])
        quality = r.choice(["exact", "lower_bound", None, "unrecognised"])
        return _set(members, quality, conditions, step=r.choice(["s1", "s2"]))
    if k < 0.45:
        return {"kind": "conditional_universal", "conditions": conditions}
    if k < 0.55:
        return _reach_unread(r.choice(["a", "b"]))
    if k < 0.6:
        return _reach_read_true(r.choice(["a", "b"]))
    if k < 0.67:
        basis = [r.choice(["caller_tainted_authority_unresolved", "other"])]
        return {"kind": "external_check_only", "check": {"target_address": r.choice(ADDRS), "extra": {"basis": basis}}}
    if k < 0.72:
        return {"kind": "unsupported", "unsupported_reason": "u"}
    if k < 0.77:
        quality = r.choice(["exact", None, "lower_bound"])
        return {"kind": "cofinite_blacklist", "blacklist": r.sample(ADDRS, 1), "blacklist_quality": quality}
    if k < 0.84:
        trace = [{"step": "source_signature_threshold", "contract": r.choice(ADDRS)}]
        threshold = {"m": 2, "signers": r.sample(ADDRS, 3)}
        return {"kind": "threshold_group", "threshold": threshold, "trace": trace, "conditions": conditions}
    if k < 0.9:
        signer = _set(r.sample(ADDRS, 2), "exact", conditions)
        return {"kind": "signature_witness", "signer": signer}
    return {"kind": "finite_set", "members": [], "membership_quality": "lower_bound", "empty_reason": "empty_by_design"}


def _random_tree(r: random.Random, depth: int, seen: list[dict[str, Any]]) -> dict[str, Any]:
    if depth == 0 or r.random() < 0.3:
        if seen and r.random() < 0.25:
            # The same object in two places, as a shared reach condition is.
            return r.choice(seen)
        leaf = _random_leaf(r)
        seen.append(leaf)
        return leaf
    node: dict[str, Any] = {
        "kind": r.choice(["AND", "OR"]),
        "children": [_random_tree(r, depth - 1, seen) for _ in range(r.randint(0, 4))],
    }
    if r.random() < 0.3:
        node["conditions"] = r.sample(CONDS, r.randint(1, 2))
    if r.random() < 0.1:
        node["subject"] = "bound"
    return node


@pytest.mark.parametrize("seed", range(4))
def test_random_trees_project_as_their_expansion(seed):
    for case in range(400):
        r = random.Random(seed * 1000 + case)
        _assert_equivalent(_random_tree(r, r.randint(1, 5), []))


def test_role_grants_read_the_same_openness_as_the_expansion():
    r = random.Random(7)
    for _ in range(300):
        cap = _random_tree(r, 3, [])
        grants = capability_role_grants(cap)
        if grants == []:
            assert _reference(copy.deepcopy(cap))["openness"] != "not_determined", cap


def test_paths_that_multiply_stay_linear_and_the_listed_paths_say_they_stop_short():
    # (r ∨ u ∨ g1) ∧ (r ∨ u ∨ g2) ∧ … with r read true: 2^60 paths in the expansion.
    universal = {"kind": "conditional_universal", "conditions": [CONDS[0]]}
    conjuncts = [{"kind": "OR", "children": [_reach_read_true(), universal, _set([ADDRS[i % 4]])]} for i in range(60)]
    cap = {"kind": "AND", "children": conjuncts}
    started = time.process_time()
    surface = project_capability_surface(cap)
    assert time.process_time() - started < 5
    assert surface.public_path_count == 2**60
    assert capability_surface_openness(cap, surface) == "open"
    listed = surface.public_path_list()
    assert len(listed.paths) == PUBLIC_PATH_LIST_BUDGET
    assert listed.incomplete_reason == PUBLIC_PATH_LIST_BUDGET_EXCEEDED
    assert {row["address"] for row in surface.principal_rows} == set(ADDRS)


def test_a_projection_over_its_work_budget_is_not_determined_never_a_truncated_answer(monkeypatch):
    from services.policy.effective_permissions import _column_values_for_capability

    restricted_by_empty = {"kind": "AND", "children": [_set([ADDRS[0]]), _set([], "exact")]}
    assert capability_surface_openness(restricted_by_empty, project_capability_surface(restricted_by_empty)) == (
        "restricted"
    )
    monkeypatch.setattr(cs, "PROJECTION_WORK_BUDGET", 3)
    for cap in (restricted_by_empty, {"kind": "conditional_universal", "conditions": CONDS}):
        surface = project_capability_surface(cap)
        assert surface.not_determined_reason == PROJECTION_BUDGET_EXCEEDED
        assert not surface.principal_rows and not surface.authority_public
        assert capability_surface_openness(cap, surface) == "not_determined"
        assert capability_surface_status(cap, surface) == "unsupported"
        bounded = bounded_capability(cap)
        assert bounded == {
            "kind": "unsupported",
            "unsupported_reason": PROJECTION_BUDGET_EXCEEDED,
            "confidence": "check_only",
        }
        columns = _column_values_for_capability(bounded)
        assert columns["authority_openness"] == "not_determined"
        assert columns["status"] == "unsupported"
        assert columns["authority_public"] is False
        assert capability_role_grants(cap) is None


def test_projections_are_shared_within_a_pass_and_never_outlive_it(monkeypatch):
    calls: list[int] = []
    real = cs._Projector.node

    def counting(self, cap_dict):
        calls.append(1)
        return real(self, cap_dict)

    monkeypatch.setattr(cs._Projector, "node", counting)
    cap = {"kind": "OR", "children": [_set([ADDRS[0]], conditions=[CONDS[0]]), _set([ADDRS[0]], conditions=[CONDS[1]])]}

    project_capability_surface(cap)
    project_capability_surface(cap)
    assert len(calls) == 6, "outside a pass nothing is shared"

    calls.clear()
    with projection_pass():
        first = project_capability_surface(cap)
        first.principal_rows[0]["details"]["conditions"].append({"kind": "business", "description": "mutated"})
        first.principal_rows[0]["details"]["trace"].append({"step": "mutated"})
        again = project_capability_surface(copy.deepcopy(cap))
        assert len(calls) == 3, "equal content is projected once per pass"
        assert again.principal_rows == project_capability_surface(cap).principal_rows
        assert {"kind": "business", "description": "mutated"} not in again.principal_rows[0]["details"]["conditions"]
        assert {"step": "mutated"} not in again.principal_rows[0]["details"]["trace"]
        with projection_pass():
            project_capability_surface(cap)
        assert len(calls) == 3, "a nested pass reuses the outer one"
    assert cs._projection_memo.get() is None

    calls.clear()
    project_capability_surface(cap)
    assert len(calls) == 3, "the pass's memo is gone once it ends"


def test_the_memo_key_covers_the_safe_lookup_and_the_function():
    group = {"kind": "threshold_group", "threshold": {"m": 1, "signers": [ADDRS[0]]}}
    with projection_pass():
        by_default = project_capability_surface(group, safe_address_lookup={"default": ADDRS[1]})
        by_function = project_capability_surface(
            group, safe_address_lookup={"default": ADDRS[1], "f()": ADDRS[2]}, function_signature="f()"
        )
        other_function = project_capability_surface(
            group, safe_address_lookup={"default": ADDRS[1], "f()": ADDRS[2]}, function_signature="g()"
        )
    assert by_default.principal_rows[0]["address"] == ADDRS[1]
    assert by_function.principal_rows[0]["address"] == ADDRS[2]
    assert other_function.principal_rows[0]["address"] == ADDRS[1]
