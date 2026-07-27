"""Unit tests for ``services.policy.capability_surface`` — the projection seam that
turns a serialized ``CapabilityExpr`` dict into principal rows / public paths / residual.

Focus: the ``cofinite_blacklist`` projection (Part 1 / P2). "Anyone except a finite
exclusion" must project to a PUBLIC path carrying the denylist as a side-condition, not
fall through to the residual sink (the old dead-end that left it under-resolved, status
``None``). Pure, offline, no DB — feeds hand-built cap dicts straight to the projector.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.policy.capability_surface import (  # noqa: E402
    capability_surface_status,
    project_capability_surface,
)

ADDR_A = "0x" + "a" * 40
ADDR_B = "0x" + "b" * 40


def test_cofinite_projects_to_public_path_with_denylist_condition():
    cap = {"kind": "cofinite_blacklist", "blacklist": [ADDR_A, ADDR_B], "membership_quality": "exact"}
    surface = project_capability_surface(cap)
    assert surface.principal_rows == []
    assert surface.residual == []
    assert surface.authority_public is True
    assert len(surface.public_paths) == 1
    path = surface.public_paths[0]
    assert any(c["kind"] == "denylist" and "denylist exclusion (2 known excluded)" in c["description"] for c in path), (
        path
    )


def test_cofinite_status_is_public():
    cap = {"kind": "cofinite_blacklist", "blacklist": [ADDR_A]}
    surface = project_capability_surface(cap)
    assert capability_surface_status(cap, surface) == "public"


def test_cofinite_carries_its_own_conditions_into_the_public_path():
    # The cofinite's own runtime conditions (whenNotPaused, a share time-lock) must ride
    # along in the public path next to the denylist summary, so a reviewer sees the filter.
    cap = {
        "kind": "cofinite_blacklist",
        "blacklist": [],
        "conditions": [{"kind": "pause", "description": "whenNotPaused"}],
    }
    surface = project_capability_surface(cap)
    assert capability_surface_status(cap, surface) == "public"
    descriptions = {c.get("description") for path in surface.public_paths for c in path}
    assert "whenNotPaused" in descriptions
    assert any("denylist exclusion (0 known excluded)" in (d or "") for d in descriptions)


def test_cofinite_openness_does_not_branch_on_quality():
    # Openness must NOT depend on blacklist_quality: an exact and a lower_bound cofinite
    # both project to public (the quality is informational / surfaced only).
    exact = {"kind": "cofinite_blacklist", "blacklist": [ADDR_A], "blacklist_quality": "exact"}
    lower = {"kind": "cofinite_blacklist", "blacklist": [ADDR_A], "blacklist_quality": "lower_bound"}
    assert capability_surface_status(exact, project_capability_surface(exact)) == "public"
    assert capability_surface_status(lower, project_capability_surface(lower)) == "public"


def test_cofinite_is_never_resolved_empty():
    # A cofinite is never "provably nobody" — even an empty blacklist means "everyone".
    cap = {"kind": "cofinite_blacklist", "blacklist": []}
    surface = project_capability_surface(cap)
    assert capability_surface_status(cap, surface) == "public"  # not "resolved_empty"


def test_external_check_only_still_falls_to_residual():
    # Guard against over-opening: a kind with no public-path branch stays residual / None,
    # exactly as before — only cofinite was added to the public set, nothing else flips.
    cap = {"kind": "external_check_only", "check": {"target_address": ADDR_A}}
    surface = project_capability_surface(cap)
    assert surface.authority_public is False
    assert surface.residual
    assert capability_surface_status(cap, surface) is None


def test_disjoint_intersection_and_never_reads_resolved_empty():
    """The end-to-end pin for G2 HIT 3: intersect({A}, {B}) now stays a
    structural AND, and the projected status is None (not-determined), never
    'resolved_empty' — while a genuinely witnessed empty conjunct still
    resolves the AND empty."""
    from services.resolution.capabilities import CapabilityExpr, intersect
    from services.resolution.capability_resolver import capability_to_dict

    disjoint = capability_to_dict(intersect(CapabilityExpr.finite_set([ADDR_A]), CapabilityExpr.finite_set([ADDR_B])))
    assert disjoint["kind"] == "AND"
    surface = project_capability_surface(disjoint)
    assert capability_surface_status(disjoint, surface) is None

    inherited = capability_to_dict(
        intersect(CapabilityExpr.finite_set([], quality="exact"), CapabilityExpr.finite_set([ADDR_B]))
    )
    surface = project_capability_surface(inherited)
    assert capability_surface_status(inherited, surface) == "resolved_empty"


def test_openness_is_total_and_three_valued():
    """``capability_surface_openness`` must answer for every capability shape,
    and the three answers must not collapse: 'open' tracks the bool exactly,
    'restricted' means a restriction was WITNESSED, 'not_determined' is the
    population the bool merged into 'restricted'."""
    from services.policy.capability_surface import AUTHORITY_OPENNESS_VALUES, capability_surface_openness

    cases = {
        "open": {"kind": "conditional_universal", "conditions": [], "membership_quality": "exact"},
        "open_cofinite": {"kind": "cofinite_blacklist", "blacklist": [ADDR_A], "membership_quality": "exact"},
        "restricted_set": {"kind": "finite_set", "members": [ADDR_A], "membership_quality": "exact"},
        "restricted_empty": {"kind": "finite_set", "members": [], "membership_quality": "exact"},
        "nd_unsupported": {"kind": "unsupported", "unsupported_reason": "guard_extraction_uncertain"},
        "nd_check": {"kind": "external_check_only", "check": {"target_address": ADDR_B}},
        "nd_lower_bound_empty": {"kind": "finite_set", "members": [], "membership_quality": "lower_bound"},
        "nd_unknown_kind": {"kind": "something_new"},
    }
    got = {}
    for name, cap in cases.items():
        surface = project_capability_surface(cap)
        verdict = capability_surface_openness(cap, surface)
        assert verdict in AUTHORITY_OPENNESS_VALUES, (name, verdict)
        assert verdict == "open" or not surface.authority_public, name
        got[name] = verdict
    assert got == {
        "open": "open",
        "open_cofinite": "open",
        "restricted_set": "restricted",
        "restricted_empty": "restricted",
        "nd_unsupported": "not_determined",
        "nd_check": "not_determined",
        "nd_lower_bound_empty": "not_determined",
        "nd_unknown_kind": "not_determined",
    }


# ---------------------------------------------------------------------------
# authority_roles — the role half of inv 3's (capability, principal) unit
# (W2-B item 8). It was the literal [] on 1773/1773 persisted rows.
# ---------------------------------------------------------------------------


def _solmate_cap(roles, members):
    return {
        "kind": "finite_set",
        "members": list(members),
        "membership_quality": "exact",
        "confidence": "enumerable",
        "trace": [
            {
                "step": "solmate_roles_authority",
                "roles": list(roles),
                "authority": "0x" + "1" * 40,
                "target": "0x" + "2" * 40,
                "selector": "0xdeadbeef",
            }
        ],
    }


def test_role_grants_witnessed_for_single_role_capability():
    from services.policy.capability_surface import capability_role_grants

    grants = capability_role_grants(_solmate_cap([2], [ADDR_A, ADDR_B]))
    assert grants == [
        {
            "role": 2,
            "principals": [
                {"address": ADDR_A, "resolved_type": None, "details": {"source": "semantic_capability:role_grant"}},
                {"address": ADDR_B, "resolved_type": None, "details": {"source": "semantic_capability:role_grant"}},
            ],
        }
    ]


def test_role_grants_not_determined_for_multi_role_capability():
    """Two roles carry the capability, so WHICH role each member holds is not
    recoverable — attributing every member to every role is the over-claim."""
    from services.policy.capability_surface import capability_role_grants

    assert capability_role_grants(_solmate_cap([1, 2], [ADDR_A])) is None


def test_role_grants_not_determined_when_role_identity_is_dissolved():
    """The enumerable role-store probes the gate and never a role name
    (CONTROLLER_RESOLUTION_SPEC §3.2): role-gated, role unknown."""
    from services.policy.capability_surface import capability_role_grants

    cap = {
        "kind": "finite_set",
        "members": [ADDR_A],
        "membership_quality": "exact",
        "trace": [{"step": "enumerable_role_store", "authority": "0x" + "3" * 40}],
    }
    assert capability_role_grants(cap) is None


def test_role_grants_empty_when_no_role_authority_witnessed():
    """Proven absent: a plain owner equality / public path is not role-gated —
    this is the ONLY shape that may read as ``[]``."""
    from services.policy.capability_surface import capability_role_grants

    assert capability_role_grants({"kind": "finite_set", "members": [ADDR_A], "membership_quality": "exact"}) == []
    assert capability_role_grants({"kind": "conditional_universal", "conditions": []}) == []
    assert capability_role_grants({"kind": "unsupported", "unsupported_reason": "x"}) == []


def test_role_grants_public_solmate_capability_is_not_role_gated():
    """``roles: []`` on the trace means no role carries the capability (it is
    public) — nothing witnessed and nothing undetermined."""
    from services.policy.capability_surface import capability_role_grants

    assert capability_role_grants(_solmate_cap([], [])) == []


def test_role_grants_walk_composites_and_fail_closed_on_roleless_node():
    from services.policy.capability_surface import capability_role_grants

    composite = {
        "kind": "OR",
        "children": [_solmate_cap([8], [ADDR_A]), {"kind": "conditional_universal", "conditions": []}],
    }
    assert capability_role_grants(composite) == [
        {
            "role": 8,
            "principals": [
                {"address": ADDR_A, "resolved_type": None, "details": {"source": "semantic_capability:role_grant"}}
            ],
        }
    ]
    # A role-naming trace on a node carrying NO member list cannot attribute the
    # role to anyone — not-determined, never an empty grant.
    orphan = {"kind": "external_check_only", "trace": _solmate_cap([8], [])["trace"]}
    assert capability_role_grants(orphan) is None
