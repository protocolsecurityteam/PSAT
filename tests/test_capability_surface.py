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
