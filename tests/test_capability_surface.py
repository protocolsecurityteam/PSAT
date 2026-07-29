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
    cap = {
        "kind": "cofinite_blacklist",
        "blacklist": [ADDR_A, ADDR_B],
        "membership_quality": "exact",
        # The producer now ALWAYS states this on a cofinite; a
        # dict without it is a pre-fix persisted row, covered by its own case in
        # ``test_cofinite_denylist_quality_is_stated_never_inferred_from_absence``.
        "blacklist_quality": "exact",
    }
    surface = project_capability_surface(cap)
    assert surface.principal_rows == []
    assert surface.residual == []
    assert surface.authority_public is True
    assert len(surface.public_paths) == 1
    path = surface.public_paths[0]
    # The count AND the completeness verdict: an exhaustive
    # exclusion and an un-enumerated one are different filters.
    assert any(c["kind"] == "denylist" and "2 excluded, exhaustive" in c["description"] for c in path), path


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
    assert any("denylist exclusion (0 known excluded" in (d or "") for d in descriptions)


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
# authority_roles — the role half of the (capability, principal) unit.
# It was the literal [] on 1773/1773 persisted rows.
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
    """The enumerable role-store probes the gate and never a role name:
    role-gated, role unknown."""
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


def test_role_grants_not_determined_on_unsupported():
    """``[]`` is "the gate was lowered and no role appeared in it" — proven
    absent. An ``unsupported`` capability means the gate was NEVER lowered, so
    nothing (including "not role-keyed") was read: that is the not-determined
    ``None``, anywhere in the tree. (Inverts the earlier pin that read an
    unsupported gate as proven not role-gated — the chronic not-determined→
    proven route.)"""
    from services.policy.capability_surface import capability_role_grants

    assert capability_role_grants({"kind": "unsupported", "unsupported_reason": "x"}) is None
    assert (
        capability_role_grants(
            {
                "kind": "and",
                "children": [
                    {"kind": "finite_set", "members": [ADDR_A], "membership_quality": "exact"},
                    {"kind": "unsupported", "unsupported_reason": "x"},
                ],
            }
        )
        is None
    )


def test_role_grants_not_determined_when_the_gate_was_never_lowered():
    """``[]`` claims the gate WAS lowered and carries no role-keyed authority.
    ``capability_surface_openness`` already decides whether one was lowered, and
    its ``not_determined`` shapes — an ``external_check_only`` probe interface,
    a ``finite_set`` whose ``empty_reason`` is ``not_read`` — read NOTHING about
    the gate, including whether it is role-keyed.

    12 of 1,159 ether.fi rows on the PR-161 preview carried the contradiction
    (``authority_roles=[]`` beside ``authority_openness='not_determined'``),
    among them two ``grantRole`` entry points gated through an unresolved
    ``RoleRegistry.canCall`` — role-gated by construction, published as proven
    not role-gated."""
    from services.policy.capability_surface import capability_role_grants

    probe = {
        "kind": "external_check_only",
        "check": {"extra": {"basis": ["caller_tainted_authority_unresolved"]}, "target_address": "0x" + "9" * 40},
        "confidence": "check_only",
        "membership_quality": "exact",
    }
    assert capability_role_grants(probe) is None

    not_read = {
        "kind": "finite_set",
        "members": [],
        "confidence": "partial",
        "empty_reason": "not_read",
        "membership_quality": "lower_bound",
    }
    assert capability_role_grants(not_read) is None


def test_role_grants_not_determined_when_no_named_role_member_is_readable():
    """A role WAS named and not one of its member entries survived the
    address filter: role-keyed with the holders not determined, never the
    proven-absent ``[]``. (0 realised on the corpus — every role-witnessing
    trace there carries a well-formed member — structural on the first that
    does not.)

    Pinned on COMPOSITES whose sibling lowers the gate, because that is the
    only place the ``if grants`` arm decides anything. Standing alone the
    malformed node's own openness is already ``not_determined``, so the value
    would leave through the openness gate on the next line and the arm could
    be deleted with every assertion still passing. Under an OR with a public
    sibling the openness is ``open``; under an AND with a readable sibling it
    is ``restricted`` — the gate is lowered, and without this arm both publish
    the ``[]`` that says "proven not role-gated" about a named role."""
    from services.policy.capability_surface import (
        capability_role_grants,
        capability_surface_openness,
        project_capability_surface,
    )

    unreadable_role = {
        "kind": "finite_set",
        "members": ["not-an-address"],
        "membership_quality": "exact",
        "confidence": "enumerable",
        "trace": [{"step": "solmate_roles_authority", "roles": [2]}],
    }
    public_sibling = {"kind": "conditional_universal", "conditions": []}
    readable_sibling = {
        "kind": "finite_set",
        "members": [ADDR_A],
        "membership_quality": "exact",
        "confidence": "enumerable",
    }

    for label, cap, expected_openness in (
        ("OR with a public sibling", {"kind": "OR", "children": [unreadable_role, public_sibling]}, "open"),
        ("AND with a readable sibling", {"kind": "AND", "children": [unreadable_role, readable_sibling]}, "restricted"),
    ):
        # Guards the test itself: if the openness verdict ever drifts back to
        # ``not_determined`` here, the assertion below stops discriminating and
        # this line says so instead of quietly passing for the wrong reason.
        assert capability_surface_openness(cap, project_capability_surface(cap)) == expected_openness, label
        assert capability_role_grants(cap) is None, label


def test_a_witnessed_role_grant_is_never_reached_by_the_openness_downgrade():
    """The downgrade is scoped to the proven-absent ``[]``, and it cannot drop a
    witness even in principle: witnessing a grant requires a ``finite_set``
    carrying members, which is exactly what makes the surface's
    ``principal_rows`` non-empty — so the openness verdict beside any witnessed
    grant is ``restricted``, never ``not_determined``. Pinned over the composite
    shapes because a composite is where the two could plausibly come apart."""
    from services.policy.capability_surface import (
        capability_role_grants,
        capability_surface_openness,
        project_capability_surface,
    )

    probe = {"kind": "external_check_only", "check": {"extra": {}}, "confidence": "check_only"}
    for kind in ("OR", "AND"):
        cap = {"kind": kind, "children": [_solmate_cap([8], [ADDR_A]), probe]}
        grants = capability_role_grants(cap)
        assert grants and [g["role"] for g in grants] == [8], kind
        assert capability_surface_openness(cap, project_capability_surface(cap)) == "restricted", kind


def test_role_grants_empty_stays_reachable_for_a_lowered_gate():
    """R2: the proven-absent ``[]`` must still be realised, or the downgrade has
    quietly collapsed a three-state field to two. Both lowered-gate verdicts
    keep it — 657 of the 1,159 PR-161 rows (408 ``open`` + 249 ``restricted``)."""
    from services.policy.capability_surface import (
        capability_role_grants,
        capability_surface_openness,
        project_capability_surface,
    )

    for cap, expected_openness in (
        ({"kind": "finite_set", "members": [ADDR_A], "membership_quality": "exact"}, "restricted"),
        ({"kind": "conditional_universal", "conditions": []}, "open"),
    ):
        assert capability_surface_openness(cap, project_capability_surface(cap)) == expected_openness
        assert capability_role_grants(cap) == []


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


# ---------------------------------------------------------------------------
# The two capability_expr keys nobody could read correctly.
# ---------------------------------------------------------------------------


def test_cofinite_denylist_quality_is_stated_never_inferred_from_absence():
    """The DEFECT was the default. Emit-when-non-default meant absence =>
    'exact', so a consumer that never heard of ``blacklist_quality`` read every
    cofinite denylist as a COMPLETE exclusion — the strong claim by default."""
    from services.resolution.capabilities import CapabilityExpr
    from services.resolution.capability_resolver import capability_to_dict

    exact = capability_to_dict(CapabilityExpr.cofinite_blacklist([ADDR_A]))
    partial = capability_to_dict(CapabilityExpr.cofinite_blacklist([ADDR_A], blacklist_quality="lower_bound"))
    assert exact["blacklist_quality"] == "exact"
    assert partial["blacklist_quality"] == "lower_bound"
    # Absence now means "not a denylist", so denylist completeness cannot be
    # misread off a capability that never had a denylist.
    assert "blacklist_quality" not in capability_to_dict(CapabilityExpr.finite_set([ADDR_A]))

    # The projected side-condition text distinguishes the three readings.
    assert "exhaustive" in project_capability_surface(exact).public_paths[0][-1]["description"]
    assert "not exhaustive" in project_capability_surface(partial).public_paths[0][-1]["description"]
    legacy = {"kind": "cofinite_blacklist", "blacklist": [ADDR_A], "membership_quality": "exact"}
    assert "completeness not recorded" in project_capability_surface(legacy).public_paths[0][-1]["description"]


def test_capability_currency_three_states():
    """``last_indexed_block`` was present on 240 rows and read by nothing.
    Deciding whether a persisted verdict still holds needs exactly
    "is this statement current?"."""
    from services.policy.capability_surface import CAPABILITY_INDEX_STALE_BLOCKS, capability_currency

    fresh = {"kind": "finite_set", "members": [ADDR_A], "last_indexed_block": 25_619_235}
    assert capability_currency(fresh, index_head=25_619_300)["verdict"] == "current"
    assert capability_currency(fresh, index_head=25_619_300)["lag_blocks"] == 65

    stale = capability_currency(fresh, index_head=25_619_235 + CAPABILITY_INDEX_STALE_BLOCKS)
    assert stale["verdict"] == "stale"

    # ABSENT fact -> not_determined, and lag is None (never 0: a zero lag is the
    # strongest currency claim available and has to be earned).
    absent = capability_currency({"kind": "finite_set", "members": [ADDR_A]}, index_head=25_619_300)
    assert absent == {
        "verdict": "not_determined",
        "last_indexed_block": None,
        "index_head": 25_619_300,
        "lag_blocks": None,
    }
    # No frontier to compare against is equally not-determined.
    assert capability_currency(fresh, index_head=None)["verdict"] == "not_determined"


def test_capability_currency_composite_takes_the_least_current_conjunct():
    from services.policy.capability_surface import capability_currency

    composite = {
        "kind": "AND",
        "children": [
            {"kind": "finite_set", "members": [ADDR_A], "last_indexed_block": 25_619_235},
            {"kind": "finite_set", "members": [ADDR_B], "last_indexed_block": 25_000_000},
        ],
    }
    verdict = capability_currency(composite, index_head=25_619_300)
    assert verdict["last_indexed_block"] == 25_000_000
    assert verdict["verdict"] == "stale"


def test_resolver_path_is_recorded_on_every_principal_row_shape():
    """``function_principals.origin`` / ``principal_type`` are
    single constants (``semantic_capability:finite_set`` / ``controller`` on
    1132/1132 rows), so the columns asserting "here is the provenance of this
    attribution" prove only "this row exists". Neither can be repurposed
    (``origin`` is read as a role name by services/chat/data.py), so the path is
    recorded beside them — three-state."""
    from services.policy.capability_surface import resolver_path

    traced = {
        "kind": "finite_set",
        "members": [ADDR_A],
        "membership_quality": "exact",
        "trace": [{"step": "enumerable_role_store"}, {"step": "differential_probe"}],
    }
    assert resolver_path(traced) == ["enumerable_role_store", "differential_probe"]
    rows = project_capability_surface(traced).principal_rows
    assert rows[0]["details"]["resolver_path"] == ["enumerable_role_store", "differential_probe"]

    # No trace at all -> resolved, path NOT recorded. A third of the local rows
    # are this; it must not read as any particular resolver.
    untraced = {"kind": "finite_set", "members": [ADDR_A], "membership_quality": "exact"}
    assert resolver_path(untraced) is None
    assert project_capability_surface(untraced).principal_rows[0]["details"]["resolver_path"] is None

    # Safe threshold rows carry it too.
    safe = {"kind": "threshold_group", "threshold": {"m": 2, "signers": [ADDR_A, ADDR_B]}}
    assert project_capability_surface(safe).principal_rows[0]["details"]["resolver_path"] is None

    # A signature_witness row reports the SIGNER set's path, not the wrapper's.
    witness = {
        "kind": "signature_witness",
        "signer": {"kind": "finite_set", "members": [ADDR_A], "trace": [{"step": "live_getter_resolution"}]},
    }
    assert project_capability_surface(witness).principal_rows[0]["details"]["resolver_path"] == [
        "live_getter_resolution"
    ]
