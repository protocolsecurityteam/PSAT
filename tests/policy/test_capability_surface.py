"""A cofinite blacklist must project to a public path carrying the denylist as a side-condition, not fall to the
residual sink.
"""

from __future__ import annotations

import pytest

from services.policy.capability_surface import (
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
        # A dict without it is a pre-fix row, covered by
        # ``test_cofinite_denylist_quality_is_stated_never_inferred_from_absence``.
        "blacklist_quality": "exact",
    }
    surface = project_capability_surface(cap)
    assert surface.principal_rows == []
    assert surface.residual == []
    assert surface.authority_public is True
    assert len(surface.public_paths) == 1
    path = surface.public_paths[0]
    # Exhaustive and un-enumerated exclusions differ.
    assert any(c["kind"] == "denylist" and "2 excluded, exhaustive" in c["description"] for c in path), path


def test_cofinite_carries_its_own_conditions_into_the_public_path():
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
    exact = {"kind": "cofinite_blacklist", "blacklist": [ADDR_A], "blacklist_quality": "exact"}
    lower = {"kind": "cofinite_blacklist", "blacklist": [ADDR_A], "blacklist_quality": "lower_bound"}
    assert capability_surface_status(exact, project_capability_surface(exact)) == "public"
    assert capability_surface_status(lower, project_capability_surface(lower)) == "public"


def test_cofinite_is_never_resolved_empty():
    # An empty blacklist still means everyone.
    cap = {"kind": "cofinite_blacklist", "blacklist": []}
    surface = project_capability_surface(cap)
    assert capability_surface_status(cap, surface) == "public"  # not "resolved_empty"


def test_external_check_only_still_falls_to_residual():
    # Only cofinite joined the public set.
    cap = {"kind": "external_check_only", "check": {"target_address": ADDR_A}}
    surface = project_capability_surface(cap)
    assert surface.authority_public is False
    assert surface.residual
    assert capability_surface_status(cap, surface) is None


def test_disjoint_intersection_and_never_reads_resolved_empty():
    """A witnessed empty conjunct still resolves empty."""
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
    """'not_determined' is the population the old bool merged into 'restricted'."""
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


# The role half of the (capability, principal) unit, which was a literal [] on every row.


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


@pytest.mark.parametrize(
    "cap",
    [
        # Attributing every member to every role is the over-claim.
        pytest.param(_solmate_cap([1, 2], [ADDR_A]), id="multi_role_capability"),
        pytest.param(
            {
                "kind": "finite_set",
                "members": [ADDR_A],
                "membership_quality": "exact",
                "trace": [{"step": "enumerable_role_store", "authority": "0x" + "3" * 40}],
            },
            id="role_identity_dissolved",
        ),
        # An ``unsupported`` capability was never lowered, so nothing was read.
        pytest.param({"kind": "unsupported", "unsupported_reason": "x"}, id="unsupported"),
        pytest.param(
            {
                "kind": "and",
                "children": [
                    {"kind": "finite_set", "members": [ADDR_A], "membership_quality": "exact"},
                    {"kind": "unsupported", "unsupported_reason": "x"},
                ],
            },
            id="unsupported_nested_in_tree",
        ),
        # 12 of 1,159 PR-161 rows paired ``authority_roles=[]`` with not-determined openness.
        pytest.param(
            {
                "kind": "external_check_only",
                "check": {
                    "extra": {"basis": ["caller_tainted_authority_unresolved"]},
                    "target_address": "0x" + "9" * 40,
                },
                "confidence": "check_only",
                "membership_quality": "exact",
            },
            id="never_lowered_external_check_probe",
        ),
        pytest.param(
            {
                "kind": "finite_set",
                "members": [],
                "confidence": "partial",
                "empty_reason": "not_read",
                "membership_quality": "lower_bound",
            },
            id="never_lowered_not_read",
        ),
    ],
)
def test_role_grants_not_determined(cap):
    from services.policy.capability_surface import capability_role_grants

    assert capability_role_grants(cap) is None


def test_role_grants_empty_when_no_role_authority_witnessed():
    from services.policy.capability_surface import capability_role_grants

    assert capability_role_grants({"kind": "finite_set", "members": [ADDR_A], "membership_quality": "exact"}) == []
    assert capability_role_grants({"kind": "conditional_universal", "conditions": []}) == []


def test_role_grants_not_determined_when_no_named_role_member_is_readable():
    """Pinned on composites, the only place the ``if grants`` arm decides anything; without it both would publish
    ``[]`` about a named role.
    """
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
        # If openness drifts to ``not_determined`` the next assertion stops discriminating.
        assert capability_surface_openness(cap, project_capability_surface(cap)) == expected_openness, label
        assert capability_role_grants(cap) is None, label


def test_a_witnessed_role_grant_is_never_reached_by_the_openness_downgrade():
    """A witnessed grant makes principal rows non-empty, so openness beside it is ``restricted``."""
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
    """R2: 657 of 1,159 PR-161 rows keep the proven-absent ``[]``."""
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
    orphan = {"kind": "external_check_only", "trace": _solmate_cap([8], [])["trace"]}
    assert capability_role_grants(orphan) is None


def test_cofinite_denylist_quality_is_stated_never_inferred_from_absence():
    """Absence used to mean 'exact', so every cofinite denylist read as a complete exclusion."""
    from services.resolution.capabilities import CapabilityExpr
    from services.resolution.capability_resolver import capability_to_dict

    exact = capability_to_dict(CapabilityExpr.cofinite_blacklist([ADDR_A]))
    partial = capability_to_dict(CapabilityExpr.cofinite_blacklist([ADDR_A], blacklist_quality="lower_bound"))
    assert exact["blacklist_quality"] == "exact"
    assert partial["blacklist_quality"] == "lower_bound"
    assert "blacklist_quality" not in capability_to_dict(CapabilityExpr.finite_set([ADDR_A]))

    assert "exhaustive" in project_capability_surface(exact).public_paths[0][-1]["description"]
    assert "not exhaustive" in project_capability_surface(partial).public_paths[0][-1]["description"]
    legacy = {"kind": "cofinite_blacklist", "blacklist": [ADDR_A], "membership_quality": "exact"}
    assert "completeness not recorded" in project_capability_surface(legacy).public_paths[0][-1]["description"]


def test_capability_currency_three_states():
    """``last_indexed_block`` was on 240 rows and read by nothing."""
    from services.policy.capability_surface import CAPABILITY_INDEX_STALE_BLOCKS, capability_currency

    fresh = {"kind": "finite_set", "members": [ADDR_A], "last_indexed_block": 25_619_235}
    assert capability_currency(fresh, index_head=25_619_300)["verdict"] == "current"
    assert capability_currency(fresh, index_head=25_619_300)["lag_blocks"] == 65

    stale = capability_currency(fresh, index_head=25_619_235 + CAPABILITY_INDEX_STALE_BLOCKS)
    assert stale["verdict"] == "stale"

    # A zero lag is the strongest currency claim and must be earned.
    absent = capability_currency({"kind": "finite_set", "members": [ADDR_A]}, index_head=25_619_300)
    assert absent == {
        "verdict": "not_determined",
        "last_indexed_block": None,
        "index_head": 25_619_300,
        "lag_blocks": None,
    }
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
    """``origin`` and ``principal_type`` are constants that prove only that the row exists, and ``origin`` is read as
    a role name, so the path is recorded beside them.
    """
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

    untraced = {"kind": "finite_set", "members": [ADDR_A], "membership_quality": "exact"}
    assert resolver_path(untraced) is None
    assert project_capability_surface(untraced).principal_rows[0]["details"]["resolver_path"] is None

    safe = {"kind": "threshold_group", "threshold": {"m": 2, "signers": [ADDR_A, ADDR_B]}}
    assert project_capability_surface(safe).principal_rows[0]["details"]["resolver_path"] is None

    witness = {
        "kind": "signature_witness",
        "signer": {"kind": "finite_set", "members": [ADDR_A], "trace": [{"step": "live_getter_resolution"}]},
    }
    assert project_capability_surface(witness).principal_rows[0]["details"]["resolver_path"] == [
        "live_getter_resolution"
    ]
