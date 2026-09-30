"""A Solmate ``requiresAuth`` function that is not public and holds no role is an exact-empty ``finite_set``;
AND-ed with the Teller's ``beforeTransfer`` hook it must stay gated.

Ground truth, RolesAuthority 0x3994741a @ 25383512 ``isCapabilityPublic``: ``withdraw`` (0x16762eed) False;
``bridge`` / ``deposit`` / ``depositAndBridge`` True.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from services.policy.capability_surface import (
    capability_surface_status,
    project_capability_surface,
)
from services.resolution.adapters import CallFrame, EvaluationContext
from services.resolution.adapters.solmate_roles import (
    CANCALL_SIGNATURE,
    SolmateRolesAuthorityAdapter,
)
from services.resolution.capability_resolver import capability_to_dict

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "solmate" / "roles_authority_3994741a.json"
TELLER_TARGET = "0x35dd2463fa7a335b721400c5ad8ba40bd85c179b"
WITHDRAW = "0x16762eed"
BRIDGE = "0x05921740"
DEPOSIT = "0x8b6099db"
DEPOSIT_AND_BRIDGE = "0xf8b7b66d"

# Public when the flag is off, OR an unresolved caller-tainted check.
_BEFORE_TRANSFER = {
    "kind": "OR",
    "children": [
        {
            "kind": "conditional_universal",
            "conditions": [{"kind": "pause", "description": "permissionedTransfers && ! permissionedOperator"}],
        },
        {
            "kind": "external_check_only",
            "check": {"target_address": None, "extra": {"basis": ["caller_tainted_authority_unresolved"]}},
        },
    ],
}


def _event_rows() -> list[SimpleNamespace]:
    fixture = json.loads(FIXTURE.read_text())
    rows: list[SimpleNamespace] = []
    for log in fixture["logs"]:
        body = log["data"][2:] if isinstance(log["data"], str) and log["data"].startswith("0x") else ""
        data_words = ["0x" + body[i : i + 64] for i in range(0, len(body), 64)] if body else []
        rows.append(SimpleNamespace(topic0=log["topics"][0], topics=log["topics"], data_words=data_words))
    return rows


class FixtureRepo:
    """A non-None ``min_indexed_block`` marks the authority warm."""

    def __init__(self, rows: list[SimpleNamespace]):
        self.rows = rows

    def iter_event_rows(self, *, chain_id, event_address, topic0s, block=None):
        del chain_id, event_address, block
        wanted = {t.lower() for t in topic0s}
        return [r for r in self.rows if str(r.topic0).lower() in wanted]

    def min_indexed_block(self, *, chain_id, event_address, topic0s):
        del chain_id, event_address, topic0s
        return 21_000_000


def _authority_cap_dict(selector: str) -> dict:
    fixture = json.loads(FIXTURE.read_text())
    descriptor = {
        "kind": "external_set",
        "callee_signature": CANCALL_SIGNATURE,
        "authority_contract": {"address_source": {"source": "state_variable", "state_variable_name": "authority"}},
    }
    ctx = EvaluationContext(
        chain_id=1,
        contract_address=TELLER_TARGET,
        # Covered by FixtureRepo's cursor (21_000_000).
        block=20_999_000,
        meta={"event_log_repo": FixtureRepo(_event_rows())},
        state_var_values={"authority": fixture["authority"]},
        call_frame=CallFrame.root(contract_address=TELLER_TARGET, function_signature=None, function_selector=selector),
    )
    cap = SolmateRolesAuthorityAdapter().enumerate(descriptor, ctx)
    return capability_to_dict(cap)


def _requires_auth_tree(selector: str) -> dict:
    return {"kind": "AND", "children": [_BEFORE_TRANSFER, _authority_cap_dict(selector)]}


@pytest.fixture
def earned_public(monkeypatch):
    monkeypatch.setenv("PSAT_AUTHORITY_EARNED_PUBLIC", "1")


def test_withdraw_empty_exact_solmate_set_gates_the_and(earned_public):
    auth = _authority_cap_dict(WITHDRAW)
    assert auth["kind"] == "finite_set"
    assert auth["members"] == []
    assert auth["membership_quality"] == "exact"
    assert any(step.get("step") == "solmate_roles_authority" for step in auth["trace"])

    surface = project_capability_surface(_requires_auth_tree(WITHDRAW))
    assert not surface.authority_public, "withdraw is role-gated (isCapabilityPublic=False) and must stay gated"
    assert capability_surface_status(_requires_auth_tree(WITHDRAW), surface) == "resolved_empty"


@pytest.mark.parametrize("selector", [BRIDGE, DEPOSIT, DEPOSIT_AND_BRIDGE])
def test_public_capability_function_stays_public(earned_public, selector):
    auth = _authority_cap_dict(selector)
    assert auth["kind"] == "conditional_universal"

    surface = project_capability_surface(_requires_auth_tree(selector))
    assert surface.authority_public, f"selector {selector} is a public RolesAuthority capability and must stay public"


def test_bare_empty_exact_set_without_solmate_trace_does_not_gate(earned_public):
    # Only the Solmate provably-nobody read blocks; a generic exact-empty set stays a side-condition.
    bare = {"kind": "finite_set", "members": [], "membership_quality": "exact", "confidence": "enumerable"}
    surface = project_capability_surface({"kind": "AND", "children": [_BEFORE_TRANSFER, bare]})
    assert surface.authority_public


def test_empty_lower_bound_solmate_like_set_does_not_manufacture_a_gate(earned_public):
    # Only an exact read is provably-nobody.
    under_resolved = {
        "kind": "finite_set",
        "members": [],
        "membership_quality": "lower_bound",
        "trace": [{"step": "solmate_roles_authority", "roles": []}],
    }
    surface = project_capability_surface({"kind": "AND", "children": [_BEFORE_TRANSFER, under_resolved]})
    # Blocked, but not via the provably-nobody path.
    assert not surface.authority_public

    from services.policy.capability_surface import _is_role_store_provably_empty

    assert not _is_role_store_provably_empty(under_resolved)
    assert not _is_role_store_provably_empty({"kind": "external_check_only"})
    assert not _is_role_store_provably_empty(
        {
            "kind": "finite_set",
            "members": ["0x" + "ab" * 20],
            "membership_quality": "exact",
            "trace": [{"step": "solmate_roles_authority"}],
        }
    )
    assert _is_role_store_provably_empty(
        {
            "kind": "finite_set",
            "members": [],
            "membership_quality": "exact",
            "trace": [{"step": "solmate_roles_authority"}],
        }
    )
