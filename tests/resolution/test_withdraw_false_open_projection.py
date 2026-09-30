"""Solmate ``requiresAuth`` projection: an empty-exact role enumeration gates.

A ``requiresAuth`` function that is not public and holds no role authorizes no caller; the
Solmate adapter reads it as an EXACT EMPTY ``finite_set`` (carrying the ``solmate_roles_authority``
trace step). AND-ed with the Teller's ``beforeTransfer`` hook (a ``conditional_universal`` that
opens when the permissioned-transfer flag is off) it must stay GATED: the authority side
provably admits nobody.

Driven on real data: the REAL adapter folds the REAL RolesAuthority ``0x3994741a…`` logs, then
the REAL ``capability_to_dict`` / ``project_capability_surface``. Only the event-log backend is a fixture.

Ground truth (RolesAuthority ``0x3994741a`` @ block 25383512, ``isCapabilityPublic``):
``withdraw`` (0x16762eed) = False (gated); ``bridge`` (0x05921740) / ``deposit`` (0x8b6099db) /
``depositAndBridge`` (0xf8b7b66d) = True (genuinely public).
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
# The LayerZeroTeller deployment governed by RolesAuthority 0x3994741a whose
# ``withdraw`` is the audited false-open; PublicCapabilityUpdated keys to it.
TELLER_TARGET = "0x35dd2463fa7a335b721400c5ad8ba40bd85c179b"
WITHDRAW = "0x16762eed"
BRIDGE = "0x05921740"
DEPOSIT = "0x8b6099db"
DEPOSIT_AND_BRIDGE = "0xf8b7b66d"

# The Teller's ``beforeTransfer`` hook, modeled exactly as the static pass emits
# it: a public path (the flag is off) OR an unresolved caller-tainted check.
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
    """In-memory ``iter_event_rows`` over the captured logs (the wire); a non-None ``min_indexed_block`` marks the
    authority warm."""

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
    # Provably-nobody empty-exact Solmate authority leaf: the sibling beforeTransfer public path must NOT open
    # the function.
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
    # PublicCapabilityUpdated(target, sig, true) => conditional_universal, not an empty set: genuinely public.
    auth = _authority_cap_dict(selector)
    assert auth["kind"] == "conditional_universal"

    surface = project_capability_surface(_requires_auth_tree(selector))
    assert surface.authority_public, f"selector {selector} is a public RolesAuthority capability and must stay public"


def test_bare_empty_exact_set_without_solmate_trace_does_not_gate(earned_public):
    # A generic exact-empty set (accept-side ceiling, no Solmate enumeration) stays a
    # side-condition next to a public path; only the Solmate provably-nobody read blocks.
    bare = {"kind": "finite_set", "members": [], "membership_quality": "exact", "confidence": "enumerable"}
    surface = project_capability_surface({"kind": "AND", "children": [_BEFORE_TRANSFER, bare]})
    assert surface.authority_public


def test_empty_lower_bound_solmate_like_set_does_not_manufacture_a_gate(earned_public):
    # An empty LOWER_BOUND set (cold index) must NOT become a confident gate even with the trace
    # step: only an EXACT read is provably-nobody (the adapter defers cold sets to a probe, so
    # this shape shouldn't reach projection; pin that the gate keys on exactness).
    under_resolved = {
        "kind": "finite_set",
        "members": [],
        "membership_quality": "lower_bound",
        "trace": [{"step": "solmate_roles_authority", "roles": []}],
    }
    surface = project_capability_surface({"kind": "AND", "children": [_BEFORE_TRANSFER, under_resolved]})
    # An empty lower_bound caller equality already blocks under earned-public, but NOT via the
    # exact provably-nobody path; the helper is checked directly below.
    assert not surface.authority_public

    from services.policy.capability_surface import _is_role_store_provably_empty

    assert not _is_role_store_provably_empty(under_resolved)
    # Non-finite-set and non-empty Solmate sets are never the provably-nobody gate.
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
