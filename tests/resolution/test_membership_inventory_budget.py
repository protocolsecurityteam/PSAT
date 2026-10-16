"""A source-witnessed linked-list inventory is read member by member up to a bound. A list that doesn't close within
it is published as not determined with the budget's reason, never as the members read so far.
"""

from __future__ import annotations

import pytest

from services.policy.capability_surface import capability_surface_openness, project_capability_surface
from services.resolution.adapters import EvaluationContext
from services.resolution.adapters import authorization as auth
from services.resolution.capability_resolver import capability_to_dict

SENTINEL = 1
DESCRIPTOR = {
    "kind": "mapping_membership",
    "membership_inventory": {"kind": "linked_list", "slot": "0x2", "sentinel": "0x1"},
}


def _ctx() -> EvaluationContext:
    return EvaluationContext(
        chain_id=1, contract_address="0x" + "aa" * 20, block=19_000_000, rpc_url="http://rpc.test", meta={}
    )


def _list_of(length: int):
    reads: list[int] = []

    def storage(rpc_url, address, block, slot, chain_id):
        reads.append(slot)
        return SENTINEL if len(reads) > length else 0x1000 + len(reads)

    return storage, reads


def test_a_list_that_closes_within_the_bound_is_its_members(monkeypatch):
    storage, _ = _list_of(3)
    monkeypatch.setattr(auth, "_storage", storage)
    cap = auth.AuthorizationAdapter().enumerate(DESCRIPTOR, _ctx())
    assert cap.kind == "finite_set" and len(cap.members or []) == 3


@pytest.mark.parametrize("length", [auth._MAX_LINKED_MEMBERS + 1, 10_000])
def test_a_list_longer_than_the_bound_is_not_determined_with_the_budget_reason(monkeypatch, length):
    storage, reads = _list_of(length)
    monkeypatch.setattr(auth, "_storage", storage)
    cap = auth.AuthorizationAdapter().enumerate(DESCRIPTOR, _ctx())
    assert len(reads) == auth._MAX_LINKED_MEMBERS + 1
    assert cap.kind == "external_check_only" and cap.check is not None
    assert auth.MEMBERSHIP_INVENTORY_BUDGET_EXCEEDED in cap.check.extra["basis"]
    as_dict = capability_to_dict(cap)
    assert capability_surface_openness(as_dict, project_capability_surface(as_dict)) == "not_determined"
