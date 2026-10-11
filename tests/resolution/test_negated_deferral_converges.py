"""A denylist read while its cursor is still backfilling converges once the cursor completes.

``require(!denied[msg.sender])`` resolves the membership, which defers on a cold cursor, then negates it. The negation
used to fold the deferred probe into a description-only condition, dropping ``deferred_pending_index``: the published
``cofinite_blacklist [] lower_bound`` was honest but the reconciler never re-resolved it. Real Postgres and production
repos.
"""

from __future__ import annotations

from typing import Any

from db.models import FIRST_INDEXED_BASIS_CREATION, IndexedEventCursor, JobStage, JobStatus
from services.resolution.adapters import EvaluationContext
from services.resolution.adapters.event_indexed import EventIndexedAdapter
from services.resolution.capabilities import CapabilityExpr, intersect, negate, union
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.deferred_reconciler import _iter_deferrals, reconcile_deferred_resolutions
from services.resolution.repos.event_logs_pg import PostgresEventLogRepo
from tests.conftest import requires_postgres
from tests.resolution.test_deferred_resolution_reconcile import _seed_completed_job_with_cap

DENY_LIST = "0x00000000000000000000000000000000de11a1a5"
TELLER = "0x00000000000000000000000000000000071e1100"
TOPIC_DENY = "0x3afb4a3c2e8b8ee0c35b0e1f5d33bd0c8eb6f4a3e2ab0b1c9f9d2f4f3e1a0001"
TOPIC_OTHER = "0x3afb4a3c2e8b8ee0c35b0e1f5d33bd0c8eb6f4a3e2ab0b1c9f9d2f4f3e1a0002"


def _deny_descriptor() -> dict[str, Any]:
    return {
        "kind": "mapping_membership",
        "key_sources": [{"source": "msg_sender"}],
        "enumeration_hint": [
            {
                "topic0": TOPIC_DENY,
                "direction": "add",
                "event_address": DENY_LIST,
                "topics_to_keys": {1: 0},
                "data_to_keys": {},
            }
        ],
    }


def _seed_cursor(session, topic0: str, *, complete: bool) -> None:
    session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=DENY_LIST,
            topic0=topic0,
            last_indexed_block=1_000,
            backfill_complete=complete,
            first_indexed_block=0,
            first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION,
        )
    )
    session.commit()


def _negated_cold_denylist(session) -> CapabilityExpr:
    ctx = EvaluationContext(
        chain_id=1, contract_address=TELLER, block=900, event_log_repo=PostgresEventLogRepo(session)
    )
    denied = EventIndexedAdapter().enumerate(_deny_descriptor(), ctx)
    assert denied.kind == "external_check_only" and denied.check is not None
    assert denied.check.extra.get("deferred_pending_index") is True, "guard: the cold read must defer"
    return negate(denied)


@requires_postgres
def test_a_negated_cold_read_keeps_its_deferral(db_session):
    _seed_cursor(db_session, TOPIC_DENY, complete=False)

    allowed = _negated_cold_denylist(db_session)

    assert (allowed.kind, allowed.blacklist, allowed.blacklist_quality) == ("cofinite_blacklist", [], "lower_bound")
    assert list(_iter_deferrals(capability_to_dict(allowed))) == [(DENY_LIST, (TOPIC_DENY,))]


@requires_postgres
def test_the_reconciler_reresolves_once_the_awaited_cursor_completes(db_session):
    _seed_cursor(db_session, TOPIC_DENY, complete=False)
    job = _seed_completed_job_with_cap(
        db_session, address=TELLER, capability_expr=capability_to_dict(_negated_cold_denylist(db_session))
    )

    # Another topic at the same address being warm does not answer this read; re-enqueueing on it would re-defer
    # every pass.
    _seed_cursor(db_session, TOPIC_OTHER, complete=True)
    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0
    assert (job.stage, job.status) == (JobStage.done, JobStatus.completed)

    cursor = db_session.query(IndexedEventCursor).filter_by(event_address=DENY_LIST, topic0=TOPIC_DENY).one()
    cursor.backfill_complete = True
    db_session.commit()
    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 1
    assert (job.stage, job.status) == (JobStage.policy, JobStatus.queued)


@requires_postgres
def test_the_deferral_survives_composition(db_session):
    _seed_cursor(db_session, TOPIC_DENY, complete=False)
    allowed = _negated_cold_denylist(db_session)
    owners = CapabilityExpr.finite_set(["0x" + "0a" * 20])
    other_denylist = CapabilityExpr.cofinite_blacklist(["0x" + "0b" * 20])
    bound = _negated_cold_denylist(db_session)
    bound.subject = "bound"

    for composed in (
        intersect(owners, allowed),
        intersect(allowed, other_denylist),
        union(allowed, other_denylist),
        union(owners, allowed),
        intersect(owners, bound),
    ):
        assert (DENY_LIST, (TOPIC_DENY,)) in set(_iter_deferrals(capability_to_dict(composed))), composed


def test_a_deferral_naming_no_topic_cursor_is_not_carried():
    """A role check also defers behind a failing tail and names no topics; carried, it would re-enqueue every pass."""
    from services.resolution.capabilities import ExternalCheck

    role_check = CapabilityExpr.external_check_only(
        ExternalCheck(target_address=DENY_LIST, target_call_selector=None, extra={"deferred_pending_index": True})
    )
    assert list(_iter_deferrals(capability_to_dict(negate(role_check)))) == []


@requires_postgres
def test_a_carried_deferral_keeps_the_owner_basis(db_session):
    from services.policy.capability_surface import _authority_basis, resolver_path

    _seed_cursor(db_session, TOPIC_DENY, complete=False)
    owner = CapabilityExpr.finite_set(
        ["0x" + "0a" * 20], trace=[{"step": "authority_getter_basis", "basis": "deunderscore_convention"}]
    )
    composed = capability_to_dict(intersect(owner, _negated_cold_denylist(db_session)))

    assert (DENY_LIST, (TOPIC_DENY,)) in set(_iter_deferrals(composed))
    assert _authority_basis(composed) == "deunderscore_convention"
    assert resolver_path(composed) == ["authority_getter_basis"]
