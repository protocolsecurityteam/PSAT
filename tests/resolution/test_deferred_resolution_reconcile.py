"""Index-cold deferrals self-heal once the event index catches up.

The cold path tags ``external_check_only`` with ``deferred_pending_index`` (only for ``no_index_cursor``) and the
same resolver folds to the real set once indexed. ``reconcile_deferred_resolutions`` re-enqueues policy only for
jobs whose authorities are now ``backfill_complete``.
"""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import func, select

from db.models import (
    Contract,
    EffectiveFunction,
    IndexedEventCursor,
    IndexedEventLog,
    Job,
    JobStage,
    JobStatus,
)
from services.resolution.adapters import CallFrame, EvaluationContext
from services.resolution.adapters.solmate_roles import (
    _ROLE_TOPICS,
    CANCALL_SELECTOR,
    CANCALL_SIGNATURE,
)
from services.resolution.capabilities import CapabilityExpr, ExternalCheck
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.deferred_reconciler import (
    DEFERRED_MARKER,
    TRACE_STEP_ENUMERABLE_ROLE_STORE,
    _iter_deferred_authorities,
    _iter_role_store_frontiers,
    reconcile_deferred_resolutions,
    reconcile_role_set_drift,
)
from services.resolution.repos.event_logs_pg import PostgresEventLogRepo
from services.resolution.role_store_standards import SOLADY_ENUMERABLE_ROLES
from tests.conftest import requires_postgres

_ROLE_SET_TOPIC0 = SOLADY_ENUMERABLE_ROLES.grant_events[0].topic0

_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "solmate" / "roles_authority_3994741a.json"
_PAUSE = "0x8456cb59"


def _fixture() -> dict:
    return json.loads(_FIXTURE.read_text())


def _descriptor() -> dict:
    return {
        "kind": "external_set",
        "callee_signature": CANCALL_SIGNATURE,
        "authority_contract": {"address_source": {"source": "state_variable", "state_variable_name": "authority"}},
    }


def _ctx(repo: PostgresEventLogRepo, teller: str, authority: str, selector: str) -> EvaluationContext:
    return EvaluationContext(
        chain_id=1,
        contract_address=teller,
        # Covered by the seeded cursors' default frontier (10_000).
        block=10_000,
        event_log_repo=repo,
        state_var_values={"authority": authority},
        call_frame=CallFrame.root(contract_address=teller, function_signature=None, function_selector=selector),
    )


def _seed_role_cursors(
    session, authority: str, *, backfill_complete: bool, last_block: int = 10_000, chain_id: int = 1
) -> None:
    for topic0 in _ROLE_TOPICS:
        session.add(
            IndexedEventCursor(
                chain_id=chain_id,
                event_address=authority.lower(),
                topic0=topic0.lower(),
                last_indexed_block=last_block,
                backfill_complete=backfill_complete,
                first_indexed_block=0,
                first_indexed_block_basis="creation_block_minus_one",
            )
        )


# ---------------------------------------------------------------------------
# Half 1 — adapters tag index-cold deferrals, and the SAME resolver self-heals
# once the events are durably indexed (real PostgresEventLogRepo + DB).
# ---------------------------------------------------------------------------


def test_iter_deferred_authorities_handles_signer_and_non_dict():
    auth = "0x" + "d7" * 20
    witness = CapabilityExpr.signature_witness(
        CapabilityExpr.external_check_only(
            ExternalCheck(target_address=auth, target_call_selector=None, extra={DEFERRED_MARKER: True})
        )
    )
    assert set(_iter_deferred_authorities(capability_to_dict(witness))) == {auth}
    assert list(_iter_deferred_authorities("not-a-dict")) == []
    assert list(_iter_deferred_authorities(None)) == []


def _deferred_cap(authority: str) -> dict:
    return capability_to_dict(
        CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=authority,
                target_call_selector=CANCALL_SELECTOR,
                extra={"basis": ["no_index_cursor"], "adapter": "solmate_roles_authority", DEFERRED_MARKER: True},
            )
        )
    )


def _seed_completed_job_with_cap(db_session, *, address: str, capability_expr: dict, chain: str = "ethereum") -> Job:
    # Teardown doesn't clear Job rows, and a leaked job trips the active-job guard.
    db_session.query(Contract).filter(func.lower(Contract.address) == address.lower()).delete()
    db_session.query(Job).filter(func.lower(Job.address) == address.lower()).delete()
    db_session.commit()
    job = Job(address=address, status=JobStatus.completed, stage=JobStage.done, request={"chain": chain})
    db_session.add(job)
    db_session.flush()
    contract = Contract(address=address, chain=chain, job_id=job.id)
    db_session.add(contract)
    db_session.flush()
    db_session.add(
        EffectiveFunction(
            contract_id=contract.id,
            function_name="pause",
            abi_signature="pause()",
            selector=_PAUSE,
            capability_expr=capability_expr,
        )
    )
    db_session.commit()
    return job


@requires_postgres
def test_reconciler_reenqueues_only_when_authority_backfilled(db_session):
    authority = "0x" + "a1" * 20
    teller = "0x" + "b2" * 20
    job = _seed_completed_job_with_cap(db_session, address=teller, capability_expr=_deferred_cap(authority))

    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0
    assert job.status == JobStatus.completed and job.stage == JobStage.done

    _seed_role_cursors(db_session, authority, backfill_complete=False)
    db_session.commit()
    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0
    assert job.stage == JobStage.done

    for cur in db_session.execute(
        select(IndexedEventCursor).where(IndexedEventCursor.event_address == authority.lower())
    ).scalars():
        cur.backfill_complete = True
    db_session.commit()
    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 1
    assert job.status == JobStatus.queued and job.stage == JobStage.policy

    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0


# ``contracts.job_id`` is SET NULL on job deletion, stranding the contract's rows outside the reconciler; these pin the
# shape, not the count.


def _seed_orphaned_contract(
    db_session,
    *,
    address: str,
    capability_expr: dict,
    chain: str = "ethereum",
    with_job: bool = True,
) -> Job | None:
    db_session.query(Contract).filter(func.lower(Contract.address) == address.lower()).delete()
    db_session.query(Job).filter(func.lower(Job.address) == address.lower()).delete()
    db_session.commit()
    job = None
    if with_job:
        job = Job(address=address, status=JobStatus.completed, stage=JobStage.done, request={"chain": chain})
        db_session.add(job)
        db_session.flush()
    contract = Contract(address=address, chain=chain, job_id=None)
    db_session.add(contract)
    db_session.flush()
    db_session.add(
        EffectiveFunction(
            contract_id=contract.id,
            function_name="pause",
            abi_signature="pause()",
            selector=_PAUSE,
            capability_expr=capability_expr,
        )
    )
    db_session.commit()
    return job


@requires_postgres
def test_orphaned_contract_is_relinked_and_reenqueued_once_warm(db_session):
    """The linkage must be repaired before re-enqueue, or the re-run writes zero rows and loops."""
    authority = "0x" + "a9" * 20
    addr = "0x" + "ba" * 20
    job = _seed_orphaned_contract(db_session, address=addr, capability_expr=_deferred_cap(authority))
    assert job is not None

    _seed_role_cursors(db_session, authority, backfill_complete=False)
    db_session.commit()
    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0
    assert job.stage == JobStage.done

    for cur in db_session.execute(
        select(IndexedEventCursor).where(IndexedEventCursor.event_address == authority.lower())
    ).scalars():
        cur.backfill_complete = True
    db_session.commit()

    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 1
    assert job.status == JobStatus.queued and job.stage == JobStage.policy

    contract = db_session.execute(select(Contract).where(func.lower(Contract.address) == addr.lower())).scalar_one()
    assert contract.job_id == job.id

    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0


@requires_postgres
def test_orphan_with_no_job_at_its_address_is_left_alone(db_session):
    """Job deletion takes its artifacts too, so a contract with no job at its address can't be re-resolved and must
    stay at zero.
    """
    authority = "0x" + "ab" * 20
    addr = "0x" + "bc" * 20
    _seed_orphaned_contract(db_session, address=addr, capability_expr=_deferred_cap(authority), with_job=False)
    _seed_role_cursors(db_session, authority, backfill_complete=True)
    db_session.commit()

    from services.resolution.deferred_reconciler import _unreachable_orphan_contracts

    for _ in range(3):
        assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0
    assert (
        db_session.execute(select(Contract.job_id).where(func.lower(Contract.address) == addr.lower())).scalar() is None
    )

    stranded_before = _unreachable_orphan_contracts(db_session, 1)
    assert stranded_before >= 1
    db_session.add(Job(address=addr, status=JobStatus.completed, stage=JobStage.done, request={"chain": "ethereum"}))
    db_session.commit()
    assert _unreachable_orphan_contracts(db_session, 1) == stranded_before - 1
    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 1


@requires_postgres
def test_orphan_adoption_never_steals_a_contract_from_a_job_that_has_one(db_session):
    """Adopting would give one job two contracts."""
    authority = "0x" + "ad" * 20
    orphan_addr = "0x" + "be" * 20
    other_addr = "0x" + "bf" * 20

    db_session.query(Contract).filter(
        func.lower(Contract.address).in_([orphan_addr.lower(), other_addr.lower()])
    ).delete()
    db_session.query(Job).filter(func.lower(Job.address) == orphan_addr.lower()).delete()
    db_session.commit()

    job = Job(address=orphan_addr, status=JobStatus.completed, stage=JobStage.done, request={"chain": "ethereum"})
    db_session.add(job)
    db_session.flush()
    owned = Contract(address=other_addr, chain="ethereum", job_id=job.id)
    db_session.add(owned)
    orphan = Contract(address=orphan_addr, chain="ethereum", job_id=None)
    db_session.add(orphan)
    db_session.flush()
    db_session.add(
        EffectiveFunction(
            contract_id=orphan.id,
            function_name="pause",
            abi_signature="pause()",
            selector=_PAUSE,
            capability_expr=_deferred_cap(authority),
        )
    )
    _seed_role_cursors(db_session, authority, backfill_complete=True)
    db_session.commit()

    from services.resolution.deferred_reconciler import _orphaned_marker_rows

    assert all(row[3] != orphan.id for row in _orphaned_marker_rows(db_session, 1))

    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0
    db_session.refresh(orphan)
    assert orphan.job_id is None
    assert job.stage == JobStage.done


# The warm self-heal for an enumerated role store drifting past its folded frontier.


def _role_store_cap(authority: str, frontier: int, members=("0x" + "ab" * 20,)) -> dict:
    return capability_to_dict(
        CapabilityExpr.finite_set(
            [m.lower() for m in members],
            quality="exact",
            confidence="enumerable",
            last_indexed_block=frontier,
            trace=[
                {
                    "step": TRACE_STEP_ENUMERABLE_ROLE_STORE,
                    "authority": authority.lower(),
                    "fold_frontier": frontier,
                    "standard": "solady_enumerable_roles",
                }
            ],
        )
    )


def _seed_role_store_cursor(
    session, authority: str, *, backfill_complete: bool = True, last_block: int = 10_000
) -> None:
    session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=authority.lower(),
            topic0=_ROLE_SET_TOPIC0.lower(),
            last_indexed_block=last_block,
            backfill_complete=backfill_complete,
            first_indexed_block=0,
            first_indexed_block_basis="creation_block_minus_one",
        )
    )


def _seed_role_set_row(session, authority: str, *, block: int) -> None:
    session.add(
        IndexedEventLog(
            chain_id=1,
            event_address=authority.lower(),
            topic0=_ROLE_SET_TOPIC0.lower(),
            tx_hash=block.to_bytes(32, "big"),
            log_index=0,
            block_number=block,
            block_hash=b"\x00" * 32,
            transaction_index=0,
            topics=[_ROLE_SET_TOPIC0.lower()],
            data_words=[],
        )
    )


def test_iter_role_store_frontiers_walks_nested():
    auth = "0x" + "a1" * 20
    cap = CapabilityExpr.structural_and(
        [
            CapabilityExpr.finite_set(["0x" + "b2" * 20]),
            CapabilityExpr.finite_set(
                ["0x" + "c3" * 20],
                trace=[{"step": TRACE_STEP_ENUMERABLE_ROLE_STORE, "authority": auth, "fold_frontier": 42}],
            ),
        ]
    )
    assert set(_iter_role_store_frontiers(capability_to_dict(cap))) == {(auth, 42)}
    frontierless = {"trace": [{"step": TRACE_STEP_ENUMERABLE_ROLE_STORE, "authority": auth}]}
    assert list(_iter_role_store_frontiers(frontierless)) == []


@requires_postgres
def test_drift_reenqueues_on_post_frontier_row(db_session):
    authority = "0x" + "a4" * 20
    addr = "0x" + "b5" * 20
    job = _seed_completed_job_with_cap(db_session, address=addr, capability_expr=_role_store_cap(authority, 100))
    _seed_role_store_cursor(db_session, authority, backfill_complete=True)
    _seed_role_set_row(db_session, authority, block=200)  # a grant past the frontier
    db_session.commit()

    assert reconcile_role_set_drift(db_session, chain_id=1) == 1
    assert job.status == JobStatus.queued and job.stage == JobStage.policy


@requires_postgres
def test_drift_requires_backfill_complete(db_session):
    # Mid-backfill would re-resolve into a cold deferral.
    authority = "0x" + "a8" * 20
    addr = "0x" + "b9" * 20
    job = _seed_completed_job_with_cap(db_session, address=addr, capability_expr=_role_store_cap(authority, 100))
    _seed_role_store_cursor(db_session, authority, backfill_complete=False)
    _seed_role_set_row(db_session, authority, block=200)
    db_session.commit()

    assert reconcile_role_set_drift(db_session, chain_id=1) == 0
    assert job.stage == JobStage.done
