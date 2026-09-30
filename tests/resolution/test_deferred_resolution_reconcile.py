"""Regression: index-cold capability deferrals self-heal once the durable event index
catches up (the event-indexer cold-start resolution race).

A privileged function whose authority isn't indexed at analysis time resolves cold to
``external_check_only`` (basis ``no_index_cursor``): fail-safe but *sticky*, since nothing
recomputes it after backfill. Two adapter-agnostic halves are pinned:

  1. The index-cold path tags its ``external_check_only`` with
     ``check.extra.deferred_pending_index = True`` (ONLY that basis, never warm-but-empty
     or missing-context), and the SAME resolver folds to the concrete set once indexed.
     Pinned against the REAL ``PostgresEventLogRepo`` using etherfi's captured logs.
  2. ``reconcile_deferred_resolutions`` re-enqueues the *policy* stage of a completed job
     whose deferred authorities are now ``backfill_complete``, and leaves still-cold jobs
     (no thrash) and non-deferred external checks (true negatives) untouched.
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
from services.resolution.adapters.event_indexed import EventIndexedAdapter
from services.resolution.adapters.solmate_roles import (
    _ROLE_TOPICS,
    CANCALL_SELECTOR,
    CANCALL_SIGNATURE,
    SolmateRolesAuthorityAdapter,
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
_SAFE_4_6 = "0xcea8039076e35a825854c5c2f85659430b06ec96"
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
        event_log_repo=repo,
        state_var_values={"authority": authority},
        call_frame=CallFrame.root(contract_address=teller, function_signature=None, function_selector=selector),
    )


def _seed_role_logs(session, authority: str) -> None:
    """Insert the captured RolesAuthority logs into ``indexed_event_logs``.

    Synthetic monotonic ``(block_number, tx, log_index)`` keeps the fixture's log order (the
    canCall fold depends on it) after ``PostgresEventLogRepo`` re-sorts.
    """
    for i, log in enumerate(_fixture()["logs"]):
        data = log.get("data") or "0x"
        body = data[2:] if isinstance(data, str) and data.startswith("0x") else ""
        data_words = ["0x" + body[j : j + 64] for j in range(0, len(body), 64)] if body else []
        session.add(
            IndexedEventLog(
                chain_id=1,
                event_address=authority.lower(),
                topic0=str(log["topics"][0]).lower(),
                tx_hash=i.to_bytes(32, "big"),
                log_index=0,
                block_number=i,
                block_hash=b"\x00" * 32,
                transaction_index=0,
                topics=[str(t).lower() for t in log["topics"]],
                data_words=data_words,
            )
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
            )
        )


# ---------------------------------------------------------------------------
# Half 1 — adapters tag index-cold deferrals, and the SAME resolver self-heals
# once the events are durably indexed (real PostgresEventLogRepo + DB).
# ---------------------------------------------------------------------------


@requires_postgres
def test_solmate_cold_index_defers_with_marker(db_session):
    fixture = _fixture()
    authority, teller = fixture["authority"].lower(), fixture["teller"].lower()
    cap = SolmateRolesAuthorityAdapter().enumerate(
        _descriptor(), _ctx(PostgresEventLogRepo(db_session), teller, authority, _PAUSE)
    )
    assert cap.kind == "external_check_only"
    assert cap.check is not None
    assert cap.check.extra.get("basis") == ["no_index_cursor"]
    # The marker the reconciler keys on; without it the cold result sticks forever.
    assert cap.check.extra.get(DEFERRED_MARKER) is True
    assert cap.check.target_address == authority


@requires_postgres
def test_solmate_warm_index_self_heals_to_concrete_caller(db_session):
    fixture = _fixture()
    authority, teller = fixture["authority"].lower(), fixture["teller"].lower()
    _seed_role_logs(db_session, authority)
    _seed_role_cursors(db_session, authority, backfill_complete=True)
    db_session.commit()

    cap = SolmateRolesAuthorityAdapter().enumerate(
        _descriptor(), _ctx(PostgresEventLogRepo(db_session), teller, authority, _PAUSE)
    )
    assert cap.kind == "finite_set"
    assert _SAFE_4_6 in (cap.members or [])
    assert cap.membership_quality == "exact"
    assert capability_to_dict(cap).get("check") is None


@requires_postgres
def test_solmate_backfill_incomplete_cursor_still_defers(db_session):
    # A mid-backfill cursor must still read as cold, else partial history folds as exact.
    fixture = _fixture()
    authority, teller = fixture["authority"].lower(), fixture["teller"].lower()
    _seed_role_cursors(db_session, authority, backfill_complete=False)
    db_session.commit()
    cap = SolmateRolesAuthorityAdapter().enumerate(
        _descriptor(), _ctx(PostgresEventLogRepo(db_session), teller, authority, _PAUSE)
    )
    assert cap.kind == "external_check_only"
    assert cap.check is not None
    assert cap.check.extra.get(DEFERRED_MARKER) is True


def test_event_indexed_marks_only_no_index_cursor_as_deferred():
    adapter = EventIndexedAdapter()
    descriptor = {"callee_selector": "0x12345678", "callee_function": "f"}
    hint = {"topic0": "0x" + "ab" * 32, "direction": "add", "event_address": "0x" + "a1" * 20}
    ctx = EvaluationContext(chain_id=1, contract_address="0x" + "11" * 20)

    cold = adapter._external_check(descriptor, hint, ctx, ["no_index_cursor", "no_hypersync_token"])
    assert cold.check is not None
    assert cold.check.extra[DEFERRED_MARKER] is True

    structural = adapter._external_check(descriptor, hint, ctx, ["event_address_unresolved"])
    assert structural.check is not None
    assert DEFERRED_MARKER not in structural.check.extra


def test_iter_deferred_authorities_walks_nested_and_skips_plain():
    auth = "0x" + "a1" * 20
    deferred_leaf = CapabilityExpr.external_check_only(
        ExternalCheck(target_address=auth, target_call_selector=CANCALL_SELECTOR, extra={DEFERRED_MARKER: True})
    )
    tree = CapabilityExpr.structural_and([CapabilityExpr.finite_set(["0x" + "b2" * 20]), deferred_leaf])
    assert set(_iter_deferred_authorities(capability_to_dict(tree))) == {auth}

    plain = CapabilityExpr.external_check_only(
        ExternalCheck(target_address="0x" + "c3" * 20, target_call_selector="0xdeadbeef", extra={"basis": ["eip1271"]})
    )
    assert list(_iter_deferred_authorities(capability_to_dict(plain))) == []


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


# ---------------------------------------------------------------------------
# Half 2 — the reconciler re-enqueues policy only when the index has caught up.
# ---------------------------------------------------------------------------


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
    # conftest ``db_session`` teardown does NOT clear Job rows, and these tests re-enqueue
    # a job to queued; a leaked job would trip the "active job" guard. Purge first.
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

    # Idempotent: the job is no longer completed/done, so a second pass is a no-op.
    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0


@requires_postgres
def test_reconciler_skips_when_address_has_an_active_job(db_session):
    # An in-flight re-analysis for the same address blocks a second job.
    authority = "0x" + "e5" * 20
    addr = "0x" + "f6" * 20
    job = _seed_completed_job_with_cap(db_session, address=addr, capability_expr=_deferred_cap(authority))
    _seed_role_cursors(db_session, authority, backfill_complete=True)
    db_session.add(Job(address=addr, status=JobStatus.processing, stage=JobStage.policy, request={"chain": "ethereum"}))
    db_session.commit()

    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0
    assert job.status == JobStatus.completed and job.stage == JobStage.done


@requires_postgres
def test_reconciler_ignores_non_deferred_external_check(db_session):
    # A genuine external check (no deferred marker) is never re-enqueued.
    target = "0x" + "c3" * 20
    plain = capability_to_dict(
        CapabilityExpr.external_check_only(
            ExternalCheck(target_address=target, target_call_selector="0xdeadbeef", extra={"basis": ["eip1271"]})
        )
    )
    job = _seed_completed_job_with_cap(db_session, address="0x" + "d4" * 20, capability_expr=plain)
    _seed_role_cursors(db_session, target, backfill_complete=True)
    db_session.commit()

    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0
    assert job.stage == JobStage.done


@requires_postgres
def test_reconciler_does_not_select_off_chain_twin(db_session):
    # The same authority being warm on chain 1 must not re-enqueue a base deployment
    # (base index still cold): the row-select is scoped to the pass's chain.
    authority = "0x" + "e5" * 20
    addr = "0x" + "f6" * 20
    base_job = _seed_completed_job_with_cap(
        db_session, address=addr, capability_expr=_deferred_cap(authority), chain="base"
    )
    _seed_role_cursors(db_session, authority, backfill_complete=True, chain_id=1)  # warm on ethereum
    _seed_role_cursors(db_session, authority, backfill_complete=False, chain_id=8453)  # still cold on base
    db_session.commit()

    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0
    assert base_job.status == JobStatus.completed and base_job.stage == JobStage.done


# ---------------------------------------------------------------------------
# Half 2b - the ORPHANED-CONTRACT class. ``contracts.job_id`` is ``ON DELETE SET NULL``
# and every stage finds its contract through it, so deleting a job strands the
# contract's rows outside the reconciler forever. 2 contracts / 32 marker rows locally
# (a LOWER bound), so these tests pin the SHAPE, not the number.
# ---------------------------------------------------------------------------


def _seed_orphaned_contract(
    db_session,
    *,
    address: str,
    capability_expr: dict,
    chain: str = "ethereum",
    with_job: bool = True,
) -> Job | None:
    """A marker-bearing contract with NULL ``job_id`` (what job deletion leaves behind),
    optionally with a completed job at the same ``(address, chain)``."""
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
def test_orphaned_contract_marker_rows_are_reachable_at_all(db_session):
    """Reachability: the old inner join on ``Contract.job_id == Job.id`` returned NOTHING
    for these rows. Pins the shape (a (job, orphan contract) pair), not the corpus count."""
    from services.resolution.deferred_reconciler import _orphaned_marker_rows

    authority = "0x" + "a7" * 20
    addr = "0x" + "b8" * 20
    job = _seed_orphaned_contract(db_session, address=addr, capability_expr=_deferred_cap(authority))
    assert job is not None

    linked = db_session.execute(
        select(func.count())
        .select_from(Contract)
        .join(Job, Contract.job_id == Job.id)
        .where(func.lower(Contract.address) == addr.lower())
    ).scalar()
    assert linked == 0

    rows = _orphaned_marker_rows(db_session, 1)
    pairs = {(row[0], row[3]) for row in rows}
    contract_id = db_session.execute(select(Contract.id).where(func.lower(Contract.address) == addr.lower())).scalar()
    assert (job.id, contract_id) in pairs


@requires_postgres
def test_orphaned_contract_is_relinked_and_reenqueued_once_warm(db_session):
    """The fix end to end. The policy stage writes ``effective_functions`` for
    ``Contract.job_id == job.id``, so the linkage must be REPAIRED before re-enqueue, or
    the re-run writes zero rows and the same job is handed back every pass."""
    authority = "0x" + "a9" * 20
    addr = "0x" + "ba" * 20
    job = _seed_orphaned_contract(db_session, address=addr, capability_expr=_deferred_cap(authority))
    assert job is not None

    # Still cold → the orphan route inherits the same thrash guard.
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
    """The residue, and why this is not a re-enqueue storm. Deleting a job deletes its
    artifacts too, so a contract with no job at its ``(address, chain)`` cannot be
    re-resolved; repeated passes must stay at zero.

    This is the local corpus's actual shape (contracts 79 and 640 have no job at all), so
    those 32 rows stay unconverged; stated in the commit, not papered over here."""
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

    # The residue is COUNTED, and a completed job at its (address, chain) moves it into
    # the convergeable set.
    stranded_before = _unreachable_orphan_contracts(db_session, 1)
    assert stranded_before >= 1
    db_session.add(Job(address=addr, status=JobStatus.completed, stage=JobStage.done, request={"chain": "ethereum"}))
    db_session.commit()
    assert _unreachable_orphan_contracts(db_session, 1) == stranded_before - 1
    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 1


@requires_postgres
def test_orphan_adoption_never_steals_a_contract_from_a_job_that_has_one(db_session):
    """Keeps the route to EXACTLY the orphaned class: a candidate job that already owns a
    contract row is the ``copy_static_cache`` reassignment shape, and adopting would give
    one job two contracts."""
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

    # Pinned at the query level too: without this arm the query guard and the loop's
    # same-transaction re-check cover for each other.
    from services.resolution.deferred_reconciler import _orphaned_marker_rows

    assert all(row[3] != orphan.id for row in _orphaned_marker_rows(db_session, 1))

    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0
    db_session.refresh(orphan)
    assert orphan.job_id is None
    assert job.stage == JobStage.done


@requires_postgres
def test_orphan_adoption_is_chain_scoped(db_session):
    """``contracts`` is scoped only by the string ``chain``, so the orphan route keys on
    ``(address, chain)``: a base orphan is not adopted by a chain-1 pass."""
    authority = "0x" + "ae" * 20
    addr = "0x" + "c1" * 20

    db_session.query(Contract).filter(func.lower(Contract.address) == addr.lower()).delete()
    db_session.query(Job).filter(func.lower(Job.address) == addr.lower()).delete()
    db_session.commit()

    eth_job = Job(address=addr, status=JobStatus.completed, stage=JobStage.done, request={"chain": "ethereum"})
    db_session.add(eth_job)
    db_session.flush()
    base_orphan = Contract(address=addr, chain="base", job_id=None)
    db_session.add(base_orphan)
    db_session.flush()
    db_session.add(
        EffectiveFunction(
            contract_id=base_orphan.id,
            function_name="pause",
            abi_signature="pause()",
            selector=_PAUSE,
            capability_expr=_deferred_cap(authority),
        )
    )
    _seed_role_cursors(db_session, authority, backfill_complete=True, chain_id=1)
    db_session.commit()

    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0
    db_session.refresh(base_orphan)
    assert base_orphan.job_id is None
    assert eth_job.stage == JobStage.done


@requires_postgres
def test_two_candidate_jobs_adopt_the_orphan_exactly_once(db_session):
    """``contracts`` is unique on ``(address, chain)``, so one orphan can have SEVERAL
    completed contract-less jobs. Exactly one may adopt it; the other must be skipped."""
    authority = "0x" + "c3" * 20
    addr = "0x" + "c4" * 20

    db_session.query(Contract).filter(func.lower(Contract.address) == addr.lower()).delete()
    db_session.query(Job).filter(func.lower(Job.address) == addr.lower()).delete()
    db_session.commit()

    jobs = []
    for _ in range(2):
        job = Job(address=addr, status=JobStatus.completed, stage=JobStage.done, request={"chain": "ethereum"})
        db_session.add(job)
        db_session.flush()
        jobs.append(job)
    orphan = Contract(address=addr, chain="ethereum", job_id=None)
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

    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 1
    db_session.refresh(orphan)
    assert orphan.job_id in {j.id for j in jobs}
    requeued = [j for j in jobs if j.stage == JobStage.policy]
    assert len(requeued) == 1
    assert requeued[0].id == orphan.job_id
    assert (
        db_session.execute(select(func.count()).select_from(Contract).where(Contract.job_id == requeued[0].id)).scalar()
        == 1
    )


@requires_postgres
def test_orphan_route_ignores_a_non_deferred_external_check(db_session):
    """True negatives stay negative on the orphan route: no deferred marker, never
    re-enqueued, even with a warm cursor on its target."""
    target = "0x" + "af" * 20
    addr = "0x" + "c2" * 20
    plain = capability_to_dict(
        CapabilityExpr.external_check_only(
            ExternalCheck(target_address=target, target_call_selector="0xdeadbeef", extra={"basis": ["eip1271"]})
        )
    )
    job = _seed_orphaned_contract(db_session, address=addr, capability_expr=plain)
    assert job is not None
    _seed_role_cursors(db_session, target, backfill_complete=True)
    db_session.commit()

    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0
    contract = db_session.execute(select(Contract).where(func.lower(Contract.address) == addr.lower())).scalar_one()
    assert contract.job_id is None
    assert job.stage == JobStage.done


@requires_postgres
def test_reconciler_active_job_check_is_chain_scoped(db_session):
    # Same address on two chains: an in-flight base twin must not block the ethereum
    # re-enqueue (the active-job guard is per chain).
    authority = "0x" + "c1" * 20
    addr = "0x" + "d2" * 20
    eth_job = _seed_completed_job_with_cap(
        db_session, address=addr, capability_expr=_deferred_cap(authority), chain="ethereum"
    )
    _seed_role_cursors(db_session, authority, backfill_complete=True, chain_id=1)
    db_session.add(Job(address=addr, status=JobStatus.processing, stage=JobStage.policy, request={"chain": "base"}))
    db_session.commit()

    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 1
    assert eth_job.status == JobStatus.queued and eth_job.stage == JobStage.policy


# ---------------------------------------------------------------------------
# Stage 4 — role-drift arm: re-resolve an enumerated role store when a grant/
# revoke is indexed past the trace's folded frontier (the warm self-heal).
# ---------------------------------------------------------------------------


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
    # A step without a numeric frontier is skipped (defensive).
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
def test_drift_ignores_pre_frontier_row(db_session):
    authority = "0x" + "a6" * 20
    addr = "0x" + "b7" * 20
    job = _seed_completed_job_with_cap(db_session, address=addr, capability_expr=_role_store_cap(authority, 100))
    _seed_role_store_cursor(db_session, authority, backfill_complete=True)
    _seed_role_set_row(db_session, authority, block=50)  # already folded (<= frontier)
    db_session.commit()

    assert reconcile_role_set_drift(db_session, chain_id=1) == 0
    assert job.stage == JobStage.done


@requires_postgres
def test_drift_requires_backfill_complete(db_session):
    # A post-frontier row while the cursor is mid-backfill would re-resolve into a
    # cold deferral — gate on backfill_complete so the re-run lands a warm fold.
    authority = "0x" + "a8" * 20
    addr = "0x" + "b9" * 20
    job = _seed_completed_job_with_cap(db_session, address=addr, capability_expr=_role_store_cap(authority, 100))
    _seed_role_store_cursor(db_session, authority, backfill_complete=False)
    _seed_role_set_row(db_session, authority, block=200)
    db_session.commit()

    assert reconcile_role_set_drift(db_session, chain_id=1) == 0
    assert job.stage == JobStage.done


@requires_postgres
def test_drift_row_select_is_chain_scoped(db_session):
    # A base job's enumerated role store must not be re-enqueued by a chain-1
    # drift pass. The post-frontier grant + warm cursor live on chain 1; the base
    # job's own index is unrelated, so a chain-1 pass must not select it.
    authority = "0x" + "ac" * 20
    addr = "0x" + "bd" * 20
    base_job = _seed_completed_job_with_cap(
        db_session, address=addr, capability_expr=_role_store_cap(authority, 100), chain="base"
    )
    _seed_role_store_cursor(db_session, authority, backfill_complete=True)  # chain_id=1
    _seed_role_set_row(db_session, authority, block=200)  # chain_id=1 grant past frontier
    db_session.commit()

    assert reconcile_role_set_drift(db_session, chain_id=1) == 0
    assert base_job.status == JobStatus.completed and base_job.stage == JobStage.done


@requires_postgres
def test_drift_ignores_non_role_store_capability(db_session):
    # A deferred (non-enumerated) cap has no enumerable_role_store trace step → the
    # drift arm never selects it (that's the cold reconciler's job, not this one).
    authority = "0x" + "aa" * 20
    addr = "0x" + "bb" * 20
    job = _seed_completed_job_with_cap(db_session, address=addr, capability_expr=_deferred_cap(authority))
    _seed_role_store_cursor(db_session, authority, backfill_complete=True)
    _seed_role_set_row(db_session, authority, block=200)
    db_session.commit()

    assert reconcile_role_set_drift(db_session, chain_id=1) == 0
    assert job.stage == JobStage.done


# ---------------------------------------------------------------------------
# Wiring — the self-heal must be invoked by the event indexer loop so it can't
# be silently unwired.
# ---------------------------------------------------------------------------


def test_event_indexer_loop_invokes_deferred_reconciler():
    import inspect

    from workers import event_log_indexer

    src = inspect.getsource(event_log_indexer.run_event_log_indexer_loop)
    assert "drain_reconciliation" in src
    from services.resolution import indexer_scheduler

    scheduler_src = inspect.getsource(indexer_scheduler.drain_reconciliation)
    assert "reconcile_deferred_resolutions" in scheduler_src
    assert "reconcile_role_set_drift" in scheduler_src
