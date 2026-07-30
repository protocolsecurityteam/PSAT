"""Regression: index-cold capability deferrals self-heal once the durable event
index catches up — the event-indexer cold-start resolution race.

The bug: a privileged function whose authority isn't durably indexed at
analysis time resolves cold to ``external_check_only`` (basis
``no_index_cursor``). That is fail-safe but *sticky* — it lands in
``EffectiveFunction`` / ``FunctionPrincipal`` / ``effective_permissions`` and
nothing recomputes it once the index backfills, so the function shows "no
controller" forever (until a manual re-analysis).

The fix has two adapter-agnostic halves, pinned here:

  1. The index-cold path tags its ``external_check_only`` with
     ``check.extra.deferred_pending_index = True`` — and ONLY that basis, never a
     warm-but-empty authority or a missing-context unresolved. Once the
     authority's role events are durably indexed, the SAME resolver folds them to
     the concrete caller set. Pinned end-to-end against the REAL
     ``PostgresEventLogRepo`` + DB using etherfi's captured RolesAuthority logs.

  2. ``reconcile_deferred_resolutions`` re-enqueues the *policy* stage of a
     completed job whose deferred authorities are now ``backfill_complete`` — and
     leaves jobs whose index is still cold untouched (no thrash) and jobs with a
     non-deferred external check untouched (true negatives stay negative).

If either half regresses, the cold result silently sticks forever — the
original Problem 2.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import func, select  # noqa: E402

from db.models import (  # noqa: E402
    Contract,
    EffectiveFunction,
    IndexedEventCursor,
    IndexedEventLog,
    Job,
    JobStage,
    JobStatus,
)
from services.resolution.adapters import CallFrame, EvaluationContext  # noqa: E402
from services.resolution.adapters.event_indexed import EventIndexedAdapter  # noqa: E402
from services.resolution.adapters.solmate_roles import (  # noqa: E402
    _ROLE_TOPICS,
    CANCALL_SELECTOR,
    CANCALL_SIGNATURE,
    SolmateRolesAuthorityAdapter,
)
from services.resolution.capabilities import CapabilityExpr, ExternalCheck  # noqa: E402
from services.resolution.capability_resolver import capability_to_dict  # noqa: E402
from services.resolution.deferred_reconciler import (  # noqa: E402
    DEFERRED_MARKER,
    ROLE_STORE_TRACE_STEP,
    _iter_deferred_authorities,
    _iter_role_store_frontiers,
    reconcile_deferred_resolutions,
    reconcile_role_set_drift,
)
from services.resolution.repos.event_logs_pg import PostgresEventLogRepo  # noqa: E402
from services.resolution.role_store_standards import SOLADY_ENUMERABLE_ROLES  # noqa: E402
from tests.conftest import requires_postgres  # noqa: E402

_ROLE_SET_TOPIC0 = SOLADY_ENUMERABLE_ROLES.grant_events[0].topic0

_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "solmate" / "roles_authority_3994741a.json"
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

    Synthetic monotonic ``(block_number, tx, log_index)`` per array index keeps
    rows in the fixture's log order (the order the canCall fold depends on) once
    ``PostgresEventLogRepo`` re-sorts them, independent of the fixture's stored
    block numbers.
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
    # No cursor, no logs for the authority — the index is cold.
    cap = SolmateRolesAuthorityAdapter().enumerate(
        _descriptor(), _ctx(PostgresEventLogRepo(db_session), teller, authority, _PAUSE)
    )
    assert cap.kind == "external_check_only"
    assert cap.check is not None
    assert cap.check.extra.get("basis") == ["no_index_cursor"]
    # The marker the reconciler keys on — without it the cold result is invisible
    # to the self-heal and sticks forever.
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
    # The exact same resolver call now folds the indexed role events to the
    # governing 4/6 Safe — a concrete caller, exact membership.
    assert cap.kind == "finite_set"
    assert _SAFE_4_6 in (cap.members or [])
    assert cap.membership_quality == "exact"
    # No external_check leaf remains, so there's nothing left for the reconciler
    # to retry — the deferral is fully healed.
    assert capability_to_dict(cap).get("check") is None


@requires_postgres
def test_solmate_backfill_incomplete_cursor_still_defers(db_session):
    # A cursor that EXISTS but is mid-backfill must still be treated as cold
    # (min_indexed_block gates on backfill_complete) — otherwise a partial
    # history would be folded as if exact.
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
    # Generic adapter (AccessControl / mapping ACLs): the marker is set on the
    # index-cold basis and NOT on structural/transient bases.
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
    # Deferred leaf nested inside an AND with a side path — must still be found.
    tree = CapabilityExpr.structural_and([CapabilityExpr.finite_set(["0x" + "b2" * 20]), deferred_leaf])
    assert set(_iter_deferred_authorities(capability_to_dict(tree))) == {auth}

    # A plain external check (e.g. EIP-1271) carries no marker — not collected.
    plain = CapabilityExpr.external_check_only(
        ExternalCheck(target_address="0x" + "c3" * 20, target_call_selector="0xdeadbeef", extra={"basis": ["eip1271"]})
    )
    assert list(_iter_deferred_authorities(capability_to_dict(plain))) == []


def test_iter_deferred_authorities_handles_signer_and_non_dict():
    # A deferred check wrapped in a signature_witness (signer branch) is found...
    auth = "0x" + "d7" * 20
    witness = CapabilityExpr.signature_witness(
        CapabilityExpr.external_check_only(
            ExternalCheck(target_address=auth, target_call_selector=None, extra={DEFERRED_MARKER: True})
        )
    )
    assert set(_iter_deferred_authorities(capability_to_dict(witness))) == {auth}
    # ...and non-dict nodes are ignored (defensive walk over arbitrary JSON).
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
    # Isolation: the conftest ``db_session`` teardown clears Contract (cascading
    # EffectiveFunction) + cursors but NOT Job rows. Since these tests re-enqueue
    # a job to status=queued, a prior run's leaked job would trip the reconciler's
    # legitimate "address already has an active job" guard. Purge any prior rows
    # for this address first so each run starts clean.
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

    # (a) No cursor at all for the authority → still waiting → not re-enqueued.
    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0
    assert job.status == JobStatus.completed and job.stage == JobStage.done

    # (b) Cursor exists but backfill not complete → thrash guard holds.
    _seed_role_cursors(db_session, authority, backfill_complete=False)
    db_session.commit()
    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0
    assert job.stage == JobStage.done

    # (c) Backfill complete → re-enqueue the policy stage.
    for cur in db_session.execute(
        select(IndexedEventCursor).where(IndexedEventCursor.event_address == authority.lower())
    ).scalars():
        cur.backfill_complete = True
    db_session.commit()
    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 1
    assert job.status == JobStatus.queued and job.stage == JobStage.policy

    # (d) Idempotent: the job is no longer completed/done, so a second pass is a
    # no-op (no re-enqueue storm).
    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0


@requires_postgres
def test_reconciler_skips_when_address_has_an_active_job(db_session):
    # Even with the authority backfilled, don't re-enqueue if a re-analysis for
    # the same address is already in flight — no piling a second job on top.
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
    # A genuine external check (e.g. EIP-1271) with no deferred marker must never
    # be re-enqueued, even if some cursor for its target happens to be backfilled.
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
    # A base deployment's deferred authority must not be re-enqueued by a chain-1
    # pass merely because the SAME authority address is warm on chain 1. The base
    # index (chain 8453) is still cold, so re-resolving now would just re-defer —
    # premature churn. The row-select must be scoped to the pass's chain.
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
# Half 2b — the ORPHANED-CONTRACT class. ``contracts.job_id`` is
# ``ON DELETE SET NULL`` and every stage finds its contract through that column,
# so deleting a job strands its contract's rows outside the reconciler's reach
# for good: the deferred authority never resolves and the index-cold capability
# is published forever. 2 contracts / 32 marker rows on the local
# production-shaped DB (a LOWER bound — one protocol, one chain), which is why
# these tests pin the SHAPE and not the number.
# ---------------------------------------------------------------------------


def _seed_orphaned_contract(
    db_session,
    *,
    address: str,
    capability_expr: dict,
    chain: str = "ethereum",
    with_job: bool = True,
) -> Job | None:
    """A marker-bearing contract whose ``job_id`` is NULL — the exact state a job
    deletion leaves behind — optionally with a completed job still present at the
    same ``(address, chain)``."""
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
    """The reachability half, stated as its own assertion: before the fix the
    inner join on ``Contract.job_id == Job.id`` returned NOTHING for these rows,
    whatever the cursor state. Pins the shape (a (job, orphan contract) pair is
    produced), not the corpus count."""
    from services.resolution.deferred_reconciler import _orphaned_marker_rows

    authority = "0x" + "a7" * 20
    addr = "0x" + "b8" * 20
    job = _seed_orphaned_contract(db_session, address=addr, capability_expr=_deferred_cap(authority))
    assert job is not None

    # Control: the pre-fix query shape sees zero rows for this contract.
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
    """The fix end to end. Reaching the rows is not enough: the policy stage
    writes ``effective_functions`` for ``Contract.job_id == job.id``, so the
    linkage is REPAIRED before the re-enqueue. Without that repair the re-run
    would write zero rows, leave the marker in place, and hand the same job back
    on every subsequent pass."""
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

    # The linkage is repaired, so the policy re-run will actually rewrite the
    # marker rows instead of logging "no Contract row for job".
    contract = db_session.execute(select(Contract).where(func.lower(Contract.address) == addr.lower())).scalar_one()
    assert contract.job_id == job.id

    # Idempotent: the job is no longer completed/done.
    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0


@requires_postgres
def test_orphan_with_no_job_at_its_address_is_left_alone(db_session):
    """The residue, and the reason this is not a re-enqueue storm. Deleting a job
    deletes its artifacts and source files too, so a contract with no job at its
    ``(address, chain)`` cannot be re-resolved from anything on disk. Repeated
    passes must stay at zero rather than churning a job that would write nothing.

    This is the LOCAL CORPUS's actual shape: both orphaned marker-bearing
    contracts (79 AccountantWithRateProviders, 640 TellerWithMultiAssetSupport)
    have no job at their address at all, so the local 32 rows stay unconverged —
    stated in the commit, not papered over here."""
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

    # The residue is COUNTED rather than silently skipped, and the counter
    # discriminates: giving the contract a completed job at its (address, chain)
    # moves it out of the stranded set and into the convergeable one.
    stranded_before = _unreachable_orphan_contracts(db_session, 1)
    assert stranded_before >= 1
    db_session.add(Job(address=addr, status=JobStatus.completed, stage=JobStage.done, request={"chain": "ethereum"}))
    db_session.commit()
    assert _unreachable_orphan_contracts(db_session, 1) == stranded_before - 1
    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 1


@requires_postgres
def test_orphan_adoption_never_steals_a_contract_from_a_job_that_has_one(db_session):
    """The guard that keeps the new route to EXACTLY the orphaned class. A
    candidate job that already owns a contract row is not a candidate: that is
    the ``copy_static_cache`` reassignment shape, where the row legitimately
    belongs to the job it points at, and adopting would give one job two
    contracts."""
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
    # The job already owns a DIFFERENT contract row.
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

    # Pinned at the QUERY level too, not only at the outcome: the candidate pair
    # must never be planned. Without this arm the query guard and the
    # same-transaction re-check in the loop cover for each other, and neither is
    # individually pinned.
    from services.resolution.deferred_reconciler import _orphaned_marker_rows

    assert all(row[3] != orphan.id for row in _orphaned_marker_rows(db_session, 1))

    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0
    db_session.refresh(orphan)
    assert orphan.job_id is None
    assert job.stage == JobStage.done


@requires_postgres
def test_orphan_adoption_is_chain_scoped(db_session):
    """``contracts`` has no ``chain_id`` — its only scoping key is the string
    ``chain`` — so the orphan route keys on ``(address, chain)``, never the bare
    address. A base-chain orphan must not be adopted by a chain-1 pass that finds
    a chain-1 job at the same address; those are different deployments."""
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
    """The collapsed-inputs question asked of the new code itself: ``contracts``
    is unique on ``(address, chain)``, so one orphan can have SEVERAL completed
    contract-less jobs at its address. Exactly one may adopt it and be
    re-enqueued; the other has no contract to write and must be skipped, not
    handed a second claim on the same row."""
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
    # Exactly one contract row points at the winner, and none at the loser.
    assert (
        db_session.execute(select(func.count()).select_from(Contract).where(Contract.job_id == requeued[0].id)).scalar()
        == 1
    )


@requires_postgres
def test_orphan_route_ignores_a_non_deferred_external_check(db_session):
    """True negatives stay negative on the new route too: an orphaned contract
    whose external check carries no deferred marker is never re-enqueued, even
    with a warm cursor on its target."""
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
    # Same address deployed on two chains. The ethereum job's authority is warm on
    # chain 1 and should re-resolve; a base twin re-analysis is in flight
    # (processing). A chain-1 pass must not treat that base in-flight job as
    # blocking the ethereum re-enqueue — the active-job guard is per chain.
    authority = "0x" + "c1" * 20
    addr = "0x" + "d2" * 20
    eth_job = _seed_completed_job_with_cap(
        db_session, address=addr, capability_expr=_deferred_cap(authority), chain="ethereum"
    )
    _seed_role_cursors(db_session, authority, backfill_complete=True, chain_id=1)
    # A base twin re-analysis already in flight for the same address.
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
                    "step": ROLE_STORE_TRACE_STEP,
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
                trace=[{"step": ROLE_STORE_TRACE_STEP, "authority": auth, "fold_frontier": 42}],
            ),
        ]
    )
    assert set(_iter_role_store_frontiers(capability_to_dict(cap))) == {(auth, 42)}
    # A step without a numeric frontier is skipped (defensive).
    assert list(_iter_role_store_frontiers({"trace": [{"step": ROLE_STORE_TRACE_STEP, "authority": auth}]})) == []


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
    assert "reconcile_deferred_resolutions" in src
    assert "reconcile_role_set_drift" in src
