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


def _seed_role_cursors(session, authority: str, *, backfill_complete: bool, last_block: int = 10_000) -> None:
    for topic0 in _ROLE_TOPICS:
        session.add(
            IndexedEventCursor(
                chain_id=1,
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


def _seed_completed_job_with_cap(db_session, *, address: str, capability_expr: dict) -> Job:
    # Isolation: the conftest ``db_session`` teardown clears Contract (cascading
    # EffectiveFunction) + cursors but NOT Job rows. Since these tests re-enqueue
    # a job to status=queued, a prior run's leaked job would trip the reconciler's
    # legitimate "address already has an active job" guard. Purge any prior rows
    # for this address first so each run starts clean.
    db_session.query(Contract).filter(func.lower(Contract.address) == address.lower()).delete()
    db_session.query(Job).filter(func.lower(Job.address) == address.lower()).delete()
    db_session.commit()
    job = Job(address=address, status=JobStatus.completed, stage=JobStage.done, request={"chain": "ethereum"})
    db_session.add(job)
    db_session.flush()
    contract = Contract(address=address, chain="ethereum", job_id=job.id)
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
    assert reconcile_deferred_resolutions(db_session) == 0
    assert job.status == JobStatus.completed and job.stage == JobStage.done

    # (b) Cursor exists but backfill not complete → thrash guard holds.
    _seed_role_cursors(db_session, authority, backfill_complete=False)
    db_session.commit()
    assert reconcile_deferred_resolutions(db_session) == 0
    assert job.stage == JobStage.done

    # (c) Backfill complete → re-enqueue the policy stage.
    for cur in db_session.execute(
        select(IndexedEventCursor).where(IndexedEventCursor.event_address == authority.lower())
    ).scalars():
        cur.backfill_complete = True
    db_session.commit()
    assert reconcile_deferred_resolutions(db_session) == 1
    assert job.status == JobStatus.queued and job.stage == JobStage.policy

    # (d) Idempotent: the job is no longer completed/done, so a second pass is a
    # no-op (no re-enqueue storm).
    assert reconcile_deferred_resolutions(db_session) == 0


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

    assert reconcile_deferred_resolutions(db_session) == 0
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

    assert reconcile_deferred_resolutions(db_session) == 0
    assert job.stage == JobStage.done


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

    assert reconcile_role_set_drift(db_session) == 1
    assert job.status == JobStatus.queued and job.stage == JobStage.policy


@requires_postgres
def test_drift_ignores_pre_frontier_row(db_session):
    authority = "0x" + "a6" * 20
    addr = "0x" + "b7" * 20
    job = _seed_completed_job_with_cap(db_session, address=addr, capability_expr=_role_store_cap(authority, 100))
    _seed_role_store_cursor(db_session, authority, backfill_complete=True)
    _seed_role_set_row(db_session, authority, block=50)  # already folded (<= frontier)
    db_session.commit()

    assert reconcile_role_set_drift(db_session) == 0
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

    assert reconcile_role_set_drift(db_session) == 0
    assert job.stage == JobStage.done


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

    assert reconcile_role_set_drift(db_session) == 0
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
