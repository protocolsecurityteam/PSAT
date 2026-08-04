"""F4b — the promotion sweep, and what it refuses to promote.

115 of 116 latest completed jobs for monitored addresses already held a
substantive ``control_tracking_plan``. The sweep moves them into the versioned
store, stamped with the source job — invariant 7's only door from a per-run
artifact into what monitoring enrolls from.

The refusals matter as much as the promotions: a contract the sweep will not
speak for must stay a visible not-determined, never a row that looks like
coverage. These tests pin one case per refusal token, and pin the report's
qualification-witness attribution — the mechanical gate over the dry run is that
every watch gaining notify rights names the arm that earns it.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from db.contract_materializations import (
    ANALYSIS_SCHEMA_VERSION,
    PUBLISH_ADDRESS_BOUND_TO_OTHER_KECCAK,
    PUBLISH_ALREADY_CURRENT,
    PUBLISH_KECCAK_BOUND_TO_OTHER_ADDRESS,
)
from db.models import ContractMaterialization, Job, JobStage, JobStatus, MonitoredContract
from db.queue import store_artifact
from scripts.promote_tracking_plans import (
    BYTECODE_KECCAK_NOT_CACHED,
    JOB_ANALYSIS_ARTIFACT_ABSENT,
    JOB_PLAN_ARTIFACT_ABSENT,
    JOB_SCHEMA_VERSION_NOT_CURRENT,
    NO_COMPLETED_JOB,
    PROMOTABLE,
    _notify_gains,
    plan_promotions,
    qualification_witness,
    summarize,
)
from services.monitoring.event_topics import (
    WITNESS_TIER_ACTIVITY,
    WITNESS_TIER_HINT,
    WITNESS_TIER_SELF_DESCRIBING,
)
from tests.conftest import requires_postgres

# A plan whose only event is an OZ-style ``AuthorityUpdated`` — the canonical
# family arm, and the shape 85 of the fleet's 111 notify gains take.
AUTHORITY_TOPIC = "0x" + "a0" * 32
PLAN = {
    "contract_address": "0x0",
    "tracked_controllers": [
        {
            "controller_id": "state_variable:authority",
            "authority_provenance": "caller_gate",
            "event_watch": {
                "events": [
                    {
                        "topic0": AUTHORITY_TOPIC,
                        "signature": "AuthorityUpdated(address,address)",
                        "inputs": [
                            {"name": "user", "type": "address", "indexed": True},
                            {"name": "newAuthority", "type": "address", "indexed": True},
                        ],
                        "effect_tags": {"writes": ["authority"]},
                        "writer_openness": "restricted",
                    }
                ]
            },
        }
    ],
}
ANALYSIS = {"subject": {"address": "0x0", "name": "C"}, "functions": []}


def _addr(n: int) -> str:
    return "0x" + f"{n:02x}" * 20


def _keccak(n: int) -> str:
    return "0x" + f"{n:02x}" * 32


@pytest.fixture()
def sweep_db(db_session):
    db_session.query(ContractMaterialization).delete()
    db_session.execute(text("DELETE FROM bytecode_cache"))
    db_session.commit()
    yield db_session
    db_session.query(ContractMaterialization).delete()
    db_session.execute(text("DELETE FROM bytecode_cache"))
    db_session.commit()


def _monitored(session, n: int, *, chain: str = "ethereum", config=None) -> MonitoredContract:
    mc = MonitoredContract(
        id=uuid.uuid4(),
        address=_addr(n),
        chain=chain,
        contract_type="regular",
        monitoring_config=config if config is not None else {},
        last_known_state={},
        last_scanned_block=0,
        needs_polling=False,
        is_active=True,
    )
    session.add(mc)
    session.commit()
    return mc


def _job(
    session,
    n: int,
    *,
    chain_id: int = 1,
    version: int | None = ANALYSIS_SCHEMA_VERSION,
    plan=PLAN,
    analysis=ANALYSIS,
    age_s: int = 0,
) -> Job:
    job = Job(
        id=uuid.uuid4(),
        address=_addr(n),
        status=JobStatus.completed,
        stage=JobStage.done,
        request={"address": _addr(n)},
        chain_id=chain_id,
        analysis_schema_version=version,
        updated_at=datetime.now(timezone.utc) - timedelta(seconds=age_s),
    )
    session.add(job)
    session.commit()
    if plan is not None:
        store_artifact(session, job.id, "control_tracking_plan", data=plan)
    if analysis is not None:
        store_artifact(session, job.id, "contract_analysis", data=analysis)
    session.commit()
    return job


def _cache_keccak(session, n: int, *, chain_id: int = 1, keccak: str | None = None) -> None:
    session.execute(
        text(
            "INSERT INTO bytecode_cache (chain_id, address, bytecode, code_keccak) "
            "VALUES (:c, :a, :b, :k) ON CONFLICT (chain_id, address) DO NOTHING"
        ),
        {"c": chain_id, "a": _addr(n), "b": "0xfeed", "k": keccak or _keccak(n)},
    )
    session.commit()


def _outcome(session, n: int) -> str:
    [promotion] = plan_promotions(session, address=_addr(n))
    return promotion.outcome


# ---------------------------------------------------------------------------
# What promotes
# ---------------------------------------------------------------------------


@requires_postgres
def test_promotes_the_newest_job_and_derives_after_tiers_from_the_real_classifier(sweep_db):
    _monitored(sweep_db, 1)
    _job(sweep_db, 1, age_s=600, plan={"contract_address": "0x0", "tracked_controllers": []})
    newest = _job(sweep_db, 1)
    _cache_keccak(sweep_db, 1)

    [promotion] = plan_promotions(sweep_db, address=_addr(1))
    assert promotion.outcome == PROMOTABLE
    assert promotion.source_job_id == str(newest.id)
    assert promotion.bytecode_keccak == _keccak(1)
    # Derived by ``extract_governance_topics`` — the function enrollment itself
    # calls — not by a second opinion living in the report.
    assert promotion.tiers_after == {WITNESS_TIER_SELF_DESCRIBING: 1}
    assert [g["event_type"] for g in promotion.notify_gains] == ["authority_updated"]
    assert promotion.notify_gains[0]["witness"]["kind"] == "canonical_family"


@requires_postgres
def test_a_current_row_is_reported_not_rewritten(sweep_db):
    _monitored(sweep_db, 2)
    _job(sweep_db, 2)
    _cache_keccak(sweep_db, 2)
    sweep_db.add(
        ContractMaterialization(
            chain="1",
            bytecode_keccak=_keccak(2),
            address=_addr(2),
            status="ready",
            analysis_schema_version=ANALYSIS_SCHEMA_VERSION,
            tracking_plan=PLAN,
        )
    )
    sweep_db.commit()

    [promotion] = plan_promotions(sweep_db, address=_addr(2))
    assert promotion.outcome == PUBLISH_ALREADY_CURRENT
    assert not promotion.promotable
    # Its plan still belongs in the table: it is what re-enrollment reads, so
    # its after-tiers are part of the fleet's before/after picture.
    assert promotion.tiers_after == {WITNESS_TIER_SELF_DESCRIBING: 1}


# ---------------------------------------------------------------------------
# What it refuses, and why each refusal is its own token
# ---------------------------------------------------------------------------


@requires_postgres
def test_never_analyzed_and_analyzed_without_a_plan_are_different_facts(sweep_db):
    _monitored(sweep_db, 3)
    _cache_keccak(sweep_db, 3)
    assert _outcome(sweep_db, 3) == NO_COMPLETED_JOB

    _monitored(sweep_db, 4)
    _job(sweep_db, 4, plan=None)
    _cache_keccak(sweep_db, 4)
    assert _outcome(sweep_db, 4) == JOB_PLAN_ARTIFACT_ABSENT


@requires_postgres
def test_a_plan_without_its_analysis_is_refused(sweep_db):
    """The row would hydrate ``analysis`` to None — read downstream as *this
    contract has no analysis*, which a missing artifact never said."""
    _monitored(sweep_db, 5)
    _job(sweep_db, 5, analysis=None)
    _cache_keccak(sweep_db, 5)
    assert _outcome(sweep_db, 5) == JOB_ANALYSIS_ARTIFACT_ABSENT


@requires_postgres
@pytest.mark.parametrize("version", [None, ANALYSIS_SCHEMA_VERSION - 1])
def test_an_unstamped_or_superseded_job_is_refused(sweep_db, version):
    _monitored(sweep_db, 6)
    _job(sweep_db, 6, version=version)
    _cache_keccak(sweep_db, 6)
    assert _outcome(sweep_db, 6) == JOB_SCHEMA_VERSION_NOT_CURRENT


@requires_postgres
def test_no_cached_keccak_is_left_to_the_operator_path(sweep_db):
    """The sweep does no RPC: an address with no cached bytecode has no key, and
    inventing one would key the bundle to code nobody read."""
    _monitored(sweep_db, 7)
    _job(sweep_db, 7)
    assert _outcome(sweep_db, 7) == BYTECODE_KECCAK_NOT_CACHED


@requires_postgres
def test_an_address_bound_to_other_bytecode_is_refused(sweep_db):
    _monitored(sweep_db, 8)
    _job(sweep_db, 8)
    _cache_keccak(sweep_db, 8)
    sweep_db.add(
        ContractMaterialization(
            chain="1",
            bytecode_keccak=_keccak(99),
            address=_addr(8),
            status="failed",
            analysis_schema_version=ANALYSIS_SCHEMA_VERSION,
        )
    )
    sweep_db.commit()
    assert _outcome(sweep_db, 8) == PUBLISH_ADDRESS_BOUND_TO_OTHER_KECCAK


@requires_postgres
def test_shared_bytecode_at_another_address_is_reported_not_stolen(sweep_db):
    """One row per ``(chain, bytecode)``. A second address with identical code
    cannot be served by address lookup, and saying so beats moving the row off
    the address that already resolves to it."""
    _monitored(sweep_db, 9)
    _job(sweep_db, 9)
    _cache_keccak(sweep_db, 9, keccak=_keccak(50))
    sweep_db.add(
        ContractMaterialization(
            chain="1",
            bytecode_keccak=_keccak(50),
            address=_addr(51),
            status="ready",
            analysis_schema_version=ANALYSIS_SCHEMA_VERSION,
        )
    )
    sweep_db.commit()
    assert _outcome(sweep_db, 9) == PUBLISH_KECCAK_BOUND_TO_OTHER_ADDRESS


@requires_postgres
def test_a_job_on_another_chain_is_not_this_deployments_plan(sweep_db):
    _monitored(sweep_db, 10, chain="base")
    _job(sweep_db, 10, chain_id=1)  # same address, mainnet deployment
    _cache_keccak(sweep_db, 10, chain_id=8453)
    assert _outcome(sweep_db, 10) == NO_COMPLETED_JOB


@requires_postgres
def test_the_report_covers_every_active_config(sweep_db):
    for n in (11, 12, 13):
        _monitored(sweep_db, n)
    _job(sweep_db, 11)
    _cache_keccak(sweep_db, 11)
    summary = summarize(plan_promotions(sweep_db))
    assert summary["configs"] == 3
    assert summary["outcomes"][PROMOTABLE] == 1
    assert summary["notify_rights_gains_unattributed"] == 0


# ---------------------------------------------------------------------------
# The mechanical gate: every notify-rights gain names its qualification
# ---------------------------------------------------------------------------


def _spec(**over):
    spec = {
        "topic0": "0x" + "cd" * 32,
        "signature": "X(address,address)",
        "event_type": "state_changed:state_variable:owner",
        "controller_id": "state_variable:owner",
        "inputs": [],
        "witness_tier": WITNESS_TIER_SELF_DESCRIBING,
        "writer_openness": "not_determined",
    }
    spec.update(over)
    return spec


def test_witness_attribution_names_each_arm():
    canonical = _spec(event_type="authority_updated")
    assert qualification_witness(canonical) == {
        "kind": "canonical_family",
        "family": "authority_updated",
        "signature": "X(address,address)",
    }

    old_new = _spec(
        inputs=[{"name": "oldOwner", "type": "address"}, {"name": "newOwner", "type": "address"}],
        effect_tags={"writes": ["owner"]},
    )
    witness = qualification_witness(old_new)
    assert witness is not None and witness["kind"] == "old_new_args_single_writer"
    assert witness["writes"] == ["owner"]

    member = _spec(
        event_type="member_changed:fromDenyList",
        member_witness={"mapping_name": "fromDenyList", "key_position": 0, "direction": "add"},
        writer_openness="restricted",
    )
    witness = qualification_witness(member)
    assert witness is not None and witness["kind"] == "member_witness"
    assert witness["mapping_name"] == "fromDenyList"
    assert witness["direction"] == "add"


def test_a_self_describing_spec_matching_no_arm_is_flagged_not_excused():
    """The report must never present an unexplained promotion as qualified."""
    witness = qualification_witness(_spec())
    assert witness is not None and witness["kind"] == "unattributed"


@pytest.mark.parametrize("tier", [WITNESS_TIER_HINT, WITNESS_TIER_ACTIVITY])
def test_non_notifying_tiers_have_no_witness_to_show(tier):
    assert qualification_witness(_spec(witness_tier=tier)) is None


def test_notify_gains_are_only_what_could_not_notify_before():
    already = _spec(event_type="authority_updated")
    hint = _spec(topic0="0x" + "ef" * 32, witness_tier=WITNESS_TIER_HINT)
    new = _spec(topic0="0x" + "ab" * 32, event_type="initialized")

    assert _notify_gains([already], [already, hint, new]) == [
        {
            "topic0": "0x" + "ab" * 32,
            "signature": "X(address,address)",
            "event_type": "initialized",
            "controller_id": "state_variable:owner",
            "witness": {
                "kind": "canonical_family",
                "family": "initialized",
                "signature": "X(address,address)",
            },
        }
    ]
    # A spec the row already carried at the same tier gains nothing.
    assert _notify_gains([already], [already]) == []
