"""F5: a vanished materialization turned EtherFiGovernanceToken's witnessed watch into an empty list
indistinguishable from "read and named nothing" (2026-08-04).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import select

from db.models import Contract, ContractMaterialization, Job, JobStage, JobStatus, MonitoredContract, Protocol
from services.monitoring.tracking_plan_state import (
    CONFIG_SUPPLIED_BY_CALLER,
    NO_CURRENT_MATERIALIZATION,
    NOT_DETERMINED_KEY,
    PLAN_NOT_DETERMINED_TOKENS,
    POLLING_PLAN_KEY,
    READY_FRESH_PROVEN_EMPTY,
    READY_FRESH_WITH_TOPICS,
    READY_STALE,
    STALENESS_MERGE_TOKENS,
    TRACKED_TOPICS_KEY,
    TRACKED_TOPICS_STALE_SINCE_KEY,
    UNCLASSIFIED,
    classify_plan_state,
    merge_stale_tracking_plan,
)

PROTO_NAME = "__test_plan_staleness__"
TOPIC0 = "0x" + "ab" * 32
_TOPICS = [{"topic0": TOPIC0, "event_type": "authority_updated", "signature": "AuthorityUpdated(address,address)"}]
_NOW = datetime(2026, 8, 4, 1, 42, tzinfo=timezone.utc)


def test_producers_mint_only_vocabulary_tokens():
    from routers.monitored import CALLER_SUPPLIED_TRACKING_PLAN
    from services.monitoring import enrollment as enr

    assert CALLER_SUPPLIED_TRACKING_PLAN in PLAN_NOT_DETERMINED_TOKENS
    assert enr.CONTRACT_NOT_ANALYZED in PLAN_NOT_DETERMINED_TOKENS
    for token in (
        enr.MATERIALIZATION_LOOKUP_FAILED,
        enr.NO_CURRENT_MATERIALIZATION,
        enr.PLAN_OBJECT_ABSENT,
        enr.PLAN_NOT_READABLE,
        enr.PLAN_LOAD_ERROR,
    ):
        assert token in PLAN_NOT_DETERMINED_TOKENS


def _fresh(token: str = NO_CURRENT_MATERIALIZATION) -> dict:
    return {"watch_ownership": True, NOT_DETERMINED_KEY: token}


def test_a_read_plan_never_merges():
    new = {"watch_ownership": True, TRACKED_TOPICS_KEY: []}
    existing = {TRACKED_TOPICS_KEY: _TOPICS}
    assert merge_stale_tracking_plan(new, existing) is new


@pytest.mark.parametrize("token", sorted(STALENESS_MERGE_TOKENS))
def test_every_merging_token_preserves_last_good_topics(token):
    merged = merge_stale_tracking_plan(_fresh(token), {TRACKED_TOPICS_KEY: _TOPICS}, now=_NOW)
    assert merged[TRACKED_TOPICS_KEY] == _TOPICS
    assert merged[NOT_DETERMINED_KEY] == token
    assert merged[TRACKED_TOPICS_STALE_SINCE_KEY] == _NOW.isoformat()


def test_caller_supplied_config_is_never_resurrected_over():
    new = {"watch_ownership": False, NOT_DETERMINED_KEY: CONFIG_SUPPLIED_BY_CALLER}
    assert merge_stale_tracking_plan(new, {TRACKED_TOPICS_KEY: _TOPICS}) is new

    existing_caller = {NOT_DETERMINED_KEY: CONFIG_SUPPLIED_BY_CALLER, TRACKED_TOPICS_KEY: _TOPICS}
    assert merge_stale_tracking_plan(_fresh(), existing_caller) == _fresh()


def test_proven_empty_topics_carry_nothing_forward():
    """``[]`` is a claim about the contract, which can't be made once the plan is unreadable."""
    merged = merge_stale_tracking_plan(_fresh(), {TRACKED_TOPICS_KEY: []})
    assert TRACKED_TOPICS_KEY not in merged
    assert merged[NOT_DETERMINED_KEY] == NO_CURRENT_MATERIALIZATION


def test_pre_discriminant_row_carries_nothing_forward():
    assert merge_stale_tracking_plan(_fresh(), {"watch_ownership": True}) == _fresh()
    assert merge_stale_tracking_plan(_fresh(), None) == _fresh()


def test_staleness_instant_is_not_refreshed_by_re_enrollment():
    """Re-enrolling must not make dated knowledge look fresher."""
    first = merge_stale_tracking_plan(_fresh(), {TRACKED_TOPICS_KEY: _TOPICS}, now=_NOW)
    later = merge_stale_tracking_plan(_fresh(), first, now=_NOW + timedelta(days=30))
    assert later[TRACKED_TOPICS_STALE_SINCE_KEY] == first[TRACKED_TOPICS_STALE_SINCE_KEY] == _NOW.isoformat()


def test_watch_authority_is_rederived_from_the_carried_topics():
    merged = merge_stale_tracking_plan(_fresh(), {TRACKED_TOPICS_KEY: _TOPICS}, now=_NOW)
    assert merged["watch_authority"] is True

    other = [{"topic0": TOPIC0, "event_type": "guardian_changed"}]
    assert "watch_authority" not in merge_stale_tracking_plan(_fresh(), {TRACKED_TOPICS_KEY: other}, now=_NOW)


def test_polling_plan_carries_analyzer_slots_and_yields_to_fresh_entries():
    """Dropping analyzer entries would flip ``needs_polling`` off and prune their observed state keys."""
    new = dict(_fresh(), **{POLLING_PLAN_KEY: [{"field": "implementation", "kind": "storage_slot"}]})
    existing = {
        TRACKED_TOPICS_KEY: _TOPICS,
        POLLING_PLAN_KEY: [
            {"field": "implementation", "kind": "stale_variant"},
            {"field": "feeRecipient", "kind": "getter_call"},
        ],
    }
    merged = merge_stale_tracking_plan(new, existing, now=_NOW)
    assert merged[POLLING_PLAN_KEY] == [
        {"field": "implementation", "kind": "storage_slot"},
        {"field": "feeRecipient", "kind": "getter_call"},
    ]
    assert merged["polling_plan_stale_since"] == _NOW.isoformat()


def test_carried_polling_entries_are_always_stamped():
    """The stamp used to be gated on the merged plan being longer, which a dropped entry could equal."""
    new = dict(_fresh(), **{POLLING_PLAN_KEY: [{"field": "implementation"}, "not-a-dict"]})
    existing = {TRACKED_TOPICS_KEY: _TOPICS, POLLING_PLAN_KEY: [{"field": "feeRecipient"}]}

    merged = merge_stale_tracking_plan(new, existing, now=_NOW)

    assert len(merged[POLLING_PLAN_KEY]) == len(new[POLLING_PLAN_KEY])  # the shape that used to slip through
    assert {e["field"] for e in merged[POLLING_PLAN_KEY]} == {"implementation", "feeRecipient"}
    assert merged["polling_plan_stale_since"] == _NOW.isoformat()


def test_polling_plan_untouched_when_nothing_to_carry():
    new = dict(_fresh(), **{POLLING_PLAN_KEY: [{"field": "implementation"}]})
    merged = merge_stale_tracking_plan(new, {TRACKED_TOPICS_KEY: _TOPICS, POLLING_PLAN_KEY: []}, now=_NOW)
    assert merged[POLLING_PLAN_KEY] == [{"field": "implementation"}]
    assert "polling_plan_stale_since" not in merged


def test_merge_does_not_mutate_its_inputs():
    new = _fresh()
    existing = {TRACKED_TOPICS_KEY: _TOPICS}
    merge_stale_tracking_plan(new, existing, now=_NOW)
    assert new == _fresh()
    assert existing == {TRACKED_TOPICS_KEY: _TOPICS}


def test_classify_keeps_the_four_states_distinct():
    assert classify_plan_state({TRACKED_TOPICS_KEY: _TOPICS}) == READY_FRESH_WITH_TOPICS
    assert classify_plan_state({TRACKED_TOPICS_KEY: []}) == READY_FRESH_PROVEN_EMPTY
    assert (
        classify_plan_state(
            {
                TRACKED_TOPICS_KEY: _TOPICS,
                NOT_DETERMINED_KEY: NO_CURRENT_MATERIALIZATION,
                TRACKED_TOPICS_STALE_SINCE_KEY: _NOW.isoformat(),
            }
        )
        == READY_STALE
    )
    assert classify_plan_state({NOT_DETERMINED_KEY: NO_CURRENT_MATERIALIZATION}) == NO_CURRENT_MATERIALIZATION
    assert classify_plan_state({"watch_ownership": True}) == UNCLASSIFIED
    assert classify_plan_state(None) == UNCLASSIFIED


def test_ready_stale_needs_its_own_witness_not_a_coincidence_of_keys():
    """Two keys coexisting is not evidence of staleness; the state needs the merge's stamp."""
    no_stamp = {TRACKED_TOPICS_KEY: _TOPICS, NOT_DETERMINED_KEY: NO_CURRENT_MATERIALIZATION}
    assert classify_plan_state(no_stamp) == NO_CURRENT_MATERIALIZATION

    caller_with_topics = {
        TRACKED_TOPICS_KEY: _TOPICS,
        NOT_DETERMINED_KEY: CONFIG_SUPPLIED_BY_CALLER,
        TRACKED_TOPICS_STALE_SINCE_KEY: _NOW.isoformat(),
    }
    assert classify_plan_state(caller_with_topics) == CONFIG_SUPPLIED_BY_CALLER


def test_scan_plane_facts_survive_every_config_rebuild():
    """``scan_gaps`` records never-scanned intervals, and every writer replaces the whole config."""
    from services.monitoring.tracking_plan_state import SCAN_GAPS_KEY, preserve_scan_plane_facts

    gaps = [{"from_block": 9_400_001, "to_block": 25_662_000, "reason": "unfloored_runaway"}]
    existing = {TRACKED_TOPICS_KEY: _TOPICS, SCAN_GAPS_KEY: gaps}

    fresh_read = preserve_scan_plane_facts({"watch_ownership": True, TRACKED_TOPICS_KEY: []}, existing)
    assert fresh_read[SCAN_GAPS_KEY] == gaps
    assert fresh_read[TRACKED_TOPICS_KEY] == []  # unrelated keys untouched

    caller = preserve_scan_plane_facts({NOT_DETERMINED_KEY: CONFIG_SUPPLIED_BY_CALLER}, existing)
    assert caller[SCAN_GAPS_KEY] == gaps

    assert preserve_scan_plane_facts({"a": 1}, {}) == {"a": 1}
    assert preserve_scan_plane_facts({"a": 1}, None) == {"a": 1}


def test_classify_reports_an_unknown_token_as_itself():
    """Folding an unknown token into a known bucket would publish a reason we did not read."""
    assert classify_plan_state({NOT_DETERMINED_KEY: "some_future_token"}) == "some_future_token"


@pytest.fixture()
def protocol_fixture(db_session):
    """``db_session`` doesn't sweep ``contract_materializations``."""
    address = "0x" + "e7" * 20
    proto = Protocol(name=PROTO_NAME)
    db_session.add(proto)
    db_session.flush()
    contract = Contract(
        address=address,
        chain="ethereum",
        protocol_id=proto.id,
        contract_name="GovernanceToken",
    )
    db_session.add(contract)
    db_session.flush()
    db_session.add(Job(address=address, protocol_id=proto.id, status=JobStatus.completed, stage=JobStage.done))
    db_session.commit()
    try:
        yield proto, address
    finally:
        db_session.rollback()
        for row in (
            db_session.execute(select(ContractMaterialization).where(ContractMaterialization.address == address))
            .scalars()
            .all()
        ):
            db_session.delete(row)
        db_session.commit()


def _materialize(session, address: str, plan: dict) -> ContractMaterialization:
    from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
    from utils.chains import chain_cache_token

    row = ContractMaterialization(
        chain=chain_cache_token("ethereum"),
        bytecode_keccak=("0x" + uuid.uuid4().hex * 2)[:66],
        address=address.lower(),
        contract_name="GovernanceToken",
        status="ready",
        analysis_schema_version=ANALYSIS_SCHEMA_VERSION,
        tracking_plan=plan,
    )
    session.add(row)
    session.commit()
    return row


def _config(session, address: str) -> dict:
    session.expire_all()
    return session.execute(
        select(MonitoredContract.monitoring_config).where(MonitoredContract.address == address.lower())
    ).scalar_one()


def _enroll(session, protocol_id: int) -> None:
    from services.monitoring.enrollment import enroll_protocol_contracts

    with patch("services.monitoring.enrollment.rpc_request", return_value=hex(21_000_000)):
        enroll_protocol_contracts(session, protocol_id, "http://rpc", "ethereum", enroll_controllers=False)


def test_vanished_materialization_keeps_the_last_read_watch_list(db_session, protocol_fixture):
    """The watch used to be silently dropped; now it survives, marked dated."""
    proto, address = protocol_fixture
    plan = {
        "tracked_controllers": [
            {
                "controller_id": "state_variable:authority",
                "event_watch": {
                    "events": [
                        {
                            "topic0": TOPIC0,
                            "signature": "AuthorityUpdated(address,address)",
                            "inputs": [{"name": "user", "type": "address", "indexed": True}],
                        }
                    ]
                },
            }
        ]
    }
    row = _materialize(db_session, address, plan)

    _enroll(db_session, proto.id)
    first = _config(db_session, address)
    assert [t["topic0"] for t in first[TRACKED_TOPICS_KEY]] == [TOPIC0]
    assert NOT_DETERMINED_KEY not in first
    assert TRACKED_TOPICS_STALE_SINCE_KEY not in first

    db_session.delete(row)
    db_session.commit()

    _enroll(db_session, proto.id)
    stale = _config(db_session, address)
    assert [t["topic0"] for t in stale[TRACKED_TOPICS_KEY]] == [TOPIC0]
    assert stale[NOT_DETERMINED_KEY] == NO_CURRENT_MATERIALIZATION
    assert stale[TRACKED_TOPICS_STALE_SINCE_KEY]
    assert classify_plan_state(stale) == READY_STALE

    _enroll(db_session, proto.id)
    again = _config(db_session, address)
    assert again[TRACKED_TOPICS_STALE_SINCE_KEY] == stale[TRACKED_TOPICS_STALE_SINCE_KEY]


def test_recovered_materialization_drops_the_staleness_marks(db_session, protocol_fixture):
    proto, address = protocol_fixture
    row = _materialize(db_session, address, {"tracked_controllers": []})
    _enroll(db_session, proto.id)
    db_session.delete(row)
    db_session.commit()
    _enroll(db_session, proto.id)

    assert TRACKED_TOPICS_KEY not in _config(db_session, address)

    _materialize(db_session, address, {"tracked_controllers": []})
    _enroll(db_session, proto.id)
    recovered = _config(db_session, address)
    assert recovered[TRACKED_TOPICS_KEY] == []
    assert NOT_DETERMINED_KEY not in recovered
    assert TRACKED_TOPICS_STALE_SINCE_KEY not in recovered
    assert classify_plan_state(recovered) == READY_FRESH_PROVEN_EMPTY
