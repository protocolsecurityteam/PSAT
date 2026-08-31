"""F5 — re-enrollment must not convert "cannot read the plan now" into
"nothing to watch".

The observed failure (EtherFiGovernanceToken, 2026-08-04): the contract's
``contract_materializations`` row disappeared, re-enrollment rebuilt the config
from scratch, and a witnessed ``AuthorityUpdated`` watch was replaced by a
not-determined token and an empty watch list — downstream indistinguishable
from "the plan was read and named nothing". Manufactured ignorance replacing
dated knowledge.

Unit tests pin the merge rule; the integration test replays the degradation
end-to-end through ``enroll_protocol_contracts`` against real
``contract_materializations`` rows, because the collapse lives in the seam
between the strict reader and the wholesale config rebuild.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import select

from db.models import Contract, ContractMaterialization, Job, JobStage, JobStatus, MonitoredContract, Protocol
from services.monitoring.observation_plan_state import (
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
    merge_stale_observation_plan,
)

PROTO_NAME = "__test_plan_staleness__"
TOPIC0 = "0x" + "ab" * 32
_TOPICS = [{"topic0": TOPIC0, "event_type": "authority_updated", "signature": "AuthorityUpdated(address,address)"}]
_NOW = datetime(2026, 8, 4, 1, 42, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------


def test_every_not_determined_token_but_the_caller_one_merges():
    """The exclusion is exactly one token, and it is the deliberate-overwrite
    one: a config an API caller authored is not ignorance to be repaired."""
    assert PLAN_NOT_DETERMINED_TOKENS - STALENESS_MERGE_TOKENS == {CONFIG_SUPPLIED_BY_CALLER}
    assert len(PLAN_NOT_DETERMINED_TOKENS) == 7


def test_producers_mint_only_vocabulary_tokens():
    """The three producers of the token — the strict reader, the enrollment
    caller, the PATCH route — stay inside the vocabulary this module owns."""
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


# ---------------------------------------------------------------------------
# The merge rule
# ---------------------------------------------------------------------------


def _fresh(token: str = NO_CURRENT_MATERIALIZATION) -> dict:
    """What ``_build_monitoring_config`` produces when the plan is unreadable."""
    return {"watch_ownership": True, NOT_DETERMINED_KEY: token}


def test_a_read_plan_never_merges():
    """A config carrying ``tracked_topics`` was witnessed this pass; nothing
    older may displace it."""
    new = {"watch_ownership": True, TRACKED_TOPICS_KEY: []}
    existing = {TRACKED_TOPICS_KEY: _TOPICS}
    assert merge_stale_observation_plan(new, existing) is new


@pytest.mark.parametrize("token", sorted(STALENESS_MERGE_TOKENS))
def test_every_merging_token_preserves_last_good_topics(token):
    merged = merge_stale_observation_plan(_fresh(token), {TRACKED_TOPICS_KEY: _TOPICS}, now=_NOW)
    assert merged[TRACKED_TOPICS_KEY] == _TOPICS
    assert merged[NOT_DETERMINED_KEY] == token
    assert merged[TRACKED_TOPICS_STALE_SINCE_KEY] == _NOW.isoformat()


def test_caller_supplied_config_is_never_resurrected_over():
    """A caller-authored config is a deliberate overwrite. Neither direction of
    the merge may undo it."""
    new = {"watch_ownership": False, NOT_DETERMINED_KEY: CONFIG_SUPPLIED_BY_CALLER}
    assert merge_stale_observation_plan(new, {TRACKED_TOPICS_KEY: _TOPICS}) is new

    existing_caller = {NOT_DETERMINED_KEY: CONFIG_SUPPLIED_BY_CALLER, TRACKED_TOPICS_KEY: _TOPICS}
    assert merge_stale_observation_plan(_fresh(), existing_caller) == _fresh()


def test_proven_empty_topics_carry_nothing_forward():
    """``tracked_topics == []`` is a claim about the contract ("read, named
    nothing"). It is not a watch list, and once the plan is unreadable we can no
    longer make that claim — so the not-determined config stands alone."""
    merged = merge_stale_observation_plan(_fresh(), {TRACKED_TOPICS_KEY: []})
    assert TRACKED_TOPICS_KEY not in merged
    assert merged[NOT_DETERMINED_KEY] == NO_CURRENT_MATERIALIZATION


def test_pre_discriminant_row_carries_nothing_forward():
    """A row with neither key never had a witnessed plan to preserve."""
    assert merge_stale_observation_plan(_fresh(), {"watch_ownership": True}) == _fresh()
    assert merge_stale_observation_plan(_fresh(), None) == _fresh()


def test_staleness_instant_is_not_refreshed_by_re_enrollment():
    """The topics are as old as the last successful read, not as old as the
    last failure to re-read. Re-running enrollment must not make dated
    knowledge look fresher."""
    first = merge_stale_observation_plan(_fresh(), {TRACKED_TOPICS_KEY: _TOPICS}, now=_NOW)
    later = merge_stale_observation_plan(_fresh(), first, now=_NOW + timedelta(days=30))
    assert later[TRACKED_TOPICS_STALE_SINCE_KEY] == first[TRACKED_TOPICS_STALE_SINCE_KEY] == _NOW.isoformat()


def test_watch_authority_is_rederived_from_the_carried_topics():
    """The flag is a function of what is being watched, so it follows the watch
    list rather than being left at the not-determined config's default."""
    merged = merge_stale_observation_plan(_fresh(), {TRACKED_TOPICS_KEY: _TOPICS}, now=_NOW)
    assert merged["watch_authority"] is True

    other = [{"topic0": TOPIC0, "event_type": "guardian_changed"}]
    assert "watch_authority" not in merge_stale_observation_plan(_fresh(), {TRACKED_TOPICS_KEY: other}, now=_NOW)


def test_polling_plan_carries_analyzer_slots_and_yields_to_fresh_entries():
    """The poll plane is the other half of the same watching: dropping the
    analyzer-derived entries flips ``needs_polling`` off and prunes the observed
    state keys they name. Vendored entries derived this pass still win their
    own field."""
    new = dict(_fresh(), **{POLLING_PLAN_KEY: [{"field": "implementation", "kind": "storage_slot"}]})
    existing = {
        TRACKED_TOPICS_KEY: _TOPICS,
        POLLING_PLAN_KEY: [
            {"field": "implementation", "kind": "stale_variant"},
            {"field": "feeRecipient", "kind": "getter_call"},
        ],
    }
    merged = merge_stale_observation_plan(new, existing, now=_NOW)
    assert merged[POLLING_PLAN_KEY] == [
        {"field": "implementation", "kind": "storage_slot"},
        {"field": "feeRecipient", "kind": "getter_call"},
    ]
    assert merged["polling_plan_stale_since"] == _NOW.isoformat()


def test_carried_polling_entries_are_always_stamped():
    """Review finding 7: the stamp used to be gated on the merged plan being
    LONGER than the raw new plan. A new plan holding a malformed entry (dropped
    by the merge) plus one carried entry gives equal lengths — stale entries
    would then ride with no staleness mark at all."""
    new = dict(_fresh(), **{POLLING_PLAN_KEY: [{"field": "implementation"}, "not-a-dict"]})
    existing = {TRACKED_TOPICS_KEY: _TOPICS, POLLING_PLAN_KEY: [{"field": "feeRecipient"}]}

    merged = merge_stale_observation_plan(new, existing, now=_NOW)

    assert len(merged[POLLING_PLAN_KEY]) == len(new[POLLING_PLAN_KEY])  # the shape that used to slip through
    assert {e["field"] for e in merged[POLLING_PLAN_KEY]} == {"implementation", "feeRecipient"}
    assert merged["polling_plan_stale_since"] == _NOW.isoformat()


def test_polling_plan_untouched_when_nothing_to_carry():
    new = dict(_fresh(), **{POLLING_PLAN_KEY: [{"field": "implementation"}]})
    merged = merge_stale_observation_plan(new, {TRACKED_TOPICS_KEY: _TOPICS, POLLING_PLAN_KEY: []}, now=_NOW)
    assert merged[POLLING_PLAN_KEY] == [{"field": "implementation"}]
    assert "polling_plan_stale_since" not in merged


def test_merge_does_not_mutate_its_inputs():
    new = _fresh()
    existing = {TRACKED_TOPICS_KEY: _TOPICS}
    merge_stale_observation_plan(new, existing, now=_NOW)
    assert new == _fresh()
    assert existing == {TRACKED_TOPICS_KEY: _TOPICS}


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


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
    """Review finding 5: two keys coexisting is not evidence of staleness. The
    state requires the stamp the merge writes, under a token the merge may act
    on — otherwise it reads as the token it carries.

    Neither shape below is producible by this module (the merge always stamps,
    and the schema rejects caller-supplied topics); classifying them as
    ``ready_stale`` anyway would publish "watching on a dated analyzer plan"
    about a config no analyzer touched.
    """
    no_stamp = {TRACKED_TOPICS_KEY: _TOPICS, NOT_DETERMINED_KEY: NO_CURRENT_MATERIALIZATION}
    assert classify_plan_state(no_stamp) == NO_CURRENT_MATERIALIZATION

    caller_with_topics = {
        TRACKED_TOPICS_KEY: _TOPICS,
        NOT_DETERMINED_KEY: CONFIG_SUPPLIED_BY_CALLER,
        TRACKED_TOPICS_STALE_SINCE_KEY: _NOW.isoformat(),
    }
    assert classify_plan_state(caller_with_topics) == CONFIG_SUPPLIED_BY_CALLER


def test_scan_plane_facts_survive_every_config_rebuild():
    """Review finding 2: ``scan_gaps`` records intervals this row's scanner
    never covered. Every writer replaces the whole config, so the carry is
    unconditional — including when the plan WAS read (no staleness merge runs)
    and when a caller authored the new config."""
    from services.monitoring.observation_plan_state import SCAN_GAPS_KEY, preserve_scan_plane_facts

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
    """A token this module does not know is still a real observed value; folding
    it into a known bucket would publish a reason we did not read."""
    assert classify_plan_state({NOT_DETERMINED_KEY: "some_future_token"}) == "some_future_token"


# ---------------------------------------------------------------------------
# End-to-end: the observed degradation
# ---------------------------------------------------------------------------


@pytest.fixture()
def protocol_fixture(db_session):
    """Protocol + analyzed Contract + completed Job, cleaned up afterwards.

    ``db_session`` sweeps monitored/protocol tables but not
    ``contract_materializations``; the rows created here are removed by address.
    """
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
    from db.contract_materializations import STATIC_FACTS_SCHEMA_VERSION
    from utils.chains import chain_cache_token

    row = ContractMaterialization(
        chain=chain_cache_token("ethereum"),
        bytecode_keccak=("0x" + uuid.uuid4().hex * 2)[:66],
        address=address.lower(),
        contract_name="GovernanceToken",
        status="ready",
        static_facts_schema_version=STATIC_FACTS_SCHEMA_VERSION,
        observation_plan=plan,
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
    """The EtherFiGovernanceToken replay: enrolled with a witnessed watch list,
    the materialization row disappears, re-enrollment runs.

    Before F5 the second config carried the token and NO topics — the watch was
    silently dropped. Now the watch survives, marked as dated.
    """
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

    # A third pass keeps the ORIGINAL staleness instant — re-enrolling is not
    # evidence about the plan.
    _enroll(db_session, proto.id)
    again = _config(db_session, address)
    assert again[TRACKED_TOPICS_STALE_SINCE_KEY] == stale[TRACKED_TOPICS_STALE_SINCE_KEY]


def test_recovered_materialization_drops_the_staleness_marks(db_session, protocol_fixture):
    """Re-reading the plan is fresh evidence: the token and the staleness stamp
    must not linger and make a current plan look dated."""
    proto, address = protocol_fixture
    row = _materialize(db_session, address, {"tracked_controllers": []})
    _enroll(db_session, proto.id)
    db_session.delete(row)
    db_session.commit()
    _enroll(db_session, proto.id)

    # Nothing was carried (the first read proved the plan empty), so this row is
    # plain not-determined — and re-materializing must restore the finding.
    assert TRACKED_TOPICS_KEY not in _config(db_session, address)

    _materialize(db_session, address, {"tracked_controllers": []})
    _enroll(db_session, proto.id)
    recovered = _config(db_session, address)
    assert recovered[TRACKED_TOPICS_KEY] == []
    assert NOT_DETERMINED_KEY not in recovered
    assert TRACKED_TOPICS_STALE_SINCE_KEY not in recovered
    assert classify_plan_state(recovered) == READY_FRESH_PROVEN_EMPTY
