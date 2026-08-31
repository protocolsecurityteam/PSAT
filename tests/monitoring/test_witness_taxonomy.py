"""The three-tier witness taxonomy and its verification reads (F1 / F2 / F9b).

Unit coverage of ``classify_witness_tier`` + ``extract_governance_topics``, and
integration coverage of the runtime halves — the ``_process_window`` tier gate,
the coalesced verification-read pass, and the notifier gate — against the real
test DB with only the RPC wire stubbed.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
from eth_utils.crypto import keccak
from sqlalchemy import select

from db.models import Contract, Job, MonitoredContract, MonitoredEvent, Protocol, ProxyUpgradeEvent, WatchedProxy
from services.monitoring.event_topics import (
    MAX_EVENT_TYPE_LENGTH,
    WITNESS_TIER_ACTIVITY,
    WITNESS_TIER_HINT,
    WITNESS_TIER_SELF_DESCRIBING,
    classify_witness_tier,
    extract_governance_topics,
    member_changed_event_type,
    normalized_writer_openness,
    read_spec_is_scalar_slot,
    value_changed_event_type,
)
from services.monitoring.polling_plan import build_polling_plan
from services.monitoring.unified_watcher import (
    _Cohort,
    _DirtyController,
    _poll_entry_for_controller,
    _process_window,
    _resolve_spec_tier,
    scan_for_events,
)
from services.monitoring.verify_status import (
    CENSUS_BASIS,
    VERIFY_ERROR,
    VERIFY_NO_READ_BINDING,
    VERIFY_OVER_BUDGET,
    VERIFY_UNANSWERED,
    count_verification_read_gaps,
    record_unresolvable_read,
)
from services.resolution.observation_plan import build_observation_plan
from services.resolution.repos.event_logs_rpc import FetchedEventLog


def ADDR(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


def _topic0(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()


def _word(value: str) -> str:
    return "0x" + "0" * 24 + value[2:]


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------


def test_minted_type_vocabulary():
    assert value_changed_event_type("state_variable:owner") == "value_changed:state_variable:owner"
    assert member_changed_event_type("fromDenyList") == "member_changed:fromDenyList"
    # Key / value / direction never enter the type string — they would make
    # every entry its own event type and defeat the identity index.
    assert ":" not in member_changed_event_type("fromDenyList").split(":", 1)[1]


def test_writer_openness_is_three_state():
    assert normalized_writer_openness("restricted") == "restricted"
    assert normalized_writer_openness("open") == "open"
    assert normalized_writer_openness(None) == "not_determined"
    assert normalized_writer_openness("") == "not_determined"
    assert normalized_writer_openness("Restricted-ish") == "not_determined"
    assert normalized_writer_openness(True) == "not_determined"


# ---------------------------------------------------------------------------
# classify_witness_tier
# ---------------------------------------------------------------------------


def test_canonical_family_is_self_describing():
    assert (
        classify_witness_tier(event_type="ownership_transferred", controller_id="state_variable:owner")
        == WITNESS_TIER_SELF_DESCRIBING
    )


def test_donated_spec_with_readable_controller_is_a_hint():
    assert (
        classify_witness_tier(
            event_type="state_changed:state_variable:paused",
            controller_id="state_variable:paused",
            effect_tags={"writes": ["paused", "_status"]},
            poll_decodable=True,
        )
        == WITNESS_TIER_HINT
    )


def test_donated_spec_without_a_read_is_activity():
    assert (
        classify_witness_tier(
            event_type="state_changed:state_variable:_balances",
            controller_id="state_variable:_balances",
            effect_tags={"writes": ["_allowances", "_balances", "_totalSupply"]},
            poll_decodable=False,
        )
        == WITNESS_TIER_ACTIVITY
    )


@pytest.mark.parametrize(
    "openness,expected",
    [
        ("restricted", WITNESS_TIER_SELF_DESCRIBING),
        ("open", WITNESS_TIER_ACTIVITY),
        ("not_determined", WITNESS_TIER_ACTIVITY),
        (None, WITNESS_TIER_ACTIVITY),
    ],
)
def test_member_witness_needs_a_proven_restricted_writer(openness, expected):
    assert (
        classify_witness_tier(
            event_type="state_changed:state_variable:fromDenyList",
            controller_id="state_variable:fromDenyList",
            effect_tags={"writes": ["fromDenyList"]},
            member_witness={"key_position": 0, "direction": "add"},
            writer_openness=openness,
        )
        == expected
    )


def test_old_new_pair_qualifies_only_when_attributable():
    inputs = [
        {"name": "oldRate", "type": "uint256", "indexed": False},
        {"name": "newRate", "type": "uint256", "indexed": False},
    ]
    # Single-write emitter naming this controller, over a slot PROVEN to hold a
    # single value: the pair can only be about that value.
    assert (
        classify_witness_tier(
            event_type="state_changed:state_variable:rate",
            controller_id="state_variable:rate",
            inputs=inputs,
            effect_tags={"writes": ["rate"]},
            controller_scalar_proven=True,
        )
        == WITNESS_TIER_SELF_DESCRIBING
    )
    # A multi-write emitter donates its whole slot set to every event it
    # emits, so the pair says nothing about which slot moved.
    assert (
        classify_witness_tier(
            event_type="state_changed:state_variable:rate",
            controller_id="state_variable:rate",
            inputs=inputs,
            effect_tags={"writes": ["rate", "lastUpdate"]},
            controller_scalar_proven=True,
        )
        == WITNESS_TIER_ACTIVITY
    )
    # A single-write emitter of a DIFFERENT slot is not this controller's witness.
    assert (
        classify_witness_tier(
            event_type="state_changed:state_variable:rate",
            controller_id="state_variable:rate",
            inputs=inputs,
            effect_tags={"writes": ["lastUpdate"]},
            controller_scalar_proven=True,
        )
        == WITNESS_TIER_ACTIVITY
    )


@pytest.mark.parametrize(
    "read_spec,scalar",
    [
        ({"type_kind": "address"}, True),
        ({"type_kind": "contract"}, True),
        ({"type_kind": "primitive"}, True),
        ({"type_kind": "mapping"}, False),
        ({"type_kind": "array"}, False),
        ({"type_kind": "struct"}, False),
        ({"type_kind": "unknown"}, False),
        ({"type_kind": ""}, False),
        ({}, False),
        (None, False),
    ],
)
def test_only_a_proven_single_cell_slot_takes_the_old_new_arm(read_spec, scalar):
    """An old/new pair over a MAPPING states that one entry moved and names no
    key, so publishing it under the slot stem puts one entry's value where
    consumers read the slot's — the P1c wrong-claim shape. An absent or
    unrecognized type_kind is the not-determined state and refuses too:
    the absence of a proof that the slot is scalar is not a proof that it is.
    """
    assert read_spec_is_scalar_slot(read_spec) is scalar
    tier = classify_witness_tier(
        event_type="state_changed:state_variable:x",
        controller_id="state_variable:x",
        inputs=[
            {"name": "oldLimit", "type": "uint64", "indexed": False},
            {"name": "newLimit", "type": "uint64", "indexed": False},
        ],
        effect_tags={"writes": ["x"]},
        controller_scalar_proven=read_spec_is_scalar_slot(read_spec),
    )
    assert (tier == WITNESS_TIER_SELF_DESCRIBING) is scalar


def test_the_old_new_arm_defaults_to_refusing():
    """A caller that does not supply the proof gets the refusal, not the
    promotion — the default is the not-determined state."""
    assert (
        classify_witness_tier(
            event_type="state_changed:state_variable:rate",
            controller_id="state_variable:rate",
            inputs=[
                {"name": "oldRate", "type": "uint256", "indexed": False},
                {"name": "newRate", "type": "uint256", "indexed": False},
            ],
            effect_tags={"writes": ["rate"]},
        )
        == WITNESS_TIER_ACTIVITY
    )


def test_untypable_controller_id_demotes_rather_than_truncates():
    """A controller id whose ``value_changed`` form overflows the column
    cannot be published under its own identity; truncating it would name a
    different slot, so the spec drops to activity instead."""
    long_id = "state_variable:" + "a" * MAX_EVENT_TYPE_LENGTH
    assert len(value_changed_event_type(long_id)) > MAX_EVENT_TYPE_LENGTH
    assert (
        classify_witness_tier(
            event_type=f"state_changed:{long_id}",
            controller_id=long_id,
            effect_tags={"writes": ["x"]},
            poll_decodable=True,
        )
        == WITNESS_TIER_ACTIVITY
    )


# ---------------------------------------------------------------------------
# Enrollment: extract_governance_topics + tracking-plan round-trip
# ---------------------------------------------------------------------------


def _plan_with(read_spec: dict | None, **event_extra: object) -> dict:
    event = {
        "name": "RateUpdated",
        "signature": "RateUpdated(uint256)",
        "topic0": _topic0("RateUpdated(uint256)"),
        "inputs": [{"name": "rate", "type": "uint256", "indexed": False}],
        "effect_tags": {"writes": ["rate"]},
    }
    event.update(event_extra)
    return {
        "tracked_controllers": [
            {
                "controller_id": "state_variable:rate",
                "read_spec": read_spec,
                "event_watch": {"events": [event]},
            }
        ]
    }


def test_extract_stamps_the_tier_and_the_three_state_openness():
    readable = {"strategy": "getter_call", "type_kind": "primitive", "type": "uint256", "target": "rate"}
    spec = extract_governance_topics(_plan_with(readable))[0]
    assert spec["witness_tier"] == WITNESS_TIER_HINT
    assert spec["writer_openness"] == "not_determined"

    spec = extract_governance_topics(_plan_with(None))[0]
    assert spec["witness_tier"] == WITNESS_TIER_ACTIVITY


def test_extract_reads_the_g3_qualification_fields():
    """The record has to be PUBLISHABLE to promote: it names the mapping whose
    entry moved, and its key position is inside the event's own argument list.
    A record missing either is covered in ``test_witness_qualification_units``,
    where the tier stays ``activity``."""
    witness = {"mapping_name": "rate", "key_position": 0, "direction": "add"}
    spec = extract_governance_topics(_plan_with(None, member_witness=witness, writer_openness="restricted"))[0]
    assert spec["witness_tier"] == WITNESS_TIER_SELF_DESCRIBING
    assert spec["writer_openness"] == "restricted"
    assert spec["member_witness"] == witness
    assert spec["event_type"] == "member_changed:rate"


def test_qualification_fields_round_trip_through_the_plan_assembler():
    """G3 writes ``member_witness`` / ``writer_openness`` onto the analysis
    events; the tracking-plan artifact must carry them through untouched or
    the tier never sees them at enrollment."""
    analysis = {
        "subject": {"address": ADDR(1), "name": "Vault"},
        "controller_tracking": [
            {
                "controller_id": "state_variable:fromDenyList",
                "label": "fromDenyList",
                "source": "static",
                "kind": "state_variable",
                "tracking_mode": "event_plus_state",
                "read_spec": None,
                "associated_events": [
                    {
                        "name": "DenyFrom",
                        "signature": "DenyFrom(address)",
                        "topic0": _topic0("DenyFrom(address)"),
                        "inputs": [{"name": "user", "type": "address", "indexed": True}],
                        "effect_tags": {"writes": ["fromDenyList"]},
                        "member_witness": {
                            "mapping_name": "fromDenyList",
                            "key_position": 0,
                            "direction": "add",
                        },
                        "writer_openness": "restricted",
                    }
                ],
                "writer_functions": [],
            }
        ],
    }
    plan = dict(build_observation_plan(analysis))  # pyright: ignore[reportArgumentType]
    event = dict(plan["tracked_controllers"][0]["event_watch"]["events"][0])  # pyright: ignore[reportIndexIssue]
    assert event["member_witness"] == {
        "mapping_name": "fromDenyList",
        "key_position": 0,
        "direction": "add",
    }
    assert event["writer_openness"] == "restricted"
    assert extract_governance_topics(plan)[0]["witness_tier"] == WITNESS_TIER_SELF_DESCRIBING


def test_polling_plan_suppresses_the_verified_type_it_would_double_report():
    plan = build_polling_plan(
        contract_type="regular",
        observation_plan=_plan_with(
            {"strategy": "getter_call", "type_kind": "primitive", "type": "uint256", "target": "rate"}
        ),
    )
    assert plan[0]["suppress_when_scan_event_types"] == ["value_changed:state_variable:rate"]


# ---------------------------------------------------------------------------
# Runtime: the _process_window tier gate + verification reads
# ---------------------------------------------------------------------------

RATE_TOPIC0 = _topic0("RateUpdated(uint256)")
RATE_SELECTOR = "0x" + keccak(text="rate()").hex()[:8]


def _tracked_spec(tier: str | None) -> dict:
    spec = {
        "topic0": RATE_TOPIC0,
        "signature": "RateUpdated(uint256)",
        "event_type": "state_changed:state_variable:rate",
        "controller_id": "state_variable:rate",
        "inputs": [{"name": "rate", "type": "uint256", "indexed": False}],
        "effect_tags": {"writes": ["rate", "lastUpdate"]},
        "writer_openness": "not_determined",
    }
    if tier is not None:
        spec["witness_tier"] = tier
    return spec


def _poll_entry() -> dict:
    return {
        "field": "rate",
        "kind": "getter_call",
        "target": "rate",
        "selector": RATE_SELECTOR,
        "type_kind": "primitive",
        "type": "uint256",
        "source": "analyzer:state_variable:rate",
    }


@pytest.fixture()
def seeded(db_session):
    protocol = Protocol(name="taxonomy", chains=["ethereum"])
    db_session.add(protocol)
    db_session.flush()
    contract = Contract(protocol_id=protocol.id, address=ADDR(0x11), chain="ethereum")
    db_session.add(contract)
    db_session.flush()

    def make(tier: str | None, *, with_plan: bool = True, state: dict | None = None) -> MonitoredContract:
        mc = MonitoredContract(
            id=uuid.uuid4(),
            address=ADDR(0x11),
            chain="ethereum",
            protocol_id=protocol.id,
            contract_id=contract.id,
            contract_type="regular",
            monitoring_config={
                "tracked_topics": [_tracked_spec(tier)],
                "polling_plan": [_poll_entry()] if with_plan else [],
            },
            last_known_state=state or {},
            last_scanned_block=100,
            enrollment_block=1,
            is_active=True,
        )
        db_session.add(mc)
        db_session.commit()
        return mc

    return make


def _logs(count: int = 3) -> list[FetchedEventLog]:
    out = []
    for i in range(count):
        raw = {
            "address": ADDR(0x11),
            "topics": [RATE_TOPIC0],
            "data": "0x" + hex(1000 + i)[2:].zfill(64),
            "blockNumber": hex(200 + i),
            "transactionHash": "0x" + f"{i:064x}",
            "logIndex": "0x0",
            "blockHash": "0x" + "b" * 64,
            "transactionIndex": "0x0",
        }
        out.append(
            FetchedEventLog(
                tx_hash=bytes.fromhex(f"{i:064x}"),
                log_index=0,
                block_number=200 + i,
                block_hash=b"\xbb" * 32,
                transaction_index=0,
                topics=[RATE_TOPIC0],
                data_words=[],
                address=ADDR(0x11),
                raw=raw,
            )
        )
    return out


def _cohort(mc: MonitoredContract) -> _Cohort:
    return _Cohort(chain="ethereum", member_ids=[mc.id], addresses=[mc.address.lower()], cursor=199)


def test_hint_occurrences_publish_nothing_and_coalesce_to_one_read(db_session, seeded):
    mc = seeded(WITNESS_TIER_HINT)
    dirty: dict = {}
    events = _process_window(db_session, _cohort(mc), _logs(3), 200, 210, dirty)
    db_session.commit()

    assert events == []
    assert db_session.query(MonitoredEvent).count() == 0
    # Three occurrences on one controller — one read.
    assert list(dirty) == [(mc.id, "state_variable:rate")]


def test_pre_enrollment_hint_never_marks_a_read(db_session, seeded):
    """Invariant 9 through the new route: a verification read compares the
    CURRENT slot against last_known_state, so letting an ancient occurrence
    trigger one would publish pre-enrollment history as a live change."""
    mc = seeded(WITNESS_TIER_HINT)
    mc.enrollment_block = 10_000
    db_session.commit()
    dirty: dict = {}
    assert _process_window(db_session, _cohort(mc), _logs(2), 200, 210, dirty) == []
    assert dirty == {}


def test_activity_occurrences_publish_nothing_and_mark_nothing(db_session, seeded):
    mc = seeded(WITNESS_TIER_ACTIVITY)
    dirty: dict = {}
    assert _process_window(db_session, _cohort(mc), _logs(3), 200, 210, dirty) == []
    db_session.commit()
    assert db_session.query(MonitoredEvent).count() == 0
    assert dirty == {}


def test_self_describing_occurrences_publish_and_carry_their_tier(db_session, seeded):
    mc = seeded(WITNESS_TIER_SELF_DESCRIBING)
    events = _process_window(db_session, _cohort(mc), _logs(2), 200, 210, {})
    db_session.commit()
    assert len(events) == 2
    assert all((e.data or {})["witness_tier"] == WITNESS_TIER_SELF_DESCRIBING for e in events)


def test_legacy_spec_without_a_tier_is_reclassified_not_grandfathered(db_session, seeded):
    """A spec persisted before the taxonomy has no proof attached, so it is
    re-classified from what the row carries rather than published on trust."""
    with_read = seeded(None, with_plan=True)
    dirty: dict = {}
    assert _process_window(db_session, _cohort(with_read), _logs(1), 200, 210, dirty) == []
    assert list(dirty) == [(with_read.id, "state_variable:rate")]

    db_session.query(MonitoredContract).delete()
    db_session.commit()
    without_read = seeded(None, with_plan=False)
    dirty = {}
    assert _process_window(db_session, _cohort(without_read), _logs(1), 200, 210, dirty) == []
    assert dirty == {}


# ---------------------------------------------------------------------------
# Verification reads
# ---------------------------------------------------------------------------


def _run_scan(db_session, *, batch_result, head: int = 1000, monkeypatch_env: dict | None = None):
    """Drive one real ``scan_for_events`` pass with the wire stubbed."""
    with (
        patch("services.monitoring.unified_watcher.get_latest_block", return_value=head),
        patch("services.monitoring.unified_watcher.RpcEventLogFetcher") as fetcher,
        patch(
            "services.monitoring.unified_watcher.rpc_batch_request_classified",
            side_effect=batch_result,
        ) as batch,
    ):
        fetcher.return_value.fetch_logs.side_effect = lambda **_kw: _logs(2)
        result = scan_for_events(db_session, "http://rpc.invalid")
    return result, batch


def test_verification_read_diff_publishes_a_witnessed_value_changed(db_session, seeded):
    mc = seeded(WITNESS_TIER_HINT, state={"rate": 7})
    _run_scan(db_session, batch_result=lambda *_a, **_k: [("0x" + hex(9)[2:].zfill(64), "ok")])

    rows = db_session.execute(select(MonitoredEvent)).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.event_type == "value_changed:state_variable:rate"
    assert row.data["old"] == "7"
    assert row.data["new"] == "9"
    assert row.data["witness"] == "read_verified"
    # A read observes a slot, not a log: no block, no tx, and outside the
    # scan-path identity index by design.
    assert row.log_index is None
    db_session.refresh(mc)
    assert mc.last_known_state["rate"] == 9


def test_verification_read_without_a_diff_publishes_nothing(db_session, seeded):
    mc = seeded(WITNESS_TIER_HINT, state={"rate": 7})
    _run_scan(db_session, batch_result=lambda *_a, **_k: [("0x" + hex(7)[2:].zfill(64), "ok")])

    assert db_session.query(MonitoredEvent).count() == 0
    db_session.refresh(mc)
    # An earned negative touches nothing — not the state, not the status map.
    assert mc.last_known_state == {"rate": 7}
    assert not (mc.last_poll_status or {})


def test_first_observation_seeds_the_baseline_without_claiming_a_change(db_session, seeded):
    mc = seeded(WITNESS_TIER_HINT, state={})
    _run_scan(db_session, batch_result=lambda *_a, **_k: [("0x" + hex(9)[2:].zfill(64), "ok")])
    assert db_session.query(MonitoredEvent).count() == 0
    db_session.refresh(mc)
    assert mc.last_known_state["rate"] == 9


@pytest.mark.parametrize(
    "status,marker",
    [("error", VERIFY_ERROR), ("transport", VERIFY_UNANSWERED)],
)
def test_failed_read_records_not_determined_never_a_change(db_session, seeded, status, marker):
    mc = seeded(WITNESS_TIER_HINT, state={"rate": 7})
    _run_scan(db_session, batch_result=lambda *_a, **_k: [(None, status)])

    assert db_session.query(MonitoredEvent).count() == 0
    db_session.refresh(mc)
    assert mc.last_poll_status == {"rate": marker}
    assert mc.last_known_state == {"rate": 7}
    assert count_verification_read_gaps(db_session)["read_failed"] == 1


def test_over_budget_reads_are_recorded_not_dropped(db_session, seeded, monkeypatch):
    mc = seeded(WITNESS_TIER_HINT, state={"rate": 7})
    monkeypatch.setenv("PSAT_SCAN_MAX_VERIFY_READS_PER_PASS", "0")
    _, batch = _run_scan(db_session, batch_result=lambda *_a, **_k: [("0x", "ok")])

    batch.assert_not_called()
    assert db_session.query(MonitoredEvent).count() == 0
    db_session.refresh(mc)
    assert mc.last_poll_status == {"rate": VERIFY_OVER_BUDGET}
    gaps = count_verification_read_gaps(db_session)
    assert gaps == {
        "read_failed": 0,
        "over_budget": 1,
        "no_read_binding": 0,
        "contracts_affected": 1,
        # The census says what it is counting: markers present now, which the
        # poller erases — never a cumulative tally.
        "basis": CENSUS_BASIS,
    }


def _scan_detail(db_session, *, batch_result, **kwargs) -> dict:
    """One pass's heartbeat ``extra_detail``."""
    with patch("services.monitoring.unified_watcher.emit_monitor_cycle") as beat:
        _run_scan(db_session, batch_result=batch_result, **kwargs)
    return beat.call_args.kwargs["extra_detail"]


def test_failed_read_is_counted_on_the_pass_not_only_marked(db_session, seeded):
    """F9b wiring: the markers are erased by the poller's next answered pass, so
    on a healthy fleet the census is usually blind to a failure that happened.
    The pass counts its own outcomes, and the heartbeat carries them."""
    seeded(WITNESS_TIER_HINT, state={"rate": 7})
    detail = _scan_detail(db_session, batch_result=lambda *_a, **_k: [(None, "error")])
    assert detail["verification_reads_failed"] == 1
    assert detail["verification_reads_over_budget"] == 0


def test_over_budget_skips_are_counted_on_the_pass(db_session, seeded, monkeypatch):
    seeded(WITNESS_TIER_HINT, state={"rate": 7})
    monkeypatch.setenv("PSAT_SCAN_MAX_VERIFY_READS_PER_PASS", "0")
    detail = _scan_detail(db_session, batch_result=lambda *_a, **_k: [("0x", "ok")])
    assert detail["verification_reads_over_budget"] == 1
    assert detail["verification_reads_failed"] == 0


def test_an_answered_pass_reports_earned_zeroes(db_session, seeded):
    """Every dirty controller was read and answered — the zeroes are proven."""
    seeded(WITNESS_TIER_HINT, state={"rate": 7})
    detail = _scan_detail(db_session, batch_result=lambda *_a, **_k: [("0x" + hex(7)[2:].zfill(64), "ok")])
    assert detail["verification_reads_failed"] == 0
    assert detail["verification_reads_over_budget"] == 0


def test_a_verification_pass_that_died_reports_not_determined_not_zero(db_session, seeded):
    """A pass that never got to its outcomes has nothing to report — publishing
    0 there would state an earned negative the pass did not earn."""
    seeded(WITNESS_TIER_HINT, state={"rate": 7})
    with patch(
        "services.monitoring.unified_watcher._resolve_verification_reads",
        side_effect=RuntimeError("verification exploded"),
    ):
        detail = _scan_detail(db_session, batch_result=lambda *_a, **_k: [("0x", "ok")])
    assert detail["verification_reads_failed"] is None
    assert detail["verification_reads_over_budget"] is None


def test_verified_control_slot_change_triggers_reanalysis(db_session):
    """The reanalysis trigger keys off the READ's field, which is the
    witnessed fact — not the emitter's donated write set."""
    protocol = Protocol(name="taxonomy-reanalysis", chains=["ethereum"])
    db_session.add(protocol)
    db_session.flush()
    contract = Contract(protocol_id=protocol.id, address=ADDR(0x22), chain="ethereum")
    db_session.add(contract)
    db_session.flush()
    owner_topic = _topic0("OwnerBumped(address)")
    mc = MonitoredContract(
        id=uuid.uuid4(),
        address=ADDR(0x22),
        chain="ethereum",
        protocol_id=protocol.id,
        contract_id=contract.id,
        contract_type="regular",
        monitoring_config={
            "tracked_topics": [
                {
                    "topic0": owner_topic,
                    "signature": "OwnerBumped(address)",
                    "event_type": "state_changed:state_variable:owner",
                    "controller_id": "state_variable:owner",
                    "inputs": [{"name": "who", "type": "address", "indexed": True}],
                    "effect_tags": {"writes": ["owner", "nonce"]},
                    "witness_tier": WITNESS_TIER_HINT,
                }
            ],
            "polling_plan": [
                {
                    "field": "owner",
                    "kind": "getter_call",
                    "target": "owner",
                    "selector": "0x8da5cb5b",
                    "type_kind": "address",
                    "source": "analyzer:state_variable:owner",
                }
            ],
        },
        last_known_state={"owner": ADDR(0xAA)},
        last_scanned_block=100,
        enrollment_block=1,
        is_active=True,
    )
    db_session.add(mc)
    db_session.commit()

    log = FetchedEventLog(
        tx_hash=b"\x01" * 32,
        log_index=0,
        block_number=200,
        block_hash=b"\xbb" * 32,
        transaction_index=0,
        topics=[owner_topic, _word(ADDR(0xBB))],
        data_words=[],
        address=ADDR(0x22),
        raw={
            "address": ADDR(0x22),
            "topics": [owner_topic, _word(ADDR(0xBB))],
            "data": "0x",
            "blockNumber": "0xc8",
            "transactionHash": "0x" + "01" * 32,
            "logIndex": "0x0",
            "blockHash": "0x" + "bb" * 32,
            "transactionIndex": "0x0",
        },
    )
    with (
        patch("services.monitoring.unified_watcher.get_latest_block", return_value=1000),
        patch("services.monitoring.unified_watcher.RpcEventLogFetcher") as fetcher,
        patch(
            "services.monitoring.unified_watcher.rpc_batch_request_classified",
            side_effect=lambda *_a, **_k: [(_word(ADDR(0xBB)), "ok")],
        ),
    ):
        fetcher.return_value.fetch_logs.side_effect = lambda **_kw: [log]
        scan_for_events(db_session, "http://rpc.invalid")

    rows = db_session.execute(select(MonitoredEvent)).scalars().all()
    assert [r.event_type for r in rows] == ["value_changed:state_variable:owner"]
    jobs = db_session.execute(select(Job)).scalars().all()
    assert len(jobs) == 1
    request = jobs[0].request or {}
    assert request["reanalysis_trigger"] == "verified_read:owner"


# ---------------------------------------------------------------------------
# Review round 1 — read binding, write-through, lease, rotation
# ---------------------------------------------------------------------------


def test_only_a_proven_controller_identity_binds_a_read(db_session, seeded):
    """A polling entry is bound to a controller by its ``source`` stamp, never
    by sharing a field name.

    Two different slots share a name routinely — ``build_polling_plan`` drops
    an analyzer entry whose field collides with a vendored standard — so a name
    match would read one storage location and publish under another
    controller's id, and would let runtime re-classification PROMOTE a spec
    whose analyzer proved no getter at all.
    """
    mc = seeded(None, with_plan=False)
    config = dict(mc.monitoring_config or {})
    config["polling_plan"] = [
        # Same field name, different (vendored) origin — not this controller's.
        {
            "field": "rate",
            "kind": "storage_slot",
            "slot": "0x1",
            "type_kind": "address",
            "source": "vendored:eip1967",
        }
    ]
    mc.monitoring_config = config
    db_session.commit()

    assert _poll_entry_for_controller(mc, "state_variable:rate") is None
    # ... and so a tierless legacy spec is NOT promoted to hint by the name.
    assert _resolve_spec_tier(_tracked_spec(None), mc) == WITNESS_TIER_ACTIVITY


def test_unbindable_hint_records_not_determined(db_session, seeded):
    """Invariant 9: a hint that resolves to no read at all is recorded, not
    dropped — an unverifiable interval must not look like a quiet one."""
    mc = seeded(WITNESS_TIER_HINT, with_plan=False)
    dirty: dict = {}
    assert _process_window(db_session, _cohort(mc), _logs(2), 200, 210, dirty) == []
    db_session.commit()

    assert dirty == {}
    assert db_session.query(MonitoredEvent).count() == 0
    db_session.refresh(mc)
    assert mc.last_poll_status == {"controller:state_variable:rate": VERIFY_NO_READ_BINDING}
    assert count_verification_read_gaps(db_session)["no_read_binding"] == 1


def test_verification_read_writes_through_the_proxy_plane(db_session):
    """Whichever reader observes an implementation move first advances
    last_known_state and silences the other, so both must record it on the
    WatchedProxy plane. A missed write-through freezes
    ``last_known_implementation``, which is what the NEXT scanner-detected
    upgrade publishes as its old value."""
    protocol = Protocol(name="proxy-write-through", chains=["ethereum"])
    db_session.add(protocol)
    db_session.flush()
    contract = Contract(protocol_id=protocol.id, address=ADDR(0x44), chain="ethereum")
    db_session.add(contract)
    db_session.flush()
    proxy = WatchedProxy(
        id=uuid.uuid4(),
        proxy_address=ADDR(0x44),
        chain="ethereum",
        last_known_implementation=ADDR(0xA1),
        last_scanned_block=0,
    )
    db_session.add(proxy)
    db_session.flush()

    impl_topic = _topic0("ImplBumped(address)")
    mc = MonitoredContract(
        id=uuid.uuid4(),
        address=ADDR(0x44),
        chain="ethereum",
        protocol_id=protocol.id,
        contract_id=contract.id,
        watched_proxy_id=proxy.id,
        contract_type="proxy",
        monitoring_config={
            "tracked_topics": [
                {
                    "topic0": impl_topic,
                    "signature": "ImplBumped(address)",
                    "event_type": "state_changed:state_variable:implementation",
                    "controller_id": "state_variable:implementation",
                    "inputs": [{"name": "who", "type": "address", "indexed": True}],
                    "effect_tags": {"writes": ["implementation", "nonce"]},
                    "witness_tier": WITNESS_TIER_HINT,
                }
            ],
            "polling_plan": [
                {
                    "field": "implementation",
                    "kind": "getter_call",
                    "target": "implementation",
                    "selector": "0x5c60da1b",
                    "type_kind": "address",
                    "source": "analyzer:state_variable:implementation",
                }
            ],
        },
        last_known_state={"implementation": ADDR(0xA1)},
        last_scanned_block=100,
        enrollment_block=1,
        is_active=True,
    )
    db_session.add(mc)
    db_session.commit()

    log = FetchedEventLog(
        tx_hash=b"\x07" * 32,
        log_index=0,
        block_number=200,
        block_hash=b"\xbb" * 32,
        transaction_index=0,
        topics=[impl_topic, _word(ADDR(0xA2))],
        data_words=[],
        address=ADDR(0x44),
        raw={
            "address": ADDR(0x44),
            "topics": [impl_topic, _word(ADDR(0xA2))],
            "data": "0x",
            "blockNumber": "0xc8",
            "transactionHash": "0x" + "07" * 32,
            "logIndex": "0x0",
            "blockHash": "0x" + "bb" * 32,
            "transactionIndex": "0x0",
        },
    )
    with (
        patch("services.monitoring.unified_watcher.get_latest_block", return_value=1000),
        patch("services.monitoring.unified_watcher.RpcEventLogFetcher") as fetcher,
        patch(
            "services.monitoring.unified_watcher.rpc_batch_request_classified",
            side_effect=lambda *_a, **_k: [(_word(ADDR(0xA2)), "ok")],
        ),
    ):
        fetcher.return_value.fetch_logs.side_effect = lambda **_kw: [log]
        scan_for_events(db_session, "http://rpc.invalid")

    upgrades = db_session.execute(select(ProxyUpgradeEvent)).scalars().all()
    assert len(upgrades) == 1
    assert upgrades[0].old_implementation == ADDR(0xA1)
    assert upgrades[0].new_implementation == ADDR(0xA2)
    db_session.refresh(proxy)
    assert proxy.last_known_implementation == ADDR(0xA2)

    row = db_session.execute(select(MonitoredEvent)).scalars().one()
    assert row.event_type == "value_changed:state_variable:implementation"
    assert (row.data or {})["read_entry_source"] == "analyzer:state_variable:implementation"


def test_lost_scanner_lease_cancels_the_verification_reads(db_session, seeded):
    """value_changed rows carry log_index NULL and so sit outside the identity
    index — there is no ON CONFLICT to catch a second scanner's duplicate, and
    a duplicate is a duplicate Discord post and reanalysis job."""
    mc = seeded(WITNESS_TIER_HINT, state={"rate": 7})
    with (
        patch("services.monitoring.unified_watcher.get_latest_block", return_value=1000),
        patch("services.monitoring.unified_watcher.RpcEventLogFetcher") as fetcher,
        patch("services.monitoring.unified_watcher.renew_daemon_lease", return_value=False),
        patch("services.monitoring.unified_watcher.rpc_batch_request_classified") as batch,
    ):
        fetcher.return_value.fetch_logs.side_effect = lambda **_kw: _logs(2)
        scan_for_events(db_session, "http://rpc.invalid")

    batch.assert_not_called()
    assert db_session.query(MonitoredEvent).count() == 0
    db_session.refresh(mc)
    assert mc.last_known_state == {"rate": 7}


def test_budget_rotates_least_recently_verified_first():
    """A stable address+id sort hands the budget to the same controllers every
    pass and starves the tail forever."""
    from services.monitoring.unified_watcher import _LAST_VERIFIED_AT, _verification_read_order

    mc_id = uuid.uuid4()
    members = {
        (mc_id, cid): _DirtyController(
            monitored_contract_id=mc_id,
            controller_id=cid,
            chain="ethereum",
            address=ADDR(1),
            entry={"field": cid},
            block_number=1,
        )
        for cid in ("a_first", "b_second", "c_third")
    }
    _LAST_VERIFIED_AT.clear()
    try:
        # Cold: never-verified controllers sort by the deterministic tiebreak.
        assert [d.controller_id for d in _verification_read_order(members)] == [
            "a_first",
            "b_second",
            "c_third",
        ]
        # After "a_first" is read, it goes to the back rather than winning again.
        _LAST_VERIFIED_AT[(mc_id, "a_first")] = 100.0
        assert [d.controller_id for d in _verification_read_order(members)][-1] == "a_first"
    finally:
        _LAST_VERIFIED_AT.clear()


@pytest.mark.parametrize("witness", [True, "yes", 1, [], {}, ["x"]])
def test_only_a_populated_correspondence_record_promotes(witness):
    """The G2<->G3 trust boundary: a truthy non-dict is not a proof of
    emit-write correspondence, and accepting one would let a serialization bug
    upstream promote every event on the contract."""
    assert (
        classify_witness_tier(
            event_type="state_changed:state_variable:fromDenyList",
            controller_id="state_variable:fromDenyList",
            effect_tags={"writes": ["fromDenyList"]},
            member_witness=witness,
            writer_openness="restricted",
        )
        == WITNESS_TIER_ACTIVITY
    )


def test_events_from_a_stale_plan_carry_its_timestamp(db_session, seeded):
    """F5 keeps a last-good watch-list rather than manufacturing an empty one.
    The rows it catches are real, but the watch-list behind them is only as
    current as that timestamp, and what it MISSED is invisible by
    construction — so the event says so rather than reading fresh-equivalent."""
    mc = seeded(WITNESS_TIER_SELF_DESCRIBING)
    config = dict(mc.monitoring_config or {})
    config["tracked_topics_stale_since"] = "2026-08-01T00:00:00Z"
    mc.monitoring_config = config
    db_session.commit()

    events = _process_window(db_session, _cohort(mc), _logs(1), 200, 210, {})
    db_session.commit()
    assert (events[0].data or {})["plan_stale_since"] == "2026-08-01T00:00:00Z"


def test_read_verified_events_carry_no_plan_staleness(db_session, seeded):
    """Their claim rests on the read, which is current regardless of when the
    plan was last refreshed — stamping it would imply doubt about a proven
    fact."""
    mc = seeded(WITNESS_TIER_HINT, state={"rate": 7})
    config = dict(mc.monitoring_config or {})
    config["tracked_topics_stale_since"] = "2026-08-01T00:00:00Z"
    mc.monitoring_config = config
    db_session.commit()

    _run_scan(db_session, batch_result=lambda *_a, **_k: [("0x" + hex(9)[2:].zfill(64), "ok")])
    row = db_session.execute(select(MonitoredEvent)).scalars().one()
    assert "plan_stale_since" not in (row.data or {})


def _deadlock_error():
    import psycopg2
    from sqlalchemy.exc import OperationalError

    return OperationalError("UPDATE monitored_contracts ...", {}, psycopg2.errors.DeadlockDetected("deadlock detected"))


def _conn_lost_error():
    import psycopg2
    from sqlalchemy.exc import OperationalError

    return OperationalError("SELECT 1", {}, psycopg2.OperationalError("server closed the connection unexpectedly"))


def test_deadlocked_verification_unit_rolls_back_without_killing_the_pass(db_session, seeded):
    """maybe_queue_reanalysis's first statement autoflushes the staged
    last_known_state UPDATE against the rows the scanner's cohort UPDATE locks,
    so it is a deadlock candidate. Swallowing the DB error would leave the
    session pending-rollback and the NEXT member's sync would raise
    PendingRollbackError past the handler, taking the whole pass with it."""
    mc = seeded(WITNESS_TIER_HINT, state={"rate": 7})
    with (
        patch("services.monitoring.unified_watcher.get_latest_block", return_value=1000),
        patch("services.monitoring.unified_watcher.RpcEventLogFetcher") as fetcher,
        patch(
            "services.monitoring.unified_watcher.rpc_batch_request_classified",
            side_effect=lambda *_a, **_k: [("0x" + hex(9)[2:].zfill(64), "ok")],
        ),
        patch("services.monitoring.unified_watcher.maybe_queue_reanalysis", side_effect=_deadlock_error()),
    ):
        fetcher.return_value.fetch_logs.side_effect = lambda **_kw: _logs(2)
        result = scan_for_events(db_session, "http://rpc.invalid")

    # The unit rolled back with its event; the pass still returned normally.
    assert [e for e in result if str(e.event_type).startswith("value_changed")] == []
    assert db_session.query(MonitoredEvent).count() == 0
    db_session.refresh(mc)
    assert mc.last_known_state == {"rate": 7}
    # ...but it does NOT report clean. A deadlocked unit takes its events AND
    # its not-determined markers back with it, so this is the one failure in
    # the pass that leaves no surviving signal of itself; a healthy-looking
    # cycle would publish "nothing to see" for an interval nobody verified.
    assert result.degraded is True


def test_non_deadlock_db_error_is_not_swallowed_per_unit(db_session, seeded):
    """A lost connection is not per-unit recoverable — it must reach the
    caller so the pass records an honest degraded cycle."""
    seeded(WITNESS_TIER_HINT, state={"rate": 7})
    with (
        patch("services.monitoring.unified_watcher.get_latest_block", return_value=1000),
        patch("services.monitoring.unified_watcher.RpcEventLogFetcher") as fetcher,
        patch(
            "services.monitoring.unified_watcher.rpc_batch_request_classified",
            side_effect=lambda *_a, **_k: [("0x" + hex(9)[2:].zfill(64), "ok")],
        ),
        patch("services.monitoring.unified_watcher.maybe_queue_reanalysis", side_effect=_conn_lost_error()),
    ):
        fetcher.return_value.fetch_logs.side_effect = lambda **_kw: _logs(2)
        result = scan_for_events(db_session, "http://rpc.invalid")
    # scan_for_events catches it at the pass boundary and marks the cycle
    # degraded rather than pretending the reads happened.
    assert result.degraded is True
    assert db_session.query(MonitoredEvent).count() == 0


def test_reads_are_issued_before_any_write_is_staged(db_session, seeded):
    """Transaction shape: holding row locks on monitored_contracts across
    network IO is what the scanner's cohort UPDATE deadlocks against, so every
    RPC for a chain is issued before that chain's writes are staged."""
    seeded(WITNESS_TIER_HINT, state={"rate": 7})
    dirty_at_read_time: list[bool] = []

    def _batch(*_a, **_k):
        # Nothing may be pending on the session when the wire is dialled.
        dirty_at_read_time.append(bool(db_session.dirty or db_session.new))
        return [("0x" + hex(9)[2:].zfill(64), "ok")]

    with (
        patch("services.monitoring.unified_watcher.get_latest_block", return_value=1000),
        patch("services.monitoring.unified_watcher.RpcEventLogFetcher") as fetcher,
        patch("services.monitoring.unified_watcher.rpc_batch_request_classified", side_effect=_batch),
    ):
        fetcher.return_value.fetch_logs.side_effect = lambda **_kw: _logs(2)
        scan_for_events(db_session, "http://rpc.invalid")

    assert dirty_at_read_time == [False]


def test_unbindable_hint_marker_converges(db_session, seeded):
    """The marker is stamped once, not once per occurrence.

    An unbound controller is usually one whose events are frequent — that is
    why it was hinted at all — so re-stamping an identical value would emit a
    monitored_contracts UPDATE on every window forever, inside the same
    transaction that carries the scanner's cursor UPDATE. That is the
    documented deadlock counterpart to the poller.
    """
    mc = seeded(WITNESS_TIER_HINT, with_plan=False)
    key = "controller:state_variable:rate"

    _process_window(db_session, _cohort(mc), _logs(2), 200, 210, {})
    db_session.commit()
    assert (mc.last_poll_status or {})[key] == VERIFY_NO_READ_BINDING

    # Second pass over the same controller writes nothing new.
    assert record_unresolvable_read(mc, "state_variable:rate") is False
    _process_window(db_session, _cohort(mc), _logs(2), 220, 230, {})
    assert mc not in db_session.dirty

    # A different unbound controller still records its own key.
    assert record_unresolvable_read(mc, "state_variable:other") is True
    assert set(mc.last_poll_status or {}) == {key, "controller:state_variable:other"}
