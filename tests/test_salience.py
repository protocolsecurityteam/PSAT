"""The salience spine: §4.2's rule table, the mechanical gate that keeps
``routine`` honest, E5's ``signal_class``, the three mint sites, the notifier
opt-in, and the enrichment recompute seam.

The census this file backs is a per-RULE one: every row of §4.2 is exercised
here with its basis code asserted, so a rule that stops firing (or starts
firing on the wrong shape) fails a named test rather than drifting.

The mechanical gate has its own section: **no ``routine`` is minted from an
absent input.** Both routine arms rest on a positive finding — a stamped
``signal_class`` carrying its own basis, or a decoded ``not_top_level_call``
status — and each of those inputs is removed in a test that requires the level
to fall back to ``not_determined`` (visible), never to ``routine``.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
from eth_utils.crypto import keccak
from sqlalchemy import select

from db.models import (
    Contract,
    MonitoredContract,
    MonitoredEvent,
    Protocol,
    ProtocolSubscription,
)
from services.monitoring import salience as sal
from services.monitoring.enrichment import ENRICHERS, NEEDS_TX, enrich_events
from services.monitoring.notifier import _salience_allows, notify_protocol_events
from services.monitoring.polling_plan import (
    SIGNAL_BASIS_CALLER_GATE,
    SIGNAL_BASIS_NO_GATE_PROVENANCE,
    SIGNAL_BASIS_TYPE_KIND_REFERENCE,
    SIGNAL_CLASS_CONFIG,
    SIGNAL_CLASS_METRIC,
    build_polling_plan,
)
from services.monitoring.unified_watcher import (
    _apply_poll_result,
    _Cohort,
    _process_window,
    scan_for_events,
)
from services.resolution.repos.event_logs_rpc import FetchedEventLog


def ADDR(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


SAFE = ADDR(0x5AFE)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def make_mc(db_session):
    protocol = Protocol(name="salience", chains=["ethereum"])
    db_session.add(protocol)
    db_session.flush()
    counter = iter(range(0x5AFE, 0x6000))

    def make(
        *,
        address: str | None = None,
        contract_type: str = "regular",
        enrollment_block: int | None = 1,
        monitoring_config: dict | None = None,
        last_known_state: dict | None = None,
    ) -> MonitoredContract:
        # Each call gets its own address: ``contracts`` is uniquely keyed on
        # (address, chain), so a test that needs two contracts cannot share one.
        address = address or ADDR(next(counter))
        contract = Contract(protocol_id=protocol.id, address=address, chain="ethereum")
        db_session.add(contract)
        db_session.flush()
        mc = MonitoredContract(
            id=uuid.uuid4(),
            address=address,
            chain="ethereum",
            protocol_id=protocol.id,
            contract_id=contract.id,
            contract_type=contract_type,
            monitoring_config=monitoring_config or {},
            last_known_state=last_known_state or {},
            last_scanned_block=100,
            enrollment_block=enrollment_block,
            is_active=True,
        )
        db_session.add(mc)
        db_session.commit()
        return mc

    return make


def rate(db_session, mc, event_type: str, data: dict | None = None) -> tuple[str, list[str]]:
    return sal.assign_salience(db_session, event_type, data, mc)


# ---------------------------------------------------------------------------
# §4.2 rule table — one named test per rule, basis asserted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("event_type", sorted(sal.CANONICAL_CONFIG_FAMILIES))
def test_rule_canonical_config_family(db_session, make_mc, event_type):
    """Every hand-rolled family whose single occurrence IS the change."""
    assert rate(db_session, make_mc(), event_type, {}) == (
        sal.SALIENCE_ALERT,
        [sal.BASIS_CANONICAL_CONFIG_FAMILY],
    )


def test_the_canonical_family_list_is_exactly_the_spec_list(db_session, make_mc):
    """A type NOT on the list may not be folded in silently — it falls through
    to ``not_determined`` (visible), which is the honest answer for a family
    nobody rated."""
    assert "new_pending_implementation" not in sal.CANONICAL_CONFIG_FAMILIES
    level, basis = rate(db_session, make_mc(), "new_pending_implementation", {})
    assert (level, basis) == (sal.SALIENCE_NOT_DETERMINED, [sal.BASIS_NO_RULE])


@pytest.mark.parametrize("event_type", ["safe_tx_failed", "safe_module_failed"])
def test_rule_execution_failure(db_session, make_mc, event_type):
    """An execution that reverted is an anomaly by construction — and it
    outranks every safe_exec rule below, so a failed indirect call is still
    an alert."""
    assert rate(db_session, make_mc(), event_type, {"safe_exec": {"status": "not_top_level_call"}}) == (
        sal.SALIENCE_ALERT,
        [sal.BASIS_EXECUTION_FAILURE],
    )


def test_rule_safe_exec_delegatecall_unrecognized(db_session, make_mc):
    """Not proven to be MultiSend ⇒ raise. The absent recognition flag is the
    reason to alert, not a reason to demote."""
    data = {"safe_exec": {"status": "decoded", "operation": 1, "to": ADDR(0xBAD)}}
    assert rate(db_session, make_mc(), "safe_tx_executed", data) == (
        sal.SALIENCE_ALERT,
        [sal.BASIS_SAFE_EXEC_DELEGATECALL_UNRECOGNIZED],
    )


def test_rule_module_bypass_execution(db_session, make_mc):
    assert rate(db_session, make_mc(), "safe_module_executed", {"module": ADDR(7)}) == (
        sal.SALIENCE_ALERT,
        [sal.BASIS_MODULE_BYPASS_EXECUTION],
    )


def test_rule_qualified_member_change(db_session, make_mc):
    assert rate(db_session, make_mc(), "member_changed:fromDenyList", {"key": ADDR(3)}) == (
        sal.SALIENCE_ALERT,
        [sal.BASIS_QUALIFIED_MEMBER_CHANGE],
    )


def test_rule_reinitialization(db_session, make_mc):
    """A second Initialized on an enrolled proxy is a takeover signal; the
    first one is a deployment doing what deployments do."""
    mc = make_mc()
    # No prior row yet — nothing to reinitialize from.
    assert rate(db_session, mc, "initialized", {}) == (sal.SALIENCE_NOT_DETERMINED, [sal.BASIS_NO_RULE])

    db_session.add(
        MonitoredEvent(
            id=uuid.uuid4(),
            monitored_contract_id=mc.id,
            event_type="initialized",
            block_number=5,
            tx_hash="0x" + "11" * 32,
            log_index=0,
            data={},
        )
    )
    db_session.commit()
    assert rate(db_session, mc, "initialized", {}) == (sal.SALIENCE_ALERT, [sal.BASIS_REINITIALIZATION])


def test_reinitialization_needs_an_enrollment_block(db_session, make_mc):
    """Without a floor there is no "since we started watching", so the prior
    row cannot be shown to be a *re*-initialization."""
    mc = make_mc(enrollment_block=None)
    db_session.add(
        MonitoredEvent(
            id=uuid.uuid4(),
            monitored_contract_id=mc.id,
            event_type="initialized",
            block_number=5,
            tx_hash="0x" + "22" * 32,
            log_index=0,
            data={},
        )
    )
    db_session.commit()
    assert rate(db_session, mc, "initialized", {}) == (sal.SALIENCE_NOT_DETERMINED, [sal.BASIS_NO_RULE])


@pytest.mark.parametrize("event_type", ["state_changed_poll", "value_changed:state_variable:owner"])
def test_rule_config_field_diff(db_session, make_mc, event_type):
    data = {"signal_class": SIGNAL_CLASS_CONFIG, "signal_class_basis": SIGNAL_BASIS_TYPE_KIND_REFERENCE}
    assert rate(db_session, make_mc(), event_type, data) == (
        sal.SALIENCE_NOTABLE,
        [sal.BASIS_CONFIG_FIELD_DIFF],
    )


@pytest.mark.parametrize("event_type", ["timelock_scheduled", "timelock_executed"])
def test_rule_timelock_operation(db_session, make_mc, event_type):
    assert rate(db_session, make_mc(), event_type, {"target": ADDR(4)}) == (
        sal.SALIENCE_NOTABLE,
        [sal.BASIS_TIMELOCK_OPERATION],
    )


def test_rule_safe_exec_call(db_session, make_mc):
    """A decoded call is substantive whether or not a name resolves — name
    resolution is display, never level."""
    unnamed = {"safe_exec": {"status": "decoded", "operation": 0, "to": ADDR(9), "signature": None}}
    named = {"safe_exec": {"status": "decoded", "operation": 0, "to": ADDR(9), "signature": "setFee(uint256)"}}
    expected = (sal.SALIENCE_NOTABLE, [sal.BASIS_SAFE_EXEC_CALL])
    mc = make_mc()
    assert rate(db_session, mc, "safe_tx_executed", unnamed) == expected
    assert rate(db_session, mc, "safe_tx_executed", named) == expected


def test_rule_safe_exec_multisend_takes_the_batch_floor(db_session, make_mc):
    data = {
        "safe_exec": {
            "status": "decoded",
            "operation": 1,
            "multisend_recognized": True,
            "batch": [
                {"operation": 0, "to": ADDR(1)},
                {"operation": 0, "to": ADDR(2)},
            ],
        }
    }
    assert rate(db_session, make_mc(), "safe_tx_executed", data) == (
        sal.SALIENCE_NOTABLE,
        [sal.BASIS_SAFE_EXEC_MULTISEND],
    )


def test_rule_safe_exec_multisend_takes_the_max_over_inner_calls(db_session, make_mc):
    """An inner delegatecall to a target not proven to be MultiSend escalates
    the whole batch — the batch's level is the max, not its floor."""
    data = {
        "safe_exec": {
            "status": "decoded",
            "operation": 1,
            "multisend_recognized": True,
            "batch": [
                {"operation": 0, "to": ADDR(1)},
                {"operation": 1, "to": ADDR(0xBAD)},
            ],
        }
    }
    assert rate(db_session, make_mc(), "safe_tx_executed", data) == (
        sal.SALIENCE_ALERT,
        [sal.BASIS_SAFE_EXEC_MULTISEND, sal.BASIS_SAFE_EXEC_DELEGATECALL_UNRECOGNIZED],
    )


def test_rule_safe_exec_batch_undecodable(db_session, make_mc):
    """A truncated batch would understate what the Safe did, so the level
    refuses rather than rating a partial list."""
    data = {
        "safe_exec": {
            "status": "decoded",
            "operation": 1,
            "multisend_recognized": True,
            "batch_status": "undecodable",
        }
    }
    assert rate(db_session, make_mc(), "safe_tx_executed", data) == (
        sal.SALIENCE_NOT_DETERMINED,
        [sal.BASIS_SAFE_EXEC_BATCH_UNDECODABLE],
    )


@pytest.mark.parametrize(
    "event_type",
    ["state_changed:state_variable:rebalancer", "controller_changed:state_variable:rebalancer"],
)
def test_rule_tracked_config_event(db_session, make_mc, event_type):
    assert rate(db_session, make_mc(), event_type, {"witness_tier": "self_describing"}) == (
        sal.SALIENCE_NOTABLE,
        [sal.BASIS_TRACKED_CONFIG_EVENT],
    )


def test_rule_correlated_cause_raises_to_the_effect_max(db_session, make_mc):
    """Same transaction hash is a fact, not an inference: a routine execution
    that caused an alert is at least as salient as what it caused."""
    data = {
        "safe_exec": {"status": "not_top_level_call"},
        "correlated_events": [
            {"event_id": "a", "event_type": "state_changed_poll", "salience": sal.SALIENCE_ROUTINE},
            {"event_id": "b", "event_type": "ownership_transferred", "salience": sal.SALIENCE_ALERT},
        ],
    }
    assert rate(db_session, make_mc(), "safe_tx_executed", data) == (
        sal.SALIENCE_ALERT,
        [sal.BASIS_SAFE_EXEC_INDIRECT, sal.BASIS_CORRELATED_CAUSE],
    )


def test_rule_correlated_cause_floors_at_notable(db_session, make_mc):
    """An effect whose own level is unknown contributes the floor, never a
    guess — and never lets the cause stay routine."""
    data = {
        "safe_exec": {"status": "not_top_level_call"},
        "correlated_events": [{"event_id": "a", "event_type": "whatever"}],
    }
    assert rate(db_session, make_mc(), "safe_tx_executed", data) == (
        sal.SALIENCE_NOTABLE,
        [sal.BASIS_SAFE_EXEC_INDIRECT, sal.BASIS_CORRELATED_CAUSE],
    )


def test_correlated_cause_replaces_no_rule(db_session, make_mc):
    """``no_rule`` would be a false statement once correlation rated the row."""
    data = {"correlated_events": [{"event_id": "a", "event_type": "paused", "salience": sal.SALIENCE_ALERT}]}
    assert rate(db_session, make_mc(), "some_unrated_type", data) == (
        sal.SALIENCE_ALERT,
        [sal.BASIS_CORRELATED_CAUSE],
    )


def test_an_empty_correlation_list_changes_nothing(db_session, make_mc):
    """The join is scoped to what is monitored, so an empty list is NOT an
    earned negative and must not move the level in either direction."""
    data = {
        "safe_exec": {"status": "not_top_level_call"},
        "correlated_events": [],
        "correlated_scope": "monitored_only",
    }
    assert rate(db_session, make_mc(), "safe_tx_executed", data) == (
        sal.SALIENCE_ROUTINE,
        [sal.BASIS_SAFE_EXEC_INDIRECT],
    )


@pytest.mark.parametrize("event_type", ["state_changed_poll", "value_changed:state_variable:_totalSupply"])
def test_rule_metric_field_diff(db_session, make_mc, event_type):
    data = {"signal_class": SIGNAL_CLASS_METRIC, "signal_class_basis": SIGNAL_BASIS_NO_GATE_PROVENANCE}
    assert rate(db_session, make_mc(), event_type, data) == (
        sal.SALIENCE_ROUTINE,
        [sal.BASIS_METRIC_FIELD_DIFF],
    )


def test_rule_safe_exec_indirect(db_session, make_mc):
    """A POSITIVE finding — the observed tx was proven not to be a direct
    execTransaction on this Safe."""
    assert rate(db_session, make_mc(), "safe_tx_executed", {"safe_exec": {"status": "not_top_level_call"}}) == (
        sal.SALIENCE_ROUTINE,
        [sal.BASIS_SAFE_EXEC_INDIRECT],
    )


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"safe_tx_hash": "0x" + "ab" * 32},
        {"safe_exec": {"status": "over_budget"}},
    ],
    ids=["absent-block", "phase-1-steady-state", "over-budget"],
)
def test_rule_safe_exec_not_enriched(db_session, make_mc, data):
    """The phase-1 steady state. A Safe execution we could not examine is
    unclassified and VISIBLE — never demoted on ignorance."""
    assert rate(db_session, make_mc(), "safe_tx_executed", data) == (
        sal.SALIENCE_NOT_DETERMINED,
        [sal.BASIS_SAFE_EXEC_NOT_ENRICHED],
    )


def test_rule_no_rule_for_everything_else(db_session, make_mc):
    assert rate(db_session, make_mc(), "some_future_event_type", {"x": 1}) == (
        sal.SALIENCE_NOT_DETERMINED,
        [sal.BASIS_NO_RULE],
    )
    assert rate(db_session, make_mc(), "some_future_event_type", None) == (
        sal.SALIENCE_NOT_DETERMINED,
        [sal.BASIS_NO_RULE],
    )


# ---------------------------------------------------------------------------
# The mechanical gate — no ``routine`` from an absent input
# ---------------------------------------------------------------------------


def test_a_field_diff_with_no_signal_class_is_not_determined(db_session, make_mc):
    """The fleet's persisted polling plans predate the stamp. Until a
    re-enrollment pass runs, every poll diff lands HERE — visible — and not on
    the routine arm."""
    for data in ({}, {"field": "x", "old_value": "1", "new_value": "2"}):
        assert rate(db_session, make_mc(), "state_changed_poll", data) == (
            sal.SALIENCE_NOT_DETERMINED,
            [sal.BASIS_NO_RULE],
        )


def test_a_metric_class_without_its_basis_cannot_mint_routine(db_session, make_mc):
    """``metric ⇒ routine`` is earned by a stated basis. A class with no basis
    is a row that LOOKS classified and is not."""
    for basis in (None, "", 3):
        data = {"signal_class": SIGNAL_CLASS_METRIC, "signal_class_basis": basis}
        level, codes = rate(db_session, make_mc(), "state_changed_poll", data)
        assert level == sal.SALIENCE_NOT_DETERMINED
        assert codes == [sal.BASIS_NO_RULE]


def test_no_rule_mints_routine_without_a_positive_basis(db_session, make_mc):
    """The gate, stated as one assertion over the whole surface: the only two
    inputs that produce ``routine`` are a stamped metric class with a basis and
    a decoded ``not_top_level_call`` status. Everything else — including every
    shape with the relevant input REMOVED — must land elsewhere."""
    mc = make_mc()
    shapes: list[tuple[str, dict | None]] = [
        ("state_changed_poll", None),
        ("state_changed_poll", {}),
        ("state_changed_poll", {"signal_class": SIGNAL_CLASS_METRIC}),
        ("state_changed_poll", {"signal_class": "made_up"}),
        ("value_changed:state_variable:x", {}),
        ("value_changed:state_variable:x", {"signal_class_basis": SIGNAL_BASIS_NO_GATE_PROVENANCE}),
        ("safe_tx_executed", {}),
        ("safe_tx_executed", {"safe_exec": {}}),
        ("safe_tx_executed", {"safe_exec": {"status": "over_budget"}}),
        ("safe_tx_executed", {"safe_exec": {"status": "decoded"}}),
        ("safe_module_executed", {}),
        ("initialized", {}),
        ("unknown_type", {}),
    ]
    for event_type, data in shapes:
        level, codes = rate(db_session, mc, event_type, data)
        assert level != sal.SALIENCE_ROUTINE, (event_type, data, codes)


def test_every_level_ships_a_non_empty_basis_from_the_closed_vocabulary(db_session, make_mc):
    """Invariant 6, over every shape this file exercises."""
    mc = make_mc()
    shapes: list[tuple[str, dict | None]] = [
        ("ownership_transferred", {}),
        ("safe_tx_failed", {}),
        ("safe_module_executed", {}),
        ("member_changed:x", {}),
        ("initialized", {}),
        ("timelock_scheduled", {}),
        ("state_changed:state_variable:x", {}),
        ("state_changed_poll", {"signal_class": "config", "signal_class_basis": "caller_gate"}),
        ("state_changed_poll", {"signal_class": "metric", "signal_class_basis": "no_gate_provenance"}),
        ("safe_tx_executed", {}),
        ("safe_tx_executed", {"safe_exec": {"status": "not_top_level_call"}}),
        ("safe_tx_executed", {"safe_exec": {"status": "decoded", "operation": 0}}),
        ("safe_tx_executed", {"safe_exec": {"status": "decoded", "operation": 1}}),
        ("anything_else", {}),
    ]
    for event_type, data in shapes:
        level, codes = rate(db_session, mc, event_type, data)
        assert level in sal.SALIENCE_VALUES
        assert codes, (event_type, data)
        assert set(codes) <= sal.SALIENCE_BASIS_VALUES, (event_type, codes)


def test_not_determined_sorts_with_notable_never_with_routine():
    """Invariant 5 as arithmetic."""
    assert sal.salience_rank(sal.SALIENCE_NOT_DETERMINED) == sal.salience_rank(sal.SALIENCE_NOTABLE)
    assert sal.salience_rank(sal.SALIENCE_NOT_DETERMINED) > sal.salience_rank(sal.SALIENCE_ROUTINE)
    assert sal.salience_rank(sal.SALIENCE_ALERT) > sal.salience_rank(sal.SALIENCE_NOTABLE)
    # An unknown / absent level is measured at not_determined, never at routine.
    assert sal.salience_rank(None) == sal.salience_rank(sal.SALIENCE_NOT_DETERMINED)
    assert sal.salience_rank("bogus") == sal.salience_rank(sal.SALIENCE_NOT_DETERMINED)


def test_salience_is_orthogonal_to_witness_tier(db_session, make_mc):
    """Invariant 3: neither is derived from the other. The same maximally
    proven tier spans three levels here."""
    mc = make_mc()
    proven = {"witness_tier": "self_describing"}
    assert rate(db_session, mc, "ownership_transferred", proven)[0] == sal.SALIENCE_ALERT
    assert rate(db_session, mc, "state_changed:state_variable:x", proven)[0] == sal.SALIENCE_NOTABLE
    assert rate(db_session, mc, "initialized", proven)[0] == sal.SALIENCE_NOT_DETERMINED


# ---------------------------------------------------------------------------
# E5 — signal_class on freshly built polling plans
# ---------------------------------------------------------------------------


def _tracking_plan(*controllers: dict) -> dict:
    return {"schema_version": "0.1", "tracked_controllers": list(controllers)}


def _controller(controller_id: str, *, type_kind: str, type_str: str = "", provenance: str | None = None) -> dict:
    tc: dict = {
        "controller_id": controller_id,
        "label": controller_id,
        "read_spec": {
            "strategy": "getter_call",
            "target": controller_id.split(":")[-1],
            "state_variable_name": controller_id.split(":")[-1],
            "type_kind": type_kind,
            "type": type_str,
        },
    }
    if provenance:
        tc["authority_provenance"] = provenance
    return tc


def _by_field(plan: list[dict]) -> dict[str, dict]:
    return {entry["field"]: entry for entry in plan}


def test_reference_typed_entries_classify_config():
    plan = _by_field(
        build_polling_plan(
            contract_type="regular",
            tracking_plan=_tracking_plan(
                _controller("state_variable:owner", type_kind="address"),
                _controller("state_variable:priceProvider", type_kind="contract"),
            ),
        )
    )
    for field in ("owner", "priceProvider"):
        assert plan[field]["signal_class"] == SIGNAL_CLASS_CONFIG
        assert plan[field]["signal_class_basis"] == SIGNAL_BASIS_TYPE_KIND_REFERENCE


def test_a_proven_caller_gate_primitive_classifies_config():
    plan = _by_field(
        build_polling_plan(
            contract_type="regular",
            tracking_plan=_tracking_plan(
                _controller("state_variable:isPaused", type_kind="primitive", type_str="bool", provenance="caller_gate")
            ),
        )
    )
    assert plan["isPaused"]["signal_class"] == SIGNAL_CLASS_CONFIG
    assert plan["isPaused"]["signal_class_basis"] == SIGNAL_BASIS_CALLER_GATE


def test_an_ungated_primitive_classifies_metric_with_a_stated_basis():
    """The honest default: an unclassified number is not presumed to be a
    control parameter. ``no_gate_provenance`` is a POSITIVE basis — the
    derivation completed for this entry and carried no gate proof — which is
    what lets it collapse at render without suppressing on ignorance."""
    plan = _by_field(
        build_polling_plan(
            contract_type="regular",
            tracking_plan=_tracking_plan(
                _controller("state_variable:_totalSupply", type_kind="primitive", type_str="uint256")
            ),
        )
    )
    assert plan["_totalSupply"]["signal_class"] == SIGNAL_CLASS_METRIC
    assert plan["_totalSupply"]["signal_class_basis"] == SIGNAL_BASIS_NO_GATE_PROVENANCE


def test_call_target_provenance_is_not_a_gate_proof():
    """``call_target`` means "called, and no gate was proven" — the same
    not-a-proof the event-type resolver refuses to mint a controller claim on."""
    plan = _by_field(
        build_polling_plan(
            contract_type="regular",
            tracking_plan=_tracking_plan(
                _controller(
                    "state_variable:threshold2",
                    type_kind="primitive",
                    type_str="uint256",
                    provenance="call_target",
                )
            ),
        )
    )
    assert plan["threshold2"]["signal_class"] == SIGNAL_CLASS_METRIC
    assert plan["threshold2"]["signal_class_basis"] == SIGNAL_BASIS_NO_GATE_PROVENANCE


@pytest.mark.parametrize(
    "contract_type,proxy_type,field,basis",
    [
        ("safe", None, "threshold", "vendored:safe"),
        ("safe", None, "guard", "vendored:safe"),
        ("safe", None, "modules_head", "vendored:safe"),
        ("timelock", None, "min_delay", "vendored:timelock"),
        ("proxy", "eip1967", "implementation", "vendored:eip1967"),
    ],
)
def test_vendored_entries_classify_config_with_their_own_provenance(contract_type, proxy_type, field, basis):
    plan = _by_field(build_polling_plan(contract_type=contract_type, proxy_type=proxy_type))
    assert plan[field]["signal_class"] == SIGNAL_CLASS_CONFIG
    assert plan[field]["signal_class_basis"] == basis


def test_every_freshly_built_entry_carries_both_keys_or_neither():
    """A class without its basis cannot mint ``routine``, so writing one alone
    would only produce a row that looks classified and is not."""
    plan = build_polling_plan(
        contract_type="safe",
        proxy_type="eip1967",
        tracking_plan=_tracking_plan(
            _controller("state_variable:owner", type_kind="address"),
            _controller("state_variable:rate", type_kind="primitive", type_str="uint256"),
            _controller("state_variable:cap", type_kind="primitive", type_str="uint256", provenance="caller_gate"),
        ),
    )
    assert plan
    for entry in plan:
        assert entry.get("signal_class") in (SIGNAL_CLASS_CONFIG, SIGNAL_CLASS_METRIC), entry
        assert entry.get("signal_class_basis"), entry


# ---------------------------------------------------------------------------
# Mint site 3 — the rotation poller
# ---------------------------------------------------------------------------


def _poll_entry(signal_class: str | None = None, basis: str | None = None) -> dict:
    entry = {
        "field": "rate",
        "kind": "getter_call",
        "target": "rate",
        "selector": RATE_SELECTOR,
        "type_kind": "primitive",
        "type": "uint256",
        "source": "analyzer:state_variable:rate",
    }
    if signal_class:
        entry["signal_class"] = signal_class
    if basis:
        entry["signal_class_basis"] = basis
    return entry


def _poll(db_session, mc, entry, raw_value: int) -> dict:
    new_events: list[MonitoredEvent] = []
    _apply_poll_result(db_session, mc, entry, "0x" + hex(raw_value)[2:].zfill(64), new_events)
    db_session.commit()
    assert len(new_events) == 1
    return new_events[0].data or {}


def test_poll_mint_stamps_the_entrys_signal_class_and_a_routine_level(db_session, make_mc):
    mc = make_mc(last_known_state={"rate": 7})
    data = _poll(db_session, mc, _poll_entry(SIGNAL_CLASS_METRIC, SIGNAL_BASIS_NO_GATE_PROVENANCE), 9)
    assert data["signal_class"] == SIGNAL_CLASS_METRIC
    assert data["signal_class_basis"] == SIGNAL_BASIS_NO_GATE_PROVENANCE
    assert data["salience"] == sal.SALIENCE_ROUTINE
    assert data["salience_basis"] == [sal.BASIS_METRIC_FIELD_DIFF]


def test_poll_mint_from_a_config_entry_is_notable(db_session, make_mc):
    mc = make_mc(last_known_state={"rate": 7})
    data = _poll(db_session, mc, _poll_entry(SIGNAL_CLASS_CONFIG, SIGNAL_BASIS_CALLER_GATE), 9)
    assert data["salience"] == sal.SALIENCE_NOTABLE
    assert data["salience_basis"] == [sal.BASIS_CONFIG_FIELD_DIFF]


def test_poll_mint_from_a_pre_stamp_entry_is_visible_not_routine(db_session, make_mc):
    """The phase-1 freshness dependency, at the mint site: a persisted plan
    entry carrying no ``signal_class`` stamps nothing, and the row renders."""
    mc = make_mc(last_known_state={"rate": 7})
    data = _poll(db_session, mc, _poll_entry(), 9)
    assert "signal_class" not in data
    assert data["salience"] == sal.SALIENCE_NOT_DETERMINED
    assert data["salience_basis"] == [sal.BASIS_NO_RULE]


def test_poll_mint_refuses_a_half_stamped_entry(db_session, make_mc):
    mc = make_mc(last_known_state={"rate": 7})
    data = _poll(db_session, mc, _poll_entry(SIGNAL_CLASS_METRIC, None), 9)
    assert "signal_class" not in data
    assert data["salience"] == sal.SALIENCE_NOT_DETERMINED


# ---------------------------------------------------------------------------
# Mint sites 1 and 2 — the scanner and the verification read
# ---------------------------------------------------------------------------

SAFE_EXEC_TOPIC0 = "0x" + keccak(text="ExecutionSuccess(bytes32,uint256)").hex()
OWNERSHIP_TOPIC0 = "0x" + keccak(text="OwnershipTransferred(address,address)").hex()
RATE_TOPIC0 = "0x" + keccak(text="RateUpdated(uint256)").hex()
RATE_SELECTOR = "0x" + keccak(text="rate()").hex()[:8]


def _fetched(topic0: str, *, address: str, data: str = "0x", block: int = 200, idx: int = 0) -> FetchedEventLog:
    raw = {
        "address": address,
        "topics": [topic0],
        "data": data,
        "blockNumber": hex(block),
        "transactionHash": "0x" + f"{idx:064x}",
        "logIndex": hex(idx),
        "blockHash": "0x" + "b" * 64,
        "transactionIndex": "0x0",
    }
    return FetchedEventLog(
        tx_hash=bytes.fromhex(f"{idx:064x}"),
        log_index=idx,
        block_number=block,
        block_hash=b"\xbb" * 32,
        transaction_index=0,
        topics=[topic0],
        data_words=[],
        address=address,
        raw=raw,
    )


def test_scan_mint_stamps_salience_on_the_persisted_row(db_session, make_mc):
    """Mint site 1. Assigned before the insert, so the level is durable in the
    same write as the row."""
    mc = make_mc(contract_type="safe", monitoring_config={"watch_safe_signers": True})
    cohort = _Cohort(chain="ethereum", member_ids=[mc.id], addresses=[mc.address.lower()], cursor=199)
    log = _fetched(SAFE_EXEC_TOPIC0, address=mc.address, data="0x" + "ab" * 32 + "00" * 32)
    events = _process_window(db_session, cohort, [log], 200, 210, {})
    db_session.commit()

    assert len(events) == 1
    persisted = db_session.execute(select(MonitoredEvent)).scalars().one()
    assert persisted.event_type == "safe_tx_executed"
    # Phase 1: no enricher, so the Safe execution is unclassified and VISIBLE.
    assert persisted.data["salience"] == sal.SALIENCE_NOT_DETERMINED
    assert persisted.data["salience_basis"] == [sal.BASIS_SAFE_EXEC_NOT_ENRICHED]


def test_scan_mint_rates_a_canonical_family_as_alert(db_session, make_mc):
    mc = make_mc(monitoring_config={"watch_ownership": True})
    cohort = _Cohort(chain="ethereum", member_ids=[mc.id], addresses=[mc.address.lower()], cursor=199)
    log = _fetched(OWNERSHIP_TOPIC0, address=mc.address, data="0x" + "00" * 32 + "00" * 31 + "07")
    _process_window(db_session, cohort, [log], 200, 210, {})
    db_session.commit()

    persisted = db_session.execute(select(MonitoredEvent)).scalars().one()
    assert persisted.event_type == "ownership_transferred"
    assert persisted.data["salience"] == sal.SALIENCE_ALERT
    assert persisted.data["salience_basis"] == [sal.BASIS_CANONICAL_CONFIG_FAMILY]


def _hint_spec() -> dict:
    return {
        "topic0": RATE_TOPIC0,
        "signature": "RateUpdated(uint256)",
        "event_type": "state_changed:state_variable:rate",
        "controller_id": "state_variable:rate",
        "witness_tier": "hint",
        "inputs": [{"name": "rate", "type": "uint256", "indexed": False}],
        "effect_tags": {"writes": ["rate", "lastUpdate"]},
        "writer_openness": "not_determined",
    }


def test_verification_read_mint_stamps_the_entrys_signal_class(db_session, make_mc):
    """Mint site 2. The plan entry that ANSWERED is in scope only here, so its
    class rides onto the row the read produced."""
    entry = _poll_entry(SIGNAL_CLASS_METRIC, SIGNAL_BASIS_NO_GATE_PROVENANCE)
    mc = make_mc(
        monitoring_config={"tracked_topics": [_hint_spec()], "polling_plan": [entry]},
        last_known_state={"rate": 7},
    )
    log = _fetched(RATE_TOPIC0, address=mc.address, data="0x" + hex(11)[2:].zfill(64))

    with (
        patch("services.monitoring.unified_watcher.get_latest_block", return_value=1000),
        patch("services.monitoring.unified_watcher.RpcEventLogFetcher") as fetcher,
        patch(
            "services.monitoring.unified_watcher.rpc_batch_request_classified",
            side_effect=lambda *_a, **_k: [("0x" + hex(9)[2:].zfill(64), "ok")],
        ),
    ):
        fetcher.return_value.fetch_logs.side_effect = lambda **_kw: [log]
        scan_for_events(db_session, "http://rpc.invalid")

    row = (
        db_session.execute(
            select(MonitoredEvent).where(MonitoredEvent.event_type == "value_changed:state_variable:rate")
        )
        .scalars()
        .one()
    )
    assert row.data["signal_class"] == SIGNAL_CLASS_METRIC
    assert row.data["signal_class_basis"] == SIGNAL_BASIS_NO_GATE_PROVENANCE
    assert row.data["salience"] == sal.SALIENCE_ROUTINE
    assert row.data["salience_basis"] == [sal.BASIS_METRIC_FIELD_DIFF]
    # Invariant 1: the routine level did not gate the insert.
    assert row.data["witness"] == "read_verified"


# ---------------------------------------------------------------------------
# The enrichment recompute seam
# ---------------------------------------------------------------------------


def _seed_event(db_session, mc, event_type: str, data: dict) -> MonitoredEvent:
    event = MonitoredEvent(
        id=uuid.uuid4(),
        monitored_contract_id=mc.id,
        event_type=event_type,
        block_number=10,
        tx_hash="0x" + "cd" * 32,
        log_index=0,
        data=data,
    )
    db_session.add(event)
    db_session.commit()
    return event


def test_the_empty_driver_leaves_rows_untouched(db_session, make_mc):
    """Phase 1's registry is empty, so the driver is a no-op on every real
    row — including the salience the mint site already assigned."""
    assert ENRICHERS == {}
    assert NEEDS_TX == frozenset()

    mc = make_mc(contract_type="safe")
    before = {
        "safe_tx_hash": "0x" + "ab" * 32,
        "salience": sal.SALIENCE_NOT_DETERMINED,
        "salience_basis": [sal.BASIS_SAFE_EXEC_NOT_ENRICHED],
    }
    event = _seed_event(db_session, mc, "safe_tx_executed", dict(before))

    enrich_events(db_session, [event], {"ethereum": "http://rpc.invalid"})
    db_session.commit()
    db_session.expire_all()

    assert db_session.get(MonitoredEvent, event.id).data == before


def test_the_driver_recomputes_salience_for_rows_an_enricher_changed(db_session, make_mc):
    """Step 6 is part of the contract, not an optimization: enrichment changes
    the inputs the rules read, so the mint-time level is provisional and the
    post-enrichment level is what the notifier and the frontend see."""
    mc = make_mc(contract_type="safe")
    event = _seed_event(
        db_session,
        mc,
        "safe_tx_executed",
        {
            "safe_tx_hash": "0x" + "ab" * 32,
            "salience": sal.SALIENCE_NOT_DETERMINED,
            "salience_basis": [sal.BASIS_SAFE_EXEC_NOT_ENRICHED],
        },
    )

    def fake(_event, _mc, _ctx):
        return {"safe_exec": {"status": "decoded", "operation": 1, "to": ADDR(0xBAD)}}

    with patch.dict(ENRICHERS, {"safe_tx_executed": fake}, clear=False):
        enrich_events(db_session, [event], {"ethereum": "http://rpc.invalid"})
    db_session.commit()
    db_session.expire_all()

    data = db_session.get(MonitoredEvent, event.id).data
    assert data["safe_exec"]["status"] == "decoded"
    assert data["salience"] == sal.SALIENCE_ALERT
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_DELEGATECALL_UNRECOGNIZED]


def test_a_failing_enricher_leaves_the_row_as_the_taxonomy_wrote_it(db_session, make_mc):
    """§3.0 rule 4: enrichment failure is never fatal, and never rewrites."""
    mc = make_mc(contract_type="safe")
    before = {"salience": sal.SALIENCE_NOT_DETERMINED, "salience_basis": [sal.BASIS_SAFE_EXEC_NOT_ENRICHED]}
    event = _seed_event(db_session, mc, "safe_tx_executed", dict(before))

    def boom(_event, _mc, _ctx):
        raise RuntimeError("decode exploded")

    with patch.dict(ENRICHERS, {"safe_tx_executed": boom}, clear=False):
        enrich_events(db_session, [event], {"ethereum": "http://rpc.invalid"})
    db_session.commit()
    db_session.expire_all()

    assert db_session.get(MonitoredEvent, event.id).data == before


def test_the_driver_never_changes_event_type_or_witness_tier(db_session, make_mc):
    """Invariant 8: enrichment is additive."""
    mc = make_mc(contract_type="safe")
    event = _seed_event(
        db_session,
        mc,
        "safe_tx_executed",
        {"witness_tier": "self_describing", "salience": sal.SALIENCE_NOT_DETERMINED, "salience_basis": ["x"]},
    )

    def fake(_event, _mc, _ctx):
        return {"safe_exec": {"status": "not_top_level_call"}}

    with patch.dict(ENRICHERS, {"safe_tx_executed": fake}, clear=False):
        enrich_events(db_session, [event], {"ethereum": "http://rpc.invalid"})
    db_session.commit()
    db_session.expire_all()

    row = db_session.get(MonitoredEvent, event.id)
    assert row.event_type == "safe_tx_executed"
    assert row.data["witness_tier"] == "self_describing"
    assert row.data["salience"] == sal.SALIENCE_ROUTINE


# ---------------------------------------------------------------------------
# §5a — the notifier opt-in
# ---------------------------------------------------------------------------


@pytest.fixture()
def notify_env(db_session, make_mc):
    mc = make_mc(monitoring_config={"watch_ownership": True})
    sub = ProtocolSubscription(
        id=uuid.uuid4(),
        protocol_id=mc.protocol_id,
        discord_webhook_url="https://discord.invalid/hook",
    )
    db_session.add(sub)
    db_session.commit()

    def emit(event_type: str, data: dict | None) -> MonitoredEvent:
        event = _seed_event(db_session, mc, event_type, data or {})
        db_session.refresh(event)
        return event

    return sub, emit


@pytest.mark.parametrize(
    "minimum,level,allowed",
    [
        (None, "routine", True),
        (None, None, True),
        ("routine", "routine", True),
        ("notable", "routine", False),
        ("notable", "notable", True),
        ("notable", "not_determined", True),
        ("notable", None, True),
        ("notable", "alert", True),
        ("alert", "notable", False),
        ("alert", "not_determined", False),
        ("alert", "alert", True),
        ("nonsense", "routine", True),
    ],
)
def test_salience_allows(db_session, notify_env, minimum, level, allowed):
    """``not_determined`` passes a ``notable`` threshold — an event the
    classifier never rated must not be dropped by a bar it was never measured
    against. It does NOT pass ``alert``: that threshold asks for proven alerts."""
    sub, emit = notify_env
    sub.event_filter = {"min_salience": minimum} if minimum else None
    db_session.commit()
    event = emit("ownership_transferred", {"salience": level} if level else {})
    assert _salience_allows(sub, event) is allowed


def test_a_subscription_without_min_salience_receives_exactly_what_it_does_today(db_session, notify_env):
    """Invariant 7: no existing subscription is muted."""
    sub, emit = notify_env
    assert sub.event_filter is None
    event = emit("ownership_transferred", {"salience": sal.SALIENCE_ROUTINE, "new_owner": ADDR(9)})
    with patch("services.monitoring.notifier._send_discord") as send:
        notify_protocol_events(db_session, [event])
    assert send.call_count == 1


def test_min_salience_composes_with_the_event_type_filter(db_session, notify_env):
    """Both must pass. The type filter alone still admits; adding the
    threshold subtracts, and only for the subscription that asked."""
    sub, emit = notify_env
    routine = emit("ownership_transferred", {"salience": sal.SALIENCE_ROUTINE, "new_owner": ADDR(9)})

    sub.event_filter = {"event_types": ["ownership_transferred"]}
    db_session.commit()
    with patch("services.monitoring.notifier._send_discord") as send:
        notify_protocol_events(db_session, [routine])
    assert send.call_count == 1

    sub.event_filter = {"event_types": ["ownership_transferred"], "min_salience": "notable"}
    db_session.commit()
    with patch("services.monitoring.notifier._send_discord") as send:
        notify_protocol_events(db_session, [routine])
    assert send.call_count == 0

    sub.event_filter = {"event_types": ["paused"], "min_salience": "routine"}
    db_session.commit()
    with patch("services.monitoring.notifier._send_discord") as send:
        notify_protocol_events(db_session, [routine])
    assert send.call_count == 0


def test_min_salience_never_overrides_the_tier_gate(db_session, notify_env):
    """Invariant 2 / integrity-spec invariant 5: an occurrence that only proves
    a writer ran never pages anyone, at any salience."""
    sub, emit = notify_env
    sub.event_filter = {"min_salience": "routine"}
    db_session.commit()
    event = emit("ownership_transferred", {"witness_tier": "hint", "salience": sal.SALIENCE_ALERT})
    with patch("services.monitoring.notifier._send_discord") as send:
        notify_protocol_events(db_session, [event])
    assert send.call_count == 0


# ---------------------------------------------------------------------------
# §5b — the API boundary
# ---------------------------------------------------------------------------


def test_the_api_passes_salience_through_verbatim(db_session, api_client, make_mc):
    """``list_monitored_events`` serializes ``data`` whole — no key whitelist,
    no projection — so the level and its basis reach the frontend for free.
    Pinned because the frontend's ``eventSalience`` reads exactly this, and a
    field silently dropped at the boundary would render as ``not_determined``
    on every row while the DB held the real answer."""
    mc = make_mc()
    _seed_event(
        db_session,
        mc,
        "ownership_transferred",
        {
            "new_owner": ADDR(9),
            "salience": sal.SALIENCE_ALERT,
            "salience_basis": [sal.BASIS_CANONICAL_CONFIG_FAMILY],
        },
    )

    body = api_client.get(f"/api/monitored-events?address={mc.address}&chain=ethereum").json()
    assert len(body) == 1
    assert body[0]["data"]["salience"] == sal.SALIENCE_ALERT
    assert body[0]["data"]["salience_basis"] == [sal.BASIS_CANONICAL_CONFIG_FAMILY]
    # The rest of the payload is untouched by the added keys.
    assert body[0]["data"]["new_owner"] == ADDR(9)


def test_a_poll_row_carries_its_signal_class_through_the_api(db_session, api_client, make_mc):
    """The census's basis lives on the row, so it has to survive the boundary
    too — that is where an auditor reads it."""
    mc = make_mc(last_known_state={"rate": 7})
    _poll(db_session, mc, _poll_entry(SIGNAL_CLASS_METRIC, SIGNAL_BASIS_NO_GATE_PROVENANCE), 9)

    body = api_client.get(f"/api/monitored-events?address={mc.address}&chain=ethereum").json()
    assert len(body) == 1
    assert body[0]["data"]["signal_class"] == SIGNAL_CLASS_METRIC
    assert body[0]["data"]["signal_class_basis"] == SIGNAL_BASIS_NO_GATE_PROVENANCE
    assert body[0]["data"]["salience"] == sal.SALIENCE_ROUTINE


# ---------------------------------------------------------------------------
# Invariant 8, enforced at the driver
# ---------------------------------------------------------------------------


def test_the_driver_refuses_an_enrichers_non_additive_keys(db_session, make_mc):
    """An enricher may not move a side-effect decision from the taxonomy to a
    decoder: ``witness_tier`` is what ``notifier._may_notify`` reads, and
    ``event_type`` is the claim itself."""
    mc = make_mc(contract_type="safe")
    event = _seed_event(
        db_session,
        mc,
        "safe_tx_executed",
        {
            "witness_tier": "hint",
            "historical": True,
            "salience": sal.SALIENCE_NOT_DETERMINED,
            "salience_basis": [sal.BASIS_SAFE_EXEC_NOT_ENRICHED],
        },
    )

    def overreaching(_event, _mc, _ctx):
        return {
            "safe_exec": {"status": "not_top_level_call"},
            "witness_tier": "self_describing",
            "historical": False,
            "event_type": "ownership_transferred",
            "reanalysis_job_id": "nope",
        }

    with patch.dict(ENRICHERS, {"safe_tx_executed": overreaching}, clear=False):
        enrich_events(db_session, [event], {"ethereum": "http://rpc.invalid"})
    db_session.commit()
    db_session.expire_all()

    row = db_session.get(MonitoredEvent, event.id)
    # The additive key landed and drove the recompute...
    assert row.data["safe_exec"] == {"status": "not_top_level_call"}
    assert row.data["salience"] == sal.SALIENCE_ROUTINE
    # ...and every key the taxonomy owns is exactly as it was.
    assert row.data["witness_tier"] == "hint"
    assert row.data["historical"] is True
    assert "reanalysis_job_id" not in row.data
    assert row.event_type == "safe_tx_executed"


def test_an_enricher_producing_only_refused_keys_changes_nothing(db_session, make_mc):
    mc = make_mc(contract_type="safe")
    before = {"witness_tier": "hint", "salience": sal.SALIENCE_NOT_DETERMINED, "salience_basis": ["x"]}
    event = _seed_event(db_session, mc, "safe_tx_executed", dict(before))

    with patch.dict(ENRICHERS, {"safe_tx_executed": lambda *_a: {"witness_tier": "self_describing"}}, clear=False):
        enrich_events(db_session, [event], {"ethereum": "http://rpc.invalid"})
    db_session.commit()
    db_session.expire_all()

    assert db_session.get(MonitoredEvent, event.id).data == before


def test_a_chainless_contract_is_skipped_rather_than_defaulted(db_session, make_mc, caplog):
    """No chain means no endpoint and no chain_id guard. Enriching it against
    whatever ethereum answered would publish another chain's transaction as
    this contract's decode."""
    mc = make_mc(contract_type="safe")
    event = _seed_event(db_session, mc, "safe_tx_executed", {"salience": sal.SALIENCE_NOT_DETERMINED})
    mc.chain = ""
    db_session.commit()

    calls: list[str] = []

    def fake(_event, _mc, _ctx):
        calls.append("ran")
        return {"safe_exec": {"status": "decoded", "operation": 0}}

    with patch.dict(ENRICHERS, {"safe_tx_executed": fake}, clear=False):
        enrich_events(db_session, [event], {"ethereum": "http://rpc.invalid"})

    assert calls == []
    db_session.expire_all()
    assert "safe_exec" not in (db_session.get(MonitoredEvent, event.id).data or {})


def test_an_unresolvable_chain_costs_that_chain_not_the_window(db_session, make_mc):
    """``enrich_events`` never raises: the window's rows are already correct
    and a chain-resolution failure must not roll them back."""
    mc = make_mc(contract_type="safe")
    event = _seed_event(db_session, mc, "safe_tx_executed", {"salience": sal.SALIENCE_NOT_DETERMINED})

    def boom(_chain, **_kw):
        raise RuntimeError("unknown chain")

    with (
        patch("services.monitoring.enrichment.chain_id_for", side_effect=boom),
        patch.dict(ENRICHERS, {"safe_tx_executed": lambda *_a: {"safe_exec": {"status": "decoded"}}}, clear=False),
    ):
        enrich_events(db_session, [event], {"ethereum": "http://rpc.invalid"})

    db_session.commit()
    db_session.expire_all()
    assert "safe_exec" not in (db_session.get(MonitoredEvent, event.id).data or {})


def test_max_salience_requires_a_stated_floor():
    """A max fold over an empty sequence would have to seed at ``routine`` —
    the one level the mechanical gate forbids from an absent input. Callers
    state their own floor instead."""
    with pytest.raises(TypeError):
        sal.max_salience()  # type: ignore[call-arg]
    assert sal.max_salience(sal.SALIENCE_NOTABLE) == sal.SALIENCE_NOTABLE
    assert sal.max_salience(sal.SALIENCE_NOTABLE, *[]) == sal.SALIENCE_NOTABLE
    assert sal.max_salience(sal.SALIENCE_ROUTINE) == sal.SALIENCE_ROUTINE
