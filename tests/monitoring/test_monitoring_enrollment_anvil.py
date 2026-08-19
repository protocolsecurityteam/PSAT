"""Anvil regression tests for the monitoring enrollment classifier.

End-to-end coverage for the bugs fixed in the
``protocol-monitoring-console`` branch:

* **Bug 1** — a state-variable-destination Safe (e.g. a Safe stored in
  ``accountantState.payoutAddress``) used to be enrolled as a fully
  monitored governance multisig because the CGN walk only checked
  ``resolved_type``. The fix gates controller enrollment on
  ``FunctionPrincipal`` membership.
* **Bug 5** — controllers enrolled in a prior run whose CGN evidence
  disappeared in a later re-analysis (observed on prod-etherfi: 4 of 5
  monitored timelocks were zombies) used to survive indefinitely.
  ``_enroll_controller_addresses`` now demotes any active auto-enrolled
  safe/timelock/proxy row whose address lacks current FP authority,
  regardless of whether CGN still surfaces it.
* **Bug 6** — CGN-discovered proxy admins were enrolled by Pass 1 then
  immediately deactivated by the stale-detection pass because
  ``'proxy'`` was missing from its "always keep" subset. Fixed by
  mirroring the controller-type set the enrollment uses.
* **initial_state owner whitelist** — ``_build_initial_state`` used
  the same substring-match bug ``services/aggregations/company_overview``
  had already fixed: ``"owner" in controller_id`` false-positives on
  ``pendingOwner`` / ``previousOwner`` / ``roleOwner`` and last-write-
  wins would latch the wrong slot into ``last_known_state.owner``.

Each test deploys minimal Solidity stand-ins on a local Anvil node so
the assertions exercise real ``rpc_request``/``eth_getLogs`` paths.
The DB-side governance evidence (``Contract`` / ``Job`` /
``ControlGraphNode`` / ``EffectiveFunction`` / ``FunctionPrincipal`` /
``ControllerValue``) is built directly because the upstream analysis
pipeline that normally produces it is out of scope for an enrollment
unit test — what matters here is the enrollment+scanner classifier
behavior given the canonical pipeline outputs.

Requires ``anvil``, ``cast``, ``forge`` on ``PATH`` and
``TEST_DATABASE_URL`` pointing at a Postgres instance with the
PSAT schema applied.

Run:
    uv run pytest tests/monitoring/test_monitoring_enrollment_anvil.py -v
"""

from __future__ import annotations

import os
import shutil

import pytest
from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session as SASession

from db.models import (
    Base,
    Contract,
    ControlGraphNode,
    ControllerValue,
    EffectiveFunction,
    FunctionPrincipal,
    Job,
    JobStage,
    JobStatus,
    MonitoredContract,
    Protocol,
    WatchedProxy,
)
from tests.conftest import requires_postgres
from tests.support.anvil import (
    ACCOUNT0,
    OWNABLE_SOURCE,
    PRIVATE_KEY,
    _cast_send,
    _compile_and_deploy,
    anvil_env,  # noqa: F401
)

_has_anvil = shutil.which("anvil") is not None
_has_cast = shutil.which("cast") is not None
_has_forge = shutil.which("forge") is not None

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")

pytestmark = [
    pytest.mark.skipif(not _has_anvil, reason="anvil not found on PATH"),
    pytest.mark.skipif(not _has_cast, reason="cast not found on PATH"),
    pytest.mark.skipif(not _has_forge, reason="forge not found on PATH"),
    requires_postgres,
    pytest.mark.anvil,
    pytest.mark.compile,
]

ACCOUNT1 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

# Distinct protocol name namespaces this test module's rows; teardown
# cascade-deletes everything keyed off it. Picked to be cheap to grep.
PROTO_NAME = "__test_enrollment_anvil__"


@pytest.fixture(autouse=True)
def _disable_scan_confirmation_depth(monkeypatch):
    # These anvil chains are only a handful of blocks long; the production
    # 12-block confirmation clamp would hide every just-emitted event.
    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")


# ---------------------------------------------------------------------------
# Solidity stand-ins. Selectors and event signatures match the real Gnosis
# Safe / OZ Ownable so the unified-watcher's topic registry recognises them.
# ---------------------------------------------------------------------------


SAFE_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TestSafe {
    address[] internal _owners;
    uint256 internal _threshold;
    event AddedOwner(address owner);
    event RemovedOwner(address owner);
    event ChangedThreshold(uint256 threshold);

    constructor() {
        _owners.push(msg.sender);
        _threshold = 1;
    }

    function getOwners() external view returns (address[] memory) { return _owners; }
    function getThreshold() external view returns (uint256) { return _threshold; }

    function addOwner(address _owner) external {
        _owners.push(_owner);
        emit AddedOwner(_owner);
    }

    function removeOwner(address _owner) external {
        for (uint i = 0; i < _owners.length; i++) {
            if (_owners[i] == _owner) {
                _owners[i] = _owners[_owners.length - 1];
                _owners.pop();
                break;
            }
        }
        emit RemovedOwner(_owner);
    }

    function changeThreshold(uint256 t) external {
        _threshold = t;
        emit ChangedThreshold(t);
    }
}
"""

# Stand-in for a contract that delegates upgrade authority to a separate
# ``ProxyAdmin``-like address. Doesn't need to be a real proxy shell —
# enrollment only cares about the CGN classification.
ROLE_PRINCIPAL_HOST_SOURCE = OWNABLE_SOURCE


SOLMATE_OWNED_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Solmate Owned shape: OwnerUpdated(user, newOwner) — distinct topic0
// from OZ OwnershipTransferred. Used to exercise the full enrollment
// pipeline that consumes a tracking_plan instead of relying on the
// hand-rolled global registry.
contract TestSolmateOwned {
    address public owner;
    event OwnerUpdated(address indexed user, address indexed newOwner);

    constructor() {
        owner = msg.sender;
        emit OwnerUpdated(address(0), msg.sender);
    }

    function setOwner(address newOwner) external {
        require(msg.sender == owner, "UNAUTHORIZED");
        owner = newOwner;
        emit OwnerUpdated(msg.sender, newOwner);
    }
}
"""


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def test_db():
    """Postgres session with the full schema. Cleans up rows tied to
    :data:`PROTO_NAME` so this module never collides with other tests
    sharing the same DB.
    """
    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine)
    session = SASession(engine, expire_on_commit=False)
    try:
        yield session
    finally:
        session.rollback()
        # Delete in FK-respecting order; everything else cascades via Contract /
        # Protocol deletion (EF→FP cascades on EF.id).
        proto = session.execute(select(Protocol).where(Protocol.name == PROTO_NAME)).scalar_one_or_none()
        if proto:
            for mc in session.execute(
                select(MonitoredContract).where(MonitoredContract.protocol_id == proto.id)
            ).scalars():
                if mc.watched_proxy_id:
                    wp = session.get(WatchedProxy, mc.watched_proxy_id)
                    if wp:
                        session.delete(wp)
                session.delete(mc)
            for j in session.execute(select(Job).where(Job.protocol_id == proto.id)).scalars():
                session.delete(j)
            for c in session.execute(select(Contract).where(Contract.protocol_id == proto.id)).scalars():
                session.delete(c)
            session.delete(proto)
        # Force ORM session sync before commit so any cascade-pending
        # deletes flush. The pre-existing ``filter(False).delete()`` no-op
        # construct was both dead code and a pyright miss; a plain flush
        # accomplishes the actual intent.
        session.flush()
        session.commit()
        session.close()
        engine.dispose()


# ---------------------------------------------------------------------------
# Pipeline-shape fixture builders. Mirror what the upstream analysis
# pipeline produces so enrollment exercises the same code path it would
# in prod — but constructed by hand so we can pin specific edge cases.
# ---------------------------------------------------------------------------


def _make_protocol(session: SASession) -> Protocol:
    proto = Protocol(name=PROTO_NAME)
    session.add(proto)
    session.flush()
    return proto


def _add_protocol_contract(
    session: SASession,
    protocol_id: int,
    address: str,
    contract_name: str = "TestContract",
    is_proxy: bool = False,
    proxy_type: str | None = None,
    implementation: str | None = None,
) -> Contract:
    contract = Contract(
        address=address.lower(),
        chain="ethereum",
        protocol_id=protocol_id,
        contract_name=contract_name,
        is_proxy=is_proxy,
        proxy_type=proxy_type,
        implementation=implementation,
    )
    session.add(contract)
    session.flush()
    job = Job(
        address=address.lower(),
        protocol_id=protocol_id,
        status=JobStatus.completed,
        stage=JobStage.done,
    )
    session.add(job)
    session.flush()
    return contract


def _grant_authority(
    session: SASession,
    contract_id: int,
    principal_address: str,
    function_name: str = "setOwner",
) -> None:
    """Attach a FunctionPrincipal row so *principal_address* is treated
    as having call authority on ``contract_id`` for the FP-gated
    enrollment classifier."""
    ef = EffectiveFunction(contract_id=contract_id, function_name=function_name, authority_public=False)
    session.add(ef)
    session.flush()
    session.add(FunctionPrincipal(function_id=ef.id, address=principal_address.lower(), principal_type="controller"))
    session.flush()


def _add_cgn(
    session: SASession,
    contract_id: int,
    address: str,
    resolved_type: str,
    label: str,
    depth: int = 1,
) -> ControlGraphNode:
    node = ControlGraphNode(
        contract_id=contract_id,
        address=address.lower(),
        node_type="principal",
        resolved_type=resolved_type,
        label=label,
        depth=depth,
    )
    session.add(node)
    session.flush()
    return node


# ---------------------------------------------------------------------------
# Bug 1 — state-variable destination Safe is not enrolled and gets no
# scanner attention.
# ---------------------------------------------------------------------------


def test_bug1_state_variable_destination_safe_not_enrolled_and_not_scanned(anvil_env, test_db):
    """Recreates the etherfi-dev shape: two Safes on a vault, one labeled
    'owner' (real governor, has FP authority) and one labeled
    'accountantState.payoutAddress' (fee destination, no FP authority).
    Only the real Safe should land in monitored_contracts and have its
    signer changes detected by the scanner.
    """
    from services.monitoring.enrollment import enroll_protocol_contracts
    from services.monitoring.unified_watcher import scan_for_events

    rpc_url, tmp_path = anvil_env
    real_safe = _compile_and_deploy(SAFE_SOURCE, "TestSafe", [], rpc_url, PRIVATE_KEY, tmp_path)
    fee_safe = _compile_and_deploy(SAFE_SOURCE, "TestSafe", [], rpc_url, PRIVATE_KEY, tmp_path)
    vault = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)

    proto = _make_protocol(test_db)
    vault_contract = _add_protocol_contract(test_db, proto.id, vault, contract_name="TestVault")

    # CGN evidence: both Safes surface as resolved_type='safe', differentiated
    # only by their label — the exact ambiguity the old code couldn't see past.
    _add_cgn(test_db, vault_contract.id, real_safe, resolved_type="safe", label="owner")
    _add_cgn(
        test_db,
        vault_contract.id,
        fee_safe,
        resolved_type="safe",
        label="accountantState.payoutAddress",
    )
    # FP evidence: only the real Safe controls a function.
    _grant_authority(test_db, vault_contract.id, real_safe, function_name="transferOwnership")
    test_db.commit()

    enroll_protocol_contracts(test_db, proto.id, rpc_url, "ethereum")

    real_mc = test_db.execute(
        select(MonitoredContract).where(MonitoredContract.address == real_safe)
    ).scalar_one_or_none()
    fee_mc = test_db.execute(
        select(MonitoredContract).where(MonitoredContract.address == fee_safe)
    ).scalar_one_or_none()

    assert real_mc is not None, "Real governance Safe should be enrolled"
    assert real_mc.is_active is True
    assert real_mc.contract_type == "safe"
    assert real_mc.enrollment_source == "auto"
    assert fee_mc is None, (
        f"Fee-destination Safe must not be enrolled (got is_active="
        f"{getattr(fee_mc, 'is_active', None)}, source="
        f"{getattr(fee_mc, 'enrollment_source', None)})"
    )

    # On-chain proof: emit signer events on both Safes; only the real one
    # should produce MonitoredEvent rows.
    _cast_send(real_safe, "addOwner(address)", [ACCOUNT1], rpc_url)
    _cast_send(fee_safe, "addOwner(address)", [ACCOUNT1], rpc_url)
    events = scan_for_events(test_db, rpc_url)

    real_evts = [e for e in events if e.event_type == "signer_added"]
    assert len(real_evts) == 1, (
        f"Exactly one signer_added event expected (from the real Safe); got {len(real_evts)} "
        f"from {[e.data for e in real_evts]}"
    )
    # MonitoredEvent.data may not carry the contract address explicitly;
    # cross-check against the monitored_contract_id to be sure.
    real_event_target = (
        test_db.execute(
            select(MonitoredContract.address).where(MonitoredContract.id == real_evts[0].monitored_contract_id)
        )
    ).scalar_one()
    assert real_event_target == real_safe


# ---------------------------------------------------------------------------
# Bug 5 — zombie controller demoted when CGN+FP evidence both disappear,
# and stops getting event scans.
# ---------------------------------------------------------------------------


def test_bug5_zombie_safe_demoted_and_skipped_by_scanner(anvil_env, test_db):
    """A Safe legitimately enrolled in run 1 must be deactivated on run 2
    when its CGN node and FP rows both disappear (re-analysis dropped
    them). The scanner must not surface events for the demoted row.
    """
    from services.monitoring.enrollment import enroll_protocol_contracts
    from services.monitoring.unified_watcher import scan_for_events

    rpc_url, tmp_path = anvil_env
    safe_addr = _compile_and_deploy(SAFE_SOURCE, "TestSafe", [], rpc_url, PRIVATE_KEY, tmp_path)
    host_addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)

    proto = _make_protocol(test_db)
    host_contract = _add_protocol_contract(test_db, proto.id, host_addr, contract_name="Host")

    cgn_node = _add_cgn(test_db, host_contract.id, safe_addr, resolved_type="safe", label="owner")
    _grant_authority(test_db, host_contract.id, safe_addr, function_name="setOwner")
    test_db.commit()

    # Run 1: Safe enrolled & active.
    enroll_protocol_contracts(test_db, proto.id, rpc_url, "ethereum")
    first = test_db.execute(select(MonitoredContract).where(MonitoredContract.address == safe_addr)).scalar_one()
    assert first.is_active is True
    assert first.enrollment_source == "auto"

    # Pre-demotion: scanner reports the Safe's signer change.
    _cast_send(safe_addr, "addOwner(address)", [ACCOUNT1], rpc_url)
    events = scan_for_events(test_db, rpc_url)
    pre = [e for e in events if e.event_type == "signer_added"]
    assert len(pre) == 1, "Active Safe should produce one signer_added event"

    # Simulate the analysis pipeline rebuilding without this controller:
    # the CGN node, EF row, and FP row all go away.
    test_db.delete(cgn_node)
    ef_ids = [
        ef_id
        for (ef_id,) in test_db.execute(
            select(EffectiveFunction.id).where(EffectiveFunction.contract_id == host_contract.id)
        ).all()
    ]
    if ef_ids:
        test_db.execute(delete(FunctionPrincipal).where(FunctionPrincipal.function_id.in_(ef_ids)))
        test_db.execute(delete(EffectiveFunction).where(EffectiveFunction.id.in_(ef_ids)))
    test_db.commit()
    test_db.expire_all()

    # Run 2: zombie state — re-enroll should demote the Safe.
    enroll_protocol_contracts(test_db, proto.id, rpc_url, "ethereum")
    demoted = test_db.execute(select(MonitoredContract).where(MonitoredContract.address == safe_addr)).scalar_one()
    assert demoted.is_active is False, (
        f"Zombie Safe should be deactivated (got is_active={demoted.is_active}, source={demoted.enrollment_source})"
    )
    assert demoted.enrollment_source == "auto_deprimary"

    # Trigger another on-chain change; scanner must skip the inactive row.
    _cast_send(safe_addr, "changeThreshold(uint256)", ["2"], rpc_url)
    post = scan_for_events(test_db, rpc_url)
    post_for_safe = [e for e in post if e.event_type in ("signer_added", "signer_removed", "threshold_changed")]
    assert post_for_safe == [], (
        f"Demoted Safe should not produce any events; got {[(e.event_type, e.data) for e in post_for_safe]}"
    )


# ---------------------------------------------------------------------------
# Bug 6 — CGN-discovered proxy admin stays is_active=True across
# successive re-enrollments. The old stale-detection pass deactivated
# them because 'proxy' wasn't in its keep-subset.
# ---------------------------------------------------------------------------


def test_bug6_proxy_admin_controller_survives_re_enrollment(anvil_env, test_db):
    """A CGN-discovered ``proxy_admin`` becomes a MC row with
    ``contract_type='proxy'``. Before the fix, the stale-detection pass
    immediately set is_active=False on every re-enrollment. Now it
    should stay active across N runs.
    """
    from services.monitoring.enrollment import enroll_protocol_contracts

    rpc_url, tmp_path = anvil_env
    admin_addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
    host_addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)

    proto = _make_protocol(test_db)
    host_contract = _add_protocol_contract(test_db, proto.id, host_addr, contract_name="Host")

    _add_cgn(test_db, host_contract.id, admin_addr, resolved_type="proxy_admin", label="admin")
    _grant_authority(test_db, host_contract.id, admin_addr, function_name="upgrade")
    test_db.commit()

    enroll_protocol_contracts(test_db, proto.id, rpc_url, "ethereum")
    first = test_db.execute(select(MonitoredContract).where(MonitoredContract.address == admin_addr)).scalar_one()
    assert first.contract_type == "proxy"
    assert first.is_active is True
    assert first.enrollment_source == "auto"

    # Re-enroll twice without changing any underlying evidence. The
    # ping-pong this guards against would flip is_active on each run.
    for _ in range(2):
        enroll_protocol_contracts(test_db, proto.id, rpc_url, "ethereum")
        test_db.expire_all()
        again = test_db.execute(select(MonitoredContract).where(MonitoredContract.address == admin_addr)).scalar_one()
        assert again.is_active is True, (
            f"CGN-discovered proxy admin must stay active across re-enrollments; "
            f"got is_active={again.is_active}, source={again.enrollment_source}"
        )
        assert again.enrollment_source == "auto"


# ---------------------------------------------------------------------------
# Substring whitelist — ``last_known_state.owner`` reflects the canonical
# Ownable slot even when sibling controller_id values share the
# substring ``"owner"``.
# ---------------------------------------------------------------------------


def test_substring_pending_owner_not_latched_into_initial_state(anvil_env, test_db):
    """Mirrors the bug company_overview had already fixed. With both
    ``state_variable:owner`` and ``state_variable:pendingOwner``
    tracked, last-write-wins iteration under the old substring match
    would latch ``pendingOwner`` and the scanner would false-positive
    an OwnershipTransferred when ``owner()`` eventually changed.
    """
    from services.monitoring.enrollment import enroll_protocol_contracts

    rpc_url, tmp_path = anvil_env
    addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)
    active_owner = ACCOUNT0
    pending_owner = ACCOUNT1

    proto = _make_protocol(test_db)
    contract = _add_protocol_contract(test_db, proto.id, addr, contract_name="OwnableHost")

    # Tracker emits both slots. Order is deliberate: pendingOwner LAST so
    # the old last-write-wins substring match would have latched it.
    test_db.add_all(
        [
            ControllerValue(
                contract_id=contract.id,
                controller_id="state_variable:owner",
                value=active_owner.lower(),
                resolved_type="eoa",
            ),
            ControllerValue(
                contract_id=contract.id,
                controller_id="state_variable:pendingOwner",
                value=pending_owner.lower(),
                resolved_type="eoa",
            ),
        ]
    )
    test_db.commit()

    enroll_protocol_contracts(test_db, proto.id, rpc_url, "ethereum")
    mc = test_db.execute(select(MonitoredContract).where(MonitoredContract.address == addr)).scalar_one()

    assert mc.last_known_state is not None
    assert mc.last_known_state.get("owner", "").lower() == active_owner.lower(), (
        f"last_known_state.owner should reflect the active Ownable slot "
        f"({active_owner.lower()}), not pendingOwner ({pending_owner.lower()}); "
        f"got {mc.last_known_state.get('owner')}"
    )


# ---------------------------------------------------------------------------
# In-flight sibling regression — a sibling job in queued/processing must
# not silently block the policy trigger from enrolling completed
# contracts. The historical in-flight gate skipped the trigger whenever
# any sibling existed in those states, with no fallback. Combined with
# terminal-failure siblings (which never transitioned out of queued/
# processing observably), this produced the prod-etherfi "completed
# contracts but missing monitored_contracts rows" symptom.
# ---------------------------------------------------------------------------


def test_in_flight_sibling_job_does_not_block_enrollment(anvil_env, test_db):
    """The policy trigger must enroll completed contracts even when a
    sibling job is still queued or processing. Pre-fix shape: the
    in-flight gate in ``maybe_enroll_protocol`` returned False as soon
    as any ``Job.status IN (queued, processing)`` existed for the
    protocol, and there was no automatic retry. A sibling that crashed
    before transitioning out of queued / processing — observed on the
    dev DB as a discovery-stage failure — would freeze the trigger and
    require a manual ``POST /api/protocols/{id}/re-enroll`` to recover.

    Today: the gate is gone. ``enroll_protocol_contracts`` is idempotent
    so a partial enrollment from a trigger that fires while siblings are
    still in flight is fine — subsequent triggers (or the reconciler)
    upsert the remaining contracts when they finish. This test pins the
    new behavior at the trigger boundary so a future "let's add the gate
    back" reflex breaks it.
    """
    from services.monitoring.enrollment import maybe_enroll_protocol

    rpc_url, tmp_path = anvil_env
    completed_addr = _compile_and_deploy(OWNABLE_SOURCE, "TestOwnable", [], rpc_url, PRIVATE_KEY, tmp_path)

    proto = _make_protocol(test_db)
    _add_protocol_contract(test_db, proto.id, completed_addr, contract_name="Completed")

    # Sibling job stuck in 'queued'. Pre-fix this caused
    # maybe_enroll_protocol to return False and skip the completed
    # contract's enrollment with no retry path.
    test_db.add(
        Job(
            address="0x" + "ab" * 20,
            protocol_id=proto.id,
            status=JobStatus.queued,
            stage=JobStage.discovery,
        )
    )
    test_db.commit()

    fired = maybe_enroll_protocol(test_db, proto.id, rpc_url, "ethereum")
    assert fired is True, (
        "maybe_enroll_protocol must fire even when a sibling is in_flight. "
        "Pre-fix the gate skipped this enrollment with no fallback."
    )

    mc = test_db.execute(
        select(MonitoredContract).where(MonitoredContract.address == completed_addr.lower())
    ).scalar_one_or_none()
    assert mc is not None, (
        "Regression: completed contract must be enrolled even while a "
        "sibling sits in queued/processing. If this fails, the in-flight "
        "gate has come back."
    )
    assert mc.is_active is True


def test_tracking_plan_drives_enrollment_and_scan_detection(anvil_env, test_db):
    """End-to-end regression for the *general* bug fix.

    Verifies the full enrollment → scan pipeline for a non-OZ ABI:

      1. Deploy a Solmate-Owned contract on Anvil.
      2. Seed Protocol + Contract + Job (completed) + ContractMaterialization
         with an inline ``tracking_plan`` JSONB that lists the contract's
         ``OwnerUpdated`` event (mirrors what the static analysis pipeline
         persists for a real Solmate-derived protocol contract).
      3. Call ``enroll_protocol_contracts`` and assert the resulting
         MonitoredContract has ``monitoring_config.tracked_topics``
         populated from the plan — i.e. enrollment did read the plan.
      4. Trigger ``setOwner`` on the deployed contract.
      5. Call ``scan_for_events`` and assert the event is detected with
         ``event_type='ownership_transferred'`` and the new owner address
         decoded into ``data.new_owner``.

    Together this proves: the analysis pipeline's per-contract event
    knowledge flows through enrollment into ``monitoring_config``,
    through the scanner's union-topic filter onto the wire, and through
    the generic decoder into a persisted ``MonitoredEvent``. None of
    those hops worked end-to-end before the general-bug fix landed.

    This test would fail under the pre-fix code on assertion (3) —
    ``enroll_protocol_contracts`` did not look at
    ``contract_materializations.tracking_plan`` and therefore wrote no
    ``tracked_topics`` field; the scanner's filter then drops the
    Solmate topic0 at the network layer and no MonitoredEvent is ever
    created.
    """
    from eth_utils.crypto import keccak

    from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
    from db.models import ContractMaterialization
    from services.monitoring.enrollment import enroll_protocol_contracts
    from services.monitoring.unified_watcher import scan_for_events

    rpc_url, tmp_path = anvil_env

    addr = _compile_and_deploy(SOLMATE_OWNED_SOURCE, "TestSolmateOwned", [], rpc_url, PRIVATE_KEY, tmp_path)

    # ContractMaterialization isn't protocol-scoped, so the fixture's
    # PROTO_NAME teardown doesn't reach it. anvil's CREATE address is
    # deterministic (deployer + nonce 0) across runs, so a stale row
    # from a prior pass would collide on the (chain, address) unique
    # index. Clear it up front; re-clear in the trailing finally.
    test_db.execute(
        delete(ContractMaterialization).where(
            ContractMaterialization.chain == "ethereum",
            ContractMaterialization.address == addr.lower(),
        )
    )
    test_db.commit()

    proto = _make_protocol(test_db)
    _add_protocol_contract(test_db, proto.id, addr, contract_name="TestSolmateOwned")

    # Persist a tracking_plan that lists the Solmate OwnerUpdated event,
    # exactly as the static analysis pipeline would for a real Solmate-
    # derived contract. The bytecode_keccak is arbitrary here — find_by_address
    # uses the (chain, address) unique index, not the keccak PK.
    owner_updated_sig = "OwnerUpdated(address,address)"
    owner_updated_topic0 = "0x" + keccak(text=owner_updated_sig).hex()
    tracking_plan = {
        "schema_version": "0.1",
        "contract_address": addr.lower(),
        "contract_name": "TestSolmateOwned",
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": [
            {
                "controller_id": "state_variable:owner",
                "label": "owner",
                "source": "state_variable",
                "kind": "state_variable",
                "read_spec": None,
                "tracking_mode": "event_plus_state",
                "event_watch": {
                    "transport": "wss_logs",
                    "contract_address": addr.lower(),
                    "events": [
                        {
                            "name": "OwnerUpdated",
                            "signature": owner_updated_sig,
                            "topic0": owner_updated_topic0,
                            "inputs": [
                                {"name": "user", "type": "address", "indexed": True},
                                {"name": "newOwner", "type": "address", "indexed": True},
                            ],
                        }
                    ],
                    "writer_functions": ["setOwner(address)"],
                },
                "polling_fallback": {
                    "contract_address": addr.lower(),
                    "polling_sources": ["owner"],
                    "cadence": "realtime_confirm",
                    "notes": [],
                },
                "notes": [],
            }
        ],
    }
    test_db.add(
        ContractMaterialization(
            chain="1",
            bytecode_keccak="0x" + "0" * 64,
            address=addr.lower(),
            contract_name="TestSolmateOwned",
            tracking_plan=tracking_plan,
            status="ready",
            # Enrollment reads via the version-filtered ``find_by_address``; seed
            # at the current analyzer version so the row is visible after an
            # ANALYSIS_SCHEMA_VERSION bump, not just at the DB default.
            analysis_schema_version=ANALYSIS_SCHEMA_VERSION,
        )
    )
    test_db.commit()

    try:
        # ---- Phase 1: enrollment consumes the tracking_plan -----------------
        enrolled = enroll_protocol_contracts(test_db, proto.id, rpc_url, "ethereum")
        assert len(enrolled) == 1
        mc = enrolled[0]
        config = mc.monitoring_config or {}
        tracked = config.get("tracked_topics") or []
        assert tracked, (
            "enrollment did not read tracking_plan from contract_materializations — "
            "monitoring_config.tracked_topics is empty. Pre-fix behavior; the "
            "general fix wires _load_tracked_topics into the enroll loop."
        )
        matched = [t for t in tracked if (t.get("topic0") or "").lower() == owner_updated_topic0]
        assert matched, f"OwnerUpdated topic0 missing from tracked_topics: {tracked}"
        spec = matched[0]
        assert spec["event_type"] == "ownership_transferred"
        assert spec["controller_id"] == "state_variable:owner"
        assert spec["signature"] == owner_updated_sig

        # ---- Phase 2: scanner picks up the on-chain event -------------------
        new_owner = ACCOUNT1
        _cast_send(addr, "setOwner(address)", [new_owner], rpc_url)

        events = scan_for_events(test_db, rpc_url)
        detected = [e for e in events if e.event_type == "ownership_transferred"]
        assert len(detected) == 1, (
            f"expected one ownership_transferred event, got {len(detected)} "
            f"(all events: {[(e.event_type, e.data) for e in events]})"
        )
        evt = detected[0]
        assert evt.monitored_contract_id == mc.id
        assert (evt.data or {}).get("new_owner", "").lower() == new_owner.lower()
    finally:
        # Cross-run cleanup: see leading comment for why the
        # fixture's PROTO_NAME teardown can't reach this row.
        test_db.execute(
            delete(ContractMaterialization).where(
                ContractMaterialization.chain == "ethereum",
                ContractMaterialization.address == addr.lower(),
            )
        )
        test_db.commit()
