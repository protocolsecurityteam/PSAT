"""Veda caller-drop (#2+#3) on a snapshot of the prod etherfi stack (``veda_teller_stack.json``), asserted at the
surface level so a symptom patch at any layer is caught.

The Teller's own ``requiresAuth`` is keyed on the end user, but its inner ``BoringVault.enter/exit`` call is keyed
on the Teller: a different caller dimension. Intersecting (#2) or AND-dropping it (#3) zeroed the real callers;
#4 dropped a public ``deposit``. Separately, the writer seeded every AND/OR as a public path, so an unresolvable
or empty gate surfaced as ``public``; ``public`` must be earned by a ``conditional_universal`` child.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from services.resolution.deferred_reconciler import (
    DEFERRED_MARKER,
    _iter_deferred_authorities,
)
from tests.conftest import DATABASE_URL as _DB_URL
from tests.conftest import _can_connect, requires_postgres

_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "solmate" / "veda_teller_stack.json"

# Cursor seeding needs one row per topic.
_ROLE_TOPICS = [
    "0xa52ea92e6e955aa8ac66420b86350f7139959adfcc7e6a14eee1bd116d09860e",  # RoleCapabilityUpdated
    "0x950a343f5d10445e82a71036d3f4fb3016180a25805141932543b83e2078a93e",  # PublicCapabilityUpdated
    "0x4c9bdd0c8e073eb5eda2250b18d8e5121ff27b62064fbeeeed4869bb99bc5bf2",  # UserRoleUpdated
]

# Role-12 holders for bulkWithdraw: what the bug drops.
_BULKWITHDRAW_CALLERS = {
    "0x989468982b08aefa46e37cd0086142a86fa466d7",
    "0xabbc3e6bccd53c55fee9a785f30a3a8202e6f61e",
    "0xf0bb20865277abd641a307ece5ee04e79073416c",
}

_BULKWITHDRAW = "bulkWithdraw(ERC20,uint256,uint256,address)"
_DEPOSIT = "deposit(ERC20,uint256,uint256)"
_DENY_ALL = "denyAll(address)"
_ZERO = "0x" + "0" * 40


@pytest.fixture
def fixture() -> dict:
    return json.loads(_FIXTURE.read_text())


@pytest.fixture
def session():
    if not _can_connect():
        pytest.skip("PostgreSQL not available")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from db.models import Contract, ControllerValue, IndexedEventCursor, IndexedEventLog, Job, Protocol

    def _wipe(sess):
        for model in (IndexedEventLog, IndexedEventCursor, ControllerValue, Contract):
            sess.query(model).delete()
        sess.query(Job).delete()
        sess.query(Protocol).delete()
        sess.commit()

    engine = create_engine(_DB_URL)
    s = Session(engine, expire_on_commit=False)
    # A prior aborted run could collide on the (address, chain) unique key.
    _wipe(s)
    try:
        yield s
    finally:
        s.rollback()
        _wipe(s)
        s.close()
        engine.dispose()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Fail bytecode confirmation and getter probes so the resolver uses event-only paths."""
    import services.clients.rpc as rpc

    def _boom(*_a, **_k):
        raise RuntimeError("network disabled in test")

    monkeypatch.setattr(rpc, "rpc_request", _boom, raising=False)
    monkeypatch.setattr(rpc, "rpc_batch_request_with_status", _boom, raising=False)


def _seed_job_with_trees(session, *, address: str, trees: dict | None):
    from db.models import Job, JobStage, JobStatus
    from db.queue import store_artifact

    job = Job(
        address=address,
        request={"address": address, "name": "T", "chain": "ethereum"},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(job)
    session.flush()
    if trees is not None:
        store_artifact(session, job.id, "predicate_trees", data=trees)
    session.commit()
    return job


def _seed_contract(session, *, address: str, job_id, controllers: dict[str, str]):
    from db.models import Contract, ControllerValue, Protocol

    proto = Protocol(name=f"veda_{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    contract = Contract(address=address, chain="ethereum", protocol_id=proto.id, job_id=job_id)
    session.add(contract)
    session.flush()
    for cid, value in controllers.items():
        session.add(ControllerValue(contract_id=contract.id, controller_id=cid, value=value, source="test"))
    session.commit()
    return contract


def _seed_role_events(session, *, authority: str, events: list[dict]):
    from db.models import IndexedEventCursor, IndexedEventLog

    max_block = 0
    for i, e in enumerate(events):
        session.add(
            IndexedEventLog(
                chain_id=1,
                event_address=authority,
                topic0=e["topic0"],
                tx_hash=i.to_bytes(32, "big"),
                log_index=e["log_index"],
                block_number=e["block_number"],
                block_hash=(i // 50).to_bytes(32, "big"),
                transaction_index=e["transaction_index"],
                topics=e["topics"],
                data_words=e["data_words"],
            )
        )
        max_block = max(max_block, e["block_number"])
    # Without backfill_complete cursors the adapter returns index-cold external_check_only.
    for topic0 in _ROLE_TOPICS:
        session.add(
            IndexedEventCursor(
                chain_id=1,
                event_address=authority,
                topic0=topic0,
                last_indexed_block=max(max_block, _ROLE_FRONTIER),
                backfill_complete=True,
                last_run_at=datetime.now(timezone.utc),
                first_indexed_block=0,
                first_indexed_block_basis="creation_block_minus_one",
            )
        )
    session.commit()


# The teller's non-canonical exit-leaf selector; a role grant for it makes the inner auth non-empty.
_INNER_EXIT_SELECTOR = "0x61a3bcc8"
# Cursor frontier for the seeded role events, and the pass pin the resolver evaluates at.
_ROLE_FRONTIER = 30_000_000
_INNER_GRANTEE = "0xdddddddddddddddddddddddddddddddddddddddd"


def _inner_exit_grant_events(vault: str) -> list[dict]:
    role_cap, _pub, user_role = _ROLE_TOPICS

    def addr_word(a: str) -> str:
        return "0x" + a[2:].rjust(64, "0")

    role_word = "0x" + format(20, "064x")
    sig_word = "0x" + _INNER_EXIT_SELECTOR[2:] + "0" * 56
    true_word = "0x" + "0" * 63 + "1"
    return [
        {
            "topic0": role_cap,
            "topics": [role_cap, role_word, addr_word(vault), sig_word],
            "data_words": [true_word],
            "block_number": 99_000_001,
            "transaction_index": 0,
            "log_index": 0,
        },
        {
            "topic0": user_role,
            "topics": [user_role, addr_word(_INNER_GRANTEE), role_word],
            "data_words": [true_word],
            "block_number": 99_000_002,
            "transaction_index": 0,
            "log_index": 0,
        },
    ]


def _resolve(
    session,
    fixture: dict,
    *,
    seed_vault: bool,
    extra_events: list[dict] | None = None,
    seed_role_events: bool = True,
) -> dict:
    """``seed_vault`` picks #2 (inner inlines) vs #3 (external_check_only); ``seed_role_events=False`` is the
    degraded path (#5).
    """
    from services.resolution.capability_resolver import resolve_contract_capabilities

    teller = fixture["teller_address"]
    vault = fixture["vault_address"]
    authority = fixture["authority_address"]

    teller_job = _seed_job_with_trees(session, address=teller, trees=fixture["teller_trees"])
    _seed_contract(
        session,
        address=teller,
        job_id=teller_job.id,
        controllers={
            "external_contract:authority": authority,
            "external_contract:vault": vault,
            "state_variable:owner": _ZERO,  # ownership renounced on-chain
        },
    )
    if seed_vault:
        vault_job = _seed_job_with_trees(session, address=vault, trees=fixture["vault_trees"])
        _seed_contract(
            session,
            address=vault,
            job_id=vault_job.id,
            controllers={"external_contract:authority": authority, "state_variable:owner": _ZERO},
        )
    if seed_role_events:
        _seed_role_events(session, authority=authority, events=fixture["role_events"] + list(extra_events or []))

    # Pinned at the seeded cursors' frontier so a warm index covers the evaluated block.
    out = resolve_contract_capabilities(session, address=teller, chain_id=1, job_id=teller_job.id, block=_ROLE_FRONTIER)
    assert out is not None, "resolver returned None — predicate_trees artifact not found"
    return out


def _surface(cap: dict):
    from services.policy.capability_surface import capability_surface_status, project_capability_surface

    surface = project_capability_surface(cap)
    return surface, capability_surface_status(cap, surface)


def _row_addresses(surface) -> set[str]:
    return {str(r.get("address")).lower() for r in surface.principal_rows}


@requires_postgres
def test_pin2b_nonempty_inner_exit_neither_drops_nor_leaks(session, fixture):
    # If the owner leaf in OR[canCall, msg.sender==owner] isn't subject-tagged, a non-empty canCall keeps the OR
    # root-tagged and the inner member leaks to and_multiple_principal_shapes.
    out = _resolve(session, fixture, seed_vault=True, extra_events=_inner_exit_grant_events(fixture["vault_address"]))
    surface, status = _surface(out[_BULKWITHDRAW])

    rows = _row_addresses(surface)
    assert rows == _BULKWITHDRAW_CALLERS, (
        f"real callers must survive a NON-EMPTY inner vault.exit auth; got {rows} status={status}"
    )
    assert _INNER_GRANTEE not in rows, "an intermediate-dimension address must never leak as an end-user principal"
    assert not any(r.get("unsupported_reason") == "and_multiple_principal_shapes" for r in surface.residual), (
        "the inner bound set must collapse into the OR, not collide with the caller set"
    )


# The fix must not resurrect true negatives.


@requires_postgres
@pytest.mark.parametrize("seed_vault", [True, False])
def test_pin4_public_capability_resolves_public_without_phantoms(session, fixture, seed_vault):
    out = _resolve(session, fixture, seed_vault=seed_vault)
    surface, status = _surface(out[_DEPOSIT])

    # The probe-materializer would enumerate low-int phantom candidates; the adapter keeps zero address rows.
    assert surface.authority_public is True, f"public deposit must resolve authority_public; status={status}"
    assert status == "public"
    assert _row_addresses(surface) == set(), "a public capability must mint zero principal rows (no phantoms)"


# #5: with the RolesAuthority unindexed, a role-gated function must not surface as public.


# #6: the cold gate persists ``deferred_pending_index`` so ``deferred_reconciler`` re-resolves it.


@requires_postgres
@pytest.mark.parametrize("seed_vault", [True, False])
def test_pin6_cold_index_gate_persists_deferral_for_selfheal(session, fixture, seed_vault):
    # The ``external_set`` branch overwrote the tagged deferral, so the reconciler never re-enqueued (Veda OR-unresolved
    # 17->106). Re-enqueue is pinned in ``test_deferred_resolution_reconcile.py``.
    out = _resolve(session, fixture, seed_vault=seed_vault, seed_role_events=False)

    authority = fixture["authority_address"].lower()
    for signature in (_DENY_ALL, _BULKWITHDRAW):
        deferred = set(_iter_deferred_authorities(out[signature]))
        assert authority in deferred, (
            f"{signature}: a cold-index canCall gate must persist its {DEFERRED_MARKER!r} "
            f"marker (authority={authority}) so deferred_reconciler self-heals it once the "
            f"index warms; got {json.dumps(out[signature])[:700]}"
        )


# Small-integer event words (0x..01 .. 0x..ff) are not addresses.


def test_materializer_rejects_low_int_phantom_candidates():
    from services.resolution.external_check_materializer import _is_plausible_candidate_address

    for phantom in ("0x" + "0" * 39 + "1", "0x" + "0" * 38 + "64", "0x" + "0" * 32 + "ff" * 4):
        assert not _is_plausible_candidate_address(phantom), f"{phantom} is a phantom, not an address"
    for real in (
        "0x989468982b08aefa46e37cd0086142a86fa466d7",
        "0x402dff43b4f24b006bbd6520a11c169f81085039",
    ):
        assert _is_plausible_candidate_address(real)
    assert not _is_plausible_candidate_address("not-hex")


# Collapse to residual only when both sides lack a valid path.


def test_and_surface_preserves_rows_when_anded_with_pure_check():
    from services.policy.capability_surface import CapabilitySurface, _and_surface

    valid = CapabilitySurface(principal_rows=[{"address": "0x" + "a" * 40, "details": {}}])
    check = CapabilitySurface(
        residual=[
            {
                "kind": "external_check_only",
                "check": {"target_address": "0x" + "b" * 40, "target_call_selector": "0xdeadbeef"},
            }
        ]
    )
    for out in (_and_surface(valid, check), _and_surface(check, valid)):  # commutative
        assert len(out.principal_rows) == 1, "caller row dropped when AND-ed with a pure check"
        assert out.principal_rows[0]["details"].get("conditions"), "check not attached as condition"
        assert out.residual, "check should also be retained as residual for the API probe"


def test_residual_as_conditions_variants():
    from services.policy.capability_surface import _residual_as_conditions

    by_check = _residual_as_conditions(
        {"kind": "external_check_only", "check": {"target_address": "0x" + "c" * 40, "target_call_selector": "0xab"}}
    )
    assert any("0x" + "c" * 40 in c["description"] for c in by_check)
    by_reason = _residual_as_conditions({"kind": "unsupported", "unsupported_reason": "nope"})
    assert any("nope" in c["description"] for c in by_reason)
    generic = _residual_as_conditions({"kind": "external_check_only"})
    assert generic and "external authorization check" in generic[0]["description"]
    assert _residual_as_conditions("not-a-dict") == []  # pyright: ignore[reportArgumentType]  # defensive non-dict guard


# Public must be justified by a ``conditional_universal`` child, not the projector's fold seed or node conditions.
