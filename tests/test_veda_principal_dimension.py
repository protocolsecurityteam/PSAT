"""Integration pins for the principal-dimension conflation fix (Veda caller-drop, #2+#3).

Drives the REAL resolver (``resolve_contract_capabilities``) against a snapshot of the
prod etherfi Veda stack — ``TellerWithMultiAssetSupport`` 0x99de9e5a, its ``BoringVault``
0x917cee80, and their shared ``RolesAuthority`` 0x402dff43 (real predicate_trees + real
role events in ``tests/fixtures/solmate/veda_teller_stack.json``). Seeds Job +
predicate_trees artifacts + Contract/ControllerValue + IndexedEventLog/cursor (the
production path: PostgresEventLogRepo → SolmateRolesAuthorityAdapter → cross-contract
inline → capability algebra → CapabilitySurface), and asserts at the surface/status level
so a symptom-patch revert at any layer is caught.

The bug: a Teller's ``bulkWithdraw``/``deposit`` is gated by its own Solmate
``requiresAuth`` (canCall on the end-user) AND it internally calls ``BoringVault.enter/exit``
(also ``requiresAuth``, but keyed on the *Teller* as caller). The inner check is a
different caller dimension — set-intersecting it (#2) or AND-dropping it in the writer (#3)
zeroes the real end-user callers.

Each behavioral pin FAILS on current main:
  * #2 (vault trees present): inner ``exit`` inlines to a bound finite_set, set-intersected
    with the own caller set → zeroed (status resolved_empty, 0 rows).
  * #3 (vault trees absent): inner call is ``external_check_only``; the writer's
    ``_and_surface`` collapses to residual-only → caller rows dropped (0 rows).
  * #4: a public ``deposit`` is dropped instead of resolving to ``public``.
The guardrail pin passes on both main and fix: it asserts the fix does NOT resurrect a
genuine true-negative (a role-less own gate, owner renounced, stays ``resolved_empty``).

A second regression in the same fix: the writer seeded every AND/OR with its own
conditions as a public path, so a function whose caller gate is unresolvable (degraded
coverage → ``external_check_only``) or provably empty (``finite_set([], exact)``)
surfaced as ``public`` / ``anyone``, masking the real controller. ``test_pin5_*``
reproduces it end-to-end (RolesAuthority left uncrawled); the ``test_seed_public_*`` pins
drive the exact prod tree shapes through the writer and assert ``public`` is earned only
by a ``conditional_universal`` child, never by the fold seed or a node-level condition.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.resolution.capabilities import CapabilityExpr, Condition, ExternalCheck  # noqa: E402

_DB_URL: str = os.environ.get("TEST_DATABASE_URL", os.environ.get("DATABASE_URL", "")) or ""
_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "solmate" / "veda_teller_stack.json"

# RolesAuthority event topic0s (Solmate). Cursor seeding needs one row per topic.
_ROLE_TOPICS = [
    "0xa52ea92e6e955aa8ac66420b86350f7139959adfcc7e6a14eee1bd116d09860e",  # RoleCapabilityUpdated
    "0x950a343f5d10445e82a71036d3f4fb3016180a25805141932543b83e2078a93e",  # PublicCapabilityUpdated
    "0x4c9bdd0c8e073eb5eda2250b18d8e5121ff27b62064fbeeeed4869bb99bc5bf2",  # UserRoleUpdated
]

# The real role-12 holders authorized for bulkWithdraw on this authority (Solmate fold of
# the snapshotted events). These are what the bug drops.
_BULKWITHDRAW_CALLERS = {
    "0x989468982b08aefa46e37cd0086142a86fa466d7",
    "0xabbc3e6bccd53c55fee9a785f30a3a8202e6f61e",
    "0xf0bb20865277abd641a307ece5ee04e79073416c",
}

_BULKWITHDRAW = "bulkWithdraw(ERC20,uint256,uint256,address)"
_DEPOSIT = "deposit(ERC20,uint256,uint256)"
_DENY_ALL = "denyAll(address)"
_ZERO = "0x" + "0" * 40


def _can_connect() -> bool:
    if not _DB_URL:
        return False
    try:
        from sqlalchemy import create_engine, text

        engine = create_engine(_DB_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


requires_postgres = pytest.mark.skipif(not _can_connect(), reason="PostgreSQL not available")


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
    # Clean at setup too — robust against a prior crashed/aborted run leaving rows that
    # would collide on the contract (address, chain) unique key.
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
    """Keep the suite offline: the Solmate adapter's bytecode confirmation and any
    owner()/getter probe go through utils.rpc — fail them so the resolver falls back to
    its event-only / state-var paths (which is all these fixtures need) rather than
    touching the network."""
    import utils.rpc as rpc

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
    # backfill_complete cursors are load-bearing: without them the Solmate adapter
    # returns external_check_only (index-cold) instead of the exact role-holder set.
    for topic0 in _ROLE_TOPICS:
        session.add(
            IndexedEventCursor(
                chain_id=1,
                event_address=authority,
                topic0=topic0,
                last_indexed_block=max_block,
                backfill_complete=True,
                last_run_at=datetime.now(timezone.utc),
            )
        )
    session.commit()


# Selector the inlined vault.exit canCall folds against (the teller's exit-leaf
# non-canonical signature, observed in the resolved trace). Granting a role for
# (vault, this selector) makes the inner downstream auth NON-EMPTY.
_INNER_EXIT_SELECTOR = "0x61a3bcc8"
_INNER_GRANTEE = "0xdddddddddddddddddddddddddddddddddddddddd"


def _inner_exit_grant_events(vault: str) -> list[dict]:
    """Events granting an unused role for (vault, exit-selector) to a fresh address, so
    ``canCall(*, vault, exit)`` folds to a non-empty bound set (the case the empty
    snapshot doesn't exercise — and where the bug otherwise recurs)."""
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
    """Seed the stack and run the production resolver against the Teller. ``seed_vault``
    toggles whether the inner ``exit``/``enter`` call inlines (→ #2 bound finite_set) or
    stays an ``external_check_only`` (→ #3). ``extra_events`` appends role events (used to
    make the inner downstream auth non-empty). ``seed_role_events=False`` leaves the
    RolesAuthority uncrawled (no events, no cursor) so the own ``canCall`` gate falls to
    ``external_check_only`` — the production degraded path (#5)."""
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

    out = resolve_contract_capabilities(session, address=teller, chain_id=1, job_id=teller_job.id)
    assert out is not None, "resolver returned None — predicate_trees artifact not found"
    return out


def _surface(cap: dict):
    from services.policy.capability_surface import capability_surface_status, project_capability_surface

    surface = project_capability_surface(cap)
    return surface, capability_surface_status(cap, surface)


def _row_addresses(surface) -> set[str]:
    return {str(r.get("address")).lower() for r in surface.principal_rows}


# ---------------------------------------------------------------------------
# #2 — inner vault.exit inlines to a bound finite_set; must NOT zero the callers
# ---------------------------------------------------------------------------


@requires_postgres
def test_pin2_inlined_inner_exit_does_not_zero_caller_set(session, fixture):
    out = _resolve(session, fixture, seed_vault=True)
    surface, status = _surface(out[_BULKWITHDRAW])

    # On main the bound inner-exit set is intersected with the own caller set → ∅
    # (a single exact-empty finite_set, status resolved_empty, 0 rows).
    assert _row_addresses(surface) == _BULKWITHDRAW_CALLERS, (
        f"the real role-12 caller set must survive the inlined vault.exit auth; "
        f"got {_row_addresses(surface)} status={status}"
    )
    assert status != "resolved_empty", "a function with real callers must not be labeled resolved_empty"
    # The inner cross-contract auth must be carried as a SIDE-CONDITION on the callers,
    # not as a narrowing of the set: every surviving row records conditions.
    assert all(r.get("details", {}).get("conditions") for r in surface.principal_rows), (
        "the inlined inner-call auth should be attached to the caller rows as a condition"
    )


@requires_postgres
def test_pin2b_nonempty_inner_exit_neither_drops_nor_leaks(session, fixture):
    # The empty-inner snapshot hides a second failure mode: a Solmate inner call resolves
    # to OR[canCall, msg.sender==owner]. If the owner-equality leaf isn't subject-tagged,
    # a NON-EMPTY canCall keeps the OR root-tagged, the cross-subject intersect never
    # fires, and the inner (intermediate-dimension) member leaks → and_multiple_principal_shapes
    # → 0 rows (the bug recurs). Grant a role for (vault, exit) so the inner set is non-empty.
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


# ---------------------------------------------------------------------------
# #3 — inner call is external_check_only; writer must keep the caller rows
# ---------------------------------------------------------------------------


@requires_postgres
def test_pin3_external_check_inner_call_preserves_caller_rows(session, fixture):
    out = _resolve(session, fixture, seed_vault=False)
    surface, status = _surface(out[_BULKWITHDRAW])

    # On main _and_surface collapses AND[external_check_only, finite_set] to residual-only
    # → 0 rows. The check is a side-condition, not grounds to drop the callers.
    assert _row_addresses(surface) == _BULKWITHDRAW_CALLERS, (
        f"caller rows must survive an AND with a pure external check; got {_row_addresses(surface)}"
    )
    assert status != "resolved_empty"
    # The external check must be ATTACHED (kept as residual and/or folded into conditions),
    # not silently discarded.
    attached = bool(surface.residual) or all(r.get("details", {}).get("conditions") for r in surface.principal_rows)
    assert attached, "the unenumerable external check must be attached, not dropped"


# ---------------------------------------------------------------------------
# Guardrail — a genuine role-less own gate (owner renounced) stays resolved_empty.
# Must hold on BOTH main and fix: the fix must not resurrect true-negatives.
# ---------------------------------------------------------------------------


@requires_postgres
@pytest.mark.parametrize("seed_vault", [True, False])
def test_guardrail_no_role_own_gate_stays_resolved_empty(session, fixture, seed_vault):
    out = _resolve(session, fixture, seed_vault=seed_vault)
    surface, status = _surface(out[_DENY_ALL])

    assert status == "resolved_empty", f"role-less own gate (owner=0) must stay resolved_empty; got {status}"
    assert _row_addresses(surface) == set(), "no principals may be minted for a true-negative"


# ---------------------------------------------------------------------------
# #4 — public capability resolves to `public` with NO phantom principals
# ---------------------------------------------------------------------------


@requires_postgres
@pytest.mark.parametrize("seed_vault", [True, False])
def test_pin4_public_capability_resolves_public_without_phantoms(session, fixture, seed_vault):
    out = _resolve(session, fixture, seed_vault=seed_vault)
    surface, status = _surface(out[_DEPOSIT])

    # On-chain canCall(<anyone>, teller, deposit) == true (a PublicCapabilityUpdated). The
    # standard-aware adapter resolves this to `public`; the generic probe-materializer would
    # instead enumerate event candidates (incl. low-int phantoms) — preferring the adapter
    # keeps it public with zero address rows.
    assert surface.authority_public is True, f"public deposit must resolve authority_public; status={status}"
    assert status == "public"
    assert _row_addresses(surface) == set(), "a public capability must mint zero principal rows (no phantoms)"


# ---------------------------------------------------------------------------
# #5 — degraded coverage: the RolesAuthority was never indexed, so the own ``canCall``
# gate is unresolvable. A restricted, role-gated function must NOT surface as `public`.
# ---------------------------------------------------------------------------


@requires_postgres
@pytest.mark.parametrize("seed_vault", [True, False])
def test_pin5_uncrawled_authority_does_not_surface_public(session, fixture, seed_vault):
    # The production preview indexed only the LayerZero endpoint, never the shared
    # RolesAuthority — so the Solmate adapter returns external_check_only for the own
    # canCall and the function's only "public path" is the projector's own AND fold seed.
    # bulkWithdraw is role-gated (restricted on-chain); reporting it `public`/`anyone`
    # masks the real controller, the worst error direction for this tool.
    out = _resolve(session, fixture, seed_vault=seed_vault, seed_role_events=False)
    surface, status = _surface(out[_BULKWITHDRAW])

    assert surface.authority_public is False, f"an unresolved caller gate must not surface as `anyone`; status={status}"
    assert status != "public"
    assert _row_addresses(surface) == set(), "no principals may be minted for an unresolved gate"


# ---------------------------------------------------------------------------
# Candidate hygiene (defense-in-depth): the materializer must reject small-integer
# event words coerced to phantom addresses (0x..01 .. 0x..ff) while keeping real ones.
# ---------------------------------------------------------------------------


def test_materializer_rejects_low_int_phantom_candidates():
    from services.resolution.external_check_materializer import _is_plausible_candidate_address

    for phantom in ("0x" + "0" * 39 + "1", "0x" + "0" * 38 + "64", "0x" + "0" * 32 + "ff" * 4):
        assert not _is_plausible_candidate_address(phantom), f"{phantom} is a phantom, not an address"
    for real in (
        "0x989468982b08aefa46e37cd0086142a86fa466d7",
        "0x402dff43b4f24b006bbd6520a11c169f81085039",
    ):
        assert _is_plausible_candidate_address(real)
    # malformed input must be rejected, not raise
    assert not _is_plausible_candidate_address("not-hex")


# ---------------------------------------------------------------------------
# Writer (_and_surface) unit pins — preserve caller rows / public paths when AND-ed
# with a pure check; collapse to residual only when BOTH sides lack a valid path.
# ---------------------------------------------------------------------------


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


def test_and_surface_preserves_public_path_when_anded_with_pure_check():
    from services.policy.capability_surface import CapabilitySurface, _and_surface, capability_surface_status

    public = CapabilitySurface(public_paths=[[{"kind": "business", "description": "p"}]])
    check = CapabilitySurface(residual=[{"kind": "unsupported", "unsupported_reason": "x"}])
    out = _and_surface(public, check)
    assert out.authority_public is True
    assert capability_surface_status({"kind": "AND"}, out) == "public"


def test_and_surface_both_pure_checks_stays_residual():
    from services.policy.capability_surface import CapabilitySurface, _and_surface

    a = CapabilitySurface(residual=[{"kind": "unsupported", "unsupported_reason": "x"}])
    b = CapabilitySurface(residual=[{"kind": "external_check_only", "check": {"target_address": "0x" + "b" * 40}}])
    out = _and_surface(a, b)
    assert out.principal_rows == [] and out.public_paths == [] and len(out.residual) == 2


def test_and_surface_valid_with_empty_branch_keeps_rows():
    # A valid side AND an empty (no rows/paths/residual) side keeps the rows verbatim.
    from services.policy.capability_surface import CapabilitySurface, _and_surface

    valid = CapabilitySurface(principal_rows=[{"address": "0x" + "a" * 40, "details": {}}])
    out = _and_surface(valid, CapabilitySurface())
    assert len(out.principal_rows) == 1


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
    assert _residual_as_conditions("not-a-dict") == []  # type: ignore[arg-type]  # defensive non-dict guard


# ---------------------------------------------------------------------------
# Seed-public pins — a `public` surface must be justified by a `conditional_universal`
# child, never by the projector's own AND/OR fold seed or by node-level side
# conditions. These feed the exact tree shapes the resolver emits for the Veda Teller
# (own Solmate gate AND-ed with an inner vault call) through the production serializer
# (``capability_to_dict``) and writer, covering both the degraded-coverage and the
# fully-indexed prod runs.
# ---------------------------------------------------------------------------

_VAULT_ADDR = "0x86b5780b606940eb59a062aa85a07959518c0161"
_AUTHORITY_ADDR = "0x3994741a5b29c60d0ab318de1024f9256fe959dc"


def _inner_call_check() -> CapabilityExpr:
    """The teller's inlined ``BoringVault.exit`` requiresAuth — keyed on the teller as
    caller, unenumerable from here, so a pure ``external_check_only`` side condition."""
    return CapabilityExpr.external_check_only(
        ExternalCheck(target_address=_VAULT_ADDR, target_call_selector="0x61a3bcc8"),
        conditions=[Condition(kind="business", description="assetsOut < minimumAssets")],
    )


def _unresolved_own_gate() -> CapabilityExpr:
    """The teller's own ``requiresAuth`` → ``authority.canCall(msg.sender, ...)`` when the
    RolesAuthority events are not indexed: an unresolvable external check OR-ed with the
    empty fallback set, exactly as the degraded resolver emits it."""
    return CapabilityExpr.structural_or(
        [
            CapabilityExpr.external_check_only(
                ExternalCheck(target_address=_AUTHORITY_ADDR, target_call_selector="0xb7009613"),
                conditions=[
                    Condition(
                        kind="business",
                        description="require(bool,string)(isAuthorized(msg.sender,msg.sig),UNAUTHORIZED)",
                    )
                ],
            ),
            CapabilityExpr.finite_set([], quality="exact"),
        ]
    )


def _surface_for(cap: CapabilityExpr):
    from services.policy.capability_surface import capability_surface_status, project_capability_surface
    from services.resolution.capability_resolver import capability_to_dict

    cap_dict = capability_to_dict(cap)
    surface = project_capability_surface(cap_dict)
    return surface, capability_surface_status(cap_dict, surface)


def test_seed_public_unresolved_own_gate_is_not_public():
    # bulkWithdraw/deposit on the degraded preview: the own canCall is unresolvable, so
    # the only "public path" is the AND fold seed. Must resolve to unknown, not public.
    cap = CapabilityExpr.structural_and([_inner_call_check(), _unresolved_own_gate()])
    surface, status = _surface_for(cap)
    assert surface.authority_public is False, "an unresolved caller gate must not surface as `anyone`"
    assert status != "public"
    assert _row_addresses(surface) == set()


def test_seed_public_resolved_empty_own_gate_stays_resolved_empty():
    # bulkWithdraw/deposit on the fully-indexed prod run: the own gate is a provably-empty
    # role set (exact). AND-ing an inner external check must not flip resolved_empty → public.
    own_gate = CapabilityExpr.finite_set(
        [],
        quality="exact",
        conditions=[
            Condition(
                kind="business",
                description="require(bool,string)(isAuthorized(msg.sender,msg.sig),UNAUTHORIZED)",
            )
        ],
    )
    cap = CapabilityExpr.structural_and([_inner_call_check(), own_gate])
    surface, status = _surface_for(cap)
    assert surface.authority_public is False
    assert status == "resolved_empty", f"a provably-empty own gate must stay resolved_empty; got {status}"
    assert _row_addresses(surface) == set()


def test_seed_public_or_node_condition_is_not_public():
    # setShareLockPeriod et al: an OR over (unresolved canCall, empty set) carrying a
    # node-level business condition. The condition seeds a NON-empty public path, so an
    # "empty-path" heuristic would miss it — it must still not surface as public.
    own_gate = CapabilityExpr(
        kind="OR",
        children=list(_unresolved_own_gate().children),
        conditions=[Condition(kind="business", description="_shareLockPeriod > MAX_SHARE_LOCK_PERIOD")],
    )
    surface, status = _surface_for(own_gate)
    assert surface.authority_public is False, "node-level side conditions must not create a public path"
    assert status != "public"
    assert _row_addresses(surface) == set()


def test_seed_public_genuine_public_survives():
    # Guardrail (#4): a real PublicCapabilityUpdated → conditional_universal child AND-ed
    # with an inner external check must STILL surface as public.
    cap = CapabilityExpr.structural_and(
        [
            CapabilityExpr.conditional_universal(
                Condition(kind="business", description="public RolesAuthority capability")
            ),
            _inner_call_check(),
        ]
    )
    surface, status = _surface_for(cap)
    assert surface.authority_public is True, "a conditional_universal-driven public must survive"
    assert status == "public"
    assert _row_addresses(surface) == set(), "a public capability mints no principal rows"


def test_seed_public_caller_rows_survive_inner_check():
    # Guardrail (#3): real role holders AND-ed with an inner external check keep their rows
    # (with the check attached as a condition) — not dropped, not surfaced as public.
    holders = ["0x" + "a" * 40, "0x" + "b" * 40]
    cap = CapabilityExpr.structural_and([CapabilityExpr.finite_set(holders, quality="exact"), _inner_call_check()])
    surface, status = _surface_for(cap)
    assert _row_addresses(surface) == {h.lower() for h in holders}, "role holders must survive an inner check"
    assert surface.authority_public is False and status != "public"
    assert status != "resolved_empty"
    assert all(r.get("details", {}).get("conditions") for r in surface.principal_rows), (
        "the inner check must attach as a condition on the surviving rows"
    )
