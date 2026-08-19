"""Delegated role-gate refine-only guard (ROLEGATE_FIX_SPEC.md §3.1 [AMENDED]).

Cross-contract inlining may only *refine* a caller-tainted delegated gate,
never un-gate it. When the un-inlined outer leaf would fail closed and the
inline result projects public, the inline is discarded and the outer
delegated check kept (``external_check_only`` + ``inline_refine_only_guard``).
The single carve-out is a legitimate deny-by-exception denylist, which the
companion emission types as a root-subject ``cofinite_blacklist`` so the
guard's cofinite counterfactual spares it (stays public).

Two harness layers:

  * SHAPE-LEVEL (``evaluate_tree`` on one compiled unit) — companion-2 leaf
    emission, permissionless/pause classification, and the pure shape
    discriminators. Mirrors ``tests/test_earned_public.py``.
  * TWO-HOP DB (``resolve_contract_capabilities`` over a seeded caller +
    registry) — the only path that reaches the ``:1976`` guard, since it
    lives inside ``_maybe_inline_cross_contract_call``. Mirrors the
    cross-contract inline tests in ``tests/test_capability_resolver.py``.

The offline suite forces ``PSAT_DIFFERENTIAL_PROBE=0`` (tests/conftest.py),
so the gated verdict is read directly, not re-opened by a live eth_call
probe. The real registry's opaque ``onlyX`` leaf compiles to a
``business/equality/truthy`` leaf with an erased ``view_call`` operand and an
expression that does NOT start with ``return `` — that shape reaches
``:1976``. A *minimal* Solady fixture instead folds to a ``computed`` operand
/ ``return ok_1`` expression that routes through the materialization
fallback (also gated, but not via the guard); FIXTURE 1 therefore seeds the
faithful ``view_call`` callee tree directly (ROLEGATE_FIX_SPEC §1.2.2).
"""

from __future__ import annotations

import tempfile
import textwrap
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.policy.capability_surface import project_capability_surface  # noqa: E402
from services.resolution.adapters.enumerable_role_store import _NEGATIVE_CONTROL_ADDR  # noqa: E402
from services.resolution.capabilities import CapabilityExpr  # noqa: E402
from services.resolution.permissionless_shapes import (  # noqa: E402
    is_caller_keyed_time_allowlist,
    is_caller_keyed_time_denylist,
)
from services.resolution.predicate_evaluator import (  # noqa: E402
    _bind_callee_parameters,
    _public_without_root_cofinites,
    evaluate_tree,
)
from services.resolution.role_store_standards import SOLADY_ENUMERABLE_ROLES  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_types import LeafPredicate  # noqa: E402
from services.static.contract_analysis_pipeline.predicates import build_predicate_tree  # noqa: E402
from services.static.contract_analysis_pipeline.reentrancy_pause import apply_reentrancy_pause_pass  # noqa: E402
from services.static.contract_analysis_pipeline.writer_gate import apply_writer_gate_pass  # noqa: E402
from tests.conftest import DATABASE_URL as _DB_URL  # noqa: E402
from tests.conftest import _can_connect  # noqa: E402


# The guard runs UNCONDITIONALLY (not behind earned_public_enabled()); every
# behavioral test therefore runs under both flag states (ROLEGATE_FIX_SPEC §6.9).
@pytest.fixture(params=["1", "0"], ids=["earned_on", "earned_off"])
def both_flags(request, monkeypatch):
    monkeypatch.setenv("PSAT_AUTHORITY_EARNED_PUBLIC", request.param)
    return request.param


@pytest.fixture
def earned_public(monkeypatch):
    monkeypatch.setenv("PSAT_AUTHORITY_EARNED_PUBLIC", "1")


@pytest.fixture
def session():
    if not _can_connect():
        pytest.skip("PostgreSQL not available")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from db.models import Contract, IndexedEventCursor, IndexedEventLog, Job, Protocol

    engine = create_engine(_DB_URL)
    s = Session(engine, expire_on_commit=False)
    try:
        yield s
    finally:
        s.rollback()
        for model in (IndexedEventLog, IndexedEventCursor, Contract):
            s.query(model).delete()
        s.query(Job).delete()
        s.query(Protocol).delete()
        s.commit()
        s.close()
        engine.dispose()


# ---------------------------------------------------------------------------
# Compile helpers (self-contained; mirror test_earned_public._compile).
# ---------------------------------------------------------------------------


def _compile(tmp_path: Path, source: str, contract_name: str = "C"):
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / f"{contract_name}.sol"
    f.write_text(src)
    sl = Slither(str(f))
    return next(c for c in sl.contracts if c.name == contract_name)


def _build_pipeline(contract) -> dict[str, Any]:
    trees: dict[str, Any] = {}
    for fn in contract.functions:
        if fn.is_constructor:
            continue
        trees[fn.full_name] = build_predicate_tree(fn)
    apply_writer_gate_pass(contract, trees)
    apply_reentrancy_pause_pass(contract, trees)
    return trees


def _iter_leaves(node):
    if isinstance(node, dict):
        if node.get("leaf") is not None:
            yield node["leaf"]
        for child in node.get("children") or []:
            yield from _iter_leaves(child)


# ---------------------------------------------------------------------------
# Fixture sources (the CALLEE registry functions the caller delegates to).
# ---------------------------------------------------------------------------

# Transparent delegated DENYLIST (nonBlacklisted) — AMENDED fixture 11.
_CALLEE_DENYLIST = """
pragma solidity ^0.8.19;
contract Registry {
    error BlacklistedUser(address user);
    mapping(address => uint256) public blacklistedUntil;
    function nonBlacklisted(address user) external view {
        if (blacklistedUntil[user] > block.timestamp) revert BlacklistedUser(user);
    }
}
"""

# Unused-arg pause (fixture 8, gates) and used-arg allowlist (fixture 4, gates).
_CALLEE_PAUSE_AND_ALLOW = """
pragma solidity ^0.8.19;
contract Registry {
    error NotAllowed();
    bool public paused;
    mapping(address => bool) public isAllowed;
    function checkNotPaused(address account) external view {
        if (paused) revert NotAllowed();
    }
    function checkAllowed(address account) external view {
        if (!isAllowed[account]) revert NotAllowed();
    }
}
"""

# No-arg pause (fixture 7, stays public — outer leaf not caller-tainted).
_CALLEE_NOARG_PAUSE = """
pragma solidity ^0.8.19;
contract Registry {
    error NotAllowed();
    bool public paused;
    function checkNotPaused() external view {
        if (paused) revert NotAllowed();
    }
}
"""

# The minimal Solady-opaque callee (fixture 3 / variant h): the assembly hasRole
# folds to a `computed`/`return ok_1` leaf -> materialization fallback gates it.
_CALLEE_SOLADY_OPAQUE = """
pragma solidity ^0.8.19;
contract Registry {
    error Unauthorized();
    uint256 constant OPERATION_MULTISIG_ROLE = 1;
    mapping(bytes32 => uint256) private _roleBitmap;
    function hasRole(address account, uint256 role) public view returns (bool ok) {
        bytes32 slot = keccak256(abi.encode(account, uint256(0x1234)));
        assembly { ok := and(shr(role, sload(slot)), 1) }
    }
    function onlyOperatingMultisig(address account) external view {
        if (!hasRole(account, OPERATION_MULTISIG_ROLE)) revert Unauthorized();
    }
}
"""


def _caller_src(callee_call: str) -> str:
    """A RolesLibrary-style caller whose modifier delegates to ``registry``.
    ``callee_call`` is the exact registry call, e.g.
    ``registry.onlyOperatingMultisig(msg.sender)``."""
    return f"""
pragma solidity ^0.8.19;
interface IReg {{
    function onlyOperatingMultisig(address account) external view;
    function onlyMixed(address account) external view;
    function nonBlacklisted(address user) external view;
    function checkNotPaused(address account) external view;
    function checkNotPaused() external view;
    function checkAllowed(address account) external view;
}}
contract CallerLike {{
    IReg public registry;
    uint256 public v;
    function guarded(uint256 x) external {{
        {callee_call};
        v = x;
    }}
}}
"""


# The faithful real-registry opaque leaf: business/equality/truthy with the
# account erased into a `view_call` operand and an expression that does NOT
# start with "return " -> reaches the :1976 guard (ROLEGATE_FIX_SPEC §1.1).
def _opaque_callee_tree(callee_sig: str) -> dict[str, Any]:
    return {
        callee_sig: {
            "op": "LEAF",
            "leaf": {
                "kind": "equality",
                "operator": "truthy",
                "authority_role": "business",
                "operands": [{"source": "view_call", "callee": "hasRole"}],
                "references_msg_sender": False,
                "parameter_indices": [],
                "expression": "! hasRole(account, OPERATION_MULTISIG_ROLE)",
                "basis": [],
            },
        }
    }


# OR-mix (fixture d2): a transparent, caller-keyed admin membership disjunct
# OR an opaque erased disjunct. The transparent arm binds and stays tainted,
# so an antecedent-level "no caller taint after binding" rule never fires;
# the opaque arm folds to conditional_universal and the OR projects public.
def _ormix_callee_tree(callee_sig: str) -> dict[str, Any]:
    return {
        callee_sig: {
            "op": "OR",
            "children": [
                {
                    "op": "LEAF",
                    "leaf": {
                        "kind": "membership",
                        "operator": "truthy",
                        "authority_role": "caller_authority",
                        "operands": [{"source": "parameter", "parameter_index": 0, "parameter_name": "account"}],
                        "set_descriptor": {
                            "kind": "mapping_membership",
                            "key_sources": [{"source": "parameter", "parameter_index": 0, "parameter_name": "account"}],
                            "storage_var": "admin",
                        },
                        "references_msg_sender": True,
                        "parameter_indices": [],
                        "expression": "admin[account]",
                        "basis": [],
                    },
                },
                {
                    "op": "LEAF",
                    "leaf": {
                        "kind": "equality",
                        "operator": "truthy",
                        "authority_role": "business",
                        "operands": [{"source": "view_call", "callee": "hasRoleAsm"}],
                        "references_msg_sender": False,
                        "parameter_indices": [],
                        "expression": "! hasRoleAsm(account)",
                        "basis": [],
                    },
                },
            ],
        }
    }


# AND-mix (adversarial, corpus-empty): a SINGLE callee that internally ANDs a
# caller-keyed time-DENYLIST with an opaque erased authority leaf —
# ``if (blacklistedUntil[account] > now) revert; if (!hasRoleOpaque(account)) revert;``.
# The denylist arm emits a root ``cofinite_blacklist`` (companion 2) and the
# opaque arm folds to ``conditional_universal``; the capability algebra folds
# ``AND(cofinite, conditional_universal)`` into a single root cofinite that
# ABSORBS the opaque authority as a mere business side-condition. The guard's
# counterfactual then strips that root cofinite and does NOT fire, so the real
# hasRole gate fails open (projects public). Adversarial finding (Stage-0
# verifier): the cofinite carve-out is slightly wider than pure denylists.
#
# NOT a regression — pre-fix this same shape resolves ``conditional_universal``
# (also public); the amended guard neither fixes nor worsens it. NOT reachable
# on the etherfi corpus: real denylist+authority mixes are SEPARATE modifiers
# (separate outer leaves), each inlined independently — the authority modifier
# gets its own ``external_check_only`` with the ``caller_tainted_authority_unresolved``
# blocker tag and gates correctly (see ``test_fixture8`` machinery / the
# multi-modifier corpus rows). xfail pins the DESIRED behavior so a future
# tightening (or the Stage-2 adapter, which enumerates the authority arm) flips
# it to xpass rather than silently leaving the gap.
def _and_denylist_opaque_callee_tree(callee_sig: str) -> dict[str, Any]:
    return {
        callee_sig: {
            "op": "AND",
            "children": [
                {
                    "op": "LEAF",
                    "leaf": {
                        "kind": "comparison",
                        "operator": "lte",
                        "authority_role": "time",
                        "operands": [
                            {"source": "parameter", "parameter_index": 0, "parameter_name": "account"},
                            {"source": "block_context", "block_context_kind": "timestamp"},
                        ],
                        "references_msg_sender": True,
                        "parameter_indices": [],
                        "expression": "blacklistedUntil[account] <= block.timestamp",
                        "basis": [],
                    },
                },
                {
                    "op": "LEAF",
                    "leaf": {
                        "kind": "equality",
                        "operator": "truthy",
                        "authority_role": "business",
                        "operands": [{"source": "view_call", "callee": "hasRole"}],
                        "references_msg_sender": False,
                        "parameter_indices": [],
                        "expression": "! hasRole(account, ROLE)",
                        "basis": [],
                    },
                },
            ],
        }
    }


# ---------------------------------------------------------------------------
# Two-hop DB harness.
# ---------------------------------------------------------------------------


def _seed_two_hop(
    session,
    *,
    caller_trees: dict[str, Any],
    callee_trees: dict[str, Any],
    seed_hook: Any = None,
) -> dict[str, Any]:
    """Seed a caller + registry (as its ``registry`` state var), resolve the
    caller, and return the ``guarded(uint256)`` capability dict.

    ``seed_hook(session, registry_addr)`` runs after the contracts are seeded and
    before the resolve — the adapter-live variants use it to make the registry a
    recognized role store (impl markers + indexed events + warm cursor)."""
    from db.models import Contract, ControllerValue, Job, JobStage, JobStatus, Protocol
    from db.queue import store_artifact
    from services.resolution.capability_resolver import resolve_contract_capabilities

    proto = Protocol(name=f"rolegate_guard_{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()

    caller_addr = "0x" + uuid.uuid4().hex[:8] + "a1" * 16
    registry_addr = "0x" + uuid.uuid4().hex[:8] + "b2" * 16

    def _seed(addr: str, trees: dict[str, Any]):
        job = Job(
            address=addr,
            request={"address": addr, "name": "T"},
            status=JobStatus.completed,
            stage=JobStage.done,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(job)
        session.flush()
        store_artifact(session, job.id, "predicate_trees", data={"schema_version": "semantic", "trees": trees})
        contract = Contract(address=addr, chain="ethereum", protocol_id=proto.id, job_id=job.id)
        session.add(contract)
        session.flush()
        return job, contract

    caller_job, caller_contract = _seed(caller_addr, caller_trees)
    _seed(registry_addr, callee_trees)
    session.add(
        ControllerValue(
            contract_id=caller_contract.id,
            controller_id="external_contract:registry",
            value=registry_addr,
            resolved_type="contract",
            source="state_variable",
        )
    )
    if seed_hook is not None:
        seed_hook(session, registry_addr)
    session.commit()

    caps = resolve_contract_capabilities(
        session, address=caller_addr, chain_id=1, chain="ethereum", job_id=caller_job.id
    )
    key = next(k for k in (caps or {}) if k.startswith("guarded"))
    return (caps or {})[key]


def _basis(cap_dict: dict[str, Any]) -> list[str]:
    return list(((cap_dict.get("check") or {}).get("extra") or {}).get("basis") or [])


def _is_public(cap_dict: dict[str, Any]) -> bool:
    return project_capability_surface(cap_dict).authority_public


# ---------------------------------------------------------------------------
# Section 1 — pure shape discriminator (is_caller_keyed_time_denylist).
# ---------------------------------------------------------------------------


def _cmp_leaf(operands, operator) -> Any:
    return {
        "kind": "comparison",
        "operator": operator,
        "authority_role": "time",
        "operands": operands,
        "references_msg_sender": False,
        "expression": "",
        "basis": [],
    }


_CALLER_OP = {"source": "root_caller"}
_TIME_OP = {"source": "block_context", "block_context_kind": "timestamp"}


def test_denylist_discriminator_matches_both_operand_orders():
    # proceed when caller_value <= now: caller LHS/lte, and reversed caller RHS/gte.
    assert is_caller_keyed_time_denylist(_cmp_leaf([_CALLER_OP, _TIME_OP], "lte"))
    assert is_caller_keyed_time_denylist(_cmp_leaf([_TIME_OP, _CALLER_OP], "gte"))


def test_denylist_discriminator_rejects_allowlist_polarity():
    # The allowlist (caller_value >= now) is NOT a denylist, and vice-versa —
    # the two are exact proceed-relation inverses.
    allow = _cmp_leaf([_CALLER_OP, _TIME_OP], "gte")
    assert is_caller_keyed_time_allowlist(allow)
    assert not is_caller_keyed_time_denylist(allow)
    deny = _cmp_leaf([_CALLER_OP, _TIME_OP], "lte")
    assert is_caller_keyed_time_denylist(deny)
    assert not is_caller_keyed_time_allowlist(deny)


def test_denylist_discriminator_requires_timestamp_and_caller():
    # A caller-keyed balance/allowance threshold (RHS a parameter, not a
    # timestamp) is not a time denylist.
    assert not is_caller_keyed_time_denylist(
        _cmp_leaf([_CALLER_OP, {"source": "parameter", "parameter_index": 0}], "lte")
    )


# ---------------------------------------------------------------------------
# Section 2 — companion-2 leaf emission (shape-level, both flags).
# ---------------------------------------------------------------------------


def test_denylist_leaf_emits_root_cofinite(tmp_path, both_flags):
    """A bound, caller-tainted time denylist emits a root-subject
    ``cofinite_blacklist`` (deny-by-exception), not ``conditional_universal``."""
    reg = _compile(tmp_path, _CALLEE_DENYLIST, "Registry")
    trees = _build_pipeline(reg)
    key = next(k for k in trees if k.startswith("nonBlacklisted"))
    bound = _bind_callee_parameters(trees[key], [{"source": "root_caller"}])
    cap = evaluate_tree(bound)
    assert cap.kind == "cofinite_blacklist", f"denylist must emit cofinite, got {cap.kind}"
    assert cap.subject == "root"
    assert cap.blacklist_quality == "lower_bound"
    assert [c.kind for c in cap.conditions] == ["time"]


# ---------------------------------------------------------------------------
# Section 3 — the :1976 guard, two-hop DB (both flags).
# ---------------------------------------------------------------------------


def test_fixture1_real_opaque_shape_gates_via_guard(session, both_flags):
    """THE acceptance shape (ROLEGATE_FIX_SPEC §6.1): the faithful real
    registry ``onlyOperatingMultisig`` leaf (opaque ``view_call``, non-return
    expression) reaches :1976. Inline projects public -> guard fires ->
    external_check_only, authority_public False, basis carries the tag."""
    caller = _build_pipeline(_compile(_tmp(), _caller_src("registry.onlyOperatingMultisig(msg.sender)"), "CallerLike"))
    cap = _seed_two_hop(
        session,
        caller_trees=caller,
        callee_trees=_opaque_callee_tree("onlyOperatingMultisig(address)"),
    )
    assert cap["kind"] == "external_check_only", f"real opaque delegated gate must gate, got {cap['kind']}"
    assert not _is_public(cap)
    assert "inline_refine_only_guard" in _basis(cap)


# ---------------------------------------------------------------------------
# Section 3a — durability telemetry (Stage 4): the guard-fire metric+WARNING and
# the delegated_gate_unresolved tripwire keyed on the callee signature.
# ---------------------------------------------------------------------------


def test_guard_fire_emits_metric_and_warning(session, both_flags, caplog):
    import logging as _logging

    import services.resolution.predicate_evaluator as _pe
    from utils.logging import stage_metrics_var

    _pe._GUARD_FIRE_COUNTS.clear()
    caller = _build_pipeline(_compile(_tmp(), _caller_src("registry.onlyOperatingMultisig(msg.sender)"), "CallerLike"))
    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    caplog.set_level(_logging.WARNING, logger="services.resolution.predicate_evaluator")
    try:
        cap = _seed_two_hop(
            session, caller_trees=caller, callee_trees=_opaque_callee_tree("onlyOperatingMultisig(address)")
        )
    finally:
        stage_metrics_var.reset(token)
    assert "inline_refine_only_guard" in _basis(cap)
    guard_keys = [k for k in metrics if k.startswith("inline_refine_only_guard::")]
    assert guard_keys and all(metrics[k] >= 1 for k in guard_keys)
    assert any("refine-only guard closed" in r.getMessage() for r in caplog.records)


def test_delegated_gate_unresolved_emitted_on_settled_gate(earned_public):
    # A caller gate that SETTLES external_check_only without a pending-index
    # deferral trips the durability metric, keyed on the callee signature.
    import services.resolution.predicate_evaluator as _pe
    from utils.logging import stage_metrics_var

    _pe._DELEGATED_GATE_UNRESOLVED_COUNTS.clear()
    leaf = {
        "kind": "external_set",
        "operator": "truthy",
        "operands": [{"source": "msg_sender"}],
        "set_descriptor": {"kind": "external_set", "key_sources": [{"source": "msg_sender"}]},
    }
    check = CapabilityExpr.external_check_only(
        _external_check(target="0x" + "a1" * 20, selector="0x12345678", sig="onlyOperatingMultisig(address)")
    )
    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    try:
        out = _pe._stamp_caller_gate_check(check, cast(LeafPredicate, leaf))
    finally:
        stage_metrics_var.reset(token)
    assert out.kind == "external_check_only"
    assert metrics.get("delegated_gate_unresolved::onlyOperatingMultisig(address)") == 1


def test_delegated_gate_unresolved_skipped_when_deferred(earned_public):
    # A cold-index deferral is transient (the reconciler self-heals it) — it must
    # NOT trip the tripwire, or every cold first pass would false-alarm.
    import services.resolution.predicate_evaluator as _pe
    from utils.logging import stage_metrics_var

    _pe._DELEGATED_GATE_UNRESOLVED_COUNTS.clear()
    leaf = {
        "kind": "external_set",
        "operator": "truthy",
        "operands": [{"source": "msg_sender"}],
        "set_descriptor": {"kind": "external_set", "key_sources": [{"source": "msg_sender"}]},
    }
    check = CapabilityExpr.external_check_only(
        _external_check(
            target="0x" + "a1" * 20,
            selector="0x12345678",
            sig="onlyOperatingMultisig(address)",
            deferred=True,
        )
    )
    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    try:
        _pe._stamp_caller_gate_check(check, cast(LeafPredicate, leaf))
    finally:
        stage_metrics_var.reset(token)
    assert not any(k.startswith("delegated_gate_unresolved") for k in metrics)


def _external_check(*, target: str, selector: str, sig: str, deferred: bool = False):
    from services.resolution.capabilities import ExternalCheck

    extra: dict[str, Any] = {"basis": [], "callee_signature": sig}
    if deferred:
        extra["deferred_pending_index"] = True
    return ExternalCheck(target_address=target, target_call_selector=selector, extra=extra)


# ---------------------------------------------------------------------------
# Section 3b — the adapter-live flip (Stage 2). Same faithful opaque shape as
# fixture 1, but with the registry made a recognized Solady role store: the
# EnumerableRoleStoreAdapter enumerates the controllers, so the outer gate never
# reaches the :1976 guard and resolves to the concrete multisig.
# ---------------------------------------------------------------------------

_LIVE_IMPL = "0x" + "3b" * 20
_LIVE_MULTISIG = "0x2aca71020de61bb532008049e1bd41e451ae8adc"
_LIVE_ROLE = 1  # OPERATION_MULTISIG_ROLE (Solady uint256 id)
_ROLE_SET_TOPIC0 = SOLADY_ENUMERABLE_ROLES.grant_events[0].topic0


def _word(value: int) -> str:
    return "0x" + format(value, "064x")


def _addr_word(address: str) -> str:
    return "0x" + address.lower().removeprefix("0x").rjust(64, "0")


def _adapter_live_seed_hook(callee_sig: str):
    """Make the seeded registry a recognized Solady role store: proxy→impl
    linkage, one active RoleSet grant to the multisig, and a warm cursor."""

    def _hook(session, registry_addr: str) -> None:
        from sqlalchemy import func, select

        from db.models import Contract, IndexedEventCursor, IndexedEventLog

        contract = session.execute(
            select(Contract).where(func.lower(Contract.address) == registry_addr.lower())
        ).scalar_one()
        contract.implementation = _LIVE_IMPL
        contract.is_proxy = True
        session.add(
            IndexedEventLog(
                chain_id=1,
                event_address=registry_addr.lower(),
                topic0=_ROLE_SET_TOPIC0.lower(),
                tx_hash=(1).to_bytes(32, "big"),
                log_index=0,
                block_number=100,
                block_hash=(100).to_bytes(32, "big"),
                transaction_index=0,
                topics=[_ROLE_SET_TOPIC0, _addr_word(_LIVE_MULTISIG), _word(_LIVE_ROLE), _word(1)],
                data_words=[],
            )
        )
        session.add(
            IndexedEventCursor(
                chain_id=1,
                event_address=registry_addr.lower(),
                topic0=_ROLE_SET_TOPIC0.lower(),
                last_indexed_block=25_000_000,
                backfill_complete=True,
            )
        )

    return _hook


def _install_adapter_live_wire(monkeypatch, callee_sig: str, members: set[str]) -> None:
    """Stub the two wires the adapter touches under the full resolver: standard
    detection (``get_code`` markers on the impl) and the Multicall3 gate probe
    (``rpc_request``). Any non-probe RPC (e.g. the resolver's head pin) raises so
    it falls back exactly as under netguard — the offline default."""
    from eth_abi.abi import decode as abi_decode
    from eth_abi.abi import encode as abi_encode
    from eth_utils.crypto import keccak

    import services.resolution.role_store_standards as rss
    import utils.rpc as _rpc

    marker_code = "0x" + "".join("63" + s.removeprefix("0x") for s in SOLADY_ENUMERABLE_ROLES.marker_selectors)

    def _fake_get_code(rpc_url, address, *, chain_id=None):
        return marker_code if address.lower() == _LIVE_IMPL.lower() else "0x00"

    monkeypatch.setattr(rss, "get_code", _fake_get_code)
    monkeypatch.setattr(rss, "rpc_request", lambda *a, **k: None)

    gate_sel = keccak(text=callee_sig).hex()[:8]
    members_l = {m.lower() for m in members}
    control_l = _NEGATIVE_CONTROL_ADDR.lower()

    def _stub(rpc_url, method, params=None, **kwargs):
        # The adapter's pin-once (§A1) reads one eth_blockNumber when the resolver
        # left the pass height unpinned (netguard blocks its head read). Answer with
        # a height above the seeded grant so the fold + probe pin to it.
        if method == "eth_blockNumber":
            return hex(25_000_000)
        to = (params[0].get("to") if params and isinstance(params[0], dict) else None) if method == "eth_call" else None
        from utils.rpc import MULTICALL3_ADDRESS

        if method != "eth_call" or (to or "").lower() != MULTICALL3_ADDRESS.lower():
            raise RuntimeError("only the Multicall3 gate probe is stubbed")
        assert params is not None
        body = bytes.fromhex(params[0]["data"][10:])
        calls = abi_decode(["(address,bool,bytes)[]"], body)[0]
        results: list[tuple[bool, bytes]] = []
        for _target, _allow, calldata in calls:
            sel = calldata[:4].hex()
            addr = "0x" + calldata[4:36][-20:].hex()
            if sel == gate_sel:
                ok = False if addr == control_l else (addr in members_l)
                results.append((ok, b""))
            else:
                results.append((False, b""))
        return "0x" + abi_encode(["(bool,bytes)[]"], [results]).hex()

    # Patch the adapter's imported reference too, so its pin-once eth_blockNumber
    # read reaches the stub (the adapter did ``from utils.rpc import rpc_request``).
    import services.resolution.adapters.enumerable_role_store as _ers

    monkeypatch.setattr(_rpc, "rpc_request", _stub)
    monkeypatch.setattr(_ers, "rpc_request", _stub)


def test_fixture1_adapter_live_flips_to_finite_set(session, both_flags, monkeypatch):
    """FIXTURE 1 ADAPTER-LIVE (ROLEGATE_FIX_SPEC §6.12 / CONTROLLER_RESOLUTION_SPEC
    §6 Stage 2): the SAME faithful opaque ``onlyOperatingMultisig`` shape as the
    guard fixture, but the registry is now a recognized Solady role store with
    indexed grants and stubbed gate probes. The EnumerableRoleStoreAdapter
    enumerates the controller, so the function resolves ``finite_set([multisig])``
    — never reaching the guard."""
    caller = _build_pipeline(_compile(_tmp(), _caller_src("registry.onlyOperatingMultisig(msg.sender)"), "CallerLike"))
    _install_adapter_live_wire(monkeypatch, "onlyOperatingMultisig(address)", {_LIVE_MULTISIG})
    cap = _seed_two_hop(
        session,
        caller_trees=caller,
        callee_trees=_opaque_callee_tree("onlyOperatingMultisig(address)"),
        seed_hook=_adapter_live_seed_hook("onlyOperatingMultisig(address)"),
    )
    assert cap["kind"] == "finite_set", f"adapter-live gate must enumerate, got {cap['kind']}"
    assert cap.get("members") == [_LIVE_MULTISIG.lower()]
    assert cap.get("membership_quality") == "exact"
    assert any(step.get("step") == "enumerable_role_store" for step in cap.get("trace") or [])
    assert "inline_refine_only_guard" not in _basis(cap)


def test_fixture3_computed_variant_gates(session, both_flags):
    """Compilation-variant coverage (fixture h): the minimal Solady assembly
    folds to a ``computed``/return leaf that routes through the
    materialization fallback — still gated (external_check_only)."""
    reg = _build_pipeline(_compile(_tmp(), _CALLEE_SOLADY_OPAQUE, "Registry"))
    caller = _build_pipeline(_compile(_tmp(), _caller_src("registry.onlyOperatingMultisig(msg.sender)"), "CallerLike"))
    cap = _seed_two_hop(session, caller_trees=caller, callee_trees=reg)
    assert cap["kind"] == "external_check_only", f"computed opaque variant must gate, got {cap['kind']}"
    assert not _is_public(cap)


def test_fixture2_or_mix_gates(session, both_flags):
    """OR-mix d2 — partial taint loss on one disjunct. Every antecedent-level
    "no caller taint after binding" rule misses this (the transparent arm
    keeps taint); the surface-level guard still gates it."""
    caller = _build_pipeline(_compile(_tmp(), _caller_src("registry.onlyMixed(msg.sender)"), "CallerLike"))
    cap = _seed_two_hop(session, caller_trees=caller, callee_trees=_ormix_callee_tree("onlyMixed(address)"))
    assert cap["kind"] == "external_check_only", f"OR-mix must gate, got {cap['kind']}"
    assert not _is_public(cap)


@pytest.mark.xfail(
    reason="corpus-empty adversarial gap (Stage-0 verifier): a single callee that ANDs a "
    "caller-keyed time-denylist with an opaque authority folds to one root cofinite that "
    "absorbs the authority as a business condition; the counterfactual strips it and the "
    "guard does not fire. Not a regression (pre-fix also public); real corpus mixes are "
    "separate modifiers that gate correctly. Flips to xpass under a tighter counterfactual "
    "or the Stage-2 enumeration adapter.",
    strict=False,
)
def test_and_mix_denylist_absorbs_opaque_authority_should_gate(session, both_flags):
    """A single callee ``AND(time-denylist(caller), opaque-hasRole(caller))``: the real
    hasRole gate is a genuine authority, so this SHOULD gate — but the AND folds into a
    root cofinite the counterfactual spares, so it currently fails open. Pins the gap."""
    caller = _build_pipeline(_compile(_tmp(), _caller_src("registry.onlyMixed(msg.sender)"), "CallerLike"))
    cap = _seed_two_hop(
        session, caller_trees=caller, callee_trees=_and_denylist_opaque_callee_tree("onlyMixed(address)")
    )
    assert not _is_public(cap), f"denylist-AND-opaque-authority must gate, got public {cap['kind']}"


def test_fixture4_transparent_used_arg_gates_without_guard(session, both_flags):
    """A transparent used-arg allowlist (``checkAllowed``): binding succeeds,
    the callee threads taint and gates on its own — external_check_only
    WITHOUT the guard firing (the tag is absent)."""
    reg = _build_pipeline(_compile(_tmp(), _CALLEE_PAUSE_AND_ALLOW, "Registry"))
    caller = _build_pipeline(_compile(_tmp(), _caller_src("registry.checkAllowed(msg.sender)"), "CallerLike"))
    cap = _seed_two_hop(session, caller_trees=caller, callee_trees=reg)
    assert not _is_public(cap), "transparent used-arg allowlist must gate"
    assert "inline_refine_only_guard" not in _basis(cap)


def test_fixture7_no_arg_paused_stays_public(session, both_flags):
    """A no-arg delegated paused check (``registry.checkNotPaused()``): the
    outer leaf never receives the caller's identity, so the guard antecedent
    is false and the pause side-condition stays public."""
    reg = _build_pipeline(_compile(_tmp(), _CALLEE_NOARG_PAUSE, "Registry"))
    caller = _build_pipeline(_compile(_tmp(), _caller_src("registry.checkNotPaused()"), "CallerLike"))
    cap = _seed_two_hop(session, caller_trees=caller, callee_trees=reg)
    assert _is_public(cap), f"no-arg delegated pause must stay public, got {cap['kind']}"
    assert "inline_refine_only_guard" not in _basis(cap)


def test_fixture8_unused_arg_paused_now_gates(session, both_flags):
    """Documented sacrifice (ROLEGATE_FIX_SPEC §6.8): a delegated pause that
    pointlessly takes the caller address (``checkNotPaused(msg.sender)``, arg
    unused) now gates. The inline resolves conditional_universal(pause) — NOT
    a cofinite — so the counterfactual does not spare it; the guard fires.
    Accepted fail-closed trade (corpus-empty shape)."""
    reg = _build_pipeline(_compile(_tmp(), _CALLEE_PAUSE_AND_ALLOW, "Registry"))
    caller = _build_pipeline(_compile(_tmp(), _caller_src("registry.checkNotPaused(msg.sender)"), "CallerLike"))
    cap = _seed_two_hop(session, caller_trees=caller, callee_trees=reg)
    assert cap["kind"] == "external_check_only", f"unused-arg pause now gates, got {cap['kind']}"
    assert not _is_public(cap)
    assert "inline_refine_only_guard" in _basis(cap)


def test_fixture11_transparent_denylist_public_cofinite(session, both_flags):
    """AMENDED regression anchor (ROLEGATE_FIX_SPEC §6.11): a transparent
    delegated denylist inline threads taint and emits a root cofinite. The
    guard's counterfactual (root cofinites removed) is NOT public, so the
    guard does not fire — the function stays PUBLIC with a deny-by-exception
    condition."""
    reg = _build_pipeline(_compile(_tmp(), _CALLEE_DENYLIST, "Registry"))
    caller = _build_pipeline(_compile(_tmp(), _caller_src("registry.nonBlacklisted(msg.sender)"), "CallerLike"))
    cap = _seed_two_hop(session, caller_trees=caller, callee_trees=reg)
    assert cap["kind"] == "cofinite_blacklist", f"transparent denylist must stay public cofinite, got {cap['kind']}"
    assert _is_public(cap)
    assert "inline_refine_only_guard" not in _basis(cap)


# ---------------------------------------------------------------------------
# Section 4 — shape-level classification controls (both flags).
# ---------------------------------------------------------------------------

# Transparent role-store (fixture 5): hasRole via an EXTERNAL RoleRegistry where
# the account binding survives the helper boundary — the leaf stays a
# caller-tainted external_bool and gates directly (no :1976 involvement).
_TRANSPARENT_ROLE_STORE = """
pragma solidity ^0.8.19;
interface IRoleRegistry { function hasRole(bytes32 role, address account) external view returns (bool); }
contract C {
    bytes32 public constant OPERATION_MULTISIG_ROLE = keccak256("OP");
    IRoleRegistry public roleRegistry;
    uint256 public maxBid;
    error Unauthorized();
    function _checkRole(bytes32 role, address account) internal view {
        if (!roleRegistry.hasRole(role, account)) revert Unauthorized();
    }
    function _checkRole(bytes32 role) internal view { _checkRole(role, msg.sender); }
    function setMaxBidPrice(uint256 x) external { _checkRole(OPERATION_MULTISIG_ROLE); maxBid = x; }
}
"""


def test_fixture5_transparent_role_store_gates(tmp_path, both_flags):
    """The transparent role-store variants keep gating exactly as today: taint
    survives the helper boundary, so the external ACL leaf gates."""
    contract = _compile(tmp_path, _TRANSPARENT_ROLE_STORE, "C")
    trees = _build_pipeline(contract)
    cap = evaluate_tree(trees["setMaxBidPrice(uint256)"])
    assert cap.kind == "external_check_only", f"transparent role store must gate, got {cap.kind}"


# Effectful permissionless (fixture 6): require(token.transferFrom(msg.sender,…))
# moves the caller's own assets — permissionless, stays open. Protects the 11.
_EFFECTFUL_PERMISSIONLESS = """
pragma solidity ^0.8.19;
interface IERC20 { function transferFrom(address f, address t, uint256 a) external returns (bool); }
contract C {
    IERC20 immutable token;
    constructor(IERC20 t) { token = t; }
    function wrap(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
    }
}
"""


def test_fixture6_effectful_permissionless_stays_open(tmp_path, earned_public):
    """The value-movement class the guard's non-permissionless conjunct must
    never gate, protecting the 11 legitimate permissionless rows. Since the
    static classifier applies the gate-shape discriminator (Wave 5 B2), an
    effectful ``require(token.transferFrom(msg.sender, …))`` arrives as a
    BUSINESS leaf — it never reaches the authority-leaf carve-out, and the
    function is open via the business side-condition path instead of
    conditional_universal(self_service). Same openness, coarser condition
    typing; restoring the self_service/permit_sig badge from the mutability
    now stamped on the leaf is a resolution-plane follow-up."""
    contract = _compile(tmp_path, _EFFECTFUL_PERMISSIONLESS, "C")
    trees = _build_pipeline(contract)
    cap = evaluate_tree(trees["wrap(uint256)"])
    assert cap.kind == "conditional_universal", f"value movement must stay open, got {cap.kind}"
    assert cap.conditions, "the external call must surface as a condition, not silently vanish"
    assert all(c.kind in ("self_service", "business") for c in cap.conditions)


# ---------------------------------------------------------------------------
# Section 5 — the counterfactual helper in isolation.
# ---------------------------------------------------------------------------


def test_public_without_root_cofinites_conditional_universal_is_public():
    from services.resolution.capabilities import Condition

    cap = CapabilityExpr.conditional_universal(Condition(kind="business", description="! hasRole(...)"))
    assert _public_without_root_cofinites(cap) is True


def test_public_without_root_cofinites_bare_cofinite_is_not_public():
    cap = CapabilityExpr.cofinite_blacklist([], blacklist_quality="lower_bound", subject="root")
    # Public ONLY via the cofinite -> counterfactual removes it -> not public.
    assert _public_without_root_cofinites(cap) is False


def test_public_without_root_cofinites_or_with_conditional_is_public():
    from services.resolution.capabilities import Condition

    or_cap = CapabilityExpr.structural_or(
        [
            CapabilityExpr.finite_set(["0x" + "ab" * 20], quality="exact"),
            CapabilityExpr.conditional_universal(Condition(kind="business", description="opaque")),
        ]
    )
    assert _public_without_root_cofinites(or_cap) is True


def test_public_without_root_cofinites_or_cofinite_conditional_is_public():
    """Milestone follow-up (b): OR(root cofinite, conditional_universal) — the
    counterfactual strips ONLY the root cofinite, leaving the conditional_universal,
    which is still public. So a laundered allowlist that OR-composes a denylist with
    an opaque public arm survives the strip → the guard's antecedent holds (True)."""
    from services.resolution.capabilities import Condition

    or_cap = CapabilityExpr.structural_or(
        [
            CapabilityExpr.cofinite_blacklist([], blacklist_quality="lower_bound", subject="root"),
            CapabilityExpr.conditional_universal(Condition(kind="business", description="opaque authority")),
        ]
    )
    assert _public_without_root_cofinites(or_cap) is True


# ---------------------------------------------------------------------------
# Section 6 — transparent role-store variants (milestone follow-up a). Every
# shape where the account binding SURVIVES the helper/modifier boundary keeps
# gating exactly as today; none opens. Sources from rolegate-failopen-repro/
# repro_pr151_B.py + repro_2771.py, alongside the fixture-5 pin above.
# ---------------------------------------------------------------------------

_TV_EXTERNAL_ROLEREGISTRY = """
pragma solidity ^0.8.19;
interface IRoleRegistry { function hasRole(bytes32 role, address account) external view returns (bool); }
contract C {
    bytes32 public constant OPERATION_MULTISIG_ROLE = keccak256("OP");
    IRoleRegistry public roleRegistry; uint256 public maxBid; error Unauthorized();
    function _checkRole(bytes32 role, address account) internal view {
        if (!roleRegistry.hasRole(role, account)) revert Unauthorized();
    }
    function _checkRole(bytes32 role) internal view { _checkRole(role, msg.sender); }
    function setMaxBidPrice(uint256 x) external { _checkRole(OPERATION_MULTISIG_ROLE); maxBid = x; }
}
"""

_TV_EXTERNAL_MSGSENDER_HELPER = """
pragma solidity ^0.8.19;
interface IRoleRegistry { function hasRole(bytes32 role, address account) external view returns (bool); }
contract C {
    bytes32 public constant OPERATION_MULTISIG_ROLE = keccak256("OP");
    IRoleRegistry public roleRegistry; uint256 public maxBid; error Unauthorized();
    function _msgSender() internal view returns (address) { return msg.sender; }
    function _checkRole(bytes32 role, address account) internal view {
        if (!roleRegistry.hasRole(role, account)) revert Unauthorized();
    }
    function _checkRole(bytes32 role) internal view { _checkRole(role, _msgSender()); }
    function setMaxBidPrice(uint256 x) external { _checkRole(OPERATION_MULTISIG_ROLE); maxBid = x; }
}
"""

_TV_MODIFIER_ONLYROLE_LOCAL = """
pragma solidity ^0.8.19;
contract AccessControl {
    mapping(bytes32 => mapping(address => bool)) private _roles;
    error AccessControlUnauthorizedAccount(address account, bytes32 role);
    function hasRole(bytes32 role, address account) public view returns (bool) { return _roles[role][account]; }
    function _checkRole(bytes32 role, address account) internal view {
        if (!hasRole(role, account)) revert AccessControlUnauthorizedAccount(account, role);
    }
    function _checkRole(bytes32 role) internal view { _checkRole(role, _msgSender()); }
    function _msgSender() internal view virtual returns (address) { return msg.sender; }
    modifier onlyRole(bytes32 role) { _checkRole(role); _; }
}
contract C is AccessControl {
    bytes32 public constant OPERATION_MULTISIG_ROLE = keccak256("OP"); uint256 public maxBid;
    function setMaxBidPrice(uint256 x) external onlyRole(OPERATION_MULTISIG_ROLE) { maxBid = x; }
}
"""

_TV_ERC2771 = """
pragma solidity ^0.8.19;
interface IRoleRegistry { function hasRole(bytes32 role, address account) external view returns (bool); }
contract C {
    bytes32 public constant OPERATION_MULTISIG_ROLE = keccak256("OP");
    IRoleRegistry public roleRegistry; address public trustedForwarder; uint256 public maxBid; error Unauthorized();
    function _msgSender() internal view returns (address signer) {
        if (msg.sender == trustedForwarder && msg.data.length >= 20) {
            assembly { signer := shr(96, calldataload(sub(calldatasize(), 20))) }
        } else { signer = msg.sender; }
    }
    function _checkRole(bytes32 role, address account) internal view {
        if (!roleRegistry.hasRole(role, account)) revert Unauthorized();
    }
    function _checkRole(bytes32 role) internal view { _checkRole(role, _msgSender()); }
    modifier onlyRole(bytes32 role) { _checkRole(role); _; }
    function setMaxBidPrice(uint256 x) external onlyRole(OPERATION_MULTISIG_ROLE) { maxBid = x; }
}
"""


@pytest.mark.parametrize(
    "source, expected_kind",
    [
        (_TV_EXTERNAL_ROLEREGISTRY, "external_check_only"),
        (_TV_EXTERNAL_MSGSENDER_HELPER, "external_check_only"),
        (_TV_MODIFIER_ONLYROLE_LOCAL, "finite_set"),
        (_TV_ERC2771, "external_check_only"),
    ],
    ids=["external_roleregistry", "external_msgSender_helper", "modifier_onlyRole_local", "erc2771"],
)
def test_transparent_role_store_variants_gate(tmp_path, both_flags, source, expected_kind):
    """Every transparent variant gates (never ``conditional_universal``/public): the
    account binding survives the helper/modifier boundary, so the ACL leaf stays
    caller-tainted and resolves to a non-public shape under both flags."""
    from services.resolution.capability_resolver import capability_to_dict

    contract = _compile(tmp_path, source, "C")
    trees = _build_pipeline(contract)
    cap = evaluate_tree(trees["setMaxBidPrice(uint256)"])
    assert cap.kind == expected_kind, f"expected {expected_kind}, got {cap.kind}"
    assert cap.kind != "conditional_universal"
    assert not project_capability_surface(capability_to_dict(cap)).authority_public


# ---------------------------------------------------------------------------
# Section 7 — two-hop EFFECTFUL permissionless delegation (milestone follow-up
# c). The guard's ``not is_permissionless_caller_shape`` conjunct must spare a
# value-movement self-service call at the inline site — the guard never gates it,
# so the 11 permissionless rows survive under both flags.
# ---------------------------------------------------------------------------

_CALLER_EFFECTFUL = """
pragma solidity ^0.8.19;
interface IReg { function pull(address from, uint256 amt) external returns (bool); }
contract CallerLike {
    IReg public registry;
    uint256 public v;
    function guarded(uint256 x) external { require(registry.pull(msg.sender, x), "fail"); v = x; }
}
"""

_CALLEE_EFFECTFUL = {
    "pull(address,uint256)": {
        "op": "LEAF",
        "leaf": {
            "kind": "equality",
            "operator": "truthy",
            "authority_role": "business",
            "operands": [{"source": "computed"}],
            "references_msg_sender": False,
            "parameter_indices": [],
            "expression": "return true",
            "basis": [],
        },
    }
}


def test_two_hop_effectful_permissionless_guard_spares(session, both_flags):
    """A caller whose gate is an EFFECTFUL delegated ``registry.pull(msg.sender, x)``
    (value movement) is the ``is_permissionless_caller_shape`` class: the guard's
    ¬permissionless conjunct means it never appends ``inline_refine_only_guard``.
    Under earned-public it stays open (conditional_universal); the guard tag is
    absent under both flags."""
    caller = _build_pipeline(_compile(_tmp(), _CALLER_EFFECTFUL, "CallerLike"))
    cap = _seed_two_hop(session, caller_trees=caller, callee_trees=_CALLEE_EFFECTFUL)
    assert "inline_refine_only_guard" not in _basis(cap), "permissionless value movement must not hit the guard"
    if both_flags == "1":
        assert _is_public(cap), f"value movement must stay open under earned-public, got {cap['kind']}"


# A fresh scratch dir so the many single-file compiles in the two-hop tests
# don't collide (each Slither run needs its own directory).
def _tmp() -> Path:
    return Path(tempfile.mkdtemp())
