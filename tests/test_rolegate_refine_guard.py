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

import os
import sys
import tempfile
import textwrap
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.policy.capability_surface import project_capability_surface  # noqa: E402
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
from services.static.contract_analysis_pipeline.predicates import build_predicate_tree  # noqa: E402
from services.static.contract_analysis_pipeline.reentrancy_pause import apply_reentrancy_pause_pass  # noqa: E402
from services.static.contract_analysis_pipeline.writer_gate import apply_writer_gate_pass  # noqa: E402


# The guard runs UNCONDITIONALLY (not behind earned_public_enabled()); every
# behavioral test therefore runs under both flag states (ROLEGATE_FIX_SPEC §6.9).
@pytest.fixture(params=["1", "0"], ids=["earned_on", "earned_off"])
def both_flags(request, monkeypatch):
    monkeypatch.setenv("PSAT_AUTHORITY_EARNED_PUBLIC", request.param)
    return request.param


@pytest.fixture
def earned_public(monkeypatch):
    monkeypatch.setenv("PSAT_AUTHORITY_EARNED_PUBLIC", "1")


_DB_URL: str = os.environ.get("TEST_DATABASE_URL", os.environ.get("DATABASE_URL", "")) or ""


def _can_connect() -> bool:
    if not _DB_URL:
        return False
    try:
        from sqlalchemy import create_engine

        engine = create_engine(_DB_URL)
        with engine.connect():
            pass
        engine.dispose()
        return True
    except Exception:
        return False


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


def _seed_two_hop(session, *, caller_trees: dict[str, Any], callee_trees: dict[str, Any]) -> dict[str, Any]:
    """Seed a caller + registry (as its ``registry`` state var), resolve the
    caller, and return the ``guarded(uint256)`` capability dict."""
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
    session.commit()

    caps = resolve_contract_capabilities(session, address=caller_addr, chain="ethereum", job_id=caller_job.id)
    key = next(k for k in (caps or {}) if k.startswith("guarded"))
    return (caps or {})[key]


def _basis(cap_dict: dict[str, Any]) -> list[str]:
    return list(((cap_dict.get("check") or {}).get("extra") or {}).get("basis") or [])


def _is_public(cap_dict: dict[str, Any]) -> bool:
    return project_capability_surface(cap_dict).authority_public


# ---------------------------------------------------------------------------
# Section 1 — pure shape discriminator (is_caller_keyed_time_denylist).
# ---------------------------------------------------------------------------


def _cmp_leaf(operands, operator):
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
    """The value-movement carve-out (an earned-public feature, so flag-ON): an
    effectful external call required to succeed stays
    conditional_universal(self_service) — this is the ``is_permissionless_caller_shape``
    class the guard's non-permissionless conjunct must never gate, protecting
    the 11 legitimate permissionless rows."""
    contract = _compile(tmp_path, _EFFECTFUL_PERMISSIONLESS, "C")
    trees = _build_pipeline(contract)
    cap = evaluate_tree(trees["wrap(uint256)"])
    assert cap.kind == "conditional_universal", f"value movement must stay open, got {cap.kind}"
    assert any(c.kind == "self_service" for c in cap.conditions)


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


# A fresh scratch dir so the many single-file compiles in the two-hop tests
# don't collide (each Slither run needs its own directory).
def _tmp() -> Path:
    return Path(tempfile.mkdtemp())
