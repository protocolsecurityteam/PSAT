"""Delegated role-gate refine-only guard.

Cross-contract inlining may only *refine* a caller-tainted delegated gate, never un-gate it.
When the un-inlined outer leaf would fail closed and the inline result projects public, the
inline is discarded and the outer delegated check kept (``external_check_only`` +
``inline_refine_only_guard``). The one carve-out is a deny-by-exception denylist, typed as a
root-subject ``cofinite_blacklist`` so the guard's cofinite counterfactual spares it.

Two harness layers: SHAPE-LEVEL (``evaluate_tree`` on one compiled unit; mirrors
``test_earned_public.py``) and TWO-HOP DB (``resolve_contract_capabilities`` over a seeded
caller + registry; the only path reaching the ``:1976`` guard inside
``_maybe_inline_cross_contract_call``; mirrors ``test_capability_resolver.py``).

The offline suite forces ``PSAT_DIFFERENTIAL_PROBE=0``, so the gated verdict is read directly.
The real registry's opaque ``onlyX`` leaf compiles to a ``business/equality/truthy`` leaf with
an erased ``view_call`` operand and an expression NOT starting with ``return `` (reaches
``:1976``); a *minimal* Solady fixture folds to a ``computed`` / ``return ok_1`` leaf that takes
the materialization fallback instead. FIXTURE 1 therefore seeds the faithful ``view_call``
callee tree directly.
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
# behavioral test therefore runs under both flag states.
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


# Folds to ``return ok_1``, so the materialization fallback gates it.


def _caller_src(callee_call: str) -> str:
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
# start with "return " -> reaches the refine-only guard.
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


# The transparent arm stays tainted, so an antecedent-level taint rule never fires while the opaque arm makes the OR
# public.


# AND(cofinite, conditional_universal) folds to a root cofinite that absorbs the opaque authority, so the guard's
# counterfactual spares it and the real hasRole gate fails open. Not a regression and not on the etherfi corpus
# (real mixes are separate modifiers); xfail pins the desired behavior so a fix flips it to xpass.


def _seed_two_hop(
    session,
    *,
    caller_trees: dict[str, Any],
    callee_trees: dict[str, Any],
    seed_hook: Any = None,
) -> dict[str, Any]:
    """``seed_hook`` runs before the resolve; adapter-live variants use it to register the role store."""
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


@pytest.mark.parametrize(
    ("operands", "operator", "is_denylist", "is_allowlist"),
    [
        pytest.param([_CALLER_OP, _TIME_OP], "lte", True, False, id="caller_lhs_lte"),
        pytest.param([_TIME_OP, _CALLER_OP], "gte", True, False, id="caller_rhs_gte"),
        # The allowlist is the exact inverse of the denylist; inverted polarity would open a gated function.
        pytest.param([_CALLER_OP, _TIME_OP], "gte", False, True, id="allowlist_polarity"),
        pytest.param(
            [_CALLER_OP, {"source": "parameter", "parameter_index": 0}], "lte", False, False, id="non_time_threshold"
        ),
    ],
)
def test_denylist_discriminator(operands, operator, is_denylist, is_allowlist):
    leaf = _cmp_leaf(operands, operator)
    assert is_caller_keyed_time_denylist(leaf) is is_denylist
    assert is_caller_keyed_time_allowlist(leaf) is is_allowlist


# Section 3 — the refine-only guard, two-hop DB (both flags).


def test_fixture1_real_opaque_shape_gates_via_guard(session, both_flags):
    """THE acceptance shape: the real registry ``onlyOperatingMultisig``
    leaf reaches :1976; inline projects public, so the guard fires (external_check_only,
    authority_public False, basis carries the tag)."""
    caller = _build_pipeline(_compile(_tmp(), _caller_src("registry.onlyOperatingMultisig(msg.sender)"), "CallerLike"))
    cap = _seed_two_hop(
        session,
        caller_trees=caller,
        callee_trees=_opaque_callee_tree("onlyOperatingMultisig(address)"),
    )
    assert cap["kind"] == "external_check_only", f"real opaque delegated gate must gate, got {cap['kind']}"
    assert not _is_public(cap)
    assert "inline_refine_only_guard" in _basis(cap)


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


@pytest.mark.parametrize(
    ("deferred", "expected_counts"),
    [
        pytest.param(False, {"delegated_gate_unresolved::onlyOperatingMultisig(address)": 1}, id="settled_gate"),
        # A cold-index deferral self-heals, so tripping here would false-alarm every cold first pass.
        pytest.param(True, {}, id="deferred"),
    ],
)
def test_delegated_gate_unresolved_metric(earned_public, deferred, expected_counts):
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
            deferred=deferred,
        )
    )
    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    try:
        out = _pe._stamp_caller_gate_check(check, cast(LeafPredicate, leaf))
    finally:
        stage_metrics_var.reset(token)
    assert out.kind == "external_check_only"
    assert {k: v for k, v in metrics.items() if k.startswith("delegated_gate_unresolved")} == expected_counts


def _external_check(*, target: str, selector: str, sig: str, deferred: bool = False):
    from services.resolution.capabilities import ExternalCheck

    extra: dict[str, Any] = {"basis": [], "callee_signature": sig}
    if deferred:
        extra["deferred_pending_index"] = True
    return ExternalCheck(target_address=target, target_call_selector=selector, extra=extra)


# Stage 2: a recognized Solady role store lets the adapter enumerate controllers, so the gate never reaches :1976.

_LIVE_IMPL = "0x" + "3b" * 20
_LIVE_MULTISIG = "0x2aca71020de61bb532008049e1bd41e451ae8adc"
_LIVE_ROLE = 1  # OPERATION_MULTISIG_ROLE (Solady uint256 id)
_ROLE_SET_TOPIC0 = SOLADY_ENUMERABLE_ROLES.grant_events[0].topic0


def _word(value: int) -> str:
    return "0x" + format(value, "064x")


def _addr_word(address: str) -> str:
    return "0x" + address.lower().removeprefix("0x").rjust(64, "0")


def _adapter_live_seed_hook(callee_sig: str):

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
                first_indexed_block=0,
                first_indexed_block_basis="creation_block_minus_one",
            )
        )

    return _hook


def _install_adapter_live_wire(monkeypatch, callee_sig: str, members: set[str]) -> None:
    """Any other RPC raises and falls back as under netguard."""
    from eth_abi.abi import decode as abi_decode
    from eth_abi.abi import encode as abi_encode
    from eth_utils.crypto import keccak

    import services.clients.rpc as _rpc
    import services.resolution.role_store_standards as rss

    marker_code = "0x" + "".join("63" + s.removeprefix("0x") for s in SOLADY_ENUMERABLE_ROLES.marker_selectors)

    def _fake_get_code(rpc_url, address, *, chain_id=None):
        return marker_code if address.lower() == _LIVE_IMPL.lower() else "0x00"

    monkeypatch.setattr(rss, "get_code", _fake_get_code)
    monkeypatch.setattr(rss, "rpc_request", lambda *a, **k: None)

    gate_sel = keccak(text=callee_sig).hex()[:8]
    members_l = {m.lower() for m in members}
    control_l = _NEGATIVE_CONTROL_ADDR.lower()

    def _stub(rpc_url, method, params=None, **kwargs):
        # The adapter's pin-once reads eth_blockNumber when the pass height is unpinned
        # (netguard blocks the head read); answer above the seeded grant so fold + probe pin to it.
        if method == "eth_blockNumber":
            return hex(25_000_000)
        to = (params[0].get("to") if params and isinstance(params[0], dict) else None) if method == "eth_call" else None
        from services.clients.rpc import MULTICALL3_ADDRESS

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

    # The adapter imported ``rpc_request`` by name.
    import services.resolution.adapters.enumerable_role_store as _ers

    monkeypatch.setattr(_rpc, "rpc_request", _stub)
    monkeypatch.setattr(_ers, "rpc_request", _stub)


def test_fixture1_adapter_live_flips_to_finite_set(session, both_flags, monkeypatch):
    """FIXTURE 1 ADAPTER-LIVE:
    same opaque shape as the guard fixture, but the registry is a recognized Solady role store,
    so the adapter enumerates it and the function resolves ``finite_set([multisig])`` without the guard."""
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


def test_fixture8_unused_arg_paused_now_gates(session, both_flags):
    """Documented sacrifice: a delegated pause pointlessly taking the
    caller address (arg unused) now gates. The inline is conditional_universal(pause), not a
    cofinite, so the counterfactual does not spare it. Accepted fail-closed trade."""
    reg = _build_pipeline(_compile(_tmp(), _CALLEE_PAUSE_AND_ALLOW, "Registry"))
    caller = _build_pipeline(_compile(_tmp(), _caller_src("registry.checkNotPaused(msg.sender)"), "CallerLike"))
    cap = _seed_two_hop(session, caller_trees=caller, callee_trees=reg)
    assert cap["kind"] == "external_check_only", f"unused-arg pause now gates, got {cap['kind']}"
    assert not _is_public(cap)
    assert "inline_refine_only_guard" in _basis(cap)


def test_fixture11_transparent_denylist_public_cofinite(session, both_flags):
    """AMENDED regression anchor: a transparent delegated denylist emits
    a root cofinite; the counterfactual is NOT public, so the guard does not fire and the function
    stays PUBLIC with a deny-by-exception condition."""
    reg = _build_pipeline(_compile(_tmp(), _CALLEE_DENYLIST, "Registry"))
    caller = _build_pipeline(_compile(_tmp(), _caller_src("registry.nonBlacklisted(msg.sender)"), "CallerLike"))
    cap = _seed_two_hop(session, caller_trees=caller, callee_trees=reg)
    assert cap["kind"] == "cofinite_blacklist", f"transparent denylist must stay public cofinite, got {cap['kind']}"
    assert _is_public(cap)
    assert "inline_refine_only_guard" not in _basis(cap)


# Moves the caller's own assets, so it stays open.
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
    """The guard must never gate this class.

    Since Wave 5 B2 it arrives as a business leaf rather than conditional_universal(self_service): same openness,
    coarser typing.
    """
    contract = _compile(tmp_path, _EFFECTFUL_PERMISSIONLESS, "C")
    trees = _build_pipeline(contract)
    cap = evaluate_tree(trees["wrap(uint256)"])
    assert cap.kind == "conditional_universal", f"value movement must stay open, got {cap.kind}"
    assert cap.conditions, "the external call must surface as a condition, not silently vanish"
    assert all(c.kind in ("self_service", "business") for c in cap.conditions)


# Transparent role-store variants: where the account binding survives the helper boundary, the function keeps gating.

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
    from services.resolution.capability_resolver import capability_to_dict

    contract = _compile(tmp_path, source, "C")
    trees = _build_pipeline(contract)
    cap = evaluate_tree(trees["setMaxBidPrice(uint256)"])
    assert cap.kind == expected_kind, f"expected {expected_kind}, got {cap.kind}"
    assert cap.kind != "conditional_universal"
    assert not project_capability_surface(capability_to_dict(cap)).authority_public


# Two-hop effectful delegation must survive under both flags.


# Each Slither run needs its own directory.
def _tmp() -> Path:
    return Path(tempfile.mkdtemp())
