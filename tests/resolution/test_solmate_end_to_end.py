"""End-to-end Solmate resolution on 100% real data.

Drives the actual resolver dispatch (``evaluate_tree_with_registry`` →
``AdapterRegistry`` → ``SolmateRolesAuthorityAdapter``) using:
  * the REAL predicate trees of ``TellerWithMultiAssetSupport`` 0xe2acf9f8…
    (``tests/fixtures/solmate/teller_predicate_trees.json``), and
  * the REAL RolesAuthority 0x3994741a… event logs
    (``tests/fixtures/solmate/roles_authority_3994741a.json``).

Pins the under-resolution fix end-to-end: ``pause`` (role-gated) resolves to
the governing 4/6 Safe; ``setShareLockPeriod`` (no role, owner renounced) does
not — a true negative, not a heuristic guess.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from services.resolution.adapters import AdapterRegistry, CallFrame, EvaluationContext
from services.resolution.adapters.event_indexed import EventIndexedAdapter
from services.resolution.adapters.solmate_roles import SolmateRolesAuthorityAdapter
from services.resolution.capabilities import CapabilityExpr
from services.resolution.capability_resolver import _selector_for_signature
from services.resolution.predicate_evaluator import evaluate_tree_with_registry

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "solmate"
SAFE_4_6 = "0xcea8039076e35a825854c5c2f85659430b06ec96"
ZERO = "0x" + "00" * 20
PAUSE = "0x8456cb59"
SET_SHARE_LOCK = "0x12056e2d"
# addAsset(ERC20): canonical EVM selector keccak("addAsset(address)") vs the
# non-canonical keccak("addAsset(ERC20)") the resolver folded against before the
# selector-canonicalization fix.
ADD_ASSET_CANONICAL = "0x298410e5"
ADD_ASSET_NONCANONICAL = "0x4fdd72aa"


def _event_rows() -> list[SimpleNamespace]:
    fixture = json.loads((FIXTURES / "roles_authority_3994741a.json").read_text())
    rows: list[SimpleNamespace] = []
    for log in fixture["logs"]:
        body = log["data"][2:] if isinstance(log["data"], str) and log["data"].startswith("0x") else ""
        data_words = ["0x" + body[i : i + 64] for i in range(0, len(body), 64)] if body else []
        rows.append(SimpleNamespace(topic0=log["topics"][0], topics=log["topics"], data_words=data_words))
    return rows


class FixtureRepo:
    def __init__(self, rows):
        self.rows = rows

    def iter_event_rows(self, *, chain_id, event_address, topic0s, block=None):
        del chain_id, event_address, block
        wanted = {t.lower() for t in topic0s}
        return [r for r in self.rows if str(r.topic0).lower() in wanted]

    def min_indexed_block(self, *, chain_id, event_address, topic0s):
        del chain_id, event_address, topic0s
        return 21_000_000


def _trees() -> dict:
    return json.loads((FIXTURES / "teller_predicate_trees.json").read_text())


def _members(cap: CapabilityExpr) -> set[str]:
    out: set[str] = set()
    for member in cap.members or []:
        out.add(member.lower())
    for child in cap.children or []:
        out |= _members(child)
    if cap.signer is not None:
        out |= _members(cap.signer)
    return out


def _trace_selectors(cap: CapabilityExpr) -> set[str]:
    """Every ``selector`` the Solmate adapter recorded it folded canCall against."""
    out: set[str] = set()
    for step in cap.trace or []:
        selector = step.get("selector") if isinstance(step, dict) else None
        if isinstance(selector, str):
            out.add(selector.lower())
    for child in cap.children or []:
        out |= _trace_selectors(child)
    if cap.signer is not None:
        out |= _trace_selectors(cap.signer)
    return out


def _resolve(tree_key: str, selector: str) -> CapabilityExpr:
    data = _trees()
    registry = AdapterRegistry()
    registry.register(SolmateRolesAuthorityAdapter)
    registry.register(EventIndexedAdapter)
    ctx = EvaluationContext(
        chain_id=1,
        contract_address=data["contract"],
        meta={"event_log_repo": FixtureRepo(_event_rows())},
        # authority resolved (RolesAuthority), owner renounced.
        state_var_values={"authority": "0x3994741a5b29c60d0ab318de1024f9256fe959dc", "owner": ZERO},
        call_frame=CallFrame.root(
            contract_address=data["contract"], function_signature=tree_key, function_selector=selector
        ),
    )
    return evaluate_tree_with_registry(data["trees"][tree_key], registry, ctx)


def _resolve_with_production_selector(tree_key: str) -> CapabilityExpr:
    """Like ``_resolve`` but derives the root-frame selector from the tree key
    the way ``resolve_contract_capabilities`` does in production —
    ``_selector_for_signature(full_name)`` — instead of being handed the
    canonical selector. The tree keys are Slither ``full_name`` signatures
    (``addAsset(ERC20)``), so this is the path that must canonicalize the
    contract-type param to ``address`` before the Solmate adapter folds canCall.
    """
    return _resolve(tree_key, _selector_for_signature(tree_key) or "")


def test_teller_pause_resolves_to_governing_safe_end_to_end():
    cap = _resolve("pause()", PAUSE)
    assert SAFE_4_6 in _members(cap), (
        f"expected 4/6 Safe in resolved callers, got kind={cap.kind} members={_members(cap)}"
    )


def test_teller_set_share_lock_period_is_not_attributed_to_safe():
    # No role capability for this selector + owner renounced => the Safe must
    # NOT be attributed as a caller (would be a false positive).
    cap = _resolve("setShareLockPeriod(uint64)", SET_SHARE_LOCK)
    assert SAFE_4_6 not in _members(cap)


def test_contract_type_param_function_folds_cancall_against_canonical_selector():
    # The tree is keyed ``addAsset(ERC20)`` (Slither full_name), but the EVM
    # selector — and every RoleCapabilityUpdated event — is canonical
    # ``addAsset(address)`` (0x298410e5). Driving the production selector path,
    # the adapter must fold canCall against the canonical selector, NOT the
    # non-canonical keccak("addAsset(ERC20)") (0x4fdd72aa). Folding the wrong
    # selector was a false-negative on every contract-type-param function.
    assert _selector_for_signature("addAsset(ERC20)") == ADD_ASSET_CANONICAL
    cap = _resolve_with_production_selector("addAsset(ERC20)")
    selectors = _trace_selectors(cap)
    assert ADD_ASSET_CANONICAL in selectors
    assert ADD_ASSET_NONCANONICAL not in selectors
    # role 8 grant in the fixture => the governing 4/6 Safe is the caller.
    assert SAFE_4_6 in _members(cap), (
        f"expected canonical-selector fold to recover the Safe, got kind={cap.kind} members={_members(cap)}"
    )
