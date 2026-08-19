"""Standards-coverage matrix — the rigor invariant across authority standards.

Each contract is compiled and run through the REAL static→predicate→resolve
pipeline. The invariant this pins (what separates a faithful standard model from
"one more heuristic"): for every standard, resolution is either

  * CORRECT  — resolves to exactly the principal the contract's own authority
    designates (verified here against the ground-truth owner the getter returns,
    supplied via a stubbed RPC), or
  * FAIL-CLOSED — an honest ``external_check_only`` / empty result when the
    principal can't be enumerated without on-chain data (e.g. an event-indexed
    RolesAuthority/AccessControl with no indexed history, or an unmodeled custom
    authority),

and NEVER a confident-but-wrong ``finite_set`` (exact, non-empty, wrong members).

Member-value correctness for the event-indexed standards (Solmate/AccessControl)
against live data is pinned separately with real fixtures in
``test_solmate_end_to_end`` / ``test_adapter_solmate_roles``; here those standards
must *fail closed* without an event history rather than fabricate a set.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.resolution.adapters import (  # noqa: E402
    AdapterRegistry,
    CallFrame,
    EnumerationResult,  # noqa: E402
)
from services.resolution.adapters import EvaluationContext as ResolverContext  # noqa: E402
from services.resolution.adapters.event_indexed import EventIndexedAdapter  # noqa: E402
from services.resolution.adapters.solmate_roles import SolmateRolesAuthorityAdapter  # noqa: E402
from services.resolution.capabilities import CapabilityExpr  # noqa: E402
from services.resolution.predicate_evaluator import evaluate_tree_with_registry  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    apply_solmate_authority_hint_pass,
)
from services.static.contract_analysis_pipeline.predicate_types import PredicateTree  # noqa: E402
from services.static.contract_analysis_pipeline.predicates import build_predicate_tree  # noqa: E402
from services.static.contract_analysis_pipeline.reentrancy_pause import apply_reentrancy_pause_pass  # noqa: E402
from services.static.contract_analysis_pipeline.writer_gate import apply_writer_gate_pass  # noqa: E402

CONTRACT = "0x" + "11" * 20
OWNER = "0x" + "ab" * 20


def _trees(tmp_path: Path, source: str) -> dict:
    f = tmp_path / "C.sol"
    f.write_text(textwrap.dedent(source).strip() + "\n")
    contract = next(c for c in Slither(str(f)).contracts if c.name == "C")
    trees: dict[str, PredicateTree] = {}
    for fn in contract.functions:
        if fn.is_constructor:
            continue
        tree = build_predicate_tree(fn)
        if tree is not None:
            trees[fn.full_name] = tree
    apply_writer_gate_pass(contract, trees)
    apply_reentrancy_pause_pass(contract, trees)
    apply_solmate_authority_hint_pass(contract, trees)
    return trees


class _NoEventsRepo:
    """No indexed event history — event-enumerated standards must fail closed."""

    def iter_event_rows(self, **_: Any):
        return []

    def min_indexed_block(self, **_: Any):
        return None

    def fold_event_writes(self, **_: Any):
        return EnumerationResult(members=[], confidence="partial", partial_reason="no_index_cursor")

    def fold_event_history(self, **_: Any):
        return EnumerationResult(members=[], confidence="partial", partial_reason="no_index_cursor")


def _resolve(trees: dict, fn: str, monkeypatch, *, rpc_owner: str | None = None) -> CapabilityExpr:
    if rpc_owner is not None:

        def fake_rpc(rpc_url, method, params, retries: int = 1, **_: Any):  # noqa: ARG001
            # Any nullary authority getter (owner()/governor()/<var>()) returns
            # the ground-truth owner, left-padded to a 32-byte word.
            return "0x" + rpc_owner[2:].rjust(64, "0")

        monkeypatch.setattr("utils.rpc.rpc_request", fake_rpc)

    registry = AdapterRegistry()
    registry.register(SolmateRolesAuthorityAdapter)
    registry.register(EventIndexedAdapter)
    ctx = ResolverContext(
        chain_id=1,
        contract_address=CONTRACT,
        rpc_url="http://stub" if rpc_owner is not None else None,
        event_log_repo=_NoEventsRepo(),
        state_var_values={},  # force live getter reads (no persisted feed)
        call_frame=CallFrame.root(contract_address=CONTRACT, function_signature=fn, function_selector="0x12345678"),
    )
    return evaluate_tree_with_registry(trees[fn], registry, ctx)


def _members(cap: CapabilityExpr) -> set[str]:
    out: set[str] = set()
    for member in cap.members or []:
        out.add(member.lower())
    for child in cap.children or []:
        out |= _members(child)
    if cap.signer is not None:
        out |= _members(cap.signer)
    return out


def _has_confident_members(cap: CapabilityExpr) -> bool:
    """True iff some branch asserts an EXACT, non-empty member set — i.e. a
    confident claim about who can call. A lower_bound / external_check_only /
    empty set is NOT a confident claim."""
    if cap.kind == "finite_set":
        return bool(cap.members) and cap.membership_quality == "exact"
    return any(_has_confident_members(child) for child in cap.children or [])


# ---------------------------------------------------------------------------
# CORRECT: owner-style standards resolve to exactly the contract's owner.
# ---------------------------------------------------------------------------


def test_oz_v4_ownable_owner_getter_resolves_to_owner(tmp_path, monkeypatch):
    trees = _trees(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address private _owner;
            function owner() public view returns (address) { return _owner; }
            function f() external view { require(msg.sender == owner()); }
        }
        """,
    )
    cap = _resolve(trees, "f()", monkeypatch, rpc_owner=OWNER)
    assert _members(cap) == {OWNER.lower()}


def test_bare_owner_state_var_resolves_to_owner(tmp_path, monkeypatch):
    trees = _trees(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            function f() external view { require(msg.sender == ownerVar); }
        }
        """,
    )
    cap = _resolve(trees, "f()", monkeypatch, rpc_owner=OWNER)
    assert _members(cap) == {OWNER.lower()}


# ---------------------------------------------------------------------------
# FAIL-CLOSED: standards needing on-chain data we don't have here must NOT
# fabricate a confident set.
# ---------------------------------------------------------------------------


def test_solmate_requires_auth_without_events_fails_closed(tmp_path, monkeypatch):
    # Recognized as Solmate canCall, but with no indexed RolesAuthority events
    # it must fail closed — not claim an exact caller set.
    trees = _trees(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface Authority { function canCall(address user, address target, bytes4 sig) external view returns (bool); }
        contract C {
            Authority public authority;
            address public owner;
            modifier requiresAuth() {
                require(msg.sender == owner || authority.canCall(msg.sender, address(this), msg.sig));
                _;
            }
            function f() external requiresAuth {}
        }
        """,
    )
    cap = _resolve(trees, "f()", monkeypatch)  # no rpc owner, no events
    assert not _has_confident_members(cap)


def test_oz_accesscontrol_role_gate_without_events_fails_closed(tmp_path, monkeypatch):
    trees = _trees(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(bytes32 => mapping(address => bool)) private _roles;
            bytes32 public constant ADMIN = keccak256("ADMIN");
            function f() external view { require(_roles[ADMIN][msg.sender]); }
        }
        """,
    )
    cap = _resolve(trees, "f()", monkeypatch)
    assert not _has_confident_members(cap)


def test_unmodeled_custom_authority_fails_closed(tmp_path, monkeypatch):
    # A bespoke external authorization check we have no model for: must surface
    # as an honest external check, never a fabricated set.
    trees = _trees(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IGuard { function mayCall(address who) external view returns (bool); }
        contract C {
            IGuard public guard;
            function f() external view { require(guard.mayCall(msg.sender)); }
        }
        """,
    )
    cap = _resolve(trees, "f()", monkeypatch)
    assert not _has_confident_members(cap)


def test_unguarded_function_makes_no_controller_claim(tmp_path):
    # An unguarded public function has no authority gate: the static stage
    # extracts no predicate tree for it, so it can never be attributed a
    # (fabricated) controller set — the 'public' end of the spectrum.
    trees = _trees(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C { uint256 public x; function f() external { x = 1; } }
        """,
    )
    assert "f()" not in trees
