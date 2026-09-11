"""PoC regression pins for the Veda RolesAuthority cold-start race.

When a Solmate ``requiresAuth`` function is resolved *before* its authority's role
events are durably indexed, ``SolmateRolesAuthorityAdapter`` fails closed to
``external_check_only`` tagged ``check.extra.deferred_pending_index`` — the marker
``deferred_reconciler`` keys on to re-resolve the function exactly once the index
catches up. The bug these tests pin: the ``external_set`` branch of the predicate
evaluator overwrote that tagged deferral with the inline cross-contract probe /
event-candidate materializer (a non-self-healing heuristic), dropping the marker. The
cold result then stuck forever — every Veda Teller/Accountant admin gate surfaced as a
``lower_bound`` live probe or a role-less ``external_check_only`` (→ OR, 0 principals)
and never converged even after the authority backfilled.

These drive the REAL adapter registry + REAL predicate evaluator + REAL reconciler
walker; only the event-log backend (the Postgres "wire") is replaced with an in-memory
cold/warm stub. No DB required, so they run in the offline suite.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
from eth_utils.crypto import keccak

from services.resolution.adapters import AdapterRegistry, CallFrame, EvaluationContext
from services.resolution.adapters.event_indexed import EventIndexedAdapter
from services.resolution.adapters.solmate_roles import _ROLE_TOPICS, SolmateRolesAuthorityAdapter
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.deferred_reconciler import DEFERRED_MARKER, _iter_deferred_authorities
from services.resolution.predicate_evaluator import evaluate_tree_with_registry
from services.static.static_analysis.predicate_types import PredicateTree

_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "solmate" / "veda_teller_stack.json"
_ZERO = "0x" + "0" * 40


def _sel(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


class _Row:
    """Minimal IndexedEventLog stand-in: the adapter reads ``.topics`` / ``.data_words``."""

    def __init__(self, topics: list[str], data_words: list[str]) -> None:
        self.topics = topics
        self.data_words = data_words


class _ColdRepo:
    """The authority's role events are NOT backfilled yet: no rows, no cursor. This is the
    state the first contract to reference a fresh RolesAuthority sees (resolution runs
    during the job; the index is populated after). The adapter must defer, not assert an
    empty/under-confident set."""

    def iter_event_rows(self, *, chain_id, event_address, topic0s, block=None):
        return []

    def min_indexed_block(self, *, chain_id, event_address, topic0s):
        return None  # no backfill_complete cursor → cold


class _WarmEmptyRepo:
    """Backfilled to head (cursor complete) but no role enables the (target, selector)
    under test — the genuine ``nobody`` answer. Used to prove the fix doesn't strand a
    real warm resolution as a deferral."""

    def __init__(self) -> None:
        user_role_topic = _ROLE_TOPICS[2]
        self._rows = [
            _Row(
                topics=[user_role_topic, "0x" + "0" * 24 + "ab" * 20, "0x" + format(1, "064x")],
                data_words=["0x" + "0" * 63 + "1"],
            )
        ]

    def iter_event_rows(self, *, chain_id, event_address, topic0s, block=None):
        return list(self._rows)

    def min_indexed_block(self, *, chain_id, event_address, topic0s):
        return 1000


class _PartialColdRepo:
    """Sub-state B of the cold-start race: SOME matching role rows are already indexed (so a
    fold finds members) but the authority's cursor is NOT yet ``backfill_complete``
    (``min_indexed_block`` is ``None``). The partial fold is not trustworthy as a final
    answer — more grants may be in the un-indexed tail — and, crucially, a bare
    ``lower_bound`` set here carries no self-heal marker, so it would freeze and never
    converge to the exact set once backfill completes. The adapter must DEFER instead."""

    def __init__(self, target: str, selector: str, holder: str) -> None:
        role_cap, _pub, user_role = _ROLE_TOPICS
        role_word = "0x" + format(7, "064x")
        target_word = "0x" + target[2:].rjust(64, "0")
        sig_word = "0x" + selector[2:] + "0" * 56
        user_word = "0x" + holder[2:].rjust(64, "0")
        true_word = "0x" + "0" * 63 + "1"
        self._rows = [
            _Row(topics=[role_cap, role_word, target_word, sig_word], data_words=[true_word]),
            _Row(topics=[user_role, user_word, role_word], data_words=[true_word]),
        ]

    def iter_event_rows(self, *, chain_id, event_address, topic0s, block=None):
        return list(self._rows)

    def min_indexed_block(self, *, chain_id, event_address, topic0s):
        return None  # cursor not backfill_complete yet → still cold despite the partial rows


class _BytecodeStub:
    """Confirms the authority is a Solmate RolesAuthority so ``matches()`` scores it at
    full confidence without touching the network."""

    def has_selector(self, *, chain_id, contract_address, selector):
        return True

    def declares_event(self, *, chain_id, contract_address, topic0):
        return False


def _registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    registry.register(SolmateRolesAuthorityAdapter)
    registry.register(EventIndexedAdapter)
    return registry


@pytest.fixture
def fixture() -> dict:
    return json.loads(_FIXTURE.read_text())


def _ctx(repo, fixture: dict) -> EvaluationContext:
    return EvaluationContext(
        chain_id=1,
        contract_address=fixture["teller_address"],
        block=None,
        event_log_repo=repo,
        bytecode=_BytecodeStub(),
        state_var_values={"authority": fixture["authority_address"], "owner": _ZERO},
        session=None,  # no cross-contract inline source seeded → exercises the fallback path
        call_frame=CallFrame.root(
            contract_address=fixture["teller_address"],
            function_signature="denyAll(address)",
            function_selector=_sel("denyAll(address)"),
        ),
    )


def _deny_all_tree(fixture: dict) -> PredicateTree:
    # Real prod snapshot of a Teller `requiresAuth` gate: OR[AND[authority!=0, canCall], owner].
    return cast(PredicateTree, fixture["teller_trees"]["trees"]["denyAll(address)"])


def test_cold_index_canCall_deferral_persists_marker(fixture):
    cap = evaluate_tree_with_registry(_deny_all_tree(fixture), _registry(), _ctx(_ColdRepo(), fixture))
    cap_dict = capability_to_dict(cap)
    deferred = set(_iter_deferred_authorities(cap_dict))

    assert fixture["authority_address"].lower() in deferred, (
        f"a cold-index canCall gate must keep its {DEFERRED_MARKER!r} marker so "
        f"deferred_reconciler re-resolves it once the authority backfills; the inline/"
        f"materializer overwrite dropped it. cap={json.dumps(cap_dict)[:800]}"
    )


def test_cold_index_gate_is_a_deferred_external_check_not_a_populated_set(fixture):
    # Post-fix shape pin: the cold gate must surface as a DEFERRED external_check_only (the
    # marker present), and it must mint ZERO concrete members. The deferred-marker assertion
    # is the load-bearing, fix-dependent half — pre-fix the inline/materializer overwrite
    # emits a plain external_check with no marker, so this fails. The no-members assertion is
    # the no-phantom/no-under-confident-set guard alongside it.
    cap = evaluate_tree_with_registry(_deny_all_tree(fixture), _registry(), _ctx(_ColdRepo(), fixture))
    cap_dict = capability_to_dict(cap)

    def _walk(node):
        yield node
        for child in node.get("children") or []:
            yield from _walk(child)

    deferred_checks = [
        n
        for n in _walk(cap_dict)
        if n.get("kind") == "external_check_only" and ((n.get("check") or {}).get("extra") or {}).get(DEFERRED_MARKER)
    ]
    members = [m for n in _walk(cap_dict) if n.get("kind") == "finite_set" for m in (n.get("members") or [])]

    assert deferred_checks, f"cold gate must be a DEFERRED external check; cap={json.dumps(cap_dict)[:800]}"
    assert not members, f"cold gate must mint no concrete members; cap={json.dumps(cap_dict)[:800]}"


def test_warm_resolution_does_not_spuriously_defer(fixture):
    # Guardrail: a warm authority with no matching role resolves to the exact `nobody`
    # set, NOT a deferral — the fix must only change the cold path.
    cap = evaluate_tree_with_registry(_deny_all_tree(fixture), _registry(), _ctx(_WarmEmptyRepo(), fixture))
    cap_dict = capability_to_dict(cap)

    assert not list(_iter_deferred_authorities(cap_dict)), (
        f"a warm resolution must not carry a {DEFERRED_MARKER!r} deferral; cap={json.dumps(cap_dict)[:800]}"
    )


def test_partial_cold_index_defers_instead_of_freezing_lower_bound(fixture):
    # Sub-state B: matching role rows are already indexed but the cursor is not yet
    # backfill_complete. The adapter must DEFER (a marked external_check_only that
    # deferred_reconciler re-resolves to the exact set once warm), NOT freeze the partial
    # fold as a markerless `lower_bound` finite_set that can never converge. Without the
    # adapter fix this returns `finite_set([holder], lower_bound)` — no marker, never
    # self-heals — so both assertions below fail.
    holder = "0x" + "cd" * 20
    selector = _sel("denyAll(address)")
    repo = _PartialColdRepo(fixture["teller_address"].lower(), selector, holder)
    cap = evaluate_tree_with_registry(_deny_all_tree(fixture), _registry(), _ctx(repo, fixture))
    cap_dict = capability_to_dict(cap)

    def _walk(node):
        yield node
        for child in node.get("children") or []:
            yield from _walk(child)

    assert fixture["authority_address"].lower() in set(_iter_deferred_authorities(cap_dict)), (
        f"a partial-cold gate must defer (marker present) so it self-heals to exact, not "
        f"freeze a lower_bound; cap={json.dumps(cap_dict)[:800]}"
    )
    members = [m.lower() for n in _walk(cap_dict) if n.get("kind") == "finite_set" for m in (n.get("members") or [])]
    assert holder.lower() not in members, (
        f"a partial-cold fold must not be surfaced as a frozen lower_bound member set; got {members}"
    )
