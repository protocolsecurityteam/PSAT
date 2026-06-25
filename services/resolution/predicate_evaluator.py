"""Predicate-tree evaluator — the bridge from static stage to resolver.

Takes a ``PredicateTree`` (from ``services.static.contract_analysis_pipeline.
predicates.build_predicate_tree``) and produces a ``CapabilityExpr``
describing the principal set / capability shape that gates the
function. Recursive: AND/OR nodes compose via the closed combinators
in ``capabilities.py``.

Per v6 round-5 #3 fix, dispatch order is:
  1. kind == "unsupported"           → CapabilityExpr.unsupported(reason)
  2. authority_role ∈ {reentrancy, pause, business, time} →
     conditional_universal (anyone, with the side condition)
  3. caller_authority / delegated_authority — dispatch on leaf kind:
     - membership   → adapter.enumerate(set_descriptor) → finite_set
     - equality     → resolve operand → finite_set([address])
     - external_bool→ external_check_only
     - signature_auth → signature_witness
     - comparison   → conditional_universal (caller-priority comparisons
                       are exotic; mostly time-gates, already handled)

Adapters are pluggable: the caller passes an ``AdapterRegistry`` (week 5
deliverable). Without adapters, membership leaves return finite_set with
quality=lower_bound and empty members — the structural skeleton is
correct, just unfilled.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import replace
from typing import Any, Protocol, cast

from eth_utils.crypto import keccak

from services.static.contract_analysis_pipeline.predicate_types import (
    LeafPredicate,
    PredicateTree,
    SetDescriptor,
)

from .capabilities import (
    CapabilityExpr,
    Condition,
    EmptyReason,
    ExternalCheck,
    intersect,
    negate,
    union,
)
from .permissionless_shapes import (
    caller_gate_basis,
    earned_public_enabled,
    is_caller_keyed_membership_allowlist,
    is_caller_keyed_time_allowlist,
    is_permissionless_caller_shape,
    leaf_is_caller_tainted,
)

_CALLER_SOURCES = {"msg_sender", "tx_origin", "signature_recovery", "root_caller"}


def _bump_resolve_counter(outer_ctx: Any, key: str, n: int = 1) -> None:
    """Increment a resolve-level work-volume counter on the outer
    EvaluationContext's ``meta['resolve_counters']`` (wired by the capability
    resolver). No-op when absent, so unit evaluations and the pure-week-4 path
    are untouched. Surfaces redundant work (live getter eth_calls, cross-contract
    inline recursions, HyperSync fallback scans) on the per-job
    ``capability_summary`` without per-RPC latency noise."""
    meta = getattr(outer_ctx, "meta", None)
    if not isinstance(meta, dict):
        return
    counters = meta.get("resolve_counters")
    if isinstance(counters, dict):
        counters[key] = counters.get(key, 0) + n


def _pass_live_read_memo(outer_ctx: Any) -> dict[Any, Any] | None:
    """The contract-scoped ``meta['live_read_memo']`` (wired by the capability resolver), or None when absent
    — leaving unit evaluations and the pure-week-4 path un-memoized. Scoped to the contract's resolution
    frame, so it is discarded when the pass ends; never a cross-run/persistent cache."""
    meta = getattr(outer_ctx, "meta", None)
    if not isinstance(meta, dict):
        return None
    memo = meta.get("live_read_memo")
    return memo if isinstance(memo, dict) else None


def _frame_is_inlined(ctx: "EvaluationContext") -> bool:
    """True when we're resolving inside an inlined cross-contract call — the frame's
    ``msg.sender`` has been bound to a concrete intermediate contract (the caller of
    the downstream call), so a caller-authorization leaf evaluated here constrains
    that intermediate, NOT the function's end-user caller. ``CallFrame.root`` leaves
    ``current_msg_sender`` None (symbolic root caller)."""
    frame = getattr(ctx, "call_frame", None)
    return frame is not None and getattr(frame, "current_msg_sender", None) is not None


def _tag_caller_subject(cap: "CapabilityExpr", ctx: "EvaluationContext") -> "CapabilityExpr":
    """Mark a freshly-resolved caller-authorization capability with the dimension it
    constrains: ``bound`` inside an inlined downstream call (subject = the frame-bound
    intermediate contract), else ``root`` (the end-user caller). The combinators in
    ``capabilities.py`` use this to keep a bound check as a side-condition rather than
    set-intersecting it into the end-user principal set (which would zero it)."""
    cap.subject = "bound" if _frame_is_inlined(ctx) else "root"
    return cap


def _adapter_declined_external_set(cap: "CapabilityExpr") -> bool:
    """True when an ``external_set`` adapter produced no concrete answer — unsupported,
    a query-only external check, or the empty non-exact placeholder of the null adapter.
    An *exact* empty set is a real ``nobody`` and is NOT a decline."""
    return cap.kind in {"unsupported", "external_check_only"} or (
        cap.kind == "finite_set" and not cap.members and cap.membership_quality != "exact"
    )


def _adapter_deferred_pending_index(cap: "CapabilityExpr") -> bool:
    """True when an adapter's decline is a *cold durable-index* deferral it has tagged
    for self-heal (``check.extra.deferred_pending_index``): the authority's events
    aren't backfilled yet, so the exact caller set becomes recoverable once they are.

    Distinct from a settled decline (``unsupported`` / a warm authority that emitted no
    role events). ``deferred_reconciler`` re-enqueues the owning job's policy stage once
    the cursor reaches head — but ONLY if this marker survives into the persisted
    ``capability_expr``. So the external_set path must preserve such a deferral verbatim
    and NOT overwrite it with the inline cross-contract probe / event-candidate
    materializer: that live probe is a non-self-healing heuristic that drops the marker
    and freezes the cold result (the Veda RolesAuthority cold-start race)."""
    return (
        cap.kind == "external_check_only"
        and cap.check is not None
        and bool((cap.check.extra or {}).get("deferred_pending_index"))
    )


def _state_var_lookup_key(operand: dict[str, Any]) -> str | None:
    name = operand.get("state_variable_name")
    if not isinstance(name, str) or not name:
        return None
    member_path = operand.get("member_path")
    if isinstance(member_path, list) and member_path:
        parts = [part for part in member_path if isinstance(part, str) and part]
        if parts:
            return ".".join([name, *parts])
    return name


# ---------------------------------------------------------------------------
# Adapter protocol (placeholder — week-5 fully-typed registry replaces this)
# ---------------------------------------------------------------------------


class SetAdapter(Protocol):
    """Minimal adapter interface for week-4. The full SetAdapter
    Protocol (with EvaluationContext, matches/enumerate/membership)
    lands in week 5 alongside concrete adapters."""

    def enumerate(self, descriptor: SetDescriptor, contract_address: str | None) -> CapabilityExpr: ...


class _NullAdapter:
    """Fallback when no real adapter is registered. Returns
    finite_set(empty, lower_bound) — the structural skeleton without
    a populated members list."""

    def enumerate(self, descriptor: SetDescriptor, contract_address: str | None) -> CapabilityExpr:
        return CapabilityExpr.finite_set(
            [],
            quality="lower_bound",
            confidence="partial",
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class EvaluationContext:
    """Resolver-side context for the simple (week-4) evaluator path.

    The full week-5 ``EvaluationContext`` lives in
    ``services.resolution.adapters`` and carries chain/RPC/repos.
    Use ``evaluate_tree_with_registry`` to dispatch via that fuller
    context.
    """

    def __init__(
        self,
        *,
        contract_address: str | None = None,
        adapter: SetAdapter | None = None,
        block: int | None = None,
        state_var_values: dict[str, str] | None = None,
        call_frame: Any = None,
    ) -> None:
        self.contract_address = contract_address
        self.adapter: SetAdapter = adapter or _NullAdapter()
        self.block = block
        # Persisted state-variable values keyed by storage-var name.
        # Used by ``_resolve_equality_principal`` to enumerate state-variable
        # authority values into concrete addresses.
        self.state_var_values = state_var_values or {}
        self.call_frame = call_frame


def evaluate_tree_with_registry(
    tree: PredicateTree | None,
    registry: Any,  # adapters.AdapterRegistry — typed loosely to avoid circular import
    ctx: Any,  # adapters.EvaluationContext
) -> CapabilityExpr:
    """Like ``evaluate_tree`` but routes membership leaves through the
    week-5 AdapterRegistry. The registry's ``enumerate(descriptor,
    ctx)`` returns a CapabilityExpr that may be a populated
    finite_set, threshold_group, external_check_only, or
    unsupported(no_adapter)."""

    class _RegistryBackedAdapter:
        # ``_outer_ctx`` exposes the full resolver ctx (session, event logs,
        # state_var_values, evaluation_stack, …) to leaf evaluators that
        # need cross-contract inlining. ``_registry`` is the AdapterRegistry
        # the recursive ``evaluate_tree_with_registry`` re-uses when it
        # spawns a child ctx for B's tree.
        _outer_ctx = ctx
        _registry = registry

        def enumerate(self, descriptor, contract_address):  # noqa: ARG002
            return registry.enumerate(descriptor, ctx)

    eval_ctx = EvaluationContext(
        contract_address=getattr(ctx, "contract_address", None),
        adapter=_RegistryBackedAdapter(),
        block=getattr(ctx, "block", None),
        state_var_values=getattr(ctx, "state_var_values", None),
        call_frame=getattr(ctx, "call_frame", None),
    )
    return evaluate_tree(tree, eval_ctx)


def evaluate_tree(
    tree: PredicateTree | None,
    ctx: EvaluationContext | None = None,
) -> CapabilityExpr:
    """Walk a PredicateTree and return its CapabilityExpr.

    None or empty tree → conditional_universal with no conditions
    (i.e., 'public' / no gating).

    AND / OR nodes recurse via closed combinators.

    LEAF nodes dispatch per the v6 order: unsupported first, then
    side-condition roles, then caller/delegated auth.
    """
    if ctx is None:
        ctx = EvaluationContext()
    if tree is None:
        return CapabilityExpr.conditional_universal(
            Condition(kind="business", description="no gating"),
        )
    op = tree.get("op")
    if op == "LEAF":
        leaf = tree.get("leaf")
        if leaf is None:
            return CapabilityExpr.unsupported("empty_leaf")
        return _evaluate_leaf(leaf, ctx)
    children = tree.get("children") or []
    if not children:
        return CapabilityExpr.unsupported("empty_branch")
    evaluated = []
    for child in children:
        side_condition = _side_condition_capability(child) if op == "AND" and len(children) > 1 else None
        evaluated.append(side_condition or evaluate_tree(child, ctx))
    if op == "AND":
        result = evaluated[0]
        for child in evaluated[1:]:
            result = intersect(result, child)
        return result
    if op == "OR":
        result = evaluated[0]
        for child in evaluated[1:]:
            result = union(result, child)
        return result
    return CapabilityExpr.unsupported(f"unknown_op_{op}")


# ---------------------------------------------------------------------------
# Per-leaf dispatch
# ---------------------------------------------------------------------------


def _has_caller_keyed_value_predicate(leaf: LeafPredicate) -> bool:
    """True iff ``leaf.set_descriptor`` carries a ``value_predicate``
    AND at least one ``key_sources`` entry is ``msg_sender`` (i.e. the
    threshold is keyed on the caller). Used to upgrade
    ``business``-flavored thresholds (PR D.1+) into finite-set
    enumerations when the adapter chain has data, while still letting
    pure-business thresholds (``amount > 1000``) fall through to
    ``conditional_universal``.
    """
    descriptor = leaf.get("set_descriptor") or {}
    if not descriptor.get("value_predicate"):
        return False
    keys = descriptor.get("key_sources") or []
    return any(k.get("source") in _CALLER_SOURCES for k in keys)


# The E3/E4 allowlist discriminators now live in ``permissionless_shapes``
# (the caller-taint default subsumes them); these module-level aliases keep
# the legacy (flag-off) call sites monkeypatchable under their historic names.
_is_caller_keyed_time_allowlist = is_caller_keyed_time_allowlist
_is_caller_keyed_membership_allowlist = is_caller_keyed_membership_allowlist


def _is_opaque_bool_return_predicate(leaf: LeafPredicate) -> bool:
    basis = leaf.get("basis") or []
    if "bool-return predicate" not in basis:
        return False
    if leaf.get("set_descriptor"):
        return False
    if leaf.get("kind") != "equality":
        return False
    return any((op or {}).get("source") in {"computed", "external_call", "top"} for op in leaf.get("operands") or [])


def _evaluate_leaf(leaf: LeafPredicate, ctx: EvaluationContext) -> CapabilityExpr:
    # 0. unsupported is structural — check first (round-5 #3 fix).
    if leaf.get("kind") == "unsupported":
        return CapabilityExpr.unsupported(leaf.get("unsupported_reason") or "unsupported")

    # 1. Non-authority leaves go to side-conditions — UNLESS the
    # descriptor carries a caller-keyed value_predicate (PR D.1+).
    # ``balances[msg.sender] < 10 revert`` is structurally a business
    # threshold but operationally an authority gate over the set of
    # callers whose latest mapping value satisfies the predicate.
    # When the adapter chain has data (durable indexer / on-demand
    # event replay / trace replay) we get a concrete finite_set;
    # otherwise the fallback path produces conditional_universal.
    role = leaf.get("authority_role")
    if role in ("reentrancy", "pause", "business", "time", "one_shot"):
        if _is_opaque_bool_return_predicate(leaf):
            return CapabilityExpr.external_check_only(
                ExternalCheck(
                    target_address=None,
                    target_call_selector=None,
                    extra={
                        "basis": ["opaque_bool_return_predicate"],
                        "expression": leaf.get("expression"),
                    },
                )
            )
        if _has_caller_keyed_value_predicate(leaf):
            descriptor = leaf.get("set_descriptor")
            if descriptor is not None:
                cap = ctx.adapter.enumerate(descriptor, ctx.contract_address)
                # Only return the enumerated capability when it has
                # at least one concrete member. Anything else
                # (``external_check_only``, ``unsupported``, empty
                # ``finite_set`` regardless of quality) means "no
                # useful data" — and a side-condition leaf's
                # description is more informative than an empty
                # principal list. Codex review #3 caught the
                # ``finite_set([], exact)`` case where a genuinely-
                # business predicate could silently lose its
                # description; gating on ``cap.members`` fixes it.
                if cap.kind == "finite_set" and cap.members:
                    return cap
        if earned_public_enabled():
            # The caller-taint default: a gate that discriminates on the caller's
            # identity and matches no known permissionless shape is an
            # authorization whose principals we couldn't enumerate — fail CLOSED
            # (gated, principals unknown), never ``conditional_universal``/public.
            # Permissionless shapes (denylist/claim-once polarity, quantity
            # thresholds, self-service equality, effectful value-movement calls)
            # deliberately fall through to open. Subsumes the legacy E3/E4 arms
            # below.
            if leaf_is_caller_tainted(leaf) and not is_permissionless_caller_shape(leaf):
                return CapabilityExpr.external_check_only(
                    ExternalCheck(
                        target_address=None,
                        target_call_selector=None,
                        extra={
                            "basis": [caller_gate_basis(leaf)],
                            "expression": leaf.get("expression"),
                        },
                    )
                )
        elif _is_caller_keyed_time_allowlist(leaf):
            # A deny-by-default caller-keyed time allowlist authorizes a caller SET (only
            # the pre-approved, until expiry) — keep it a gated query-only check, never
            # ``conditional_universal``/public. The share-lock and balance/allowance
            # conditions deliberately fall through to open (see the helper).
            return CapabilityExpr.external_check_only(
                ExternalCheck(
                    target_address=None,
                    target_call_selector=None,
                    extra={
                        "basis": ["caller_keyed_time_allowlist"],
                        "expression": leaf.get("expression"),
                    },
                )
            )
        elif _is_caller_keyed_membership_allowlist(leaf):
            # ``require(allowed[msg.sender])`` — a positive caller allowlist. Only
            # recorded addresses pass, so it's a gated external check, never the
            # ``conditional_universal``/public a side-condition would emit. The
            # denylist/claim-once (``falsy``) sibling deliberately falls through to
            # open below. Mirrors the time-allowlist arm above.
            return CapabilityExpr.external_check_only(
                ExternalCheck(
                    target_address=None,
                    target_call_selector=None,
                    extra={
                        "basis": ["caller_keyed_membership_allowlist"],
                        "expression": leaf.get("expression"),
                    },
                )
            )
        cond = _condition_from_leaf(leaf)
        return CapabilityExpr.conditional_universal(cond)

    # 2. caller_authority / delegated_authority — dispatch on kind.
    kind = leaf.get("kind")
    operator = leaf.get("operator")

    if kind == "membership":
        descriptor = leaf.get("set_descriptor")
        if descriptor is None:
            return CapabilityExpr.unsupported("membership_without_descriptor")
        cap = _resolve_view_key_membership(descriptor, ctx)
        if cap is None:
            cap = ctx.adapter.enumerate(descriptor, ctx.contract_address)
        cap = _tag_caller_subject(cap, ctx)
        if operator == "falsy":
            # A falsy membership leaf is an exclusion gate (``if (set[caller]) revert``).
            # When the set can't be enumerated, normalize that decline to an external
            # check so the negate below reaches its cofinite arm and the denylist
            # resolves to "anyone except an un-enumerated exclusion", rather than being
            # discarded as ``negate_of_no_adapter``. See the helper.
            cap = _normalize_membership_decline_for_negation(cap, leaf, descriptor, ctx)
            cap = negate(cap)
        return cap

    if kind == "equality":
        if operator in ("eq", "ne"):
            # Tag equality the same way membership/external_bool are, so the subject
            # propagates through an inlined callee's predicate tree. A Solmate function
            # is OR[canCall(...), msg.sender == owner]; inside an inlined frame the
            # owner-equality goes through _resolve_contextual_equality (msg.sender is
            # frame-rewritten, so it has no caller operand). Without a bound tag here,
            # the OR can't collapse to a single bound capability — the OR container
            # defaults to root, the cross-subject intersect never fires, and the inner
            # (intermediate-dimension) members leak to the surface as a competing
            # principal shape, re-dropping the real callers via and_multiple_principal_shapes.
            if not _leaf_has_caller_operand(leaf):
                return _tag_caller_subject(_resolve_contextual_equality(leaf, ctx, operator), ctx)
            base = _tag_caller_subject(_resolve_equality_principal(leaf, ctx), ctx)
            return base if operator == "eq" else negate(base)
        return CapabilityExpr.unsupported(f"equality_op_{operator}_unsupported")

    if kind == "external_bool":
        if (
            earned_public_enabled()
            and operator == "truthy"
            and leaf.get("callee_state_mutability") == "nonview"
            and leaf_is_caller_tainted(leaf)
            and is_permissionless_caller_shape(leaf)
        ):
            # Value movement (§2.3): an effectful EXTERNAL call required to
            # succeed — ``require(token.transfer(msg.sender, …))`` — moves
            # the caller's own assets; any caller moves their own. The
            # delegated_authority classification (state-var target + caller
            # arg) is structural noise here: real external ACLs are
            # view/pure. Effectful LIBRARY calls (own-storage membership
            # consume) and void merkle-witness verifications keep the gated
            # path — see is_permissionless_caller_shape; they fall through
            # to the external_set descriptor/adapter resolution below.
            if _is_permit_family_signature(leaf.get("callee_signature")):
                # The void EIP-2612/3009 statement call: still an open
                # self-auth path, but typed as a permit so the badge can say
                # "open via signature" instead of a bare self-service open.
                return CapabilityExpr.conditional_universal(
                    Condition(
                        kind="permit_sig",
                        description=f"signature authorization (permit family): {leaf.get('expression') or 'call'}",
                    )
                )
            return CapabilityExpr.conditional_universal(
                Condition(
                    kind="self_service",
                    description=f"effectful external call must succeed: {leaf.get('expression') or 'call'}",
                )
            )
        descriptor = leaf.get("set_descriptor")
        if descriptor is not None:
            if descriptor.get("kind") == "external_set":
                # Prefer a confirmed standard-aware adapter (e.g. the Solmate
                # RolesAuthority adapter resolves canCall from indexed role events:
                # a *public* capability => anyone, else the exact role-holder set)
                # over the generic cross-contract inline + probe-materializer. The
                # materializer mis-renders a public capability as an enumerated list
                # and can admit phantom event-word candidates as principals — so
                # consulting it before the standard-aware adapter produced false
                # callers for every Veda Teller. Only when the adapter declines do we
                # inline the cross-contract call, then fall back to a bare external
                # check. The adapter's own confidence gating means a decline
                # (external_check_only / unsupported / non-exact-empty) is exactly
                # "no standard-aware answer", so this never special-cases by name.
                cap = ctx.adapter.enumerate(descriptor, ctx.contract_address)
                if _adapter_declined_external_set(cap):
                    if _adapter_deferred_pending_index(cap):
                        # Cold durable index: keep the adapter's tagged deferral so
                        # ``deferred_reconciler`` re-resolves this function *exactly* once
                        # the authority's events backfill. Falling through to the inline
                        # probe / event-candidate materializer would drop the
                        # ``deferred_pending_index`` marker and freeze a cold result
                        # (a lower_bound live probe, or a bare external check that masks a
                        # role-less owner-renounced gate) that never self-heals — the Veda
                        # RolesAuthority cold-start race.
                        cap = _tag_caller_subject(cap, ctx)
                    else:
                        inlined = _maybe_inline_cross_contract_call(leaf, descriptor, ctx)
                        if inlined is not None:
                            # The inline result carries its own subject — ``bound`` when the
                            # inlined downstream call's auth keyed on the frame-bound
                            # intermediate caller (so it stays a side-condition, not a caller
                            # set). Do NOT re-tag against the (root) outer frame.
                            cap = inlined
                        else:
                            cap = _tag_caller_subject(_external_check_from_descriptor(leaf, descriptor, ctx), ctx)
                else:
                    cap = _tag_caller_subject(cap, ctx)
            else:
                # Non-external_set: no standard adapter to prefer, keep inline-first.
                inlined = _maybe_inline_cross_contract_call(leaf, descriptor, ctx)
                if inlined is not None:
                    cap = inlined
                else:
                    cap = ctx.adapter.enumerate(descriptor, ctx.contract_address)
                    if cap.kind == "unsupported" and cap.unsupported_reason == "no_adapter":
                        cap = _external_check_from_descriptor(leaf, descriptor, ctx)
                    cap = _tag_caller_subject(cap, ctx)
            # An unresolved check that IS a caller gate (requiresAuth/ACL
            # declines) gets the caller-gate basis tag here, where the leaf
            # is known — the projection blocker keys on it. Inlined results
            # and enumerations pass through untouched (kind guard).
            cap = _stamp_caller_gate_check(cap, leaf)
            if operator == "falsy":
                cap = negate(cap)
            return cap
        return _resolve_external_bool(leaf, ctx)

    if kind == "signature_auth":
        signer = _resolve_signer_from_leaf(leaf, ctx)
        return CapabilityExpr.signature_witness(signer)

    if kind == "comparison":
        # Caller-authority comparisons are exotic; legacy treats them as
        # conditional (public). Under the caller-taint default, the only
        # comparison shape that is an authorization is the deny-by-default
        # time allowlist — quantity thresholds stay permissionless.
        if earned_public_enabled() and leaf_is_caller_tainted(leaf) and not is_permissionless_caller_shape(leaf):
            return CapabilityExpr.external_check_only(
                ExternalCheck(
                    target_address=None,
                    target_call_selector=None,
                    extra={
                        "basis": [caller_gate_basis(leaf)],
                        "expression": leaf.get("expression"),
                    },
                )
            )
        cond = _condition_from_leaf(leaf)
        return CapabilityExpr.conditional_universal(cond)

    return CapabilityExpr.unsupported(f"unknown_leaf_kind_{kind}")


def _side_condition_capability(tree: PredicateTree) -> CapabilityExpr | None:
    conditions = _side_conditions_from_tree(tree)
    if conditions is None:
        return None
    return CapabilityExpr(
        kind="conditional_universal",
        conditions=conditions,
        confidence="enumerable",
    )


def _side_conditions_from_tree(tree: PredicateTree) -> list[Condition] | None:
    op = tree.get("op")
    if op == "LEAF":
        leaf = tree.get("leaf")
        if not isinstance(leaf, dict):
            return None
        role = leaf.get("authority_role")
        if role in ("reentrancy", "pause", "business", "time", "one_shot") and not leaf.get("references_msg_sender"):
            return [_condition_from_leaf(cast(LeafPredicate, leaf))]
        return None

    children = tree.get("children") or []
    if not children:
        return None

    branch_conditions: list[list[Condition]] = []
    for child in children:
        child_conditions = _side_conditions_from_tree(child)
        if child_conditions is None:
            return None
        branch_conditions.append(child_conditions)

    if op == "AND":
        return [condition for group in branch_conditions for condition in group]
    if op == "OR":
        descriptions = [_condition_group_description(group) for group in branch_conditions]
        description = " OR ".join(description for description in descriptions if description)
        return [Condition(kind="business", description=description or "non-caller side condition")]
    return None


def _condition_group_description(conditions: list[Condition]) -> str:
    descriptions = [condition.description for condition in conditions if condition.description]
    if not descriptions:
        return ""
    if len(descriptions) == 1:
        return descriptions[0]
    return " AND ".join(f"({description})" for description in descriptions)


# ---------------------------------------------------------------------------
# Operand resolution helpers
# ---------------------------------------------------------------------------


def _nullary_getter_selector(name: str | None) -> str | None:
    """4-byte selector for ``<name>()`` — the auto-getter of a public state
    variable. ``None`` for an empty name."""
    if not isinstance(name, str) or not name:
        return None
    return _selector_for_signature(f"{name}()")


# Canonical public authority view-getters. A caller-equality gate may read the
# authority through a non-canonical accessor — an internal helper (``_governor()``),
# an explicit storage-slot constant (Solady ``_OWNER_SLOT``, OZ-v5
# ``OwnableStorageLocation``), or an ERC-7201 namespaced struct member — none of
# which is itself a readable public getter (reading ``_governor()`` /
# ``_OWNER_SLOT()`` reverts). Every such standard still exposes the SAME canonical
# public view getter, which reads the same storage, so we read that live instead.
# OZ v4 keeps a plain ``_owner`` state var and OZ v5 keeps it in a namespaced
# storage struct, but both expose ``owner()`` identically.
_OWNER_SELECTOR = "0x8da5cb5b"  # owner()
_GOVERNOR_SELECTOR = "0x0c340a24"  # governor()
_AUTHORITY_SELECTOR = "0xbf7e214f"  # authority()

# Burn sentinel: ownership renounced to a dead address (e.g. Solady TopUp, whose
# owner is 0x…dEaD). A gate against it has no live controller — treat it like the
# zero address rather than minting 0x…dEaD as a phantom principal everywhere.
_BURN_ADDRESS = "0x" + "00" * 18 + "dead"

# Keyword → canonical getter, for slot-constant authority operands. Matched as a
# substring of the (lowercased) slot-constant name, which must itself be a
# storage-layout locator (``_is_storage_layout_constant`` — a ``*_slot`` /
# ``*StorageLocation`` suffix): ``_OWNER_SLOT`` → owner(); OZ-v5
# ``OwnableStorageLocation`` → owner() (note "ownable", not "owner");
# ``_GOVERNOR_SLOT`` / ``GovernorStorageLocation`` → governor();
# ``_AUTHORITY_SLOT`` / ``AuthorityStorageLocation`` → authority(). governor /
# authority are checked before owner so a name carrying both resolves to the
# more specific one.
_SLOT_KEYWORD_TO_GETTER = (
    ("governor", _GOVERNOR_SELECTOR),
    ("authority", _AUTHORITY_SELECTOR),
    ("ownable", _OWNER_SELECTOR),
    ("owner", _OWNER_SELECTOR),
)

# Public authority view-getter base names (optionally ``pending``-prefixed). The
# internal-accessor fallback de-underscores ``_x()`` → ``x()`` only when ``x`` is
# one of these; an arbitrary ``_x()`` is left fail-closed, because resolving it to
# whatever public ``x()`` returns would risk a *wrong* controller — worse than a
# missing one for this tool.
_AUTHORITY_GETTER_BASENAMES = frozenset({"owner", "governor", "authority"})


def _live_authority_result(result_addr: str, selector: str, contract: str) -> CapabilityExpr:
    """Build the finite_set a successful live authority read yields — identical whether the address came from
    a fresh eth_call or the pass memo. ``""`` (zero / renounced) → empty exact set; an address → singleton,
    matching the original inline construction (including the trace for the non-empty case)."""
    if not result_addr:
        return CapabilityExpr.finite_set([], quality="exact", confidence="enumerable")
    return CapabilityExpr.finite_set(
        [result_addr],
        quality="exact",
        confidence="enumerable",
        trace=[{"step": "live_getter_resolution", "selector": selector, "contract": contract.lower()}],
    )


def _live_resolve_authority(ctx: EvaluationContext | None, selector: str | None) -> CapabilityExpr | None:
    """Resolve ``msg.sender == X`` by reading ``X`` live when the static
    ``state_var_values`` feed didn't carry it.

    ``msg.sender == owner()`` / ``== governor()`` / ``== <stateVar>`` names a
    single authorized caller; the persisted ``ControllerValue`` feed is the
    only thing :func:`_resolve_equality_principal` consults, so an
    owner()/governor()-gated function whose value was never captured (or was
    captured under a different key) dropped every principal. This reads the
    getter on the contract under analysis and materializes the result.

    Returns ``finite_set([addr], exact)`` for a concrete non-zero address,
    ``finite_set([], exact)`` when the getter returns the zero address
    (genuinely unset / renounced), a labeled ``finite_set([], lower_bound)``
    when a read was *attempted but unreadable* (``unreadable_revert`` on a
    revert, ``unreadable_empty`` on an empty / no-code return), or ``None`` when
    nothing was attempted — no RPC reachable through the outer context, a
    malformed selector, or an unusable contract address. The labeled-empty vs
    ``None`` split lets the caller fall through to a fallback getter (a revert is
    not a final answer) yet still record *why* the final placeholder is empty.
    Gating on a reachable ``rpc_url`` keeps pure-unit evaluations (no RPC) on
    their existing empty-placeholder behaviour."""
    if ctx is None or not isinstance(selector, str) or not selector.startswith("0x") or len(selector) != 10:
        return None
    outer = getattr(getattr(ctx, "adapter", None), "_outer_ctx", None)
    rpc_url = getattr(outer, "rpc_url", None)
    contract = getattr(outer, "contract_address", None) or ctx.contract_address
    block = getattr(outer, "block", None) if outer is not None else ctx.block
    if not isinstance(rpc_url, str) or not rpc_url:
        return None
    if not isinstance(contract, str) or not contract.startswith("0x") or len(contract) != 42:
        return None
    # Pass-scoped dedup: owner()/governor()/<stateVar>() reads are deterministic at a fixed block, so N
    # functions gating on the same getter need ONE read, not N. Only SUCCESSFUL reads are memoized — a revert
    # or transient RPC error is never cached, so each gated function still reads/retries independently (no
    # poisoning). Result is byte-identical to the un-memoized path.
    memo = _pass_live_read_memo(outer)
    block_repr = block if isinstance(block, int) else "latest"
    memo_key = ("live_authority", rpc_url, contract.lower(), selector, block_repr)
    if memo is not None and memo_key in memo:
        _bump_resolve_counter(outer, "live_getter_memo_hits")
        return _live_authority_result(memo[memo_key], selector, contract)

    _bump_resolve_counter(outer, "live_getter_calls")
    try:
        from utils.rpc import rpc_request

        raw = rpc_request(
            rpc_url,
            "eth_call",
            [{"to": contract.lower(), "data": selector}, hex(block) if isinstance(block, int) else "latest"],
            retries=1,
        )
    except Exception:
        _bump_resolve_counter(outer, "live_getter_failures")
        return CapabilityExpr.finite_set(
            [], quality="lower_bound", confidence="partial", empty_reason="unreadable_revert"
        )
    if not isinstance(raw, str) or not raw.startswith("0x") or len(raw) < 66:
        return CapabilityExpr.finite_set(
            [], quality="lower_bound", confidence="partial", empty_reason="unreadable_empty"
        )
    addr = "0x" + raw[-40:].lower()
    result_addr = "" if (_is_zero_address(addr) or addr == _BURN_ADDRESS) else addr
    if memo is not None:
        memo[memo_key] = result_addr
    return _live_authority_result(result_addr, selector, contract)


def _live_resolve_authority_slot(
    ctx: EvaluationContext | None,
    slot: str | None,
    *,
    zero_empty_reason: EmptyReason | None = "empty_by_design",
) -> CapabilityExpr | None:
    """Resolve ``msg.sender == <getter-less slot reader>`` by reading the raw
    storage slot live.

    Two getter-less authority shapes use this. (1) An internal accessor that
    ``sload``s a *constant* slot (Governable ``_pendingGovernor`` reads
    ``keccak256("LRTSquare.pending.governor")``) — a ``view_call`` operand. (2) A
    *named* address state var declared without ``public`` (ether.fi
    ``MembershipNFT.membershipManager``) — a ``state_variable`` operand whose slot
    is its sequential layout position. In both the static stage attaches the slot
    and this reads it with ``eth_getStorageAt`` against the runtime address — the
    proxy when the job is proxy-linked, so the *live* value is seen rather than a
    standalone impl's empty storage.

    Mirrors :func:`_live_resolve_authority`'s contract: ``finite_set([addr],
    exact)`` for a non-zero slot, ``finite_set([], exact)`` for a confirmed-zero
    slot, a labeled ``lower_bound`` when the read was attempted but unreadable, or
    ``None`` when nothing could be attempted. ``zero_empty_reason`` labels the
    confirmed-zero outcome: ``empty_by_design`` for a pending-transfer accept gate
    (a read-confirmed ceiling — no transfer queued), ``None`` for a plain
    authority var that simply reads zero (renounced/unset, like
    :func:`_live_resolve_authority`'s clean-zero)."""
    if ctx is None or not isinstance(slot, str) or not slot.startswith("0x") or len(slot) != 66:
        return None
    outer = getattr(getattr(ctx, "adapter", None), "_outer_ctx", None)
    rpc_url = getattr(outer, "rpc_url", None)
    contract = getattr(outer, "contract_address", None) or ctx.contract_address
    block = getattr(outer, "block", None) if outer is not None else ctx.block
    if not isinstance(rpc_url, str) or not rpc_url:
        return None
    if not isinstance(contract, str) or not contract.startswith("0x") or len(contract) != 42:
        return None
    _bump_resolve_counter(outer, "live_slot_calls")
    try:
        from utils.rpc import rpc_request

        raw = rpc_request(
            rpc_url,
            "eth_getStorageAt",
            [contract.lower(), slot, hex(block) if isinstance(block, int) else "latest"],
            retries=1,
        )
    except Exception:
        _bump_resolve_counter(outer, "live_slot_failures")
        return CapabilityExpr.finite_set(
            [], quality="lower_bound", confidence="partial", empty_reason="unreadable_revert"
        )
    if not isinstance(raw, str) or not raw.startswith("0x") or len(raw) < 66:
        return CapabilityExpr.finite_set(
            [], quality="lower_bound", confidence="partial", empty_reason="unreadable_empty"
        )
    addr = "0x" + raw[-40:].lower()
    if _is_zero_address(addr) or addr == _BURN_ADDRESS:
        return CapabilityExpr.finite_set([], quality="exact", confidence="enumerable", empty_reason=zero_empty_reason)
    return CapabilityExpr.finite_set(
        [addr],
        quality="exact",
        confidence="enumerable",
        trace=[{"step": "live_slot_resolution", "slot": slot, "contract": contract.lower()}],
    )


def _resolve_authority_via_getters(ctx: EvaluationContext | None, selectors: list[str | None]) -> CapabilityExpr | None:
    """Read an authority through the first of ``selectors`` that gives a concrete
    answer.

    Short-circuits only on a *resolved* read (``membership_quality == "exact"`` —
    a real address, or a confirmed renounced/zero), so a literal getter that
    reverts still falls through to the canonical/slot getter behind it (the #4
    internal-accessor and #6 slot-constant fallbacks both depend on this: their
    first candidate reverts on purpose). When every candidate was attempted but
    unreadable, returns the last labeled ``lower_bound`` empty (carrying
    ``unreadable_revert`` / ``unreadable_empty``). Returns ``None`` only when
    nothing was attempted (no candidate selector, no reachable RPC) so the caller
    can label the placeholder ``not_read``."""
    attempted_failure: CapabilityExpr | None = None
    for selector in selectors:
        if selector is None:
            continue
        live = _live_resolve_authority(ctx, selector)
        if live is None:
            continue
        if live.membership_quality == "exact":
            return live
        attempted_failure = live
    return attempted_failure


def _public_getter_selector_for_internal_accessor(signature: str | None) -> str | None:
    """Selector for the public getter behind a nullary *internal* authority
    accessor, or ``None`` (fail-closed) for anything else.

    A custom authority gate often reads its principal through an internal helper
    rather than the public getter: Governable's ``onlyGovernor`` lowers to
    ``msg.sender == _governor()``, where ``_governor()`` is ``internal`` and has
    no external selector (calling it reverts). The leading-underscore ⇄ public
    convention (``_governor()``→``governor()``, ``_owner()``→``owner()``) is
    shared across OZ / Solady / Solmate / Governable, so the de-underscored
    getter reads the same value.

    Scoped to the canonical authority getters (``owner`` / ``governor`` /
    ``authority``, optionally ``pending``-prefixed): an arbitrary ``_x()`` is left
    fail-closed, since resolving it to whatever public ``x()`` returns would risk
    a *wrong* controller — worse than a missing one for this tool."""
    if not isinstance(signature, str) or not signature.endswith("()"):
        return None
    name = signature[:-2]
    if not name.startswith("_") or "(" in name:
        return None
    public_name = name.lstrip("_")
    if not public_name:
        return None
    base = public_name[len("pending") :] if public_name.lower().startswith("pending") else public_name
    if base.lower() not in _AUTHORITY_GETTER_BASENAMES:
        return None
    return _selector_for_signature(f"{public_name}()")


def _oz_v5_namespaced_authority_selector(signature: str | None) -> str | None:
    """Canonical public authority-getter selector for an OZ-v5 namespaced-storage
    OWNERSHIP accessor, or ``None`` (fail-closed).

    OZ-v5 keeps ownership in an ERC-7201 namespaced struct, so a caller-equality
    gate that lowers through ``owner()`` inlines to a ``view_call`` of the
    PRIVATE accessor that ``sload``s the namespace (CumulativeMerkleDrop overrides
    ``owner()`` to ``defaultAdmin()`` → ``_getAccessControlDefaultAdminRulesStorage()``).
    That accessor has no external selector, so reading it reverts; the canonical
    public ``owner()`` reads the same root. Anchored to the known ownership
    accessors by EXACT name (via the shared OZ-v5 recognition table) so an
    arbitrary ``_get<X>Storage()`` — the L1BaseSyncPool namespace, the parametric
    ``_getAccessControlStorage()`` role-admin root — is never rerouted here."""
    if not isinstance(signature, str) or not signature.endswith("()"):
        return None
    from services.static.contract_analysis_pipeline.tracking import (
        _oz_v5_ownership_getter_for_accessor,
    )

    getter = _oz_v5_ownership_getter_for_accessor(signature[:-2])
    if getter is None:
        return None
    return _selector_for_signature(f"{getter}()")


def _canonical_authority_selector_for_slot(name: str | None) -> str | None:
    """Canonical public authority-getter selector for a storage-slot-constant
    operand, or ``None`` when the name doesn't denote one (fail-closed).

    Solady ``_OWNER_SLOT`` / OZ-v5 ``OwnableStorageLocation`` /
    ``_GOVERNOR_SLOT`` name a *slot locator*, not a getter — reading
    ``<slot>()`` reverts. The contract's canonical public getter
    (``owner()``/``governor()``/``authority()``) reads that same slot. Gated on
    :func:`_is_storage_layout_constant` so ordinary address state vars — which
    resolve through their own auto-getter — are never rerouted here."""
    if not isinstance(name, str) or not name:
        return None
    from services.static.contract_analysis_pipeline.tracking import _is_storage_layout_constant

    if not _is_storage_layout_constant(name):
        return None
    lowered = name.lower()
    for keyword, selector in _SLOT_KEYWORD_TO_GETTER:
        if keyword in lowered:
            return selector
    return None


# Authority roles whose ``pending`` half names an accept-side 2-step transfer:
# ``pendingGovernor`` (Governable claimGovernance), ``pendingDefaultAdmin`` /
# ``pendingAdmin`` (OZ AccessControlDefaultAdminRules acceptDefaultAdminTransfer),
# ``pendingOwner`` (OZ Ownable2Step). Matched exactly after the ``pending``
# prefix is stripped, so only these flip to empty-by-design.
_PENDING_AUTHORITY_BASENAMES = frozenset({"owner", "governor", "authority", "admin", "defaultadmin"})


def _pending_authority_base(name: str | None) -> str | None:
    """The authority role behind a ``pending``-prefixed accessor name, or
    ``None``. ``_pendingGovernor`` → ``governor``; ``_pendingDefaultAdmin`` →
    ``defaultadmin``; a non-``pending`` name (plain ``owner``) → ``None``."""
    if not isinstance(name, str):
        return None
    bare = name.lstrip("_").lower()
    if not bare.startswith("pending"):
        return None
    base = bare[len("pending") :]
    return base if base in _PENDING_AUTHORITY_BASENAMES else None


def _is_pending_authority_accessor_operand(op: dict[str, Any]) -> bool:
    """True when an equality operand reads the *pending* half of a 2-step
    authority transfer — the accept-side gate (``claimGovernance`` /
    ``acceptDefaultAdminTransfer``) that is uncallable until a transfer is
    queued. Covers both shapes seen on-chain: an internal ``_pendingGovernor()``
    accessor (``view_call``) and an OZ ``_pendingDefaultAdmin.newAdmin`` storage
    struct member (``state_variable``). Keyed on the ``pending`` prefix so a plain
    ``owner()`` / ``governor()`` gate is never caught."""
    src = op.get("source")
    if src == "view_call":
        signature = op.get("callee_signature")
        name = signature[:-2] if isinstance(signature, str) and signature.endswith("()") else signature
    elif src == "state_variable":
        name = op.get("state_variable_name")
    else:
        return False
    return _pending_authority_base(name) is not None


def _resolve_param_keyed_authority_mapping(op: dict[str, Any], ctx: EvaluationContext | None) -> CapabilityExpr:
    """``msg.sender == <mapping>[<param>]`` — resolve the parameter-keyed authority
    mapping to the set of its VALUES (claim #3 group C).

    L1BaseSyncPool gates ``onMessageReceived`` on ``msg.sender == receivers[originEid]``,
    a ``mapping(uint32 => address)`` keyed by a function parameter. The authorized
    caller is whichever receiver the (caller-chosen) eid maps to, so the principal is
    the mapping's value set — there is no single getter to read. Fold those values
    from the mapping's setter events (``ReceiverSet``) on the runtime address (the
    proxy when proxy-linked, so the *live* receivers are seen rather than a standalone
    impl's empty storage). Emit a ``finite_set`` of the folded receivers; when no
    event source is reachable, no setter spec exists, or the live mapping folds empty,
    emit an ``external_check_only`` query interface rather than a phantom "nobody"
    (mirrors :func:`_resolve_view_key_membership`'s ``view_key_membership_unresolved``).
    ``lower_bound`` because event replay is a lower bound on the live value set."""
    mapping_name = op.get("mapping_name") or ""
    writer_specs = op.get("mapping_writer_specs") or []
    outer = getattr(getattr(ctx, "adapter", None), "_outer_ctx", None) if ctx is not None else None
    contract = getattr(outer, "contract_address", None) or (ctx.contract_address if ctx is not None else None)

    def _unresolved(basis: str) -> CapabilityExpr:
        target = contract.lower() if isinstance(contract, str) and contract.startswith("0x") else None
        return CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=target,
                target_call_selector=None,
                extra={"basis": [basis], "mapping_name": mapping_name},
            )
        )

    if not writer_specs:
        return _unresolved("param_keyed_mapping_no_writer_spec")
    if not isinstance(contract, str) or not contract.startswith("0x") or len(contract) != 42:
        return _unresolved("param_keyed_mapping_no_address")

    values = _enumerate_param_keyed_mapping_values(contract, list(writer_specs), outer)
    if not values:
        # No event source reachable, or the live mapping folded no receivers (e.g. a
        # standalone impl whose receivers were set on the proxy): an honest query
        # interface, never a fabricated empty principal set.
        return _unresolved("param_keyed_mapping_unresolved")
    return CapabilityExpr.finite_set(
        values,
        quality="lower_bound",
        confidence="partial",
        trace=[{"step": "param_keyed_mapping_enumeration", "mapping": mapping_name, "contract": contract.lower()}],
    )


def _enumerate_param_keyed_mapping_values(contract: str, writer_specs: list[dict[str, Any]], outer: Any) -> list[str]:
    """Fold the deduped non-zero address VALUE set of a parameter-keyed mapping from
    its ``set``-direction setter events via on-demand replay. Returns an empty list
    when no event source is reachable (no hypersync token / injected client), the
    scan errors, or the mapping folds empty — the caller surfaces all three as an
    external check. The hypersync client / module are read from ``outer.meta`` so a
    test can seed the event source without replacing the enumerator (the wire is the
    stub seam, mirroring ``rpc_request``)."""
    import os

    meta = getattr(outer, "meta", None) or {}
    token = meta.get("hypersync_token") or os.getenv("ENVIO_API_TOKEN")
    client = meta.get("hypersync_client")
    module = meta.get("hypersync_module")
    if not token and client is None:
        return []
    block = getattr(outer, "block", None)
    chain_id = getattr(outer, "chain_id", None)
    _bump_resolve_counter(outer, "mapping_value_scans")
    from services.resolution.creation_block_floor import creation_block_floor

    kwargs: dict[str, Any] = {
        "from_block": creation_block_floor(contract, chain_id if isinstance(chain_id, int) else 1)
    }
    if isinstance(block, int):
        kwargs["to_block"] = block
    if token:
        kwargs["bearer_token"] = token
    if client is not None:
        kwargs["client"] = client
    if module is not None:
        kwargs["hypersync_module"] = module
    hypersync_url = meta.get("hypersync_url")
    if isinstance(hypersync_url, str) and hypersync_url:
        kwargs["hypersync_url"] = hypersync_url
    try:
        from services.resolution.mapping_enumerator import enumerate_mapping_values_sync

        scan = enumerate_mapping_values_sync(
            contract,
            cast(Any, writer_specs),
            chain=str(chain_id) if isinstance(chain_id, int) else None,
            **kwargs,
        )
    except Exception:
        return []
    if scan["status"] == "error":
        return []
    values: list[str] = []
    seen: set[str] = set()
    for entry in scan["entries"]:
        value_hex = entry.get("value_hex") or ""
        if not isinstance(value_hex, str) or len(value_hex) != 66:
            continue
        addr = "0x" + value_hex[-40:].lower()
        if _is_zero_address(addr) or addr == _BURN_ADDRESS or addr in seen:
            continue
        seen.add(addr)
        values.append(addr)
    return sorted(values)


def _view_call_caller_selects_key(op: Mapping[str, Any]) -> bool:
    """Does the CALLER choose the lookup key of this arg-taking view call?
    With recorded ``callee_args`` (registry-built trees), some arg must
    derive from a parameter or the caller itself — constant/state-derived
    keys (``roleAdmin(ROLE)``) are fixed authority lookups, not
    caller-chosen rows. Compiled trees don't record args; there the derived
    view_call fold (``predicates._derived_view_call_source``) fires only
    when a parameter flows into the value, so the absence of recorded args
    IS the parameter-keyed evidence."""
    args = op.get("callee_args")
    if not args:
        return True
    return any((arg or {}).get("source") in ("parameter", "msg_sender", "tx_origin", "root_caller") for arg in args)


def _resolve_equality_principal(
    leaf: LeafPredicate,
    ctx: EvaluationContext | None = None,
) -> CapabilityExpr:
    """``msg.sender == X`` — resolve X to a CapabilityExpr.

    Per v6 round-5 #2: when X is a function parameter, the result is
    conditional_universal(self_service) — anyone may call but only
    for their own data. State-var operands consult
    ``ctx.state_var_values`` (populated from ``controller_values``);
    when the value isn't there we emit the lower_bound placeholder so
    the FE can still render 'guarded by X' even without enumeration."""
    operands = leaf.get("operands") or []
    other = [op for op in operands if op["source"] not in _CALLER_SOURCES]
    if len(other) != 1:
        return CapabilityExpr.unsupported("equality_operand_ambiguous")
    op = other[0]

    # ``msg.sender == <mapping>[<param>]`` — the authorized caller is any VALUE in a
    # parameter-keyed address mapping (claim #3 group C, L1BaseSyncPool
    # ``receivers[originEid]``). Route to event enumeration before the per-source
    # getter dispatch: the operand's ``source`` is the bare storage accessor, and the
    # mapping identity rides on ``mapping_name`` / ``mapping_writer_specs`` (stamped
    # by the static stage). There is no getter to read here.
    if op.get("mapping_name") is not None:
        return _resolve_param_keyed_authority_mapping(cast(dict[str, Any], op), ctx)

    src = op["source"]
    if src == "constant":
        val = op.get("constant_value")
        if isinstance(val, str) and val.startswith("0x") and len(val) == 42:
            if _is_zero_address(val):
                return CapabilityExpr.finite_set([], quality="exact", confidence="enumerable")
            return CapabilityExpr.finite_set([val])
        return CapabilityExpr.unsupported(f"equality_constant_non_address_{val}")

    if src == "state_variable":
        sv_name = _state_var_lookup_key(cast(dict[str, Any], op))
        if ctx is not None and sv_name and sv_name in ctx.state_var_values:
            value = ctx.state_var_values[sv_name]
            if isinstance(value, str) and value.startswith("0x") and len(value) == 42:
                if _is_zero_address(value):
                    return CapabilityExpr.finite_set([], quality="exact", confidence="enumerable")
                return CapabilityExpr.finite_set(
                    [value],
                    quality="exact",
                    confidence="enumerable",
                )
        # state_var_values miss. For a bare (non-struct-member) variable the
        # equality ``msg.sender == X`` names X as the sole authorized caller, so
        # reading X's getter live recovers the principal the persisted
        # ControllerValue feed didn't carry (or carried under a different key,
        # e.g. an owner()/governor() gate). Three getter candidates are tried in
        # order until one reads a concrete value:
        #   1. ``<name>()`` — the auto-getter of a ``public`` state var, named
        #      after the var itself (``owner``→``owner()``).
        #   2. the de-underscored canonical getter — an OZ-v4 ``onlyOwner`` lowers
        #      to ``msg.sender == _owner`` (the private backing var, since the
        #      trivial ``owner(){return _owner;}`` getter is inlined), and
        #      ``_owner()`` has no selector of its own, but ``owner()`` reads the
        #      same storage (``_governor``→``governor()`` likewise). Mirrors the
        #      view_call branch's internal-accessor fallback and is fail-closed to
        #      {owner,governor,authority}(+pending), so an arbitrary ``_x`` is left
        #      alone rather than bound to whatever public ``x()`` returns.
        #   3. the canonical getter behind a storage-slot *locator* (Solady
        #      ``_OWNER_SLOT``, OZ-v5 ``OwnableStorageLocation``, ``_GOVERNOR_SLOT``)
        #      whose own ``<slot>()`` getter reverts.
        # Struct members are read only for the OZ-v5 namespaced ``_owner``; others
        # (``accountantState.payoutAddress``) have no nullary getter and describe
        # fund destinations, not callers.
        name = op.get("state_variable_name")
        result: CapabilityExpr | None = None
        if not op.get("member_path"):
            result = _resolve_authority_via_getters(
                ctx,
                [
                    _nullary_getter_selector(name),
                    _public_getter_selector_for_internal_accessor(f"{name}()") if name else None,
                    _canonical_authority_selector_for_slot(name),
                ],
            )
        elif op.get("member_path") == ["_owner"]:
            result = _resolve_authority_via_getters(ctx, [_OWNER_SELECTOR])
        if result is not None and result.membership_quality == "exact":
            return result
        # Getter-less internal address var (ether.fi ``MembershipNFT.membershipManager``
        # is declared without ``public``, so its ``membershipManager()`` getter
        # reverts on every deployment): the *sequential* storage slot the static
        # stage carried is AUTHORITATIVE — the value lives in the contract's own
        # storage, read it directly. A non-zero slot IS the principal; a
        # confirmed-zero slot is a renounced/unset authority (resolved_empty, like a
        # clean-zero getter — NOT empty-by-design, hence ``zero_empty_reason=None``);
        # an unreadable slot stays an honest ``lower_bound``. Only bare address
        # scalars carry a slot (the static pass excludes mappings/structs/packed
        # vars), so a non-address word is never misread as a principal.
        slot = op.get("storage_slot")
        if isinstance(slot, str) and not op.get("member_path"):
            slot_result = _live_resolve_authority_slot(ctx, slot, zero_empty_reason=None)
            if slot_result is not None:
                return slot_result
            # Slot present but no read attempted (no reachable RPC) — honest
            # unknown, not a guess.
            return CapabilityExpr.finite_set([], quality="lower_bound", confidence="partial", empty_reason="not_read")
        # An accept-side 2-step transfer gate (pending governor / default admin)
        # that read empty — or, like ``_pendingDefaultAdmin.newAdmin``, has no
        # getter to read — is uncallable until a transfer is queued. That is
        # empty-by-design, not an unresolved gap.
        if _is_pending_authority_accessor_operand(cast(dict[str, Any], op)):
            return CapabilityExpr.finite_set([], quality="exact", empty_reason="empty_by_design")
        if result is not None:
            return result  # carries unreadable_revert / unreadable_empty
        # Fallback: a guarding state-var with no getter attempted (struct member /
        # non-address value). UI surfaces this as 'guarded but unresolved'.
        return CapabilityExpr.finite_set(
            [],
            quality="lower_bound",
            confidence="partial",
            empty_reason="not_read",
        )

    if src == "self_address":
        value = ctx.contract_address if ctx is not None else None
        if isinstance(value, str) and value.startswith("0x") and len(value) == 42:
            return CapabilityExpr.finite_set([value.lower()], quality="exact", confidence="enumerable")
        return CapabilityExpr.unsupported("self_address_without_contract")

    if src == "view_call":
        # ``msg.sender == owner()`` / ``== governor()``: the static stage
        # recorded the getter but couldn't read it. Resolve it live against the
        # contract under analysis. This branch previously returned an empty
        # lower_bound placeholder unconditionally, which dropped every
        # owner()/governor()-gated function's principal (the etherfi SyncPool /
        # LRTSquaredCore recall gap). Falls back to the placeholder when no RPC
        # is reachable.
        # Only nullary getters (owner()/governor()) are read live — a view
        # taking args (e.g. roleAdmin(role)) can't be called with empty
        # calldata, so leave it to the placeholder.
        signature = op.get("callee_signature")
        if (
            earned_public_enabled()
            and isinstance(signature, str)
            and "(" in signature
            and not signature.endswith("()")
            and _view_call_caller_selects_key(op)
        ):
            # An ARG-taking view lookup whose key the CALLER selects —
            # ``msg.sender == ownerOf(tokenId)`` / ``== getApproved(id)`` /
            # ``== withdrawal.owner``: every caller passes for their own key
            # (self-service-or-appointed, the uniform policy). A FIXED
            # authority keeps the gated path below — nullary getters, and
            # arg-taking lookups keyed by constants/state
            # (``msg.sender == roleAdmin(ROLE)``), which are authority
            # values, not caller-chosen rows. Without this arm the
            # placeholder empty-lower set would trip the earned-public
            # projection blocker and gate every ERC721 transfer/claim
            # family function.
            cond = Condition(
                kind="self_service",
                description=f"caller matches {signature} for their own key",
            )
            return CapabilityExpr.conditional_universal(cond)
        selector = None
        canonical_selector = None
        if not op.get("callee_args"):
            signature = op.get("callee_signature")
            selector = op.get("callee_selector")
            if not (isinstance(selector, str) and selector.startswith("0x") and len(selector) == 10):
                selector = (
                    _selector_for_signature(signature)
                    if isinstance(signature, str) and signature.endswith("()")
                    else None
                )
            # Internal authority accessors (``_governor()``/``_owner()``) have no
            # external selector, so reading them reverts (the etherfi LRTSquared
            # ``onlyGovernor`` gap: the gate is ``msg.sender == _governor()``). The
            # authority is the value the public getter returns, so prefer the
            # de-underscored canonical getter (``governor()``/``owner()``).
            canonical_selector = _public_getter_selector_for_internal_accessor(signature)
            # OZ-v5 keeps ownership in an ERC-7201 namespace, so an ``owner()``
            # gate inlines to a ``view_call`` of the namespaced storage accessor
            # (``_getAccessControlDefaultAdminRulesStorage()``) rather than a
            # ``_owner()`` helper — recognized by exact accessor name and read
            # through ``owner()``.
            if canonical_selector is None:
                canonical_selector = _oz_v5_namespaced_authority_selector(signature)
        # Canonical public getter first (when the operand is an internal authority
        # accessor its own selector is dead); otherwise the literal selector.
        result = _resolve_authority_via_getters(ctx, list(dict.fromkeys((canonical_selector, selector))))
        if result is not None and result.membership_quality == "exact":
            return result
        # Getter-less slot-backed accessor (Governable ``_pendingGovernor`` reads a
        # keccak slot via assembly, no public getter): the slot the static stage
        # carried is AUTHORITATIVE. A non-zero slot IS the principal — on
        # Governable ``_changeGovernor`` never clears the pending slot, so after a
        # completed transfer it stays == governor and the accept gate is
        # satisfiable by the sitting governor; a confirmed-zero slot is a
        # read-confirmed accept-side ceiling; an unreadable slot stays an honest
        # ``lower_bound``. We never downgrade an unreadable slot to a name guess,
        # so resolved_empty here is always an evidenced (read-confirmed) verdict.
        slot = op.get("storage_slot")
        if isinstance(slot, str):
            slot_result = _live_resolve_authority_slot(ctx, slot)
            if slot_result is not None:
                return slot_result
            # Slot present but no read attempted (no reachable RPC) — honest
            # unknown, not a guess.
            return CapabilityExpr.finite_set([], quality="lower_bound", confidence="partial", empty_reason="not_read")
        # No slot to read. A getter-less ``pending``-prefixed accept gate (the OZ
        # ``_pendingDefaultAdmin.newAdmin`` struct member, which has no nullary
        # getter) is uncallable until a transfer is queued — empty-by-design.
        if _is_pending_authority_accessor_operand(cast(dict[str, Any], op)):
            return CapabilityExpr.finite_set([], quality="exact", empty_reason="empty_by_design")
        if result is not None:
            return result  # carries unreadable_revert / unreadable_empty
        return CapabilityExpr.finite_set(
            [],
            quality="lower_bound",
            confidence="partial",
            empty_reason="not_read",
        )

    if src == "parameter":
        # Self-service: anyone, on their own data.
        cond = Condition(
            kind="self_service",
            description=f"caller acting on their own {op.get('parameter_name') or 'arg'}",
            parameter_index=op.get("parameter_index"),
            parameter_name=op.get("parameter_name"),
        )
        return CapabilityExpr.conditional_universal(cond)

    if src == "signature_recovery":
        # Already handled via signature_auth leaf kind, but defensive.
        return CapabilityExpr.signature_witness(CapabilityExpr.unsupported("signer_unresolved"))

    if src == "external_call":
        # ``msg.sender == otherContract.someGetter()`` — the authority lives in
        # another contract (PauserRegistry.unpauser(), avsNodeRunner(), …). The
        # operand carries the callee selector but not the target address (the
        # callee's host is a state var of the contract under analysis), so we
        # can't enumerate it offline. Surface a query-only external check: the
        # caller must equal the getter's return. This is GATED (external_check_only
        # → residual, zero principal rows), never public — the whole point of
        # recognizing it as caller_authority rather than letting it fall to a
        # business side-condition that opens the function.
        selector = op.get("callee_selector")
        return CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=None,
                target_call_selector=selector if isinstance(selector, str) else None,
                extra={
                    "basis": ["caller_equals_external_getter"],
                    "callee": op.get("callee"),
                    "callee_signature": op.get("callee_signature"),
                },
            )
        )

    if src == "computed":
        return CapabilityExpr.unsupported(f"equality_operand_computed_{op.get('computed_kind')}")

    return CapabilityExpr.unsupported(f"equality_operand_source_{src}")


def _resolve_view_key_membership(descriptor: SetDescriptor, ctx: EvaluationContext) -> CapabilityExpr | None:
    if descriptor.get("kind") != "mapping_membership":
        return None
    key_sources = list(descriptor.get("key_sources") or [])
    caller_indices = [idx for idx, source in enumerate(key_sources) if source.get("source") in _CALLER_SOURCES]
    view_indices = [idx for idx, source in enumerate(key_sources) if source.get("source") == "view_call"]
    if len(caller_indices) != 1 or len(view_indices) != 1:
        return None

    outer_ctx = getattr(getattr(ctx, "adapter", None), "_outer_ctx", None)
    session = getattr(outer_ctx, "session", None)
    rpc_url = getattr(outer_ctx, "rpc_url", None)
    if session is None or not isinstance(rpc_url, str) or not rpc_url:
        return None

    view_index = view_indices[0]
    view_source = key_sources[view_index]
    selector = view_source.get("callee_selector")
    if not isinstance(selector, str) or not selector.startswith("0x"):
        signature = view_source.get("callee_signature")
        selector = _selector_for_signature(signature) if isinstance(signature, str) else None
    if not selector:
        return None

    event_hints: list[dict[str, Any]] = [
        dict(hint) for hint in (descriptor.get("enumeration_hint") or []) if isinstance(hint, dict)
    ]
    if not event_hints:
        return None
    role_words = _observed_event_key_words(
        session=session,
        outer_ctx=outer_ctx,
        descriptor=descriptor,
        event_hints=event_hints,
        key_index=view_index,
    )
    if not role_words:
        return None

    contract_address = getattr(outer_ctx, "contract_address", None) or ctx.contract_address
    if not isinstance(contract_address, str) or not contract_address.startswith("0x"):
        return None
    admin_words = _call_unary_bytes32_view(
        rpc_url=rpc_url,
        contract_address=contract_address,
        selector=selector,
        args=role_words,
        block=getattr(outer_ctx, "block", None) or ctx.block,
    )
    if not admin_words:
        return CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=contract_address.lower(),
                target_call_selector=selector,
                extra={"basis": ["view_key_membership_unresolved"]},
            )
        )

    result: CapabilityExpr | None = None
    for admin_word in admin_words:
        patched = dict(descriptor)
        patched_keys = [dict(source) for source in key_sources]
        patched_keys[view_index] = {"source": "constant", "constant_value": admin_word}
        patched["key_sources"] = patched_keys
        child = ctx.adapter.enumerate(cast(SetDescriptor, patched), ctx.contract_address)
        result = child if result is None else union(result, child)
    return result


def _observed_event_key_words(
    *,
    session: Any,
    outer_ctx: Any,
    descriptor: SetDescriptor,
    event_hints: list[dict[str, Any]],
    key_index: int,
) -> list[str]:
    from sqlalchemy import func, select

    from db.models import IndexedEventLog
    from services.resolution.adapters.event_indexed import _resolve_event_address
    from services.resolution.repos.event_logs_pg import _event_keys, _normalize_word

    out: set[str] = set()
    for hint in event_hints:
        topic0 = hint.get("topic0")
        if not isinstance(topic0, str):
            continue
        event_address = _resolve_event_address(cast(dict[str, Any], descriptor), hint, outer_ctx)
        if event_address is None:
            continue
        stmt = (
            select(IndexedEventLog)
            .where(IndexedEventLog.chain_id == getattr(outer_ctx, "chain_id", 1))
            .where(func.lower(IndexedEventLog.event_address) == event_address.lower())
            .where(func.lower(IndexedEventLog.topic0) == topic0.lower())
            .order_by(
                IndexedEventLog.block_number.asc(),
                IndexedEventLog.transaction_index.asc(),
                IndexedEventLog.log_index.asc(),
            )
        )
        block = getattr(outer_ctx, "block", None)
        if isinstance(block, int):
            stmt = stmt.where(IndexedEventLog.block_number <= block)
        for row in session.execute(stmt).scalars():
            keys = _event_keys(
                row.topics or [],
                row.data_words or [],
                hint.get("topics_to_keys") or {},
                hint.get("data_to_keys") or {},
            )
            word = _normalize_word(keys.get(key_index))
            if word is not None:
                out.add(word)
    if not out:
        out.update(
            _observed_event_key_words_from_hypersync(
                outer_ctx=outer_ctx,
                descriptor=descriptor,
                event_hints=event_hints,
                key_index=key_index,
            )
        )
    return sorted(out)


def _observed_event_key_words_from_hypersync(
    *,
    outer_ctx: Any,
    descriptor: SetDescriptor,
    event_hints: list[dict[str, Any]],
    key_index: int,
) -> list[str]:
    import asyncio
    import os
    import time

    from services.resolution.adapters.event_indexed import _resolve_event_address
    from services.resolution.repos.event_logs_hypersync import (
        _data_words_from_log,
        _logs_from_response,
        _topics_from_log,
    )
    from services.resolution.repos.event_logs_pg import _event_keys, _normalize_word

    token = os.getenv("ENVIO_API_TOKEN") or getattr(outer_ctx, "meta", {}).get("hypersync_token")
    if not token:
        return []
    _bump_resolve_counter(outer_ctx, "hypersync_fallback_scans")
    address_topics: dict[str, set[str]] = {}
    hints_by_address_topic: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for hint in event_hints:
        topic0 = hint.get("topic0")
        if not isinstance(topic0, str):
            continue
        event_address = _resolve_event_address(cast(dict[str, Any], descriptor), hint, outer_ctx)
        if event_address is None:
            continue
        address_topics.setdefault(event_address.lower(), set()).add(topic0.lower())
        hints_by_address_topic.setdefault((event_address.lower(), topic0.lower()), []).append(hint)
    if not address_topics:
        return []

    async def _scan() -> list[str]:
        try:
            import hypersync  # type: ignore
        except Exception:
            return []
        url = str(
            getattr(outer_ctx, "meta", {}).get("hypersync_url")
            or os.getenv("PSAT_HYPERSYNC_URL", "https://eth.hypersync.xyz")
        )
        timeout_s = float(os.getenv("PSAT_HYPERSYNC_EVENT_FALLBACK_TIMEOUT_S", "45"))
        max_pages = int(os.getenv("PSAT_HYPERSYNC_EVENT_FALLBACK_MAX_PAGES", "50"))
        client = hypersync.HypersyncClient(hypersync.ClientConfig(url=url, bearer_token=token))
        from services.resolution.creation_block_floor import creation_block_floor

        scan_chain_id = getattr(outer_ctx, "chain_id", None)
        found: set[str] = set()
        for event_address, topic0s in address_topics.items():
            current_from = creation_block_floor(event_address, scan_chain_id if isinstance(scan_chain_id, int) else 1)
            page_count = 0
            started = time.monotonic()
            while True:
                if time.monotonic() - started > timeout_s or page_count >= max_pages:
                    break
                query = hypersync.Query(
                    from_block=current_from,
                    to_block=getattr(outer_ctx, "block", None),
                    logs=[
                        hypersync.LogSelection(
                            address=[event_address],
                            topics=[sorted(topic0s)],
                        )
                    ],
                    field_selection=hypersync.FieldSelection(log=[field.value for field in hypersync.LogField]),
                )
                try:
                    response = await client.get(query)
                except Exception:
                    break
                page_count += 1
                for log in _logs_from_response(response):
                    topics = _topics_from_log(log)
                    if not topics:
                        continue
                    topic0 = topics[0].lower()
                    for hint in hints_by_address_topic.get((event_address, topic0), []):
                        keys = _event_keys(
                            topics,
                            _data_words_from_log(log),
                            hint.get("topics_to_keys") or {},
                            hint.get("data_to_keys") or {},
                        )
                        word = _normalize_word(keys.get(key_index))
                        if word is not None:
                            found.add(word)
                next_block = getattr(response, "next_block", None)
                if next_block is None or next_block <= current_from:
                    break
                block = getattr(outer_ctx, "block", None)
                if isinstance(block, int) and next_block >= block:
                    break
                current_from = next_block
        return sorted(found)

    try:
        return asyncio.run(_scan())
    except Exception:
        return []


def _call_unary_bytes32_view(
    *,
    rpc_url: str,
    contract_address: str,
    selector: str,
    args: list[str],
    block: int | None,
) -> list[str]:
    from services.resolution.repos.event_logs_pg import _normalize_word
    from utils.rpc import rpc_batch_request_with_status

    calls: list[tuple[str, list[Any]]] = []
    for arg in args:
        word = _normalize_word(arg)
        if word is None:
            continue
        calls.append(
            (
                "eth_call",
                [
                    {"to": contract_address.lower(), "data": selector + word[2:]},
                    hex(block) if isinstance(block, int) else "latest",
                ],
            )
        )
    if not calls:
        return []
    out: set[str] = set()
    for raw, had_error in rpc_batch_request_with_status(rpc_url, calls):
        if had_error:
            continue
        word = _normalize_word(raw)
        if word is not None:
            out.add(word)
    return sorted(out)


def _leaf_has_caller_operand(leaf: LeafPredicate) -> bool:
    return any((op.get("source") in _CALLER_SOURCES) for op in (leaf.get("operands") or []))


def _resolve_contextual_equality(
    leaf: LeafPredicate,
    ctx: EvaluationContext | None,
    operator: str,
) -> CapabilityExpr:
    """Evaluate equality leaves whose caller operand was already bound.

    Recursive external-call evaluation intentionally rewrites a callee's
    ``msg.sender`` to the calling contract address. A guard like
    ``msg.sender == liquidityPool`` then becomes a concrete call-edge
    condition, not a root-caller principal. Exact true is no caller
    restriction; exact false means the external call can never authorize
    this edge. Dynamic non-caller checks remain business side-conditions.
    """
    operands = leaf.get("operands") or []
    if len(operands) != 2:
        return CapabilityExpr.conditional_universal(_condition_from_leaf(leaf))

    left = _resolve_operand_static_value(cast(dict[str, Any], operands[0]), ctx)
    right = _resolve_operand_static_value(cast(dict[str, Any], operands[1]), ctx)
    if left is None or right is None:
        return CapabilityExpr.conditional_universal(_condition_from_leaf(leaf))

    matches = left == right
    allowed = matches if operator == "eq" else not matches
    if allowed:
        return CapabilityExpr.conditional_universal(
            Condition(kind="business", description="resolved call-frame equality")
        )
    return CapabilityExpr.finite_set([], quality="exact", confidence="enumerable")


def _resolve_operand_static_value(operand: dict[str, Any], ctx: EvaluationContext | None) -> str | None:
    src = operand.get("source")
    if src == "constant":
        value = operand.get("constant_value")
        return value.lower() if isinstance(value, str) else None
    if src == "state_variable":
        sv_name = _state_var_lookup_key(operand)
        values = ctx.state_var_values if ctx is not None else None
        value = values.get(sv_name) if values is not None and isinstance(sv_name, str) else None
        return value.lower() if isinstance(value, str) else None
    if src == "self_address":
        value = ctx.contract_address if ctx is not None else None
        return value.lower() if isinstance(value, str) else None
    return None


def _is_zero_address(value: str) -> bool:
    return value.lower() == "0x" + "0" * 40


def _maybe_inline_cross_contract_call(
    leaf: LeafPredicate,
    descriptor: SetDescriptor,
    ctx: EvaluationContext,
) -> CapabilityExpr | None:
    """Try to resolve a delegated external-check leaf by
    evaluating the registry contract's predicate trees under the
    caller's context.

    The leaf must carry:
      * ``set_descriptor.authority_contract.address_source`` — pointing
        at the state-variable that holds the registry address.
      * ``set_descriptor.callee_signature`` or ``callee_selector`` — the
        exact registry function to inline.

    Returns:
      * a ``CapabilityExpr`` from re-evaluating B's tree under A's
        sender, OR
      * ``None`` if any precondition isn't met (no session, no
        state-var resolution, no Job for the registry, no
        predicate_trees artifact, no matching function tree, or the
        recursion guard fires) — caller falls through to the existing
        adapter path.

    The resolver carries an ``evaluation_stack`` set on the context to
    short-circuit cycles: ``(chain_id, address.lower(), function_signature)``
    is added before recursing and removed after. A repeat hit (e.g.
    A→B→A or B→B) returns ``CapabilityExpr.external_check_only`` so
    the leaf still surfaces as 'gated' even if we can't resolve.
    """
    callee_signature = descriptor.get("callee_signature")
    callee_selector = descriptor.get("callee_selector")
    if not isinstance(callee_signature, str):
        callee_signature = None
    if not isinstance(callee_selector, str):
        callee_selector = None
    if not callee_signature and not callee_selector:
        return None
    if callee_selector is None and callee_signature is not None:
        callee_selector = _selector_for_signature(callee_signature)

    # session lives on the OUTER (adapters) context — pulled by the
    # registry-backed adapter wrapper. Fall back to None gracefully.
    outer_ctx = getattr(getattr(ctx, "adapter", None), "_outer_ctx", None)
    if outer_ctx is None:
        return None
    session = getattr(outer_ctx, "session", None)
    if session is None:
        return None

    authority_contract = descriptor.get("authority_contract") or {}
    address_source = authority_contract.get("address_source") or {}
    if address_source.get("source") != "state_variable":
        return None
    sv_name = _state_var_lookup_key(cast(dict[str, Any], address_source))
    if not isinstance(sv_name, str) or not sv_name:
        return None
    state_vars = getattr(outer_ctx, "state_var_values", None) or {}
    registry_addr = state_vars.get(sv_name)
    if not isinstance(registry_addr, str) or not registry_addr.startswith("0x") or len(registry_addr) != 42:
        return None
    registry_addr = registry_addr.lower()

    chain_id = getattr(outer_ctx, "chain_id", 1)
    stack = outer_ctx.evaluation_stack if hasattr(outer_ctx, "evaluation_stack") else set()
    callee_identity = callee_signature or callee_selector or ""
    key = (chain_id, registry_addr, callee_identity)
    if key in stack:
        # Cycle: B's resolution depends on its own gate, or we've already
        # walked through this address+function in this evaluation tree.
        return CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=registry_addr,
                target_call_selector=callee_selector,
                extra={"basis": ["cycle_detected_in_cross_contract_inlining"]},
            )
        )

    # Look up the registry's semantic artifacts. If the registry address is
    # a proxy, predicate_trees live on its implementation child job.
    from db.queue import get_artifact
    from services.resolution.capability_resolver import find_analysis_job_for_address

    lookup = find_analysis_job_for_address(
        session,
        registry_addr,
        required_artifact="predicate_trees",
        completed_only=False,
    )
    if lookup is None:
        return None
    artifact = get_artifact(session, lookup.analysis_job.id, "predicate_trees")
    if not isinstance(artifact, dict):
        return None
    from services.resolution.adapters import CallFrame

    parent_frame = getattr(outer_ctx, "call_frame", None)
    if parent_frame is None:
        parent_frame = CallFrame.root(
            contract_address=getattr(outer_ctx, "contract_address", None),
            function_signature=None,
            function_selector=None,
        )
    call_args = [
        _normalize_operand_for_call_arg(
            arg,
            parent_frame,
            ctx,
            callee_contract_address=registry_addr,
            rpc_url=getattr(outer_ctx, "rpc_url", None),
            block=getattr(outer_ctx, "block", None),
        )
        for arg in _callee_argument_operands(
            leaf,
            callee_signature=callee_signature,
            callee_selector=callee_selector,
        )
    ]

    trees = artifact.get("trees")
    check_trees = artifact.get("check_trees")
    tree_maps = [m for m in (trees, check_trees) if isinstance(m, dict) and m]
    if not tree_maps:
        return _materialize_external_check_from_candidates(
            session=session,
            outer_ctx=outer_ctx,
            chain_id=chain_id,
            registry_addr=registry_addr,
            callee_selector=callee_selector,
            call_args=call_args,
        )

    callee_tree = None
    for tree_map in tree_maps:
        callee_tree = _tree_for_signature_or_selector(
            tree_map,
            callee_signature=callee_signature,
            callee_selector=callee_selector,
        )
        if callee_tree is not None:
            break
    if callee_tree is None:
        return _materialize_external_check_from_candidates(
            session=session,
            outer_ctx=outer_ctx,
            chain_id=chain_id,
            registry_addr=registry_addr,
            callee_selector=callee_selector,
            call_args=call_args,
        )

    callee_tree = _bind_callee_parameters(
        callee_tree,
        call_args,
    )

    # Build a child evaluation context targeting the registry.
    # Parameter arguments are already bound above. Direct Solidity
    # globals inside the callee get the child frame: msg.sender is
    # the calling contract, address(this) is the registry, and
    # msg.sig is the callee selector.
    from services.resolution.capability_resolver import _load_state_var_values

    state_var_values = _load_state_var_values(
        session,
        lookup.analysis_job.address or registry_addr,
        job_id=lookup.analysis_job.id,
    )
    if not state_var_values and lookup.runtime_job.id != lookup.analysis_job.id:
        state_var_values = _load_state_var_values(session, registry_addr, job_id=lookup.runtime_job.id)

    parent_this = getattr(parent_frame, "current_address_this", None) or getattr(
        parent_frame, "executing_contract_address", None
    )
    child_frame = CallFrame(
        protected_contract_address=getattr(parent_frame, "protected_contract_address", None),
        executing_contract_address=registry_addr,
        current_function_signature=callee_signature,
        current_function_selector=callee_selector,
        current_msg_sender=parent_this.lower() if isinstance(parent_this, str) else None,
        current_address_this=registry_addr,
        current_msg_sig=callee_selector,
        bound_parameters=tuple(call_args),
    )
    callee_tree = _normalize_tree_for_frame(callee_tree, child_frame)

    child_outer = type(outer_ctx)(
        chain_id=chain_id,
        rpc_url=getattr(outer_ctx, "rpc_url", None),
        block=getattr(outer_ctx, "block", None),
        finality_depth=getattr(outer_ctx, "finality_depth", 12),
        contract_address=registry_addr,
        event_log_repo=getattr(outer_ctx, "event_log_repo", None),
        bytecode=outer_ctx.bytecode,
        recursive_resolver=outer_ctx.recursive_resolver,
        state_var_values=state_var_values,
        session=session,
        evaluation_stack=stack | {key},
        call_frame=child_frame,
        meta=dict(outer_ctx.meta),
    )

    # Same registry-backed adapter pattern as evaluate_tree_with_registry,
    # just keyed on the child outer ctx.
    from services.resolution.adapters import AdapterRegistry as _Reg

    registry_adapters = (
        ctx.adapter._registry  # type: ignore[attr-defined]
        if hasattr(ctx.adapter, "_registry")
        else _Reg()
    )
    _bump_resolve_counter(outer_ctx, "inline_recursions")
    resolved = evaluate_tree_with_registry(callee_tree, registry_adapters, child_outer)
    if _inline_result_needs_materialization(resolved):
        materialized = _materialize_external_check_from_candidates(
            session=session,
            outer_ctx=outer_ctx,
            chain_id=chain_id,
            registry_addr=registry_addr,
            callee_selector=callee_selector,
            call_args=call_args,
        )
        if materialized is not None:
            return materialized
        # Fall through to the caller's adapter dispatch instead of dead-ending.
        # When the inlined delegated check can't be materialized (e.g. canCall's
        # role-mapping join the generic materializer can't express), the caller's
        # external_set path can still try a named adapter — SolmateRolesAuthorityAdapter
        # folds canCall from indexed role events. The old dead-end (an
        # external_check_only with basis=["delegated_check_not_materialized"])
        # returned non-None and pre-empted that adapter for every Solmate-protected
        # contract analyzed alongside its RolesAuthority, so the adapter never ran.
        return None
    return resolved


def _inline_result_needs_materialization(cap: CapabilityExpr) -> bool:
    if cap.kind == "finite_set":
        return not cap.members and cap.membership_quality != "exact"
    if cap.kind in {"external_check_only", "unsupported"}:
        return True
    if cap.kind == "conditional_universal":
        return _conditional_result_needs_materialization(cap)
    if cap.kind == "OR":
        return _or_result_needs_materialization(cap)
    return False


def _conditional_result_needs_materialization(cap: CapabilityExpr) -> bool:
    for condition in cap.conditions:
        description = condition.description or ""
        if description.startswith("return "):
            return True
    return False


def _or_result_needs_materialization(cap: CapabilityExpr) -> bool:
    saw_materializable = False
    for child in cap.children:
        if child.kind == "finite_set":
            if child.members:
                return False
            if child.membership_quality != "exact":
                saw_materializable = True
            continue
        if child.kind in {"external_check_only", "unsupported"}:
            saw_materializable = True
            continue
        if child.kind == "conditional_universal" and _conditional_result_needs_materialization(child):
            saw_materializable = True
            continue
        return False
    return saw_materializable


def _materialize_external_check_from_candidates(
    *,
    session: Any,
    outer_ctx: Any,
    chain_id: int,
    registry_addr: str,
    callee_selector: str | None,
    call_args: list[dict[str, Any]],
) -> CapabilityExpr | None:
    from services.resolution.external_check_materializer import materialize_external_check_from_events

    try:
        return materialize_external_check_from_events(
            session=session,
            rpc_url=getattr(outer_ctx, "rpc_url", None),
            chain_id=chain_id,
            checker_address=registry_addr,
            checker_selector=callee_selector,
            call_args=call_args,
            block=getattr(outer_ctx, "block", None),
        )
    except Exception:
        return None


def _callee_argument_operands(
    leaf: LeafPredicate,
    *,
    callee_signature: str | None,
    callee_selector: str | None,
) -> list[dict[str, Any]]:
    args: list[dict[str, Any]] = []
    for raw_operand in leaf.get("operands") or []:
        if not isinstance(raw_operand, dict):
            continue
        operand = cast(dict[str, Any], raw_operand)
        if _is_target_call_operand(operand, callee_signature=callee_signature, callee_selector=callee_selector):
            continue
        args.append(deepcopy(operand))
    return args


def _is_target_call_operand(
    operand: dict[str, Any],
    *,
    callee_signature: str | None,
    callee_selector: str | None,
) -> bool:
    if operand.get("source") != "external_call":
        return False
    op_sig = operand.get("callee_signature")
    if callee_signature and isinstance(op_sig, str) and op_sig == callee_signature:
        return True
    op_selector = operand.get("callee_selector")
    if callee_selector and isinstance(op_selector, str) and op_selector == callee_selector:
        return True
    return False


def _bind_callee_parameters(tree: PredicateTree, call_args: list[dict[str, Any]]) -> PredicateTree:
    bound = _bind_value(deepcopy(tree), call_args)
    return cast(PredicateTree, bound) if isinstance(bound, dict) else tree


def _normalize_operand_for_call_arg(
    operand: dict[str, Any],
    frame: Any,
    ctx: EvaluationContext,
    *,
    callee_contract_address: str | None = None,
    rpc_url: str | None = None,
    block: int | None = None,
) -> dict[str, Any]:
    source = operand.get("source")
    if source in _CALLER_SOURCES:
        return {"source": "root_caller"}
    if source == "external_call":
        outer = getattr(getattr(ctx, "adapter", None), "_outer_ctx", None)
        constant = _resolve_static_external_call_operand(
            operand,
            callee_contract_address=callee_contract_address,
            rpc_url=rpc_url,
            block=block,
            memo=_pass_live_read_memo(outer),
        )
        if constant is not None:
            return constant
    if source == "self_address":
        value = getattr(frame, "current_address_this", None) or getattr(frame, "executing_contract_address", None)
        if isinstance(value, str) and value.startswith("0x"):
            return {"source": "constant", "constant_value": value.lower()}
    if source == "computed" and operand.get("computed_kind") == "msg.sig":
        selector = getattr(frame, "current_msg_sig", None) or getattr(frame, "current_function_selector", None)
        if isinstance(selector, str) and selector.startswith("0x"):
            return {"source": "constant", "constant_value": selector.lower()}
    if source == "parameter":
        bound = _bound_parameter_operand(operand, frame)
        if bound is not None:
            return _normalize_operand_for_call_arg(
                bound,
                frame,
                ctx,
                callee_contract_address=callee_contract_address,
                rpc_url=rpc_url,
                block=block,
            )
    if source == "state_variable":
        name = _state_var_lookup_key(operand)
        value = ctx.state_var_values.get(name) if isinstance(name, str) else None
        if isinstance(value, str) and value.startswith("0x") and len(value) in {42, 66}:
            return {"source": "constant", "constant_value": value.lower()}
    return deepcopy(operand)


def _resolve_static_external_call_operand(
    operand: dict[str, Any],
    *,
    callee_contract_address: str | None,
    rpc_url: str | None,
    block: int | None,
    memo: dict[Any, Any] | None = None,
) -> dict[str, Any] | None:
    signature = operand.get("callee_signature")
    selector = operand.get("callee_selector")
    if not isinstance(signature, str) or not signature.endswith("()"):
        return None
    if not isinstance(selector, str) or not selector.startswith("0x") or len(selector) != 10:
        selector = _selector_for_signature(signature)
    if not selector or not isinstance(callee_contract_address, str) or not callee_contract_address.startswith("0x"):
        return None
    if not rpc_url:
        return None
    block_tag = hex(block) if isinstance(block, int) else "latest"
    # Pass-scoped dedup of this nullary callee getter (deterministic at a fixed block). Successful reads only:
    # a revert/transient error is never cached, so behavior is byte-identical to the un-memoized path.
    memo_key = ("ext_operand", rpc_url, callee_contract_address.lower(), selector, block_tag)
    if memo is not None and memo_key in memo:
        return {"source": "constant", "constant_value": memo[memo_key]}
    try:
        from utils.rpc import rpc_request

        raw = rpc_request(
            rpc_url,
            "eth_call",
            [{"to": callee_contract_address.lower(), "data": selector}, block_tag],
            retries=1,
        )
    except Exception:
        return None
    if not isinstance(raw, str) or not raw.startswith("0x") or len(raw) < 66:
        return None
    constant_value = "0x" + raw[-64:].lower()
    if memo is not None:
        memo[memo_key] = constant_value
    return {"source": "constant", "constant_value": constant_value}


def _normalize_tree_for_frame(tree: PredicateTree, frame: Any) -> PredicateTree:
    normalized = _normalize_value_for_frame(deepcopy(tree), frame)
    return cast(PredicateTree, normalized) if isinstance(normalized, dict) else tree


def _normalize_value_for_frame(value: Any, frame: Any, seen_parameters: frozenset[int] = frozenset()) -> Any:
    if isinstance(value, list):
        return [_normalize_value_for_frame(item, frame, seen_parameters) for item in value]
    if not isinstance(value, dict):
        return value

    source = value.get("source")
    if source == "msg_sender":
        sender = getattr(frame, "current_msg_sender", None)
        if isinstance(sender, str) and sender.startswith("0x"):
            return {"source": "constant", "constant_value": sender.lower()}
    if source == "self_address":
        address_this = getattr(frame, "current_address_this", None) or getattr(
            frame, "executing_contract_address", None
        )
        if isinstance(address_this, str) and address_this.startswith("0x"):
            return {"source": "constant", "constant_value": address_this.lower()}
    if source == "computed" and value.get("computed_kind") == "msg.sig":
        selector = getattr(frame, "current_msg_sig", None) or getattr(frame, "current_function_selector", None)
        if isinstance(selector, str) and selector.startswith("0x"):
            return {"source": "constant", "constant_value": selector.lower()}
    if source == "parameter":
        idx = value.get("parameter_index")
        if isinstance(idx, int):
            if idx in seen_parameters:
                return deepcopy(value)
            seen_parameters = seen_parameters | {idx}
        bound = _bound_parameter_operand(value, frame)
        if bound is not None:
            return _normalize_value_for_frame(bound, frame, seen_parameters)

    return {k: _normalize_value_for_frame(v, frame, seen_parameters) for k, v in value.items()}


def _bound_parameter_operand(operand: dict[str, Any], frame: Any) -> dict[str, Any] | None:
    idx = operand.get("parameter_index")
    bound_params = getattr(frame, "bound_parameters", ()) or ()
    if isinstance(idx, int) and 0 <= idx < len(bound_params):
        bound = bound_params[idx]
        return deepcopy(bound) if isinstance(bound, dict) else None
    return None


def _bind_value(value: Any, call_args: list[dict[str, Any]]) -> Any:
    if isinstance(value, list):
        return [_bind_value(item, call_args) for item in value]
    if not isinstance(value, dict):
        return value
    if value.get("source") == "parameter":
        idx = value.get("parameter_index")
        if isinstance(idx, int) and 0 <= idx < len(call_args):
            return deepcopy(call_args[idx])
    out = {k: _bind_value(v, call_args) for k, v in value.items()}
    leaf = out.get("leaf")
    if isinstance(leaf, dict):
        _promote_bound_caller_leaf(leaf)
    return out


def _promote_bound_caller_leaf(leaf: dict[str, Any]) -> None:
    if leaf.get("authority_role") != "business":
        return
    if leaf.get("kind") not in {"equality", "membership", "external_bool"}:
        return
    operands = leaf.get("operands") or []
    key_sources = (leaf.get("set_descriptor") or {}).get("key_sources") or []
    has_caller = any(_is_caller_source(item) for item in [*operands, *key_sources] if isinstance(item, dict))
    if has_caller:
        leaf["authority_role"] = "delegated_authority"
        leaf["references_msg_sender"] = True


def _is_caller_source(item: dict[str, Any]) -> bool:
    return item.get("source") in _CALLER_SOURCES


def _tree_for_signature_or_selector(
    trees: dict[str, Any],
    *,
    callee_signature: str | None,
    callee_selector: str | None,
) -> PredicateTree | None:
    """Find a predicate tree by exact ABI signature or selector."""
    if callee_signature and callee_signature in trees:
        tree = trees[callee_signature]
        return cast(PredicateTree, tree) if isinstance(tree, dict) else None
    if callee_selector:
        for signature, tree in trees.items():
            if not isinstance(signature, str):
                continue
            if _selector_for_signature(signature) == callee_selector and isinstance(tree, dict):
                return cast(PredicateTree, tree)
    return None


def _selector_for_signature(signature: str) -> str | None:
    if "(" not in signature or not signature.endswith(")"):
        return None
    return "0x" + keccak(text=signature).hex()[:8]


def _stamp_caller_gate_check(cap: CapabilityExpr, leaf: LeafPredicate) -> CapabilityExpr:
    """Under the earned-public default, mark an unresolvable
    ``external_check_only`` that IS a caller gate (caller-tainted leaf, no
    permissionless shape) with its ``caller_gate_basis`` tag. The projection
    blocker keys on the tag: a tagged check suppresses a sibling public path
    (the Solmate ``requiresAuth`` decline, a view ACL probe), while an
    untagged check — a downstream statement-call probe whose revert surface
    gates the INTERMEDIATE contract (the un-inlined Veda teller→vault call)
    — keeps the legacy side-condition fold. The decision is made here, where
    the leaf is in hand, never by pattern-matching check dicts downstream."""
    if cap.kind != "external_check_only" or cap.check is None:
        return cap
    if not earned_public_enabled():
        return cap
    if not (leaf_is_caller_tainted(leaf) and not is_permissionless_caller_shape(leaf)):
        return cap
    tag = caller_gate_basis(leaf)
    extra = dict(cap.check.extra or {})
    basis = list(extra.get("basis") or [])
    if tag not in basis:
        basis.append(tag)
    extra["basis"] = basis
    return replace(cap, check=replace(cap.check, extra=extra))


def _resolve_external_bool(leaf: LeafPredicate, ctx: EvaluationContext | None = None) -> CapabilityExpr:
    """``require(authority.check(...))`` — produces an
    external_check_only capability."""
    selector = None
    for op in leaf.get("operands") or []:
        if op.get("source") == "external_call":
            raw = op.get("callee_selector")
            selector = raw if isinstance(raw, str) else selector
    check = ExternalCheck(
        target_address=None,
        target_call_selector=selector,
        extra={"basis": list(leaf.get("basis", []))},
    )
    cap = _stamp_caller_gate_check(CapabilityExpr.external_check_only(check), leaf)
    operator = leaf.get("operator")
    if operator == "falsy":
        cap = negate(cap)
    return cap


def _normalize_membership_decline_for_negation(
    cap: CapabilityExpr,
    leaf: LeafPredicate,
    descriptor: SetDescriptor,
    ctx: EvaluationContext,
) -> CapabilityExpr:
    """Turn an *un-enumerable* membership decline into an ``external_check_only`` so a
    pending ``falsy`` negate reaches ``negate``'s cofinite arm.

    A ``falsy`` membership leaf (``if (set[caller]) revert``) proceeds for anyone NOT in
    the set, so its faithful resolution is the complement (cofinite/open). But when the
    adapter can't enumerate the set the decline arrives as ``unsupported("no_adapter")``
    (the real ``AdapterRegistry`` has no enumerator for this ``mapping_membership``) or
    as the null adapter's ``finite_set([], lower_bound)`` placeholder — and the raw
    ``unsupported`` would negate to ``unsupported("negate_of_no_adapter")``, discarding
    the denylist. Convert *only* that decline to an ``external_check_only`` describing
    the membership probe; ``negate(external_check_only)`` then yields a lower_bound
    cofinite. ``subject`` is carried through so a bound (inlined-hook) denylist stays a
    side-condition.

    Narrow by construction — a populated/exact ``finite_set``,
    ``membership_without_descriptor``, or any other reason is returned untouched and
    stays gated. Mirrors the external_bool branch's existing ``no_adapter`` handling.
    """
    is_no_adapter = cap.kind == "unsupported" and cap.unsupported_reason == "no_adapter"
    is_null_placeholder = cap.kind == "finite_set" and not cap.members and cap.membership_quality == "lower_bound"
    if not (is_no_adapter or is_null_placeholder):
        return cap
    check = _external_check_from_descriptor(leaf, descriptor, ctx)
    check.subject = cap.subject
    return check


def _external_check_from_descriptor(
    leaf: LeafPredicate,
    descriptor: SetDescriptor,
    ctx: EvaluationContext,
) -> CapabilityExpr:
    target_address = _target_address_from_descriptor(descriptor, ctx)
    selector = descriptor.get("callee_selector")
    check = ExternalCheck(
        target_address=target_address,
        target_call_selector=selector if isinstance(selector, str) else None,
        extra={
            "basis": list(leaf.get("basis", [])),
            "callee_function": descriptor.get("callee_function"),
            "callee_signature": descriptor.get("callee_signature"),
            "topic0": _first_hint_value(descriptor, "topic0"),
            "direction": _first_hint_value(descriptor, "direction"),
        },
    )
    return CapabilityExpr.external_check_only(check)


def _target_address_from_descriptor(descriptor: SetDescriptor, ctx: EvaluationContext) -> str | None:
    authority = descriptor.get("authority_contract") or {}
    raw = authority.get("address")
    if isinstance(raw, str) and raw.startswith("0x") and len(raw) == 42:
        return raw.lower()
    source = authority.get("address_source") or {}
    if source.get("source") == "state_variable":
        name = _state_var_lookup_key(cast(dict[str, Any], source))
        value = ctx.state_var_values.get(name) if isinstance(name, str) else None
        if isinstance(value, str) and value.startswith("0x") and len(value) == 42:
            return value.lower()
    return ctx.contract_address.lower() if ctx.contract_address else None


def _first_hint_value(descriptor: SetDescriptor, key: str) -> Any:
    hints = descriptor.get("enumeration_hint") or []
    for hint in hints:
        value = hint.get(key)
        if value is not None:
            return value
    return None


def _resolve_signer_from_leaf(
    leaf: LeafPredicate,
    ctx: EvaluationContext | None = None,
) -> CapabilityExpr:
    """For a signature_auth leaf, the principal is whoever signed.
    Find the operand that's NOT the signature_recovery source — that
    operand identifies the expected signer, which becomes a
    capability that the resolver-side check verifies the signature
    against.

    State-variable signers consult ``ctx.state_var_values`` so persisted
    ``ControllerValue`` rows surface as concrete signers — mirrors the
    sibling ``_resolve_equality_principal`` branch. Without this lookup,
    every signature-gated function whose signer is a state variable
    wraps an empty ``finite_set``, and the writer emits zero
    ``FunctionPrincipal`` rows of ``principal_type=signature_witness``.
    """
    operands = leaf.get("operands") or []
    signers = [op for op in operands if op["source"] != "signature_recovery"]
    if len(signers) != 1:
        return CapabilityExpr.unsupported("signature_signer_ambiguous")
    op = signers[0]

    if op["source"] == "state_variable":
        sv_name = _state_var_lookup_key(cast(dict[str, Any], op))
        if ctx is not None and sv_name and sv_name in ctx.state_var_values:
            value = ctx.state_var_values[sv_name]
            if isinstance(value, str) and value.startswith("0x") and len(value) == 42:
                if _is_zero_address(value):
                    return CapabilityExpr.finite_set([], quality="exact", confidence="enumerable")
                return CapabilityExpr.finite_set(
                    [value],
                    quality="exact",
                    confidence="enumerable",
                )
        return CapabilityExpr.finite_set(
            [],
            quality="lower_bound",
            confidence="partial",
        )
    if op["source"] == "constant":
        val = op.get("constant_value")
        if isinstance(val, str) and val.startswith("0x") and len(val) == 42:
            return CapabilityExpr.finite_set([val])
    return CapabilityExpr.unsupported(f"signature_signer_source_{op['source']}")


def _condition_from_leaf(leaf: LeafPredicate) -> Condition:
    role = leaf.get("authority_role")
    kind: str = role if role in ("time", "pause", "reentrancy", "business", "one_shot") else "business"
    if kind == "business" and _leaf_is_permit_shape(leaf):
        # A signature-witness open path that folded to a side condition (the
        # void EIP-2612 statement call, or a recover-equality that stayed a
        # business leaf): record that this open is a permit, not a bare open.
        kind = "permit_sig"
    return Condition(
        kind=kind,  # type: ignore[arg-type]
        description=leaf.get("expression") or "",
    )


# Canonical signature-verification callees: the EVM ``ecrecover`` builtin, the
# OZ ECDSA library (``recover``/``tryRecover``), and OZ SignatureChecker /
# EIP-1271 (``isValidSignature``/``isValidSignatureNow``). Standard library
# entry points, not user identifiers.
_SIGNATURE_VERIFIER_CALLEES = frozenset(
    {"ecrecover", "recover", "tryRecover", "isValidSignature", "isValidSignatureNow"}
)

# EIP-2612 / DAI-style permit and EIP-3009 authorization ABI signatures — the
# canonical self-authorizing token entry points a void statement call gates on.
_PERMIT_FAMILY_SIGNATURES = frozenset(
    {
        "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
        "permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)",
        "transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)",
        "receiveWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)",
        "cancelAuthorization(address,bytes32,uint8,bytes32,bytes32)",
    }
)


def _leaf_is_permit_shape(leaf: LeafPredicate) -> bool:
    """Structural permit witness on a side-condition leaf: an operand carrying
    ``signature_recovery`` provenance, a canonical signature-verifier callee,
    or a void call into the EIP-2612/3009 permit family."""
    for op in leaf.get("operands") or []:
        if op.get("source") == "signature_recovery":
            return True
        callee = op.get("callee")
        if isinstance(callee, str) and callee in _SIGNATURE_VERIFIER_CALLEES:
            return True
    return _is_permit_family_signature(leaf.get("callee_signature"))


def _is_permit_family_signature(signature: Any) -> bool:
    if not isinstance(signature, str) or "(" not in signature:
        return False
    return signature.replace(" ", "") in _PERMIT_FAMILY_SIGNATURES
