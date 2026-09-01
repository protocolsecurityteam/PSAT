"""Public evaluator API, per-leaf dispatch, and cross-contract inlining.

The recursion cycle evaluate_tree -> _evaluate_leaf ->
_maybe_inline_cross_contract_call -> evaluate_tree_with_registry stays here.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Any, cast

from services.resolution.caller_sources import CALLER_SOURCES as _CALLER_SOURCES
from services.static.static_analysis.predicate_types import (
    LeafPredicate,
    PredicateTree,
    SetDescriptor,
)

from ..capabilities import (
    CapabilityExpr,
    Condition,
    ExternalCheck,
    intersect,
    negate,
    union,
)
from ..permissionless_shapes import (
    caller_gate_basis,
    earned_public_enabled,
    is_caller_keyed_membership_allowlist,
    is_caller_keyed_time_allowlist,
    is_caller_keyed_time_denylist,
    is_permissionless_caller_shape,
    leaf_is_caller_tainted,
)
from .adapters import SetAdapter, _NullAdapter
from .binding import (
    _bind_callee_parameters,
    _callee_argument_operands,
    _normalize_operand_for_call_arg,
    _normalize_tree_for_frame,
    _selector_for_signature,
    _tree_for_signature_or_selector,
)
from .descriptors import (
    _condition_from_leaf,
    _external_check_from_descriptor,
    _normalize_membership_decline_for_negation,
    _resolve_external_bool,
    _resolve_signer_from_leaf,
    _stamp_caller_gate_check,
)
from .equality import (
    _leaf_has_caller_operand,
    _resolve_contextual_equality,
    _resolve_equality_principal,
)
from .materialization import (
    _inline_result_needs_materialization,
    _materialize_external_check_from_candidates,
    _public_without_root_cofinites,
)
from .membership import _resolve_view_key_membership
from .permit import _is_permit_family_signature
from .telemetry import (
    _adapter_declined_external_set,
    _adapter_deferred_pending_index,
    _bump_resolve_counter,
    _record_guard_fire,
    _state_var_lookup_key,
    _tag_caller_subject,
)

logger = logging.getLogger("services.resolution.predicate_evaluator")

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
        cap = _evaluate_leaf(leaf, ctx)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "predicate leaf decision",
                extra={
                    "adapter": "predicate_evaluator",
                    "address": ctx.contract_address,
                    "decision": cap.kind,
                    "reason": leaf.get("authority_role") or leaf.get("kind") or "unknown",
                },
            )
        return cap
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
        if leaf_is_caller_tainted(leaf) and is_caller_keyed_time_denylist(leaf):
            # Deny-by-exception: a caller-keyed time denylist proceeds for the
            # unset/expired caller, so it is public modulo a finite, time-bounded
            # exclusion — a cofinite, not a bare open. Emitting it as a
            # root-subject cofinite is what lets the refine-only inline guard's
            # counterfactual distinguish it from a laundered allowlist and spare
            # it (leave it public) instead of gating it.
            return CapabilityExpr.cofinite_blacklist(
                [],
                blacklist_quality="lower_bound",
                conditions=[_condition_from_leaf(leaf)],
                subject="root",
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
            # static classifier stamps these leaves ``business`` (see
            # ``external_bool_leaf_is_gate_shape``: real external ACLs are
            # view/pure), so they normally resolve as side conditions above;
            # this arm is the resolution plane's own guard for any
            # delegated_authority-tagged leaf that still arrives with the
            # value-movement shape. Effectful LIBRARY calls (own-storage
            # membership consume) and void merkle-witness verifications keep
            # the gated path — see is_permissionless_caller_shape; they fall
            # through to the external_set descriptor/adapter resolution below.
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
        # A comparison leaf only reaches here with role caller_authority /
        # delegated_authority — i.e. the writer-gate already judged the
        # caller-keyed mapping admin-curated (the value can't be self-
        # acquired). So this is an authority threshold, NOT a self-service
        # quantity gate (which stays role=business and opens to public in the
        # side-condition block above). ``is_permissionless_caller_shape`` is
        # shape-only and role-blind — consulting it here would re-open a
        # promoted authority to public, the caller-keyed-threshold fail-open.
        if earned_public_enabled() and leaf_is_caller_tainted(leaf):
            descriptor = leaf.get("set_descriptor")
            if descriptor is not None and _has_caller_keyed_value_predicate(leaf):
                cap = ctx.adapter.enumerate(descriptor, ctx.contract_address)
                # Honor an authoritative enumeration — populated (restricted
                # holders) OR an authoritative empty (provably nobody now).
                if cap.kind == "finite_set" and (
                    cap.members or cap.membership_quality == "exact" or cap.empty_reason == "empty_by_design"
                ):
                    return _tag_caller_subject(cap, ctx)
            # No authoritative answer (cold / unsupported / non-exact empty):
            # fail CLOSED — gated, principals unknown — never public.
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

    chain_id = getattr(outer_ctx, "chain_id", None)
    if not isinstance(chain_id, int):
        # ctx.chain_id is required (inv. 6); a chainless inline can't key its
        # recursion stack or resolve the callee on a chain.
        return None
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
    from db.queue.typed import load_assessment_inputs
    from services.resolution.capability_resolver import find_analysis_job_for_address

    lookup = find_analysis_job_for_address(
        session,
        registry_addr,
        required_artifact="assessment",
        completed_only=False,
    )
    if lookup is None:
        return None
    inputs = load_assessment_inputs(get_artifact, session, lookup.analysis_job.id)
    if inputs is None:
        return None
    _static_facts, artifact, _effects = inputs
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
        ctx.adapter._registry  # pyright: ignore[reportAttributeAccessIssue]
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
    if (
        leaf.get("operator") == "truthy"
        and leaf_is_caller_tainted(leaf)
        and not is_permissionless_caller_shape(leaf)
        and _public_without_root_cofinites(resolved)
    ):
        # Refine-only invariant: un-inlined, this caller-tainted delegated gate
        # fails closed; an inline result that projects public would un-gate it,
        # so keep the outer delegated check. A public verdict that survives
        # removing root-subject cofinites is a laundered allowlist, not a
        # legitimate deny-by-exception denylist — only the former fires here.
        cap = _external_check_from_descriptor(leaf, descriptor, ctx)
        if cap.check is not None:
            extra = dict(cap.check.extra or {})
            basis = list(extra.get("basis") or [])
            if "inline_refine_only_guard" not in basis:
                basis.append("inline_refine_only_guard")
            extra["basis"] = basis
            cap = replace(cap, check=replace(cap.check, extra=extra))
        _record_guard_fire(descriptor)
        return cap
    return resolved
