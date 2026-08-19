"""Equality-principal resolution (``msg.sender == X``)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, cast

from services.resolution.caller_sources import CALLER_SOURCES as _CALLER_SOURCES
from services.static.contract_analysis_pipeline.predicate_types import (
    LeafPredicate,
)

from ..capabilities import (
    CapabilityExpr,
    Condition,
    ExternalCheck,
)
from ..permissionless_shapes import (
    earned_public_enabled,
)
from .authority import (
    _OWNER_SELECTOR,
    _canonical_authority_selector_for_slot,
    _is_pending_authority_accessor_operand,
    _live_resolve_authority_slot,
    _nullary_getter_selector,
    _oz_v5_namespaced_authority_selector,
    _pending_ceiling_capability,
    _public_getter_selector_for_internal_accessor,
    _resolve_authority_via_getters,
    _resolve_param_keyed_authority_mapping,
    _view_call_caller_selects_key,
)
from .binding import _selector_for_signature
from .descriptors import _condition_from_leaf
from .telemetry import _is_zero_address, _state_var_lookup_key

if TYPE_CHECKING:
    from .core import EvaluationContext

logger = logging.getLogger(__name__)


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
                    _canonical_authority_selector_for_slot(name, leaf),
                ],
                bases=["abi_auto_getter", "deunderscore_convention", "slot_name_keyword"],
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
        # clean-zero getter), published as the read that produced it
        # (``slot_read_zero``, with the slot, contract and pinned block);
        # an unreadable slot stays an honest ``lower_bound``. Only bare address
        # scalars carry a slot (the static pass excludes mappings/structs/packed
        # vars), so a non-address word is never misread as a principal.
        slot = op.get("storage_slot")
        if isinstance(slot, str) and not op.get("member_path"):
            slot_result = _live_resolve_authority_slot(ctx, slot)
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
            return _pending_ceiling_capability(cast(dict[str, Any], op), result)
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
        canonical_basis = "deunderscore_convention"
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
            canonical_basis = "deunderscore_convention"
            # OZ-v5 keeps ownership in an ERC-7201 namespace, so an ``owner()``
            # gate inlines to a ``view_call`` of the namespaced storage accessor
            # (``_getAccessControlDefaultAdminRulesStorage()``) rather than a
            # ``_owner()`` helper — recognized by exact accessor name and read
            # through ``owner()``.
            if canonical_selector is None:
                canonical_selector = _oz_v5_namespaced_authority_selector(signature)
                canonical_basis = "standard_namespaced_accessor"
        # Canonical public getter first (when the operand is an internal authority
        # accessor its own selector is dead); otherwise the literal selector.
        candidates = dict.fromkeys((canonical_selector, selector))
        # Which HELPER produced the canonical selector is a control-flow fact at
        # this write point, so the two accessor arms are published as themselves
        # rather than under one label a consumer cannot split: an ERC-7201
        # accessor matched against the standard's table
        # (``standard_namespaced_accessor``) and the leading-underscore naming
        # convention (``deunderscore_convention``). Both are accessor-NAME
        # matches and neither is ranked above the other.
        candidate_basis = {selector: "callee_selector", canonical_selector: canonical_basis}
        result = _resolve_authority_via_getters(
            ctx,
            list(candidates),
            bases=[candidate_basis[c] for c in candidates],
        )
        if result is not None and result.membership_quality == "exact":
            return result
        # Getter-less slot-backed accessor (Governable ``_pendingGovernor`` reads a
        # keccak slot via assembly, no public getter): the slot the static stage
        # carried is AUTHORITATIVE. A non-zero slot IS the principal — on
        # Governable ``_changeGovernor`` never clears the pending slot, so after a
        # completed transfer it stays == governor and the accept gate is
        # satisfiable by the sitting governor; a confirmed-zero slot publishes the
        # read (``slot_read_zero``) and leaves the accept-side-ceiling
        # CLASSIFICATION to ``_pending_ceiling_capability``, which discloses that it
        # rests on the accessor's name; an unreadable slot stays an honest
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
            return _pending_ceiling_capability(cast(dict[str, Any], op), result)
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
