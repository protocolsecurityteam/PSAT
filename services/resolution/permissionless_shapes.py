"""Caller-taint default: "public" is an earned verdict, not a fallback.

A revert gate whose proceed-condition is data-dependent on the caller's
identity (``msg.sender`` / ``tx.origin`` taints the condition) is an
authorization unless it matches a known PERMISSIONLESS shape. Authority has
unbounded syntactic shapes (modifiers, inline requires, custom errors,
external ACLs, role registries, …) — permissionlessness has only a few. So
the public/gated verdict is driven by caller-taint plus a finite exclusion
list, never by positive recognition of authority patterns: an unrecognized
caller gate fails CLOSED (``external_check_only`` — gated, principals
unknown), not open.

The exclusion list (each entry structural, never name-based):

  - exclusion polarity (``falsy`` / ``ne``): the predicate names the DENIED
    set — denylist, claim-once, ``!=`` guards. Default-state callers are
    allowed → open (the cofinite/denylist principle, PR #129).
  - comparisons: a caller-keyed quantity threshold (``balances[msg.sender]
    >= amount``) conditions on what the caller holds, uniformly — except
    the deny-by-default caller-keyed *time allowlist*, which authorizes a
    pre-approved caller set (see ``is_caller_keyed_time_allowlist``).
  - self-service equality: the caller compared only against caller-derived
    values (``msg.sender == tx.origin``, ``msg.sender == ecrecover(…)`` —
    self-authorization) or against the caller's own argument (``account ==
    _msgSender()`` — every caller passes for their own value).
  - effectful external bool calls: ``require(token.transferFrom(msg.sender,
    …))`` taints from the caller but moves the caller's own assets; the
    discriminator is callee state-mutability (non-view), not the name. A
    ``view``/``pure`` bool call gated on the caller is an external ACL →
    authority.

Behavior is gated behind ``PSAT_AUTHORITY_EARNED_PUBLIC`` while the corpus
metrics mature; the legacy path keeps the E3/E4 point fixes
(``is_caller_keyed_time_allowlist`` / ``is_caller_keyed_membership_allowlist``,
which the general rule subsumes).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from services.static.contract_analysis_pipeline.predicate_types import LeafPredicate

# The caller's identity, in every frame representation: ``root_caller`` is the
# frame-rewritten root msg.sender inside an inlined callee tree;
# ``signature_recovery`` is a recovered signer — checking it against a
# contract-governed set is delegated authority (self-auth shapes are excluded
# by the equality arm below, and permit flows resolve through the
# ``signature_auth`` leaf kind). Matches the evaluator's ``_CALLER_SOURCES``.
_CALLER_TAINT_SOURCES = ("msg_sender", "tx_origin", "signature_recovery", "root_caller")


def earned_public_enabled() -> bool:
    """The caller-taint default (plan: AUTHORITY_REFACTOR) — ON by default;
    ``PSAT_AUTHORITY_EARNED_PUBLIC=0`` is the release kill-switch back to the
    legacy E3/E4 point-fix path (precedent: #130's env kill switch)."""
    return os.getenv("PSAT_AUTHORITY_EARNED_PUBLIC", "1").lower() in ("1", "true", "yes")


def leaf_is_caller_tainted(leaf: LeafPredicate) -> bool:
    """True iff the leaf's condition is data-dependent on the caller's
    identity: a caller-sourced operand, or a caller-sourced membership key.

    Deliberately reads operand/key sources, NOT ``references_msg_sender``:
    operands are frame-normalized during cross-contract inlining (an inlined
    callee's ``msg.sender`` becomes the bound intermediate, not the end-user
    caller), while the static flag is stamped pre-inlining and would
    over-taint bound frames.
    """
    return _leaf_has_direct_caller_source(leaf) or leaf_caller_taint_is_collapsed(leaf)


def _leaf_has_direct_caller_source(leaf: LeafPredicate) -> bool:
    """Caller taint the leaf states DIRECTLY: a caller-sourced operand or
    membership key. The shape of such a gate is readable, so
    ``is_permissionless_caller_shape`` may classify it."""
    for op in leaf.get("operands") or []:
        if (op or {}).get("source") in _CALLER_TAINT_SOURCES:
            return True
    descriptor = leaf.get("set_descriptor") or {}
    for key in descriptor.get("key_sources") or []:
        if (key or {}).get("source") in _CALLER_TAINT_SOURCES:
            return True
    return False


def leaf_caller_taint_is_collapsed(leaf: LeafPredicate) -> bool:
    """True iff the ONLY evidence of caller-dependence is an origin recorded
    under a collapsing operand's ``derived_from`` (A1 Part B).

    A ``view_call`` / ``computed`` operand collapses its inputs;
    ``derived_from`` is the readable record of what reached it (the digest
    beside it is an opaque hash). A caller consumed as an ARGUMENT of the read
    the gate tests is caller-dependence just as a direct operand is — this is
    the taint an assembly-backed role read (Solady
    ``hasRole(address,uint256)``) hashed away, letting the earned-public arm
    publish ``RoleRegistry.upgradeTo`` as public over a real timelock gate.

    ``None``/absent ``derived_from`` stays not-determined (no taint claim).
    ``external_call`` operands are deliberately excluded: their mutability is
    unknown at the operand level and the value-movement canary rule ("absent
    mutability stays permissionless") already governs that shape, so a
    ``require(target.pull(msg.sender, …))`` result must not become a
    manufactured gate. An inlined bound frame yields ``subject="bound"``
    downstream and never blocks a root public path, so this cannot over-gate
    an intermediate's side condition.
    """
    if _leaf_has_direct_caller_source(leaf):
        return False
    for op in leaf.get("operands") or []:
        if (op or {}).get("source") not in ("view_call", "computed"):
            continue
        for origin in (op or {}).get("derived_from") or []:
            if (origin or {}).get("source") in _CALLER_TAINT_SOURCES:
                return True
    return False


def is_permissionless_caller_shape(leaf: LeafPredicate) -> bool:
    """True iff a caller-tainted gate matches a known permissionless shape
    (so it may open to ``conditional_universal``). See the module docstring
    for the shape-by-shape rationale. Callers must already have established
    caller-taint; this function only discriminates the shape.

    A leaf whose caller-dependence is visible ONLY through a collapsing
    operand's ``derived_from`` is never classified permissionless: every arm
    below is a positive judgement about a shape (which operator, against
    what), and there the comparison the gate performs was never lowered — the
    operand is the opaque result of a read the lifter could not model.
    Claiming a permissionless shape over an unread comparison is the
    absence-as-proof error itself, so it fails closed (A1 Part B).
    """
    if leaf_caller_taint_is_collapsed(leaf):
        return False
    operator = leaf.get("operator")
    kind = leaf.get("kind")

    # Exclusion polarity: the predicate names the DENIED set; the
    # default-state caller proceeds (denylist / claim-once / ``!=`` guard).
    if operator in ("falsy", "ne"):
        return True

    if kind == "comparison":
        # Quantity thresholds on caller-keyed values (balance, allowance,
        # cooldown-elapsed) are uniform self-service conditions — except the
        # deny-by-default time allowlist, which excludes the unset caller.
        return not is_caller_keyed_time_allowlist(leaf)

    if kind == "equality":
        operands = leaf.get("operands") or []
        others = [op for op in operands if (op or {}).get("source") not in _CALLER_TAINT_SOURCES]
        # All operands caller-derived. A genuine BINARY self-comparison
        # (``msg.sender == tx.origin``, ``msg.sender == ecrecover(…)``) is
        # uniform across callers → permissionless. A SINGLE-operand truthy
        # "equality" is a folded caller-keyed bool flag
        # (``validatorSpawner[msg.sender].registered``) — an allowlist —
        # UNLESS the bool is an effectful-call result (``require(sent)``
        # after ``msg.sender.call{value: …}``): value movement, not a flag.
        if not others:
            if operator == "eq" and len(operands) >= 2:
                return True
            return leaf.get("callee_state_mutability") not in (None, "view", "pure")
        # Caller vs the caller's own argument: self-service (renounceRole's
        # ``account == _msgSender()``) — every caller passes for their own.
        if all((op or {}).get("source") == "parameter" for op in others):
            return True
        # An identity authorization compares the caller to an ADDRESS. When
        # no non-caller operand is plausibly address-typed, the "equality"
        # is a folded value comparison on caller-keyed data — an inlined
        # ``!hasPod(msg.sender)`` / ``!isDelegated(msg.sender)`` /
        # ``status[msg.sender][x] == REGISTERED`` collapses the mapping
        # read to its key, leaving ``msg.sender == <uint/enum constant>``.
        # Claim-once / own-status checks, not authorities.
        if not any(_operand_address_plausible(op) for op in others):
            return True
        return False

    if kind == "external_bool":
        # An effectful (non-view) EXTERNAL bool call moves/changes the
        # caller's own state (``transferFrom(msg.sender, …)``) —
        # permissionless. A view/pure bool gated on the caller is an
        # external ACL → authority. An effectful LIBRARY call
        # (``nonview_library``) manipulates the contract's OWN storage —
        # ``pendingAdmins.remove(msg.sender)`` is a membership-consume gate,
        # so it stays an authority. Absent mutability (pre-flag trees,
        # unresolvable callee) stays permissionless so re-resolving an old
        # tree can't manufacture a false-gate on the value-movement canary.
        if leaf.get("callee_state_mutability") not in (None, "nonview"):
            return False
        # A VOID statement call (``external_call_revert``/``try_catch_revert``
        # — the gate is the callee's entire revert surface, not a returned
        # bool) that consumes a caller-supplied bytes32[] hash-path witness
        # is a merkle membership verification against a contract-committed
        # root: an allowlist the caller cannot self-admit into
        # (MembershipManager.wrapEthForEap's EAP snapshot). Contrast permit:
        # the caller signs its OWN authorization (self-auth, permissionless);
        # here the CONTRACT governs the verified structure. Result-checked
        # requires and witness-free void calls (transfer hooks, self-keyed
        # registrations, permit) stay permissionless.
        if leaf.get("gate_kind") in ("external_call_revert", "try_catch_revert"):
            signature = leaf.get("callee_signature") or (leaf.get("set_descriptor") or {}).get("callee_signature") or ""
            if "bytes32[]" in signature:
                return False
        return True

    # membership (truthy caller-keyed = allowlist), signature_auth (never
    # reaches the side-condition path), unknown kinds: not permissionless.
    return False


def _operand_address_plausible(op: Mapping[str, Any]) -> bool:
    """Could this operand hold an Ethereum address — i.e. could an equality
    against the caller be a genuine identity test? Storage/getter/external
    reads qualify (the resolver type-checks them downstream); constants and
    computed values qualify only with explicit address typing. Mirrors the
    static classifier's ``_operand_is_address_typed`` judgment, applied at
    the evaluator so post-inlining folds are covered too."""
    source = (op or {}).get("source")
    if source in ("state_variable", "view_call", "external_call", "self_address"):
        return True
    if source == "constant":
        if op.get("value_type") == "address":
            return True
        value = op.get("constant_value")
        return isinstance(value, str) and value.startswith("0x") and len(value) == 42
    # computed / top / block_context / parameter handled by earlier arms.
    return (op or {}).get("value_type") == "address"


# Every basis tag ``caller_gate_basis`` can stamp on an unresolved CALLER
# gate. The projection blocker keys on these: only a check that is
# positively a caller-discriminating authorization may suppress a sibling
# public path — a targeted downstream-call probe (the Veda teller→vault
# check, basis = gate provenance strings) must keep folding as a side
# condition.
CALLER_GATE_BASIS_TAGS = frozenset(
    {
        "caller_tainted_authority_unresolved",
        "caller_keyed_time_allowlist",
        "caller_keyed_membership_allowlist",
    }
)


def caller_gate_basis(leaf: LeafPredicate) -> str:
    """Stable basis tag for a caller-tainted gate the default fails closed
    on. The two subsumed point-fix shapes keep their historical tags so
    dashboards/tests keyed on them stay meaningful."""
    if is_caller_keyed_time_allowlist(leaf):
        return "caller_keyed_time_allowlist"
    if is_caller_keyed_membership_allowlist(leaf):
        return "caller_keyed_membership_allowlist"
    return "caller_tainted_authority_unresolved"


def is_caller_keyed_time_allowlist(leaf: LeafPredicate) -> bool:
    """True iff the leaf is a *deny-by-default* caller-keyed time allowlist:
    ``if (allowedUntil[msg.sender] < block.timestamp) revert`` — only callers whose
    stored time is still in the future may proceed, and an unset caller (mapping default
    0) is DENIED. That is an authorization over a caller set, not a permissionless side-
    condition, so it must stay gated rather than open to ``conditional_universal``.

    The discriminator is the proceed-relation between the caller's keyed value and
    ``block.timestamp``: a *lower bound* (``caller_value >= now``) excludes the unset
    default → allowlist → gate. This is exactly what distinguishes it from the two shapes
    that legitimately open and must NOT be caught:

      * a share-LOCK (``if (shareUnlockTime[from] > now) revert`` → proceed
        ``value <= now``): the default 0 is ALLOWED, so it opens once unlocked;
      * a balance/allowance condition (``balances[msg.sender] >= amount``): compared
        against a parameter, not ``block.timestamp`` — a permissionless "you can move what
        you hold" check.

    Both are present across the etherfi set; neither matches (operator direction / non-time
    RHS), so this discriminator has zero blast radius there — it only catches the
    deny-by-default time-allowlist shape, which has no instance today.
    """
    if leaf.get("kind") != "comparison":
        return False
    operands = leaf.get("operands") or []
    if len(operands) != 2:
        return False
    caller_idx = next((i for i, o in enumerate(operands) if o.get("source") in _CALLER_TAINT_SOURCES), None)
    time_idx = next(
        (
            i
            for i, o in enumerate(operands)
            if o.get("source") == "block_context" and o.get("block_context_kind") == "timestamp"
        ),
        None,
    )
    if caller_idx is None or time_idx is None:
        return False
    op = leaf.get("operator")
    # Proceed-relation lower-bounds the caller value by the timestamp (deny-by-default):
    #   caller is LHS → "caller OP time"  → allowlist when OP in {gt, gte}
    #   caller is RHS → "time OP caller"  → allowlist when OP in {lt, lte}  (i.e. caller >= time)
    if caller_idx < time_idx:
        return op in ("gt", "gte")
    return op in ("lt", "lte")


def is_caller_keyed_time_denylist(leaf: LeafPredicate) -> bool:
    """True iff the leaf is a *deny-by-exception* caller-keyed time denylist —
    the proceed-relation-inverted twin of ``is_caller_keyed_time_allowlist``:
    ``if (blacklistedUntil[msg.sender] > block.timestamp) revert`` proceeds when
    the caller's keyed time is in the PAST or unset (mapping default 0), so the
    default caller is ALLOWED and only a finite, time-bounded set is excluded.

    That is public modulo a finite exclusion — a cofinite denylist, not an
    authorization — so it must resolve to ``cofinite_blacklist`` (public + a
    deny-by-exception condition), never a caller SET.

    The discriminator is the same operand skeleton as the allowlist, with the
    proceed-relation *upper*-bounding the caller value by the timestamp
    (``caller_value <= now``): the default 0 satisfies it → allow-by-default.
    """
    if leaf.get("kind") != "comparison":
        return False
    operands = leaf.get("operands") or []
    if len(operands) != 2:
        return False
    caller_idx = next((i for i, o in enumerate(operands) if o.get("source") in _CALLER_TAINT_SOURCES), None)
    time_idx = next(
        (
            i
            for i, o in enumerate(operands)
            if o.get("source") == "block_context" and o.get("block_context_kind") == "timestamp"
        ),
        None,
    )
    if caller_idx is None or time_idx is None:
        return False
    op = leaf.get("operator")
    # Proceed-relation upper-bounds the caller value by the timestamp (allow-by-default):
    #   caller is LHS → "caller OP time"  → denylist when OP in {lt, lte}
    #   caller is RHS → "time OP caller"  → denylist when OP in {gt, gte}  (i.e. caller <= time)
    if caller_idx < time_idx:
        return op in ("lt", "lte")
    return op in ("gt", "gte")


def is_caller_keyed_membership_allowlist(leaf: LeafPredicate) -> bool:
    """True iff the leaf is a positive (``truthy``) membership test keyed on the
    caller — ``require(allowed[msg.sender])`` — i.e. an ALLOWLIST: only the
    addresses the contract recorded may proceed; an unset caller (mapping default
    ``false``) is DENIED. That authorizes a caller SET, so it must stay gated (an
    unenumerable external check), never open to ``conditional_universal``/public.

    Polarity is the discriminator, mirroring ``is_caller_keyed_time_allowlist``.
    The two membership shapes that legitimately open and must NOT be caught:
      * a DENYLIST / claim-once (``require(!registered[msg.sender])`` → operator
        ``falsy``): the default-``false`` caller is ALLOWED, so anyone not yet
        listed may call — deliberately public (the self-registration path the
        cofinite refactor preserves).
      * a non-caller-keyed membership (``require(allowedToken[token])``): keyed on
        a parameter, not the caller — a business precondition, not an authority.
    Only the positive + caller-keyed combination is an allowlist, so this re-gates
    exactly the false-opens and nothing that is genuinely permissionless.

    A 1-key caller membership is classified ``business`` on the static side (it
    can't be told from a claim flag by shape alone, see
    ``_classify_authority_membership``) and so reaches the side-condition block;
    multi-key permission tables are ``caller_authority`` and resolve through the
    membership branch instead, untouched.
    """
    if leaf.get("kind") != "membership":
        return False
    if leaf.get("operator") != "truthy":
        return False
    descriptor = leaf.get("set_descriptor") or {}
    keys = descriptor.get("key_sources") or []
    return any(k.get("source") in _CALLER_TAINT_SOURCES for k in keys)
