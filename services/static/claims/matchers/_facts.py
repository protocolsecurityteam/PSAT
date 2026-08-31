"""Shared Plane-0 fact readers for the behavior-family matchers.

Underscore-prefixed so matcher auto-discovery skips it — it registers no
claims. Everything here reads the tolerant :class:`ClaimContext` view (effects
facts + predicate trees + the Slither subject) and, where a signal only exists
in IR, the ``contract`` object. Per-contract derivations that several triggers
share (pause targets, address-pointer writers) are memoized against the context
instance so a full ``build_claims`` pass computes them once.
"""

from __future__ import annotations

import re
from typing import Any
from weakref import WeakKeyDictionary

from utils.scoring_status import (
    SELF_SERVICE_DISCLOSE_SIBLING,
    SELF_SERVICE_DISCLOSE_UPGRADE,
    SELF_SERVICE_STATE_PROVEN,
)

from ...static_analysis.record_ordering import W2_BASIS_CLEAR_DOMINATES_CALLS
from ..context import ClaimContext, abi_selector, selector_of

# Per-context memo tables (keyed by the ClaimContext instance, which lives only
# for one contract's build_claims pass).
_PAUSE_TARGETS: WeakKeyDictionary[ClaimContext, set[tuple[str, str | None]]] = WeakKeyDictionary()
_MANDATORY_READS: WeakKeyDictionary[ClaimContext, set[tuple[str, str | None]]] = WeakKeyDictionary()
_MANDATORY_READS_BY_FUNCTION: WeakKeyDictionary[ClaimContext, dict[str, set[tuple[str, str | None]]]] = (
    WeakKeyDictionary()
)
_MANDATORY_LATCH_READS: WeakKeyDictionary[ClaimContext, set[tuple[str, str | None]]] = WeakKeyDictionary()
_MANDATORY_LATCH_READS_BY_FUNCTION: WeakKeyDictionary[ClaimContext, dict[str, set[tuple[str, str | None]]]] = (
    WeakKeyDictionary()
)
_TOTAL_SUPPLY_VARS: WeakKeyDictionary[ClaimContext, set[str]] = WeakKeyDictionary()


# ---------------------------------------------------------------------------
# Predicate-tree readers
# ---------------------------------------------------------------------------


def _iter_leaves(tree: Any) -> Any:
    if not isinstance(tree, dict):
        return
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if isinstance(leaf, dict):
            yield leaf
        return
    for child in tree.get("children") or []:
        yield from _iter_leaves(child)


def tree_has_role(tree: Any, roles: tuple[str, ...]) -> bool:
    return any(leaf.get("authority_role") in roles for leaf in _iter_leaves(tree))


def tree_is_authority_gated(tree: Any) -> bool:
    """The function's guard depends on the caller's identity/authority."""
    return tree_has_role(tree, ("caller_authority", "delegated_authority"))


def tree_is_one_shot(tree: Any) -> bool:
    """An initializer latch (``initializer``/``reinitializer``) — writes here
    are a one-time set, never a recurring toggle."""
    return tree_has_role(tree, ("one_shot",))


def _mandatory_operands(tree: Any) -> set[tuple[str, str | None]]:
    """State-var operands read on a *mandatory* gate path — every ancestor is a
    conjunction (``AND``), so the operand's value can force a revert with no
    ``OR`` escape. This is the structural separator between a real pause gate
    (``if (paused) revert`` at the top level) and a mode selector under a branch
    (``if (executorRequired) require(sig)`` — reachable via an ``OR`` in the
    tree)."""
    out: set[tuple[str, str | None]] = set()

    def walk(node: Any, mandatory: bool) -> None:
        if not isinstance(node, dict):
            return
        op = node.get("op")
        if op == "LEAF":
            if not mandatory:
                return
            leaf = node.get("leaf")
            if not isinstance(leaf, dict):
                return
            for operand in leaf.get("operands") or []:
                if not isinstance(operand, dict):
                    continue
                name = operand.get("state_variable_name")
                if not name:
                    continue
                member_path = operand.get("member_path") or []
                out.add((name, member_path[0] if member_path else None))
            return
        child_mandatory = mandatory and op != "OR"
        for child in node.get("children") or []:
            walk(child, child_mandatory)

    walk(tree, True)
    return out


def mandatory_gate_reads(ctx: ClaimContext) -> set[tuple[str, str | None]]:
    """State read as a mandatory gate by a state-changing entry point."""
    cached = _MANDATORY_READS.get(ctx)
    if cached is not None:
        return cached
    reads: set[tuple[str, str | None]] = set()
    for function_reads in mandatory_gate_reads_by_function(ctx).values():
        reads |= function_reads
    _MANDATORY_READS[ctx] = reads
    return reads


def mandatory_gate_reads_by_function(ctx: ClaimContext) -> dict[str, set[tuple[str, str | None]]]:
    """Mandatory state reads keyed by state-changing function signature."""

    cached = _MANDATORY_READS_BY_FUNCTION.get(ctx)
    if cached is not None:
        return cached
    reads: dict[str, set[tuple[str, str | None]]] = {}
    for signature in ctx.function_signatures():
        if ctx.effect_record(signature).get("state_changing") is not True:
            continue
        tree = ctx.predicate_tree(signature)
        if tree is not None:
            reads[signature] = _mandatory_operands(tree)
    _MANDATORY_READS_BY_FUNCTION[ctx] = reads
    return reads


def _mandatory_latch_operands(tree: Any) -> set[tuple[str, str | None]]:
    """Mandatory reads with boolean/constant-equality latch shape."""

    out: set[tuple[str, str | None]] = set()

    def walk(node: Any, mandatory: bool) -> None:
        if not isinstance(node, dict):
            return
        op = node.get("op")
        if op == "LEAF":
            if not mandatory:
                return
            leaf = node.get("leaf")
            if not isinstance(leaf, dict):
                return
            operator = leaf.get("operator")
            operands = [operand for operand in (leaf.get("operands") or []) if isinstance(operand, dict)]
            absorbed = [operand for operand in (leaf.get("absorbed_operands") or []) if isinstance(operand, dict)]
            if operator not in ("truthy", "falsy", "eq", "ne"):
                return
            if operator in ("eq", "ne") and not any(
                operand.get("source") == "constant" for operand in (*operands, *absorbed)
            ):
                return
            for operand in (*operands, *absorbed):
                name = operand.get("state_variable_name")
                if not isinstance(name, str) or not name:
                    continue
                member_path = operand.get("member_path") or []
                member = member_path[0] if isinstance(member_path, list) and member_path else None
                out.add((name, member if isinstance(member, str) else None))
            return
        child_mandatory = mandatory and op != "OR"
        for child in node.get("children") or []:
            walk(child, child_mandatory)

    walk(tree, True)
    return out


def mandatory_latch_reads(ctx: ClaimContext) -> set[tuple[str, str | None]]:
    """Numeric/bitmap reads that carry a mandatory latch comparison."""

    cached = _MANDATORY_LATCH_READS.get(ctx)
    if cached is not None:
        return cached
    reads: set[tuple[str, str | None]] = set()
    for function_reads in mandatory_latch_reads_by_function(ctx).values():
        reads |= function_reads
    _MANDATORY_LATCH_READS[ctx] = reads
    return reads


def mandatory_latch_reads_by_function(ctx: ClaimContext) -> dict[str, set[tuple[str, str | None]]]:
    """Latch-shaped mandatory reads keyed by state-changing function."""

    cached = _MANDATORY_LATCH_READS_BY_FUNCTION.get(ctx)
    if cached is not None:
        return cached
    reads: dict[str, set[tuple[str, str | None]]] = {}
    for signature in ctx.function_signatures():
        if ctx.effect_record(signature).get("state_changing") is not True:
            continue
        tree = ctx.predicate_tree(signature)
        if tree is not None:
            reads[signature] = _mandatory_latch_operands(tree)
    _MANDATORY_LATCH_READS_BY_FUNCTION[ctx] = reads
    return reads


# ---------------------------------------------------------------------------
# Parameter destination constraints
# ---------------------------------------------------------------------------
#
# Answers, per ABI parameter: *does a mandatory revert gate reference this
# parameter between entry and sink?* — three states:
#
#   ``constrained``           a mandatory leaf references the parameter against
#                             something outside the caller's control, and the
#                             verdict names which guard and where.
#   ``unconstrained_proven``  the predicate tree is present, NO mandatory leaf
#                             pins or opaquely touches the parameter, AND the
#                             projection was checkable: every mandatory leaf's
#                             operand account is complete as far as this walk
#                             can verify. A leaf's SILENCE about a parameter is
#                             only evidence when the account of what it reads is
#                             itself trustworthy — the governing rule cuts here
#                             hardest, because this state is a published proof
#                             of absence.
#   ``not_determined``        the analysis did not settle it: no tree, an
#                             unsupported/opaque mandatory leaf, a
#                             parameter-referencing leaf whose semantics this
#                             walk cannot classify, or a leaf whose operand
#                             projection is demonstrably or possibly incomplete.
#
# Three projection-completeness checks guard the ``unconstrained_proven`` state
# (each one is a real, measured lossiness of the leaf projection — reading its
# silence as proof demonstrably over-claims on production rows):
#
#   * A leaf whose ``expression`` names a declared parameter the leaf's operands
#     do not account for (CumulativeMerkleDrop.claim's ``! verify(account, …)``
#     projected only ``expectedMerkleRoot``) blocks that parameter.
#   * A non-membership leaf reading a keyed collection (mapping/array state var)
#     with no account of the KEY (EtherFiTimelock's ``isOperationReady(id)``
#     folds ``_timestamps[id]`` to the bare mapping — ``id`` is parameter-derived
#     and invisible) blocks every parameter: the dropped key can be any of them.
#   * A function record with no ``parameter_names`` list cannot be
#     expression-checked at all, so nothing about it may be called proven.
#
# ``confidence`` on the leaf is deliberately NOT consulted: it grades the
# authority classification, not the operand account — the same lossy
# ``isOperationReady(id)`` fold carries ``low`` on its business half and
# ``high`` on its time half, so it cannot discriminate a complete projection
# from a lossy one in either direction.
#
# Standard-gate pre-pass: on a proven OZ TimelockController execute entry every
# ABI parameter is re-hashed into the operation id a mandatory gate requires
# scheduled, and on a proven Safe ``execTransaction`` every parameter rides
# under the owners' signature threshold. Those commitments come from the
# STANDARD's shape (the same gates ``exec.arbitrary`` uses), not from the tree
# walk — and routing them through here means the flow witness and the exec
# witness publish the SAME verdict for the same parameter instead of
# contradicting each other. Safe's module-exec entries
# (``execTransactionFromModule*``) are deliberately NOT in the pre-pass: their
# standard gate is ``modules[msg.sender] != address(0)`` — an allowlist on the
# CALLER. No signature commits ``to``; an enabled module calls any target with
# any calldata, so the standard commits nothing about any parameter and the
# ordinary tree walk answers instead (publishing ``pins: True`` there would be a
# proof fabricated from the standard's shape).
#
# The tightened rule: a mandatory leaf constrains a
# parameter only if it is NOT the function's own effect sink. The sink's own
# revert surface mentions its destination argument vacuously —
# ``safeTransfer(_to, bal)`` reverting on failure is not a constraint on
# ``_to``, and neither is ``target.call(data)`` reverting on ``!ok`` — so a
# leaf that IS the revert surface of the call carrying the described effect is
# transparent. Without it ``sweepDust`` — the positive control — classifies as
# constrained, which is a false positive.
#
# The join is against the FACTS (``value_flows`` selectors and
# ``_facts.body_sinks``), never against a claim witness's ``sink_ids``, which is
# empty on ``value_router``. It matches a selector OR the callee's bare name,
# because a predicate leaf records the DECLARED signature
# (``exit(address,IERC20,uint256,…)``) whose hash is not the selector the sink
# recorded — there is no selector to compare on exactly that shape.
#
# ``external_call_revert`` leaves are NOT blanket-excluded. Two independent
# discriminators keep the genuine ones: a **view/pure** callee moves nothing, so
# its revert surface is a real precondition (``forwardExternalCall``'s
# ``deployedEtherFiNodes(...)``), and an effectful callee that is NOT one of
# this function's effect sinks is left unresolved rather than assumed away.
#
# ``derived_from`` (the commitment provenance) is consumed but NOT treated as
# ground truth: it is flow-insensitive, so a local reassignment misbinds the
# origin — it can OMIT a genuinely committed parameter and PUBLISH one that only
# reaches the name on another branch. Two bounds follow:
#   * positive direction: a ``derived_from`` binding may prove ``constrained``
#     (the guard is real), but never ``pins: True`` — the verdict carries
#     ``pins: None`` and ``binding: "derived_from"``, because a flow-insensitive
#     union cannot prove the guard confines THIS parameter on every path, and
#     ``pins`` is the one field allowed to soften the caller-chosen reading;
#   * negative direction: a parameter's ABSENCE from every ``derived_from``
#     proves nothing, so any mandatory leaf carrying a computed operand blocks
#     ``unconstrained_proven`` for every parameter it does not positively
#     constrain (they land on ``not_determined``).

_MEMBERSHIP_SET_KINDS = frozenset({"mapping_membership", "array_contains", "external_set"})
_EXTERNAL_GATE_KINDS = frozenset({"external_call_revert", "try_catch_revert"})

# Whether each guard kind PINS the destination — the three-state answer a
# ``constrained`` verdict carries as ``pins`` (a consumer must be able to
# tell proven-pins from proven-does-not-pin from not-determined, because only
# the first may soften the caller-chosen / theft-shaped reading downstream):
#
#   True   the guard confines the parameter to a set the caller did not write
#          (an allowlist, a hash/signature commitment, equality vs storage).
#   False  the guard provably does NOT pin: a denylist excludes a set and
#          leaves the rest of the address space freely chosen; an ordering
#          bound never confines an identity.
#   None   the guard is real but its set semantics are another contract's
#          (``external_call_revert``): a ``nonBlacklisted(addr)`` blacklist and
#          a ``deployedEtherFiNodes(addr)`` allowlist present the identical
#          revert-surface shape here, so whether it pins is NOT determined —
#          and on the local artifacts every ``constrained`` flow row (4/4,
#          EtherFiRedemptionManager.redeem*) is this kind and is in fact a
#          blacklist. Publishing those as if they pinned dropped the
#          caller-chosen signal on all four.
_GUARD_PINS: dict[str, bool | None] = {
    "mapping_allowlist": True,
    "hash_commitment": True,
    "signature_witness": True,
    "equality_vs_storage": True,
    "equality_vs_caller": True,
    "denylist": False,
    "numeric_bound": False,
    "external_call_revert": None,
}

# An ``unsupported`` leaf publishes ``operands: []`` and ``parameter_indices:
# []`` unconditionally (``predicates._unsupported_leaf``), so its silence about
# parameters is a construction artifact and it must normally block the
# unconstrained proof. Two reason classes are exceptions **because of what the
# gate's inputs structurally are**, not because they look harmless:
#
#   ``solidity_call_abi.decode()…``  gates on a CALL'S RETURNDATA. Its input is
#       the callee's output; the constraint it expresses is that callee's
#       revert surface, which the sibling ``external_bool`` leaf already carries
#       WITH the callee identity and the parameters. (SafeERC20's
#       ``_callOptionalReturn`` emits exactly this pair.)
#   ``solidity_call_tload(…)`` / ``solidity_call_sload(…)``  gates on a storage
#       slot read; its input is a slot literal.
#
# Neither can reach an ABI parameter, so neither blocks. Every other reason —
# ``opaque_try_catch`` above all, whose expression routinely carries parameters
# (``depositAsset.permit(msg.sender, vault, depositAmount, …)``) — keeps
# blocking, and an unrecognised reason blocks by default (fail toward
# ``not_determined``). Census over every mandatory unsupported leaf in the local
# artifacts: tload 68, opaque_try_catch 60, abi.decode 31 — no other reason
# exists there, and a new one arriving under-claims rather than over-claims.
_NON_PARAMETRIC_UNSUPPORTED_PREFIXES = (
    "solidity_call_abi.decode()",
    "solidity_call_tload(",
    "solidity_call_sload(",
)


def _unsupported_leaf_is_parametric(leaf: dict[str, Any]) -> bool:
    reason = leaf.get("unsupported_reason")
    if not isinstance(reason, str):
        return True
    return not reason.startswith(_NON_PARAMETRIC_UNSUPPORTED_PREFIXES)


_PARAM_CONSTRAINTS: WeakKeyDictionary[ClaimContext, dict[tuple[str, str], dict[int, dict[str, Any]]]] = (
    WeakKeyDictionary()
)
_KEYED_COLLECTIONS: WeakKeyDictionary[ClaimContext, frozenset[str]] = WeakKeyDictionary()

_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


def _declared_param_indices(ctx: ClaimContext, function: str) -> dict[str, int] | None:
    """``{parameter_name: abi_index}`` from the effect record's
    ``parameter_names``, or ``None`` when the record does not carry the list
    (every function in the local corpus does — 2,415/2,415 — so ``None`` is the
    stale-artifact shape). Without it the expression cross-check below cannot
    run, and an uncheckable projection never supports a proof of absence."""
    record = ctx.effect_record(function)
    names = record.get("parameter_names")
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        return None
    return {name: index for index, name in enumerate(names) if name}


def _unaccounted_param_mentions(leaf: dict[str, Any], name_indices: dict[str, int], accounted: set[int]) -> set[int]:
    """Parameter indices the leaf's rendered ``expression`` names but its
    operand account does not carry. The expression is the builder's own record
    of what the gate textually touches; a parameter present there and absent
    from the operands is the projection dropping a reference
    (``! verify(account, …)`` carrying only ``expectedMerkleRoot``), and that
    silence must not become a proof. Free text in revert strings can collide
    with a parameter name — that costs an under-claim (``not_determined``),
    never an over-claim."""
    expression = leaf.get("expression")
    if not isinstance(expression, str) or not expression or not name_indices:
        return set()
    out: set[int] = set()
    for token in _IDENTIFIER_RE.findall(expression):
        index = name_indices.get(token)
        if index is not None and index not in accounted:
            out.add(index)
    return out


def keyed_collection_vars(ctx: ClaimContext) -> frozenset[str]:
    """State variables declared as keyed collections (mappings / arrays),
    learned from the ``declared_type`` the state-write facts record anywhere in
    the contract (cached per contract). Used to spot a leaf that folded an
    ELEMENT read down to the bare collection variable — the key is gone, and
    with it any account of which parameter selects the gating cell."""
    cached = _KEYED_COLLECTIONS.get(ctx)
    if cached is not None:
        return cached
    out: set[str] = set()
    for signature in ctx.function_signatures():
        for write in state_writes(ctx, signature, body_only=False):
            var = write.get("var")
            declared = write.get("declared_type")
            if (
                isinstance(var, str)
                and isinstance(declared, str)
                and (declared.startswith("mapping(") or declared.endswith("]"))
            ):
                out.add(var)
    frozen = frozenset(out)
    _KEYED_COLLECTIONS[ctx] = frozen
    return frozen


def _reads_keyed_collection_without_key(leaf: dict[str, Any], collections: frozenset[str]) -> bool:
    """True when a non-membership leaf carries a mapping/array state variable as
    a bare operand. Solidity cannot compare a collection itself, so the operand
    is an element read whose key the projection dropped
    (``_timestamps[id] > _DONE_TIMESTAMP`` recorded as ``_timestamps`` vs
    ``_DONE_TIMESTAMP``); the dropped key may be derived from any parameter. A
    membership leaf accounts its keys in ``set_descriptor.key_sources`` and an
    array ``length`` read has no element key, so both pass."""
    if not collections:
        return False
    if leaf.get("kind") == "membership" and isinstance(leaf.get("set_descriptor"), dict):
        return False
    for operand in leaf.get("operands") or []:
        if not isinstance(operand, dict) or operand.get("source") != "state_variable":
            continue
        if operand.get("state_variable_name") not in collections:
            continue
        member_path = operand.get("member_path") or []
        if member_path and member_path[-1] == "length":
            continue
        return True
    return False


def standard_destination_commitment(ctx: ClaimContext, function: str) -> dict[str, Any] | None:
    """The standard-gate constraint verdict covering EVERY ABI parameter of a
    proven standard exec entry, or ``None`` where the function is not one.

    OZ TimelockController ``execute``/``executeBatch`` re-derive
    ``hashOperation(target, value, payload, predecessor, salt)`` and require the
    operation scheduled-and-ready — a hash commitment over the full parameter
    list. Safe ``execTransaction`` checks the owners' signatures over the
    transaction — a signature witness over the full parameter list. These are
    the same contract-shape gates ``exec.arbitrary`` proves its standard tier
    with; publishing the flow verdict from the same source keeps the two
    witnesses on one function from ever contradicting each other.

    Safe's module-exec entries (``execTransactionFromModule`` /
    ``...ReturnData``) get NO commitment here, although they sit in
    ``SAFE_EXEC_SELECTORS`` and earn ``exec.arbitrary`` at the standard tier:
    their gate is ``modules[msg.sender] != address(0)`` — an allowlist on the
    CALLER that says nothing about the destination. An enabled module calls any
    target with any calldata; the destination answer must come from the
    mandatory-gate tree walk, which sees exactly that caller-keyed gate."""
    from ._gates import SAFE_EXEC_TRANSACTION, TIMELOCK_EXECUTE_SELECTORS, is_oz_timelock_gate, is_safe_gate

    selector = ctx.canonical_selector(function)
    if selector in TIMELOCK_EXECUTE_SELECTORS and is_oz_timelock_gate(ctx):
        return {"state": "constrained", "guard": "hash_commitment", "pins": True, "binding": "standard_gate"}
    if selector == SAFE_EXEC_TRANSACTION and is_safe_gate(ctx):
        return {"state": "constrained", "guard": "signature_witness", "pins": True, "binding": "standard_gate"}
    return None


def _operand_param_indices(operand: Any) -> tuple[set[int], set[int], bool]:
    """``(direct, derived, opaque)`` parameter references of one operand.

    ``direct`` — the operand IS the parameter. ``derived`` — the operand is a
    computed value whose ``derived_from`` provenance includes the parameter
    (flow-insensitive). ``opaque`` — the operand can involve a
    parameter without saying so.

    Every ``computed`` operand is opaque, including one whose ``derived_from``
    resolves entirely to parameter/state/constant origins. ``derived_from`` is
    flow-insensitive: it can OMIT an origin that genuinely feeds
    the value (Teller ``depositAsset``) while publishing one that only reaches
    the name on another branch. A list that LOOKS complete therefore proves
    nothing in the negative direction — it contributes positive ``derived``
    bindings and nothing else."""
    direct: set[int] = set()
    derived: set[int] = set()
    opaque = False
    if not isinstance(operand, dict):
        return direct, derived, True
    source = operand.get("source")
    if source == "parameter":
        index = operand.get("parameter_index")
        if isinstance(index, int):
            direct.add(index)
        else:
            opaque = True
    elif source == "computed":
        opaque = True
        provenance = operand.get("derived_from", None)
        if isinstance(provenance, list):
            for origin in provenance:
                if isinstance(origin, dict) and origin.get("source") == "parameter":
                    index = origin.get("parameter_index")
                    if isinstance(index, int):
                        derived.add(index)
    elif source == "top":
        opaque = True
    return direct, derived, opaque


def _leaf_param_refs(leaf: dict[str, Any]) -> tuple[set[int], set[int], bool]:
    """All parameter references of a leaf: operands, ``set_descriptor``
    key sources, and the leaf's own ``parameter_indices`` list (which the
    builder populates from provenance the operand projection may have
    dropped)."""
    direct: set[int] = set()
    derived: set[int] = set()
    opaque = leaf.get("kind") == "unsupported" and _unsupported_leaf_is_parametric(leaf)
    operands = [o for o in (leaf.get("operands") or []) if isinstance(o, dict)]
    descriptor = leaf.get("set_descriptor")
    if isinstance(descriptor, dict):
        operands.extend(k for k in (descriptor.get("key_sources") or []) if isinstance(k, dict))
    for operand in operands:
        d, dv, op = _operand_param_indices(operand)
        direct |= d
        derived |= dv
        opaque = opaque or op
    for index in leaf.get("parameter_indices") or []:
        if isinstance(index, int):
            direct.add(index)
    return direct, derived, opaque


def _leaf_callee_selector(leaf: dict[str, Any]) -> str | None:
    selector = leaf.get("callee_selector")
    if isinstance(selector, str) and selector:
        return selector
    return selector_of(leaf.get("callee_signature"))


def _leaf_callee_name(leaf: dict[str, Any]) -> str | None:
    """The bare callee name of a leaf's signature. The selector is preferred
    wherever it exists; this is the fallback for a DECLARED signature carrying
    an interface-typed parameter (``exit(address,IERC20,…)``), whose hash is not
    the selector the sink recorded and so can never join on one."""
    signature = leaf.get("callee_signature")
    if not isinstance(signature, str) or "(" not in signature:
        return None
    name = signature.split("(", 1)[0].strip()
    return name or None


def _is_external_callee_leaf(leaf: dict[str, Any]) -> bool:
    """A leaf whose truth is (or includes) another contract's answer: a
    result-checked external bool, a signature check, or a statement call whose
    entire revert surface gates the path."""
    if leaf.get("kind") in ("external_bool", "signature_auth"):
        return True
    if leaf.get("gate_kind") in _EXTERNAL_GATE_KINDS:
        return True
    return bool(leaf.get("callee_signature"))


def effect_sink_identities(ctx: ClaimContext, function: str, *, mode: str) -> tuple[set[str], set[str]]:
    """``(selectors, bare callee names)`` of the calls that CARRY the effect a
    claim is describing — the transparency set for the tightened rule.

    ``mode="value_flow"`` names the moves in ``value_flows`` plus, on a
    ``value_router`` flow, its recorded ``router_ops`` — the specific call(s)
    the producer's walk crossed to find the move. The routed flow's own
    selector belongs to the CALLEE's inner transfer, so the router call's
    identity must be carried explicitly; transparency is earned per op, never
    granted to every body call (a nonview destination guard beside the router —
    ``guard.checkDestination(to)`` before ``vault.exit(to, …)`` — is NOT the
    op carrying the move, and its leaf must block the negative proof instead
    of being swallowed). A routed flow with no recorded ``router_ops`` (an
    artifact produced before the field existed) makes nothing extra
    transparent: its router leaf then blocks, i.e. the function falls to
    ``not_determined`` — the failure direction over-claims nothing and can
    never mint ``unconstrained_proven``.

    ``mode="external_call"`` names only the body calls whose destination is
    PROVEN parameter-rooted in IR (:func:`_taint.proven_param_destination_call_identities`).
    For a claim whose effect IS an external call (``exec.arbitrary``), the
    described call's own revert surface is vacuous about the caller's choice —
    but that vacuousness is a property of the call's destination, not of being
    a body call. A nonview callee with a fixed or unresolved receiver (a
    Safe/Zodiac transaction guard vetting ``(target, data)``) stays OUTSIDE
    this set, so its mandatory leaf blocks the negative proof below instead of
    being swallowed; without it a guarded function and an open one published
    the same ``unconstrained_proven``. Without a Slither subject nothing is
    provable and the set is empty — every effectful-callee leaf then blocks,
    which under-claims and never proves."""
    if mode == "external_call":
        from . import _taint

        identities = _taint.proven_param_destination_call_identities(ctx, function)
        if identities is None:
            return set(), set()
        return identities
    selectors: set[str] = set()
    names: set[str] = set()
    for flow in value_flows(ctx, function):
        selector = flow.get("selector")
        if isinstance(selector, str) and selector:
            selectors.add(selector)
        for op in flow.get("router_ops") or []:
            if not isinstance(op, dict):
                continue
            op_selector = op.get("selector")
            if isinstance(op_selector, str) and op_selector:
                selectors.add(op_selector)
            op_name = op.get("callee")
            if isinstance(op_name, str) and op_name:
                names.add(op_name)
    return selectors, names


def _classify_constraining_leaf(leaf: dict[str, Any], via_derived: bool) -> str | None:
    """The guard kind a mandatory leaf pins a referenced parameter with, or
    ``None`` when the leaf pins nothing (a zero-address check, a compare whose
    only other operand is a constant). Callers have already handled the
    external-callee exclusion, so this only reads the leaf's own structure."""
    kind = leaf.get("kind")
    operator = leaf.get("operator")
    descriptor = leaf.get("set_descriptor")
    if kind == "membership" and isinstance(descriptor, dict) and descriptor.get("kind") in _MEMBERSHIP_SET_KINDS:
        # The polarity-folded leaf records the ALLOWED form: truthy membership
        # is an allowlist; falsy is a denylist — recorded as a guard, but a
        # denylist excludes a set without pinning the destination, and the
        # consumer must keep treating it as caller-chosen.
        return "denylist" if operator in ("falsy", "ne") else "mapping_allowlist"
    if kind == "signature_auth":
        return "signature_witness"
    if _is_external_callee_leaf(leaf):
        return "external_call_revert"
    if kind in ("equality", "comparison"):
        if operator in ("ne", "falsy"):
            # Allowed form "!= x" excludes one value; it pins nothing.
            return None
        if via_derived:
            return "hash_commitment"
        operands = [o for o in (leaf.get("operands") or []) if isinstance(o, dict)]
        if any(o.get("source") == "state_variable" for o in operands):
            return "equality_vs_storage" if kind == "equality" else "numeric_bound"
        if any(o.get("source") in ("msg_sender", "tx_origin") for o in operands):
            return "equality_vs_caller"
        if any(o.get("source") in ("external_call", "view_call") for o in operands):
            return "numeric_bound" if kind == "comparison" else "equality_vs_storage"
        return None
    return None


def _mandatory_leaves_with_paths(tree: Any) -> list[tuple[dict[str, Any], list[int]]]:
    out: list[tuple[dict[str, Any], list[int]]] = []

    def walk(node: Any, mandatory: bool, path: list[int]) -> None:
        if not isinstance(node, dict):
            return
        op = node.get("op")
        if op == "LEAF":
            leaf = node.get("leaf")
            if mandatory and isinstance(leaf, dict):
                out.append((leaf, path))
            return
        for index, child in enumerate(node.get("children") or []):
            walk(child, mandatory and op != "OR", path + [index])

    walk(tree, True, [])
    return out


def param_constraints(ctx: ClaimContext, function: str, *, mode: str = "value_flow") -> dict[int, dict[str, Any]]:
    """Per-parameter-index constraint verdicts for ``function`` (memoized).

    ``mode`` selects which calls carry the described effect and are therefore
    transparent — see :func:`effect_sink_identities`.

    Returns ``{parameter_index: verdict}`` where each verdict is a witness
    fragment ``{"state": ..., "guard": ..., "binding": ..., "leaf_path": ...}``.
    The pseudo-index ``-1`` carries the function-wide default for indices with
    no verdict of their own; callers use :func:`param_constraint`, which folds
    it in (``unconstrained_proven`` under a clean tree, ``not_determined``
    otherwise)."""
    memo = _PARAM_CONSTRAINTS.setdefault(ctx, {})
    cached = memo.get((function, mode))
    if cached is not None:
        return cached

    verdicts: dict[int, dict[str, Any]] = {}

    standard = standard_destination_commitment(ctx, function)
    if standard is not None:
        # The standard's own gate commits every parameter; the tree walk below
        # could only re-derive a weaker answer from a lossier projection.
        verdicts[-1] = standard
        memo[(function, mode)] = verdicts
        return verdicts

    tree = ctx.predicate_tree(function)
    if tree is None:
        # No tree at all: nothing is settled for any parameter. A missing tree
        # is NOT proof that no gate exists — reading it as "unconstrained" is
        # exactly the over-claim this state exists to prevent.
        verdicts[-1] = {"state": "not_determined"}
        memo[(function, mode)] = verdicts
        return verdicts

    effect_selectors, effect_names = effect_sink_identities(ctx, function, mode=mode)
    name_indices = _declared_param_indices(ctx, function)
    collections = keyed_collection_vars(ctx)

    blocked: set[int] = set()
    # A record with no parameter_names list (a pre-enrichment artifact) cannot
    # be expression-checked, so the completeness of no leaf's account is
    # verifiable: positives below still mint, but no silence becomes a proof.
    blocked_all = name_indices is None
    for leaf, path in _mandatory_leaves_with_paths(tree):
        direct, derived, opaque = _leaf_param_refs(leaf)
        mentioned = _unaccounted_param_mentions(leaf, name_indices or {}, direct | derived)
        keyed_read = _reads_keyed_collection_without_key(leaf, collections)
        if _is_external_callee_leaf(leaf):
            mutability = leaf.get("callee_state_mutability")
            if mutability not in ("view", "pure"):
                selector = _leaf_callee_selector(leaf)
                name = _leaf_callee_name(leaf)
                carries_effect = (selector is not None and selector in effect_selectors) or (
                    name is not None and name in effect_names
                )
                if carries_effect:
                    # The described effect's own revert surface: mentioning its
                    # destination argument is vacuous. Fully transparent.
                    continue
                # An effectful callee that is NOT proven to be the described
                # effect's own call: its revert surface may or may not restrict
                # the referenced parameters, and nothing here can say which.
                # Same answer whether the mutability was stamped ``nonview`` or
                # not stamped at all (an older tree) — neither is evaluable.
                blocked |= direct | derived | mentioned
                if opaque or keyed_read:
                    blocked_all = True
                continue
            # view/pure callee: it moves nothing, so its revert surface is a
            # genuine precondition — falls through to classification below.
        # Projection-completeness blocks (see the module comment above): a
        # parameter the expression names without an operand, and a keyed
        # collection read whose key the fold dropped, are both the leaf
        # touching something its account does not carry.
        blocked |= mentioned
        if opaque or keyed_read:
            # An unsupported leaf / undetermined computed provenance / dropped
            # collection key may reference any parameter without saying so: it
            # can never prove a constraint, and it blocks the unconstrained
            # proof for everyone.
            blocked_all = True
        for index in sorted(direct | derived):
            via_derived = index in derived and index not in direct
            guard = _classify_constraining_leaf(leaf, via_derived=via_derived)
            if guard is None:
                continue
            incumbent = verdicts.get(index)
            if incumbent is not None and incumbent.get("guard") != "denylist":
                continue
            binding = "derived_from" if via_derived else "operand"
            verdict: dict[str, Any] = {
                "state": "constrained",
                "guard": guard,
                # Three-state by construction: an unmapped guard kind must not
                # read as pinning, so absence from the map is None, not False.
                # A ``derived_from`` binding caps ``pins`` at None regardless of
                # the guard: the binding is flow-insensitive, so the
                # guard's set semantics are proven but WHICH parameter it
                # confines is not — only a proven pin may soften the
                # caller-chosen reading downstream.
                "pins": None if binding == "derived_from" else _GUARD_PINS.get(guard),
                "binding": binding,
                "leaf_path": list(path),
            }
            verdicts[index] = verdict

    for index in sorted(blocked):
        verdicts.setdefault(index, {"state": "not_determined"})
    if blocked_all:
        verdicts[-1] = {"state": "not_determined"}
    memo[(function, mode)] = verdicts
    return verdicts


def param_constraint(
    ctx: ClaimContext, function: str, index: int | None, *, mode: str = "value_flow"
) -> dict[str, Any]:
    """The three-state constraint verdict for one parameter index.

    ``index=None`` (the caller could not resolve which parameter) is
    ``not_determined`` by construction. An index with no recorded verdict
    inherits the function-wide default: ``unconstrained_proven`` when the tree
    was present and free of opaque mandatory leaves, else ``not_determined``."""
    if index is None or not isinstance(index, int):
        return {"state": "not_determined"}
    verdicts = param_constraints(ctx, function, mode=mode)
    verdict = verdicts.get(index)
    if verdict is not None:
        return dict(verdict)
    default = verdicts.get(-1)
    if default is not None:
        return dict(default)
    return {"state": "unconstrained_proven"}


# ---------------------------------------------------------------------------
# Self-service payout — the W1 amount-record join and the W1 ∧ W2 witness
# ---------------------------------------------------------------------------
#
# A payout is "self-service" when the paid amount is read out of a storage cell
# the caller is PROVEN to own (W1) AND that cell is cleared before any external
# call in the function, or a verified reentrancy guard stands in for that order
# (W2). Every state traces to a witness; a refusal carries the reason it fell
# short and is never a bare bool. Two separate producer walks meet here — the
# amount side (``effects.py`` publishes ``amount_record_*`` on the flow) and the
# guard side (``predicates.py`` stamps ``element_*`` on the leaf operand). Both
# name the base off Slither's ``StateVariable.canonical_name`` (the DECLARING
# contract, so an inherited var reads the same on both sides), so the join
# compares canonical names and refuses on any disagreement rather than guessing.
#
# ``unconstrained_proven`` is deliberately never minted for W1: proving the
# caller does NOT own the cell is an absence proof, and reading a missing
# owner-guard as "not owned" is exactly the over-claim discipline forbids. W1 is
# ``constrained`` (proven owned) or ``not_determined``.

_W1_KEYED_BY_CALLER = "keyed_by_caller"
_W1_OWNER_GUARDED_RECORD = "owner_guarded_record"

_W1_AMOUNT_ROOT_NOT_CLASSIFIABLE = "amount_root_not_classifiable"
_W1_MULTIPLE_RECORD_DECLARATIONS = "multiple_record_declarations"
_W1_RECORD_MISMATCH = "record_mismatch"
_W1_KEY_INDEX_DISAGREEMENT = "key_index_disagreement"
_W1_GUARD_NOT_MANDATORY = "guard_not_mandatory"

# W2 bases: U3's basis is imported from its producer so the payload names one
# vocabulary; U4's ``verified_guard`` is normalized here.
_W2_VERIFIED_GUARD = "verified_guard"

_W2_GUARD_FUNCTION_NOT_ANALYZED = "function_not_analyzed"

# The full closed vocabulary the fact publishes, for the reviewer and for a
# consumer that wants to assert it never sees an unlisted token. W1 reasons,
# U3's ordering reasons, U4's guard reasons, and the two positive states.
SELF_SERVICE_REFUSAL_REASONS = frozenset(
    {
        _W1_AMOUNT_ROOT_NOT_CLASSIFIABLE,
        _W1_MULTIPLE_RECORD_DECLARATIONS,
        _W1_RECORD_MISMATCH,
        _W1_KEY_INDEX_DISAGREEMENT,
        _W1_GUARD_NOT_MANDATORY,
        # U3 (record_ordering) — W2 ordering refusals.
        "clearing_write_does_not_dominate_calls",
        "no_clearing_write",
        "assembly_state_access",
        "cross_unit_ordering_unproven",
        "loop_nesting_mismatch",
        "call_enumeration_incomplete",
        "record_not_resolvable",
        # U4 (verified guard) — W2 guard refusals.
        "guard_modifier_not_applied",
        "no_verified_guard_modifier",
        "ambiguous_function_declaration",
        _W2_GUARD_FUNCTION_NOT_ANALYZED,
        # burn variant (SPEC S1 §1.5), registered for forward compatibility —
        # the shipped producers publish no burn record for this join to read.
        "amount_is_external_conversion_of_burn",
    }
)


_VERIFIED_GUARD_VERDICTS: WeakKeyDictionary[ClaimContext, dict[str, Any]] = WeakKeyDictionary()


def _verified_guard_verdicts(ctx: ClaimContext) -> dict[str, Any]:
    """U4's per-function verified-guard verdicts for this contract, memoized per
    context. A context with no live Slither contract yields an empty map, so the
    lookup below returns an explicit ``function_not_analyzed`` refusal rather
    than inferring a guard from a missing row."""
    cached = _VERIFIED_GUARD_VERDICTS.get(ctx)
    if cached is not None:
        return cached
    verdicts: dict[str, Any] = {}
    if ctx.contract is not None:
        from ...static_analysis.reentrancy_pause import verified_guard_verdicts

        try:
            verdicts = verified_guard_verdicts(ctx.contract)
        except Exception:  # pragma: no cover - a malformed contract view refuses closed
            verdicts = {}
    _VERIFIED_GUARD_VERDICTS[ctx] = verdicts
    return verdicts


def _owner_guarded_record_constraint(
    ctx: ClaimContext, function: str, flow: dict[str, Any], record: str
) -> dict[str, Any]:
    """W1 via an ownership guard: a mandatory ``caller_authority`` leaf that
    reads the SAME record against ``msg.sender``.

    A guard leaf names exactly one key level (U1 refuses multi-level element
    reads), so it can vouch only for a single-level record, and only when the
    amount side pinned that level to an entry slot: a ``param`` kind whose index
    the cross-site fold stripped is a disagreement, never a proof, so the index
    must be present AND equal, never ``kind == param`` alone."""
    key_indexes = flow.get("amount_record_key_param_indexes")
    single_index = (
        key_indexes[0]
        if isinstance(key_indexes, list) and len(key_indexes) == 1 and isinstance(key_indexes[0], int)
        else None
    )
    tree = ctx.predicate_tree(function)
    saw_base_mismatch = False
    saw_key_mismatch = False
    if tree is not None:
        for leaf, _path in _mandatory_leaves_with_paths(tree):
            if leaf.get("authority_role") != "caller_authority":
                continue
            operands = [o for o in (leaf.get("operands") or []) if isinstance(o, dict)]
            if not any(o.get("source") == "msg_sender" for o in operands):
                continue
            for op in operands:
                if "element_base_variable" not in op:
                    continue
                # Canonical comparison: both sides derive the base from
                # ``StateVariable.canonical_name``, so a bare-name match would be
                # the silent-zero the two-walk split threatens.
                if op.get("element_base_variable") != record:
                    saw_base_mismatch = True
                    continue
                idx = op.get("element_key_param_index")
                if single_index is not None and isinstance(idx, int) and idx == single_index:
                    return {"state": "constrained", "basis": _W1_OWNER_GUARDED_RECORD, "record": record}
                # Same base, but the guard reads a different cell (a different
                # key slot) or the amount side pinned no single slot to align to.
                saw_key_mismatch = True
    if saw_key_mismatch:
        reason = _W1_KEY_INDEX_DISAGREEMENT
    elif saw_base_mismatch:
        reason = _W1_RECORD_MISMATCH
    else:
        reason = _W1_GUARD_NOT_MANDATORY
    return {"state": "not_determined", "reason": reason}


def amount_record_constraint(ctx: ClaimContext, function: str, flow: dict[str, Any]) -> dict[str, Any]:
    """W1: is the flow's AMOUNT read out of a storage record the caller is proven
    to own? Three-state, shaped on :func:`param_constraint`.

    ``constrained`` carries the basis and the canonical record; anything short of
    a full proof is ``not_determined`` with the reason it fell short. See the
    module comment for why ``unconstrained_proven`` is never minted."""
    record = flow.get("amount_record_variable")
    if not isinstance(record, str) or not record:
        variables = flow.get("amount_record_variables")
        reason = (
            _W1_MULTIPLE_RECORD_DECLARATIONS
            if isinstance(variables, list) and variables
            else _W1_AMOUNT_ROOT_NOT_CLASSIFIABLE
        )
        return {"state": "not_determined", "reason": reason}

    key_kinds = flow.get("amount_record_key_kinds")
    # keyed_by_caller: a level of the cell's own key IS the caller's address, so
    # the cell is the caller's with no guard leaf needed. ``msg_sender`` is an
    # EARNED origin (proven, not a name fallback), and the folded kinds are
    # published only where every contributing site agreed — so its presence is
    # itself the proof, even if another level is a caller-chosen param: the
    # caller can only ever reach cells under their own address at that level.
    if isinstance(key_kinds, list) and "msg_sender" in key_kinds:
        return {"state": "constrained", "basis": _W1_KEYED_BY_CALLER, "record": record}

    return _owner_guarded_record_constraint(ctx, function, flow, record)


def self_service_payout(ctx: ClaimContext, function: str, flow: dict[str, Any]) -> dict[str, Any]:
    """W1 ∧ W2: the paid amount is read from a cell the caller owns (W1) AND that
    cell is cleared before any external call, or a verified reentrancy guard
    stands in for that order (W2). Three-state; proven only on the full
    conjunction, and every refusal names the conjunct that failed.

    W2 is satisfied by EITHER U3's ordering proof (``record_ordering`` on the
    flow) OR U4's verified guard — distinct proofs with distinct residuals, so
    the basis names which one. When both refuse, the ordering reason wins: it
    names WHY the code order is unsafe, the security-relevant fact."""
    w1 = amount_record_constraint(ctx, function, flow)
    if w1.get("state") != "constrained":
        return {"state": "not_determined", "reason": w1.get("reason", _W1_AMOUNT_ROOT_NOT_CLASSIFIABLE)}

    ordering = flow.get("record_ordering")
    ordering = ordering if isinstance(ordering, dict) else {}
    guard = _verified_guard_verdicts(ctx).get(function) or {
        "state": "not_determined",
        "reason": _W2_GUARD_FUNCTION_NOT_ANALYZED,
    }

    if ordering.get("state") == "proven_ordering":
        w2_basis = W2_BASIS_CLEAR_DOMINATES_CALLS
        disclosures = [str(d) for d in (ordering.get("disclosures") or [])]
    elif guard.get("state") == "proven":
        w2_basis = _W2_VERIFIED_GUARD
        disclosures = []
    else:
        reason = ordering.get("reason") if ordering.get("state") == "not_determined" else None
        if not reason:
            reason = guard.get("reason") or _W2_GUARD_FUNCTION_NOT_ANALYZED
        return {"state": "not_determined", "reason": reason}

    return {
        "state": SELF_SERVICE_STATE_PROVEN,
        "w1_basis": w1["basis"],
        "w2_basis": w2_basis,
        "record": w1["record"],
        # The two G7 disclosures ride every proof; the loop residual rides only a
        # per-iteration ordering proof (U3's ``cross_iteration_ordering_not_proven``).
        "disclosures": [SELF_SERVICE_DISCLOSE_UPGRADE, SELF_SERVICE_DISCLOSE_SIBLING, *disclosures],
    }


# ---------------------------------------------------------------------------
# State-write facts
# ---------------------------------------------------------------------------


def state_writes(ctx: ClaimContext, function: str, *, body_only: bool = True) -> list[dict[str, Any]]:
    record = ctx.effect_record(function)
    writes = record.get("state_writes")
    if not isinstance(writes, list):
        return []
    out = [w for w in writes if isinstance(w, dict)]
    if body_only:
        out = [w for w in out if w.get("origin") != "guard"]
    return out


def bool_write_targets(ctx: ClaimContext, function: str) -> set[tuple[str, str | None]]:
    """``(var, member)`` pairs this function writes as a latch flag in its body.

    Two shapes qualify. A plain ``bool`` state variable is the classic form. An
    ERC-7201 *namespaced* flag is the modern one: the struct lives at a
    keccak-derived slot reached through assembly, so Plane 0 records a write to
    the ``bytes32`` slot pseudo-variable (``hygiene_class ==
    "storage_location_pseudo"``) with no member path — the declared type is
    ``bytes32``, never ``bool``, and a bool-only filter cannot see it at all.
    That blind spot is what left ``pause``/``unpause`` unlabelled across the
    OZ-v5 / etherfi money contracts.

    A pseudo-slot write only becomes a pause target if some function reads the
    same slot as a mandatory revert gate (``pause_targets``), so admitting the
    shape here widens the candidate set without weakening the gate evidence."""
    out: set[tuple[str, str | None]] = set()
    for write in state_writes(ctx, function):
        declared = write.get("declared_type")
        namespaced = write.get("hygiene_class") == "storage_location_pseudo"
        if declared != "bool" and not namespaced:
            continue
        member_path = write.get("member_path") or []
        out.add((write["var"], member_path[0] if member_path else None))
    return out


def numeric_latch_write_targets(ctx: ClaimContext, function: str) -> set[tuple[str, str | None]]:
    """Numeric state writes admitted only when a latch-shaped gate reads them."""

    out: set[tuple[str, str | None]] = set()
    for write in state_writes(ctx, function):
        if write.get("declared_type") not in ("uint8", "uint256"):
            continue
        member_path = write.get("member_path") or []
        out.add((write["var"], member_path[0] if member_path else None))
    return out


def namespaced_write_vars(ctx: ClaimContext, function: str) -> set[str]:
    """Slot pseudo-variables this function writes (ERC-7201 namespaced storage).

    A namespaced slot aggregates every field of its struct, so "this function
    writes a slot that some gate reads" is far weaker evidence than the same
    statement about a plain ``bool``: an owner change writes the very slot the
    owner gate reads. Callers use this to demand stronger evidence — see the
    definite-polarity requirement in the pause matcher."""
    return {
        str(write["var"])
        for write in state_writes(ctx, function)
        if write.get("hygiene_class") == "storage_location_pseudo" and write.get("var")
    }


def value_flows(ctx: ClaimContext, function: str, *, body_only: bool = True) -> list[dict[str, Any]]:
    record = ctx.effect_record(function)
    flows = record.get("value_flows")
    if not isinstance(flows, list):
        return []
    out = [f for f in flows if isinstance(f, dict)]
    if body_only:
        out = [f for f in out if f.get("origin") != "guard"]
    return out


def body_sinks(ctx: ClaimContext, function: str) -> list[dict[str, Any]]:
    return [s for s in ctx.sinks(function) if s.get("origin") != "guard"]


# ---------------------------------------------------------------------------
# Contract-shape helpers
# ---------------------------------------------------------------------------


_ADDRESS_ELEMENTARY = frozenset({"address", "address payable"})


def is_scalar_pointer(variable: Any) -> bool:
    """True when the Slither variable is stored as a callable 20-byte pointer: an
    elementary ``address``/``address payable``, or a contract/interface reference
    (an ``IBeforeTransferHook`` field holds that contract's address). A mapping,
    array, struct, enum, or user-defined value type is not.

    Decided on the resolved ``Type`` object rather than the rendered declaration,
    so a struct or enum field cannot pass for a code pointer — the tag this feeds
    (``callee_pointer.rotate``) grants its principal the admin capability."""
    try:
        from slither.core.declarations.contract import Contract
        from slither.core.solidity_types.elementary_type import ElementaryType
        from slither.core.solidity_types.user_defined_type import UserDefinedType
    except Exception:  # pragma: no cover - import edge
        return False
    var_type = getattr(variable, "type", None)
    if isinstance(var_type, ElementaryType):
        return var_type.name in _ADDRESS_ELEMENTARY
    if isinstance(var_type, UserDefinedType):
        return isinstance(var_type.type, Contract)
    return False


def is_erc20(ctx: ClaimContext) -> bool:
    ercs = getattr(ctx.contract, "ercs", None)
    if not callable(ercs):
        return False
    try:
        values: Any = ercs()
        return "ERC20" in {str(value) for value in values}
    except Exception:
        return False


def written_state_variables(function: Any) -> list[Any]:
    getter = getattr(function, "all_state_variables_written", None)
    if not callable(getter):
        return []
    try:
        result: Any = getter()
        return list(result)
    except Exception:
        return []


def contract_function(ctx: ClaimContext, signature: str) -> Any | None:
    """The Slither function object for an effects full-name signature.

    Two functions can share a full-name — a concrete body and an inherited
    interface re-declaration (0 nodes). Prefer the implemented body so IR reads
    (polarity, supply sign, use-links) see the real code, mirroring the effects
    builder's own tie-break."""
    best = None
    for fn in getattr(ctx.contract, "functions", []) or []:
        full = getattr(fn, "full_name", None) or getattr(fn, "name", None)
        if full != signature:
            continue
        if best is None or _fn_prefers(fn, best):
            best = fn
    return best


def _fn_prefers(new_fn: Any, old_fn: Any) -> bool:
    new_impl = bool(getattr(new_fn, "is_implemented", False)) and bool(getattr(new_fn, "nodes", None))
    old_impl = bool(getattr(old_fn, "is_implemented", False)) and bool(getattr(old_fn, "nodes", None))
    if new_impl != old_impl:
        return new_impl
    # A base function shadowed by a most-derived override is not the entry point.
    new_shadow = bool(getattr(new_fn, "is_shadowed", False))
    old_shadow = bool(getattr(old_fn, "is_shadowed", False))
    if new_shadow != old_shadow:
        return not new_shadow
    return len(getattr(new_fn, "nodes", []) or []) > len(getattr(old_fn, "nodes", []) or [])


def contract_functions(ctx: ClaimContext, signature: str) -> list[Any]:
    """Every Slither function object with this full-name (both a most-derived
    override and its shadowed base), for evidence that may live on either."""
    return [
        fn
        for fn in getattr(ctx.contract, "functions", []) or []
        if (getattr(fn, "full_name", None) or getattr(fn, "name", None)) == signature
    ]


# ---------------------------------------------------------------------------
# Pause derivation (facts + trees; the PauseAnalyzer idiom with its four fixes)
# ---------------------------------------------------------------------------


def pause_targets(ctx: ClaimContext) -> set[tuple[str, str | None]]:
    """``(var, member)`` bool flags that gate the contract's own entry points.

    A target is a ``bool`` written in some function body that is also read as a
    *mandatory* revert gate by another function (``mandatory_gate_reads``). The
    member-path facts recover struct-member pauses (Accountant ``state.isPaused``)
    and inherited-private pauses (EtherFiNodesManager ``_paused``) that the
    scalar ``state_variables`` view misses, while the mandatory-gate structure
    keeps a branch-mode selector (OneSig ``executorRequired``) out."""
    cached = _PAUSE_TARGETS.get(ctx)
    if cached is not None:
        return cached
    gate_reads = mandatory_gate_reads(ctx)
    all_bool_writes: set[tuple[str, str | None]] = set()
    all_numeric_writes: set[tuple[str, str | None]] = set()
    for signature in ctx.function_signatures():
        all_bool_writes |= bool_write_targets(ctx, signature)
        all_numeric_writes |= numeric_latch_write_targets(ctx, signature)
    numeric_gate_reads = mandatory_latch_reads(ctx)
    targets = {pair for pair in all_bool_writes if _pair_is_gate_read(pair, gate_reads)} | {
        pair for pair in all_numeric_writes if _pair_is_gate_read(pair, numeric_gate_reads)
    }
    _PAUSE_TARGETS[ctx] = targets
    return targets


def _pair_is_gate_read(pair: tuple[str, str | None], gate_reads: set[tuple[str, str | None]]) -> bool:
    var, member = pair
    if pair in gate_reads:
        return True
    # A scalar bool read (member None) still matches a var-granular write.
    if member is not None and (var, None) in gate_reads:
        return True
    # ...and the mirror image, which is the namespaced case: the WRITE is
    # recorded against the slot pseudo-variable with no member path
    # (`PAUSABLE_STORAGE_SLOT`), while the guard READ resolves through the
    # struct and carries one (`["paused"]`). Requiring the member paths to agree
    # would reject every ERC-7201 latch, so a memberless write matches any read
    # of the same variable.
    return member is None and any(read_var == var for read_var, _read_member in gate_reads)


def function_pause_targets(ctx: ClaimContext, function: str) -> set[tuple[str, str | None]]:
    """The contract's pause targets that ``function`` writes in its body."""
    return (bool_write_targets(ctx, function) | numeric_latch_write_targets(ctx, function)) & pause_targets(ctx)


def pause_affected_functions(ctx: ClaimContext, targets: set[tuple[str, str | None]]) -> list[str]:
    """State-changing entry points mandatorily gated by one of ``targets``."""

    toggle_functions = {
        signature
        for signature in ctx.function_signatures()
        if (bool_write_targets(ctx, signature) | numeric_latch_write_targets(ctx, signature)) & targets
    }
    out: list[str] = []
    for signature, reads in mandatory_latch_reads_by_function(ctx).items():
        if signature in toggle_functions:
            continue
        if any(_pair_is_gate_read(target, reads) for target in targets):
            out.append(signature)
    return sorted(out)


def pause_target_declared_types(ctx: ClaimContext, function: str, target: tuple[str, str | None]) -> set[str]:
    """Declared write types contributing to one pause target."""

    variable, member = target
    out: set[str] = set()
    for write in state_writes(ctx, function):
        if write.get("var") != variable:
            continue
        member_path = write.get("member_path") or []
        write_member = member_path[0] if member_path else None
        if member is not None and write_member != member:
            continue
        declared = write.get("declared_type")
        if isinstance(declared, str):
            out.add(declared)
    return out


def toggle_polarity(function: Any, var: str, member: str | None, *, alias_members: frozenset[str] = frozenset()) -> str:
    """``set`` / ``unset`` / ``both`` (indeterminate write) / ``none``.

    Member writes are paired through their ``Member`` reference the way the
    effects builder pairs them. Walks internal callees so an OZ
    ``_pause()``/``_unpause()`` indirection is attributed to the entry point.

    ``alias_members`` handles the ERC-7201 namespaced latch, where the write is
    attributed to the slot pseudo-variable but the IR assigns through a LOCAL
    storage pointer (``$.paused = true``), so no assignment ever names ``var``.
    The caller passes the member names the guard reads on that slot; an
    assignment to any of them counts, whatever the pointer is called. Without
    this the polarity is indeterminate and every namespaced pauser would claim
    both directions — asserting that ``pause()`` also unpauses."""
    polarities: set[str] = set()
    matched_write = False
    visited: set[tuple[int, tuple[tuple[str, str], ...]]] = set()

    def walk(unit: Any, bound_polarities: dict[str, str] | None = None) -> None:
        nonlocal matched_write
        bound = dict(bound_polarities or {})
        visit_key = (id(unit), tuple(sorted(bound.items())))
        if visit_key in visited:
            return
        visited.add(visit_key)
        for node in getattr(unit, "nodes", []) or []:
            ref_pair: dict[int, tuple[str, str]] = {}
            irs = list(getattr(node, "irs", []) or [])
            for ir in irs:
                if type(ir).__name__ != "Member":
                    continue
                base = getattr(getattr(ir, "variable_left", None), "name", None)
                member_name = getattr(getattr(ir, "variable_right", None), "name", None)
                lvalue = getattr(ir, "lvalue", None)
                if base is not None and lvalue is not None:
                    ref_pair[id(lvalue)] = (str(base), str(member_name))
            for ir in irs:
                if type(ir).__name__ != "Assignment":
                    continue
                lvalue = getattr(ir, "lvalue", None)
                rvalue = getattr(ir, "rvalue", None)
                polarity = _constant_bool_polarity(rvalue)
                rvalue_name = getattr(rvalue, "name", None)
                if polarity is None and isinstance(rvalue_name, str):
                    polarity = bound.get(rvalue_name)
                lvalue_name = getattr(lvalue, "name", None)
                if polarity is not None and isinstance(lvalue_name, str):
                    bound[lvalue_name] = polarity
                if member is None:
                    named = _base_name(getattr(lvalue, "name", None)) == var
                    aliased = bool(alias_members) and (ref_pair.get(id(lvalue)) or ("", ""))[1] in alias_members
                    if not (named or aliased):
                        continue
                elif lvalue is None or ref_pair.get(id(lvalue)) != (var, member):
                    continue
                matched_write = True
                if polarity:
                    polarities.add(polarity)
            for ir in irs:
                if type(ir).__name__ in ("InternalCall", "LibraryCall"):
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None):
                        callee_bound: dict[str, str] = {}
                        parameters = list(getattr(callee, "parameters", None) or [])
                        arguments = list(getattr(ir, "arguments", None) or [])
                        for parameter, argument in zip(parameters, arguments, strict=False):
                            parameter_name = getattr(parameter, "name", None)
                            argument_name = getattr(argument, "name", None)
                            argument_polarity = _constant_bool_polarity(argument)
                            if argument_polarity is None and isinstance(argument_name, str):
                                argument_polarity = bound.get(argument_name)
                            if isinstance(parameter_name, str) and argument_polarity is not None:
                                callee_bound[parameter_name] = argument_polarity
                        walk(callee, callee_bound)

    walk(function)
    if polarities == {"set"}:
        return "set"
    if polarities == {"unset"}:
        return "unset"
    if not matched_write:
        return "none"
    return "both"


def _base_name(name: Any) -> str | None:
    if not isinstance(name, str):
        return None
    parts = name.rsplit("_", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return name


def _constant_bool_polarity(rvalue: Any) -> str | None:
    text = getattr(rvalue, "value", None)
    if text is None:
        text = getattr(rvalue, "name", None)
    text = str(text if text is not None else rvalue or "").strip().lower()
    if text in ("true", "1"):
        return "set"
    if text in ("false", "0"):
        return "unset"
    try:
        return "set" if int(text, 0) != 0 else "unset"
    except ValueError:
        pass
    return None


# ---------------------------------------------------------------------------
# Supply-sign derivation (the ERC-20 total-supply var, +/- via the Binary IR)
# ---------------------------------------------------------------------------

_TOTAL_SUPPLY_SELECTOR = abi_selector("totalSupply()")


def total_supply_vars(ctx: ClaimContext) -> set[str]:
    """Names of the state variables this contract publishes as its ERC-20 total
    supply: a ``public`` variable whose auto-generated getter is the standard's
    ``totalSupply()`` (``0x18160ddd``).

    The ABI entry — not the identifier — is what identifies the supply. A private
    supply var behind a hand-written getter is deliberately NOT resolved here: its
    binding to ``totalSupply()`` would have to be guessed, and the zero-address
    ``Transfer`` path (:func:`mint_burn_transfer_sign`) already covers that shape
    with real evidence."""
    cached = _TOTAL_SUPPLY_VARS.get(ctx)
    if cached is not None:
        return cached
    found: set[str] = set()
    for variable in getattr(ctx.contract, "state_variables", None) or []:
        if getattr(variable, "visibility", None) != "public":
            continue
        signature = getattr(variable, "solidity_signature", None)
        name = getattr(variable, "name", None)
        if isinstance(signature, str) and isinstance(name, str) and selector_of(signature) == _TOTAL_SUPPLY_SELECTOR:
            found.add(name)
    _TOTAL_SUPPLY_VARS[ctx] = found
    return found


def total_supply_sign(function: Any, supply_vars: set[str]) -> str | None:
    """``"mint"`` if the function increases one of ``supply_vars``, ``"burn"`` if
    it decreases one, via the Binary IR *operation type* (Addition/Subtraction)
    on that variable — no source-string parsing. Walks internal/library callees
    so a supply change through ``_mint``/``_burn`` is attributed to the entry."""
    if not supply_vars:
        return None
    signs: set[str] = set()
    visited: set[int] = set()

    def walk(unit: Any) -> None:
        if id(unit) in visited:
            return
        visited.add(id(unit))
        for node in getattr(unit, "nodes", []) or []:
            irs = list(getattr(node, "irs", []) or [])
            binary_sign: dict[int, str] = {}
            for ir in irs:
                if type(ir).__name__ != "Binary":
                    continue
                op_type = getattr(getattr(ir, "type", None), "name", "") or ""
                left = _base_name(getattr(getattr(ir, "variable_left", None), "name", None))
                right = _base_name(getattr(getattr(ir, "variable_right", None), "name", None))
                lvalue = getattr(ir, "lvalue", None)
                sign = None
                if op_type == "ADDITION" and (left in supply_vars or right in supply_vars):
                    sign = "mint"
                elif op_type == "SUBTRACTION" and left in supply_vars:
                    sign = "burn"
                if sign is None:
                    continue
                # In-place (`totalSupply += x`): the Binary lvalue is the supply
                # var itself. Two-step: a TMP the next Assignment stores back.
                if _base_name(getattr(lvalue, "name", None)) in supply_vars:
                    signs.add(sign)
                elif lvalue is not None:
                    binary_sign[id(lvalue)] = sign
            for ir in irs:
                if type(ir).__name__ != "Assignment":
                    continue
                target = _base_name(getattr(getattr(ir, "lvalue", None), "name", None))
                rvalue = getattr(ir, "rvalue", None)
                if target in supply_vars and rvalue is not None and id(rvalue) in binary_sign:
                    signs.add(binary_sign[id(rvalue)])
            for ir in irs:
                if type(ir).__name__ in ("InternalCall", "LibraryCall"):
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None):
                        walk(callee)

    walk(function)
    if len(signs) == 1:
        return next(iter(signs))
    return None


def monotone_balance_delta(function: Any) -> str | None:
    """``"mint"`` / ``"burn"`` when every monotone write this function makes to
    the contract's own storage moves in one direction, else ``None``.

    Unlike :func:`total_supply_sign` this resolves a ``ReferenceVariable`` back to
    the state variable it indexes, so the WETH9 shape — a balance ledger credited
    out of nothing (``balanceOf[msg.sender] += msg.value``) with no supply
    variable anywhere — is observed rather than assumed. A body that both credits
    and debits (a ledger move) is ambiguous and yields ``None``."""
    from slither.core.variables.state_variable import StateVariable

    def state_origin(value: Any) -> Any:
        if isinstance(value, StateVariable):
            return value
        origin = getattr(value, "points_to_origin", None)
        return origin if isinstance(origin, StateVariable) else None

    signs: set[str] = set()
    visited: set[int] = set()

    def walk(unit: Any) -> None:
        if id(unit) in visited:
            return
        visited.add(id(unit))
        for node in getattr(unit, "nodes", []) or []:
            irs = list(getattr(node, "irs", []) or [])
            for ir in irs:
                if type(ir).__name__ != "Binary":
                    continue
                op_type = getattr(getattr(ir, "type", None), "name", "") or ""
                if op_type not in ("ADDITION", "SUBTRACTION"):
                    continue
                if state_origin(getattr(ir, "lvalue", None)) is None:
                    continue
                if state_origin(getattr(ir, "variable_left", None)) is None:
                    continue
                signs.add("mint" if op_type == "ADDITION" else "burn")
            for ir in irs:
                if type(ir).__name__ in ("InternalCall", "LibraryCall"):
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None):
                        walk(callee)

    walk(function)
    if len(signs) == 1:
        return next(iter(signs))
    return None


# ---------------------------------------------------------------------------
# Mint/burn via the ERC-20 standard Transfer event (name-independent supply)
# ---------------------------------------------------------------------------

# The ERC-20 published signature ``Transfer(address,address,uint256)``. A
# rebasing token (EETH) tracks supply in a differently-named var and computes
# ``totalSupply()`` externally, so ``total_supply_sign`` cannot see the write;
# the standard zero-address ``Transfer`` is the general, name-independent mint /
# burn signal.
_ERC20_TRANSFER_ARG_TYPES = ("address", "address", "uint256")


def _is_erc20_transfer_event(ir: Any) -> bool:
    if getattr(ir, "name", None) != "Transfer":
        return False
    args = list(getattr(ir, "arguments", []) or [])
    if len(args) != 3:
        return False
    return tuple(str(getattr(arg, "type", None)) for arg in args) == _ERC20_TRANSFER_ARG_TYPES


def _arg_is_zero(arg: Any, origins: dict[int, tuple[str, str | None]]) -> bool:
    from slither.slithir.variables import Constant

    if isinstance(arg, Constant):
        return getattr(arg, "value", None) in (0, "0", "0x0", False)
    return origins.get(id(arg)) == ("zero", None)


def _transfer_zero_direction(ir: Any, origins: dict[int, tuple[str, str | None]]) -> str | None:
    """``"mint"`` for an ERC-20 ``Transfer`` whose FROM is the zero address,
    ``"burn"`` when the TO is, ``None`` otherwise (neither endpoint zero, both
    zero, or not the canonical ``Transfer(address,address,uint256)`` shape)."""
    if not _is_erc20_transfer_event(ir):
        return None
    args = list(getattr(ir, "arguments", []) or [])
    from_zero = _arg_is_zero(args[0], origins)
    to_zero = _arg_is_zero(args[1], origins)
    if from_zero and not to_zero:
        return "mint"
    if to_zero and not from_zero:
        return "burn"
    return None


def mint_burn_transfer_sign(function: Any) -> str | None:
    """``"mint"`` / ``"burn"`` when the function both emits a zero-endpoint
    ERC-20 ``Transfer`` and makes a matching-direction monotone Binary write to
    a state variable, else ``None``.

    Both halves are required. The zero-address ``Transfer`` alone would fire on a
    proxy/forwarder that re-emits it without changing its own supply, so a
    monotone ``+`` (mint) or ``-`` (burn) to some ``StateVariable`` in the same
    body must corroborate it. Walks internal/library callees like
    :func:`total_supply_sign` so a mint/burn routed through a helper is
    attributed to the entry point. Fails to ``None`` on any doubt — a mixed body
    that emits both a from-zero and a to-zero ``Transfer`` is ambiguous."""
    from slither.core.variables.state_variable import StateVariable

    transfer_dirs: set[str] = set()
    write_signs: set[str] = set()
    visited: set[int] = set()

    def walk(unit: Any) -> None:
        if id(unit) in visited:
            return
        visited.add(id(unit))
        origins = _operand_origins(unit)
        for node in getattr(unit, "nodes", []) or []:
            irs = list(getattr(node, "irs", []) or [])
            for ir in irs:
                if type(ir).__name__ == "EventCall":
                    direction = _transfer_zero_direction(ir, origins)
                    if direction:
                        transfer_dirs.add(direction)
            binary_sign: dict[int, str] = {}
            for ir in irs:
                if type(ir).__name__ != "Binary":
                    continue
                op_type = getattr(getattr(ir, "type", None), "name", "") or ""
                left = getattr(ir, "variable_left", None)
                right = getattr(ir, "variable_right", None)
                lvalue = getattr(ir, "lvalue", None)
                sign = None
                if op_type == "ADDITION" and (isinstance(left, StateVariable) or isinstance(right, StateVariable)):
                    sign = "mint"
                elif op_type == "SUBTRACTION" and isinstance(left, StateVariable):
                    sign = "burn"
                if sign is None:
                    continue
                # In-place (`S += x`): the Binary lvalue is the state var itself.
                # Two-step: a TMP the next Assignment stores back into a state var.
                if isinstance(lvalue, StateVariable):
                    write_signs.add(sign)
                elif lvalue is not None:
                    binary_sign[id(lvalue)] = sign
            for ir in irs:
                if type(ir).__name__ != "Assignment":
                    continue
                target = getattr(ir, "lvalue", None)
                rvalue = getattr(ir, "rvalue", None)
                if isinstance(target, StateVariable) and rvalue is not None and id(rvalue) in binary_sign:
                    write_signs.add(binary_sign[id(rvalue)])
            for ir in irs:
                if type(ir).__name__ in ("InternalCall", "LibraryCall"):
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None):
                        walk(callee)

    walk(function)
    if transfer_dirs == {"mint"} and "mint" in write_signs:
        return "mint"
    if transfer_dirs == {"burn"} and "burn" in write_signs:
        return "burn"
    return None


# ---------------------------------------------------------------------------
# Emitted-log identity (topic0, not the event's name)
# ---------------------------------------------------------------------------


def emits_event_topic(ctx: ClaimContext, function: Any, topic0: str) -> bool:
    """True when ``function`` (or an internal/library callee it reaches) emits the
    log whose ``topic0`` is given — the standard's published event, identified by
    the 32 bytes the chain indexes rather than by the event's name.

    Each ``emit`` site is resolved through the contract's event *declarations*
    (:meth:`ClaimContext.declared_event_topic`), which is where the signature
    lives: the emitted arguments carry post-conversion types (a ``uint96``
    balance emitted into a ``uint256`` member) and would hash to a topic no chain
    ever logs."""
    visited: set[int] = set()

    def walk(unit: Any) -> bool:
        if id(unit) in visited:
            return False
        visited.add(id(unit))
        for node in getattr(unit, "nodes", []) or []:
            irs = list(getattr(node, "irs", []) or [])
            for ir in irs:
                if type(ir).__name__ != "EventCall":
                    continue
                name = getattr(ir, "name", None)
                arity = len(list(getattr(ir, "arguments", []) or []))
                if isinstance(name, str) and ctx.declared_event_topic(name, arity) == topic0:
                    return True
            for ir in irs:
                if type(ir).__name__ in ("InternalCall", "LibraryCall"):
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None) and walk(callee):
                        return True
        return False

    return walk(function)


# ---------------------------------------------------------------------------
# Callee-pointer use-link (destination identity, not name strings)
# ---------------------------------------------------------------------------


def pointer_write_targets(ctx: ClaimContext, function: str) -> list[Any]:
    """State variables ``function`` writes that are callable scalar pointers
    (address / contract-typed, hygiene-normal), as Slither ``StateVariable``
    objects for identity comparison. The pointer test reads the variable's
    resolved type; the effects facts contribute only the hygiene filter, which
    keeps the OZ-v5 slot pseudo-variables out."""
    normal_names = {write["var"] for write in state_writes(ctx, function) if write.get("hygiene_class") == "normal"}
    if not normal_names:
        return []
    fn = contract_function(ctx, function)
    if fn is None:
        return []
    from slither.core.variables.state_variable import StateVariable

    out = []
    for var in written_state_variables(fn):
        if isinstance(var, StateVariable) and getattr(var, "name", None) in normal_names and is_scalar_pointer(var):
            out.append(var)
    return out


def writes_first_time_set_pointer(ctx: ClaimContext, function: str, pointers: list[Any]) -> bool:
    """True if the function gates one of the scalar pointers it writes on a
    zero-address self-check (``require(pointer == address(0))``) — a set-once
    latch that installs the pointer for the first time. Distinguishes an
    initializer's first-time set (setup) from a runtime rotation for the manual
    ``require``-based latches ``tree_is_one_shot`` (OZ initializer-family
    modifiers) does not recognize."""
    if not pointers:
        return False
    fn = contract_function(ctx, function)
    if fn is None:
        return False
    from slither.slithir.operations import Binary

    pointer_names = {name for p in pointers if isinstance((name := getattr(p, "name", None)), str)}
    origins = _operand_origins(fn)
    for node in getattr(fn, "nodes", []) or []:
        for ir in getattr(node, "irs", []) or []:
            if not isinstance(ir, Binary) or getattr(getattr(ir, "type", None), "name", "") != "EQUAL":
                continue
            left = origins.get(id(getattr(ir, "variable_left", None)))
            right = origins.get(id(getattr(ir, "variable_right", None)))
            sides = {left, right}
            if ("zero", None) in sides and any(side == ("state", name) for name in pointer_names for side in sides):
                return True
    return False


def _operand_origins(fn: Any) -> dict[int, tuple[str, str | None]]:
    """``id(ir_value) -> origin`` over the function body, folding
    ``TypeConversion``/``Assignment`` chains so a Binary operand resolves to the
    ``("state", name)`` variable or the ``("zero", None)`` address(0)/0 constant
    it came from (the pieces a ``pointer == address(0)`` latch is built from)."""
    from slither.core.variables.state_variable import StateVariable
    from slither.slithir.operations import Assignment, TypeConversion
    from slither.slithir.variables import Constant

    origins: dict[int, tuple[str, str | None]] = {}
    # Fixpoint over the chain length: address(state) and address(0) are single
    # TypeConversions here, but nested casts can stack a few links deep.
    for _ in range(8):
        changed = False
        for node in getattr(fn, "nodes", []) or []:
            for ir in getattr(node, "irs", []) or []:
                lvalue = getattr(ir, "lvalue", None)
                if lvalue is None:
                    continue
                if isinstance(ir, TypeConversion):
                    source = getattr(ir, "variable", None)
                elif isinstance(ir, Assignment):
                    source = getattr(ir, "rvalue", None)
                else:
                    continue
                origin: tuple[str, str | None] | None = None
                if isinstance(source, StateVariable):
                    origin = ("state", getattr(source, "name", None))
                elif isinstance(source, Constant):
                    origin = ("zero", None) if getattr(source, "value", None) in (0, "0", "0x0", False) else None
                elif source is not None:
                    origin = origins.get(id(source))
                if origin is not None and origins.get(id(lvalue)) != origin:
                    origins[id(lvalue)] = origin
                    changed = True
        if not changed:
            break
    return origins


def sibling_invokes_pointer(ctx: ClaimContext, writer: str, pointer: Any) -> str | None:
    """Full-name of an entry-point sibling that (transitively) invokes
    ``pointer`` as a call destination *by identity* and also moves value or
    writes a mapping — the ``transfer``-calls-``hook`` shape. ``None`` if no
    such sibling exists."""
    from slither.core.variables.state_variable import StateVariable
    from slither.slithir.operations import HighLevelCall, LowLevelCall

    if not isinstance(pointer, StateVariable):
        return None

    def resolves_to_pointer(destination: Any) -> bool:
        if destination is pointer:
            return True
        origin = getattr(destination, "points_to_origin", None)
        return origin is pointer

    def calls_pointer(fn: Any, seen: set[int]) -> bool:
        if id(fn) in seen:
            return False
        seen.add(id(fn))
        for node in getattr(fn, "nodes", []) or []:
            for ir in getattr(node, "irs", []) or []:
                if isinstance(ir, (HighLevelCall, LowLevelCall)) and resolves_to_pointer(
                    getattr(ir, "destination", None)
                ):
                    return True
                # Body-origin only: a pointer reached only through a modifier
                # (an authority consulted by a guard) is not a runtime code
                # pointer the entry point invokes.
                if type(ir).__name__ in ("InternalCall", "LibraryCall") and not _is_modifier_call(ir):
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None) and calls_pointer(callee, seen):
                        return True
        return False

    for signature in ctx.function_signatures():
        if signature == writer:
            continue
        if not _sibling_moves_value_or_writes_mapping(ctx, signature):
            continue
        if any(calls_pointer(fn, set()) for fn in contract_functions(ctx, signature)):
            return signature
    return None


def _is_modifier_call(ir: Any) -> bool:
    """True iff ``ir`` dispatches a modifier body (a guard), so the walk should
    not follow it into guard-origin territory."""
    if getattr(ir, "is_modifier_call", False):
        return True
    return type(getattr(ir, "function", None)).__name__ == "Modifier"


def _sibling_moves_value_or_writes_mapping(ctx: ClaimContext, signature: str) -> bool:
    if value_flows(ctx, signature):
        return True
    for write in state_writes(ctx, signature):
        if str(write.get("declared_type") or "").startswith("mapping"):
            return True
    return False
