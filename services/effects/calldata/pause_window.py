"""Freeze/pause (Tier 2): latch pairs, pause-duration window, pauser probes."""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # typing-only: the effects plane stays off static's runtime import graph
    from services.static.contract_analysis_pipeline.predicate_types import (
        OperandAbsorption,
    )

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import EffectiveFunction, FunctionPrincipal
from services.effects.anvil import EntryPoint, ForkFixture
from services.effects.config import (
    DURATION_BOUND_GUARD_CONSTANT,
    DURATION_BOUND_NO_TIME_REFERENCE,
    DURATION_BOUND_NOT_DETERMINED,
)
from services.resolution.differential_probe import (
    _parse_arg_types,
)

from .encoding import _arg_values, encode_calldata
from .facts import ContractFacts, FunctionFacts, facts_for_name
from .flows import _selector_of
from .plans import (
    _AUTHORITY_ROLES,
    _MAX_PLAUSIBLE_DURATION_S,
    ARG_AMOUNT,
    FIXTURE_BALANCE_WEI,
    NEUTRAL_CALLER,
)
from .roles import integer_param_roles
from .trees import _all_leaves, _authority_roles, _operands

logger = logging.getLogger("services.effects.calldata")


def _claim_latch_pairs(session: Session, function_id: int) -> set[tuple[str, str | None]]:
    """Latch ``(var, member)`` pairs from a persisted ``pause.set`` witness; usually empty (blank-claim selection),
    so corroborating only.
    """
    from services.effects.prefetch import get_prefetch

    pf = get_prefetch(session)
    if pf is not None and function_id in pf.function_ids:
        claims = pf.claims_by_function.get(function_id)
    else:
        claims = session.execute(
            select(EffectiveFunction.claims).where(EffectiveFunction.id == function_id)
        ).scalar_one_or_none()
    out: set[tuple[str, str | None]] = set()
    if not isinstance(claims, list):
        return out
    for claim in claims:
        if not isinstance(claim, dict) or claim.get("claim_id") != "pause.set":
            continue
        witness = claim.get("witness")
        if not isinstance(witness, dict) or witness.get("kind") != "pause_flag":
            continue
        for flag in witness.get("flags") or []:
            if isinstance(flag, dict) and flag.get("var"):
                member = flag.get("member")
                out.add((str(flag["var"]), str(member) if member else None))
    return out


def _latch_pairs(fn: FunctionFacts) -> set[tuple[str, str | None]]:
    """State writes shaped like a freeze latch: a ``bool``, or the ERC-7201 ``bytes32`` slot pseudo-variable
    (``storage_location_pseudo``, empty member path).

    Requires ``origin == "body"``: guard-origin entries are the latch being read by ``whenNotPaused``, which on
    namespaced contracts would make every victim look like a pauser and send it to Tier 2 (as
    ``_effect_targets_from_sinks`` does).
    """
    pairs: set[tuple[str, str | None]] = set()
    for write in fn.effect_info.get("state_writes") or []:
        if not isinstance(write, dict):
            continue
        if write.get("origin") != "body":
            continue
        hygiene = str(write.get("hygiene_class") or "")
        declared = str(write.get("declared_type") or "")
        latch_shaped = (hygiene == "normal" and "bool" in declared) or hygiene == "storage_location_pseudo"
        if not latch_shaped:
            continue
        var = write.get("var")
        if not var:
            continue
        member_path = write.get("member_path") or []
        pairs.add((str(var), str(member_path[0]) if member_path else None))
    return pairs


def _principals_by_selector(session: Session, contract_id: int) -> dict[str, str]:
    from services.effects.prefetch import get_prefetch

    pf = get_prefetch(session)
    if pf is not None and contract_id in pf.contract_ids:
        return dict(pf.principals_by_selector_by_contract.get(contract_id, {}))
    # Ordered so a multi-principal selector's ``setdefault`` pick is deterministic; matches
    # ``prefetch.install_prefetch``.
    rows = session.execute(
        select(EffectiveFunction.selector, FunctionPrincipal.address)
        .join(FunctionPrincipal, FunctionPrincipal.function_id == EffectiveFunction.id)
        .where(EffectiveFunction.contract_id == contract_id)
        .order_by(EffectiveFunction.id, FunctionPrincipal.address)
    ).all()
    out: dict[str, str] = {}
    for selector, address in rows:
        if isinstance(selector, str) and isinstance(address, str):
            out.setdefault(selector.lower(), address.lower())
    return out


def _compared_operands(leaf: Mapping[str, Any]) -> list[dict[str, Any]]:
    """A leaf's operands plus the additive sub-operands it absorbed.

    The pause window needs three facts (clock, latch, offset) but a comparison holds two operands, so
    ``absorbed_operands`` supplies the rest. Older trees lack the key and read as before, but an operand's absence there
    proves nothing (see :func:`_absorption_recorded`).
    """
    absorbed = leaf.get("absorbed_operands")
    extra = [op for op in absorbed if isinstance(op, dict)] if isinstance(absorbed, list) else []
    return [*_operands(leaf), *extra]


# Root marker from ``predicate_artifacts.build_predicate_artifacts`` on trees built with absorbed operands. A literal
# because effects doesn't import static at runtime; typed against ``predicate_types.OperandAbsorption``.
_OPERAND_ABSORPTION_RECORDED: "OperandAbsorption" = "recorded"


# Operand sources whose contents weren't recorded and may hide a clock: ``computed`` (anything beyond one-level
# ``+``/``-``), ``top``, and ``view_call``/``external_call`` (reading time through a helper like ``_blockTimestamp()``
# or ``clock()`` is common; ``require(!frozen || _clock() > unpauseAt)`` shows no ``block_context`` anywhere). Resolved
# sources (state vars, constants, params, callers, ``block_context``) aren't opaque; a stored timestamp isn't a clock.
_OPAQUE_OPERAND_SOURCES = frozenset({"computed", "top", "view_call", "external_call"})

# ``now`` is ``block.timestamp``. Demotion counts any self-advancing clock (``block.number`` lifts a freeze too), but
# the seconds harvest counts only seconds: a block-number constant is a block count.
_SECONDS_CLOCK_KINDS = frozenset({"timestamp", "now"})
_CLOCK_KINDS = frozenset({"timestamp", "now", "number"})

# Operators under which a constant bounds its other side from above, keyed by the constant's slot (IR left-right order).
# ``eq``/``ne``/``truthy``/``falsy`` bound nothing. Every persisted leaf carries an operator, so absence is read as
# undecidable.
_CONSTANT_IS_UPPER_BOUND = {0: frozenset({"gt", "gte"}), 1: frozenset({"lt", "lte"})}


def _absorption_recorded(tree: Any) -> bool:
    """Whether this tree's operand lists are complete for the additive shape.

    A comparison keeps two slots, so ``block.timestamp - pausedUntil < 2592000`` records ``{pausedUntil, 2592000}`` and
    loses the clock. With the marker, the absorption recorder ran on every comparison and an operand's absence is
    evidence; without it (every persisted tree so far), absence proves nothing.

    This matters for ``no_time_reference`` in :func:`_duration_from_trees`, a proof by absence: the same source reads as
    a 30-day window with the marker and as proven indefinite without it.
    """
    return isinstance(tree, dict) and tree.get("operand_absorption") == _OPERAND_ABSORPTION_RECORDED


def _window_ceiling_constant(leaf: Mapping[str, Any], latch_vars: set[str]) -> int | None:
    """The constant this comparison proves is a ceiling on the clock-to-latch gap, or ``None``.

    Taking the max plausible constant regardless of side and operator published non-windows as windows, in the
    severity-reducing direction:

        require(block.timestamp + 3600 < pausedUntil)   → 3600  (lead time)
        require(block.timestamp > pausedUntil + 300)    → 300   (cooldown)
        require(block.timestamp - pausedUntil > 600)    → 600   (minimum elapsed)

    Only one shape is decidable: the constant on one side, and on the other an additive group containing both a seconds
    clock and the latch, with an upper-bounding operator. Both subtraction orders bound the same gap.

    Not admitted: groups of ``{latch, constant}`` (``block.timestamp < pausedUntil + MAX_PAUSE``) or ``{clock,
    constant}``, because the answer depends on the constant's sign, which ``_stamp_absorbed_operands`` doesn't record.
    That family is ``not_determined`` until the producer stamps the sign; reading it from ``leaf["expression"]`` is
    deliberately refused.

    Also requires exactly two slots, and no foreign clock in the leaf (a mixed seconds/``block.number`` leaf can't say
    which unit the constant is in).
    """
    operands = _operands(leaf)
    if len(operands) != 2:
        return None
    raw_absorbed = leaf.get("absorbed_operands")
    absorbed = [op for op in raw_absorbed if isinstance(op, dict)] if isinstance(raw_absorbed, list) else []
    # Clock and latch must be in one additive group.
    if all(str(op.get("block_context_kind") or "") not in _SECONDS_CLOCK_KINDS for op in absorbed):
        return None
    if all(str(op.get("state_variable_name") or "") not in latch_vars for op in absorbed):
        return None
    clock_kinds = {str(op.get("block_context_kind") or "") for op in (*operands, *absorbed)}
    if clock_kinds & (_CLOCK_KINDS - _SECONDS_CLOCK_KINDS):
        return None
    operator = str(leaf.get("operator") or "")
    best: int | None = None
    for slot, operand in enumerate(operands):
        if operator not in _CONSTANT_IS_UPPER_BOUND[slot]:
            continue
        value = _parse_int(operand.get("constant_value"))
        if value is None or not 0 < value <= _MAX_PLAUSIBLE_DURATION_S:
            continue
        # MAX as tie-break: the longest window is the least mitigating reading.
        best = value if best is None else max(best, value)
    return best


def _duration_from_trees(trees: Mapping[str, Any], latch_vars: set[str]) -> tuple[int | None, str]:
    """The latch's freeze window and how it was established.

    ``guard_constant``: a leaf whose shape proves a constant ceils the clock-to-latch gap
    (:func:`_window_ceiling_constant`). Scoped to the latch, since a contract may have an indefinite latch and a timed
    one.

    ``no_time_reference``: proof of an indefinite latch; some leaf reads the latch and nothing in the tree can lift it
    with time. A latch no leaf reads is ``not_determined``, never indefinite.

    ``not_determined``: also the answer when the guard compares against time but the window isn't in code (etherfi's
    ``PausableUntil`` stores it in ``$.pauseUntilDuration``). A live read wouldn't help: the window is mutable and
    re-armable, so a read bounds one call, not the freeze.

    ``no_time_reference`` is a proof by absence, asked of the whole gate tree reading the latch:

    1. No clock anywhere in the tree. ``require(!frozen || block.timestamp > unpauseAt)`` lowers into sibling leaves, so
    a leaf-local check would call an expiring freeze indefinite. A pure conjunction is demoted too (a tree walk can't
    tell them apart).
    2. Operand lists known complete (:func:`_absorption_recorded`) and no opaque operand
    (:data:`_OPAQUE_OPERAND_SOURCES`) anywhere in the tree, since quotients and view helpers can hide a clock. This
    costs substantial recall (projected: most latches move off the proven state), but only ever away from the most
    severe claim.

    No persisted tree carries the marker yet, so this state has no realized rows until static re-runs.

    With several ceilings the MAX is taken (least mitigating).
    """
    best: int | None = None
    saw_latch_guard = False
    saw_timed_latch_guard = False
    clock_in_a_latch_tree = False
    latch_read_from_lossy_tree = False
    for tree in trees.values():
        tree_reads_latch = False
        tree_reads_clock = False
        tree_holds_opaque_operand = False
        for leaf in _all_leaves(tree):
            operands = _compared_operands(leaf)
            clock_kinds = {str(op.get("block_context_kind") or "") for op in operands}
            leaf_reads_clock = not clock_kinds.isdisjoint(_CLOCK_KINDS)
            tree_reads_clock = tree_reads_clock or leaf_reads_clock
            if any(op.get("source") in _OPAQUE_OPERAND_SOURCES for op in operands):
                tree_holds_opaque_operand = True
            if not any(str(op.get("state_variable_name") or "") in latch_vars for op in operands):
                continue
            tree_reads_latch = True
            saw_latch_guard = True
            if clock_kinds.isdisjoint(_SECONDS_CLOCK_KINDS):
                continue
            saw_timed_latch_guard = True
            value = _window_ceiling_constant(leaf, latch_vars)
            if value is not None:
                best = value if best is None else max(best, value)
        if tree_reads_latch and tree_reads_clock:
            clock_in_a_latch_tree = True
        if tree_reads_latch and (not _absorption_recorded(tree) or tree_holds_opaque_operand):
            latch_read_from_lossy_tree = True
    if best is not None:
        # Positive evidence: all three facts were in one leaf, so the preconditions don't apply.
        return best, DURATION_BOUND_GUARD_CONSTANT
    if saw_timed_latch_guard or not saw_latch_guard:
        return None, DURATION_BOUND_NOT_DETERMINED
    if clock_in_a_latch_tree or latch_read_from_lossy_tree:
        return None, DURATION_BOUND_NOT_DETERMINED
    return None, DURATION_BOUND_NO_TIME_REFERENCE


def _parse_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def read_max_pause_duration(facts: ContractFacts, latch_vars: set[str]) -> tuple[int | None, str]:
    """The pause bound, read per latch.

    Returns ``(seconds_or_None, source)`` with one of the three ``DURATION_BOUND_*`` states; ``None`` alone can't say
    whether there's no window or we didn't find one.

    The writer function pins which latch; an indefinite latch yields ``None`` (no auto-expiry probe).

    The only source is the IR (:func:`_duration_from_trees`). A former fallback scraped ``*PAUSE*``/``*FREEZE*``
    constants from source text, but the bound reaches the witness as a severity reducer
    (``claims_bridge._observed_summary``), so a stray cooldown would discount an indefinite freeze.

    Not read: etherfi's window in ``$.pauseUntilDuration``. That needs a live read (per-deployment, not code-plane) or a
    cross-function derivation static doesn't record; picking the getter by name is identifier matching. So it's
    ``not_determined``, and the fork cross-checks any bound found by warping past it.
    """
    return _duration_from_trees(facts.trees, latch_vars)


def _state_changing_functions(facts: ContractFacts) -> list[str]:
    return sorted(name for name, info in facts.effects.items() if isinstance(info, dict) and info.get("state_changing"))


def _entry_point_for(
    facts: ContractFacts, name: str, principals: Mapping[str, str], *, caller_override: str | None = None
) -> EntryPoint | None:
    """One blast-radius probe from that function's own principal (a contract-wide caller would fail every gate
    pre-pause). Unresolved functions are probed from a neutral identity. ``caller_override`` forces the pause
    principal for victims with no resolved principal.
    """
    sig = facts.canonical_signature(name)
    selector = _selector_of(sig)
    types = _parse_arg_types(sig)
    if not selector or types is None:
        return None
    caller = caller_override or principals.get(selector, NEUTRAL_CALLER)
    # Any direction: a blast-radius probe just needs justified argument values.
    probe_fn = facts_for_name(facts, name)
    roles = integer_param_roles(probe_fn, types) if probe_fn is not None else {}
    calldata = encode_calldata(
        selector,
        sig,
        substitutions=_arg_values(types, identity=caller, amount=ARG_AMOUNT, integer_roles=roles).substitutions,
    )
    if calldata is None:
        return None
    # Gas only, so an out-of-gas revert can't look like a freeze.
    fixtures = (ForkFixture(kind="set_balance", address=caller, value=hex(FIXTURE_BALANCE_WEI)),)
    return EntryPoint(key=name, calldata=calldata, from_addr=caller, fixtures=fixtures)


def _pauser_identity_probes(
    facts: ContractFacts, predicted: Sequence[str], principals: Mapping[str, str], pauser: str
) -> list[EntryPoint]:
    """Extra probes of predicted victims from the pause principal.

    A victim with no resolved caller is probed from ``NEUTRAL_CALLER`` and rejected by its auth gate pre-pause, hiding
    any freeze. The same ``EntryPoint`` key unions identities: it succeeds pre-pause if either caller does, and enters
    the blast only if both revert after, so this can only add witnessed freezes.

    Limited to the predicted set, caller-authority-gated victims, and victims without a resolved principal.
    """
    resolved = set(principals)
    probes: list[EntryPoint] = []
    for name in predicted:
        tree = facts.trees.get(name)
        # Only a caller-authority gate can hide a victim from the neutral caller.
        if not (_authority_roles(tree) & set(_AUTHORITY_ROLES)):
            continue
        selector = _selector_of(facts.canonical_signature(name))
        if not selector or selector in resolved:
            continue
        ep = _entry_point_for(facts, name, principals, caller_override=pauser)
        if ep is not None:
            probes.append(ep)
    return probes
