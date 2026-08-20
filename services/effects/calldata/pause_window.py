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

# ---------------------------------------------------------------------------
# freeze/pause (Tier 2)
# ---------------------------------------------------------------------------


def _claim_latch_pairs(session: Session, function_id: int) -> set[tuple[str, str | None]]:
    """Latch ``(var, member)`` pairs from a persisted ``pause.set`` claim witness.
    Usually empty — the selection cascade selects BLANK-claim functions — so this is the
    corroborating path, not the primary one."""
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
    """State writes with the shape a freeze latch has.

    A plain ``bool`` flag is the classic form; an ERC-7201 namespaced latch is
    recorded as a write to the ``bytes32`` slot pseudo-variable with hygiene class
    ``storage_location_pseudo`` and an empty member path, so it must be admitted
    too — that is the only fact tying the writer to the latch.

    ``origin == "body"`` is REQUIRED. A ``guard``-origin entry is the latch being
    READ by this function's own ``whenNotPaused`` modifier, not written by it — so
    on a namespaced contract every guarded function records the very same var and
    hygiene class as the pauser. Admitting those makes each of a pause's VICTIMS
    look like a pauser and puts them on the most expensive tier (measured: 141
    Tier-2 plans instead of 98 on the real candidate set) to probe functions that
    definitionally cannot flip the latch. ``_effect_targets_from_sinks`` filters
    to body-origin sinks for exactly this reason."""
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
    # ORDER BY is load-bearing, not cosmetic: a selector with two principals
    # resolves to whichever row arrives first under ``setdefault``, so an
    # unordered read makes the ``from_addr`` we simulate with depend on the plan
    # path (and on Postgres' row order). Matches ``prefetch.install_prefetch``
    # exactly so batched and unbatched planning simulate the same call.
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
    """A leaf's operands UNION the additive sub-operands it absorbed.

    A Solidity comparison holds two operands, and the pause-window question needs
    three facts (the clock, the latch, the offset) — so before
    ``absorbed_operands`` existed this reader's positive branch was unreachable
    from any compiled source (measured over 11 guard shapes).
    ``absorbed_operands`` is the sibling list the leaf builder now records; taking
    the union here is the whole widening.

    Trees persisted before that field simply have no key, and this reads them
    exactly as it did: absent ⇒ the old two-operand answer. What that answer may
    NOT be used for is a conclusion drawn from an operand's ABSENCE — see
    :func:`_absorption_recorded`, which is the positive marker that separates
    "this comparison read nothing more" from "we do not know what it read".
    """
    absorbed = leaf.get("absorbed_operands")
    extra = [op for op in absorbed if isinstance(op, dict)] if isinstance(absorbed, list) else []
    return [*_operands(leaf), *extra]


# Root-node marker stamped by ``predicate_artifacts.build_predicate_artifacts`` on
# every tree built by a builder that records absorbed operands
# (``predicates._stamp_absorbed_operands``). Duplicated as a literal for the same
# reason ``"op"``/``"leaf"`` are: the effects plane reads static's persisted JSON and
# does not import the static package at runtime. Annotated against the canonical
# ``predicate_types.OperandAbsorption`` (type-only) so drift is a pyright error.
_OPERAND_ABSORPTION_RECORDED: "OperandAbsorption" = "recorded"


# Operand sources that stand for an expression whose CONTENTS were not recorded, so
# the operand may be HIDING a clock read:
#   * ``computed`` — any arithmetic / hash / encode result the absorption recorder did
#     not decompose (it handles ``+``/``-`` one level deep and nothing else).
#   * ``top`` — provenance saturation.
#   * ``view_call`` / ``external_call`` — an operand that names a CALLEE the recorder
#     never entered. Reading time through a helper is the mainstream idiom, not a
#     curiosity: ``_blockTimestamp()`` in Uniswap V3's pool, ``clock()`` in OZ
#     Governor, ``oracle.nowSeconds()`` on any time oracle. Reproduced from compiled
#     Solidity: ``require(!frozen || _clock() > unpauseAt)`` records
#     ``{view_call _clock(), state_variable unpauseAt}`` and no ``block_context``
#     operand appears anywhere in the tree, so "no clock here" was a false proof about
#     a freeze that demonstrably expires.
# None of these may be read as "this operand is not a clock". The named, decomposed
# sources are deliberately absent from this set: ``state_variable``, ``constant``,
# ``parameter``, ``msg_sender``/``tx_origin``/``signature_recovery``,
# ``self_address``, ``block_context``. Each is a fact the builder resolved and none
# is an unentered expression — a stored timestamp or a caller-supplied deadline is
# not a clock (no passage of time changes it without a transaction). A
# ``block_context`` operand is not OPAQUE — its kind is right there — but three of
# its kinds ARE the clock, which is what the two sets below express.
_OPAQUE_OPERAND_SOURCES = frozenset({"computed", "top", "view_call", "external_call"})

# The static plane maps every ``block.*`` global to ``source="block_context"`` with
# ``block_context_kind`` = the suffix — and ``now``, the pre-0.7 spelling, IS
# ``block.timestamp`` verbatim. Two sets because the two uses have different unit
# constraints:
#   * demotion (rule 1: a clock anywhere in a latch-reading tree denies the
#     proven-indefinite state) counts every kind that advances on its own —
#     ``block.number`` lifts a freeze by itself just as a timestamp does;
#   * the SECONDS arithmetic (``saw_timed_latch_guard`` + the constant harvest) may
#     count only second-denominated clocks: a ``block.number`` comparison constant
#     is a BLOCK COUNT, and harvesting one as ``duration_bound_seconds`` would
#     misstate the window by the block-time factor (216000 blocks ≈ 30 days, not
#     2.5 days).
_SECONDS_CLOCK_KINDS = frozenset({"timestamp", "now"})
_CLOCK_KINDS = frozenset({"timestamp", "now", "number"})

# Comparison operators under which a constant BOUNDS ITS OTHER SIDE FROM ABOVE, keyed
# by the slot the constant sits in (``operands`` is the comparison's two slots in IR
# left-right order, which is what makes the question answerable at all). ``eq``/``ne``
# and the unary ``truthy``/``falsy`` are deliberately absent: neither bounds anything.
# Measured over the 5,089 persisted leaves in the local database: every one carries an
# ``operator`` (lte 324, gte 225, lt 170, gt 88, plus the non-ordering kinds), so an
# ABSENT operator is a hand-built leaf and is read as undecidable rather than defaulted.
_CONSTANT_IS_UPPER_BOUND = {0: frozenset({"gt", "gte"}), 1: frozenset({"lt", "lte"})}


def _absorption_recorded(tree: Any) -> bool:
    """Whether this tree's operand lists are known-complete for the additive shape.

    An operand list is LOSSY by construction: a comparison leaf holds two slots, so
    ``block.timestamp - pausedUntil < 2592000`` records ``{pausedUntil, 2592000}``
    and the clock is simply gone. ``absorbed_operands`` is what recovers it — but a
    MISSING ``absorbed_operands`` has two meanings, and only this marker tells them
    apart:

    * marker present ⇒ the builder ran the absorption recorder over every
      comparison in this tree, so no key means the comparison read no additive
      sub-expression. An operand's absence is then evidence.
    * marker ABSENT ⇒ the tree was built before the widening (every
      ``contract_materializations.predicate_trees`` row in the database is such a
      tree, and bumping the effects stage does not re-run the static stage). An
      operand's absence says nothing at all, so no conclusion may be drawn FROM it.

    That distinction is load-bearing for exactly one caller: the
    ``no_time_reference`` state of :func:`_duration_from_trees` is a claim that no
    leaf reading the latch touches a clock — a proof BY ABSENCE, and the most
    severe freeze statement this system makes. Reproduced on compiled source:
    ``require(block.timestamp - pausedUntil < 2592000)`` reads as
    ``(2592000, "guard_constant")`` from a tree built at this HEAD and, with
    ``absorbed_operands`` stripped to the persisted shape, as PROVEN INDEFINITE —
    the same source, the opposite answer, in the severe direction.
    """
    return isinstance(tree, dict) and tree.get("operand_absorption") == _OPERAND_ABSORPTION_RECORDED


def _window_ceiling_constant(leaf: Mapping[str, Any], latch_vars: set[str]) -> int | None:
    """The constant this comparison PROVES is a ceiling on the clock-to-latch gap, or
    ``None`` when the comparison's shape does not establish one.

    The harvest used to take the max plausible constant out of
    ``operands ∪ absorbed_operands``, blind to which SIDE of the comparison it sat on
    and to the operator — so three shapes a compiler really produces published a
    number that is not the freeze window at all, in the severity-REDUCING direction
    (``duration_bound_seconds`` is read as a mitigation, gated on fork confirmation):

        require(block.timestamp + 3600 < pausedUntil)   → 3600  = a LEAD TIME
        require(block.timestamp > pausedUntil + 300)    → 300   = a COOLDOWN offset
        require(block.timestamp - pausedUntil > 600)    → 600   = a MINIMUM elapsed

    In all three the real expiry is a storage timestamp (etherfi's shape, which the
    reader's own docstring says must be ``not_determined``).

    ONE shape is decidable from what the static plane records, and it is the only one
    admitted here: the comparison's two slots hold the CONSTANT on one side and the
    collapsed representative of an additive group on the other, and that group holds
    BOTH a seconds clock and the latch — i.e. the compared expression is the signed
    time DIFFERENCE between the clock and the latch, and the constant is its bound.
    Both subtraction orders are admissible (elapsed ``clock - latch`` and remaining
    ``latch - clock`` bound the same gap by the same magnitude), which is what makes
    this arm answerable without the sign the recorder does not keep. Compiled and
    verified: ``block.timestamp - pausedUntil < 2592000``,
    ``2592000 > block.timestamp - pausedUntil`` and
    ``pausedUntil - block.timestamp < 2592000`` all resolve; the ``> 600`` twin of the
    first does not.

    NOT ADMITTED, and the reason is a missing producer fact rather than a judgment
    about the shape: when the absorbed group is ``{latch, constant}`` (the mainstream
    ``require(block.timestamp < pausedUntil + MAX_PAUSE)``) or ``{clock, constant}``,
    the answer turns entirely on the SIGN with which the constant entered that group —
    ``latch + C`` bounds the gap by C and ``latch - C`` does not — and
    ``predicates._stamp_absorbed_operands`` records neither the sign nor the side
    (``absorbed_operands`` is a SORTED list of both inner operands of an ADDITION *or*
    a SUBTRACTION). Two sources with opposite meanings therefore produce byte-identical
    evidence here, and the honest answer for that family is ``not_determined``. The
    recall cost is real and is stated rather than discovered later; recovering it needs
    the static producer to stamp the additive sign, which this module cannot do.
    Reading the sign out of ``leaf["expression"]`` is available and deliberately
    refused: this reader's whole history is the removal of a source-text fallback.

    Two further conditions, both about not being fooled by what the leaf does NOT say:

    * exactly TWO slots. "Which side" is meaningless otherwise, and a 3-slot leaf is a
      real persisted shape (560 of the 5,089 local leaves), not only a hand-built one —
      a threshold/oracle leaf can carry more. None of the 560 holds a latch, a clock
      and a plausible constant today, so this refuses nothing that was being answered.
    * no FOREIGN clock anywhere in the leaf. A leaf whose operand union carries
      both a seconds clock and ``block.number`` cannot say which clock the constant is
      denominated against, and harvesting a block count as seconds understates a
      ~30-day gate as 2.5 days (216000 blocks ≈ 30 days). The outer reader already
      refuses a leaf with NO seconds clock; this refuses the MIXED one, which absorption
      across a mixed expression is what makes reachable.
    """
    operands = _operands(leaf)
    if len(operands) != 2:
        return None
    raw_absorbed = leaf.get("absorbed_operands")
    absorbed = [op for op in raw_absorbed if isinstance(op, dict)] if isinstance(raw_absorbed, list) else []
    # The compared side must be a clock-to-latch difference: both facts inside ONE
    # additive group, which no two-slot operand list can fake.
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
        # Two plausible constants cannot both be the ceiling in a two-slot comparison,
        # but the MAX is kept as the tie-break for the same reason the reader's other
        # ambiguities take it: the value is consumed as a severity reducer, so the
        # longest candidate window is the least mitigating reading.
        best = value if best is None else max(best, value)
    return best


def _duration_from_trees(trees: Mapping[str, Any], latch_vars: set[str]) -> tuple[int | None, str]:
    """The latch's freeze window and HOW it was established.

    A guard leaf whose SHAPE proves a constant is a ceiling on the gap between the
    clock and the latch IS that latch's window (``guard_constant``) —
    :func:`_window_ceiling_constant` is that shape test, and it is the whole of the
    harvest: taking the largest plausible constant out of the operand union instead
    published a lead time, a cooldown offset or a minimum-elapsed as the freeze window,
    and a block count as seconds off a mixed-clock leaf. Scoped to the
    latch because a contract can carry two latches with different semantics (one
    indefinite, one timed) and the wrong constant is a wrong witness, not a rounding
    error.

    ``no_time_reference`` is the PROOF of an indefinite latch: some guard leaf DOES
    read the latch (so the gate was lowered and we are looking at it) and no leaf
    reading it touches a clock, so no passage of time can lift the freeze — a plain
    ``bool frozen`` gate. A latch no lowered leaf reads at all is
    ``not_determined``, never indefinite: that is the tree-absent case, and the
    governing rule is that absence of a proven bound is not proof that no bound
    exists. ``not_determined`` is likewise the honest answer
    for the shape this reader cannot resolve: the guard DOES compare the latch
    against ``block.timestamp`` (so the latch is timed and the freeze does expire)
    but the window itself is not in the code — etherfi's ``PausableUntil`` stores
    it (``$.pauseUntilDuration``, bounded by ``MIN``/``MAX_PAUSE_DURATION`` inside
    a different function's guard), so only a live read of that state or a
    cross-function derivation could name it. All 4 proven ``freeze_pause``
    verdicts in the local corpus are that shape, and every one of them publishes
    ``null``; the function inspector renders that as "window not determined", and
    the proven-indefinite sentence is reserved for ``no_time_reference``.

    A live read would not lift the ``not_determined`` either, and that is a
    conclusion rather than a gap. The window is MUTABLE — ``pauseUntil()`` is
    nullary and ``setPauseUntilDuration(uint256)`` dispatches on all four
    contracts — and nothing observed stops the latch being re-armed the instant it
    lapses, so any window read at one height bounds ONE call and not the freeze.
    Publishing it as a bound would lower freeze severity from a value that its own
    holder can raise, which is why the duration contributes zero severity in
    either direction here rather than a small number.

    ``no_time_reference`` IS A PROOF BY ABSENCE, so it carries two preconditions
    beyond the leaf-local one, and neither is optional. Both are asked of the WHOLE
    gate tree that reads the latch, never of the latch-reading leaf alone: a
    leaf-local reading of "no clock here" was unsound in both directions a real
    compiler produces, and a leaf-local reading of "nothing unread here" is unsound
    for exactly the same reason — the clock and the latch end up in sibling leaves.

    1. A SIBLING LEAF MAY HOLD THE CLOCK. Solidity lowers ``||``/``&&`` into
       separate leaves, so ``require(!frozen || block.timestamp > unpauseAt)``
       yields one leaf holding ``{frozen}`` and another holding
       ``{timestamp, unpauseAt}``. No leaf holds both, and the freeze
       demonstrably expires. This is not an edge case: :func:`_latch_pairs` admits
       only ``bool``-typed writes (or the ERC-7201 pseudo-slot) and a ``bool``
       cannot be compared against ``block.timestamp`` in ANY leaf, so for the whole
       two-variable timed-pause family (``bool paused`` + ``uint pauseExpiry``) the
       leaf-local answers were only ``not_determined`` or proven-most-severe. So
       the clock is looked for across the WHOLE gate tree that reads the latch: a
       clock anywhere in it means time may lift this freeze, and the honest state
       is ``not_determined``. Deliberately conservative — a pure conjunction
       ``!frozen && block.timestamp > x`` genuinely IS indefinite and is demoted
       too, because a tree walk cannot tell a lowered disjunction from a lowered
       conjunction and the cost of being wrong is asymmetric.
    2. THE OPERAND LISTS MUST BE KNOWN-COMPLETE (:func:`_absorption_recorded`). A
       pre-widening tree drops the clock out of ``block.timestamp - pausedUntil <
       2592000`` entirely, so its absence proves nothing. Every persisted tree in
       the database is such a tree, which is why this state has ZERO realised rows
       locally: it is reachable by construction and test-covered (the compiled
       ``TimedLatch`` corpus fixture), and it will start being realised when the
       static stage next re-runs. That is the honest reading of a lower bound, not
       a dead branch. The marker's promise is bounded in the same way the recorder
       is — ADDITIVE, one level deep, and it never enters a callee — so an OPAQUE
       operand (:data:`_OPAQUE_OPERAND_SOURCES`) ANYWHERE in a latch-reading tree
       denies the proof too. Two shapes, both compiled: ``block.timestamp / 2 >
       pausedUntil`` records ``{computed, pausedUntil}`` (the recorder does not
       decompose a quotient, so the clock is inside an operand nobody read), and
       ``require(!frozen || _clock() > unpauseAt)`` — reading time through an
       internal view helper or a time oracle, the Uniswap-V3 / OZ-Governor idiom —
       records ``{view_call _clock(), unpauseAt}`` in the SIBLING leaf with no
       ``block_context`` operand anywhere, so rule 1 does not see it either. Scoping
       this to the tree rather than the leaf is what makes the two rules symmetric:
       both ask "could this tree be hiding a clock from me", and neither may be
       answered from the two slots of one comparison.

       THE RECALL COST IS LARGE AND IS THE POINT, so it is stated rather than
       discovered later. A tree here is a whole FUNCTION's lowered guard set, so an
       unrelated leaf makes the whole tree opaque: SafeMath ``add``/``sub``, an
       ``allowance()`` read, ``toTypedDataHash``, an internal helper's return.
       Projected over the 75 local materializations with the marker force-stamped
       (nothing persisted carries it yet, so the realised delta today is 0 either
       way): of the 16 latches the static plane names, 9 reached the proven state
       before and 1 does after; treating every compared state variable as a
       hypothetical latch, 379 reached it before and 149 after. Every move is OFF the
       proven state and none onto it, which is the only direction this reader is
       allowed to be wrong in — a false "most severe freeze there is" is a claim
       about a contract, ``not_determined`` is a claim about our evidence. Nothing in
       the demoted set showed a plausible hidden clock, and the reader cannot tell
       that from a real one: ``oracle.isExpired()`` is an ``external_bool`` leaf that
       hides the entire time check, which is why the test cannot be narrowed to
       ordering comparisons. Same conservatism as rule 1, one order louder.

    When several leaves each prove a ceiling the MAX is taken: the value is consumed
    as a severity reducer, so the longest candidate window is the least mitigating
    reading of ambiguous evidence.
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
        # A resolved window is positive evidence: all three facts were present in one
        # leaf's union, which no lossy list can fake, so neither precondition above
        # applies to it.
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
    """The pause bound is READ, never hardcoded — and it is per-LATCH.
    Returns ``(seconds_or_None, source)`` where ``source`` is one of the three
    ``DURATION_BOUND_*`` states; the pair is the whole point, because
    ``None`` alone cannot say whether the latch has no window or whether we
    failed to find one.

    A contract can hold an indefinite latch and a timed one at once; the writer
    function pins which. An indefinite latch legitimately yields ``None`` (the
    recipe then skips the auto-expiry probe and records no duration bound), and
    emitting the timed latch's constant for it would be a false witness.

    ONE source, and it is the IR: a constant that the latch's own guard leaf
    compares ``block.timestamp`` against IS that latch's window
    (:func:`_duration_from_trees`). There used to be a source-text fallback that
    scraped ``constant`` declarations whose NAME contained PAUSE/FREEZE out of
    every file mentioning the latch. That is identifier matching, and the value it
    produced did not stay in the transcript: it reaches the claim witness as
    ``duration_bound_seconds``, where the documented scorer contract
    (``claims_bridge._observed_summary``) reads a bound as a severity REDUCER. A
    cooldown, a minimum, or an unrelated timer picked up by the name pattern would
    therefore have discounted an indefinite freeze. No bound is the correct and
    conservative output — but "no bound" and "no bound FOUND" are different facts
    and the returned ``source`` is what keeps them apart. The old contract
    ("``duration_bound_seconds is None`` + ``auto_expiry is None`` means indefinite
    latch, most severe") was false on every row that had it: the corpus's four
    proven rows are all ``pauseUntil`` — a latch that expires — and they published
    exactly that pair.

    What is deliberately NOT read here, stated so the gap is not mistaken for an
    oversight: etherfi's window lives in ``$.pauseUntilDuration``, a storage value
    with a public getter, bounded by ``MIN_PAUSE_DURATION``/``MAX_PAUSE_DURATION``
    inside ``setPauseUntilDuration``'s own guard. Reading it means either a live
    ``eth_call`` (a per-deployment observation — it would belong in the state-plane
    residue, never in the code-plane ``details`` this value rides) or a
    cross-function derivation the static plane does not record (the latch write's
    assigned-expression origins are not in the effects artifact). Selecting the
    getter by NAME is the identifier matching this docstring already refuses. So
    the honest published state for that shape is ``not_determined``, and the fork
    still cross-checks any bound this reader DOES find by warping past it."""
    return _duration_from_trees(facts.trees, latch_vars)


def _state_changing_functions(facts: ContractFacts) -> list[str]:
    return sorted(name for name, info in facts.effects.items() if isinstance(info, dict) and info.get("state_changing"))


def _entry_point_for(
    facts: ContractFacts, name: str, principals: Mapping[str, str], *, caller_override: str | None = None
) -> EntryPoint | None:
    """One blast-radius probe. ``from_addr`` is THAT function's own resolved
    principal — a contract-wide caller would be rejected by every gated entry
    point pre-pause, collapsing the observed radius to nothing. A function with no
    resolved principal is still probed, from a neutral identity: it may be public,
    and skipping it could only lose a witness.

    ``caller_override`` forces a specific caller (the pauser-identity probe):
    a predicted victim whose OWN principal could not be resolved is additionally
    probed from the pause principal, so a gate the neutral caller can't pass is
    still exercised by a caller that can."""
    sig = facts.canonical_signature(name)
    selector = _selector_of(sig)
    types = _parse_arg_types(sig)
    if not selector or types is None:
        return None
    caller = caller_override or principals.get(selector, NEUTRAL_CALLER)
    # Any direction: a blast-radius probe is not scoped to one value flow, it just
    # needs each argument to carry a value the role evidence justifies.
    probe_fn = facts_for_name(facts, name)
    roles = integer_param_roles(probe_fn, types) if probe_fn is not None else {}
    calldata = encode_calldata(
        selector,
        sig,
        substitutions=_arg_values(types, identity=caller, amount=ARG_AMOUNT, integer_roles=roles).substitutions,
    )
    if calldata is None:
        return None
    # Gas only: the caller must be able to pay, or an out-of-gas revert pre-pause
    # would look like the pause froze this point.
    fixtures = (ForkFixture(kind="set_balance", address=caller, value=hex(FIXTURE_BALANCE_WEI)),)
    return EntryPoint(key=name, calldata=calldata, from_addr=caller, fixtures=fixtures)


def _pauser_identity_probes(
    facts: ContractFacts, predicted: Sequence[str], principals: Mapping[str, str], pauser: str
) -> list[EntryPoint]:
    """A PREDICTED pause victim whose own caller could not be resolved is probed from
    ``NEUTRAL_CALLER`` and rejected by its auth gate pre-pause, hiding any freeze
    from the diff.
    Add a second probe of each such victim from the PAUSE principal — often the ops
    multisig, which reaches many gated functions.

    Same ``EntryPoint`` key ⇒ the succeeding-set unions the identities: a victim
    counts as succeeding if EITHER caller reaches it pre-pause, and enters the
    observed blast only when it reverts under BOTH post-pause. So this can only ADD
    witnessed freezes, never manufacture one — the observed radius stays a sound
    lower bound.

    Scoped tightly so it adds probes only where they can help: (1) the PREDICTED set
    only (never the probe-everything fallback); (2) victims behind a CALLER-authority
    gate — a pause-only or permissionless victim is already reachable by the neutral
    caller, so a pauser probe there is pure redundant cost; (3) victims whose own
    principal could not be resolved (a resolved one already probes as itself)."""
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
