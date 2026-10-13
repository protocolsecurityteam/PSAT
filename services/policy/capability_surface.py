"""Narrow projections of the resolver's capability algebra (caller rows, public paths, residual checks), in one place
so DB and artifact paths don't drift.
"""

from __future__ import annotations

import contextlib
import contextvars
import copy
import functools
import hashlib
import itertools
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, ParamSpec, TypeVar

from services.resolution.capabilities import DEFERRED_MARKER, is_reach_not_determined
from services.resolution.permissionless_shapes import CALLER_GATE_BASIS_TAGS, earned_public_enabled
from utils.scoring_status import OPENNESS_STATES, TRACE_STEP_ENUMERABLE_ROLE_STORE, TRACE_STEP_SOLMATE_ROLES_AUTHORITY

# Work units (condition ids touched) one projection may spend; a capability over it publishes not_determined.
PROJECTION_WORK_BUDGET = 20_000_000
PROJECTION_BUDGET_EXCEEDED = "projection_budget_exceeded"
# Paths an explicit public-path list may hold; openness and caller rows never read the list.
PUBLIC_PATH_LIST_BUDGET = 256
PUBLIC_PATH_LIST_BUDGET_EXCEEDED = "public_path_list_budget_exceeded"


@dataclass
class PublicPathList:
    paths: list[list[dict[str, Any]]]
    # ``None`` only when ``paths`` holds every public path.
    incomplete_reason: str | None = None


@dataclass
class CapabilitySurface:
    principal_rows: list[dict[str, Any]] = field(default_factory=list)
    residual: list[dict[str, Any]] = field(default_factory=list)
    # A path whose callers aren't determined (an unread reach condition): it may be open, so the rows beside it are no
    # proof of a restriction.
    open_not_determined: bool = False
    public_path_count: int = 0
    # Set when the projection stopped at its work budget: neither the rows nor the paths are a finished answer.
    not_determined_reason: str | None = None
    _path_condition_ids: tuple[int, ...] = field(default=(), repr=False, compare=False)
    _table: list[dict[str, Any]] = field(default_factory=list, repr=False, compare=False)
    _paths: Any = field(default=None, repr=False, compare=False)

    @property
    def authority_public(self) -> bool:
        return self.public_path_count > 0

    @property
    def conditions(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for row in self.principal_rows:
            details = row.get("details")
            if isinstance(details, dict):
                out.extend(_condition_dicts(details.get("conditions")))
        out.extend(copy.deepcopy(self._table[i]) for i in self._path_condition_ids)
        return _unique_conditions(out)

    def public_path_list(self, budget: int = PUBLIC_PATH_LIST_BUDGET) -> PublicPathList:
        """The public paths themselves, in expansion order, at most ``budget`` of them."""
        if self._paths is None or not self.public_path_count:
            return PublicPathList(paths=[])
        expansion = itertools.islice(_enumerate_paths(self._paths), budget)
        paths = [[copy.deepcopy(self._table[i]) for i in path] for path in expansion]
        reason = PUBLIC_PATH_LIST_BUDGET_EXCEEDED if self.public_path_count > budget else None
        return PublicPathList(paths=paths, incomplete_reason=reason)


# Persisted beside ``authority_public``; see ``capability_surface_openness``.
AUTHORITY_OPENNESS_VALUES = OPENNESS_STATES


def capability_surface_openness(cap_dict: dict[str, Any], surface: CapabilitySurface) -> str:
    """Three-state authority verdict for one capability.

    * ``open`` — a public path was earned; exactly ``authority_public``.
    * ``restricted`` — a restriction was witnessed: caller rows, or a complete enumeration admitting nobody, with no
    path beside them that may be open.
    * ``not_determined`` — neither (unsupported, external_check_only, irreducible residual, a path that may be open),
    all of which the bool reported as ``False``.

    Never raises. ``restricted`` means a restriction exists, not that these are all the callers (that's
    ``membership_quality``).
    """
    if surface.not_determined_reason is not None:
        return "not_determined"
    if surface.authority_public:
        return "open"
    if surface.open_not_determined:
        return "not_determined"
    if surface.principal_rows:
        return "restricted"
    if _is_resolved_empty_capability(cap_dict):
        return "restricted"
    return "not_determined"


# Above the measured 203-block per-address cursor skew within one job, far below the ~2-week backfill-stall signature
# ``fleet`` alarms on.
CAPABILITY_INDEX_STALE_BLOCKS = 1_000


def capability_currency(cap_dict: Any, *, index_head: int | None) -> dict[str, Any]:
    """Three-state currency of a capability against the index frontier (``index_head``, a local read).

    A bare ``last_indexed_block`` isn't a currency claim: two capabilities in one job sat 203 blocks apart.

    * ``current`` — within ``CAPABILITY_INDEX_STALE_BLOCKS`` of the frontier.
    * ``stale`` — further behind; later grants/revokes are missing.
    * ``not_determined`` — no fold height or no frontier. Must never render as ``current``.

    ``lag_blocks`` is ``None`` when not determined, never 0 (a zero lag must be earned).
    """
    heights = _last_indexed_blocks(cap_dict)
    lowest = min(heights) if heights else None
    if lowest is None or index_head is None:
        return {"verdict": "not_determined", "last_indexed_block": lowest, "index_head": index_head, "lag_blocks": None}
    lag = max(0, int(index_head) - int(lowest))
    return {
        "verdict": "stale" if lag >= CAPABILITY_INDEX_STALE_BLOCKS else "current",
        "last_indexed_block": lowest,
        "index_head": int(index_head),
        "lag_blocks": lag,
    }


# Admissible steps are enumerated, since any producer could append a step: ``solmate_roles_authority`` defers without a
# ``backfill_complete`` cursor; ``enumerable_role_store`` folds at the MIN over complete cursors; the two live reads are
# single pinned calls.
_COVERAGE_PROVING_TRACE_STEPS = frozenset(
    {"solmate_roles_authority", "enumerable_role_store", "live_getter_resolution", "live_slot_resolution"}
)

# Only reasons reporting a completed read. ``empty_by_design`` rests on an accessor name; failure states never
# license credit; ``owner_read_burn_address`` rests on a convention, not a read.
_READ_CONFIRMED_EMPTY_REASONS = frozenset({"owner_read_zero", "slot_read_zero"})


def exact_empty_credit(cap_dict: Any) -> dict[str, Any]:
    """Has this capability earned the "nobody can call this" credit?

    Consumers awarded it on ``exact`` + ``members == []`` alone, which provenance-less empties also satisfy. All three
    are required:

    * a trace step from a coverage-proving producer;
    * an observation block (``observed_at_block`` or equal-heights ``exact_as_of``), never ``last_indexed_block``, a MIN
    across operands;
    * an ``empty_reason`` naming a completed read.

    Otherwise ``not_determined`` with ``missing`` naming the gap. Withholds credit; never asserts callers exist.
    """
    missing: list[str] = []
    if not isinstance(cap_dict, dict):
        return {"verdict": "not_determined", "missing": ["capability"]}
    if cap_dict.get("kind") != "finite_set" or cap_dict.get("members") != []:
        return {"verdict": "not_applicable", "missing": []}
    if cap_dict.get("membership_quality") != "exact" or cap_dict.get("confidence") != "enumerable":
        missing.append("exact_enumerable")
    trace = cap_dict.get("trace")
    steps = [s.get("step") for s in trace if isinstance(s, dict)] if isinstance(trace, list) else []
    if not any(step in _COVERAGE_PROVING_TRACE_STEPS for step in steps):
        missing.append("coverage_proving_step")
    block, block_source = _observation_block(cap_dict)
    if block is None:
        missing.append("observation_block")
    reason = cap_dict.get("empty_reason")
    if reason not in _READ_CONFIRMED_EMPTY_REASONS:
        missing.append("read_confirmed_empty_reason")
    if missing:
        return {"verdict": "not_determined", "missing": missing}
    return {
        "verdict": "earned",
        "missing": [],
        "block": block,
        "block_source": block_source,
        "empty_reason": reason,
    }


def _observation_block(cap_dict: dict[str, Any]) -> tuple[int | None, str | None]:
    """The height the set was observed empty at. Not ``last_indexed_block`` (see :func:`exact_empty_credit`)."""
    trace = cap_dict.get("trace")
    if isinstance(trace, list):
        for step in trace:
            if not isinstance(step, dict):
                continue
            observed = step.get("observed_at_block")
            if isinstance(observed, int) and not isinstance(observed, bool):
                return observed, "trace.observed_at_block"
    exact_as_of = cap_dict.get("exact_as_of")
    if isinstance(exact_as_of, int) and not isinstance(exact_as_of, bool):
        return exact_as_of, "exact_as_of"
    return None, None


def _last_indexed_blocks(cap_dict: Any) -> list[int]:
    """The lowest governs: an AND/OR is only as current as its least-current conjunct."""
    out: list[int] = []
    if not isinstance(cap_dict, dict):
        return out
    height = cap_dict.get("last_indexed_block")
    if isinstance(height, int) and not isinstance(height, bool):
        out.append(height)
    for child in _child_dicts(cap_dict):
        out.extend(_last_indexed_blocks(child))
    signer = cap_dict.get("signer")
    if isinstance(signer, dict):
        out.extend(_last_indexed_blocks(signer))
    return out


# ``enumerable_role_store`` dissolves role identity (probes the gate, not a role), so its rows are role-gated with role
# not determined.
_ROLE_DISSOLVING_TRACE_STEPS = frozenset({TRACE_STEP_ENUMERABLE_ROLE_STORE})


def capability_role_grants(cap_dict: dict[str, Any]) -> list[dict[str, Any]] | None:
    """Witnessed ``(role, principals)`` grants for one capability (``authority_roles`` was literally ``[]`` on every
    row).

    * non-empty — proven: a trace names exactly one role for the enumerated set.
    * ``None`` — not determined: role identity dissolved, multiple roles (per-member attribution unrecoverable), or an
    ``unsupported`` node.
    * ``[]`` — proven absent: the gate was lowered with no role-keyed authority.

    ``[]`` requires a lowered gate; openness ``not_determined`` means it wasn't, so the answer is ``None``. Missing this
    let 12 ether.fi rows claim "proven not role-gated", including two ``grantRole`` entry points. A non-empty grant is
    kept regardless of openness. Reads only the persisted shape.
    """
    grants: dict[int, list[str]] = {}
    not_determined = False

    def visit(node: Any) -> None:
        nonlocal not_determined
        if not isinstance(node, dict):
            return
        if node.get("kind") == "unsupported":
            not_determined = True
        for step in node.get("trace") or []:
            if not isinstance(step, dict):
                continue
            name = step.get("step")
            if name in _ROLE_DISSOLVING_TRACE_STEPS:
                not_determined = True
                continue
            if name != TRACE_STEP_SOLMATE_ROLES_AUTHORITY:
                continue
            roles = [r for r in (step.get("roles") or []) if isinstance(r, int)]
            if not roles:
                # No role carries a public Solmate capability.
                continue
            members = node.get("members")
            if node.get("kind") != "finite_set" or not isinstance(members, list) or not members:
                not_determined = True
                continue
            if len(roles) > 1:
                not_determined = True
                continue
            grants.setdefault(roles[0], [])
            for member in members:
                if isinstance(member, str) and member.startswith("0x") and len(member) == 42:
                    lowered = member.lower()
                    if lowered not in grants[roles[0]]:
                        grants[roles[0]].append(lowered)
        for child in _child_dicts(node):
            visit(child)
        signer = node.get("signer")
        if isinstance(signer, dict):
            visit(signer)

    visit(cap_dict)
    if not_determined:
        return None
    witnessed = [
        {
            "role": role,
            "principals": [
                {"address": address, "resolved_type": None, "details": {"source": "semantic_capability:role_grant"}}
                for address in members
            ],
        }
        for role, members in sorted(grants.items())
        if members
    ]
    if witnessed:
        return witnessed
    if grants:
        # A role was named but no well-formed member survived: role-keyed, holders undetermined.
        return None
    if capability_surface_openness(cap_dict, project_capability_surface(cap_dict)) == "not_determined":
        return None
    return []


def capability_surface_status(cap_dict: dict[str, Any], surface: CapabilitySurface) -> str | None:
    if surface.not_determined_reason is not None:
        return "unsupported"
    if surface.authority_public:
        return "public"
    # Only with no caller rows: an AND with real callers beside an exact-empty bound side-condition keeps them (the Veda
    # caller-drop).
    if not surface.principal_rows and _is_resolved_empty_capability(cap_dict):
        return "resolved_empty"
    if cap_dict.get("kind") == "unsupported" and not surface.principal_rows:
        return "unsupported"
    return None


_P = ParamSpec("_P")
_R = TypeVar("_R")

_projection_memo: contextvars.ContextVar[dict[bytes, Any] | None] = contextvars.ContextVar(
    "psat_projection_memo", default=None
)


@contextlib.contextmanager
def projection_pass() -> Iterator[None]:
    """Share projections by content for one pass; a nested pass reuses the outer one."""
    if _projection_memo.get() is not None:
        yield
        return
    token = _projection_memo.set({})
    try:
        yield
    finally:
        _projection_memo.reset(token)


def projection_scoped(fn: Callable[_P, _R]) -> Callable[_P, _R]:
    @functools.wraps(fn)
    def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        with projection_pass():
            return fn(*args, **kwargs)

    return wrapper


def project_capability_surface(
    cap_dict: dict[str, Any],
    *,
    safe_address_lookup: dict[str, str] | None = None,
    function_signature: str | None = None,
) -> CapabilitySurface:
    """Caller rows, public paths and residual checks of one capability, computed on the tree in one bottom-up pass.

    Equal to expanding the tree into its paths (an AND's paths are the products of its children's) and merging rows
    by ``(address, origin, principal_type)``, without materializing the product.
    """
    memo = _projection_memo.get()
    key = None
    result = None
    # A function's capability carries every effect site's capability beside it: keying it costs more than projecting
    # it, and it is projected only a few times. The site capabilities are the ones projected again and again.
    if memo is not None and "effect_capabilities" not in cap_dict:
        key = _projection_key(cap_dict, safe_address_lookup, function_signature)
        result = memo.get(key)
    if result is None:
        projector = _Projector(safe_address_lookup=safe_address_lookup, function_signature=function_signature)
        try:
            summary: _Summary | None = projector.node(cap_dict)
        except _ProjectionBudgetExceeded:
            summary = None
        result = (summary, projector.table)
        if memo is not None and key is not None:
            memo[key] = result
    summary, table = result
    if summary is None:
        return CapabilitySurface(
            residual=[
                {
                    "kind": "unsupported",
                    "unsupported_reason": PROJECTION_BUDGET_EXCEEDED,
                    "confidence": "check_only",
                }
            ],
            not_determined_reason=PROJECTION_BUDGET_EXCEEDED,
        )
    return CapabilitySurface(
        principal_rows=[acc.materialize(table) for acc in summary.rows.values()],
        residual=list(summary.residual),
        open_not_determined=summary.ond,
        public_path_count=summary.count,
        _path_condition_ids=summary.punion,
        _table=table,
        _paths=summary.pexpr,
    )


def not_determined_capability(reason: str) -> dict[str, Any]:
    """The capability published in place of one whose computation hit a budget."""
    return {"kind": "unsupported", "unsupported_reason": reason, "confidence": "check_only"}


def bounded_capability(cap_dict: dict[str, Any]) -> dict[str, Any]:
    """``cap_dict``, or the unsupported capability naming the budget its projection exceeded."""
    surface = project_capability_surface(cap_dict)
    if surface.not_determined_reason is None:
        return cap_dict
    return not_determined_capability(surface.not_determined_reason)


def _projection_key(cap_dict: Any, safe_address_lookup: dict[str, str] | None, function_signature: str | None) -> bytes:
    # ``repr`` keeps types (a tuple of children isn't a list of them) and insertion order; a differently ordered equal
    # dict only misses the memo.
    material = repr((cap_dict, safe_address_lookup, function_signature, earned_public_enabled()))
    return hashlib.blake2b(material.encode(), digest_size=20).digest()


class _ProjectionBudgetExceeded(Exception):
    pass


_RowKey = tuple[str, str, str]
_Ids = tuple[int, ...]


class _RowAcc:
    """Every copy of one ``(address, origin, principal_type)`` row the expansion would hold, merged.

    ``first`` is the first copy's conditions and ``union`` all copies' conditions, both in expansion order; ``multi`` is
    whether there is more than one copy (a lone copy keeps its details as they are).
    """

    __slots__ = ("row", "first", "union", "multi", "touched", "trace", "has_quality", "quality")

    def __init__(self, row, first, union, multi, touched, trace, has_quality, quality):
        self.row: dict[str, Any] = row
        self.first: _Ids = first
        self.union: _Ids = union
        self.multi: bool = multi
        self.touched: bool = touched
        self.trace: list[Any] = trace
        self.has_quality: bool = has_quality
        self.quality: Any = quality

    def materialize(self, table: list[dict[str, Any]]) -> dict[str, Any]:
        # A copy: the summary may be shared with later projections of the same content in this pass.
        out = copy.deepcopy(self.row)
        details = out["details"] = dict(out.get("details") or {})
        if self.multi:
            details["conditions"] = [copy.deepcopy(table[i]) for i in self.union]
            if self.trace:
                details["trace"] = copy.deepcopy(self.trace)
            if self.has_quality:
                details["membership_quality"] = self.quality
        elif self.touched:
            details["conditions"] = [copy.deepcopy(table[i]) for i in self.first]
        return out


class _Summary:
    __slots__ = ("rows", "residual", "ond", "count", "pfirst", "punion", "pexpr", "nobody")

    def __init__(
        self,
        rows: dict[_RowKey, _RowAcc] | None = None,
        residual: list[dict[str, Any]] | None = None,
        ond: bool = False,
        count: int = 0,
        pfirst: _Ids = (),
        punion: _Ids = (),
        pexpr: Any = None,
        nobody: bool = False,
    ):
        self.rows = rows if rows is not None else {}
        self.residual = residual if residual is not None else []
        # A path that may be open (``open_not_determined``).
        self.ond = ond
        # The number of public paths, the first one, and every condition on any of them, in expansion order.
        self.count = count
        self.pfirst = pfirst
        self.punion = punion
        # How to enumerate the paths: ("leaf", ids) | ("or", a, b) | ("and", a, b) | ("app", a, ids).
        self.pexpr = pexpr
        # Proven to admit no end user (``_is_proven_empty``), as opposed to having nothing to show for any other reason.
        self.nobody = nobody

    @property
    def valid(self) -> bool:
        return bool(self.rows) or self.count > 0

    def may_admit_anyone(self) -> bool:
        return self.count > 0 or self.ond or not (self.valid or self.nobody)


_EMPTY = _Summary()


class _Projector:
    """One projection: the interned condition table, the work spent, and per-node memo of authority blockers."""

    def __init__(self, *, safe_address_lookup: dict[str, str] | None, function_signature: str | None):
        self.safe_address_lookup = safe_address_lookup
        self.function_signature = function_signature
        self.index: dict[str, int] = {}
        self.table: list[dict[str, Any]] = []
        self.work = 0
        self.earned_public = earned_public_enabled()
        self.blockers: dict[int, tuple[dict[str, Any], bool]] = {}
        self.not_read = self.intern([_CONDITION_NOT_READ])

    def spend(self, units: int) -> None:
        self.work += units
        if self.work > PROJECTION_WORK_BUDGET:
            raise _ProjectionBudgetExceeded

    def intern(self, conditions: list[dict[str, Any]]) -> _Ids:
        """Ids of ``_condition_dicts``-clean conditions, first occurrences only, keyed as ``_unique_conditions``."""
        self.spend(len(conditions))
        out: dict[int, None] = {}
        for condition in conditions:
            key = repr(sorted(condition.items()))
            ident = self.index.get(key)
            if ident is None:
                ident = self.index[key] = len(self.table)
                self.table.append(condition)
            out[ident] = None
        return tuple(out)

    def unique(self, *parts: _Ids) -> _Ids:
        self.spend(sum(len(part) for part in parts))
        return tuple(dict.fromkeys(itertools.chain(*parts)))

    def node(self, cap_dict: dict[str, Any]) -> _Summary:
        self.spend(1)
        kind = cap_dict.get("kind")
        node_conditions = _condition_dicts(cap_dict.get("conditions"))

        if is_reach_not_determined(cap_dict):
            return _Summary(residual=[dict(cap_dict)], ond=True)
        if kind == "finite_set":
            surface = self.leaf_rows(_rows_for_finite_set(cap_dict, node_conditions))
            surface.nobody = _is_proven_empty(cap_dict)
            return surface
        if kind == "threshold_group":
            return self.leaf_rows(
                _rows_for_threshold_group(
                    cap_dict,
                    conditions=node_conditions,
                    safe_address_lookup=self.safe_address_lookup,
                    function_signature=self.function_signature,
                )
            )
        if kind == "signature_witness":
            return self.leaf_rows(_rows_for_signature_witness(cap_dict, node_conditions))
        if kind == "conditional_universal":
            return self.leaf_path(node_conditions)
        if kind == "OR":
            surface = _EMPTY
            for child in _child_dicts(cap_dict):
                surface = self.or_(surface, self.node(child))
            return self.append(surface, node_conditions)
        if kind == "AND":
            # Start empty: ``anyone`` must be earned by a conditional_universal child, not minted by AND-ing checks.
            surface = _EMPTY
            blocked = False
            for child in _child_dicts(cap_dict):
                child_surface = self.node(child)
                if self.earned_public and not child_surface.valid and self.is_blocker(child):
                    blocked = True
                surface = self.and_(surface, child_surface)
            surface = self.append(surface, node_conditions)
            if blocked and surface.count:
                # An unresolved root-caller authorization AND-ed in means the function is gated with principals unknown;
                # sibling public paths aren't earned. See ``_is_root_authority_blocker``.
                surface = _Summary(rows=surface.rows, residual=surface.residual, ond=surface.ond, nobody=surface.nobody)
            return surface
        if kind == "cofinite_blacklist":
            # A cofinite is a public path with the denylist as a side-condition. Quality doesn't change openness but
            # does change condition text: a ``lower_bound`` denylist isn't the complete exclusion set. Absent quality
            # means a pre-fix row, rendered as unknown.
            quality = cap_dict.get("blacklist_quality")
            excluded = len(cap_dict.get("blacklist") or [])
            if quality == "exact":
                description = f"denylist exclusion ({excluded} excluded, exhaustive)"
            elif quality is None:
                description = f"denylist exclusion ({excluded} known excluded; completeness not recorded)"
            else:
                description = f"denylist exclusion (at least {excluded} excluded; not exhaustive)"
            denial = {"kind": "denylist", "description": description}
            return self.leaf_path(node_conditions + [denial])
        return _Summary(residual=[dict(cap_dict)])

    def is_blocker(self, cap_dict: dict[str, Any]) -> bool:
        hit = self.blockers.get(id(cap_dict))
        if hit is None:
            hit = self.blockers[id(cap_dict)] = (cap_dict, _is_root_authority_blocker(cap_dict, self))
        return hit[1]

    def leaf_path(self, conditions: list[dict[str, Any]]) -> _Summary:
        ids = self.intern(conditions)
        return _Summary(count=1, pfirst=ids, punion=ids, pexpr=("leaf", ids))

    def leaf_rows(self, rows: list[dict[str, Any]]) -> _Summary:
        accs: dict[_RowKey, _RowAcc] = {}
        for row in rows:
            self.spend(1)
            raw_details = row.get("details")
            details: dict[str, Any] = raw_details if isinstance(raw_details, dict) else {}
            first = self.intern(_condition_dicts(details.get("conditions")))
            acc = _RowAcc(
                row=row,
                first=first,
                union=first,
                multi=False,
                touched=False,
                trace=list(details.get("trace") or []),
                has_quality="membership_quality" in details,
                quality=details.get("membership_quality"),
            )
            key = _row_key(row)
            accs[key] = self.merge(accs[key], acc) if key in accs else acc
        return _Summary(rows=accs)

    def merge(self, earlier: _RowAcc, later: _RowAcc) -> _RowAcc:
        trace = list(earlier.trace)
        self.spend(len(trace) + len(later.trace))
        trace.extend(item for item in later.trace if item not in trace)
        return _RowAcc(
            row=earlier.row,
            first=earlier.first,
            union=self.unique(earlier.union, later.union),
            multi=True,
            touched=earlier.touched,
            trace=trace,
            has_quality=earlier.has_quality or later.has_quality,
            quality=merged_membership_quality(earlier.quality, later.quality),
        )

    def concat(self, *parts: dict[_RowKey, _RowAcc]) -> dict[_RowKey, _RowAcc]:
        out: dict[_RowKey, _RowAcc] = {}
        for part in parts:
            for key, acc in part.items():
                out[key] = self.merge(out[key], acc) if key in out else acc
        return out

    def with_conditions(self, acc: _RowAcc, ids: _Ids) -> _RowAcc:
        """Every copy with ``ids`` appended."""
        return _RowAcc(
            row=acc.row,
            first=self.unique(acc.first, ids),
            union=self.unique(acc.first, ids, acc.union),
            multi=acc.multi,
            touched=True,
            trace=acc.trace,
            has_quality=acc.has_quality,
            quality=acc.quality,
        )

    def crossed(self, acc: _RowAcc, paths: _Summary) -> _RowAcc:
        """Every copy once per path of ``paths``, with that path's conditions appended."""
        return _RowAcc(
            row=acc.row,
            first=self.unique(acc.first, paths.pfirst) if paths.pfirst else acc.first,
            union=self.unique(acc.first, paths.punion, acc.union),
            multi=acc.multi or paths.count > 1,
            touched=acc.touched or bool(paths.pfirst),
            trace=acc.trace,
            has_quality=acc.has_quality,
            quality=acc.quality,
        )

    def append(self, surface: _Summary, raw: list[dict[str, Any]]) -> _Summary:
        """Node conditions narrow a real authorization; they never constitute one."""
        if not raw:
            return surface
        ids = self.intern(raw)
        rows = {key: self.with_conditions(acc, ids) for key, acc in surface.rows.items()}
        if not surface.count:
            return _Summary(rows=rows, residual=surface.residual, ond=surface.ond, nobody=surface.nobody)
        return _Summary(
            rows=rows,
            residual=surface.residual,
            ond=surface.ond,
            count=surface.count,
            pfirst=self.unique(surface.pfirst, ids),
            punion=self.unique(surface.pfirst, ids, surface.punion),
            pexpr=("app", surface.pexpr, ids),
            nobody=surface.nobody,
        )

    def or_(self, left: _Summary, right: _Summary) -> _Summary:
        if left is _EMPTY:
            return right
        self.spend(len(left.residual) + len(right.residual))
        if not right.count:
            pfirst, punion, pexpr = left.pfirst, left.punion, left.pexpr
        elif not left.count:
            pfirst, punion, pexpr = right.pfirst, right.punion, right.pexpr
        else:
            pfirst, punion, pexpr = left.pfirst, self.unique(left.punion, right.punion), ("or", left.pexpr, right.pexpr)
        return _Summary(
            rows=self.concat(left.rows, right.rows),
            residual=left.residual + right.residual,
            ond=left.ond or right.ond,
            count=left.count + right.count,
            pfirst=pfirst,
            punion=punion,
            pexpr=pexpr,
            nobody=left.nobody and right.nobody,
        )

    def and_(self, left: _Summary, right: _Summary) -> _Summary:
        self.spend(len(left.residual) + len(right.residual))
        if not left.valid and not right.valid:
            surface = _Summary(residual=left.residual + right.residual)
        elif not right.valid:
            # The pure-check side is a side-condition, not grounds to drop the callers; collapsing to residual silently
            # dropped the Veda Teller caller sets.
            surface = self.with_side_checks(left, right.residual)
        elif not left.valid:
            surface = self.with_side_checks(right, left.residual)
        else:
            surface = self.product(left, right)
        # A path that may be open stays one beside anything but a conjunct that admits only its callers, or nobody.
        surface.ond = (left.ond and right.may_admit_anyone()) or (right.ond and left.may_admit_anyone())
        surface.nobody = left.nobody or right.nobody
        return surface

    def with_side_checks(self, valid: _Summary, side_residual: list[dict[str, Any]]) -> _Summary:
        """Keep ``valid``'s callers/public paths, folding the other branch in as side-conditions (and in ``residual``
        for the API).
        """
        conditions = [cond for residual in side_residual for cond in _residual_as_conditions(residual)]
        appended = self.append(valid, conditions)
        return _Summary(
            rows=appended.rows,
            residual=valid.residual + side_residual,
            count=appended.count,
            pfirst=appended.pfirst,
            punion=appended.punion,
            pexpr=appended.pexpr,
        )

    def product(self, left: _Summary, right: _Summary) -> _Summary:
        rows = self.concat(
            {key: self.crossed(acc, right) for key, acc in left.rows.items()} if right.count else {},
            {key: self.crossed(acc, left) for key, acc in right.rows.items()} if left.count else {},
            # A side that may admit anyone passes the other side's callers through, as a public path would.
            {key: self.with_conditions(acc, self.not_read) for key, acc in left.rows.items()} if right.ond else {},
            {key: self.with_conditions(acc, self.not_read) for key, acc in right.rows.items()} if left.ond else {},
        )
        residual = left.residual + right.residual
        if left.rows and right.rows:
            residual.append({"kind": "unsupported", "unsupported_reason": "and_multiple_principal_shapes"})
        if not (left.count and right.count):
            return _Summary(rows=rows, residual=residual)
        return _Summary(
            rows=rows,
            residual=residual,
            count=left.count * right.count,
            pfirst=self.unique(left.pfirst, right.pfirst),
            punion=self.unique(left.pfirst, right.punion, left.punion),
            pexpr=("and", left.pexpr, right.pexpr),
        )


def _row_key(row: dict[str, Any]) -> _RowKey:
    return (
        str(row.get("address") or "").lower(),
        str(row.get("origin") or ""),
        str(row.get("principal_type") or ""),
    )


def _enumerate_paths(expr: Any) -> Iterator[_Ids]:
    kind = expr[0]
    if kind == "leaf":
        yield expr[1]
    elif kind == "or":
        yield from _enumerate_paths(expr[1])
        yield from _enumerate_paths(expr[2])
    elif kind == "and":
        for left in _enumerate_paths(expr[1]):
            for right in _enumerate_paths(expr[2]):
                yield tuple(dict.fromkeys(left + right))
    else:
        for path in _enumerate_paths(expr[1]):
            yield tuple(dict.fromkeys(path + expr[2]))


def _is_root_authority_blocker(cap_dict: dict[str, Any], projector: _Projector | None = None) -> bool:
    """Is this an unresolved authorization on the root caller? Public must be earned, so such a check AND-ed with
    public side-conditions gates the function.

    Blocks:
      - ``external_check_only`` with a ``CALLER_GATE_BASIS_TAGS`` tag (untagged checks are downstream probes that fold
    as side-conditions, e.g. Veda teller->vault ``requiresAuth``).
      - ``unsupported``, and an unread reach condition (a path that may be open is no earned one).
      - an empty non-exact ``finite_set`` (authority value unread); exact-empty / by-design sets are resolved.
      - an empty set enumerated from a Solmate ``RolesAuthority``: provably nobody.
      - AND if any child blocks; OR only if every disjunct blocks.

    Bound-subject capabilities never block: they condition the intermediate contract, not the end user.
    """
    if cap_dict.get("subject", "root") != "root":
        return False
    kind = cap_dict.get("kind")
    if is_reach_not_determined(cap_dict):
        return True
    if kind == "finite_set":
        if cap_dict.get("members"):
            return False
        if _is_role_store_provably_empty(cap_dict):
            return True
        # Resolved, not unresolved; mirrors ``_is_resolved_empty_capability``.
        if cap_dict.get("membership_quality") == "exact" or cap_dict.get("empty_reason") == "empty_by_design":
            return False
        return True
    if kind == "unsupported":
        return True
    if kind == "external_check_only":
        extra = (cap_dict.get("check") or {}).get("extra") or {}
        basis = extra.get("basis") or []
        return any(tag in CALLER_GATE_BASIS_TAGS for tag in basis)
    if kind == "AND":
        return any(_child_blocks(child, projector) for child in _child_dicts(cap_dict))
    if kind == "OR":
        children = _child_dicts(cap_dict)
        return bool(children) and all(_child_blocks(child, projector) for child in children)
    return False


def _child_blocks(cap_dict: dict[str, Any], projector: _Projector | None) -> bool:
    return projector.is_blocker(cap_dict) if projector is not None else _is_root_authority_blocker(cap_dict)


# Both settle cold reads to deferral, so an exact-empty here is real, not under-resolution.
_PROVABLY_EMPTY_TRACE_STEPS = {"solmate_roles_authority", "enumerable_role_store"}


def _is_role_store_provably_empty(cap_dict: dict[str, Any]) -> bool:
    """Exact-empty set from a confirmed role-store adapter: literally no caller.

    Keyed on the trace step so lower-bound and generic ceilings are excluded.
    """
    if cap_dict.get("kind") != "finite_set":
        return False
    if cap_dict.get("members"):
        return False
    if cap_dict.get("membership_quality") != "exact":
        return False
    trace = cap_dict.get("trace")
    if not isinstance(trace, list):
        return False
    return any(isinstance(step, dict) and step.get("step") in _PROVABLY_EMPTY_TRACE_STEPS for step in trace)


def _is_proven_empty(cap_dict: dict[str, Any]) -> bool:
    """A complete enumeration or read of the end user's callers that found none. An empty set that is a lower bound,
    unread, of unknown quality, of an intermediate contract's callers, or empty because of what an accessor is named
    (``empty_by_design``) proves nothing about who may pass.
    """
    return (
        cap_dict.get("kind") == "finite_set"
        and cap_dict.get("members") == []
        and cap_dict.get("membership_quality") == "exact"
        and cap_dict.get("confidence") == "enumerable"
        and cap_dict.get("subject", "root") == "root"
        and (cap_dict.get("empty_reason") is None or cap_dict.get("empty_reason") in _READ_CONFIRMED_EMPTY_REASONS)
    )


def _is_resolved_empty_capability(cap_dict: dict[str, Any]) -> bool:
    kind = cap_dict.get("kind")
    if kind == "finite_set":
        if cap_dict.get("members") != []:
            return False
        # An empty-by-design ceiling is provably nobody even when only inferred lower_bound.
        return cap_dict.get("membership_quality") == "exact" or cap_dict.get("empty_reason") == "empty_by_design"
    if kind == "AND":
        return any(_is_resolved_empty_capability(child) for child in _child_dicts(cap_dict))
    if kind == "OR":
        children = _child_dicts(cap_dict)
        return bool(children) and all(_is_resolved_empty_capability(child) for child in children)
    return False


_CONDITION_NOT_READ: dict[str, Any] = {"kind": "business", "description": "condition not read"}


def _residual_as_conditions(residual: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(residual, dict):
        return []
    out = _condition_dicts(residual.get("conditions"))
    check = residual.get("check")
    if is_reach_not_determined(residual):
        expression = ((check or {}).get("extra") or {}).get("expression") or "reach condition"
        out.append({"kind": "business", "description": f"condition not read: {expression}"})
    elif isinstance(check, dict) and check.get("target_address"):
        selector = check.get("target_call_selector")
        suffix = f".{selector}" if selector else ""
        target = check["target_address"]
        out.append({"kind": "business", "description": f"external authorization check: {target}{suffix}"})
    elif residual.get("unsupported_reason"):
        out.append({"kind": "business", "description": f"unresolved check: {residual['unsupported_reason']}"})
    else:
        out.append({"kind": "business", "description": "external authorization check"})
    return out


# Unrecognized labels (including 33 rows of the pre-split ``internal_accessor_convention``) aren't passed through: one
# field, one vocabulary.
_SHIPPED_AUTHORITY_BASES = frozenset(
    {
        "abi_auto_getter",
        "standard_namespaced_accessor",
        "deunderscore_convention",
        "slot_name_keyword",
        "callee_selector",
    }
)

# Accessor-name matches: one tier, mutually unordered; the storage-agreement residual is published beside them.
_NAME_MATCHED_AUTHORITY_BASES = frozenset(
    {"standard_namespaced_accessor", "deunderscore_convention", "slot_name_keyword"}
)

# Any other step means a second producer contributed members.
_BASIS_COMPATIBLE_TRACE_STEPS = frozenset({"authority_getter_basis", "live_getter_resolution"})


def _authority_basis(cap_dict: dict[str, Any]) -> str | None:
    """The accessor basis every member rests on, or ``None``.

    Merged sets concatenate traces and the basis is stamped on every member row, so it's hoisted only for a single
    member named by exactly one basis step.
    """
    trace = cap_dict.get("trace")
    if not isinstance(trace, list):
        return None
    if len(cap_dict.get("members") or []) != 1:
        return None
    bases: list[str] = []
    for step in trace:
        if not isinstance(step, dict):
            return None
        name = step.get("step")
        if step.get(DEFERRED_MARKER):
            # A deferral riding along from a denylist names no members.
            continue
        if name == "authority_getter_basis":
            basis = step.get("basis")
            if not isinstance(basis, str):
                return None
            bases.append(basis)
        elif name not in _BASIS_COMPATIBLE_TRACE_STEPS:
            return None
    if len(bases) != 1 or bases[0] not in _SHIPPED_AUTHORITY_BASES:
        return None
    return bases[0]


def _rows_for_finite_set(cap_dict: dict[str, Any], conditions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    members = cap_dict.get("members") or []
    # Beside quality/confidence: otherwise "exact + enumerable" hid that the principal rests on an accessor name.
    basis = _authority_basis(cap_dict)
    for member in members:
        if not isinstance(member, str) or not member.startswith("0x") or len(member) != 42:
            continue
        details: dict[str, Any] = {
            "source": "semantic_predicate_capability_resolver",
            "resolver_path": resolver_path(cap_dict),
            "membership_quality": cap_dict.get("membership_quality"),
            "confidence": cap_dict.get("confidence"),
            "trace": cap_dict.get("trace") or [],
        }
        if basis is not None:
            details["authority_basis"] = basis
            if basis in _NAME_MATCHED_AUTHORITY_BASES:
                # Whether the accessor reads the canonical getter's storage is unestablished; the slot differential is
                # unrunnable on this corpus.
                details["accessor_slot_agreement"] = "not_determined"
        rows.append(
            {
                "address": member.lower(),
                "resolved_type": None,
                "origin": "semantic_capability:finite_set",
                "principal_type": "controller",
                "details": _details_with_conditions(details, conditions),
            }
        )
    return rows


def _rows_for_threshold_group(
    cap_dict: dict[str, Any],
    *,
    conditions: list[dict[str, Any]],
    safe_address_lookup: dict[str, str] | None,
    function_signature: str | None,
) -> list[dict[str, Any]]:
    threshold = cap_dict.get("threshold") or {}
    if not isinstance(threshold, dict):
        return []
    m = threshold.get("m")
    signers = threshold.get("signers") or []
    if not isinstance(signers, list):
        signers = []
    owners = [s.lower() for s in signers if isinstance(s, str) and s.startswith("0x") and len(s) == 42]
    safe_address = None
    for step in cap_dict.get("trace") or []:
        if isinstance(step, dict) and step.get("step") == "source_signature_threshold":
            safe_address = step.get("contract")
            break
    if not safe_address and safe_address_lookup:
        if function_signature and function_signature in safe_address_lookup:
            safe_address = safe_address_lookup[function_signature]
        elif "default" in safe_address_lookup:
            safe_address = safe_address_lookup["default"]
    if not safe_address:
        safe_address = "0x" + "0" * 40
    return [
        {
            "address": safe_address.lower(),
            "resolved_type": "safe",
            "origin": "semantic_capability:threshold_group",
            "principal_type": "controller",
            "details": _details_with_conditions(
                {
                    "threshold": int(m) if isinstance(m, int) else None,
                    "owners": owners,
                    "total_signers": len(owners),
                    "source": "semantic_predicate_capability_resolver",
                    "resolver_path": resolver_path(cap_dict),
                },
                conditions,
            ),
        }
    ]


def _rows_for_signature_witness(cap_dict: dict[str, Any], conditions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    signer = cap_dict.get("signer")
    if not isinstance(signer, dict) or signer.get("kind") != "finite_set":
        return []
    signer_conditions = _condition_dicts(signer.get("conditions"))
    rows: list[dict[str, Any]] = []
    for member in signer.get("members") or []:
        if not isinstance(member, str) or not member.startswith("0x") or len(member) != 42:
            continue
        rows.append(
            {
                "address": member.lower(),
                "resolved_type": None,
                "origin": "semantic_capability:signature_witness",
                "principal_type": "signature_witness",
                "details": _details_with_conditions(
                    {
                        "signer_kind": "finite_set",
                        "source": "semantic_predicate_capability_resolver",
                        "resolver_path": resolver_path(signer),
                        "membership_quality": signer.get("membership_quality"),
                    },
                    conditions + signer_conditions,
                ),
            }
        )
    return rows


def resolver_path(cap_dict: dict[str, Any]) -> list[str] | None:
    """Which resolver path produced the members.

    ``origin``/``principal_type`` are constant on every row and can't be repurposed (read elsewhere as role name /
    label).

    A list of trace steps (proven), ``None`` when no trace was recorded (not any particular resolver), key absent on
    pre-field rows.
    """
    trace = cap_dict.get("trace")
    if not isinstance(trace, list):
        return None
    # A deferral carried from a folded denylist resolves no members.
    steps = [
        str(step["step"])
        for step in trace
        if isinstance(step, dict) and step.get("step") and not step.get(DEFERRED_MARKER)
    ]
    return steps or None


def _details_with_conditions(details: dict[str, Any], conditions: list[dict[str, Any]]) -> dict[str, Any]:
    if conditions:
        existing = _condition_dicts(details.get("conditions"))
        details["conditions"] = _unique_conditions(existing + conditions)
    return details


def merged_membership_quality(a: Any, b: Any) -> Any:
    """The weaker of two membership qualities for one address: ``lower_bound`` beats ``exact``, and a missing or
    unrecognised quality (``None``) beats both, so a merge never reads more complete than its weakest operand.
    """
    if a == b:
        return a
    if {a, b} <= {"exact", "lower_bound"}:
        return "lower_bound"
    return None


def _condition_dicts(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    return [{key: value for key, value in item.items() if value is not None} for item in raw if isinstance(item, dict)]


def _unique_conditions(conditions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for condition in conditions:
        key = repr(sorted(condition.items()))
        if key in seen:
            continue
        seen.add(key)
        out.append(dict(condition))
    return out


def _child_dicts(cap_dict: dict[str, Any]) -> list[dict[str, Any]]:
    children = cap_dict.get("children")
    if not isinstance(children, list):
        return []
    return [child for child in children if isinstance(child, dict)]
