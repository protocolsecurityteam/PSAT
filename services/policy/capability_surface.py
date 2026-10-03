"""Narrow projections of the resolver's capability algebra (caller rows, public paths, residual checks), in one place
so DB and artifact paths don't drift.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from services.resolution.permissionless_shapes import CALLER_GATE_BASIS_TAGS, earned_public_enabled
from utils.scoring_status import OPENNESS_STATES, TRACE_STEP_ENUMERABLE_ROLE_STORE, TRACE_STEP_SOLMATE_ROLES_AUTHORITY


@dataclass
class CapabilitySurface:
    principal_rows: list[dict[str, Any]] = field(default_factory=list)
    public_paths: list[list[dict[str, Any]]] = field(default_factory=list)
    residual: list[dict[str, Any]] = field(default_factory=list)

    @property
    def authority_public(self) -> bool:
        return bool(self.public_paths)

    @property
    def conditions(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for row in self.principal_rows:
            details = row.get("details")
            if isinstance(details, dict):
                out.extend(_condition_dicts(details.get("conditions")))
        for path in self.public_paths:
            out.extend(path)
        return _unique_conditions(out)


# Persisted beside ``authority_public``; see ``capability_surface_openness``.
AUTHORITY_OPENNESS_VALUES = OPENNESS_STATES


def capability_surface_openness(cap_dict: dict[str, Any], surface: CapabilitySurface) -> str:
    """Three-state authority verdict for one capability.

    * ``open`` — a public path was earned; exactly ``authority_public``.
    * ``restricted`` — a restriction was witnessed: caller rows, or a complete enumeration admitting nobody.
    * ``not_determined`` — neither (unsupported, external_check_only, irreducible residual), all of which the bool
    reported as ``False``.

    Never raises. ``restricted`` means a restriction exists, not that these are all the callers (that's
    ``membership_quality``).
    """
    if surface.authority_public:
        return "open"
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
    if surface.authority_public:
        return "public"
    # Only with no caller rows: an AND with real callers beside an exact-empty bound side-condition keeps them (the Veda
    # caller-drop).
    if not surface.principal_rows and _is_resolved_empty_capability(cap_dict):
        return "resolved_empty"
    if cap_dict.get("kind") == "unsupported" and not surface.principal_rows:
        return "unsupported"
    return None


def project_capability_surface(
    cap_dict: dict[str, Any],
    *,
    safe_address_lookup: dict[str, str] | None = None,
    function_signature: str | None = None,
) -> CapabilitySurface:
    surface = _project_node(
        cap_dict,
        safe_address_lookup=safe_address_lookup,
        function_signature=function_signature,
    )
    surface.principal_rows = _dedupe_rows(surface.principal_rows)
    surface.public_paths = [_unique_conditions(path) for path in surface.public_paths]
    return surface


def _project_node(
    cap_dict: dict[str, Any],
    *,
    safe_address_lookup: dict[str, str] | None,
    function_signature: str | None,
) -> CapabilitySurface:
    kind = cap_dict.get("kind")
    node_conditions = _condition_dicts(cap_dict.get("conditions"))

    if kind == "finite_set":
        return CapabilitySurface(principal_rows=_rows_for_finite_set(cap_dict, node_conditions))
    if kind == "threshold_group":
        return CapabilitySurface(
            principal_rows=_rows_for_threshold_group(
                cap_dict,
                conditions=node_conditions,
                safe_address_lookup=safe_address_lookup,
                function_signature=function_signature,
            )
        )
    if kind == "signature_witness":
        return CapabilitySurface(principal_rows=_rows_for_signature_witness(cap_dict, node_conditions))
    if kind == "conditional_universal":
        return CapabilitySurface(public_paths=[node_conditions])
    if kind == "OR":
        surface = CapabilitySurface()
        for child in _child_dicts(cap_dict):
            child_surface = _project_node(
                child,
                safe_address_lookup=safe_address_lookup,
                function_signature=function_signature,
            )
            surface = _or_surface(surface, child_surface)
        return _with_node_conditions(surface, node_conditions)
    if kind == "AND":
        # Start empty: ``anyone`` must be earned by a conditional_universal child, not minted by AND-ing checks.
        surface = CapabilitySurface()
        blocked = False
        for child in _child_dicts(cap_dict):
            child_surface = _project_node(
                child,
                safe_address_lookup=safe_address_lookup,
                function_signature=function_signature,
            )
            if earned_public_enabled() and not _has_valid_path(child_surface) and _is_root_authority_blocker(child):
                blocked = True
            surface = _and_surface(surface, child_surface)
        surface = _with_node_conditions(surface, node_conditions)
        if blocked and surface.public_paths:
            # An unresolved root-caller authorization AND-ed in means the function is gated with principals unknown;
            # sibling public paths aren't earned. See ``_is_root_authority_blocker``.
            surface = CapabilitySurface(
                principal_rows=list(surface.principal_rows),
                public_paths=[],
                residual=list(surface.residual),
            )
        return surface
    if kind == "cofinite_blacklist":
        # A cofinite is a public path with the denylist as a side-condition. Quality doesn't change openness but does
        # change condition text: a ``lower_bound`` denylist isn't the complete exclusion set. Absent quality means a
        # pre-fix row, rendered as unknown.
        quality = cap_dict.get("blacklist_quality")
        excluded = len(cap_dict.get("blacklist") or [])
        if quality == "exact":
            description = f"denylist exclusion ({excluded} excluded, exhaustive)"
        elif quality is None:
            description = f"denylist exclusion ({excluded} known excluded; completeness not recorded)"
        else:
            description = f"denylist exclusion (at least {excluded} excluded; not exhaustive)"
        denial = {"kind": "denylist", "description": description}
        return CapabilitySurface(public_paths=[node_conditions + [denial]])
    return CapabilitySurface(residual=[dict(cap_dict)])


def _is_root_authority_blocker(cap_dict: dict[str, Any]) -> bool:
    """Is this an unresolved authorization on the root caller? Public must be earned, so such a check AND-ed with
    public side-conditions gates the function.

    Blocks:
      - ``external_check_only`` with a ``CALLER_GATE_BASIS_TAGS`` tag (untagged checks are downstream probes that fold
    as side-conditions, e.g. Veda teller->vault ``requiresAuth``).
      - ``unsupported``.
      - an empty non-exact ``finite_set`` (authority value unread); exact-empty / by-design sets are resolved.
      - an empty set enumerated from a Solmate ``RolesAuthority``: provably nobody.
      - AND if any child blocks; OR only if every disjunct blocks.

    Bound-subject capabilities never block: they condition the intermediate contract, not the end user.
    """
    if cap_dict.get("subject", "root") != "root":
        return False
    kind = cap_dict.get("kind")
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
        return any(_is_root_authority_blocker(child) for child in _child_dicts(cap_dict))
    if kind == "OR":
        children = _child_dicts(cap_dict)
        return bool(children) and all(_is_root_authority_blocker(child) for child in children)
    return False


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


def _with_node_conditions(surface: CapabilitySurface, conditions: list[dict[str, Any]]) -> CapabilitySurface:
    """Node conditions narrow a real authorization; they never constitute one."""
    if not conditions:
        return surface
    return CapabilitySurface(
        principal_rows=[_row_with_conditions(row, conditions) for row in surface.principal_rows],
        public_paths=[_unique_conditions(path + conditions) for path in surface.public_paths],
        residual=list(surface.residual),
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


def _or_surface(left: CapabilitySurface, right: CapabilitySurface) -> CapabilitySurface:
    return CapabilitySurface(
        principal_rows=left.principal_rows + right.principal_rows,
        public_paths=left.public_paths + right.public_paths,
        residual=left.residual + right.residual,
    )


def _and_surface(left: CapabilitySurface, right: CapabilitySurface) -> CapabilitySurface:
    left_valid = _has_valid_path(left)
    right_valid = _has_valid_path(right)

    if not left_valid and not right_valid:
        return CapabilitySurface(residual=left.residual + right.residual)

    # The pure-check side is a side-condition, not grounds to drop the callers; collapsing to residual silently dropped
    # the Veda Teller caller sets.
    if not right_valid:
        return _surface_with_side_checks(left, right.residual)
    if not left_valid:
        return _surface_with_side_checks(right, left.residual)

    public_paths: list[list[dict[str, Any]]] = []
    for left_path in left.public_paths:
        for right_path in right.public_paths:
            public_paths.append(_unique_conditions(left_path + right_path))

    rows: list[dict[str, Any]] = []
    for row in left.principal_rows:
        for path in right.public_paths:
            rows.append(_row_with_conditions(row, path))
    for row in right.principal_rows:
        for path in left.public_paths:
            rows.append(_row_with_conditions(row, path))

    residual = left.residual + right.residual
    if left.principal_rows and right.principal_rows:
        residual.append({"kind": "unsupported", "unsupported_reason": "and_multiple_principal_shapes"})

    return CapabilitySurface(principal_rows=rows, public_paths=public_paths, residual=residual)


def _surface_with_side_checks(valid: CapabilitySurface, side_residual: list[dict[str, Any]]) -> CapabilitySurface:
    """Keep ``valid``'s callers/public paths, folding the other branch in as side-conditions (and in ``residual`` for
    the API).
    """
    conditions = [cond for residual in side_residual for cond in _residual_as_conditions(residual)]
    if not conditions:
        return CapabilitySurface(
            principal_rows=list(valid.principal_rows),
            public_paths=list(valid.public_paths),
            residual=list(valid.residual) + list(side_residual),
        )
    rows = [_row_with_conditions(row, conditions) for row in valid.principal_rows]
    public_paths = [_unique_conditions(path + conditions) for path in valid.public_paths]
    return CapabilitySurface(
        principal_rows=rows,
        public_paths=public_paths,
        residual=list(valid.residual) + list(side_residual),
    )


def _residual_as_conditions(residual: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(residual, dict):
        return []
    out = _condition_dicts(residual.get("conditions"))
    check = residual.get("check")
    if isinstance(check, dict) and check.get("target_address"):
        selector = check.get("target_call_selector")
        suffix = f".{selector}" if selector else ""
        target = check["target_address"]
        out.append({"kind": "business", "description": f"external authorization check: {target}{suffix}"})
    elif residual.get("unsupported_reason"):
        out.append({"kind": "business", "description": f"unresolved check: {residual['unsupported_reason']}"})
    else:
        out.append({"kind": "business", "description": "external authorization check"})
    return out


def _has_valid_path(surface: CapabilitySurface) -> bool:
    return bool(surface.principal_rows or surface.public_paths)


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
                    },
                    conditions + signer_conditions,
                ),
            }
        )
    return rows


def _row_with_conditions(row: dict[str, Any], conditions: list[dict[str, Any]]) -> dict[str, Any]:
    out = dict(row)
    details = dict(out.get("details") or {})
    out["details"] = _details_with_conditions(details, conditions)
    return out


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
    steps = [str(step["step"]) for step in trace if isinstance(step, dict) and step.get("step")]
    return steps or None


def _details_with_conditions(details: dict[str, Any], conditions: list[dict[str, Any]]) -> dict[str, Any]:
    if conditions:
        existing = _condition_dicts(details.get("conditions"))
        details["conditions"] = _unique_conditions(existing + conditions)
    return details


def _dedupe_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = (
            str(row.get("address") or "").lower(),
            str(row.get("origin") or ""),
            str(row.get("principal_type") or ""),
        )
        if key in by_key:
            existing = by_key[key]
            existing_details = dict(existing.get("details") or {})
            row_details = row.get("details") if isinstance(row.get("details"), dict) else {}
            if isinstance(row_details, dict):
                existing_details["conditions"] = _unique_conditions(
                    _condition_dicts(existing_details.get("conditions"))
                    + _condition_dicts(row_details.get("conditions"))
                )
                trace = list(existing_details.get("trace") or [])
                trace.extend(item for item in row_details.get("trace") or [] if item not in trace)
                if trace:
                    existing_details["trace"] = trace
            existing["details"] = existing_details
            continue
        copied = dict(row)
        copied["details"] = dict(copied.get("details") or {})
        by_key[key] = copied
        out.append(copied)
    return out


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
