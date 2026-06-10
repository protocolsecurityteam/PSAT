"""Projection helpers for semantic capability trees.

The resolver preserves the full capability algebra. Policy rows and API
payloads need a narrower view: materializable caller rows, public paths,
and residual unresolved checks. Keep that interpretation in one place so
DB and artifact paths do not drift.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from services.resolution.permissionless_shapes import CALLER_GATE_BASIS_TAGS, earned_public_enabled


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


def capability_surface_status(cap_dict: dict[str, Any], surface: CapabilitySurface) -> str | None:
    if surface.authority_public:
        return "public"
    # ``resolved_empty`` means "provably nobody". Only when the surface yields NO
    # caller rows: an AND that carries a real caller set alongside an exact-empty
    # *bound* side-condition (a downstream call whose own auth resolved empty) still
    # has those callers — flagging it resolved_empty would drop them via the status,
    # re-opening the Veda caller-drop one layer up. A genuine no-role own gate has no
    # rows, so this still resolves_empty correctly.
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
        # Fold from an empty identity, never a seeded public path: an `anyone` surface must
        # be earned by a conditional_universal child, not minted by AND-ing pure checks.
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
            # Earned-public: an unresolved ROOT-caller authorization is AND-ed
            # in (an external_check / unsupported gate / a caller-equality
            # whose authority value couldn't be read). The sibling public
            # paths are not earned — the function is gated, principals
            # unknown. Principal rows (already-gated callers) keep folding the
            # blocker as a side-condition exactly as before; bound-subject
            # checks (inlined downstream auth) never block — see
            # ``_is_root_authority_blocker``.
            surface = CapabilitySurface(
                principal_rows=list(surface.principal_rows),
                public_paths=[],
                residual=list(surface.residual),
            )
        return surface
    if kind == "cofinite_blacklist":
        # "Anyone except a finite exclusion" is a PUBLIC path with the denylist as a
        # side-condition, not an unresolved residual. Surface the exclusion so a reviewer
        # still sees the filter; the cofinite's own conditions (whenNotPaused, a share
        # time-lock) ride along in ``node_conditions``. Quality (exact vs lower_bound) is
        # informational only — every cofinite is "open modulo a finite/condition filter",
        # so the openness verdict never branches on it.
        denial = {
            "kind": "business",
            "description": f"denylist exclusion ({len(cap_dict.get('blacklist') or [])} known excluded)",
        }
        return CapabilitySurface(public_paths=[node_conditions + [denial]])
    return CapabilitySurface(residual=[dict(cap_dict)])


def _is_root_authority_blocker(cap_dict: dict[str, Any]) -> bool:
    """Does this capability represent an UNRESOLVED authorization on the
    root (end-user) caller? Under the earned-public default such a check
    AND-ed with public side-conditions gates the function — "public" must be
    earned, and an authority whose principal set couldn't be read/enumerated
    is still an authority.

    Shapes that block:
      - ``external_check_only`` carrying a caller-gate basis tag
        (``CALLER_GATE_BASIS_TAGS`` — the earned-public default's fail-closed
        verdicts and the subsumed E3/E4 allowlists). A check WITHOUT the tag
        is a targeted downstream-call probe (the un-inlined Veda teller→vault
        ``requiresAuth``, a descriptor probe awaiting an adapter) — an
        intermediate-contract condition that must keep folding as a side
        condition next to an adapter-earned public capability
        (PublicCapabilityUpdated) exactly as the legacy path did.
      - ``unsupported`` — an un-modeled gate (extraction fail-closed, E2).
      - an EMPTY non-exact ``finite_set`` — a caller equality whose authority
        value wasn't read (``msg.sender == owner`` with no controller value);
        exact-empty (provably nobody / empty-by-design) is NOT a blocker —
        that is resolved, not unresolved.
      - AND: any blocking child; OR: only if EVERY disjunct blocks (a single
        genuinely-open disjunct keeps the OR open).

    Bound-subject capabilities never block: an inlined downstream call's
    authorization is a runtime side-condition on the intermediate contract,
    not a restriction of the end-user caller (the Veda Teller contract).
    """
    if cap_dict.get("subject", "root") != "root":
        return False
    kind = cap_dict.get("kind")
    if kind == "finite_set":
        if cap_dict.get("members"):
            return False
        # Exact-empty / empty-by-design is RESOLVED (provably nobody, or an
        # accept-side ceiling) — mirrors ``_is_resolved_empty_capability``.
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


def _with_node_conditions(surface: CapabilitySurface, conditions: list[dict[str, Any]]) -> CapabilitySurface:
    """Qualify the caller rows / public paths an AND or OR resolved to with the node's own
    side conditions. A public path exists only where a child contributed one (a
    ``conditional_universal``, which always carries its condition); node-level conditions
    narrow a real authorization, they never constitute one."""
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
        # An exact-empty set is provably nobody; an empty-by-design ceiling (the
        # accept side of a 2-step transfer with none pending) is too, even when
        # the read that confirmed it could only structurally infer a lower_bound.
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

    # Neither side carries a caller path — both are pure checks; keep them residual.
    if not left_valid and not right_valid:
        return CapabilitySurface(residual=left.residual + right.residual)

    # Exactly one side carries the caller path (principal rows / public paths); the
    # other is a pure check with no path — a downstream/bound-subject authorization or
    # an unenumerable external check. That check is a runtime SIDE-CONDITION on the
    # call, NOT grounds to drop the real callers. Preserve the valid side and attach
    # the check as a condition, per this module's contract ("AND with caller path +
    # side conditions → caller rows with conditions"). Collapsing to residual-only
    # here is what silently dropped the Veda Teller withdraw/deposit caller sets.
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
    """Keep ``valid``'s caller rows / public paths, folding the pure-check residual on
    the other AND branch in as side-condition(s) (and retaining it in ``residual`` so
    the API can still surface the probe)."""
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
    """Render a residual check (an ``external_check_only`` / ``unsupported`` cap dict)
    as side-condition dict(s): any conditions it already carries, plus one summarizing
    the check itself."""
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


def _rows_for_finite_set(cap_dict: dict[str, Any], conditions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    members = cap_dict.get("members") or []
    for member in members:
        if not isinstance(member, str) or not member.startswith("0x") or len(member) != 42:
            continue
        rows.append(
            {
                "address": member.lower(),
                "resolved_type": None,
                "origin": "semantic_capability:finite_set",
                "principal_type": "controller",
                "details": _details_with_conditions(
                    {
                        "source": "semantic_predicate_capability_resolver",
                        "membership_quality": cap_dict.get("membership_quality"),
                        "confidence": cap_dict.get("confidence"),
                        "trace": cap_dict.get("trace") or [],
                    },
                    conditions,
                ),
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
    if safe_address_lookup:
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
