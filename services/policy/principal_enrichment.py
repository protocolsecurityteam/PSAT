"""Build frontend-friendly principal labels from effective permissions and resolved control graphs."""

from __future__ import annotations

import logging
import re
import threading
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import (
    EDGE_RELATION_CONTROLLER_VALUE,
    EDGE_RELATION_EXTERNAL_CALL_TARGET,
    Contract,
    EffectiveFunction,
    FunctionPrincipal,
)
from schemas.control_tracking import ResolvedControllerType, coerce_resolved_controller_type
from schemas.principal_labels import LabelConfidence, PrincipalLabels, PrincipalPermission, PrincipalProfile
from services.concurrency import parallel_map
from services.governance.principals import is_terminal_principal_type, resolve_terminal_principal
from services.resolution.tracking import classify_resolved_address_with_status
from utils.logging import record_stage_metric

logger = logging.getLogger(__name__)


# --- signer-overlap attribution fact -----------------------------------------
def load_protocol_safe_owner_sets(session: Session, protocol_id: int) -> dict[str, dict[str, Any]]:
    """The protocol's dispositively-enumerated Safe owner sets, keyed by lowercased
    Safe address, for signer-overlap comparison.

    Sources ``function_principals`` (the authoritative owner store with the
    ``membership_quality`` witness). Only ``resolved_type='safe'`` rows whose
    ``details.owners`` is present AND ``membership_quality == 'exact'`` are
    admitted — the on-chain owner set was dispositively read, not a lower-bound
    guess. A Safe appears on many function rows; identical exact rows dedup by
    address. If two exact rows DISAGREE on the owner set, that Safe is a witness
    conflict and is OMITTED (no recency column to arbitrate, so we
    never silently pick one contradictory enumeration). The set is only as
    complete as the protocol contracts analyzed so far, which is correct: the
    comparison pool grows monotonically as more contracts resolve (inv-6), never
    producing a wrong deduction, only fewer comparisons.
    """
    rows = session.execute(
        select(func.lower(FunctionPrincipal.address), FunctionPrincipal.details)
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .where(Contract.protocol_id == protocol_id, FunctionPrincipal.resolved_type == "safe")
    ).all()

    # Per-Safe accumulator: the first exact owner set seen, its threshold, and a
    # conflict flag. ``function_principals`` has no recency column (no
    # updated_at/probe-block on the row — see db/models.py), so two exact rows
    # that DISAGREE on the owner set are contradictory witnesses with no
    # dispositive way to pick between them: fail closed. Identical
    # duplicate exact rows agree and are kept.
    accum: dict[str, dict[str, Any]] = {}
    for address, details in rows:
        if not isinstance(details, dict):
            continue
        # Fallback (no guessing): omit when the owner set was not dispositively
        # enumerated. ``lower_bound`` membership means the resolution did not
        # prove the full owner set — inadmissible as a Tier-1 owner fact. An exact
        # + lower_bound pair is NOT a conflict: the lower_bound row is skipped here
        # and the exact one stands.
        if details.get("membership_quality") != "exact":
            continue
        owners_raw = details.get("owners")
        if not isinstance(owners_raw, list) or not owners_raw:
            continue
        owners = sorted({str(o).lower() for o in owners_raw if isinstance(o, str) and o.startswith("0x")})
        if not owners:
            continue
        addr = str(address).lower()
        existing = accum.get(addr)
        if existing is None:
            accum[addr] = {"owners": owners, "threshold": details.get("threshold"), "conflict": False}
        elif existing["owners"] != owners:
            # Two exact witnesses disagree — refuse to arbitrate, drop the Safe.
            existing["conflict"] = True
    return {
        addr: {"owners": entry["owners"], "threshold": entry["threshold"], "membership_quality": "exact"}
        for addr, entry in accum.items()
        if not entry["conflict"]
    }


def _compute_signer_overlap(
    self_address: str, protocol_safe_owner_sets: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any] | None:
    """The ``signer_overlap`` fact for one Safe principal, or ``None`` to omit.

    Emits subset/superset/equal flags + Jaccard of this Safe's owner set against
    every *other* dispositively-enumerated Safe of the same protocol. Omitted
    when this Safe isn't in the exact-owners registry (owners absent or
    ``membership_quality != exact``) or when there is no other Safe to compare
    against. A disjoint pair is still emitted (empty overlap) — that is itself a
    dispositive fact ("no shared signers"). NB the honesty boundary: shared
    signers is grade-admissible attribution CONTEXT (Tier 1, on-chain owner
    reads), NOT proof of shared organizational identity — org identity stays a
    warning/confidence signal and is never deduced here.
    """
    self_entry = protocol_safe_owner_sets.get(self_address)
    if self_entry is None:
        return None
    self_owners = frozenset(self_entry.get("owners") or ())
    if not self_owners:
        return None

    overlaps: list[dict[str, Any]] = []
    for other_addr, other_entry in sorted(protocol_safe_owner_sets.items()):
        if other_addr == self_address:
            continue
        other_owners = frozenset(other_entry.get("owners") or ())
        if not other_owners:
            continue
        shared = self_owners & other_owners
        union = self_owners | other_owners
        overlaps.append(
            {
                "address": other_addr,
                "other_owner_count": len(other_owners),
                "shared_count": len(shared),
                "shared_owners": sorted(shared),
                "subset": self_owners <= other_owners,
                "superset": self_owners >= other_owners,
                "equal": self_owners == other_owners,
                "jaccard": round(len(shared) / len(union), 4) if union else 0.0,
            }
        )
    if not overlaps:
        return None
    return {
        # Dispositive Safe getOwners() reads — scoring Tier 1, grade-admissible.
        # Kept as a semantic provenance string (NOT "tier1"/"tier2") so a consumer
        # never collides it with services/effects/config.py's fork/call tier
        # strings. See docstring for the same-signers != same-org boundary.
        "provenance": "onchain_owner_read",
        "self_owner_count": len(self_owners),
        "overlaps": overlaps,
    }


# --- shared-deployer attribution fact ----------------------------------------
def load_protocol_deployer_groups(session: Session, protocol_id: int) -> dict[str, dict[str, Any]]:
    """Per-address shared-deployer groups for a protocol, keyed by lowercased
    contract address.

    Groups the protocol's ``contracts`` by ``deployer`` (lowercased); a group of
    ≥2 contracts sharing one deployer yields, for each member, ``{"deployer",
    "addresses": [full sorted group]}``. Contracts with a NULL ``deployer`` (73/205
    populated locally) are omitted — no fact without the witness. Same-deployer is
    a WITNESSED on-chain fact but a HEURISTIC for attribution (factories defeat
    "same deployer ⇒ same org"); the emitted fact carries that flag and never
    yields an org-identity deduction (see ``_shared_deployer_fact``).
    """
    rows = session.execute(
        select(func.lower(Contract.address), func.lower(Contract.deployer)).where(
            Contract.protocol_id == protocol_id, Contract.deployer.is_not(None)
        )
    ).all()

    by_deployer: dict[str, set[str]] = defaultdict(set)
    for address, deployer in rows:
        addr = str(address).lower()
        dep = str(deployer).lower()
        if addr.startswith("0x") and dep.startswith("0x"):
            by_deployer[dep].add(addr)

    groups: dict[str, dict[str, Any]] = {}
    for deployer, addresses in by_deployer.items():
        if len(addresses) < 2:
            continue  # a lone contract shares a deployer with nobody — no fact
        ordered = sorted(addresses)
        for addr in ordered:
            groups[addr] = {"deployer": deployer, "addresses": ordered}
    return groups


def _shared_deployer_fact(address: str, deployer_groups: Mapping[str, Mapping[str, Any]]) -> dict[str, Any] | None:
    """The ``shared_deployer`` fact for a principal that co-shares a deployer with
    other protocol contracts, or ``None`` to omit (deployer absent / singleton).

    WITNESSED fact, NOT a conclusion: ``provenance="deployer_read"`` is a Tier-1
    on-chain read, but ``heuristic=True`` flags that same-deployer does NOT prove
    same organization (factories, shared deployer EOAs, and vanity-deployer
    services all defeat it). Routes to confidence/warnings, never a grade
    deduction, and MUST NOT mint an org-identity label — same honesty as the
    signer-overlap fact: fact yes, org conclusion no.
    """
    entry = deployer_groups.get(address)
    if entry is None:
        return None
    return {
        "provenance": "deployer_read",
        "heuristic": True,
        "deployer": entry["deployer"],
        "addresses": list(entry["addresses"]),
    }


def _safe_role_int(role: Any) -> int | None:
    """Coerce a role identifier to int, returning None for non-int shapes.

    Role-name strings and Condition-mapping shapes cannot be represented as
    numeric policy roles. Callers decide whether to skip-with-warning or
    surface ``role=None`` on a typed permission while preserving the
    original identifier in the controller bucket.
    """
    try:
        return int(role)
    except (TypeError, ValueError):
        return None


def _slug(value: str) -> str:
    lowered = value.lower()
    lowered = re.sub(r"[^a-z0-9]+", "_", lowered)
    return lowered.strip("_")


# --- Plane-1 claim → principal-tag vocabulary --------------------------------
# Which claim families grant which enrichment tag. Keyed on the atomic claim_id
# (namespace prefix or exact id), NOT consumer_family: ``pause.*`` / ``lz_oapp.*``
# are control-plane but not admin powers, and ``exec.arbitrary`` is a manager
# power that ``contract_deployment`` (also exec-family) is not.
# ``callee_pointer.rotate`` IS an admin power — the precise use-link idiom that
# replaced the diluted ``hook_update`` label.
_ADMIN_CLAIM_PREFIXES = ("ownership.", "roles.", "authority.", "upgrade.", "timelock.", "safe.")
_ADMIN_CLAIM_IDS = frozenset({"authorized_caller.rotate", "proxy.admin_change", "callee_pointer.rotate"})
_OPERATOR_CLAIM_PREFIXES = ("flow.", "supply.")
_MANAGER_CLAIM_IDS = frozenset({"exec.arbitrary"})

# Legacy effect_labels → tag: the fallback for rows written before the claims
# plane (or a degraded effects artifact). ``hook_update`` is deliberately absent
# from the admin set — it was the 1/69-correct diluted label, and no measured
# prod principal depends on it for an admin tag.
_LEGACY_ADMIN_LABELS = frozenset(
    {"authority_update", "ownership_transfer", "implementation_update", "role_management", "timelock_operation"}
)
_LEGACY_OPERATOR_LABELS = frozenset({"asset_pull", "asset_send", "mint", "burn"})
_LEGACY_MANAGER_LABELS = frozenset({"arbitrary_external_call"})


def _claim_ids(claims: Any) -> set[str]:
    """The ``claim_id`` strings from a function's ``claims`` list — the
    ``{claim_id, tier, witness}`` dict shape the effective-permissions payload
    carries. An unexpected shape reads as empty (claims-less fallback)."""
    out: set[str] = set()
    if not isinstance(claims, list):
        return out
    for claim in claims:
        if isinstance(claim, dict):
            cid = claim.get("claim_id")
            if isinstance(cid, str) and cid:
                out.add(cid)
    return out


def _enrichment_tags(claims: Any, effect_labels_set: set[str]) -> set[str]:
    """The admin/operator/manager tags a function grants its authorized callers.

    Plane-1 claims are authoritative when present; a claim-less function (stale
    row / degraded artifact) falls back to the legacy effect_labels."""
    claim_ids = _claim_ids(claims)
    tags: set[str] = set()
    if claim_ids:
        for cid in claim_ids:
            if cid in _ADMIN_CLAIM_IDS or cid.startswith(_ADMIN_CLAIM_PREFIXES):
                tags.add("admin")
            if cid.startswith(_OPERATOR_CLAIM_PREFIXES):
                tags.add("operator")
            if cid in _MANAGER_CLAIM_IDS:
                tags.add("manager")
        return tags
    if effect_labels_set & _LEGACY_ADMIN_LABELS:
        tags.add("admin")
    if effect_labels_set & _LEGACY_OPERATOR_LABELS:
        tags.add("operator")
    if effect_labels_set & _LEGACY_MANAGER_LABELS:
        tags.add("manager")
    return tags


def _display_from_type(resolved_type: str) -> str:
    return {
        "safe": "Safe",
        "timelock": "Timelock",
        "proxy_admin": "Proxy admin",
        "eoa": "Externally owned account",
        "contract": "Contract",
        "zero": "Zero address",
        "cross_chain_authority": "Cross-chain authority",
        "unknown": "Unknown principal",
    }.get(resolved_type, "Unknown principal")


def _cross_chain_display_name(details: dict[str, Any]) -> str:
    """Human label for a ``cross_chain_authority`` principal, from its role."""
    role = str(details.get("role") or "")
    if role == "cross_domain_messenger":
        return "Cross-domain messenger"
    if role == "bridge_executor":
        return "Bridge executor"
    if role == "aliased_l1_owner":
        implied = str(details.get("implied_l1_address") or "").strip()
        return f"Aliased L1 owner ({implied})" if implied else "Aliased L1 owner"
    return "Cross-chain authority"


def _node_display_name(node: dict[str, Any] | None) -> str:
    if not isinstance(node, dict):
        return ""
    for candidate in (node.get("contract_name"), node.get("label")):
        name = str(candidate or "").strip()
        if not name:
            continue
        if _slug(name) in {"contract", "role_principal", "roleprincipal", "principal"}:
            continue
        return name
    return ""


def _collect_permissions(
    effective_permissions: dict[str, Any],
) -> tuple[dict[str, list[PrincipalPermission]], dict[str, str]]:
    by_address: dict[str, list[PrincipalPermission]] = defaultdict(list)
    contract_name = effective_permissions["contract_name"]
    contract_slug = _slug(contract_name)
    permission_labels: dict[str, set[str]] = defaultdict(set)

    for function in effective_permissions.get("functions", []):
        function_name = str(function.get("function", ""))
        effect_labels = [str(label) for label in function.get("effect_labels", [])]
        authority_public = bool(function.get("authority_public", False))
        effect_labels_set = set(effect_labels)
        # Tags depend only on the function's effects, not the caller — compute
        # once and stamp every authorized principal below.
        function_tags = _enrichment_tags(function.get("claims"), effect_labels_set)
        direct_owner = function.get("direct_owner")
        if direct_owner:
            address = direct_owner["address"].lower()
            if not address.startswith("0x") or len(address) != 42:
                continue
            permission: PrincipalPermission = {
                "function": function_name,
                "effect_labels": effect_labels,
                "authority_public": authority_public,
                "role": None,
                "controller": "owner",
            }
            by_address[address].append(permission)
            permission_labels[address].update({f"{contract_slug}_direct_owner", f"{contract_slug}_controlled"})

        # ``or []`` — see recursive.py: authority_roles is present-with-None
        # for a role-gated function whose role is not determined, and a dict
        # default only fires on an absent key. Not-determined mints no
        # role_N label, exactly as [] did.
        for role_grant in function.get("authority_roles") or []:
            raw_role = role_grant.get("role")
            role = _safe_role_int(raw_role)
            if role is None:
                logger.debug(
                    "principal_enrichment: skipping int-coercion for non-int role %r on %s",
                    raw_role,
                    function_name,
                )
            controller_role_label = str(role) if role is not None else str(raw_role)
            for principal in role_grant.get("principals", []):
                address = principal["address"].lower()
                if not address.startswith("0x") or len(address) != 42:
                    continue
                permission: PrincipalPermission = {
                    "function": function_name,
                    "effect_labels": effect_labels,
                    "authority_public": authority_public,
                    "role": role,
                    "controller": f"role_{controller_role_label}",
                }
                by_address[address].append(permission)
                permission_labels[address].update(
                    {
                        f"{contract_slug}_controlled",
                        f"{contract_slug}_role_{controller_role_label}_holder",
                    }
                )
                if "manager" in function_tags:
                    permission_labels[address].add(f"{contract_slug}_manager")
                if "operator" in function_tags:
                    permission_labels[address].add(f"{contract_slug}_operator")
                if "admin" in function_tags:
                    permission_labels[address].add(f"{contract_slug}_admin")

        for controller in function.get("controllers", []):
            controller_label = str(controller.get("label") or controller.get("source") or "controller")
            controller_slug = _slug(controller_label)
            for principal in controller.get("principals", []):
                address = principal["address"].lower()
                if not address.startswith("0x") or len(address) != 42:
                    continue
                permission = {
                    "function": function_name,
                    "effect_labels": effect_labels,
                    "authority_public": authority_public,
                    "role": None,
                    "controller": controller_label,
                }
                by_address[address].append(permission)
                permission_labels[address].update(
                    {
                        f"{contract_slug}_controlled",
                        f"{contract_slug}_controller_{controller_slug}",
                    }
                )
                # Controller-path parity with the pre-claims behavior: a
                # state-variable controller earns manager/admin, never operator.
                if "manager" in function_tags:
                    permission_labels[address].add(f"{contract_slug}_manager")
                if "admin" in function_tags:
                    permission_labels[address].add(f"{contract_slug}_admin")

    return by_address, {address: ",".join(sorted(labels)) for address, labels in permission_labels.items()}


def _incoming_edges(graph: dict) -> dict[str, list[dict]]:
    incoming: dict[str, list[dict]] = defaultdict(list)
    for edge in graph.get("edges", []):
        incoming[edge["to_id"]].append(edge)
    return incoming


def _outgoing_edges(graph: dict) -> dict[str, list[dict]]:
    outgoing: dict[str, list[dict]] = defaultdict(list)
    for edge in graph.get("edges", []):
        outgoing[edge["from_id"]].append(edge)
    return outgoing


def _node_by_id(graph: dict) -> dict[str, dict]:
    return {node["id"]: node for node in graph.get("nodes", [])}


def _graph_labels_for_node(
    node: dict, incoming_edges: list[dict], node_index: dict[str, dict]
) -> tuple[set[str], list[str]]:
    labels = {node.get("resolved_type", "unknown")}
    context: list[str] = []
    if node.get("resolved_type") == "safe":
        labels.add("safe_multisig")
    elif node.get("resolved_type") == "eoa":
        labels.add("likely_eoa")
    elif node.get("resolved_type") == "contract":
        labels.add("contract_controller")
    elif node.get("resolved_type") == "zero":
        labels.add("zero_address")

    for edge in incoming_edges:
        source_node = node_index.get(edge["from_id"], {})
        source_contract_name = source_node.get("contract_name") or source_node.get("label") or "contract"
        source_slug = _slug(str(source_contract_name))
        relation = edge["relation"]
        edge_label = _slug(edge.get("label") or relation)
        context.append(f"{source_contract_name}:{edge.get('label') or relation}")
        if relation == EDGE_RELATION_CONTROLLER_VALUE:
            labels.add("controller_value")
            labels.add(f"{source_slug}_{edge_label}")
            labels.add(f"controller_{edge_label}")
            if edge_label == "authority":
                labels.add("authority_controller")
            if edge_label == "owner":
                labels.add("owner_controller")
        elif relation == EDGE_RELATION_EXTERNAL_CALL_TARGET:
            # The from-node CALLS this address. That is a proven fact and worth
            # publishing, but it is not control: minting ``controller_*`` here
            # is what labelled the Ethereum 2 deposit contract a controller of
            # StakingManager and the Curve stETH/ETH pool a controller of
            # Liquifier. Neither controls anything; both are callees.
            labels.add("call_target")
            labels.add(f"{source_slug}_calls_{edge_label}")
        elif relation == "safe_owner":
            labels.add("safe_signer")
        elif relation == "timelock_owner":
            labels.add("timelock_owner")
        elif relation == "proxy_admin_owner":
            labels.add("proxy_admin_owner")
        elif relation == "role_principal":
            labels.add("role_principal")

    return labels, sorted(set(context))


def _display_name(
    address: str,
    resolved_type: ResolvedControllerType,
    labels: set[str],
    graph_context: list[str],
    permissions: list[PrincipalPermission],
    contract_name: str,
    node_name: str = "",
) -> tuple[str, LabelConfidence]:
    contract_slug = _slug(contract_name)
    permission_effects = {effect for permission in permissions for effect in permission.get("effect_labels", [])}
    permission_controllers = sorted(
        {
            str(permission.get("controller", "")).strip()
            for permission in permissions
            if str(permission.get("controller", "")).strip()
        }
    )

    if resolved_type == "zero":
        return "Zero address", "high"
    if f"{contract_slug}_admin" in labels:
        if resolved_type == "safe":
            return f"{contract_name} admin Safe", "high"
        if resolved_type == "contract":
            return f"{contract_name} admin contract", "high"
        return f"{contract_name} admin", "high"
    if f"{contract_slug}_manager" in labels:
        if resolved_type == "contract":
            return f"{contract_name} manager contract", "high"
        return f"{contract_name} manager", "high"
    if f"{contract_slug}_operator" in labels:
        function_names = sorted({permission["function"].split("(", 1)[0] for permission in permissions})
        if len(function_names) <= 2 and function_names:
            joined = "/".join(function_names)
            if resolved_type == "contract":
                return f"{contract_name} {joined} contract", "medium"
            return f"{contract_name} {joined} operator", "medium"
        if resolved_type == "contract":
            return f"{contract_name} operator contract", "medium"
        return f"{contract_name} operator", "medium"
    if "authority_controller" in labels:
        return f"{contract_name} authority", "high"
    if "owner_controller" in labels and resolved_type == "safe":
        owner_of = graph_context[0].split(":", 1)[0] if graph_context else contract_name
        return f"{owner_of} owner Safe", "high"
    if permission_controllers:
        controller_name = permission_controllers[0]
        suffix = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", controller_name).replace("_", " ")
        if resolved_type == "contract" and node_name:
            return f"{node_name} ({contract_name} {suffix})", "medium"
        if resolved_type == "contract":
            return f"{contract_name} {suffix} contract", "medium"
        return f"{contract_name} {suffix}", "medium"
    if "safe_signer" in labels:
        return "Safe signer", "high"
    if permission_effects:
        return f"{contract_name} controlled principal", "medium"
    if resolved_type == "contract" and node_name:
        return node_name, "medium"
    if resolved_type == "contract" and graph_context:
        source_name, _, relation = graph_context[-1].partition(":")
        source_name = source_name.strip()
        relation = relation.strip()
        if source_name and relation and _slug(relation) not in {"role_principal", "controller_value"}:
            return f"{source_name} {relation}", "medium"
        if source_name:
            return f"{source_name} contract", "medium"
    return _display_from_type(resolved_type), "high" if resolved_type != "unknown" else "low"


def build_principal_labels(
    effective_permissions: dict,
    *,
    resolved_control_graph: dict | None = None,
    rpc_url: str | None = None,
    chain_id: int | None = None,
    classify_cache: dict[str, tuple[str, dict[str, object]]] | None = None,
    cross_chain_recognizer: Callable[[str], tuple[str, dict[str, object]] | None] | None = None,
    protocol_safe_owner_sets: Mapping[str, Mapping[str, Any]] | None = None,
    protocol_deployer_groups: Mapping[str, Mapping[str, Any]] | None = None,
    resolve_controllers: Callable[[str], Sequence[Mapping[str, Any]] | None] | None = None,
) -> PrincipalLabels:
    """Construct principal records for every authority address.

    ``classify_cache`` is mutated in place. When supplied, classification
    results from prior pipeline stages (resolution, policy graph refresh)
    are reused and any new classifications discovered here are added to
    the same dict — so a caller threading the same cache through the whole
    job sees fan-out of 6-10 RPCs per address collapse to one lookup.

    ``cross_chain_recognizer`` is an ``address -> (resolved_type,
    details) | None`` classifier that takes priority over the generic
    EOA/contract typing: an aliased L1 owner reads as a codeless EOA and a
    bridge predeploy as a generic contract, yet both are cross-chain
    authorities, never anonymous principals. ``None`` (the mainnet path, and
    every chain without bridge constants) leaves classification byte-identical.

    ``protocol_safe_owner_sets`` — the protocol's
    exact-owner Safe registry (``load_protocol_safe_owner_sets``). When present,
    each Safe principal gains a ``details.signer_overlap`` attribution fact
    against every other protocol Safe. ``None`` omits the fact (no guessing).

    ``protocol_deployer_groups`` — the protocol's shared-deployer
    groups (``load_protocol_deployer_groups``). When present, a principal whose
    address co-shares a deployer with other protocol contracts gains a witnessed
    (heuristic-tagged) ``details.shared_deployer`` fact. ``None`` omits it.

    ``resolve_controllers`` — an
    ``address -> [{"address","resolved_type","details"}, ...] | None`` step
    function (backed by on-chain owner reads). When present, each
    ``resolved_type=contract`` principal is walked to its ultimate Safe/EOA and
    the result stored in ``details.terminal_principal``. ``None`` skips the walk;
    the non-terminal
    ``details.terminal`` marking is still stamped on every principal so a
    contract way-point never reads as a settled key.
    """
    nodes_by_id = _node_by_id(resolved_control_graph or {})
    nodes_by_address = {node["address"].lower(): node for node in (resolved_control_graph or {}).get("nodes", [])}
    incoming_by_id = _incoming_edges(resolved_control_graph or {})
    outgoing_by_id = _outgoing_edges(resolved_control_graph or {})
    permissions_by_address, permission_label_hints = _collect_permissions(effective_permissions)

    addresses = set(nodes_by_address)
    addresses.update(permissions_by_address)

    target_address = effective_permissions["contract_address"].lower()
    contract_name = effective_permissions["contract_name"]
    # The per-job classify_cache is shared read+write across worker threads.
    # Fast path is the cache hit (artifact pre-populated by resolution stage),
    # so the lock is uncontended in the common case.
    classify_cache_lock = threading.Lock()
    # Cache effectiveness is the dominant perf signal here (labeling re-runs
    # classify_resolved_address = 6-10 RPCs on a miss; the memory note records a
    # 14+ min etherfi LP-impl labeling pass). A hit-rate collapse run-over-run is
    # the regression to watch.
    classify_stats: dict[str, int] = {"hits": 0, "misses": 0}

    def _per_address(address: str) -> PrincipalProfile | None:
        if not address.startswith("0x") or len(address) != 42:
            return None
        if address == target_address:
            return None
        node = nodes_by_address.get(address)
        resolved_type = coerce_resolved_controller_type(node.get("resolved_type")) if node else "unknown"
        details = dict(node.get("details", {})) if node else {}

        # Cross-chain authority is recognised from the registry +
        # run scope with no RPC, and overrides the generic classification an
        # aliased owner / bridge predeploy would otherwise receive.
        if cross_chain_recognizer is not None:
            recognized = cross_chain_recognizer(address)
            if recognized is not None:
                recognized_type, cc_details = recognized
                resolved_type = coerce_resolved_controller_type(recognized_type)
                details = {**details, **cc_details}

        if resolved_type == "unknown" and rpc_url:
            cache_key = address.lower()
            cached: tuple[str, dict[str, object]] | None = None
            if classify_cache is not None:
                with classify_cache_lock:
                    cached = classify_cache.get(cache_key)
            if cached is not None:
                with classify_cache_lock:
                    classify_stats["hits"] += 1
                cached_type, cached_details = cached
                # Pre-seeded from a persisted artifact — unproven until coerced.
                resolved_type = coerce_resolved_controller_type(cached_type)
                details = dict(cached_details)
            else:
                with classify_cache_lock:
                    classify_stats["misses"] += 1
                resolved_type, details, cacheable = classify_resolved_address_with_status(
                    rpc_url, address, chain_id=chain_id
                )
                # Skip per-job cache write if any underlying probe errored —
                # otherwise a transient blip during labeling would persist
                # a wrong "contract" classification for the rest of the job.
                if classify_cache is not None and cacheable:
                    with classify_cache_lock:
                        classify_cache[cache_key] = (resolved_type, dict(details))

        if resolved_type == "contract" and node:
            if str(details.get("controller_label", "")).strip() == "permissionController":
                return None
            outgoing_edges = outgoing_by_id.get(node.get("id", ""), [])
            if any(edge.get("to_id") != node.get("id") for edge in outgoing_edges):
                return None

        labels, graph_context = _graph_labels_for_node(
            node or {"resolved_type": resolved_type}, incoming_by_id.get((node or {}).get("id", ""), []), nodes_by_id
        )
        hint_string = permission_label_hints.get(address)
        if hint_string:
            labels.update(hint_string.split(","))

        permissions = sorted(
            permissions_by_address.get(address, []),
            key=lambda item: (item["function"], -1 if item["role"] is None else item["role"]),
        )
        display_name, confidence = _display_name(
            address,
            resolved_type,
            labels,
            graph_context,
            permissions,
            contract_name,
            _node_display_name(node),
        )
        if resolved_type == "cross_chain_authority":
            display_name, confidence = _cross_chain_display_name(details), "high"
            labels.add("cross_chain_authority")
            role = str(details.get("role") or "")
            if role:
                labels.add(role)

        # Non-terminal marking: a contract/unresolved principal is a
        # way-point, never a settled controlling key. Stamped on every principal
        # so a consumer never mistakes a ``contract`` row for a resolved key.
        details["terminal"] = is_terminal_principal_type(resolved_type)
        if resolved_type == "contract" and resolve_controllers is not None:
            # Bounded, cycle-safe walk to the ultimate Safe/EOA. Fails closed to
            # an ``unknown`` terminal record (never a guessed key) when the
            # controller is unfetched/unverified, the chain doesn't terminate, or
            # a step exposes parallel control planes (ambiguous_controllers).
            details["terminal_principal"] = resolve_terminal_principal(
                address, resolved_type, resolve_controllers=resolve_controllers
            )
        # Signer-overlap attribution fact for dispositively-enumerated Safes.
        if resolved_type == "safe" and protocol_safe_owner_sets:
            overlap = _compute_signer_overlap(address, protocol_safe_owner_sets)
            if overlap is not None:
                details["signer_overlap"] = overlap
        # Shared-deployer attribution fact — witnessed, heuristic,
        # never an org-identity deduction. Applies to any principal that is itself
        # a protocol contract co-sharing a deployer.
        if protocol_deployer_groups:
            shared = _shared_deployer_fact(address, protocol_deployer_groups)
            if shared is not None:
                details["shared_deployer"] = shared

        return {
            "address": address,
            "resolved_type": resolved_type,
            "display_name": display_name,
            "labels": sorted(label for label in labels if label),
            "confidence": confidence,
            "details": details,
            "graph_context": graph_context,
            "controller_context": sorted(
                {
                    str(permission.get("controller", "")).strip()
                    for permission in permissions
                    if str(permission.get("controller", "")).strip()
                }
            ),
            "permissions": permissions,
        }

    sorted_addresses = sorted(addresses)
    results = parallel_map(_per_address, sorted_addresses, max_workers=8)
    principals: list[PrincipalProfile] = []
    for _addr, outcome in results:
        if isinstance(outcome, BaseException):
            raise outcome
        if outcome is not None:
            principals.append(outcome)

    logger.info(
        "principal labels: %d principals (classify %d hit / %d miss)",
        len(principals),
        classify_stats["hits"],
        classify_stats["misses"],
        extra={
            "phase": "principal_labels_detail",
            "principal_count": len(principals),
            "classify_hits": classify_stats["hits"],
            "classify_misses": classify_stats["misses"],
        },
    )
    record_stage_metric("label_classify_hits", classify_stats["hits"])
    record_stage_metric("label_classify_misses", classify_stats["misses"])

    return {
        "schema_version": "0.1",
        "contract_address": effective_permissions["contract_address"],
        "contract_name": contract_name,
        "principals": principals,
    }
