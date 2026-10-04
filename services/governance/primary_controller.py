"""Per-contract primary-controller assignment, shared by canvas grouping and monitoring enrollment so they can't
drift.

(Enrollment used to watch every Safe/Timelock CGN node, so fee-destination Safes like ``payoutAddress`` were monitored
as governance.)

Candidates are principals with a ``FunctionPrincipal`` row on the contract: state-variable destinations aren't callers,
so they drop out without heuristics. Not CGN, which is transitive and reintroduces the misclassification.

Winner: authority tier on that contract (governs > grants > operates), then type (Safe > Timelock > EOA > proxy admin),
then lex-smallest address. Only per-contract facts, so analyzing more of the protocol never flips an assignment (the old
"owns more contracts" tiebreak did).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from services.static.claims import CONTROL_GRANT_CLASSES, claim_ids_of_class
from utils import claim_ids as C

PRINCIPAL_PRIORITY: dict[str, int] = {
    "safe": 4,
    "timelock": 3,
    "eoa": 2,
    "proxy_admin": 1,
}

# One claim->chip vocabulary for contract chips, controller detail and tier ranking, so a power reads the same
# everywhere. Unmapped control claims (:data:`_UNCHIPPED_CONTROL_CLAIMS`) show by name.
CLAIM_CAPABILITY: dict[str, str] = {
    C.PAUSE_SET: "pause",
    C.PAUSE_UNSET: "pause",
    C.OWNERSHIP_TRANSFER: "ownership",
    C.OWNERSHIP_RENOUNCE: "ownership",
    C.OWNERSHIP_ACCEPT: "ownership",
    C.AUTHORIZED_CALLER_ROTATE: "authority",
    C.AUTHORITY_REPLACE: "authority",
    C.ROLES_GRANT: "roles",
    C.ROLES_REVOKE: "roles",
    C.ROLES_CONFIGURE: "roles",
    C.UPGRADE_IMPLEMENTATION: "upgrade",
    C.PROXY_ADMIN_CHANGE: "upgrade",
    C.TIMELOCK_SCHEDULE: "timelock",
    C.TIMELOCK_EXECUTE: "timelock",
    C.TIMELOCK_CANCEL: "timelock",
    C.TIMELOCK_SET_DELAY: "timelock",
    C.SAFE_SIGNER_MGMT: "safe",
    C.SAFE_MODULE_MGMT: "safe",
    C.SAFE_SET_GUARD: "safe",
    C.TRANSFER_POLICY_CONFIGURE: "config",
    C.FLOW_OUT: "fund-out",
    C.FLOW_IN: "fund-in",
    C.SUPPLY_MINT: "mint",
    C.SUPPLY_BURN: "burn",
    C.EXEC_ARBITRARY: "arbitrary-call",
    C.DELEGATECALL_EXECUTE: "delegatecall",
    C.CONTRACT_DEPLOYMENT: "deploy",
}
_UNCHIPPED_CONTROL_CLAIMS: frozenset[str] = frozenset(
    {C.CALLEE_POINTER_ROTATE, C.LZ_OAPP_SET_PEER, C.LZ_OAPP_SET_DELEGATE, C.AUTHORITY_GRANT}
)


def function_capabilities(claim_ids: Iterable[str]) -> set[str]:
    """Chips for one function's claims. A claim-less function earns none."""
    return {CLAIM_CAPABILITY[cid] for cid in claim_ids if cid in CLAIM_CAPABILITY}


# Tier 3 governs (replaces or executes code, reassigns control, or drives a timelock); tier 2 grants access; tier 1
# operates. An operational Safe must never outrank the actual owner.
_GOVERNING_CLAIMS: frozenset[str] = claim_ids_of_class("control.code") | {
    C.OWNERSHIP_TRANSFER,
    C.OWNERSHIP_RENOUNCE,
    C.OWNERSHIP_ACCEPT,
    C.AUTHORITY_REPLACE,
    C.AUTHORIZED_CALLER_ROTATE,
    C.PROXY_ADMIN_CHANGE,
    C.TIMELOCK_SCHEDULE,
    C.TIMELOCK_EXECUTE,
}
_GRANTING_CLAIMS: frozenset[str] = frozenset({C.ROLES_GRANT, C.ROLES_REVOKE, C.ROLES_CONFIGURE})


def _authority_tier(claim_ids: set[str]) -> int:
    if claim_ids & _GOVERNING_CLAIMS:
        return 3
    if claim_ids & _GRANTING_CLAIMS:
        return 2
    return 1


# Real stacks are 1–2 hops; the visited-set breaks cycles.
_MAX_GOVERNANCE_HOPS = 4


def _addr_of(token: str) -> str:
    """Bare address from a possibly-composite token; plain addresses pass through."""
    return token.rsplit("::", 1)[-1]


def assign_primary_controllers(
    principals: list[dict[str, Any]],
    fp_addrs_by_contract: Mapping[str, set[str]],
    governance_passthrough: set[str] | None = None,
    fp_function_detail_by_contract: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
) -> dict[str, list[str]]:
    """Pick one primary controller per contract.

    *fp_addrs_by_contract* and *fp_function_detail_by_contract* keys and values may be bare or composite entities, but
    consistently. Drop ``signature_witness`` rows first.

    *governance_passthrough* — in-protocol Timelocks/ProxyAdmins that mediate control; eligibility resolves through
    their FP callers. Only FP edges are followed, so fund destinations can't re-enter. ``None`` = one hop.

    With function detail (``None`` degrades each to evidence-free):

    * **Tier** — the strongest capability held on the contract; passthrough principals rank by the mediator's functions.
    No detail means every candidate is tier 1.
    * **Driver gating** — expand through a mediator only to callers that can make it act (or whose power is
    undetermined). A cancel-only veto inherits nothing.
    * **Significance** — callers whose functions are all broad whitelists (``createBid``) aren't eligible, directly or
    via a mediator. Same test as :func:`assign_co_controllers`.

    Returns ``{principal: [contracts]}`` for every eligible principal, empty lists included, sorted.
    """
    principal_by_addr: dict[str, dict[str, Any]] = {}
    for p in principals:
        addr = (p.get("address") or "").lower()
        if not addr:
            continue
        if p.get("type") not in PRINCIPAL_PRIORITY:
            continue
        principal_by_addr[addr] = p

    fp_graph: dict[str, set[str]] = {}
    for contract_addr, fp_addrs in fp_addrs_by_contract.items():
        fp_graph.setdefault(contract_addr.lower(), set()).update((a or "").lower() for a in fp_addrs)
    passthrough = {(a or "").lower() for a in (governance_passthrough or ())}

    # Per (contract, caller): claim ids, plus ``significant_on`` and ``driver_on``. Caller keys normalized via
    # ``_addr_of`` so a keyspace mismatch can't silently disable the gates.
    claims_on: dict[tuple[str, str], set[str]] = {}
    with_rows: set[tuple[str, str]] = set()
    significant_on: set[tuple[str, str]] = set()
    driver_on: set[tuple[str, str]] = set()
    for contract_addr, functions in (fp_function_detail_by_contract or {}).items():
        c_lc = contract_addr.lower()
        for fn in functions:
            fn_claims = {c for c in fn.get("claims") or () if isinstance(c, str) and c}
            callers = {_addr_of((a or "").lower()) for a in fn.get("callers", ())} - {""}
            significant = _function_is_privileged(list(fn_claims)) or len(callers) <= _MAX_GATE_CALLERS
            drives = (
                not fn_claims  # claim-less row: driving power not determined
                or bool(fn_claims & (_GOVERNING_CLAIMS | _GRANTING_CLAIMS))
            )
            for la in callers:
                claims_on.setdefault((c_lc, la), set()).update(fn_claims)
                with_rows.add((c_lc, la))
                if significant:
                    significant_on.add((c_lc, la))
                if drives:
                    driver_on.add((c_lc, la))

    def _tier_on(contract_lc: str, caller_token: str) -> int:
        key = (contract_lc, _addr_of(caller_token))
        return _authority_tier(claims_on.get(key, set()))

    def _has_governance_on(contract_lc: str, caller_token: str) -> bool:
        """No detail rows stays eligible: absence isn't proof of a broad whitelist."""
        key = (contract_lc, _addr_of(caller_token))
        return key in significant_on or key not in with_rows

    def _can_inherit_through(mediator_lc: str, caller_token: str) -> bool:
        """Needs significance plus driving evidence (or undetermined power). No rows means legacy expansion."""
        key = (mediator_lc, _addr_of(caller_token))
        if key not in with_rows:
            return True
        return key in significant_on and key in driver_on

    def _effective_controllers(contract_lc: str) -> dict[str, int]:
        """Terminal controllers with their best tier: direct callers at their own tier, passthrough-inherited ones at
        the mediator's. Revisiting only on a strictly better tier breaks cycles.
        """
        best: dict[str, int] = {}
        stack: list[tuple[str, int, int]] = [
            (a, _tier_on(contract_lc, a), 1)
            for a in fp_graph.get(contract_lc, ())
            if _has_governance_on(contract_lc, a)
        ]
        while stack:
            addr, tier, depth = stack.pop()
            if best.get(addr, 0) >= tier:
                continue
            best[addr] = tier
            if addr != contract_lc and addr in passthrough and depth < _MAX_GOVERNANCE_HOPS:
                stack.extend(
                    (nxt, tier, depth + 1)
                    for nxt in fp_graph.get(addr, ())
                    if best.get(nxt, 0) < tier and _can_inherit_through(addr, nxt)
                )
        return best

    # Principal identity is the bare address.
    eligibility: dict[str, dict[str, int]] = {addr: {} for addr in principal_by_addr}
    for contract_lc in fp_graph:
        for ctrl, tier in _effective_controllers(contract_lc).items():
            ctrl_addr = _addr_of(ctrl)
            owned = eligibility.get(ctrl_addr)
            if owned is not None and owned.get(contract_lc, 0) < tier:
                owned[contract_lc] = tier

    primary_for: dict[str, list[str]] = {addr: [] for addr in principal_by_addr}

    all_contested: set[str] = set()
    for owned in eligibility.values():
        all_contested.update(owned)

    for contract_lc in all_contested:
        best_addr: str | None = None
        best_key: tuple[int, int, str] | None = None
        for addr, owned in eligibility.items():
            tier = owned.get(contract_lc)
            if tier is None:
                continue
            ptype = principal_by_addr[addr].get("type") or ""
            priority = PRINCIPAL_PRIORITY.get(ptype, 0)
            # Negated so larger sorts first; every component is per-contract, so unrelated contracts can't change the
            # winner.
            key = (-tier, -priority, addr)
            if best_key is None or key < best_key:
                best_addr = addr
                best_key = key
        if best_addr is not None:
            primary_for[best_addr].append(contract_lc)

    for addr in primary_for:
        primary_for[addr].sort()

    return primary_for


def assign_operand_render_groups(
    fp_addrs_by_contract: Mapping[str, set[str]],
    contract_keys: set[str],
    governance_passthrough: set[str],
    primary_for: Mapping[str, list[str]],
) -> dict[str, str]:
    """Render home for machinery contracts (FP authority on other contracts) whose operands were won by a different
    principal, based on the machinery's own FP rows.

    * **Any contract — unanimity**: every operand owned by one principal.
    * **Passthrough mediator — strict plurality**; ties emit nothing.

    ``primary_for`` is untouched (enrollment and authority claims keep the true controller). Only members of
    *contract_keys* are re-homed. Returns entries only where the home differs from the primary.
    """
    primary_of: dict[str, str] = {}
    for paddr, owned in primary_for.items():
        for c in owned:
            primary_of[(c or "").lower()] = (paddr or "").lower()

    contract_keys_lc = {(c or "").lower() for c in contract_keys}
    passthrough_lc = {(m or "").lower() for m in governance_passthrough}

    # None counts unowned operands: they block unanimity but don't weigh in the plurality.
    operand_homes: dict[str, dict[str | None, int]] = {}
    for contract_addr, callers in fp_addrs_by_contract.items():
        c_lc = contract_addr.lower()
        winner = primary_of.get(c_lc)
        for tok in callers:
            x_lc = (tok or "").lower()
            if x_lc == c_lc or x_lc not in contract_keys_lc:
                continue
            counts = operand_homes.setdefault(x_lc, {})
            counts[winner] = counts.get(winner, 0) + 1

    out: dict[str, str] = {}
    for x_lc, counts in operand_homes.items():
        own = primary_of.get(x_lc)
        homes = [h for h in counts if h is not None]
        if len(counts) == 1 and homes:
            target = homes[0]
        elif x_lc in passthrough_lc and homes:
            ranked = sorted(((h, counts[h]) for h in homes), key=lambda kv: (-kv[1], kv[0]))
            if len(ranked) > 1 and ranked[1][1] == ranked[0][1]:
                continue
            target = ranked[0][0]
        else:
            continue
        if target != own:
            out[x_lc] = target
    return out


# Holding one of these makes a non-primary caller a real co-controller. ``callee_pointer.rotate`` and ``value_router``
# are absent: permissionless callers bear them too (``createBid``).
_PRIVILEGED_CLAIMS: frozenset[str] = (claim_ids_of_class(*CONTROL_GRANT_CLASSES) - {C.CALLEE_POINTER_ROTATE}) | {
    C.FLOW_IN,
    C.CONTRACT_DEPLOYMENT,
}


def _function_is_privileged(claims: Any) -> bool:
    claim_ids = {c for c in claims if isinstance(c, str) and c} if isinstance(claims, list) else set()
    return bool(claim_ids & _PRIVILEGED_CLAIMS)


# ``createBid`` has ~33 callers; real admin gates have 1–3. Anything in [3, 32] separates them; 4 leaves margin.
_MAX_GATE_CALLERS = 4


def assign_co_controllers(
    principals: list[dict[str, Any]],
    fp_function_detail_by_contract: Mapping[str, Sequence[Mapping[str, Any]]],
    primary_for: Mapping[str, list[str]],
    *,
    max_gate_callers: int = _MAX_GATE_CALLERS,
) -> dict[str, list[str]]:
    """Per principal, contracts it co-controls: real authority without being primary (a pause/recovery guardian Safe
    that lost the contest would otherwise vanish from canvas and monitoring).

    ``P`` co-controls ``C`` iff it can call a significant function of ``C``: privileged by claim, or gated to at most
    *max_gate_callers*. The gate arm catches unclaimed admin functions (``setCapacity``); the claim arm keeps privileged
    ones with large role sets. Never lists a contract ``P`` already primary-controls. Same return shape as
    :func:`assign_primary_controllers`.
    """
    principal_addrs: set[str] = set()
    for p in principals:
        addr = (p.get("address") or "").lower()
        if addr and p.get("type") in PRINCIPAL_PRIORITY:
            principal_addrs.add(addr)

    primary_of: dict[str, str] = {}
    for paddr, owned in primary_for.items():
        for c in owned:
            primary_of[(c or "").lower()] = (paddr or "").lower()

    co: dict[str, set[str]] = {addr: set() for addr in principal_addrs}
    for contract_addr, functions in fp_function_detail_by_contract.items():
        c_lc = (contract_addr or "").lower()
        for fn in functions:
            callers = {(a or "").lower() for a in fn.get("callers", ())}
            significant = _function_is_privileged(fn.get("claims")) or len(callers) <= max_gate_callers
            if not significant:
                continue
            for caller in callers:
                if caller in principal_addrs and primary_of.get(c_lc) != caller:
                    co[caller].add(c_lc)

    return {addr: sorted(contracts) for addr, contracts in co.items()}
