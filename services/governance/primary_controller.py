"""Per-contract primary-controller assignment.

Both the Surface canvas grouping and the unified monitoring enrollment
need to answer the same question: "for each contract in this protocol,
which non-contract principal (Safe / Timelock / EOA / proxy admin) is
its canonical governing authority?". Computing the answer in one place
on the server is what keeps those two views from drifting — the
frontend used to derive it locally from ``principal.controls`` + a
priority constant, and the enrollment path used to enroll *every*
safe/timelock CGN node regardless of relation, so a fee-destination
Safe stored in a state variable (e.g. ``accountantState.payoutAddress``)
ended up in the Monitoring tab as a fully-watched governance multisig.

Eligibility uses ``function_principals`` membership, the same signal
``services/aggregations/company_overview`` already trusts for
in-protocol contract principals: an address is a primary-controller
candidate for a contract iff it has a ``FunctionPrincipal`` row on at
least one ``EffectiveFunction`` of that contract. State-variable
destinations don't appear in FP — they describe where the contract
*sends* something, not who can call it — so they drop out
automatically without a label heuristic. This intentionally diverges
from a CGN-walk because CGN is a flattened transitive graph and would
re-introduce the fee-destination misclassification it's meant to fix.

When several principals are eligible for the same contract, one wins
deterministically: Safe > Timelock > EOA > proxy admin (Safes are
where the actual signers live; proxy_admin tends to wrap an EOA), then
the principal owning more contracts overall (treats "owns more" as
"more canonical"), then lex-smallest address as the final stable
tiebreak.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from schemas.common import Address
from schemas.governance_schemas import GovernancePrincipal

PRINCIPAL_PRIORITY: dict[str, int] = {
    "safe": 4,
    "timelock": 3,
    "eoa": 2,
    "proxy_admin": 1,
}

# Maximum number of governance contracts (Timelock / ProxyAdmin) an
# ownership chain may traverse before we stop. Real stacks are 1–2 hops
# (multisig → timelock → governed contract); the cap only guards against
# pathological or cyclic FP graphs — the visited-set already breaks cycles.
_MAX_GOVERNANCE_HOPS = 4


def assign_primary_controllers(
    principals: list[GovernancePrincipal],
    fp_addrs_by_contract: Mapping[Address, set[Address]],
    governance_passthrough: set[Address] | None = None,
) -> dict[Address, list[Address]]:
    """Pick one primary controller per contract.

    *principals* — non-contract principals (the ``_build_flows_and_principals``
    output shape). Each must have ``address`` and ``type``; only those whose
    ``type`` is in :data:`PRINCIPAL_PRIORITY` participate.

    *fp_addrs_by_contract* — for every contract address (lower-cased), the
    set of ``function_principals.address`` values (lower-cased) attached to
    any ``EffectiveFunction`` of that contract. The caller is expected to
    drop ``signature_witness`` rows before building this map.

    *governance_passthrough* — addresses of in-protocol governance contracts
    (Timelocks / ProxyAdmins) that *mediate* control rather than hold it: the
    real authority calls them, and they in turn call the governed contracts.
    When a contract's FP caller is one of these, eligibility is resolved one
    hop further — through that governance contract's own FP callers — until a
    terminal principal is reached. Because only FP (call-authority) edges are
    traversed, fund-destination addresses (e.g. ``payoutAddress`` Safes, which
    never hold an FP row) cannot be re-introduced. ``None`` ⇒ no traversal:
    every caller is terminal, i.e. the original one-hop behavior.

    Returns ``{principal_address_lc: [contract_address_lc, ...]}`` for every
    eligible principal. Principals that lose every contract still appear in
    the dict with an empty list so a caller can distinguish "not primary"
    from "unknown principal". Each list is sorted for deterministic output.
    """
    principal_by_addr: dict[Address, GovernancePrincipal] = {}
    for p in principals:
        addr = (p.get("address") or "").lower()
        if not addr:
            continue
        if p.get("type") not in PRINCIPAL_PRIORITY:
            continue
        principal_by_addr[addr] = p

    # Normalize the FP graph to lower-case keys/values once so the closure
    # below can walk it directly (callers don't always normalize both sides).
    fp_graph: dict[Address, set[Address]] = {}
    for contract_addr, fp_addrs in fp_addrs_by_contract.items():
        fp_graph.setdefault(contract_addr.lower(), set()).update((a or "").lower() for a in fp_addrs)
    passthrough = {(a or "").lower() for a in (governance_passthrough or ())}

    def _effective_controllers(contract_lc: Address) -> set[Address]:
        """Terminal controllers of *contract_lc*: its direct FP callers, with
        any caller that is itself a ``passthrough`` governance contract
        expanded into *its* callers. Depth-bounded; the visited set breaks
        cycles and the ``addr != contract_lc`` guard avoids self-recursion."""
        out: set[Address] = set()
        seen: set[Address] = set()
        stack: list[tuple[Address, int]] = [(a, 1) for a in fp_graph.get(contract_lc, ())]
        while stack:
            addr, depth = stack.pop()
            if addr in seen:
                continue
            seen.add(addr)
            out.add(addr)
            if addr != contract_lc and addr in passthrough and depth < _MAX_GOVERNANCE_HOPS:
                stack.extend((nxt, depth + 1) for nxt in fp_graph.get(addr, ()) if nxt not in seen)
        return out

    # eligibility[principal_lc] = set of contract addresses this principal
    # could primary-control. A principal is eligible for a contract iff it is
    # one of that contract's effective controllers (its FP callers, resolved
    # transitively through any in-protocol governance contract in between).
    eligibility: dict[Address, set[Address]] = {addr: set() for addr in principal_by_addr}
    for contract_lc in fp_graph:
        for ctrl in _effective_controllers(contract_lc):
            if ctrl in eligibility:
                eligibility[ctrl].add(contract_lc)

    total_owned = {addr: len(owned) for addr, owned in eligibility.items()}

    primary_for: dict[Address, list[Address]] = {addr: [] for addr in principal_by_addr}

    all_contested: set[Address] = set()
    for owned in eligibility.values():
        all_contested.update(owned)

    for contract_lc in all_contested:
        best_addr: Address | None = None
        best_key: tuple[int, int, str] | None = None
        for addr, owned in eligibility.items():
            if contract_lc not in owned:
                continue
            ptype = principal_by_addr[addr].get("type") or ""
            priority = PRINCIPAL_PRIORITY.get(ptype, 0)
            # Smaller tuple wins: negate priority/size so larger sorts earlier;
            # raw address (lex-smallest) is the final stable tiebreak.
            key = (-priority, -total_owned[addr], addr)
            if best_key is None or key < best_key:
                best_addr = addr
                best_key = key
        if best_addr is not None:
            primary_for[best_addr].append(contract_lc)

    for addr in primary_for:
        primary_for[addr].sort()

    return primary_for


# Effect labels that mark a function as a governance/admin power on their own.
# Holding authority on one is enough to treat a non-primary FP caller as a real
# co-controller worth surfacing/monitoring, no matter how many callers share
# the function. ``external_contract_call`` / ``hook_update`` are intentionally
# absent: they're borne by both privileged config setters AND permissionless
# callers (EtherFi ``createBid`` is ``external_contract_call``), so they don't
# discriminate — the caller-set-size arm separates those.
PRIVILEGED_EFFECT_LABELS: frozenset[str] = frozenset(
    {
        "pause_toggle",
        "ownership_transfer",
        "role_management",
        "implementation_update",
        "asset_send",
        "asset_pull",
        "mint",
        "burn",
        "delegatecall_execution",
        "authority_update",
        "contract_deployment",
    }
)

# A function shared by more than this many distinct authorized callers reads as
# a broad whitelist (permissionless-ish), not an access-controlled governance
# gate. EtherFi's ``createBid`` is shared by ~33 callers; real admin gates
# (pause / recover / setCapacity) are held by 1–3. Anything in [3, 32] cleanly
# separates them on the observed data; 4 leaves margin for a small
# multisig + timelock + operator-EOA set sharing one gate.
_MAX_GATE_CALLERS = 4


def assign_co_controllers(
    principals: list[GovernancePrincipal],
    fp_function_detail_by_contract: Mapping[Address, Sequence[Mapping[str, Any]]],
    primary_for: Mapping[Address, list[Address]],
    *,
    max_gate_callers: int = _MAX_GATE_CALLERS,
    privileged_labels: frozenset[str] = PRIVILEGED_EFFECT_LABELS,
) -> dict[Address, list[Address]]:
    """Per principal, the contracts it *co-controls*: holds real authority on
    without being the canonical primary controller.

    :func:`assign_primary_controllers` names one primary per contract, so a
    legitimate co-governor that loses the contest — e.g. a pause / fund-recovery
    guardian Safe whose contracts a bigger governance Safe also wins — drops off
    both the Surface canvas and monitoring enrollment. This recovers exactly
    that set while excluding the noise the bare FP-authority signal admits:
    permissionless callers like whitelisted auction bidders.

    *fp_function_detail_by_contract* — ``{contract_addr_lc: [{"callers":
    set[addr], "labels": set[str]}, ...]}``, one entry per ``EffectiveFunction``
    of the contract that has at least one (non-``signature_witness``) FP caller.
    Contract addresses are the *rendered* (proxy) addresses, matching
    *primary_for* and Surface group containment.

    *primary_for* — the :func:`assign_primary_controllers` output. A principal
    is never listed as co-controlling a contract it already primary-controls.

    A principal ``P`` (type in :data:`PRINCIPAL_PRIORITY`) co-controls contract
    ``C`` iff ``P`` is an authorized caller of some *significant* function ``f``
    of ``C``: ``f`` bears a label in *privileged_labels*, or ``f`` is gated to at
    most *max_gate_callers* distinct callers. The arms are complementary — the
    gate arm catches privileged functions the analyzer labels weakly
    (``setCapacity`` / ``sweepFunds`` surface only as ``external_contract_call``)
    regardless of label, while the label arm keeps a privileged function even
    when its role-holder set is larger than the gate. Together they keep
    guardians and drop broad whitelists.

    Returns ``{principal_address_lc: [contract_address_lc, ...]}`` for every
    eligible principal (empty list when it co-controls nothing), each list
    sorted — same shape as :func:`assign_primary_controllers`.
    """
    principal_addrs: set[Address] = set()
    for p in principals:
        addr = (p.get("address") or "").lower()
        if addr and p.get("type") in PRINCIPAL_PRIORITY:
            principal_addrs.add(addr)

    primary_of: dict[Address, Address] = {}
    for paddr, owned in primary_for.items():
        for c in owned:
            primary_of[(c or "").lower()] = (paddr or "").lower()

    co: dict[Address, set[Address]] = {addr: set() for addr in principal_addrs}
    for contract_addr, functions in fp_function_detail_by_contract.items():
        c_lc = (contract_addr or "").lower()
        for fn in functions:
            callers = {(a or "").lower() for a in fn.get("callers", ())}
            labels = {(label or "").lower() for label in fn.get("labels", ())}
            significant = bool(labels & privileged_labels) or len(callers) <= max_gate_callers
            if not significant:
                continue
            for caller in callers:
                if caller in principal_addrs and primary_of.get(c_lc) != caller:
                    co[caller].add(c_lc)

    return {addr: sorted(contracts) for addr, contracts in co.items()}
