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

from collections.abc import Mapping
from typing import Any

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
    principals: list[dict[str, Any]],
    fp_addrs_by_contract: Mapping[str, set[str]],
    governance_passthrough: set[str] | None = None,
) -> dict[str, list[str]]:
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
    principal_by_addr: dict[str, dict[str, Any]] = {}
    for p in principals:
        addr = (p.get("address") or "").lower()
        if not addr:
            continue
        if p.get("type") not in PRINCIPAL_PRIORITY:
            continue
        principal_by_addr[addr] = p

    # Normalize the FP graph to lower-case keys/values once so the closure
    # below can walk it directly (callers don't always normalize both sides).
    fp_graph: dict[str, set[str]] = {}
    for contract_addr, fp_addrs in fp_addrs_by_contract.items():
        fp_graph.setdefault(contract_addr.lower(), set()).update((a or "").lower() for a in fp_addrs)
    passthrough = {(a or "").lower() for a in (governance_passthrough or ())}

    def _effective_controllers(contract_lc: str) -> set[str]:
        """Terminal controllers of *contract_lc*: its direct FP callers, with
        any caller that is itself a ``passthrough`` governance contract
        expanded into *its* callers. Depth-bounded; the visited set breaks
        cycles and the ``addr != contract_lc`` guard avoids self-recursion."""
        out: set[str] = set()
        seen: set[str] = set()
        stack: list[tuple[str, int]] = [(a, 1) for a in fp_graph.get(contract_lc, ())]
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
    eligibility: dict[str, set[str]] = {addr: set() for addr in principal_by_addr}
    for contract_lc in fp_graph:
        for ctrl in _effective_controllers(contract_lc):
            if ctrl in eligibility:
                eligibility[ctrl].add(contract_lc)

    total_owned = {addr: len(owned) for addr, owned in eligibility.items()}

    primary_for: dict[str, list[str]] = {addr: [] for addr in principal_by_addr}

    all_contested: set[str] = set()
    for owned in eligibility.values():
        all_contested.update(owned)

    for contract_lc in all_contested:
        best_addr: str | None = None
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
