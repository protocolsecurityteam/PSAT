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
deterministically, ranked by per-contract evidence: first the authority
*tier* the principal provably holds on that contract (governs > grants
> operates — see :func:`_authority_tier`), then principal type
(Safe > Timelock > EOA > proxy admin: Safes are where the actual
signers live; proxy_admin tends to wrap an EOA), then lex-smallest
address. The key is built only from facts about the contested contract
itself, so analyzing more of the protocol can never flip an existing
assignment — the old "owns more contracts overall" tiebreak was a count
over whatever subset happened to be analyzed, and box identity flipped
as coverage grew.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

PRINCIPAL_PRIORITY: dict[str, int] = {
    "safe": 4,
    "timelock": 3,
    "eoa": 2,
    "proxy_admin": 1,
}

# One shared vocabulary: effect facts → capability chip. Feeds the machine
# ``capabilities`` field (the contract card / contract-click chips), the
# per-(controller, contract) detail (guardian / co-controller chips, sidebar
# "Can Call"), and the authority-tier ranking below. One map means the same
# power reads the same word no matter what you click — a Safe's "fund-out" on
# EETH matches the chip you'd see clicking EETH itself.
#
# ``CLAIM_CAPABILITY`` is the Plane-1 vocabulary, authoritative per function.
# It adds the ``timelock`` / ``safe`` chips (no legacy label ever mapped to
# them) and finally produces ``arbitrary-call`` (its ``arbitrary_external_call``
# legacy source was corpus-dead). The hook/external exclusion is now structural:
# ``external_contract_call`` isn't representable as a claim at all, and
# ``callee_pointer.rotate`` (the precise hook-pointer rotation) is deliberately
# unmapped, so those functions are still shown by name.
CLAIM_CAPABILITY: dict[str, str] = {
    "pause.set": "pause",
    "pause.unset": "pause",
    "ownership.transfer": "ownership",
    "ownership.renounce": "ownership",
    "ownership.accept": "ownership",
    "authorized_caller.rotate": "authority",
    "authority.replace": "authority",
    "roles.grant": "roles",
    "roles.revoke": "roles",
    "roles.configure": "roles",
    "upgrade.implementation": "upgrade",
    "proxy.admin_change": "upgrade",
    "timelock.schedule": "timelock",
    "timelock.execute": "timelock",
    "timelock.cancel": "timelock",
    "timelock.set_delay": "timelock",
    "safe.signer_mgmt": "safe",
    "safe.module_mgmt": "safe",
    "safe.set_guard": "safe",
    "flow.out": "fund-out",
    "flow.in": "fund-in",
    "supply.mint": "mint",
    "supply.burn": "burn",
    "exec.arbitrary": "arbitrary-call",
    "contract_deployment": "deploy",
}

# Legacy effect_labels → chip, the fallback for claim-less rows (stale data /
# degraded artifact). ``delegatecall_execution`` is a Plane-0 fact with no claim
# projection, so it only ever surfaces a chip through this path.
EFFECT_CAPABILITY: dict[str, str] = {
    "pause_toggle": "pause",
    "ownership_transfer": "ownership",
    "role_management": "roles",
    "implementation_update": "upgrade",
    "asset_send": "fund-out",
    "asset_pull": "fund-in",
    "mint": "mint",
    "burn": "burn",
    "delegatecall_execution": "delegatecall",
    "authority_update": "authority",
    "contract_deployment": "deploy",
    "arbitrary_external_call": "arbitrary-call",
}


def function_capabilities(labels: Iterable[str], claim_ids: Iterable[str]) -> set[str]:
    """Capability chips for ONE function. Plane-1 claims are authoritative when
    present; a claim-less function falls back to the legacy effect_labels map.
    Coarse effects with no clean chip drop out — their functions are shown by
    name instead."""
    claim_id_set = set(claim_ids)
    if claim_id_set:
        return {CLAIM_CAPABILITY[cid] for cid in claim_id_set if cid in CLAIM_CAPABILITY}
    return {EFFECT_CAPABILITY[label] for label in labels if label in EFFECT_CAPABILITY}


# Authority tiers for the primary contest. Tier 3 ("governs"): can replace the
# contract's code or reassign who controls it — upgrade / ownership / authority /
# delegatecall capabilities, or driving a timelock (schedule/execute claims: the
# driver of a timelock exercises everything the timelock owns). Tier 2
# ("grants"): can grant or revoke access. Tier 1 ("operates"): everything else —
# pause, fund recovery, whitelists, parameter setters. An operational Safe with
# rights on many contracts must never outrank the contract's actual owner, which
# is what the old portfolio-count tiebreak allowed.
_GOVERNING_CAPS: frozenset[str] = frozenset({"upgrade", "ownership", "authority", "arbitrary-call", "delegatecall"})
_GRANTING_CAPS: frozenset[str] = frozenset({"roles"})
_GOVERNING_CLAIMS: frozenset[str] = frozenset({"timelock.schedule", "timelock.execute"})


def _authority_tier(caps: set[str], claim_ids: set[str]) -> int:
    if (caps & _GOVERNING_CAPS) or (claim_ids & _GOVERNING_CLAIMS):
        return 3
    if caps & _GRANTING_CAPS:
        return 2
    return 1


# Maximum number of governance contracts (Timelock / ProxyAdmin) an
# ownership chain may traverse before we stop. Real stacks are 1–2 hops
# (multisig → timelock → governed contract); the cap only guards against
# pathological or cyclic FP graphs — the visited-set already breaks cycles.
_MAX_GOVERNANCE_HOPS = 4


def _addr_of(token: str) -> str:
    """Bare lowercased address of a possibly-composite ``<chain>::<address>``
    token. A plain address (no ``"::"``) passes through unchanged, so callers
    that key by bare address (the pre-multichain shape, and the unit tests) work
    identically to callers that key by composite entity (the Surface pipeline,
    which keeps twins on different chains from merging — inv. 13)."""
    return token.rsplit("::", 1)[-1]


def assign_primary_controllers(
    principals: list[dict[str, Any]],
    fp_addrs_by_contract: Mapping[str, set[str]],
    governance_passthrough: set[str] | None = None,
    fp_function_detail_by_contract: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
) -> dict[str, list[str]]:
    """Pick one primary controller per contract.

    *principals* — non-contract principals (the ``_build_flows_and_principals``
    output shape). Each must have ``address`` and ``type``; only those whose
    ``type`` is in :data:`PRINCIPAL_PRIORITY` participate.

    *fp_addrs_by_contract* — for every contract key, the set of
    ``function_principals.address`` values attached to any ``EffectiveFunction``
    of that contract. Keys and values may be bare lowercased addresses OR
    composite ``<chain>::<address>`` entity tokens; the two must be in the same
    keyspace so the passthrough walk connects a governance contract's caller edge
    to its own contract key. The returned contract keys mirror whatever keyspace
    was passed in. The caller is expected to drop ``signature_witness`` rows
    before building this map.

    *governance_passthrough* — addresses of in-protocol governance contracts
    (Timelocks / ProxyAdmins) that *mediate* control rather than hold it: the
    real authority calls them, and they in turn call the governed contracts.
    When a contract's FP caller is one of these, eligibility is resolved one
    hop further — through that governance contract's own FP callers — until a
    terminal principal is reached. Because only FP (call-authority) edges are
    traversed, fund-destination addresses (e.g. ``payoutAddress`` Safes, which
    never hold an FP row) cannot be re-introduced. ``None`` ⇒ no traversal:
    every caller is terminal, i.e. the original one-hop behavior.

    *fp_function_detail_by_contract* — per contract key (same keyspace as
    *fp_addrs_by_contract*), the per-function ``{"callers": set, "labels": set,
    "claims": [claim_id, ...]}`` rows (the ``fp_function_detail`` projection).
    Caller values may be bare addresses (what the projection emits) or
    composite entity tokens — both are normalized to bare for the evidence
    lookups, so either convention matches the FP graph's caller tokens.
    Supplies the evidence for the rank refinements below; ``None`` degrades
    all of them to the evidence-free default:

    * **Authority tier.** Each eligible principal is ranked by the strongest
      capability it provably holds on the contested contract
      (:func:`_authority_tier`): a direct caller by its own functions there, a
      passthrough-resolved principal by the *mediator's* functions there (the
      mediator is what actually acts on the contract). Best tier across all
      paths wins. No detail ⇒ every candidate ranks tier 1 — absence of a
      proven capability is not proof of one, so nothing outranks anything.

    * **Driver gating.** The walk expands through a mediator only to callers
      that can make it act (:func:`_can_inherit_through`): a proven driving
      function — timelock schedule/execute claims, or a governing/granting
      capability on the mediator — or a claim-less function whose power is
      not determined. A caller every one of whose mediator functions is
      proven non-driving (a cancel-only veto, a delay setter) can block the
      mediator but never wield what it owns, so it inherits nothing. Callers
      with no rows at all expand as before — absence of evidence excludes
      nothing.

    * **Significance gating.** A caller whose proven functions on a contract
      are all insignificant — not privileged and shared wider than the
      co-controller gate threshold (a broad whitelist like ``createBid``) —
      is not primary-eligible for that contract at all, and the same bar
      applies to inheriting through a mediator (a whitelist on the mediator
      anchors nothing one hop out either). Same two-arm test as
      :func:`assign_co_controllers`, so primary eligibility is a subset of
      real-authority. Callers with no detail rows stay eligible.

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

    # Per (contract_lc, caller_addr_lc): the capabilities and claim ids the
    # caller holds across that contract's functions (the tier evidence), plus
    # two per-pair facts the gates below read. Caller keys are normalized
    # through ``_addr_of`` so composite ``<chain>::<address>`` caller tokens in
    # the detail map key identically to the bare addresses the projection
    # emits today — a keyspace mismatch must not silently disable the gates.
    #
    # *significant_on* — the caller holds at least one significant function:
    # privileged or tightly gated, the same two arms
    # :func:`assign_co_controllers` uses. A caller whose proven functions on a
    # contract are all insignificant (a broad whitelist like ``createBid``)
    # holds no governance there and must not be primary-eligible: with the
    # portfolio-count tiebreak gone, an arbitrary lex-smallest bidder would
    # otherwise win the box.
    #
    # *driver_on* — the caller can provably MAKE the contract act (a
    # timelock.schedule/execute claim, or a governing/granting capability), or
    # holds a claim-less function whose power is therefore not determined.
    # What stays out is a caller every one of whose functions is proven
    # non-driving — cancel-only vetoes, delay setters — which can block or
    # tune a mediator but never wield what it owns.
    caps_on: dict[tuple[str, str], set[str]] = {}
    claims_on: dict[tuple[str, str], set[str]] = {}
    with_rows: set[tuple[str, str]] = set()
    significant_on: set[tuple[str, str]] = set()
    driver_on: set[tuple[str, str]] = set()
    for contract_addr, functions in (fp_function_detail_by_contract or {}).items():
        c_lc = contract_addr.lower()
        for fn in functions:
            fn_claims = {c for c in fn.get("claims") or () if isinstance(c, str) and c}
            labels_lc = {(label or "").lower() for label in fn.get("labels") or ()}
            fn_caps = function_capabilities(labels_lc, fn_claims)
            callers = {_addr_of((a or "").lower()) for a in fn.get("callers", ())} - {""}
            significant = (
                _function_is_privileged(list(fn_claims), labels_lc, PRIVILEGED_EFFECT_LABELS)
                or len(callers) <= _MAX_GATE_CALLERS
            )
            drives = (
                not fn_claims  # claim-less row: driving power not determined
                or bool(fn_claims & _GOVERNING_CLAIMS)
                or bool(fn_caps & (_GOVERNING_CAPS | _GRANTING_CAPS))
            )
            for la in callers:
                caps_on.setdefault((c_lc, la), set()).update(fn_caps)
                claims_on.setdefault((c_lc, la), set()).update(fn_claims)
                with_rows.add((c_lc, la))
                if significant:
                    significant_on.add((c_lc, la))
                if drives:
                    driver_on.add((c_lc, la))

    def _tier_on(contract_lc: str, caller_token: str) -> int:
        key = (contract_lc, _addr_of(caller_token))
        return _authority_tier(caps_on.get(key, set()), claims_on.get(key, set()))

    def _has_governance_on(contract_lc: str, caller_token: str) -> bool:
        """Whether the caller's authority on the contract can anchor a primary
        claim. Requires a significant function when the caller's rows are in
        evidence; a caller with no detail rows stays eligible — absence of
        rows is not proof its authority is a broad whitelist."""
        key = (contract_lc, _addr_of(caller_token))
        return key in significant_on or key not in with_rows

    def _can_inherit_through(mediator_lc: str, caller_token: str) -> bool:
        """Whether the caller inherits the mediator's authority over what the
        mediator governs. Needs the same significance a direct primary claim
        needs (a broad whitelist on the mediator anchors nothing one hop out
        either), plus driving evidence: a proven driver function, or a
        claim-less one whose power is not determined. A caller whose every
        function on the mediator is proven non-driving (cancel-only veto,
        delay setter) can block the mediator, never act through it. No rows
        at all ⇒ legacy expansion — absence of evidence excludes nothing."""
        key = (mediator_lc, _addr_of(caller_token))
        if key not in with_rows:
            return True
        return key in significant_on and key in driver_on

    def _effective_controllers(contract_lc: str) -> dict[str, int]:
        """Terminal controllers of *contract_lc* with the best authority tier
        each holds there: direct FP callers at their own tier, and — for any
        caller that is itself a ``passthrough`` governance contract — its
        inheriting callers (see :func:`_can_inherit_through`) at the
        *mediator's* tier (the mediator is the thing acting on the contract;
        its driver wields that same authority). Depth-bounded; re-visiting
        only on a strictly better tier both breaks cycles and keeps the best
        tier across multiple governance paths."""
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

    # eligibility[principal_lc] = {contract_lc: best authority tier}. A
    # principal is eligible for a contract iff it is one of that contract's
    # effective controllers (its FP callers, resolved transitively through any
    # in-protocol governance contract in between). Contract keys and caller
    # tokens may be composite ``<chain>::<address>`` entities; principal
    # identity is the bare address, so map each caller back.
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
            # Smaller tuple wins: negate tier/priority so larger sorts earlier;
            # raw address (lex-smallest) is the final stable tiebreak. Every
            # component is a per-contract fact or a constant, so the winner
            # cannot change when unrelated contracts enter the analysis.
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
    """Rendering home for machinery contracts whose operand unit lives in
    another principal's group.

    An in-protocol contract that holds FP authority on other contracts is
    *machinery*: it acts on its operands on behalf of whoever controls it —
    a passthrough timelock executing governance calls, a Pauser fanning out
    ``pauseAll``, an L1 bridge receiver feeding one sync pool. The primary
    contest correctly assigns such a contract to its own controller, but when
    everything it operates on was won by a different principal, rendering it
    inside its controller's box separates it from the unit it exists to serve.
    This computes, per machinery contract, the operand group it belongs with.
    The placement witness is the contract's own FP rows on that group's
    members, never a name or a guess. Two arms:

    * **Any contract — unanimity.** Every operand is owned, and all by the
      same principal. One split operand (or one unowned one) is evidence the
      machinery serves more than one unit, so it stays with its controller.

    * **Passthrough mediator — strict plurality.** Timelocks / ProxyAdmins
      exist only to mediate governance, so the bar is lower: the group owning
      strictly more of its operands than any other is its home even when a
      few operands live elsewhere. A tie emits nothing.

    ``primary_for`` itself is untouched: the controller keeps the contract for
    enrollment and every authority claim, and the operand group's Controllers
    accordion lists it as a controller row (the frontend's group-controller
    fold reads ``primary_for`` as well as ``co_controls`` for exactly this
    case). Operand homes are taken from ``primary_for`` alone (never from
    other overrides), so placement is single-pass and order-independent.

    All inputs share one keyspace (bare or composite entity keys, as in
    :func:`assign_primary_controllers`). *contract_keys* is the set of
    rendered contract entities — only members of it are re-homed, so a
    principal appearing as an FP caller can never be pulled into a box.
    Returns ``{contract_key: principal_address_lc}`` only where the operand
    home differs from the contract's own primary controller.
    """
    primary_of: dict[str, str] = {}
    for paddr, owned in primary_for.items():
        for c in owned:
            primary_of[(c or "").lower()] = (paddr or "").lower()

    contract_keys_lc = {(c or "").lower() for c in contract_keys}
    passthrough_lc = {(m or "").lower() for m in governance_passthrough}

    # operand_homes[x] = {owner_addr_or_None: count} over x's operands; None
    # counts operands nobody won (they block the unanimity arm but stay out of
    # the mediator plurality, which only weighs proven homes).
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
            # Unanimous: every operand owned by the same principal.
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

# Plane-1 claims mirror of :data:`PRIVILEGED_EFFECT_LABELS` — the claim families
# whose presence on a function marks its authorized callers as real
# co-controllers: control-plane + value-flow + exec. ``callee_pointer.rotate``
# (the precise hook-pointer rotation) and external-call facts are excluded for
# the same reason the legacy set omits ``hook_update`` / ``external_contract_call``
# — they ride on permissionless callers too, so they don't discriminate.
# ``upgrade.*`` now fires (it never did as the corpus-dead ``implementation_update``
# label), so upgrade functions gain co-controller significance for the first time.
_PRIVILEGED_CLAIM_PREFIXES = (
    "ownership.",
    "roles.",
    "authority.",
    "upgrade.",
    "timelock.",
    "safe.",
    "pause.",
    "proxy.",
    "authorized_caller.",
    "lz_oapp.",
    "flow.",
    "supply.",
    "exec.",
)
_PRIVILEGED_CLAIM_IDS: frozenset[str] = frozenset({"contract_deployment"})
_EXCLUDED_CLAIM_IDS: frozenset[str] = frozenset({"callee_pointer.rotate"})


def _function_is_privileged(claims: Any, labels_lc: set[str], privileged_labels: frozenset[str]) -> bool:
    """Whether a function is a governance/admin power on its own. Plane-1 claims
    (the ``fp_function_detail`` projection's pre-extracted claim-id strings) are
    authoritative when present; a claim-less function falls back to the legacy
    effect_labels."""
    claim_ids = {c for c in claims if isinstance(c, str) and c} if isinstance(claims, list) else set()
    if claim_ids:
        return any(
            cid not in _EXCLUDED_CLAIM_IDS
            and (cid in _PRIVILEGED_CLAIM_IDS or cid.startswith(_PRIVILEGED_CLAIM_PREFIXES))
            for cid in claim_ids
        )
    return bool(labels_lc & privileged_labels)


# A function shared by more than this many distinct authorized callers reads as
# a broad whitelist (permissionless-ish), not an access-controlled governance
# gate. EtherFi's ``createBid`` is shared by ~33 callers; real admin gates
# (pause / recover / setCapacity) are held by 1–3. Anything in [3, 32] cleanly
# separates them on the observed data; 4 leaves margin for a small
# multisig + timelock + operator-EOA set sharing one gate.
_MAX_GATE_CALLERS = 4


def assign_co_controllers(
    principals: list[dict[str, Any]],
    fp_function_detail_by_contract: Mapping[str, Sequence[Mapping[str, Any]]],
    primary_for: Mapping[str, list[str]],
    *,
    max_gate_callers: int = _MAX_GATE_CALLERS,
    privileged_labels: frozenset[str] = PRIVILEGED_EFFECT_LABELS,
) -> dict[str, list[str]]:
    """Per principal, the contracts it *co-controls*: holds real authority on
    without being the canonical primary controller.

    :func:`assign_primary_controllers` names one primary per contract, so a
    legitimate co-governor that loses the contest — e.g. a pause / fund-recovery
    guardian Safe whose contracts a bigger governance Safe also wins — drops off
    both the Surface canvas and monitoring enrollment. This recovers exactly
    that set while excluding the noise the bare FP-authority signal admits:
    permissionless callers like whitelisted auction bidders.

    *fp_function_detail_by_contract* — ``{contract_addr_lc: [{"callers":
    set[addr], "labels": set[str], "claims": [claim_id, ...]}, ...]}``, one entry
    per ``EffectiveFunction`` of the contract that has at least one
    (non-``signature_witness``) FP caller. ``claims`` is optional (Plane-1); when
    present it is authoritative for the privileged-function test, with ``labels``
    the fallback for claim-less rows. Contract addresses are the *rendered*
    (proxy) addresses, matching *primary_for* and Surface group containment.

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
            labels = {(label or "").lower() for label in fn.get("labels", ())}
            significant = (
                _function_is_privileged(fn.get("claims"), labels, privileged_labels) or len(callers) <= max_gate_callers
            )
            if not significant:
                continue
            for caller in callers:
                if caller in principal_addrs and primary_of.get(c_lc) != caller:
                    co[caller].add(c_lc)

    return {addr: sorted(contracts) for addr, contracts in co.items()}
