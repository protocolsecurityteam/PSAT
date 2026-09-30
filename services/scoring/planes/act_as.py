"""The act-as plane: whether a caller can exercise a destination's authority."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from services.scoring.planes._shared import _lower
from services.scoring.schema import coalesce_chain, entity_key
from utils.scoring_status import OPENNESS_OPEN, OPENNESS_RESTRICTED

ACT_AS_WITNESSED = "witnessed"
ACT_AS_NO_CALL_SITE = "no_function_of_the_caller_calls_this_selector"
# No read was attempted; says nothing about the value.
ACT_AS_RECEIVER_NOT_READ = "caller_state_variable_never_read_on_chain"
# The read was issued and reverted: not determined, and not a reader coverage gap.
ACT_AS_RECEIVER_READ_FAILED = "caller_state_variable_read_reverted_on_chain"
ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS = "caller_state_variable_holds_a_different_address"
# Earned negatives sharper than "holds a different address": renounced to address(0), or an address proven codeless.
# Kept apart since CREATE2 can put code at an EOA's address but never at zero.
ACT_AS_RECEIVER_IS_THE_RENOUNCED_ZERO_ADDRESS = "caller_state_variable_holds_the_renounced_zero_address"
ACT_AS_RECEIVER_HOLDS_A_NON_CONTRACT = "caller_state_variable_holds_an_address_proven_to_hold_no_code"
ACT_AS_CALL_SITE_IS_PUBLIC = "the_call_site_needs_no_gate"
# The pipeline didn't determine this gate; never spelled as public.
ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED = "call_site_caller_gate_openness_is_not_determined"
ACT_AS_CALL_SITE_GATE_NOT_DELEGATED = "call_site_caller_gate_is_not_witnessed_delegated_to_an_authority"
ACT_AS_NO_DESTINATION_ACL = "destination_does_not_accept_this_caller_for_this_selector"
# Past the first hop: the caller calls the selector, but not from the function the previous hop admitted.
ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION = (
    "intermediate_calling_function_is_not_the_selector_admitted_at_the_previous_hop"
)
ACT_AS_DESTINATION_ACL_NAMES_NO_ADMITTING_ROLE = "destination_access_control_row_names_no_admitting_role"
ACT_AS_DESTINATION_ACL_NOT_ENUMERABLE = "destination_access_control_membership_is_not_enumerable"

# Which witness shape admitted a step, published on every step.
ACT_AS_WITNESS_CALLER_STATE_VARIABLE = "caller_state_variable"
ACT_AS_WITNESS_DESTINATION_ACL = "destination_access_control_list"

# A destination ACL row must enumerate the accepted set; ``lower_bound`` doesn't bound it.
_ENUMERATED_MEMBERSHIP = "exact"

# Only ``controller`` rows answer "who may invoke this function".
_ACCEPTING_PRINCIPAL_TYPE = "controller"

# An external authority decides the caller set; seizing that authority opens the function.
_DELEGATED_GUARD_METHOD = "cancall"


def _call_site_order(site: tuple[str, str, str, bool, str | None]) -> tuple[str, str, str, bool, str]:
    """Total order over call sites (``calling_selector`` may be None)."""
    return (site[0], site[1], site[2], site[3], site[4] or "")


@dataclass(frozen=True)
class DestinationAcceptance:
    """One ``function_principals`` row: D's ACL naming a caller of a selector.

    Empty ``roles`` means the row reached the caller without a role; still indexed, to separate "not named" from "named
    without an admitting role".
    """

    roles: tuple[int, ...]
    membership_quality: str
    destination_function: str
    function_principal_id: int

    @property
    def enumerated(self) -> bool:
        return self.membership_quality == _ENUMERATED_MEMBERSHIP

    @property
    def strength(self) -> tuple[bool, bool]:
        """How much acceptance the row witnesses, to pick between rows for the same caller and selector."""
        return (bool(self.roles), self.enumerated)

    def as_json(self) -> dict[str, Any]:
        return {
            "source": "function_principals",
            "function_principal_id": self.function_principal_id,
            "destination_function": self.destination_function,
            "accepting_roles": list(self.roles),
            "membership_quality": self.membership_quality,
        }


@dataclass(frozen=True)
class ActAsStep:
    """One witnessed "N can be made to call ``selector`` at D" step.

    ``calling_selector`` is the calling function's own selector (names don't identify functions: ``manage`` has
    several). ``witness_kind`` names the shape: a caller state-variable read proving the receiver holds D, or D's own
    ACL naming N for a parameter-bound receiver.
    """

    caller: str
    destination: str
    selector: str
    calling_function: str
    calling_function_openness: str
    calling_selector: str | None = None
    witness_kind: str = ACT_AS_WITNESS_CALLER_STATE_VARIABLE
    receiver_variable: str | None = None
    receiver_observed_via: str | None = None
    receiver_block: int | None = None
    acceptance: DestinationAcceptance | None = None
    # True when admitted without a delegation witness (allowed only past the first hop). A fact about the site, so a
    # delegated hop-2 step reads false.
    admitted_without_a_delegation_witness: bool = False

    def _not_delegation_tested(self) -> str:
        """Only where it applies."""
        if not self.admitted_without_a_delegation_witness:
            return ""
        return (
            f" This step is past the first hop, where the licence is the selector the previous hop "
            f"admitted rather than the seized authority pointer, so no witness that "
            f"{self.calling_function}'s own caller gate is delegated to an authority was required — "
            f"and none is claimed: this call site carries none."
        )

    def _basis(self) -> str:
        if self.witness_kind == ACT_AS_WITNESS_DESTINATION_ACL and self.acceptance is not None:
            gate = (
                f"{self.calling_function} is a restricted function of {self.caller} entered under "
                f"the selector the previous hop admitted"
                if self.admitted_without_a_delegation_witness
                else (
                    f"{self.calling_function} is a restricted function of {self.caller} whose caller "
                    f"gate is witnessed delegated to an authority"
                )
            )
            return (
                f"{gate}, and whose body calls "
                f"{self.selector} at an address the CALLER of that function supplies — the "
                f"receiver is parameter-bound, so no state variable of {self.caller} names it. "
                f"{self.destination}'s own access-control list is what names the address from the "
                f"other end: function_principals row {self.acceptance.function_principal_id} on "
                f"{self.acceptance.destination_function} accepts {self.caller} as a caller of "
                f"{self.selector} by role(s) {list(self.acceptance.roles)}, with "
                f"membership_quality '{self.acceptance.membership_quality}'" + self._not_delegation_tested()
            )
        return (
            f"{self.calling_function} is a restricted function of {self.caller} whose body "
            f"calls {self.selector} on its own state variable '{self.receiver_variable}', and "
            f"'{self.receiver_variable}' was read {self.receiver_observed_via} at block "
            f"{self.receiver_block} holding {self.destination}" + self._not_delegation_tested()
        )

    def as_json(self) -> dict[str, Any]:
        return {
            "caller": self.caller,
            "destination": self.destination,
            "selector": self.selector,
            "calling_function": self.calling_function,
            "calling_function_openness": self.calling_function_openness,
            "calling_selector": self.calling_selector,
            "witness_kind": self.witness_kind,
            "receiver_variable": self.receiver_variable,
            "receiver_observed_via": self.receiver_observed_via,
            "receiver_block": self.receiver_block,
            "destination_acceptance": (self.acceptance.as_json() if self.acceptance is not None else None),
            "admitted_without_a_delegation_witness": self.admitted_without_a_delegation_witness,
            "basis": self._basis(),
        }


@dataclass(frozen=True)
class ActAsVerdict:
    """The answer, plus the ``resolved_type`` read when the refusal is about what a receiver holds."""

    outcome: str
    step: ActAsStep | None = None
    receiver_resolved_type: str | None = None

    @property
    def witnessed(self) -> bool:
        return self.outcome == ACT_AS_WITNESSED


_READ_OBSERVATIONS = frozenset({"eth_call", "eth_call_impl_fallback", "beacon_owner", "event_log"})
# Issued and failed: no address, so no receiver test, but an attempt.
_READ_FAILURE_OBSERVATIONS = frozenset({"eth_call_error"})

# ``zero`` (renounced) and ``eoa`` (proven codeless via empty ``eth_getCode``) carry facts beyond the address; other
# classifications don't affect the receiver test.
_RESOLVED_RENOUNCED = "zero"
_RESOLVED_CODELESS = "eoa"

# The only value witnessing a gate; everything but ``open`` is the third state.
_OPENNESS_RESTRICTED = OPENNESS_RESTRICTED
_OPENNESS_PUBLIC = OPENNESS_OPEN


@dataclass
class ActAsPlane:
    """Whether seizing a node's gate witnesses making that node act elsewhere.

    Membership in a gate's set answers "may N call ``s`` at D", not "can the principal make N do it". Seizing an
    authority pointer on N only buys a call at D if one of N's restricted functions is witnessed calling D.

    A call site from N's compiled source is always required. The address it lands on is witnessed by either a
    ``controller_values`` read of the bound state variable holding D (the address comparison decides; ``zero``/``eoa``
    sharpen the negative; failed reads are not determined), or, for a parameter-bound receiver, D's own ACL naming N by
    an enumerated role with ``exact`` membership. With neither, the step is refused: a plausible path isn't a witnessed
    one. The ACL shape is a magnitude admission only: never used by the closure walk, and silent on D's business
    preconditions.

    The calling function must be ``restricted`` and, at the first hop, delegated (a ``canCall`` guard):
    ``receiveFlashLoan`` is restricted but gated by ``msg.sender == balancerVault``, which seizing authority doesn't
    open. Past hop 1 the principal arrives as whoever the previous hop admitted, so delegation isn't required. Public
    call sites are refused at every hop (their value belongs to their own finding); undetermined openness has its own
    refusal.

    Unwitnessed: that the guard's ``canCall`` authority is the one the finding seizes; ``GateGrant``'s same-kind bound
    stands in.
    """

    # (caller, selector) -> ((calling function, openness, receiver variable, delegated, calling selector), ...)
    call_sites: dict[tuple[str, str], tuple[tuple[str, str, str, bool, str | None], ...]] = field(default_factory=dict)
    # (caller, state variable) -> (address held, observed_via, block)
    reads: dict[tuple[str, str], tuple[str, str, int | None]] = field(default_factory=dict)
    # resolved_type per read, kept apart so the test reads addresses, not labels. Absent is a third state.
    read_kinds: dict[tuple[str, str], str] = field(default_factory=dict)
    # (caller, state variable) -> (observed_via, block) for issued reads that failed.
    read_failures: dict[tuple[str, str], tuple[str, int | None]] = field(default_factory=dict)
    # (destination, selector) -> {caller: accepting ACL row}
    destination_acl: dict[tuple[str, str], dict[str, DestinationAcceptance]] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def acts_as(
        self, caller: str, destination: str, selector: str, *, via: frozenset[str] | None = None
    ) -> ActAsVerdict:
        """Whether ``caller`` can be made to call ``selector`` at ``destination``, optionally only from functions
        whose selectors are in ``via`` (a set: a node may be admitted under several). ``via=None`` is the first
        hop, which is what keys the delegation conjunct.
        """
        token = _lower(selector)
        sites = self.call_sites.get((caller, token))
        if not sites:
            return ActAsVerdict(ACT_AS_NO_CALL_SITE)
        if via is not None:
            admitted = frozenset(_lower(entry) for entry in via)
            # Unextracted selectors match nothing.
            sites = tuple(site for site in sites if site[4] is not None and site[4] in admitted)
            if not sites:
                return ActAsVerdict(ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION)
        # The sharpest shortfall reported, with the resolved type where relevant; first site in order wins ties.
        outcome: str | None = None
        held_types: dict[str, str] = {}

        def refuse(reason: str | None) -> ActAsVerdict:
            if reason is None:
                # Every site reports; arriving here is a broken invariant, not an answer.
                raise AssertionError(f"act_as refusal with no reported shortfall: {caller} -> {destination}.{token}")
            return ActAsVerdict(reason, receiver_resolved_type=held_types.get(reason))

        for name, openness, variable, delegated, calling_selector in sites:
            if not variable:
                continue
            read = self.reads.get((caller, variable))
            if read is None:
                attempted = (caller, variable) in self.read_failures
                outcome = _rank_outcome(outcome, ACT_AS_RECEIVER_READ_FAILED if attempted else ACT_AS_RECEIVER_NOT_READ)
                continue
            held, observed_via, block = read
            kind = self.read_kinds.get((caller, variable))
            if held != destination:
                if kind == _RESOLVED_RENOUNCED:
                    shortfall = ACT_AS_RECEIVER_IS_THE_RENOUNCED_ZERO_ADDRESS
                elif kind == _RESOLVED_CODELESS:
                    shortfall = ACT_AS_RECEIVER_HOLDS_A_NON_CONTRACT
                else:
                    shortfall = ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS
                held_types.setdefault(shortfall, kind or "not_determined")
                outcome = _rank_outcome(outcome, shortfall)
                continue
            # The read holds D; its label isn't consulted.
            gate = self._gate_shortfall(openness, delegated, via=via)
            if gate is not None:
                outcome = _rank_outcome(outcome, gate)
                continue
            return ActAsVerdict(
                ACT_AS_WITNESSED,
                ActAsStep(
                    caller=caller,
                    destination=destination,
                    selector=token,
                    calling_function=name,
                    calling_function_openness=openness,
                    calling_selector=calling_selector,
                    witness_kind=ACT_AS_WITNESS_CALLER_STATE_VARIABLE,
                    receiver_variable=variable,
                    receiver_observed_via=observed_via,
                    receiver_block=block,
                    admitted_without_a_delegation_witness=via is not None and not delegated,
                ),
            )
        # No state variable names D: parameter-bound sites with D's ACL naming this caller. Sorted for determinism. Gate
        # conjuncts aren't filtered here, or the gate failure would be misreported as a receiver problem.
        parameter_bound = sorted((site for site in sites if not site[2]), key=_call_site_order)
        if not parameter_bound:
            return refuse(outcome)
        # Acceptance is the same for every call site, so it is checked once.
        accepted = self.destination_acl.get((destination, token), {}).get(caller)
        if accepted is None:
            return refuse(_rank_outcome(outcome, ACT_AS_NO_DESTINATION_ACL))
        if not accepted.roles:
            return refuse(_rank_outcome(outcome, ACT_AS_DESTINATION_ACL_NAMES_NO_ADMITTING_ROLE))
        if not accepted.enumerated:
            return refuse(_rank_outcome(outcome, ACT_AS_DESTINATION_ACL_NOT_ENUMERABLE))
        for name, openness, _variable, delegated, calling_selector in parameter_bound:
            gate = self._gate_shortfall(openness, delegated, via=via)
            if gate is not None:
                outcome = _rank_outcome(outcome, gate)
                continue
            return ActAsVerdict(
                ACT_AS_WITNESSED,
                ActAsStep(
                    caller=caller,
                    destination=destination,
                    selector=token,
                    calling_function=name,
                    calling_function_openness=openness,
                    calling_selector=calling_selector,
                    witness_kind=ACT_AS_WITNESS_DESTINATION_ACL,
                    acceptance=accepted,
                    admitted_without_a_delegation_witness=via is not None and not delegated,
                ),
            )
        return refuse(outcome)

    @staticmethod
    def _gate_shortfall(openness: str, delegated: bool, *, via: frozenset[str] | None) -> str | None:
        """Which gate conjunct this site fails at this hop, or ``None``.

        Openness is three-valued (open, restricted, undetermined). Delegation is required only at the first hop, where
        the principal's leverage is the seized pointer.
        """
        if openness == _OPENNESS_PUBLIC:
            return ACT_AS_CALL_SITE_IS_PUBLIC
        if openness != _OPENNESS_RESTRICTED:
            return ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED
        if via is None and not delegated:
            return ACT_AS_CALL_SITE_GATE_NOT_DELEGATED
        return None


# How far a site got before refusal, lower is further, so the sharpest shortfall is reported: proven-absent receivers
# (they answer the question), then gate reasons, then destination-ACL reasons, then read reasons. Every outcome
# ``acts_as`` can rank must be here.
_ACT_AS_RANK = {
    ACT_AS_RECEIVER_IS_THE_RENOUNCED_ZERO_ADDRESS: 0,
    ACT_AS_RECEIVER_HOLDS_A_NON_CONTRACT: 1,
    ACT_AS_CALL_SITE_GATE_NOT_DELEGATED: 2,
    ACT_AS_CALL_SITE_IS_PUBLIC: 3,
    ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED: 4,
    ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS: 5,
    ACT_AS_RECEIVER_READ_FAILED: 6,
    ACT_AS_RECEIVER_NOT_READ: 7,
    ACT_AS_DESTINATION_ACL_NOT_ENUMERABLE: 8,
    ACT_AS_DESTINATION_ACL_NAMES_NO_ADMITTING_ROLE: 9,
    ACT_AS_NO_DESTINATION_ACL: 10,
    # Sites existed but ``via`` excluded all.
    ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION: 11,
    ACT_AS_NO_CALL_SITE: 12,
}


def _rank_outcome(current: str | None, candidate: str) -> str:
    """The first reported candidate wins outright."""
    if current is None:
        return candidate
    return candidate if _ACT_AS_RANK[candidate] < _ACT_AS_RANK[current] else current


def load_act_as_plane(session: Session, protocol_id: int) -> ActAsPlane:
    """Call-site, receiver and destination-acceptance witnesses, indexed for the composition walk."""
    from db.models import Contract, ControllerValue, EffectiveFunction, FunctionPrincipal

    call_sites: dict[tuple[str, str], list[tuple[str, str, str, bool, str | None]]] = defaultdict(list)
    sinks_read = external_calls = selector_bearing = state_variable_bound = delegated_gates = 0
    call_sites_naming_their_own_selector = 0
    functions = (
        session.query(
            EffectiveFunction.function_name,
            EffectiveFunction.authority_openness,
            EffectiveFunction.sinks,
            EffectiveFunction.selector,
            EffectiveFunction.deployment_address,
            Contract.address,
            Contract.chain,
        )
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(EffectiveFunction.id)
        .all()
    )
    for name, openness, sinks, own_selector, deployment, address, chain in functions:
        if not isinstance(sinks, list):
            # NULL means effects didn't run, not that nothing is called.
            continue
        sinks_read += 1
        key = entity_key(coalesce_chain(chain), deployment or address)
        delegated = any(
            isinstance(sink, dict)
            and sink.get("origin") == "guard"
            and _lower(str(sink.get("target") or "")).rsplit(".", 1)[-1] == _DELEGATED_GUARD_METHOD
            for sink in sinks
        )
        delegated_gates += 1 if delegated else 0
        # Fallback/receive name no selector.
        calling_selector = _lower(str(own_selector)) if own_selector else None
        if calling_selector is not None and not calling_selector.startswith("0x"):
            calling_selector = None
        for sink in sinks:
            if not isinstance(sink, dict) or sink.get("kind") != "external_call":
                continue
            external_calls += 1
            selector = _lower(str(sink.get("selector") or ""))
            if not selector.startswith("0x"):
                continue
            selector_bearing += 1
            receiver = sink.get("receiver") if isinstance(sink.get("receiver"), dict) else {}
            variable = ""
            if (receiver or {}).get("binding") == "state_variable":
                variable = str((receiver or {}).get("variable") or "")
                if variable:
                    state_variable_bound += 1
            call_sites_naming_their_own_selector += 1 if calling_selector is not None else 0
            call_sites[(key, selector)].append(
                (str(name), str(openness or "not_determined"), variable, delegated, calling_selector)
            )

    reads: dict[tuple[str, str], tuple[str, str, int | None]] = {}
    read_kinds: dict[tuple[str, str], str] = {}
    read_failures: dict[tuple[str, str], tuple[str, int | None]] = {}
    resolved_type_histogram: dict[str, int] = defaultdict(int)
    ambiguous: set[tuple[str, str]] = set()
    rows = (
        session.query(
            ControllerValue.source,
            ControllerValue.value,
            ControllerValue.resolved_type,
            ControllerValue.observed_via,
            ControllerValue.block_number,
            ControllerValue.deployment_address,
            Contract.address,
            Contract.chain,
        )
        .join(Contract, Contract.id == ControllerValue.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(ControllerValue.id)
        .all()
    )
    for source, value, resolved_type, observed_via, block, deployment, address, chain in rows:
        if not source:
            continue
        key = (entity_key(coalesce_chain(chain), deployment or address), str(source))
        if observed_via in _READ_FAILURE_OBSERVATIONS:
            read_failures.setdefault(key, (str(observed_via), int(block) if block is not None else None))
            continue
        if observed_via not in _READ_OBSERVATIONS:
            continue
        held = _lower(str(value or ""))
        if not held.startswith("0x"):
            continue
        # Indexed regardless of the row's label; the test is the address comparison.
        kind = str(resolved_type) if resolved_type else ""
        resolved_type_histogram[kind or "not_determined"] += 1
        held_key = entity_key(coalesce_chain(chain), held)
        previous = reads.get(key)
        if previous is not None and previous[0] != held_key:
            # Disagreeing reads: the variable resolves to nothing.
            ambiguous.add(key)
            continue
        reads.setdefault(key, (held_key, str(observed_via), int(block) if block is not None else None))
        if kind:
            read_kinds.setdefault(key, kind)
    for key in ambiguous:
        reads.pop(key, None)
        read_kinds.pop(key, None)
        # Drop the failure too, so disagreement doesn't publish the sharper "read reverted" reason.
        read_failures.pop(key, None)

    destination_acl: dict[tuple[str, str], dict[str, DestinationAcceptance]] = defaultdict(dict)
    acl_rows_keyed = acl_rows_naming_a_role = 0
    quality_histogram: dict[str, int] = defaultdict(int)
    acl_rows = (
        session.query(
            FunctionPrincipal.id,
            FunctionPrincipal.address,
            FunctionPrincipal.details,
            EffectiveFunction.selector,
            EffectiveFunction.function_name,
            EffectiveFunction.deployment_address,
            Contract.address,
            Contract.chain,
        )
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .filter(FunctionPrincipal.principal_type == _ACCEPTING_PRINCIPAL_TYPE)
        .order_by(FunctionPrincipal.id)
        .all()
    )
    for row_id, principal, details, selector, function_name, deployment, address, chain in acl_rows:
        token = _lower(str(selector or ""))
        holder = _lower(str(principal or ""))
        if not token.startswith("0x") or not holder.startswith("0x") or not isinstance(details, dict):
            continue
        acl_rows_keyed += 1
        roles: set[int] = set()
        trace = details.get("trace")
        if isinstance(trace, list):
            for step in trace:
                if not isinstance(step, dict):
                    continue
                named = step.get("roles")
                if isinstance(named, list):
                    roles.update(role for role in named if isinstance(role, int) and not isinstance(role, bool))
        if roles:
            acl_rows_naming_a_role += 1
        quality = str(details.get("membership_quality") or "not_determined")
        quality_histogram[quality] += 1
        chain_key = coalesce_chain(chain)
        accepting = DestinationAcceptance(
            roles=tuple(sorted(roles)),
            membership_quality=quality,
            destination_function=str(function_name),
            function_principal_id=int(row_id),
        )
        # An ACL belongs to one deployment on one chain.
        bucket = destination_acl[(entity_key(chain_key, deployment or address), token)]
        previous = bucket.get(entity_key(chain_key, holder))
        # Keep the row witnessing the most.
        if previous is None or accepting.strength > previous.strength:
            bucket[entity_key(chain_key, holder)] = accepting

    plane = ActAsPlane(
        call_sites={key: tuple(sorted(set(rows), key=_call_site_order)) for key, rows in sorted(call_sites.items())},
        reads=reads,
        read_kinds=read_kinds,
        read_failures=read_failures,
        destination_acl={key: dict(sorted(callers.items())) for key, callers in sorted(destination_acl.items())},
    )
    plane.provenance = {
        "call_sites": {
            "functions_with_sinks_extracted": sinks_read,
            "functions": len(functions),
            "external_call_sinks": external_calls,
            "sinks_naming_a_selector": selector_bearing,
            "sinks_whose_receiver_is_a_state_variable": state_variable_bound,
            "functions_whose_caller_gate_is_delegated_to_an_authority": delegated_gates,
            "call_sites_naming_their_own_selector": call_sites_naming_their_own_selector,
        },
        "receiver_reads": {
            # Every variable read to an address; the histogram counts rows, so they don't sum.
            "state_variables_read_on_chain": len(reads),
            "state_variables_whose_read_failed": len(read_failures),
            "resolved_type_of_each_read_row": dict(sorted(resolved_type_histogram.items())),
            "variables_two_reads_disagree_under": len(ambiguous),
            "observations_admitted": sorted(_READ_OBSERVATIONS),
            "observations_recorded_as_a_failed_read": sorted(_READ_FAILURE_OBSERVATIONS),
        },
        "destination_acceptance": {
            "function_principal_rows_returned": len(acl_rows),
            "rows_naming_a_selector_and_a_caller_address": acl_rows_keyed,
            "rows_naming_an_admitting_role": acl_rows_naming_a_role,
            "destination_selectors_with_an_indexed_caller": len(destination_acl),
            "indexed_callers": sum(len(callers) for callers in destination_acl.values()),
            "membership_quality": dict(sorted(quality_histogram.items())),
            "principal_type_read": _ACCEPTING_PRINCIPAL_TYPE,
            "membership_quality_admitted": _ENUMERATED_MEMBERSHIP,
        },
        "reading": (
            "the witnesses a composed magnitude needs on top of a licence. The CALL SITE is "
            "always required (effective_functions.sinks, an external_call carrying the called "
            "selector and the receiver it binds to, compiled from the caller's own source). "
            "What names the ADDRESS it lands on has two shapes and either witnesses the step: "
            "the RECEIVER (controller_values, an on-chain read at a recorded block, compared "
            "against the destination address) — the READ and the comparison are the witness, and "
            "controller_values.resolved_type is context, not a filter: a pointer classified "
            "'safe' or 'timelock' that holds the destination witnesses the step exactly as a "
            "'contract' one does, because what the pointer holds is the question and what the "
            "row calls it is not. Where the address read is NOT the destination the "
            "classification sharpens the earned negative into one of three: "
            "caller_state_variable_holds_the_renounced_zero_address (the pointer is renounced, "
            "and address(0) holds no code and never can), "
            "caller_state_variable_holds_an_address_proven_to_hold_no_code (an empty "
            "eth_getCode, which an RPC failure does not produce), and otherwise "
            "caller_state_variable_holds_a_different_address. A read that was ISSUED AND "
            "REVERTED is none of those: it is indexed apart as "
            "caller_state_variable_read_reverted_on_chain, a not_determined, and is never "
            "published as caller_state_variable_never_read_on_chain — the row exists, with an "
            "observation kind and a block, and calling it a read that never happened asserts a "
            "coverage gap the evidence disproves. The second shape is — when the receiver is "
            "bound to a "
            "parameter, a local or an unresolved head, where no storage of the caller CAN name "
            "it because the callee is chosen at call time — the DESTINATION'S OWN ACL "
            "(function_principals, a principal_type='controller' row naming this caller as an "
            "accepted caller of that selector by an enumerated role). The second shape is "
            "admitted only on a row whose trace names at least one role, only where "
            "membership_quality is 'exact', and "
            "only for MAGNITUDE: it is never read into reach, and it does not witness that the "
            "call succeeds — the same row carries the destination's own preconditions and none "
            "of them are consulted. UNDER BOTH SHAPES the call site's own caller gate is tested, "
            "and its three states are published as three reasons: authority_openness 'restricted' "
            "passes, 'open' is refused as the_call_site_needs_no_gate — a proven-absent gate, and "
            "the refusal is ATTRIBUTION rather than caution, since a function anyone can call "
            "moves value that no seized gate conferred and that belongs to that function's own "
            "finding — and anything else, not_determined included, is refused as "
            "call_site_caller_gate_openness_is_not_determined, never collapsed into either: a "
            "gate the pipeline did not read is not a gate proven absent. The gate reasons and the "
            "destination-ACL reasons are ranked, not merged, so a parameter-bound site reports "
            "the conjunct that actually failed rather than the fact that its receiver is "
            "parameter-bound — which is the PRECONDITION for this shape and never a shortfall of "
            "it. Each shortfall is published as its own reason rather than "
            "collapsed into one: no row naming this caller at all is "
            "destination_does_not_accept_this_caller_for_this_selector; a row that names the "
            "caller but expresses no role that admits it is "
            "destination_access_control_row_names_no_admitting_role — the destination's list "
            "reached this caller by a route it did not state as a role, which is not the same "
            "fact as the list not naming it; and a row that names a role without bounding the "
            "accepted set is destination_access_control_membership_is_not_enumerable, because "
            "naming some accepted callers is not the same fact as bounding which they are. "
            "A composition walk past its first hop additionally constrains the question to "
            "the functions of the caller a previous hop admitted, matched on the calling "
            "function's OWN selector because a function name does not identify a function; "
            "a caller with no call site under any admitted function is refused as "
            "intermediate_calling_function_is_not_the_selector_admitted_at_the_previous_hop "
            "rather than answered from a site that constraint excludes. That admitted selector "
            "is also what REPLACES the delegation conjunct past the first hop: the calling "
            "function's gate must be witnessed delegated to an authority at hop 1, where the "
            "principal's leverage IS the seized authority pointer and only a delegated gate is "
            "opened by seizing it, and it is NOT required past hop 1, where the principal has "
            "seized nothing on the intermediate and arrives as whoever the previous hop admitted "
            "— an intermediate gated by a direct msg.sender check is exactly the shape such a "
            "chain runs through, and refusing it would discard a witnessed path over a mechanism "
            "the principal is not using. A step admitted with no delegation witness carries "
            "admitted_without_a_delegation_witness: true and says so in its basis. The field is "
            "a fact about the SITE and not about the hop: false on a step past the first hop "
            "means the requirement was lifted there and that call site carries the delegation "
            "witness anyway — a different fact from a step let through without one, and "
            "published as one. The "
            "openness conjunct is NOT relaxed with it and applies at every hop, for the "
            "attribution reason above and not because it is conservative. "
            "THE RESIDUAL THIS PLANE DOES NOT CLOSE: the calling function's guard is witnessed "
            "consulting AN authority (a canCall call), never that it is the same authority the "
            "finding's gate seizes — the guard's receiver is a local and no read pins it. The "
            "same-kind GateGrant bound stands in for it, and a bound is not a witness. THIS "
            "PLANE DOES NOT MEASURE HOW WIDE THAT GAP IS: it counts no contracts by how many "
            "authority-kind state variables they carry, and it does not ask which variable a "
            "given guard reads, so nothing published here rules out a second candidate. On a "
            "contract carrying two, the bound is doing work a witness should — and no field of "
            "this document says whether that happened"
        ),
    }
    return plane
