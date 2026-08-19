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
# No read of this variable was ever recorded: the reader never attempted it.
# Says nothing about what the variable holds, and must never be published for a
# variable whose read was attempted — that is a different fact, below.
ACT_AS_RECEIVER_NOT_READ = "caller_state_variable_never_read_on_chain"
# The read was ISSUED and reverted. A not_determined, distinct from both
# proven-absent and from "never read": the row exists, with an observation kind
# and a block, and calling that a coverage gap of the reader misstates it.
ACT_AS_RECEIVER_READ_FAILED = "caller_state_variable_read_reverted_on_chain"
ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS = "caller_state_variable_holds_a_different_address"
# Two earned negatives the plain address comparison would publish as the weaker
# "holds a different address". The pointer is renounced (address(0), which holds
# no code and never can), or it holds an address proven codeless by an empty
# eth_getCode. Kept apart: an EOA can become a contract at the same address via
# CREATE2, and the zero address cannot, so they are not the same proof.
ACT_AS_RECEIVER_IS_THE_RENOUNCED_ZERO_ADDRESS = "caller_state_variable_holds_the_renounced_zero_address"
ACT_AS_RECEIVER_HOLDS_A_NON_CONTRACT = "caller_state_variable_holds_an_address_proven_to_hold_no_code"
ACT_AS_CALL_SITE_IS_PUBLIC = "the_call_site_needs_no_gate"
# The third state of the openness field, and never spelled as either of the
# other two: the pipeline did not determine this function's gate. Publishing it
# as ACT_AS_CALL_SITE_IS_PUBLIC would mint the positive claim "this function
# needs no gate" out of a field nobody read.
ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED = "call_site_caller_gate_openness_is_not_determined"
ACT_AS_CALL_SITE_GATE_NOT_DELEGATED = "call_site_caller_gate_is_not_witnessed_delegated_to_an_authority"
ACT_AS_NO_DESTINATION_ACL = "destination_does_not_accept_this_caller_for_this_selector"
# Asked only by a composition walk past its first hop, which constrains the
# question to "…entering this caller through the function the previous hop
# admitted". The caller does call the selector; it does not call it from that
# function, so nothing witnesses the principal can cause this call.
ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION = (
    "intermediate_calling_function_is_not_the_selector_admitted_at_the_previous_hop"
)
ACT_AS_DESTINATION_ACL_NAMES_NO_ADMITTING_ROLE = "destination_access_control_row_names_no_admitting_role"
ACT_AS_DESTINATION_ACL_NOT_ENUMERABLE = "destination_access_control_membership_is_not_enumerable"

# Which of the two witness shapes admitted a step. Published on every step so a
# reader is never left to infer from the basis sentence which evidence was read.
ACT_AS_WITNESS_CALLER_STATE_VARIABLE = "caller_state_variable"
ACT_AS_WITNESS_DESTINATION_ACL = "destination_access_control_list"

# The membership quality a destination-side ACL row must carry to witness
# acceptance: the resolver enumerated the accepted set. A ``lower_bound`` row
# names SOME accepted callers and does not bound the set, so it cannot witness
# that this caller's presence is the whole answer.
_ENUMERATED_MEMBERSHIP = "exact"

# The only principal kind whose acceptance of a caller is an ACL fact: a
# ``controller`` row is the resolver's answer to "who may invoke this function".
# The other kinds answer a different question and are not read here.
_ACCEPTING_PRINCIPAL_TYPE = "controller"

# The method a guard calls when a function's caller set is decided by an
# external authority contract rather than by the function's own code. 748 guard
# sinks on the reference corpus carry it; it is the witness that seizing that
# authority is what opens the function.
_DELEGATED_GUARD_METHOD = "cancall"


def _call_site_order(site: tuple[str, str, str, bool, str | None]) -> tuple[str, str, str, bool, str]:
    """A total order over call sites. ``calling_selector`` is nullable, and
    ordering tuples that mix ``None`` and ``str`` at one position raises."""
    return (site[0], site[1], site[2], site[3], site[4] or "")


@dataclass(frozen=True)
class DestinationAcceptance:
    """One ``function_principals`` row: D's own ACL naming a caller of a selector.

    ``roles`` are the role numbers the resolver walked to reach the caller, and
    is EMPTY when the row reached the caller by some route it did not express as
    a role. Such a row is still indexed: it is the difference between "the
    destination's list does not name this caller" and "it names it, and names no
    role that admits it", and a reader is owed which of the two was found.
    ``membership_quality`` is whether the resolver enumerated the accepted set or
    only bounded it below. ``function_principal_id`` names the row so the
    published basis points at the evidence rather than restating it.
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
        """How much of the acceptance this row witnesses, for picking between
        two rows that name the same caller at the same selector."""
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

    Every field names a witness, not an inference. ``calling_function`` is the
    function of N whose compiled body carries the call site, and
    ``calling_selector`` is THAT function's own selector — the join key a
    multi-hop walk needs, because a function NAME does not identify a function:
    32 ``(entity, name)`` pairs on the reference corpus carry more than one
    selector, ``manage`` at the BoringVaults among them. ``None`` is a function
    whose selector was never extracted, and it matches nothing. ``witness_kind``
    says which of the two admissible shapes proved the step lands at D, and the
    fields of the other shape are ``None``: for
    ``ACT_AS_WITNESS_CALLER_STATE_VARIABLE`` the ``receiver_*`` fields are the
    state variable the receiver binds to and the on-chain read that proved it
    holds D; for ``ACT_AS_WITNESS_DESTINATION_ACL`` the receiver is
    parameter-bound — nothing in N's storage names D, and ``acceptance`` is D's
    own access-control row naming N.
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
    # A fact about this SITE, not about its hop: true exactly when the step was
    # admitted and its calling function carries no delegation witness, which only
    # the hops past the first permit. FALSE means the witness IS present, whether
    # or not this hop required it — so the stored fact is recoverable from the
    # published one at every hop, and a hop-2 step that happens to be delegated
    # is never published as a step that was let through without one. Named for
    # the site because a hop-shaped name ("not required at this hop") would read
    # as false on exactly those steps: the requirement was lifted there and the
    # witness was present anyway, and one field cannot say both.
    admitted_without_a_delegation_witness: bool = False

    def _not_delegation_tested(self) -> str:
        """Named on the basis only where it applies, so no step that carries the
        delegation witness acquires a sentence about not having one."""
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
    """The answer, and — where the answer is an earned negative about what a
    receiver holds — the ``resolved_type`` of the address that was read, so the
    refusal carries WHAT it held and not only that it was something else."""

    outcome: str
    step: ActAsStep | None = None
    receiver_resolved_type: str | None = None

    @property
    def witnessed(self) -> bool:
        return self.outcome == ACT_AS_WITNESSED


# An on-chain read of the caller's own storage that RETURNED an address.
_READ_OBSERVATIONS = frozenset({"eth_call", "eth_call_impl_fallback", "beacon_owner", "event_log"})
# A read that was issued and FAILED. Indexed separately and never as a read: it
# carries no address, so it can satisfy no receiver test — but it is a record of
# an attempt, which is not the same fact as no attempt.
_READ_FAILURE_OBSERVATIONS = frozenset({"eth_call_error"})

# The two ``controller_values.resolved_type`` classifications that carry a fact
# BEYOND the address itself. ``zero`` is the renounced pointer; ``eoa`` is an
# address proven codeless by an empty ``eth_getCode`` (an RPC failure classifies
# as ``contract`` and is not cached, so this is an earned witness). Every other
# value — ``contract``, ``safe``, ``timelock``, ``unknown``, NULL — is a
# classification of an address the row already carries, and the receiver test
# reads the address.
_RESOLVED_RENOUNCED = "zero"
_RESOLVED_CODELESS = "eoa"

# ``effective_functions.authority_openness``: the only value that witnesses a
# gate, and the value that witnesses its proven absence. Everything else is the
# third state.
_OPENNESS_RESTRICTED = OPENNESS_RESTRICTED
_OPENNESS_PUBLIC = OPENNESS_OPEN


@dataclass
class ActAsPlane:
    """Whether seizing a node's gate witnesses making that node ACT somewhere.

    Membership in a gate's licensed set answers "may N call ``s`` at D". It does
    not answer "can the principal make N do it" — the question a composed
    magnitude turns on. Seizing an authority POINTER on N buys the ability to
    call N's own restricted functions; it buys a call at D only if one of those
    functions is witnessed calling D. Pricing the hop on the licence alone is
    the membership-as-capability error one level up from the sheet-as-reach one.

    The CALL SITE is always required — ``effective_functions.sinks``, an
    ``external_call`` entry carrying the called ``selector`` and the receiver it
    is bound to, compiled from N's own verified source. What names the ADDRESS
    that call site lands on has two admissible shapes, and a step is witnessed
    under either:

    * the CALLER'S RECEIVER — ``controller_values``, the on-chain read
      (``eth_call`` at a recorded block) of the state variable that receiver is
      bound to. The row says N's ``vault`` IS D. The WITNESS is the read and the
      address comparison; ``resolved_type`` is a classification of the address
      the row already carries, and admission does not branch on it — a pointer
      classified ``safe`` or ``timelock`` that holds D witnesses the step, and
      refusing it would discard a read on the strength of a label. Where the
      address is NOT D the classification sharpens the earned negative: ``zero``
      is a renounced pointer and ``eoa`` an address proven codeless, each
      published under its own reason rather than as "holds a different address".
      A read that was ISSUED AND FAILED is indexed apart from both and satisfies
      nothing: it is a not_determined, and publishing it as "never read on
      chain" would assert a coverage gap of the reader that the row disproves.
    * the DESTINATION'S ACL — ``function_principals``, D's own resolved
      access-control list naming N as an accepted caller of that selector by an
      enumerated role. This is the only shape available when the receiver is a
      PARAMETER: the callee is chosen at call time, so the binding cannot live
      in N's storage, and D's own list of accepted callers is what bounds which
      choices D honours. It is admitted only when the row names a role AND the
      membership is ``exact`` — a row naming no role reached N by a route it did
      not state, and a ``lower_bound`` membership names some accepted callers
      without bounding the set. Each is refused under its own reason, because
      "the list does not name N", "it names N and no role that admits it" and
      "it names a role and does not bound the set" are three different findings
      and collapsing them publishes one of them as the others.

    A parameter-bound call site with NEITHER witness is REFUSED, not credited:
    whoever calls N chooses that address and no evidence at either end names it,
    so the code witnesses a call at an address nobody named. It is a plausible
    path and it is not a witnessed one, and the difference is the whole
    discipline.

    The destination-ACL shape is a MAGNITUDE admission only. It says D accepts a
    call from N; it says nothing about which entities the principal reaches, and
    it is never consulted by the closure walk. It also does not witness that the
    call SUCCEEDS: the same ``function_principals`` row carries D's own business
    preconditions and this plane consults none of them.

    The calling function must itself be ``restricted`` AND its caller gate must
    be witnessed DELEGATED — a guard-origin sink calling ``canCall`` on an
    authority contract. Restricted alone is not enough and the corpus proves it:
    ``ManagerWithMerkleVerification.receiveFlashLoan`` is restricted, calls
    ``vault.manage``, and is gated by ``msg.sender == balancerVault`` — its
    ``authority_roles`` is the proven-empty ``[]`` and it carries no ``canCall``
    guard. Seizing the manager's authority pointer opens
    ``manageVaultWithMerkleVerification`` and does not open that one, and without
    the guard witness the two are indistinguishable. That conjunct is required at
    the FIRST hop and only there: past it the principal has seized nothing on the
    intermediate and arrives as whoever the previous hop admitted, the via rule
    has already pinned the intermediate's calling function to that admitted
    selector, and an intermediate gated by a direct ``msg.sender ==`` check is
    exactly the shape such a chain runs through — so past hop 1 the delegation
    test asks after a mechanism the principal is not using, and refusing on it
    would discard a witnessed path.

    A public call site is refused at EVERY hop, and not because the rule is
    conservative: an open function is one anyone can call, so the value it moves
    is not conferred by the seized gate and belongs to that function's own
    finding. That is attribution, not caution, and it is the same attribution at
    hop k as at hop 1. An openness the pipeline did NOT determine is neither of
    those two facts and carries its own refusal — a gate nobody read is not a
    gate proven absent.

    What this plane still does NOT witness is that the authority the guard
    consults is the same one the finding's gate seizes: the ``canCall`` receiver
    is a local, and no read pins it. The same-kind bound (``GateGrant``) is what
    stands in for it, and it is a bound, not a witness — recorded here so the
    residual is visible where the composition is built rather than only in a
    review note.
    """

    # (caller entity, selector) -> ((calling function, openness, receiver variable,
    # whether that function's caller gate is delegated to an authority), ...)
    call_sites: dict[tuple[str, str], tuple[tuple[str, str, str, bool, str | None], ...]] = field(default_factory=dict)
    # (caller entity, state variable) -> (address it was read holding, observed_via, block)
    reads: dict[tuple[str, str], tuple[str, str, int | None]] = field(default_factory=dict)
    # The resolved_type beside each read, kept out of ``reads`` so the receiver
    # test reads the address and never the label. Absent where the row carried
    # no classification, which is a third state and not 'contract'.
    read_kinds: dict[tuple[str, str], str] = field(default_factory=dict)
    # (caller entity, state variable) -> (observed_via, block) for a read that
    # was ISSUED AND FAILED. Never a read: it carries no address and witnesses
    # no receiver. Separate from ``reads`` so "the read reverted" cannot be
    # published as "the read never happened".
    read_failures: dict[tuple[str, str], tuple[str, int | None]] = field(default_factory=dict)
    # (destination entity, selector) -> {caller entity: the ACL row accepting it}
    destination_acl: dict[tuple[str, str], dict[str, DestinationAcceptance]] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def acts_as(
        self, caller: str, destination: str, selector: str, *, via: frozenset[str] | None = None
    ) -> ActAsVerdict:
        """Whether ``caller`` is witnessed able to be made to call ``selector`` at
        ``destination``, optionally only from the functions ``via`` names.

        ``via`` is the multi-hop constraint and is a SET because a node can be
        admitted under several of its functions; a call site whose own selector
        is in it is considered, every other site is not looked at, and a caller
        with no site under any of them is refused rather than answered from a
        site the constraint excludes. ``via=None`` is the unconstrained question
        the first hop asks — and it is the ONLY thing that distinguishes hop 1
        from hop k, which is why the delegation conjunct is keyed on it.
        """
        token = _lower(selector)
        sites = self.call_sites.get((caller, token))
        if not sites:
            return ActAsVerdict(ACT_AS_NO_CALL_SITE)
        if via is not None:
            admitted = frozenset(_lower(entry) for entry in via)
            # A site whose own selector was never extracted matches nothing: not
            # determined is not a match, and treating it as one would walk a hop
            # on an unread field.
            sites = tuple(site for site in sites if site[4] is not None and site[4] in admitted)
            if not sites:
                return ActAsVerdict(ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION)
        # The sharpest shortfall any call site reported, and — where that
        # shortfall is a statement about what a receiver holds — the resolved
        # type of the address that was read, so the refusal carries WHAT it held.
        # First site in the deterministic site order wins a reason it shares.
        outcome: str | None = None
        held_types: dict[str, str] = {}

        def refuse(reason: str | None) -> ActAsVerdict:
            if reason is None:
                # Every site is either state-variable-bound (reported by the loop
                # below) or parameter-bound (reported by the arm after it), and a
                # caller with no site at all has already returned. Arriving here
                # with nothing reported is a broken invariant, not an answer, and
                # a refusal invented to cover it would be published as evidence.
                raise AssertionError(f"act_as refusal with no reported shortfall: {caller} -> {destination}.{token}")
            return ActAsVerdict(reason, receiver_resolved_type=held_types.get(reason))

        for name, openness, variable, delegated, calling_selector in sites:
            if not variable:
                continue
            read = self.reads.get((caller, variable))
            if read is None:
                # A read that was issued and reverted is not a read, and it is
                # not the absence of one either.
                attempted = (caller, variable) in self.read_failures
                outcome = _rank_outcome(outcome, ACT_AS_RECEIVER_READ_FAILED if attempted else ACT_AS_RECEIVER_NOT_READ)
                continue
            held, observed_via, block = read
            kind = self.read_kinds.get((caller, variable))
            if held != destination:
                # The comparison is the answer; the classification says what the
                # pointer holds instead, and two of its values are sharper
                # negatives than "some other address".
                if kind == _RESOLVED_RENOUNCED:
                    shortfall = ACT_AS_RECEIVER_IS_THE_RENOUNCED_ZERO_ADDRESS
                elif kind == _RESOLVED_CODELESS:
                    shortfall = ACT_AS_RECEIVER_HOLDS_A_NON_CONTRACT
                else:
                    shortfall = ACT_AS_RECEIVER_IS_ANOTHER_ADDRESS
                held_types.setdefault(shortfall, kind or "not_determined")
                outcome = _rank_outcome(outcome, shortfall)
                continue
            # The read holds the destination. What the row CALLS that address is
            # not consulted: a 'safe' or 'timelock' pointer holding D witnesses
            # the step exactly as a 'contract' one does.
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
        # No state variable of the caller names the destination. The second
        # shape: a call site whose callee the caller's own caller supplies, with
        # the destination's ACL naming this caller from the other end. Sorted so
        # a caller with several such sites names one function deterministically.
        # The gate conjuncts are NOT in this filter: a site excluded by one of
        # them would leave the arm reporting that the receiver is parameter-bound
        # — the precondition for this shape, not a shortfall of it — and publish
        # the receiver binding as the failure when the gate is what failed.
        parameter_bound = sorted((site for site in sites if not site[2]), key=_call_site_order)
        if not parameter_bound:
            return refuse(outcome)
        # Acceptance is a fact about the DESTINATION and is the same under every
        # call site, so it is consulted once, before any per-site gate reason.
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
        """Which conjunct this call site's caller gate fails, or ``None`` if it
        clears every one that applies at this hop.

        Openness is three-valued and each value has its own answer: ``open`` is a
        gate proven absent, ``restricted`` is a gate proven present, and anything
        else is a field the pipeline did not determine — which is not a gate, and
        is not the proven absence of one either.

        Delegation is required at the FIRST hop and only there. At hop 1 the
        principal's leverage IS the seized authority pointer, so only an
        authority-delegated gate is opened by seizing it. Past hop 1 the licence
        is the previous hop's admitted selector, which ``via`` has already pinned,
        and the delegation of this function's own gate tests a mechanism the
        principal is not using.
        """
        if openness == _OPENNESS_PUBLIC:
            return ACT_AS_CALL_SITE_IS_PUBLIC
        if openness != _OPENNESS_RESTRICTED:
            return ACT_AS_CALL_SITE_OPENNESS_NOT_DETERMINED
        if via is None and not delegated:
            return ACT_AS_CALL_SITE_GATE_NOT_DELEGATED
        return None


# How far a call site GOT before it was refused, so a caller with several call
# sites for one selector reports the sharpest shortfall rather than whichever it
# happened to look at last. Lower is further.
#
# The two proven-absent receiver reasons rank first because each ANSWERS the
# question rather than falling short of it: a renounced pointer holds an address
# that has no code and never can, and a codeless one holds an address proven to
# hold none today. The three gate reasons come next — a site whose receiver
# resolved and whose destination ACL was consulted got as far as its own gate.
# They rank ahead of the three destination-ACL reasons, which report on the
# destination rather than on this site. Among the ACL three, a row that names a
# role but bounds its membership only below got further than one that names no
# role at all, which got further than no row at all. Among the read reasons, an
# address that was read and is somebody else got further than a read that was
# issued and reverted, which got further than a read never attempted.
#
# Every constant that ``acts_as`` can rank MUST appear here: ``_rank_outcome``
# indexes this map, so an unregistered outcome raises at runtime.
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
    # A call site exists and the multi-hop constraint excluded every one of
    # them, so nothing about the receiver was ever consulted — further than no
    # call site at all, and short of every reason that did consult one.
    ACT_AS_NO_CALL_SITE_UNDER_THE_ADMITTED_FUNCTION: 11,
    ACT_AS_NO_CALL_SITE: 12,
}


def _rank_outcome(current: str | None, candidate: str) -> str:
    """``current`` is ``None`` until some call site has reported. Nothing is not
    a shortfall, so the first candidate wins outright rather than competing with
    a sentinel that would be published if no site reported at all."""
    if current is None:
        return candidate
    return candidate if _ACT_AS_RANK[candidate] < _ACT_AS_RANK[current] else current


def load_act_as_plane(session: Session, protocol_id: int) -> ActAsPlane:
    """The call-site, receiver and destination-acceptance witnesses, indexed for
    the composition walk."""
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
            # SQL NULL is "the effects stage did not run here", which is a
            # different fact from a function proven to call nothing. Neither
            # produces a call site, and only the second is an answer.
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
        # The calling function's OWN selector, so a multi-hop walk can ask which
        # function of this caller a step is issued from. A fallback or receive
        # names none, and stays None rather than being spelled as an empty match.
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
            # The reader tried and the call reverted. Indexed so the refusal can
            # say so; never a read, because it carries no address.
            read_failures.setdefault(key, (str(observed_via), int(block) if block is not None else None))
            continue
        if observed_via not in _READ_OBSERVATIONS:
            continue
        held = _lower(str(value or ""))
        if not held.startswith("0x"):
            continue
        # Every read that RETURNED an address is indexed, whatever the row calls
        # that address. resolved_type is a classification of a value the row
        # already carries, and the receiver test is the address comparison; a
        # pointer dropped for its label is a read discarded on a name.
        kind = str(resolved_type) if resolved_type else ""
        resolved_type_histogram[kind or "not_determined"] += 1
        held_key = entity_key(coalesce_chain(chain), held)
        previous = reads.get(key)
        if previous is not None and previous[0] != held_key:
            # Two reads of one variable disagreeing on which address it holds.
            # Picking one publishes a call destination out of row order, so the
            # variable resolves to nothing and the hop stays unwitnessed.
            ambiguous.add(key)
            continue
        reads.setdefault(key, (held_key, str(observed_via), int(block) if block is not None else None))
        if kind:
            read_kinds.setdefault(key, kind)
    for key in ambiguous:
        reads.pop(key, None)
        read_kinds.pop(key, None)
        # The failure record goes with them. A variable read twice to two
        # different addresses AND carrying a failed read would otherwise be
        # refused as caller_state_variable_read_reverted_on_chain — a sharper
        # claim than the evidence supports, since the reads that DID return are
        # what defeated it. It falls back to never_read_on_chain, which is the
        # standing (registered) mislabel for the disagreement case and awaits its
        # own reason; this must not make it a second, more specific one.
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
        # Both ends keyed on the destination's own chain: an ACL is a fact about
        # one deployment, and a same-address caller on another chain is a
        # different contract.
        bucket = destination_acl[(entity_key(chain_key, deployment or address), token)]
        previous = bucket.get(entity_key(chain_key, holder))
        # Several rows can name one caller at one selector. Keep the one that
        # witnesses the most, so a row bounded below or naming no role never
        # displaces one that names an enumerated role for the same pair.
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
            # Not "…holding_a_contract": admission no longer branches on what the
            # row calls the address, so the count is every VARIABLE read to an
            # address. The histogram beside it counts ROWS — one variable read
            # twice contributes twice, and a variable dropped for disagreeing
            # reads still contributes — so the two do not sum to each other and
            # the names say which unit each is in.
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
