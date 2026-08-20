"""The deletability plane: can a principal delete the authority gating a function."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Text
from sqlalchemy.orm import Session

from services.scoring.planes._shared import _lower
from services.scoring.schema import coalesce_chain, entity_key, is_entity_key
from utils.execution_record import GATE_CLAIM_NOT_CORROBORATED
from utils.scoring_status import TRACE_STEP_SOLMATE_ROLES_AUTHORITY

# --- authority deletability --------------------------------------------------
# Can this principal DELETE the authority that gates this destination function?
#
# A composed magnitude is a figure proven by a call the principal did not make:
# the proof is a direct impersonated call to the destination, the published
# route runs through a wrapper that authors the call's arguments. The figure
# transfers to the principal only where the principal can author that calldata
# itself — which it can if it can repoint or rewrite the authority the
# destination's gate consults, because then there is no gate left to satisfy.
#
# The question is asked per (principal, destination, selector) and answered from
# ``function_principals`` rows on the four setters below. It is NEVER answered
# from a hop count, a selector name or a contract shape: on the corpus this was
# calibrated against, ``len(act_as_chain) == 1`` partitions the population
# identically, and shipping that correlation would publish an abstraction above
# an available witness (inv. 16).
#
# THREE OUTCOMES, none collapsible (inv. 1):
#   * a qualifying row exists                     -> ``deletable``
#   * the join ran and returned no row            -> ``proven_not_deletable``
#   * the join could not be run, or was run on a  -> ``not_determined``
#     witness that proves less than membership
# The third is not the second. An unresolvable authority failing to "not
# deletable" mints an earned negative out of an absence; failing to "deletable"
# republishes a figure on an unproven control claim. Both are banned, so the
# third state carries its own typed reason all the way to the consumer.

# The two arms, each INDEPENDENTLY sufficient — arm (a) is not a relaxation of
# arm (b). HOST: ``setAuthority`` repoints the destination's own authority
# pointer and ``transferOwnership`` takes the owner slot that may repoint it.
# AUTHORITY: the role-writing setters ON the authority the destination is
# witnessed to consult let the principal write itself the admitting role.
#
# Matched on ``effective_functions.function_name``, which is what the ruling
# this implements specifies and what its 28/12 partition was measured against.
# A name is not a signature, so the matched row's own selector is published in
# the basis rather than assumed: measured on this snapshot, ``transferOwnership``
# carries TWO selectors (``0xf2fde38b`` x122, ``0x078dfbe7`` x4) and a reader
# who needs to know which one proved the control can read it off the basis.
DELETABILITY_HOST_SETTERS = ("setAuthority", "transferOwnership")
DELETABILITY_AUTHORITY_SETTERS = ("setRoleCapability", "setUserRole")
DELETABILITY_SETTERS = tuple(sorted(DELETABILITY_HOST_SETTERS + DELETABILITY_AUTHORITY_SETTERS))

# ``membership_quality`` is NOT a column — it lives at
# ``details->>'membership_quality'``, domain measured as
# {lower_bound: 26493, exact: 2196}. Only ``exact`` proves this address is in
# the admitting set; ``lower_bound`` proves the set has at least these members,
# which is a floor on the SET and not a proof about this address. Measured cost
# of requiring it on the four setters: zero — all 262 rows are already exact.
MEMBERSHIP_QUALITY_EXACT = "exact"

# ``principal_type`` is NEVER a filter here: it is ``'controller'`` on 28,689 of
# 28,689 rows, so a join carrying it fails open while looking scoped.

# The NORMATIVE authority witness: the destination function's own resolution
# record, per (destination, selector). The corroborating one is contract-scoped
# and cannot separate two selectors on one host that consult different
# authorities, so it is admitted as a cross-check and never as the source.
SOLMATE_ROLES_AUTHORITY_STEP = TRACE_STEP_SOLMATE_ROLES_AUTHORITY
AUTHORITY_CONTROLLER_ID = "external_contract:authority"
# The gate's own admission that it could not resolve the authority it consults.
CALLER_TAINTED_AUTHORITY_UNRESOLVED = "caller_tainted_authority_unresolved"

DELETABILITY_DELETABLE = "deletable"
DELETABILITY_PROVEN_NOT_DELETABLE = "proven_not_deletable"
DELETABILITY_NOT_DETERMINED = "not_determined"
DELETABILITY_STATES = (
    DELETABILITY_DELETABLE,
    DELETABILITY_PROVEN_NOT_DELETABLE,
    DELETABILITY_NOT_DETERMINED,
)

DELETABILITY_ARM_HOST = "host"
DELETABILITY_ARM_GATING_AUTHORITY = "gating_authority"
DELETABILITY_ARMS = (DELETABILITY_ARM_HOST, DELETABILITY_ARM_GATING_AUTHORITY)

# One reason per evidential situation. The consumer counts refusals by these
# tokens, so two situations sharing one token would publish a count nobody can
# decompose.
DELETABILITY_NO_SETTER_ROW = "no_setter_row_names_this_principal_at_the_host_or_at_the_gating_authority"
DELETABILITY_MEMBERSHIP_NOT_EXACT = "every_setter_row_naming_this_principal_is_a_lower_bound_on_the_admitting_set"
DELETABILITY_AUTHORITY_UNRESOLVED = "no_witness_names_the_authority_this_destination_selector_consults"
DELETABILITY_AUTHORITY_NOT_UNIQUE = "the_selector_scoped_witnesses_name_more_than_one_authority_for_this_selector"
DELETABILITY_AUTHORITY_SOURCES_DISAGREE = "the_selector_scoped_and_contract_scoped_authority_witnesses_disagree"
DELETABILITY_AUTHORITY_TAINTED = "the_destination_gate_carries_an_unresolved_caller_authority"
DELETABILITY_NO_PRINCIPAL_ADDRESS = "the_row_names_no_principal_address_to_ask_the_join_about"
DELETABILITY_DESTINATION_NOT_CHAIN_SCOPED = "the_destination_key_carries_no_chain_scope"
DELETABILITY_REASONS = (
    DELETABILITY_AUTHORITY_NOT_UNIQUE,
    DELETABILITY_AUTHORITY_SOURCES_DISAGREE,
    DELETABILITY_AUTHORITY_TAINTED,
    DELETABILITY_AUTHORITY_UNRESOLVED,
    DELETABILITY_DESTINATION_NOT_CHAIN_SCOPED,
    DELETABILITY_MEMBERSHIP_NOT_EXACT,
    DELETABILITY_NO_PRINCIPAL_ADDRESS,
    DELETABILITY_NO_SETTER_ROW,
)

# What the contract-scoped cross-check had to say. ``not_corroborated`` and
# ``disagrees`` are different facts: the first is a witness that did not answer,
# the second is one that answered differently, and only the second is evidence.
CROSSCHECK_AGREES = "agrees"
CROSSCHECK_DISAGREES = "disagrees"
CROSSCHECK_NOT_CORROBORATED = GATE_CLAIM_NOT_CORROBORATED
CROSSCHECK_NOT_COMPARED = "not_compared"


@dataclass(frozen=True, order=True)
class SetterPrincipal:
    """One ``function_principals`` row on a setter of one contract.

    ``membership_quality`` is carried raw, including ``None``: an absent quality
    is an unread witness, and reading it as ``exact`` would let a row that
    proves nothing about this address prove control.
    """

    function_principal_id: int
    chain: str
    contract_address: str
    function_name: str
    selector: str | None
    principal_address: str
    membership_quality: str | None

    @property
    def is_membership_exact(self) -> bool:
        return self.membership_quality == MEMBERSHIP_QUALITY_EXACT


@dataclass(frozen=True)
class DeletabilityVerdict:
    """The three-state answer for one (principal set, destination, selector).

    ``reason`` is populated in exactly the two withholding states and is the
    token a consumer counts refusals by; ``basis`` is populated in exactly the
    deletable state and names the row that proved it. The two authority witness
    fields are published in every state, because "which authority did you even
    ask about" is the first question a reader of a refusal has.
    """

    state: str
    destination_key: str
    selector: str
    principal_addresses: tuple[str, ...]
    reason: str | None = None
    arm: str | None = None
    basis: SetterPrincipal | None = None
    gating_authorities: tuple[str, ...] = ()
    crosscheck_authorities: tuple[str, ...] = ()
    crosscheck: str = CROSSCHECK_NOT_COMPARED

    def __post_init__(self) -> None:
        # The pairing is the whole point of the type: a deletable verdict with
        # no basis is a control claim with no witness, and a withheld one with
        # no reason is a refusal a consumer cannot publish or count.
        if self.state not in DELETABILITY_STATES:
            raise ValueError(f"unknown deletability state: {self.state!r}")
        if self.state == DELETABILITY_DELETABLE:
            if self.basis is None or self.arm is None or self.reason is not None:
                raise ValueError("a deletable verdict carries an arm and a basis row, and no reason")
        elif self.basis is not None or self.arm is not None or self.reason is None:
            raise ValueError("a withheld verdict carries a reason, and neither an arm nor a basis row")

    @property
    def is_deletable(self) -> bool:
        return self.state == DELETABILITY_DELETABLE

    def disclosure(self) -> dict[str, Any]:
        """The verdict as a publishable block — the whole verdict, every state.

        Published on WITHHELD entries too, and that is not decoration: under
        this rule a protocol whose gating authority cannot be resolved lands on
        ``not_determined``, its figure is withheld, and its published exposure
        FALLS. Obscuring evidence must not pay (inv. 13), so the withheld entry
        discloses the state, the typed reason, the authority it asked about and
        which witnesses answered — a suppressed authority then presents as a
        disclosed unknown rather than as an absent finding. The caller pairs
        this with its own ``refused`` counter, keyed on ``reason``.
        """
        block: dict[str, Any] = {
            "state": self.state,
            "reason": self.reason,
            "destination": self.destination_key,
            "selector": self.selector,
            "principal_addresses": list(self.principal_addresses),
            "gating_authority_witness": {
                "selector_scoped": list(self.gating_authorities),
                "contract_scoped_crosscheck": list(self.crosscheck_authorities),
                "crosscheck": self.crosscheck,
            },
        }
        block["basis"] = None if self.basis is None else self.basis_block()
        return block

    def basis_block(self) -> dict[str, Any] | None:
        """What proved it: the arm, the setter row, and the row's own id.

        ``function_principal_id`` and the setter's own selector are the two
        fields a reader needs to re-run this join by hand, which is what makes
        the republished figure checkable rather than asserted.
        """
        if self.basis is None:
            return None
        return {
            "arm": self.arm,
            "function_principal_id": self.basis.function_principal_id,
            "principal_address": self.basis.principal_address,
            "setter_function_name": self.basis.function_name,
            "setter_selector": self.basis.selector,
            "setter_contract": entity_key(self.basis.chain, self.basis.contract_address),
            "membership_quality": self.basis.membership_quality,
        }


@dataclass
class DeletabilityPlane:
    """The rows :func:`authority_deletability` decides from, loaded once.

    Every map is keyed on ``(chain, lowercased address)`` — chain-scoped,
    because the same address on two chains is two contracts and an unscoped key
    would let one chain's setter row prove control on the other.
    """

    setters: dict[tuple[str, str], tuple[SetterPrincipal, ...]] = field(default_factory=dict)
    gating: dict[tuple[str, str, str], tuple[str, ...]] = field(default_factory=dict)
    crosscheck: dict[tuple[str, str], tuple[str, ...]] = field(default_factory=dict)
    tainted: frozenset[tuple[str, str, str]] = frozenset()

    def setter_rows(
        self,
        chain: str,
        address: str,
        function_names: Iterable[str],
        principal_addresses: Iterable[str],
    ) -> tuple[SetterPrincipal, ...]:
        """Setter rows at one contract naming one of these principals.

        Membership quality is NOT filtered here: the caller has to be able to
        tell "no row names this principal" from "a row does, and it proves less
        than membership", because those are different published states.
        """
        wanted = frozenset(function_names)
        principals = frozenset(_lower(a) for a in principal_addresses)
        rows = self.setters.get((coalesce_chain(chain), _lower(address)), ())
        return tuple(r for r in rows if r.function_name in wanted and r.principal_address in principals)

    def counts(self) -> dict[str, int]:
        """Row counts, for the provenance block."""
        return {
            "setter_principal_rows": sum(len(rows) for rows in self.setters.values()),
            "setter_contracts": len(self.setters),
            "gating_authority_witnesses": len(self.gating),
            "authority_crosscheck_contracts": len(self.crosscheck),
            "tainted_destination_gates": len(self.tainted),
        }


def _authority_address(value: Any) -> str:
    """A stored authority value as a plain lowercased address, or ``""``.

    Only the two shapes the column is known to carry are read: a 42-character
    address, and a 66-character 32-byte word whose low 20 bytes are one.
    Anything else is left unread rather than sliced into a plausible address.
    """
    token = _lower(value)
    if not token.startswith("0x"):
        return ""
    if len(token) == 42:
        return token
    if len(token) == 66:
        return "0x" + token[-40:]
    return ""


def load_deletability_plane(session: Session) -> DeletabilityPlane:
    """Every witness :func:`authority_deletability` reads, in four queries.

    NOT protocol-scoped, deliberately, and this is the one scoping decision in
    this plane that could go wrong in a way nothing downstream would show. The
    join asks about specific ``(chain, address)`` contracts — the destination a
    figure was proven at, and the authority its gate is witnessed to consult —
    and a ``(chain, address)`` is a global on-chain identity, not a
    protocol-relative one. Measured on this snapshot: 51 of the 262 setter rows
    sit on 33 contracts whose ``protocol_id`` is NULL, and a protocol-scoped
    read would drop them. Dropping a witness here does not fail safe: the join
    would return no row and the entry would publish ``proven_not_deletable`` —
    an earned negative minted from our own scoping, which is exactly the defect
    class this plane exists to close. The population is a pure function of the
    database state, so replay (inv. 11) is unaffected.

    The queries are narrow by construction — four setter names, one trace step,
    one controller id, one basis tag — so "unscoped" is a few hundred rows, not
    a table scan of ``function_principals``.
    """
    from db.models import Contract, ControllerValue, EffectiveFunction, FunctionPrincipal

    setters: dict[tuple[str, str], list[SetterPrincipal]] = defaultdict(list)
    for fp_id, fp_address, details, function_name, selector, address, chain in (
        session.query(
            FunctionPrincipal.id,
            FunctionPrincipal.address,
            FunctionPrincipal.details,
            EffectiveFunction.function_name,
            EffectiveFunction.selector,
            Contract.address,
            Contract.chain,
        )
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(EffectiveFunction.function_name.in_(DELETABILITY_SETTERS))
        .order_by(FunctionPrincipal.id)
        .all()
    ):
        principal = _lower(fp_address)
        host = _lower(address)
        if not principal or not host:
            continue
        quality = (details or {}).get("membership_quality") if isinstance(details, dict) else None
        setters[(coalesce_chain(chain), host)].append(
            SetterPrincipal(
                function_principal_id=int(fp_id),
                chain=coalesce_chain(chain),
                contract_address=host,
                function_name=str(function_name),
                selector=_lower(selector) or None,
                principal_address=principal,
                membership_quality=None if quality is None else str(quality),
            )
        )

    # The gating authority, per (destination, selector). The LIKE is a prefilter
    # only — the step name is matched exactly, in Python, below; a row whose
    # trace merely mentions the string contributes nothing.
    gating: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for details, selector, address, chain in (
        session.query(
            FunctionPrincipal.details,
            EffectiveFunction.selector,
            Contract.address,
            Contract.chain,
        )
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(FunctionPrincipal.details.cast(Text).like(f"%{SOLMATE_ROLES_AUTHORITY_STEP}%"))
        .filter(EffectiveFunction.selector.isnot(None))
        .order_by(FunctionPrincipal.id)
        .all()
    ):
        key = (coalesce_chain(chain), _lower(address), _lower(selector))
        for step in (details or {}).get("trace") or []:
            if not isinstance(step, dict) or step.get("step") != SOLMATE_ROLES_AUTHORITY_STEP:
                continue
            authority = _authority_address(step.get("authority"))
            if authority:
                gating[key].add(authority)

    crosscheck: dict[tuple[str, str], set[str]] = defaultdict(set)
    for value, address, chain in (
        session.query(ControllerValue.value, Contract.address, Contract.chain)
        .join(Contract, Contract.id == ControllerValue.contract_id)
        .filter(ControllerValue.controller_id == AUTHORITY_CONTROLLER_ID)
        .order_by(ControllerValue.id)
        .all()
    ):
        authority = _authority_address(value)
        if authority:
            crosscheck[(coalesce_chain(chain), _lower(address))].add(authority)

    tainted = {
        (coalesce_chain(chain), _lower(address), _lower(selector))
        for selector, address, chain in (
            session.query(EffectiveFunction.selector, Contract.address, Contract.chain)
            .join(Contract, Contract.id == EffectiveFunction.contract_id)
            .filter(EffectiveFunction.capability_expr.cast(Text).like(f"%{CALLER_TAINTED_AUTHORITY_UNRESOLVED}%"))
            .filter(EffectiveFunction.selector.isnot(None))
            .order_by(EffectiveFunction.id)
            .all()
        )
    }

    return DeletabilityPlane(
        setters={key: tuple(sorted(rows)) for key, rows in sorted(setters.items())},
        gating={key: tuple(sorted(values)) for key, values in sorted(gating.items())},
        crosscheck={key: tuple(sorted(values)) for key, values in sorted(crosscheck.items())},
        tainted=frozenset(tainted),
    )


def authority_deletability(
    plane: DeletabilityPlane,
    principal_addresses: Iterable[str],
    destination_key: str,
    selector: str,
) -> DeletabilityVerdict:
    """Can this principal author a call to ``destination_key.selector`` itself?

    ``principal_addresses`` is the ROW's ``principal_addresses`` list, never its
    ``principal_unit``. The two differ wherever a row is reached through an
    ``access_path``: measured on the reference corpus, the row whose unit is a
    Safe but whose addresses name the timelock it acts through holds all four
    setters at its destination under the timelock and NONE under the Safe, so
    keying on the unit withholds a $11.36M figure the evidence supports and
    publishes no diagnostic saying why. Any one of the addresses qualifying is
    enough; the row that qualified is named in the basis.

    Destination-scoped, and that scope is load-bearing in the other direction:
    unscoped ("does this principal hold a setter ANYWHERE"), the EOA of the
    reference corpus holds all four setters on solver contracts it has nothing
    to do with these vaults, and every withheld entry is republished.

    Deterministic: the arms are asked in a fixed order and the basis is the
    lowest-id qualifying row, so the same database state answers identically.
    """
    addresses = tuple(sorted({_lower(a) for a in (principal_addresses or ()) if _lower(a)}))
    selector = _lower(selector)

    def withheld(state: str, reason: str, **kwargs: Any) -> DeletabilityVerdict:
        return DeletabilityVerdict(
            state=state,
            destination_key=destination_key,
            selector=selector,
            principal_addresses=addresses,
            reason=reason,
            **kwargs,
        )

    if not addresses:
        return withheld(DELETABILITY_NOT_DETERMINED, DELETABILITY_NO_PRINCIPAL_ADDRESS)
    if not is_entity_key(destination_key):
        return withheld(DELETABILITY_NOT_DETERMINED, DELETABILITY_DESTINATION_NOT_CHAIN_SCOPED)
    chain, _, host = destination_key.partition("::")
    chain = coalesce_chain(chain)

    # Arm (a), the HOST arm, first: it asks nothing about the gating authority,
    # so it stands whatever the authority witnesses do or do not say.
    host_rows = plane.setter_rows(chain, host, DELETABILITY_HOST_SETTERS, addresses)
    exact_host = [row for row in host_rows if row.is_membership_exact]
    if exact_host:
        return DeletabilityVerdict(
            state=DELETABILITY_DELETABLE,
            destination_key=destination_key,
            selector=selector,
            principal_addresses=addresses,
            arm=DELETABILITY_ARM_HOST,
            basis=min(exact_host),
            gating_authorities=plane.gating.get((chain, _lower(host), selector), ()),
            crosscheck_authorities=plane.crosscheck.get((chain, _lower(host)), ()),
            crosscheck=CROSSCHECK_NOT_COMPARED,
        )

    # Arm (b) needs to know WHICH authority the destination's own gate consults.
    normative: tuple[str, ...] = plane.gating.get((chain, _lower(host), selector)) or ()
    corroborating: tuple[str, ...] = plane.crosscheck.get((chain, _lower(host))) or ()
    if not normative:
        crosscheck_state = CROSSCHECK_NOT_COMPARED
    elif not corroborating:
        crosscheck_state = CROSSCHECK_NOT_CORROBORATED
    elif set(normative) == set(corroborating):
        crosscheck_state = CROSSCHECK_AGREES
    else:
        crosscheck_state = CROSSCHECK_DISAGREES
    witnesses = {
        "gating_authorities": tuple(normative),
        "crosscheck_authorities": tuple(corroborating),
        "crosscheck": crosscheck_state,
    }

    if (chain, _lower(host), selector) in plane.tainted:
        # The gate itself records that it could not resolve the authority it
        # consults. A trace that names one anyway is naming a candidate, not the
        # gate's answer, and control over a candidate proves nothing.
        return withheld(DELETABILITY_NOT_DETERMINED, DELETABILITY_AUTHORITY_TAINTED, **witnesses)
    if not normative:
        return withheld(DELETABILITY_NOT_DETERMINED, DELETABILITY_AUTHORITY_UNRESOLVED, **witnesses)
    if len(normative) > 1:
        # Two answers to "which authority gates this selector" is no answer.
        # Asking the arm over each in turn would take the union — control over
        # any candidate read as control over the real one.
        return withheld(DELETABILITY_NOT_DETERMINED, DELETABILITY_AUTHORITY_NOT_UNIQUE, **witnesses)
    if crosscheck_state == CROSSCHECK_DISAGREES:
        return withheld(DELETABILITY_NOT_DETERMINED, DELETABILITY_AUTHORITY_SOURCES_DISAGREE, **witnesses)

    authority = next(iter(normative))
    authority_rows = plane.setter_rows(chain, authority, DELETABILITY_AUTHORITY_SETTERS, addresses)
    exact_authority = [row for row in authority_rows if row.is_membership_exact]
    if exact_authority:
        return DeletabilityVerdict(
            state=DELETABILITY_DELETABLE,
            destination_key=destination_key,
            selector=selector,
            principal_addresses=addresses,
            arm=DELETABILITY_ARM_GATING_AUTHORITY,
            basis=min(exact_authority),
            **witnesses,
        )
    if host_rows or authority_rows:
        # Rows DO name this principal on a setter; none of them proves
        # membership. That is not "the join found nothing" and must not be
        # published as the earned negative.
        return withheld(DELETABILITY_NOT_DETERMINED, DELETABILITY_MEMBERSHIP_NOT_EXACT, **witnesses)
    # Both arms were asked, on witnesses that answered, and neither returned a
    # row. This is the earned negative.
    return withheld(DELETABILITY_PROVEN_NOT_DELETABLE, DELETABILITY_NO_SETTER_ROW, **witnesses)
