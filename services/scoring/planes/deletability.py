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

# Can this principal delete the authority gating a destination function?
#
# A composed magnitude was proven by a direct impersonated call; it transfers to the principal only if the principal can
# author that calldata itself, i.e. repoint or rewrite the authority the destination's gate consults. Answered per
# (principal, destination, selector) from ``function_principals`` rows on four setters, never from hop counts or names
# (``len(act_as_chain) == 1`` correlates perfectly on the corpus but isn't a witness).
#
# Three outcomes: a qualifying row (``deletable``), the join ran and found none (``proven_not_deletable``), or it
# couldn't run or proves less than membership (``not_determined``). The third collapses to neither.

# Two independently sufficient arms. Host: ``setAuthority`` repoints the destination's authority, ``transferOwnership``
# takes the owner slot. Authority: role-writing setters on the authority the destination consults. Matched on function
# name, so the row's own selector is published (``transferOwnership`` has two).
DELETABILITY_HOST_SETTERS = ("setAuthority", "transferOwnership")
DELETABILITY_AUTHORITY_SETTERS = ("setRoleCapability", "setUserRole")
DELETABILITY_SETTERS = tuple(sorted(DELETABILITY_HOST_SETTERS + DELETABILITY_AUTHORITY_SETTERS))

# ``details->>'membership_quality'``: only ``exact`` proves this address is in the set; ``lower_bound`` only floors the
# set.
MEMBERSHIP_QUALITY_EXACT = "exact"

# ``principal_type`` is never a filter: it is ``controller`` on every row, so filtering would fail open.

# The normative witness is the destination function's own resolution record; the contract-scoped one can't separate
# selectors and is only a cross-check.
SOLMATE_ROLES_AUTHORITY_STEP = TRACE_STEP_SOLMATE_ROLES_AUTHORITY
AUTHORITY_CONTROLLER_ID = "external_contract:authority"
# The gate admitted it couldn't resolve its authority.
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

# One reason per evidential situation, so refusal counts decompose.
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

# ``not_corroborated`` (didn't answer) and ``disagrees`` (answered differently) are different; only the second is
# evidence.
CROSSCHECK_AGREES = "agrees"
CROSSCHECK_DISAGREES = "disagrees"
CROSSCHECK_NOT_CORROBORATED = GATE_CLAIM_NOT_CORROBORATED
CROSSCHECK_NOT_COMPARED = "not_compared"


@dataclass(frozen=True, order=True)
class SetterPrincipal:
    """One ``function_principals`` row on a setter.

    ``membership_quality`` is raw including ``None`` (unread, never treated as exact).
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
    """The three-state verdict for one (principal set, destination, selector).

    ``reason`` only when withheld, ``basis`` only when deletable; the authority witnesses are published in every state.
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
        # A deletable verdict without basis or a withheld one without reason is malformed.
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
        """The whole verdict as a publishable block, including on withheld entries: an unresolvable authority
        withholds the figure and lowers exposure, so the withheld entry must disclose the state, reason, authority
        asked about and witnesses, and obscuring evidence can't pay.
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
        """What proved it: the arm, the setter row and its id, enough to re-run the join by hand."""
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
    """The rows :func:`authority_deletability` decides from, keyed by ``(chain, address)`` (the same address on two
    chains is two contracts).
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
        """Setter rows at one contract naming these principals, unfiltered by quality so "no row" and "a row proving
        less" stay distinguishable.
        """
        wanted = frozenset(function_names)
        principals = frozenset(_lower(a) for a in principal_addresses)
        rows = self.setters.get((coalesce_chain(chain), _lower(address)), ())
        return tuple(r for r in rows if r.function_name in wanted and r.principal_address in principals)

    def counts(self) -> dict[str, int]:
        return {
            "setter_principal_rows": sum(len(rows) for rows in self.setters.values()),
            "setter_contracts": len(self.setters),
            "gating_authority_witnesses": len(self.gating),
            "authority_crosscheck_contracts": len(self.crosscheck),
            "tainted_destination_gates": len(self.tainted),
        }


def _authority_address(value: Any) -> str:
    """A stored authority as a lowercased address, or ``""``: only a 42-char address or a 32-byte word with a 20-byte
    address is read.
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

    Deliberately not protocol-scoped: a ``(chain, address)`` is a global identity, and 51 of 262 setter rows sit on
    contracts with no ``protocol_id``. Dropping them would publish ``proven_not_deletable`` from our own scoping. The
    queries are narrow (four setters, one step, one controller id), so a few hundred rows.
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

    # The LIKE is only a prefilter; the step name is matched exactly below.
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

    Uses the row's ``principal_addresses``, not ``principal_unit``: a row whose unit is a Safe but whose addresses name
    the timelock it acts through holds all four setters under the timelock and none under the Safe (keying on the unit
    withheld an $11.36M figure). Any address qualifying is enough. Destination-scoped: unscoped, an unrelated EOA
    holding setters elsewhere would republish every withheld entry. Deterministic: fixed arm order, lowest-id qualifying
    row.
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

    # The host arm first: it doesn't depend on the authority witnesses.
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

    # Which authority the destination's gate consults.
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
        # The gate couldn't resolve its authority; a trace naming one names a candidate.
        return withheld(DELETABILITY_NOT_DETERMINED, DELETABILITY_AUTHORITY_TAINTED, **witnesses)
    if not normative:
        return withheld(DELETABILITY_NOT_DETERMINED, DELETABILITY_AUTHORITY_UNRESOLVED, **witnesses)
    if len(normative) > 1:
        # Two authorities is no answer; the union would treat control of any as control of the real one.
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
        # Rows name the principal but none proves membership: not the earned negative.
        return withheld(DELETABILITY_NOT_DETERMINED, DELETABILITY_MEMBERSHIP_NOT_EXACT, **witnesses)
    # Both arms asked on answering witnesses, no row: the earned negative.
    return withheld(DELETABILITY_PROVEN_NOT_DELETABLE, DELETABILITY_NO_SETTER_ROW, **witnesses)
