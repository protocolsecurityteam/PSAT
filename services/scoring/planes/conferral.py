"""The conferral plane: what a gate CONFERS on the principal that holds it."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from services.scoring.planes._shared import SCOPE_ROLES, EdgeScope, _lower
from services.scoring.schema import coalesce_chain, entity_key

# What a gate confers. A control edge proves an authority relation exists, not that the gate a finding seizes is the
# authority it runs on. Two witnesses, per scope kind:
#
# ``roles N``: the role -> selector join from ``function_principals.details.trace`` resolves "role N at T" to the
# selectors it licenses, credited only where ``effective_functions`` names a function of T under that selector. A role
# licensing no named function makes the hop not determined.
#
# ``state_var L``: a same-kind bound, not a conferral witness. The gate's ``state_writes`` name what it rewrites on its
# own contract; requiring that name to match the edge label refuses hops whose authority is a different kind from what
# the gate seizes (``ownership.transfer`` writes ``owner``, so hops on ``hook``/``vault`` are refused). It removes hops
# and adds no evidence. Where kinds differ the hop isn't disproved: deciding it needs the intermediate's own functions
# and outbound calls, a join this plane doesn't run, so it is not determined.
#
# Residual: the role branch doesn't require the seizing capability to govern role assignment; there is no witness for
# it, so the bound is what the role licenses.
CONFERRAL_CONFERRED = "conferred"
CONFERRAL_SCOPE_NOT_DETERMINED = "scope_not_determined"
CONFERRAL_ROLE_NOT_LICENSED = "role_licenses_no_named_function_at_the_destination"
CONFERRAL_VARIABLE_NOT_REWRITTEN = "capability_not_witnessed_rewriting_this_variable"
CONFERRAL_WRITES_NOT_EXTRACTED = "capability_state_writes_not_extracted"
CONFERRAL_OUTCOMES = (
    CONFERRAL_CONFERRED,
    CONFERRAL_SCOPE_NOT_DETERMINED,
    CONFERRAL_ROLE_NOT_LICENSED,
    CONFERRAL_VARIABLE_NOT_REWRITTEN,
    CONFERRAL_WRITES_NOT_EXTRACTED,
)

# Body writes are the function's own; guard writes are modifier bookkeeping.
_WRITE_ORIGIN_BODY = "body"


@dataclass(frozen=True, order=True)
class LicensedFunction:
    """One named function a role licenses at a destination, structured (selector for the join, name for the reader)
    rather than a string consumers re-parse.
    """

    selector: str
    name: str

    def as_json(self) -> dict[str, str]:
        return {"selector": self.selector, "name": self.name}


@dataclass(frozen=True)
class ConferralVerdict:
    outcome: str
    licensed: tuple[LicensedFunction, ...] = ()
    basis: str = ""

    @property
    def conferred(self) -> bool:
        return self.outcome == CONFERRAL_CONFERRED


@dataclass(frozen=True)
class GateGrant:
    """One gate-control capability instance and what it seizes.

    ``rewrites`` comes from the specific function the signal was witnessed on. ``writes_extracted`` separates "never
    extracted" from "rewrites nothing"; both are withheld.
    """

    capability: str
    rewrites: frozenset[str]
    writes_extracted: bool
    basis: str
    plane: ConferralPlane = field(repr=False, compare=False)

    def confers(self, scope: EdgeScope, destination: str) -> ConferralVerdict:
        if not scope.is_determined:
            return ConferralVerdict(
                CONFERRAL_SCOPE_NOT_DETERMINED,
                basis=(
                    "the edge's label names no role and no state variable, so what this gate "
                    "would confer here is not_determined"
                ),
            )
        if scope.kind == SCOPE_ROLES:
            licensed = self.plane.licensed_functions(destination, scope.roles)
            if not licensed:
                return ConferralVerdict(
                    CONFERRAL_ROLE_NOT_LICENSED,
                    basis=(
                        f"no witnessed trace step licenses role(s) {list(scope.roles)} to a named "
                        f"function of {destination}, so the hop confers nothing that can be named"
                    ),
                )
            return ConferralVerdict(
                CONFERRAL_CONFERRED,
                licensed,
                basis=(
                    f"role(s) {list(scope.roles)} license {len(licensed)} named function(s) at "
                    f"{destination} (function_principals.details.trace[].selector joined to "
                    "effective_functions.selector)"
                ),
            )
        if not self.writes_extracted:
            return ConferralVerdict(CONFERRAL_WRITES_NOT_EXTRACTED, basis=self.basis)
        if scope.state_var not in self.rewrites:
            return ConferralVerdict(
                CONFERRAL_VARIABLE_NOT_REWRITTEN,
                basis=(
                    f"{self.capability} is witnessed rewriting {sorted(self.rewrites)} on its own "
                    f"contract and not '{scope.state_var}', so this hop runs on an authority of a "
                    "different kind from the one the gate seizes. Refused as a same-kind bound; "
                    "whether it composes anyway turns on the intermediate node's function surface, "
                    "which this plane does not consult"
                ),
            )
        return ConferralVerdict(
            CONFERRAL_CONFERRED,
            basis=(
                f"same-kind: {self.capability} is witnessed rewriting a variable named "
                f"'{scope.state_var}' on its own contract, which is the name the hop's authority "
                f"slot carries on the destination's ({self.basis}). A NAME MATCH ACROSS TWO "
                "CONTRACTS' STORAGE, not a witness that seizing one exercises the other — the "
                "composition step is unwitnessed and this bound only removes hops of a different "
                "kind"
            ),
        )


@dataclass
class ConferralPlane:
    """The two conferral witnesses, indexed for the walk.

    ``writes_by_function`` feeds the walk; ``writes_by_capability`` (the class-wide union, an upper bound) only feeds
    the census.
    """

    role_functions: dict[tuple[str, int], tuple[LicensedFunction, ...]] = field(default_factory=dict)
    writes_by_function: dict[int, frozenset[str]] = field(default_factory=dict)
    writes_by_capability: dict[str, frozenset[str]] = field(default_factory=dict)
    # Recovery key for signals whose ``function_id`` no longer resolves; only where every function under the key agrees.
    writes_by_deployment_selector: dict[tuple[str, str], frozenset[str]] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def licensed_functions(self, destination: str, roles: tuple[int, ...]) -> tuple[LicensedFunction, ...]:
        """Named functions the union of ``roles`` licenses at ``destination`` (a multi-role label is one principal
        holding all of them).
        """
        out: set[LicensedFunction] = set()
        for role in roles:
            out.update(self.role_functions.get((destination, int(role)), ()))
        return tuple(sorted(out))

    def grant_for(
        self, capability: str, function_id: int | None, *, entity: str | None = None, selector: str | None = None
    ) -> GateGrant:
        """What one gate seizes, by its own function where that still resolves.

        Re-analysis deletes and reinserts ``effective_functions`` and the signal's ``function_id`` is ``ON DELETE SET
        NULL``, so a dangling id would read as "not extracted" and silently stop walks. It falls back to the signal's
        ``(deployment entity, selector)``, only where every function under that key agrees.
        """
        writes = self.writes_by_function.get(function_id) if function_id is not None else None
        if writes is not None:
            return GateGrant(
                capability, writes, True, f"effective_functions.state_writes(function {function_id})", self
            )
        key = (str(entity), _lower(str(selector))) if entity and selector else None
        recovered = self.writes_by_deployment_selector.get(key) if key else None
        if recovered is not None:
            return GateGrant(
                capability,
                recovered,
                True,
                (
                    f"effective_functions.state_writes recovered on (deployment, selector) {key} — "
                    f"function_id {function_id} does not resolve"
                ),
                self,
            )
        return GateGrant(
            capability,
            frozenset(),
            False,
            (
                "effective_functions.state_writes carries no extracted array for this gate: "
                f"function_id {function_id} does not resolve and (deployment, selector) {key} "
                "recovers no single agreed answer, so what this gate rewrites was never read"
            ),
            self,
        )

    def capability_grant(self, capability: str) -> GateGrant:
        """The class-wide union of what every witness of ``capability`` rewrites: a census instrument, never a walk
        input.
        """
        writes = self.writes_by_capability.get(capability)
        if writes is None:
            return GateGrant(
                capability,
                frozenset(),
                False,
                f"no function carrying {capability} has extracted state_writes in this protocol",
                self,
            )
        return GateGrant(
            capability,
            writes,
            True,
            f"union of effective_functions.state_writes over every {capability} witness in this protocol",
            self,
        )


def load_conferral_plane(session: Session, protocol_id: int) -> ConferralPlane:
    from db.models import Contract, EffectiveFunction, FunctionPrincipal

    named: dict[tuple[str, str], LicensedFunction] = {}
    writes_by_function: dict[int, frozenset[str]] = {}
    writes_by_key: dict[tuple[str, str], set[frozenset[str]]] = defaultdict(set)
    claims_by_function: dict[int, tuple[str, ...]] = {}
    functions = (
        session.query(
            EffectiveFunction.id,
            EffectiveFunction.function_name,
            EffectiveFunction.selector,
            EffectiveFunction.state_writes,
            EffectiveFunction.claims,
            EffectiveFunction.deployment_address,
            Contract.address,
            Contract.chain,
        )
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(EffectiveFunction.id)
        .all()
    )
    for function_id, name, selector, state_writes, claims, deployment, address, chain in functions:
        key = entity_key(coalesce_chain(chain), deployment or address)
        token = _lower(str(selector)) if selector else None
        if token:
            named.setdefault((key, token), LicensedFunction(token, str(name)))
        # An array means extraction ran; anything else means it didn't.
        if isinstance(state_writes, list):
            written = frozenset(
                str(entry.get("var"))
                for entry in state_writes
                if isinstance(entry, dict) and entry.get("var") and entry.get("origin") == _WRITE_ORIGIN_BODY
            )
            writes_by_function[int(function_id)] = written
            if token:
                writes_by_key[(key, token)].add(written)
        if isinstance(claims, list):
            claims_by_function[int(function_id)] = tuple(
                str(entry.get("claim_id")) for entry in claims if isinstance(entry, dict) and entry.get("claim_id")
            )

    writes_by_capability: dict[str, set[str]] = defaultdict(set)
    capability_functions: dict[str, int] = defaultdict(int)
    capability_functions_extracted: dict[str, int] = defaultdict(int)
    for function_id, claim_ids in claims_by_function.items():
        for claim_id in set(claim_ids):
            capability_functions[claim_id] += 1
            writes = writes_by_function.get(function_id)
            if writes is None:
                continue
            capability_functions_extracted[claim_id] += 1
            writes_by_capability[claim_id].update(writes)

    role_functions: dict[tuple[str, int], set[LicensedFunction]] = defaultdict(set)
    role_authorities: dict[tuple[str, int], set[str]] = defaultdict(set)
    steps = unnamed_selectors = 0
    principals = (
        session.query(FunctionPrincipal.details, Contract.chain)
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(FunctionPrincipal.id)
        .all()
    )
    for details, chain in principals:
        trace = (details or {}).get("trace") if isinstance(details, dict) else None
        for step in trace or []:
            if not isinstance(step, dict):
                continue
            selector, target, roles = step.get("selector"), step.get("target"), step.get("roles")
            if not selector or not target or not isinstance(roles, list):
                continue
            steps += 1
            key = entity_key(coalesce_chain(chain), str(target))
            function = named.get((key, _lower(str(selector))))
            if function is None:
                # Licenses a selector no analysed function carries: counted, not credited.
                unnamed_selectors += 1
                continue
            for role in roles:
                try:
                    number = int(role)
                except (TypeError, ValueError):
                    continue
                role_functions[(key, number)].add(function)
                if step.get("authority"):
                    role_authorities[(key, number)].add(_lower(str(step["authority"])))

    recovery = {key: next(iter(rows)) for key, rows in sorted(writes_by_key.items()) if len(rows) == 1}
    plane = ConferralPlane(
        role_functions={key: tuple(sorted(rows)) for key, rows in sorted(role_functions.items())},
        writes_by_function=writes_by_function,
        writes_by_capability={key: frozenset(rows) for key, rows in sorted(writes_by_capability.items())},
        writes_by_deployment_selector=recovery,
    )
    plane.provenance = {
        "role_selector_join": {
            "trace_steps_carrying_a_selector": steps,
            "steps_whose_selector_names_no_analysed_function": unnamed_selectors,
            "role_scopes_resolved": len(plane.role_functions),
            "destinations": len({key[0] for key in plane.role_functions}),
            "role_scopes_resolved_by_more_than_one_authority": sum(
                1 for holders in role_authorities.values() if len(holders) > 1
            ),
            "reading": (
                "a (destination, role) pair resolves to the NAMED functions that role licenses "
                "there: function_principals.details.trace[].selector joined to "
                "effective_functions.selector at the same destination. A step whose selector "
                "names no analysed function of the destination is counted above and credited "
                "nowhere — it licenses something this document cannot name. Role numbers are "
                "per-authority; the join is keyed on (destination, role) because the "
                "destination pins which authority governs it, and the count of pairs resolved "
                "through more than one authority is published so a reader can see whether that "
                "pinning was ambiguous anywhere"
            ),
        },
        "capability_rewrites": {
            "functions_with_state_writes_extracted": len(writes_by_function),
            "functions": len(functions),
            "by_capability": {
                capability: {
                    "rewrites": sorted(writes_by_capability.get(capability, ())),
                    "functions": capability_functions[capability],
                    "functions_with_state_writes_extracted": capability_functions_extracted.get(capability, 0),
                }
                for capability in sorted(capability_functions)
            },
            "reading": (
                "what each capability's own witnesses are observed to REWRITE, from "
                "effective_functions.state_writes with origin=body — a guard-origin write is the "
                "modifier's bookkeeping and not what the capability does. The walk consults the "
                "witnessed function's OWN set, never this union; the union is published because "
                "it is the upper bound the hop census is computed against. This is a SAME-KIND "
                "BOUND and not a conferral witness: the gate's variable is named on its own "
                "contract and the hop's authority slot on the destination's, so requiring the "
                "names to match refuses hops of a different kind and witnesses no composition "
                "step for the ones that survive"
            ),
        },
        "stale_function_reference_recovery": {
            "keys": len(recovery),
            "keys_two_functions_disagree_under": sum(1 for rows in writes_by_key.values() if len(rows) > 1),
            "reading": (
                "function_score_signals.function_id is ON DELETE SET NULL against "
                "effective_functions, and a re-analysis deletes and reinserts a contract's rows, "
                "so a persisted signal that outlives one re-analysis points at nothing. Left "
                "alone that reports every gate as state_writes-not-extracted and silently stops "
                "walking hops it walked yesterday — a withhold that is counted and whose cause is "
                "a stale foreign key. A dangling reference falls back to the signal's own "
                "(deployment entity, selector), which the re-analysis preserves, and only where "
                "every function under that key agrees on what it rewrites"
            ),
        },
    }
    return plane
