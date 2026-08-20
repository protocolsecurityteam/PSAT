"""The conferral plane: what a gate CONFERS on the principal that holds it."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from services.scoring.planes._shared import SCOPE_ROLES, EdgeScope, _lower
from services.scoring.schema import coalesce_chain, entity_key

# --- what a gate CONFERS -----------------------------------------------------
#
# A control edge proves that an authority relation EXISTS. It does not prove
# that the gate a finding seizes is the authority that relation runs on, and
# until this plane there was nothing to ask: gate control walked every edge whose
# label named a scope at all, which is a label-PRESENCE test wearing a conferral
# test's name. Two witnesses answer it, one per scope kind.
#
#   roles N      The role -> selector join. ``function_principals.details.trace[]``
#                records, per resolved principal, the step that admitted it —
#                ``(step, authority, target, selector, roles)`` — so "role N at
#                target T" resolves to the SELECTORS role N licenses at T. A
#                selector is credited only where ``effective_functions.selector``
#                names a function of T under it: four bytes nobody can name is
#                not a licensed function, and the named function is what a
#                magnitude can later be attributed to. A role that licenses no
#                named function at the destination confers nothing anyone can
#                point at, and the hop is not_determined.
#
#   state_var L  A SAME-KIND BOUND, not a conferral witness. Read exactly:
#                the gate's own ``effective_functions.state_writes`` names the
#                variable IT rewrites, on ITS contract; the edge's label names
#                the authority slot on the DESTINATION's contract. Requiring the
#                two names to match is a name match across two different
#                contracts' storage, and it witnesses no composition step — no
#                row anywhere says that seizing A's ``owner`` lets its holder
#                exercise A's ownership of B. What the match does is REFUSE
#                every hop whose authority is of a different kind from the one
#                the gate is witnessed to seize, which is a bound, and a bound
#                is all it is published as. ownership.transfer is witnessed
#                writing owner/_owner; authority.replace writing authority;
#                roles.grant writing _roles. None is witnessed writing hook,
#                vault, roleRegistry or endpoint, so hops running on those are
#                refused. A same-kind hop is walked as the label-presence test
#                already walked it — this bound removes hops, it adds no
#                evidence to the ones that survive.
#
#                Where the kinds differ the hop is NOT disproved and the row is
#                not the only thing missing: whether the seized gate reaches the
#                other authority turns on the intermediate node's own function
#                surface, and THIS PLANE DOES NOT CONSULT IT. The surface often
#                exists — 0x4df6b733's setUserRole, setRoleCapability and
#                transferOwnership are analysed ``effective_functions`` rows on
#                the reference corpus — so this is a join not performed, not a
#                witness that is missing. The join that would decide it is the
#                intermediate node's own functions (``effective_functions``
#                at A, gated by the authority the capability seizes) against its
#                outbound targets (``effective_functions.sinks`` /
#                ``effect_targets``, and the ``external_call_target`` edges
#                CONTROL_RELATIONS excludes): does a function of A that the
#                seized gate lets its holder call exercise A's authority over B.
#                Until that runs, the hop is not_determined — withheld and
#                published, never walked and never counted as a proven negative.
#
# One residual, named rather than assumed away: the ROLE branch asks only what
# the role licenses at the destination. It does not additionally require the
# seizing capability to be one that governs role assignment, so an
# ``authority.replace`` gate walks a ``roles N`` hop on the join's answer alone.
# That is the same homogeneity question the state-variable branch answers with
# state_writes, and there is no equivalent witness for it — the role edge names a
# role, not the authority slot that grants it. The bound stated here is therefore
# what the role LICENSES, which is the bound a compositional magnitude needs, and
# it is an upper bound on what this gate can exercise.
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

# ``state_writes[].origin``: a write in the function BODY is the function doing
# it. A write attributed to a guard is the modifier's bookkeeping (a reentrancy
# latch, a namespaced-storage pointer read) and is not what the capability
# rewrites, so it is not evidence of the authority the gate seizes.
_WRITE_ORIGIN_BODY = "body"


@dataclass(frozen=True, order=True)
class LicensedFunction:
    """One named function a role licenses at a destination.

    Structured, not a formatted string: the selector is the join key back into
    ``effective_functions`` and the name is for the reader. Publishing
    ``"0x39d6ba32 enter"`` made every consumer re-parse a string this plane had
    already taken apart, and a function name containing a space would have
    broken the parse silently.
    """

    selector: str
    name: str

    def as_json(self) -> dict[str, str]:
        return {"selector": self.selector, "name": self.name}


@dataclass(frozen=True)
class ConferralVerdict:
    """Whether one gate confers one hop, and what it confers there."""

    outcome: str
    licensed: tuple[LicensedFunction, ...] = ()
    basis: str = ""

    @property
    def conferred(self) -> bool:
        return self.outcome == CONFERRAL_CONFERRED


@dataclass(frozen=True)
class GateGrant:
    """One gate-control capability instance, and what its witness says it seizes.

    ``rewrites`` is read from the SPECIFIC function the signal was witnessed on,
    not from the capability's class-wide behaviour: the claim being tested is
    what THIS gate rewrites. ``writes_extracted`` keeps the coverage gap distinct
    from an empty answer — a function whose ``state_writes`` never ran rewrites
    nothing anyone read, which is not the same fact as a function proven to
    rewrite nothing, and both are withheld rather than either being walked.
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

    ``role_functions`` is the role -> selector join, already narrowed to
    selectors that name a function. ``writes_by_function`` is per-function and is
    what the walk consults; ``writes_by_capability`` is the same evidence rolled
    up to the class and is used ONLY by the census, which has no instance to ask.
    The two are published side by side because the class-wide union is an upper
    bound on the per-function answer, and a reader comparing a census count to a
    finding's walk has to be able to see which one they are looking at.
    """

    role_functions: dict[tuple[str, int], tuple[LicensedFunction, ...]] = field(default_factory=dict)
    writes_by_function: dict[int, frozenset[str]] = field(default_factory=dict)
    writes_by_capability: dict[str, frozenset[str]] = field(default_factory=dict)
    # The recovery key for a signal whose ``function_id`` no longer resolves.
    # Populated only where every function under the key agrees on what it
    # rewrites; a key two functions disagree under is left out, because a
    # recovered answer nobody can attribute to one row is a guess.
    writes_by_deployment_selector: dict[tuple[str, str], frozenset[str]] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def licensed_functions(self, destination: str, roles: tuple[int, ...]) -> tuple[LicensedFunction, ...]:
        """The named functions the union of ``roles`` licenses at ``destination``.

        The union is the honest read of a multi-role label: "roles 5,9" is one
        principal holding both, and each licenses what it licenses.
        """
        out: set[LicensedFunction] = set()
        for role in roles:
            out.update(self.role_functions.get((destination, int(role)), ()))
        return tuple(sorted(out))

    def grant_for(
        self, capability: str, function_id: int | None, *, entity: str | None = None, selector: str | None = None
    ) -> GateGrant:
        """What one gate seizes, by its own function where that still resolves.

        ``function_score_signals.function_id`` is ``ON DELETE SET NULL`` against
        ``effective_functions``, and a re-analysis DELETES and reinserts a
        contract's rows — so a persisted signal that outlives one re-analysis
        points at nothing, and this lookup would report every gate as
        "state_writes not extracted" and quietly stop walking hops it walked
        yesterday. The withhold would be counted and its CAUSE would be a stale
        foreign key, indistinguishable from an extraction that never ran.

        So a dangling reference falls back to the signal's own
        ``(deployment entity, selector)`` — the identity the signal carries in
        its own columns and the re-analysis preserves. The fallback is admitted
        only where every function under that key agrees on what it rewrites; a
        key two functions disagree under resolves to nothing, and the grant
        stays unextracted rather than picking one.
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
        """The class-wide grant: the UNION of what every witness of ``capability``
        rewrites anywhere in this protocol. Strictly wider than any one instance's
        grant, so it is a census instrument and never a walk input.
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
    """The role -> selector join and the capability -> rewritten-variable witness."""
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
        # An ARRAY is an extraction that ran; anything else never did, and the
        # two must not reach the walk as the same empty answer.
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
                # The step names a selector no analysed function of the target
                # carries. It licenses something, but not something this document
                # can name or later attribute a magnitude to, so it is counted
                # and not credited.
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
