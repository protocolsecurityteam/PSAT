"""Signal-row construction and severity."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from services.scoring import constants as K
from services.scoring.schema import (
    NOT_DETERMINED,
    FunctionSignal,
    PrincipalRef,
    Tri,
    entity_key,
    not_determined_signal_defaults,
)
from utils.execution_record import PROVING_EXECUTION_KEY
from utils.scoring_status import (
    DESTINATION_FREE_CLAIMS,
    DESTINATION_SHAPE_NOT_APPLICABLE,
    DESTINATION_STATE_NOT_APPLICABLE,
    NO_SELECTOR,
    OPENNESS_NOT_DETERMINED,
    OPENNESS_OPEN,
    OPENNESS_RESTRICTED,
    PRINCIPAL_STATE_ENUMERATED,
    PRINCIPAL_STATE_NONE_REQUIRED,
    PRINCIPAL_STATE_NOT_DETERMINED,
    REACH_GATE_LICENSED,
    REACH_GATE_NOT_DETERMINED,
    SEVERITY_STATE_PROVEN,
    VALUE_BOUND_EXACT,
    VALUE_BOUND_FLOOR,
    VALUE_BOUND_NOT_DETERMINED,
    VALUE_STATE_NOT_DETERMINED,
    VALUE_STATE_PROVEN_NO_REACH,
    VALUE_STATE_PROVEN_REACH,
)

from .claims import _amount_kinds, _best_tier, _claims, _tier
from .destination import (
    _UNDETERMINED_DESTINATION,
    _Destination,
    _exec_destination,
    _flow_destination,
    _fork_caller_arbitrary_param,
    _meet_destinations,
)
from .facts import (
    _W2_ARM_RANK,
    W2_INVARIANT_NOT_DETERMINED,
    W2_NO_STATE_VAR_RECEIVER,
    W2_PLANE_ABSENT,
    W2_SELECTOR_UNRESOLVED,
    W2_STATUS_NOT_RESOLVED,
    _ContractFacts,
    _f,
    _function_is_self_gated,
    _is_true,
    _lower,
)
from .flow_reach import (
    _cited_verdict_entry,
    _flow_reach,
    _no_reach,
    _proving_execution_gate,
    _Reach,
    _repointed_entities,
    _verdict_bearing_entries,
)
from .msg_value import (
    _MSG_VALUE_NOT_ASKED,
    MSG_VALUE_ARM_PASSTHROUGH,
    MSG_VALUE_ARM_SELF_RETURN,
    MSG_VALUE_REPETITION_RESIDUAL,
    _msg_value_return,
    _MsgValueReturn,
)
from .self_service import (
    _SELF_SERVICE_NOT_ASKED,
    SELF_SERVICE_BASIS,
    _flow_asset_class,
    _self_service_bound,
    _SelfServiceBound,
)

logger = logging.getLogger("services.scoring.distill")

# ---------------------------------------------------------------- the signals


def _signals_for_function(facts: _ContractFacts, func: Any, *, job_id: Any) -> list[FunctionSignal]:
    claims = _claims(func)
    if not claims:
        return []
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for claim in claims:
        claim_id = claim.get("claim_id")
        if claim_id:
            grouped[str(claim_id)].append(claim)

    # The register's own entity rule: the runtime address is
    # ``effective_functions.deployment_address`` falling back to
    # ``contracts.address``. The fallback is licensed there because a row with no
    # deployment address IS analysed at the contract's own address.
    deployment_address = _lower(func.deployment_address) if func.deployment_address else facts.address
    acting_key = entity_key(facts.chain, deployment_address)
    openness = _openness(func)
    principals = facts.principals.get(func.id, [])
    exact_empty, exact_empty_notes = _exact_empty_gate(func, principals)
    latch = _latch_gate(func)

    signals: list[FunctionSignal] = []
    for claim_id in sorted(grouped):
        signals.append(
            _build_signal(
                facts,
                func,
                claim_id=claim_id,
                entries=grouped[claim_id],
                all_claims=claims,
                deployment_address=deployment_address,
                acting_key=acting_key,
                openness=openness,
                principals=principals,
                exact_empty=exact_empty,
                exact_empty_notes=exact_empty_notes,
                latch=latch,
                job_id=job_id,
            )
        )
    return signals


def _openness(func: Any) -> str:
    value = func.authority_openness
    if value in (OPENNESS_OPEN, OPENNESS_RESTRICTED, OPENNESS_NOT_DETERMINED):
        return str(value)
    # NULL predates the column and cannot be read as any of the three; the
    # boolean sibling merges "restricted" with "unread" and is not consulted.
    return OPENNESS_NOT_DETERMINED


def _exact_empty_gate(func: Any, principals: list[Any]) -> tuple[Tri[dict[str, Any]], set[str]]:
    """The SERVED earned-negative gate. Never re-derived here (B16.3).

    The withheld arm is disclosed rather than dropped: a function whose caller
    set is an empty ``finite_set`` that did not earn the credit is neither
    unreachable nor reachable, and its shortfall names which witness is missing.
    """
    from services.policy.capability_surface import exact_empty_credit

    capability = func.capability_expr
    if not isinstance(capability, dict):
        return Tri[dict[str, Any]].not_determined(), set()
    verdict = exact_empty_credit(capability)
    if verdict.get("verdict") == "earned" and not principals:
        return Tri.proven("earned", verdict), set()
    notes: set[str] = set()
    if verdict.get("verdict") == "not_determined" and capability.get("members") == []:
        notes.add("empty_caller_set_not_earned")
    return Tri[dict[str, Any]].not_determined(), notes


def _latch_gate(func: Any) -> Tri[dict[str, Any]]:
    """A ``one_shot`` latch witness, if the resolver published one.

    ``consumed`` is a mutable now-fact — re-openable by the upgrade authority of
    the proxy it was read at — so it is carried as an annotation whose strength
    is tied to that authority, never as a permanent credit.
    """
    conditions = func.conditions
    if not isinstance(conditions, list):
        return Tri[dict[str, Any]].not_determined()
    for condition in conditions:
        if not isinstance(condition, dict) or condition.get("kind") != "one_shot":
            continue
        witness = condition.get("latch_witness")
        if not isinstance(witness, dict) or not witness.get("probe_block"):
            # Absent, or read at no reproducible height: the weakest branch.
            continue
        return Tri.proven(
            "witnessed",
            {
                "latch_state": condition.get("latch_state"),
                "latch_basis": witness.get("latch_basis"),
                "probe_block": witness.get("probe_block"),
                "probe_address": witness.get("probe_address"),
                "slot": witness.get("slot"),
                "reopenable_by": "the upgrade authority of the probed proxy",
            },
        )
    return Tri[dict[str, Any]].not_determined()


def _build_signal(
    facts: _ContractFacts,
    func: Any,
    *,
    claim_id: str,
    entries: list[dict[str, Any]],
    all_claims: list[dict[str, Any]],
    deployment_address: str,
    acting_key: str,
    openness: str,
    principals: list[Any],
    exact_empty: Tri[dict[str, Any]],
    exact_empty_notes: set[str],
    latch: Tri[dict[str, Any]],
    job_id: Any,
) -> FunctionSignal:
    fields: dict[str, Any] = not_determined_signal_defaults()
    notes: set[str] = set()
    citations: list[dict[str, Any]] = []
    gates: dict[str, Any] = {
        "exact_empty_credit": exact_empty.to_json(),
        "latch_witness": latch.to_json(),
        "reach_magnitude_usd": Tri[float].not_determined().to_json(),
    }

    notes.update(exact_empty_notes)
    fields["witness_tier"] = _best_tier({_tier(entry) for entry in entries})

    # --- destination -------------------------------------------------------
    destination = _UNDETERMINED_DESTINATION
    if claim_id in ("delegatecall.execute", "exec.arbitrary"):
        fork_param = _fork_caller_arbitrary_param(facts.verdicts.get(func.id, []))
        destination = _meet_destinations(
            [_exec_destination(claim_id, e.get("witness") or {}, fork_param) for e in entries]
        )
        gates["destination_basis"] = Tri.proven("basis", destination.basis).to_json()
    elif claim_id == "flow.out":
        destination = _meet_destinations([_flow_destination(e, all_claims, openness) for e in entries])
        gates["destination_basis"] = Tri.proven("basis", destination.basis).to_json()
    elif claim_id in DESTINATION_FREE_CLAIMS:
        destination = _Destination(
            tri=Tri.proven(DESTINATION_STATE_NOT_APPLICABLE, DESTINATION_SHAPE_NOT_APPLICABLE),
            severity=None,
            basis="not_applicable",
        )
    else:
        # Not in the bearing tuple is not the same as destination-free. A claim
        # this scorer has no destination model for publishes not_determined:
        # stamping "there is no destination here" from the absence of a rule is
        # the same absence-as-a-witness move in a quieter place.
        destination = _Destination(
            tri=Tri[str].not_determined(),
            severity=None,
            basis="destination_model_absent(not_determined)",
        )
    fields["destination"] = destination.tri
    notes.update(destination.notes)

    if claim_id == "flow.out" and not destination.tri.is_determined:
        for verdict in facts.verdicts.get(func.id, []):
            if verdict.verdict != "proven" or not verdict.concrete_destination:
                continue
            # Gated on ``shape_proved_by``: with no proven shape this is one
            # destination from one probe — an existential, which cannot prove a
            # fixed destination and does not enter the grade.
            citations.append(
                {
                    "field": "effect_verdicts.concrete_destination",
                    "value": _lower(verdict.concrete_destination),
                    "gate": "shape_proved_by=none",
                    "reading": "existential; observed on the witnessed path only",
                }
            )
            notes.add("concrete_destination_existential_not_a_fixed_destination")

    # --- severity ----------------------------------------------------------
    severity, severity_basis, severity_notes = _severity(
        facts,
        func,
        claim_id=claim_id,
        entries=entries,
        destination=destination,
        openness=openness,
        deployment_address=deployment_address,
        self_gated=_function_is_self_gated(facts, func),
        # Asked only where the flow set is what the claim is ABOUT; every other
        # claim carries the state where the question was never put.
        msg_value=_msg_value_return(all_claims) if claim_id == "flow.out" else _MSG_VALUE_NOT_ASKED,
        self_service=_self_service_bound(all_claims) if claim_id == "flow.out" else _SELF_SERVICE_NOT_ASKED,
    )
    fields["severity"] = severity
    fields["severity_basis"] = severity_basis
    notes.update(severity_notes)

    # --- authority / principals -------------------------------------------
    fields["authority_openness"] = openness
    if openness == OPENNESS_OPEN:
        fields["principal_state"] = PRINCIPAL_STATE_NONE_REQUIRED
        fields["principal_refs"] = ()
    elif principals:
        fields["principal_state"] = PRINCIPAL_STATE_ENUMERATED
        fields["principal_refs"] = tuple(
            PrincipalRef(function_principal_id=p.id, chain=facts.chain, address=_lower(p.address)) for p in principals
        )
    else:
        fields["principal_state"] = PRINCIPAL_STATE_NOT_DETERMINED
        fields["principal_refs"] = ()
        if severity.state == SEVERITY_STATE_PROVEN:
            notes.add("restricted_privileged_no_principal")

    # --- reach gate --------------------------------------------------------
    licensed = facts.licensed_reach_entities
    fields["reach_gate_state"] = REACH_GATE_LICENSED if licensed else REACH_GATE_NOT_DETERMINED
    if licensed:
        citations.append({"field": "gated_contract_backlink", "value": licensed})

    # --- value -------------------------------------------------------------
    reach = _reach_for_claim(
        facts,
        claim_id=claim_id,
        entries=entries,
        acting_key=acting_key,
        gates=gates,
        citations=citations,
    )
    extra_keys: list[str] = []
    if reach.state == VALUE_STATE_PROVEN_REACH and licensed:
        extra_keys = [entry["entity_key"] for entry in licensed]
    if licensed:
        # ``licensed`` is a fact about the GATE — this contract is the gating
        # contract of those vaults — and it is stamped whatever this signal's own
        # reach turned out to be. The licence is consumed as a reach key only
        # where the signal ALSO proved reach; on every other signal the state
        # names a witness that was cited and not spent, and reading it as a
        # consumed reach key is the laundering this field was corrected to stop.
        citations.append(
            {
                "field": "reach_gate_state",
                "value": REACH_GATE_LICENSED,
                "licensed_keys_cited": len(licensed),
                "licensed_keys_consumed": len(extra_keys),
                "reading": (
                    "licensed names the gate witness, not a consumed reach key: the keys are "
                    "added to this signal's reach only where the signal proved reach of its own"
                ),
            }
        )
    keys = tuple(sorted(set(reach.entity_keys) | set(extra_keys)))
    fields["value_state"] = reach.state
    fields["value_bound"] = reach.bound
    fields["value_entity_keys"] = keys if reach.state == VALUE_STATE_PROVEN_REACH else ()
    fields["value_basis"] = reach.basis
    gates["reach_magnitude_usd"] = reach.magnitude.to_json()
    # F6: the execution that PROVED the figure above, carried BESIDE it. The two
    # travel together or the fold publishes a number with no account of the call
    # it came from — which is what every consumer of this magnitude has had until
    # now, because the caller exists only inside the transcript blob.
    gates[PROVING_EXECUTION_KEY] = _proving_execution_gate(facts, func, entries).to_json()
    notes.update(reach.notes)

    # --- claim-scoped gates -------------------------------------------------
    if claim_id == "flow.out":
        gates.update(_flow_gates(facts, entries, all_claims, notes))
    if claim_id == "pause.set":
        gates.update(_pause_gates(facts, func, entries))

    # ONE rule, read once, so the signal's own citation and the execution record
    # in ``gate_inputs`` name the same verdict by construction. Every
    # verdict-bearing entry still travels as a citation below — the ambiguity is
    # disclosed, not collapsed — and a claim naming more than one says so in its
    # notes rather than letting stored order settle it in silence.
    cited = _cited_verdict_entry(entries)
    if cited is not None:
        fields["effect_verdict_id"] = int((cited.get("witness") or {})["effect_verdict_id"])
    if len(_verdict_bearing_entries(entries)) > 1:
        notes.add("multiple_effect_verdicts_on_one_claim")
    for entry in entries:
        witness = entry.get("witness") or {}
        verdict_id = witness.get("effect_verdict_id")
        if verdict_id is not None:
            verdict = next((v for v in facts.verdicts.get(func.id, []) if v.id == int(verdict_id)), None)
            # inv.9: a published verdict carries its transcript pointer, or is
            # published WITHOUT a traceability claim — never as "no transcript".
            citations.append(
                {
                    "field": "claims[].witness.effect_verdict_id",
                    "value": int(verdict_id),
                    "transcript_ptr": (verdict.transcript_ptr if verdict is not None else None) or NOT_DETERMINED,
                    "verdict": verdict.verdict if verdict is not None else NOT_DETERMINED,
                }
            )
        observed = witness.get("observed") or {}
        if observed.get("block_number") is not None:
            citations.append(
                {
                    "field": "observed.block_number",
                    "value": observed.get("block_number"),
                    "block_source": observed.get("block_source"),
                }
            )
    if isinstance(func.authority_roles, list) and func.authority_roles:
        citations.append(
            {
                "field": "effective_functions.authority_roles",
                "value": [r.get("role") for r in func.authority_roles if isinstance(r, dict)],
                "note": "role ids are meaningful only per registry; cited, never keyed on",
            }
        )

    fields["gate_inputs"] = gates
    fields["citations"] = tuple(citations)
    fields["witness_notes"] = tuple(sorted(notes))

    return FunctionSignal(
        job_id=job_id,
        protocol_id=facts.protocol_id,
        contract_id=facts.contract_id,
        chain=facts.chain,
        deployment_address=deployment_address,
        function_name=str(func.function_name),
        claim_id=claim_id,
        selector=str(func.selector or NO_SELECTOR),
        function_id=func.id,
        **fields,
    )


def _reach_for_claim(
    facts: _ContractFacts,
    *,
    claim_id: str,
    entries: list[dict[str, Any]],
    acting_key: str,
    gates: dict[str, Any],
    citations: list[dict[str, Any]],
) -> _Reach:
    if claim_id == "flow.out":
        best: _Reach | None = None
        for entry in entries:
            observed = (entry.get("witness") or {}).get("observed") or {}
            candidate = _flow_reach(observed, facts, acting_key)
            if best is None or _reach_rank(candidate) > _reach_rank(best):
                best = candidate
        reach = best or _no_reach("reach_not_witnessed(not_determined)")
        for entry in entries:
            keys, bases, refused = _repointed_entities(entry, facts)
            _cite_refused_repoints(refused, citations)
            if keys and reach.state == VALUE_STATE_PROVEN_REACH:
                reach = _Reach(
                    state=reach.state,
                    bound=reach.bound,
                    entity_keys=tuple(sorted(set(reach.entity_keys) | set(keys))),
                    basis=reach.basis + "+" + ",".join(bases),
                    # The magnitude the flow witness proved, unchanged. A repoint
                    # widens WHERE that one call's value may sit; it does not
                    # multiply the call, and the per-call cap holds the sum of
                    # the widened key set to the figure the witness proved.
                    magnitude=reach.magnitude,
                    notes=reach.notes + ("reach_repointed_by_witness",),
                )
                citations.append({"field": bases[0], "value": keys})
        return reach

    if claim_id == "pause.set":
        # FIELDS §5: the value membership is GATED on the fork proof that the
        # latch takes effect. Charging an entity whose latch is unproven is the
        # balance-sheet error, so an unproven latch reaches nothing.
        effective = any(
            _is_true(((e.get("witness") or {}).get("observed") or {}).get("pause_effective")) for e in entries
        )
        if not effective:
            return _no_reach("pause_effective_not_witnessed(not_determined)", ("freeze_effectiveness_not_determined",))
        return _Reach(
            state=VALUE_STATE_PROVEN_REACH,
            bound=VALUE_BOUND_FLOOR,
            entity_keys=(acting_key,),
            basis="value_held_at_frozen_entity(pause_effective)",
            magnitude=Tri[float].not_determined(),
            notes=("freeze_immobilised_fraction_not_determined",),
        )

    repointed: list[str] = []
    bases: list[str] = []
    for entry in entries:
        keys, entry_bases, refused = _repointed_entities(entry, facts)
        _cite_refused_repoints(refused, citations)
        repointed.extend(keys)
        bases.extend(entry_bases)
    if claim_id not in K.BASE_SEVERITY:
        # A named callee is not a capability. Reading the repoint as one is what
        # promoted six ``flow.in`` rows from capability_not_scored to
        # proven_reach purely because a witness named an address — an upgrade of
        # the reach STATE out of a fact about call structure.
        return _no_reach("capability_not_scored(not_determined)")
    keys = tuple(sorted({acting_key, *repointed}))
    basis = "acting_entity" + ("+" + ",".join(sorted(set(bases))) if bases else "")
    return _Reach(
        state=VALUE_STATE_PROVEN_REACH,
        bound=VALUE_BOUND_FLOOR,
        entity_keys=keys,
        basis=basis,
        magnitude=Tri[float].not_determined(),
    )


def _cite_refused_repoints(refused: list[dict[str, Any]], citations: list[dict[str, Any]]) -> None:
    """A declined repoint is published, never absent.

    An admitted repoint travels as a citation; a refused one that travelled as
    nothing would be indistinguishable from a witness that named no entity at
    all, and the two are opposite facts about how much reach this row is not
    claiming.
    """
    for entry in refused:
        citations.append(
            {"field": entry["basis"], "value": entry["entity_key"], "admitted": False, "why": entry["why"]}
        )


def _reach_rank(reach: _Reach) -> tuple[int, int]:
    state_rank = {VALUE_STATE_PROVEN_REACH: 2, VALUE_STATE_PROVEN_NO_REACH: 1, VALUE_STATE_NOT_DETERMINED: 0}
    bound_rank = {VALUE_BOUND_EXACT: 2, VALUE_BOUND_FLOOR: 1, VALUE_BOUND_NOT_DETERMINED: 0}
    return state_rank[reach.state], bound_rank[reach.bound]


def _flow_gates(
    facts: _ContractFacts, entries: list[dict[str, Any]], all_claims: list[dict[str, Any]], notes: set[str]
) -> dict[str, Any]:
    amount_kinds = _amount_kinds(all_claims)
    asset_class = _flow_asset_class(all_claims)
    observed_blocks = [(e.get("witness") or {}).get("observed") or {} for e in entries]
    identity, refusal = _token_identity(facts, entries)
    identity_json = identity.to_json()
    if refusal is not None:
        # The arm travels twice on purpose: in the envelope, where the persisted
        # signal carries it, and in the notes, which are the only path onto the
        # document. The three-state itself is untouched — a named refusal is
        # still a refusal.
        identity_json["not_determined_reason"] = refusal
        notes.add(refusal)
        if refusal == W2_PLANE_ABSENT:
            identity_json["asset_identity_plane_state"] = facts.asset_identity_state
            notes.add(f"asset_identity_plane_{facts.asset_identity_state}")
    return {
        # ``token_identity`` proves exactly one NON-FUNGIBLE token moves, which
        # forbids pricing the row off a fungible balance sheet.
        "token_identity": (
            Tri.proven("proven", True) if "token_identity" in amount_kinds else Tri[bool].not_determined()
        ).to_json(),
        "asset_class": (Tri.proven("proven", asset_class) if asset_class else Tri[str].not_determined()).to_json(),
        "input_seeded": (
            Tri.proven("proven", True)
            if any(_is_true(o.get("input_seeded")) for o in observed_blocks)
            else Tri[bool].not_determined()
        ).to_json(),
        "contract_balance_seeded": (
            Tri.proven("proven", True)
            if any(_is_true(o.get("contract_balance_seeded")) for o in observed_blocks)
            else Tri[bool].not_determined()
        ).to_json(),
        "amount_capped_by_balance": (
            Tri.proven("proven", True) if "capped_by_balance" in amount_kinds else Tri[bool].not_determined()
        ).to_json(),
        "asset_identity": identity_json,
    }


def _token_identity(facts: _ContractFacts, entries: list[dict[str, Any]]) -> tuple[Tri[dict[str, Any]], str | None]:
    """The W2 pricing precondition: is the moved asset's identity decidable?

    Satisfied only by a state-variable receiver whose address RESOLVED with a
    non-``not_determined`` invariant. A caller-named receiver fails it — a
    demotion, in the honest direction — and an absent plane is ``not_determined``
    because the plane did not run, never "no asset".

    Returns the answer AND, where it is ``not_determined``, the arm that refused
    it: five distinct conjuncts reach the same third state, and a refusal that
    does not name itself is one a reader cannot act on. The token is the arm the
    walk got FURTHEST on across all entries — the entry that reached the
    invariant check says so, rather than being reported as the coarser miss some
    other entry took.
    """
    if not facts.asset_identity:
        return Tri[dict[str, Any]].not_determined(), W2_PLANE_ABSENT
    arms: set[str] = set()
    for entry in entries:
        witness = entry.get("witness") or {}
        for sink_id, receiver in sorted((witness.get("sink_receivers") or {}).items()):
            if not isinstance(receiver, dict):
                continue
            if receiver.get("receiver_provenance") != "contract_state_unresolved":
                arms.add(W2_NO_STATE_VAR_RECEIVER)
                continue
            selector = receiver.get("auto_getter_selector")
            resolved = facts.asset_identity.get(str(selector)) if selector else None
            if not isinstance(resolved, dict):
                arms.add(W2_SELECTOR_UNRESOLVED)
                continue
            if resolved.get("asset_address_status") != "resolved":
                arms.add(W2_STATUS_NOT_RESOLVED)
                continue
            if resolved.get("asset_identity_invariant") in (None, NOT_DETERMINED):
                arms.add(W2_INVARIANT_NOT_DETERMINED)
                continue
            return (
                Tri.proven(
                    "resolved",
                    {
                        "sink_id": sink_id,
                        "asset_address": resolved.get("asset_address"),
                        "observed_at_block": resolved.get("observed_at_block"),
                        "asset_identity_invariant": resolved.get("asset_identity_invariant"),
                    },
                ),
                None,
            )
    furthest = next((arm for arm in reversed(_W2_ARM_RANK) if arm in arms), W2_NO_STATE_VAR_RECEIVER)
    return Tri[dict[str, Any]].not_determined(), furthest


def _pause_gates(facts: _ContractFacts, func: Any, entries: list[dict[str, Any]]) -> dict[str, Any]:
    observed_blocks = [(e.get("witness") or {}).get("observed") or {} for e in entries]
    effective = any(_is_true(o.get("pause_effective")) for o in observed_blocks)
    blast: list[str] = []
    for observed in observed_blocks:
        blast.extend(str(x) for x in (observed.get("observed_blast_radius") or []))
    recovery = facts.pause_unset_principals
    return {
        "pause_effective": (Tri.proven("proven", True) if effective else Tri[bool].not_determined()).to_json(),
        "freeze_recovery_principals": (
            Tri.proven("enumerated", recovery) if recovery else Tri[list].not_determined()
        ).to_json(),
        # A count ratio over function names is a COVERAGE fraction, never a
        # fraction of dollars; it is cited and never multiplied into value.
        "freeze_coverage_fraction": (
            Tri.proven("observed_blast_radius", sorted(set(blast))) if blast else Tri[list].not_determined()
        ).to_json(),
    }


def _severity(
    facts: _ContractFacts,
    func: Any,
    *,
    claim_id: str,
    entries: list[dict[str, Any]],
    destination: _Destination,
    openness: str,
    deployment_address: str,
    self_gated: bool = False,
    msg_value: _MsgValueReturn = _MSG_VALUE_NOT_ASKED,
    self_service: _SelfServiceBound = _SELF_SERVICE_NOT_ASKED,
) -> tuple[Tri[float], tuple[str, ...], set[str]]:
    # The ``msg_value`` default is the state where the question was never put —
    # it publishes nothing and moves nothing, so a caller that omits it loses the
    # witness rather than gaining a verdict.
    notes: set[str] = set()

    if claim_id in K.UNMODELLED_CLAIMS:
        notes.add("claim_type_not_scored")
        return Tri[float].not_determined(), (), notes
    if claim_id in K.PRODUCT_CLAIMS:
        # ``claim_id`` does not prove permissionlessness, so a not_determined
        # openness is not product and is surfaced rather than dropped.
        if openness == OPENNESS_NOT_DETERMINED:
            notes.add("product_claim_reachability_unproven")
        else:
            notes.add("product_surface")
        return Tri[float].not_determined(), (), notes
    if claim_id not in K.BASE_SEVERITY:
        notes.add("capability_has_no_severity_model")
        return Tri[float].not_determined(), (), notes

    if claim_id in K.DESTINATION_BEARING_SEVERITY:
        # Published whatever the destination turns out to be: what the flow set
        # proved about the amount is a fact about the amount, and a withheld
        # destination is not a reason to un-say it.
        notes.update(msg_value.notes)
        if msg_value.arm == MSG_VALUE_ARM_SELF_RETURN and destination.tri.is_determined:
            # AHEAD of the withhold, and conditional on it: the open-caller arm
            # withholds the price *pending an amount witness*, and this IS that
            # witness. Reading the withhold first would leave the row carrying
            # both "no witness bounds this payout" and the witness that bounds
            # it. The gate is the destination being PROVEN, not priced — an
            # unread destination still reaches nothing here, so the arm cannot
            # fire on a payee nobody read. The wave-4 self-service consumer arm
            # sits beside this one the same way, for the same reason.
            #
            # What the zero rests on: the caller is paid its own attached value,
            # to itself, on the function's ONE out-flow entry, so the payout
            # moves no position the caller did not just fund. How many times one
            # call makes that payment is a question this witness did not ask,
            # and the residual note says so.
            return (
                Tri.proven(SEVERITY_STATE_PROVEN, K.FLOW_SEVERITY_MSG_VALUE_SELF_RETURN),
                (MSG_VALUE_ARM_SELF_RETURN,),
                notes | {MSG_VALUE_REPETITION_RESIDUAL},
            )
        # The PASS-THROUGH arm, ruled in by the owner (W3b): the caller's own
        # msg.value reaching a fixed payee it cannot name. Beside the self-return
        # arm and for the same reason — AHEAD of the withhold, gated on a PROVEN
        # destination — the amount moved is bounded by what the caller just
        # attached, so it is uncharged product surface and scores 0.0. Its basis
        # names the arm, which is how ``fold._uncharged_product`` excludes it.
        if msg_value.arm == MSG_VALUE_ARM_PASSTHROUGH and destination.tri.is_determined:
            return (
                Tri.proven(SEVERITY_STATE_PROVEN, K.FLOW_SEVERITY_MSG_VALUE_PASSTHROUGH),
                (MSG_VALUE_ARM_PASSTHROUGH,),
                notes,
            )
        # The self-service consumer arm, sitting beside the msg_value arms for the
        # same reason and with the same gate: an open-caller payout has its
        # destination PROVEN and its severity withheld pending an amount witness,
        # and W1 ∧ W2 IS that witness. Evaluated BEFORE the ``severity is None``
        # withhold so a proven row is reachable (SPEC §4 compose-ordering); gated
        # on the destination being determined, never priced, so it cannot fire on
        # a payee nobody read; and a REFUSED conjunction falls through to the
        # withhold below, never to a cheaper number.
        if claim_id == "flow.out" and self_service.proven and destination.tri.is_determined:
            return (
                Tri.proven(SEVERITY_STATE_PROVEN, K.FLOW_SEVERITY_SELF_SERVICE_BOUNDED),
                (SELF_SERVICE_BASIS,),
                notes | set(self_service.notes),
            )
        if destination.severity is None:
            # A withheld price has two different reasons and one token cannot
            # carry both: an unread destination, or a proven destination whose
            # price waits on a witness of its own.
            notes.add(
                "destination_not_determined_row_withheld"
                if not destination.tri.is_determined
                else "flow_severity_withheld_pending_amount_witness"
            )
            # A self-service witness that was ASKED and refused names why on the
            # row it leaves withheld, so the refusal is not lost to silence. A
            # not-asked / proven-but-unread-destination witness adds nothing here.
            refusal = self_service.refusal_note
            if refusal is not None:
                notes.add(refusal)
            return Tri[float].not_determined(), (), notes
        return Tri.proven(SEVERITY_STATE_PROVEN, destination.severity), (destination.basis,), notes

    if claim_id == "pause.set":
        return _pause_severity(entries, notes)

    base = K.BASE_SEVERITY[claim_id]
    basis = ["capability_class_base"]

    if claim_id == "ownership.transfer":
        if any((e.get("witness") or {}).get("standard") == "default_admin_rules" for e in entries):
            base = min(base, K.OWNERSHIP_DEFAULT_ADMIN_RULES)
            basis.append("default_admin_rules_enforced_delay")
    elif claim_id == "authority.replace":
        owner = facts.registry_owner
        if owner and facts.solmate_mutators:
            # Escalation gated on POSITIVE proof: an owner resolves AND the role
            # mutators it would need are present on this contract.
            base = K.DEST_SEVERITY_UNCONSTRAINED
            basis.append("registry_owner_self_grant_escalation")
            notes.add("owner_may_grant_itself_any_role_on_this_registry")
        elif owner:
            notes.add("registry_escalation_mutators_unverified")
    elif claim_id == "timelock.set_delay":
        # No credit either way. "Every resolved principal is the contract itself"
        # is "no other caller RESOLVED", and the principal enumeration is a proven
        # LOWER BOUND on the caller set — the one thing it can never witness is
        # that the set is closed. The observation is published; the severity does
        # not move on it.
        notes.add("delay_gate_self_gated_lower_bound" if self_gated else "delay_change_gate_not_self_gated")

    return Tri.proven(SEVERITY_STATE_PROVEN, base), tuple(basis), notes


def _pause_severity(entries: list[dict[str, Any]], notes: set[str]) -> tuple[Tri[float], tuple[str, ...], set[str]]:
    """Built up from zero, from proven components only.

    The proven existence of a freeze capability is the first and unconditional
    component; a proven auto-expiry refines it downward. The sustainable-freeze
    component is added by the fold, and only where key-set dependence is PROVEN.
    Every undetermined recovery question — no recovery claim, an unresolved
    recovery principal, an unread freezing key set — leaves this rung exactly
    where it is, in either direction.
    """
    severity = K.BASE_SEVERITY["pause.set"] + K.FREEZE_CAPABILITY_PROVEN
    basis = ["freeze_capability_proven"]
    for entry in entries:
        observed = (entry.get("witness") or {}).get("observed") or {}
        bound = _f(observed.get("duration_bound_seconds"))
        if observed.get("auto_expiry") is True and bound is not None and bound <= K.FREEZE_AUTO_EXPIRY_MAX_SECONDS:
            severity = min(severity, K.FREEZE_AUTO_EXPIRY)
            basis.append("auto_expiry_witnessed")
        elif observed.get("auto_expiry") is False:
            # The fork CONTRADICTED the static constant. Recorded; no witness
            # sets the size of a raise, so none is taken.
            notes.add("fork_contradicted_static_duration_bound")
    return Tri.proven(SEVERITY_STATE_PROVEN, severity), tuple(basis), notes
