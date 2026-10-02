from __future__ import annotations

from typing import Any, cast

import pytest

from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.constants import FREEZE_CAPABILITY_PROVEN
from services.scoring.schema import (
    FunctionSignal,
    PrincipalRef,
    Tri,
    entity_key,
    not_determined_signal_defaults,
)
from tests.support import composition_admission_fixtures as CA
from utils.scoring_status import (
    SEVERITY_STATE_PROVEN,
    VALUE_BOUND_FLOOR,
    VALUE_STATE_PROVEN_REACH,
)

C = "0x" + "a" * 40
VAULT = "0x" + "b" * 40
SAFE = "0x" + "2" * 40
EOA = "0x" + "3" * 40
OWNERS = tuple("0x" + c * 40 for c in "cdef")
KEY_C = entity_key("ethereum", C)
KEY_V = entity_key("ethereum", VAULT)


def sig(**over: Any) -> FunctionSignal:
    fields = not_determined_signal_defaults()
    fields["gate_inputs"] = {
        "exact_empty_credit": Tri.not_determined().to_json(),
        "latch_witness": Tri.not_determined().to_json(),
        "reach_magnitude_usd": Tri.not_determined().to_json(),
    }
    base: dict[str, Any] = dict(
        job_id=None,
        protocol_id=1,
        contract_id=1,
        chain="ethereum",
        deployment_address=C,
        function_name="f",
        claim_id="upgrade.implementation",
        selector="0xdeadbeef",
    )
    gates = over.pop("gates", None)
    base.update(fields)
    base.update(over)
    if gates:
        base["gate_inputs"] = {**base["gate_inputs"], **gates}
    return FunctionSignal(**base)


def flow_sig(**over: Any) -> FunctionSignal:
    gates = {
        "token_identity": Tri.not_determined().to_json(),
        "asset_class": Tri.not_determined().to_json(),
        "input_seeded": Tri.not_determined().to_json(),
        "contract_balance_seeded": Tri.not_determined().to_json(),
        "amount_capped_by_balance": Tri.not_determined().to_json(),
        "asset_identity": Tri.not_determined().to_json(),
        **over.pop("gates", {}),
    }
    return sig(claim_id="flow.out", gates=gates, **over)


def magnitude(usd: float) -> dict[str, Any]:
    """Otherwise every perimeter test would really test the reach-magnitude term."""
    return {"reach_magnitude_usd": Tri.proven("proven_floor", usd).to_json()}


def bounded_by_sheet(usd: float) -> dict[str, Any]:
    """The fold never substitutes the reached entity's sheet for a magnitude witness, so tests about exposure, ties
    or floors need one. Usually set to the sheet, where ``min(sheet, witness)`` leaves the sheet standing.
    """
    return {"reach_magnitude_usd": Tri.proven("proven_exact", usd).to_json()}


def proven(severity: float, basis: tuple[str, ...] = ("capability_class_base",)) -> dict[str, Any]:
    return {"severity": Tri.proven(SEVERITY_STATE_PROVEN, severity), "severity_basis": basis}


def reaches(*keys: str, bound: str = VALUE_BOUND_FLOOR) -> dict[str, Any]:
    return {
        "value_state": VALUE_STATE_PROVEN_REACH,
        "value_bound": bound,
        "value_entity_keys": tuple(sorted(keys)),
        "value_basis": "acting_entity",
    }


def facts(
    pid: int,
    address: str,
    resolved_type: str,
    *,
    chain: str = "ethereum",
    owners: tuple[str, ...] = (),
    threshold: int | None = None,
    delay: float | None = None,
    withheld: bool = False,
) -> P.PrincipalFacts:
    return P.PrincipalFacts(
        function_principal_id=pid,
        chain=chain,
        address=address.lower(),
        resolved_type=resolved_type,
        owners=frozenset(o.lower() for o in owners),
        threshold=threshold,
        delay_seconds=delay,
        protection_credit_withheld=withheld,
        protection_basis="safe_protection_absent(not_determined);credit_stands",
        resolver_bases=(),
        role_bindings=(),
    )


def value_plane(
    per_asset: dict[str, dict[str, float]] | None = None,
    contracts: tuple[str, ...] = (),
    alias: dict[str, str] | None = None,
    per_asset_state: dict[str, dict[str, str]] | None = None,
    asset_set_proven_complete: dict[str, dict] | None = None,
) -> P.ValuePlane:
    plane = P.ValuePlane()
    plane.per_asset = per_asset or {}
    plane.per_asset_state = per_asset_state or {}
    plane.asset_set_proven_complete = asset_set_proven_complete or {}
    plane.contract_entities = set(contracts) | set(plane.per_asset) | set(plane.per_asset_state)
    plane.alias = alias or {}
    plane.provenance = {"stub": True}
    return plane


# Built here so the state under test is the plane's rule, not one corpus's data.
SCANNED = {
    "source": "chain_log_sweep",
    "accounts_scanned": 1,
    "accounts_folded": 1,
    "accounts": ["0x" + "a" * 40],
    "swept_from_block": 0,
    "swept_through_block": 21_000_000,
    "basis": ["chain scan of blocks 0-21000000 over Transfer/TransferSingle/TransferBatch"],
}


def closure_of(
    adjacency: dict[str, set[str]] | P.ControlClosure | None,
    *,
    relation: str = "controller_value",
    label: str | None = "owner",
) -> P.ControlClosure:
    """Relation and label are stub detail; these tests assert reach membership.

    Pass a real closure to exercise scope.
    """
    if isinstance(adjacency, P.ControlClosure):
        return adjacency
    return P.ControlClosure(
        edges=tuple(
            P.ControlEdge(
                principal=principal,
                anchor=anchor,
                relation=relation,
                scope=P.parse_edge_scope(label, relation),
                witness=P.EDGE_WITNESS_CONTROL_GRAPH,
            )
            for principal, anchors in sorted((adjacency or {}).items())
            for anchor in sorted(anchors)
        )
    )


def condition_plane(
    *,
    licensed: dict[tuple[str, str], tuple[tuple[str, int, tuple[str, ...]], ...]] | None = None,
    by_entity: dict[str, tuple[tuple[str, int, tuple[str, ...]], ...]] | None = None,
) -> P.ConditionPlane:
    """Empty by default: no destination function analysed, so every hop stands on its edge."""

    def rows(spec):
        return {
            key: tuple(P.DestinationFunction(fid, name, conds) for name, fid, conds in entries)
            for key, entries in (spec or {}).items()
        }

    plane = P.ConditionPlane()
    plane.by_entity = rows(by_entity)
    plane.licensed = rows(licensed)
    plane.provenance = {"stub": True}
    return plane


class _StubConferral(P.ConferralPlane):
    """Stub signals have no persisted function, so the real ``state_writes`` lookup would confer nothing; the grant
    is stipulated visibly instead.
    """

    def __init__(self, rewrites, role_functions):
        super().__init__(role_functions=dict(role_functions or {}))
        self._rewrites = frozenset(rewrites)

    def grant_for(self, capability, function_id, *, entity=None, selector=None):
        return P.GateGrant(capability, self._rewrites, True, "stub(test)", self)

    def capability_grant(self, capability):
        return self.grant_for(capability, None)


def conferral_plane(*, rewrites=("owner",), role_functions=None) -> P.ConferralPlane:
    """``rewrites`` defaults to ``owner`` because ``closure_of`` labels edges ``owner``."""
    return _StubConferral(rewrites, role_functions)


def act_as_plane(
    call_sites: dict[tuple[str, str], tuple[tuple[str, str, str, bool, str | None], ...]] | None = None,
    reads: dict[tuple[str, str], tuple[str, str, int | None]] | None = None,
    destination_acl: dict[tuple[str, str], dict[str, P.DestinationAcceptance]] | None = None,
    read_kinds: dict[tuple[str, str], str] | None = None,
    read_failures: dict[tuple[str, str], tuple[str, int | None]] | None = None,
) -> P.ActAsPlane:
    """Empty by default, so no gate-control magnitude composes."""
    plane = P.ActAsPlane(
        call_sites=dict(call_sites or {}),
        reads=dict(reads or {}),
        destination_acl=dict(destination_acl or {}),
        read_kinds=dict(read_kinds or {}),
        read_failures=dict(read_failures or {}),
    )
    plane.provenance = {"stub": True}
    return plane


@pytest.fixture()
def fold(monkeypatch):

    def _run(
        signals,
        *,
        value=None,
        closure=None,
        principals=None,
        role_floors=None,
        eoas=None,
        discovery=None,
        conditions=None,
        conferral=None,
        act_as=None,
        deletability=None,
        routes=None,
    ):
        """``signals=None`` drives the persisted path.

        ``deletability`` defaults to the bypass because these cases vary the axes around the rule; its own arms are in
        ``tests/scoring/test_three_arm_composition.py``.
        """
        monkeypatch.setattr(P, "discovery_relation_entities", lambda s, p: discovery or {})
        monkeypatch.setattr(P, "load_value_plane", lambda s, p: value or value_plane())
        monkeypatch.setattr(P, "load_control_closure", lambda s, p: closure_of(closure))
        monkeypatch.setattr(P, "load_condition_plane", lambda s, p: conditions or condition_plane())
        monkeypatch.setattr(P, "load_conferral_plane", lambda s, p: conferral or conferral_plane())
        monkeypatch.setattr(P, "load_act_as_plane", lambda s, p: act_as or act_as_plane())
        monkeypatch.setattr(P, "load_deletability_plane", lambda s: deletability or CA.admits_every_principal())
        monkeypatch.setattr(P, "load_router_flow_plane", lambda s, p: routes or P.RouterFlowPlane())
        monkeypatch.setattr(P, "load_proven_eoa_entities", lambda s, p: eoas or set())
        monkeypatch.setattr(P, "load_role_holder_floors", lambda s, p: role_floors or {})
        monkeypatch.setattr(P, "load_principal_plane", lambda s, refs: principals or {})
        monkeypatch.setattr(P, "perimeter_state", lambda s, p: ("settled", {"pending_jobs": 0}))
        monkeypatch.setattr(P, "plane_row_counts", lambda s, p: {"stub": True})
        monkeypatch.setattr(P, "load_upgrade_provenance", lambda s, p: {"stub": True})
        monkeypatch.setattr(P, "unconsumed_reach_relations", lambda s, p: {"stub": True})
        monkeypatch.setattr(P, "load_ledgers", lambda s, p: {"stub": True})
        monkeypatch.setattr(P, "load_audit_posture", lambda s, p, v: {"stub": True})
        return FOLD.compute_protocol_score(cast(Any, None), 1, signals=signals)

    return _run


def _role_edge(label, principal=None, anchor=None):
    return P.ControlEdge(
        principal=principal or KEY_C,
        anchor=anchor or KEY_V,
        relation="role_principal",
        scope=P.parse_edge_scope(label, "role_principal"),
        witness=P.EDGE_WITNESS_CONTROL_GRAPH,
    )


# Reused so each test varies exactly one witness.
COMPOSED_SELECTOR = "0x18457e61"

# Single-hop cases never constrain the calling selector.
CALLING_SELECTOR = "0x2ddd62ce"


def _composing_case(**over: Any) -> dict[str, Any]:
    """Role 12 licenses ``exit`` at ``V``, which has a $1M ``flow.out`` witness, and a gated function of ``C`` calls
    it on a state variable holding ``V``.
    """
    case: dict[str, Any] = {
        "closure": P.ControlClosure(edges=(_role_edge("roles 12"),)),
        "conferral": conferral_plane(role_functions={(KEY_V, 12): (P.LicensedFunction(COMPOSED_SELECTOR, "exit"),)}),
        "act_as": act_as_plane(
            call_sites={(KEY_C, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, CALLING_SELECTOR),)},
            reads={(KEY_C, "vault"): (KEY_V, "eth_call", 25_657_731)},
        ),
        "value": value_plane({KEY_V: {"usdc": 5_000_000.0}}, contracts=(KEY_C,)),
    }
    case.update(over)
    return case


def _composing_signals() -> list[FunctionSignal]:
    gate = sig(
        claim_id="authority.replace",
        function_name="setAuthority",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(0.75),
        **reaches(KEY_C),
    )
    destination = flow_sig(
        deployment_address=VAULT,
        contract_id=2,
        function_name="exit",
        selector=COMPOSED_SELECTOR,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(2, "ethereum", SAFE),),
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_exact", 1_000_000.0).to_json()},
        **proven(0.9),
        **reaches(KEY_V),
    )
    return [gate, destination]


def _composing_principals() -> dict[int, P.PrincipalFacts]:
    return {1: facts(1, EOA, "eoa"), 2: facts(2, SAFE, "safe", owners=OWNERS, threshold=3)}


def _gate_row(document) -> dict[str, Any]:
    return next(f for f in document.findings if f["capability"] == "authority.replace")


# The corpus's solver -> teller -> vault chain. The teller holds nothing.
TELLER = "0x" + "7" * 40
KEY_T = entity_key("ethereum", TELLER)
# The selector the teller's ACL admits, and also the teller function hop 2 is issued from.
HOP1_SELECTOR = "0x3e64ce99"

HOP1_ACCEPTED = P.DestinationAcceptance(
    roles=(12,),
    membership_quality="exact",
    destination_function="bulkWithdraw",
    function_principal_id=14279,
)


def _two_hop_case(**over: Any) -> dict[str, Any]:
    """Hop 1: a parameter callee witnessed by the teller's ACL (role 12).

    Hop 2: the teller's ``vault`` pointer read on-chain.
    """
    case: dict[str, Any] = {
        "closure": P.ControlClosure(
            edges=(
                _role_edge("roles 12", anchor=KEY_T),
                _role_edge("roles 12", principal=KEY_T, anchor=KEY_V),
            )
        ),
        "conferral": conferral_plane(
            role_functions={
                (KEY_T, 12): (P.LicensedFunction(HOP1_SELECTOR, "bulkWithdraw"),),
                (KEY_V, 12): (P.LicensedFunction(COMPOSED_SELECTOR, "exit"),),
            }
        ),
        "act_as": act_as_plane(
            call_sites={
                (KEY_C, HOP1_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),),
                (KEY_T, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, HOP1_SELECTOR),),
            },
            reads={(KEY_T, "vault"): (KEY_V, "eth_call", 25_657_731)},
            destination_acl={(KEY_T, HOP1_SELECTOR): {KEY_C: HOP1_ACCEPTED}},
        ),
        "value": value_plane({KEY_V: {"usdc": 5_000_000.0}}, contracts=(KEY_C, KEY_T)),
    }
    case.update(over)
    return case


# Pairs the higher selector with the weaker state so a first-arrival rule publishes the wrong one.
TIE_SELECTOR = "0xf6e715d0"
TIE_CALLING_SELECTOR = "0x244b0f6a"


def _tied_case(**over: Any) -> dict[str, Any]:
    """Each selector has its own calling function and pointer read, so a chain left on the losing candidate still
    looks well-formed.
    """
    case: dict[str, Any] = {
        "closure": P.ControlClosure(edges=(_role_edge("roles 12"),)),
        "conferral": conferral_plane(
            role_functions={
                (KEY_V, 12): (
                    P.LicensedFunction(COMPOSED_SELECTOR, "exit"),
                    P.LicensedFunction(TIE_SELECTOR, "manage"),
                )
            }
        ),
        "act_as": act_as_plane(
            call_sites={
                (KEY_C, COMPOSED_SELECTOR): (("bulkWithdraw", "restricted", "vault", True, CALLING_SELECTOR),),
                (KEY_C, TIE_SELECTOR): (
                    ("manageVaultWithMerkleVerification", "restricted", "vaultPtr", True, TIE_CALLING_SELECTOR),
                ),
            },
            reads={
                (KEY_C, "vault"): (KEY_V, "eth_call", 25_657_731),
                (KEY_C, "vaultPtr"): (KEY_V, "eth_call", 25_659_227),
            },
        ),
        "value": value_plane({KEY_V: {"usdc": 5_000_000.0}}, contracts=(KEY_C,)),
    }
    case.update(over)
    return case


def _tied_signals(*, tie_usd: float = 1_000_000.0) -> list[FunctionSignal]:
    signals = _composing_signals()
    signals.append(
        flow_sig(
            deployment_address=VAULT,
            contract_id=2,
            function_name="manage",
            selector=TIE_SELECTOR,
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(2, "ethereum", SAFE),),
            witness_tier="behavioral_observed",
            gates={"reach_magnitude_usd": Tri.proven("proven_floor", tie_usd).to_json()},
            **proven(0.9),
            **reaches(KEY_V),
        )
    )
    return signals


def _cc_row(document, capability: str = "upgrade.implementation") -> dict[str, Any]:
    return next(f for f in document.findings if f["capability"] == capability)


# Shared across the redteam modules.
SAFE2 = "0x" + "5" * 40
TIMELOCK = "0x" + "7" * 40
PROXY = "0x" + "6" * 40
IMPL = "0x" + "9" * 40
KEY_PROXY = entity_key("ethereum", PROXY)
KEY_IMPL = entity_key("ethereum", IMPL)


def pause_sig(**over: Any) -> FunctionSignal:
    gates = {
        "pause_effective": Tri.not_determined().to_json(),
        "freeze_recovery_principals": Tri.not_determined().to_json(),
        "freeze_coverage_fraction": Tri.not_determined().to_json(),
        **over.pop("gates", {}),
    }
    return sig(claim_id="pause.set", gates=gates, **over)


def _pause_document(fold, pauser: P.PrincipalFacts, recovery: P.PrincipalFacts | None):
    entries = [{"function_principal_id": 2, "chain": "ethereum", "address": recovery.address}] if recovery else None
    signal = pause_sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", pauser.address),),
        gates=(
            {"freeze_recovery_principals": Tri.proven("enumerated", entries).to_json()} if entries is not None else {}
        ),
        **proven(FREEZE_CAPABILITY_PROVEN, ("freeze_capability_proven",)),
        **reaches(KEY_C),
    )
    principals = {1: pauser}
    if recovery is not None:
        principals[2] = recovery
    return fold([signal], principals=principals, value=value_plane({KEY_C: {"usdc": 5_000_000.0}}))


class _Row:
    def __init__(self, usd, *, block=None, fetched=None, rid=0, raw="1000000"):
        self.usd_value = usd
        self.block_number = block
        self.fetched_at = fetched
        self.id = rid
        self.raw_balance = raw


def _reduce(**buckets):
    return P._reduce_observations({("k", "asset"): {a: rows for a, rows in buckets.items()}})


KEY_ZERO = entity_key("ethereum", "0x" + "0" * 40)


def _perimeter_signal():
    return sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(1_000_000.0),
        **proven(1.0),
        **reaches(KEY_C),
    )


INITIATOR_GUARD = "initiator != address(this)"


def _queue_signal(claim: str, **over: Any) -> FunctionSignal:
    return sig(
        claim_id=claim,
        function_name="setAuthority",
        deployment_address=C,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(0.75),
        **reaches(KEY_C),
        **over,
    )


def _var_edge(label, principal=None, anchor=None):
    return P.ControlEdge(
        principal=principal or KEY_C,
        anchor=anchor or KEY_V,
        relation="controller_value",
        scope=P.parse_edge_scope(label, "controller_value"),
        witness=P.EDGE_WITNESS_CONTROL_GRAPH,
    )


ACL_CALL_SITES = {(KEY_C, COMPOSED_SELECTOR): (("finishSolve", "restricted", "", True, CALLING_SELECTOR),)}
ACL_ACCEPTED = P.DestinationAcceptance(
    roles=(12,),
    membership_quality="exact",
    destination_function="bulkWithdraw",
    function_principal_id=14279,
)


def _acl_plane(**over: Any) -> P.ActAsPlane:
    case: dict[str, Any] = {
        "call_sites": ACL_CALL_SITES,
        "destination_acl": {(KEY_V, COMPOSED_SELECTOR): {KEY_C: ACL_ACCEPTED}},
    }
    case.update(over)
    return act_as_plane(**case)
