"""Signal, plane and case builders for the scoring fold.

Extracted verbatim from ``test_scoring_redteam``, which eight other test
modules imported these from.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.schema import (
    FunctionSignal,
    PrincipalRef,
    Tri,
    entity_key,
    not_determined_signal_defaults,
)
from tests import composition_admission_fixtures as CA
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
    """A ``flow.out`` signal carrying the gates the distiller always writes."""
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
    """A witnessed reach magnitude, so the reach-magnitude term is not the minimum.

    A perimeter test asserts on the perimeter; leaving the magnitude unwitnessed
    would make every one of them a test of the reach-magnitude term instead.
    """
    return {"reach_magnitude_usd": Tri.proven("proven_floor", usd).to_json()}


def bounded_by_sheet(usd: float) -> dict[str, Any]:
    """An EXACT magnitude witness, so the entity's sheet may bound the charge.

    A magnitude witness is the only thing that puts a dollar figure on a reach:
    the reached entity's balance sheet answers "how much is there", never "how
    much can this reach move", and the fold refuses to substitute one for the
    other. A test whose subject is the exposure budget, the tie disclosure or the
    floor flag needs a row that publishes dollars at all, so it carries the
    witness the real signal would have to carry — usually set to the sheet, which
    is the case where ``min(sheet, witness)`` leaves the sheet standing.
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
    # The confidence perimeter's base population, as the DB would supply it.
    plane.contract_entities = set(contracts) | set(plane.per_asset) | set(plane.per_asset_state)
    plane.alias = alias or {}
    plane.provenance = {"stub": True}
    return plane


# The chain-scan witness a proven-empty sheet cannot be published without. The
# reference corpus carries real ones now; these tests build theirs so the state
# under test is the plane's rule and not one corpus's data.
SCANNED = {
    "source": "chain_log_sweep",
    # Both figures, as the plane publishes them: a sheet is whole only where
    # every account it folds was scanned, so the denominator travels with the
    # numerator.
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
    """A ``ControlClosure`` from bare ``{principal: {anchor}}`` adjacency.

    The relation and label are stub witness detail — these tests assert on reach
    membership, which is the whole of what the closure carried before it carried
    scope. A test that means to exercise a scope builds its own closure and
    passes it here, where it goes straight through.
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
    """A ``ConditionPlane`` from ``{key: ((name, id, conditions), ...)}``.

    Empty by default, which is the "no destination function was analysed" state:
    the walk consults nothing, no caller condition is witnessed, and every hop
    stands on its edge — the behaviour every test written before the plane
    existed asserts.
    """

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
    """A conferral plane that answers for signals carrying no ``function_id``.

    The stub signals these tests build have no persisted function behind them,
    so the real per-function ``state_writes`` lookup would report every gate's
    rewrites as unextracted and no gate would confer anything. That is the right
    answer for a real signal and the wrong question for a test asserting reach
    membership over a hand-built closure, so the grant is stipulated instead —
    and the stipulation is visible in the call, not hidden in a default.
    """

    def __init__(self, rewrites, role_functions):
        super().__init__(role_functions=dict(role_functions or {}))
        self._rewrites = frozenset(rewrites)

    def grant_for(self, capability, function_id, *, entity=None, selector=None):
        return P.GateGrant(capability, self._rewrites, True, "stub(test)", self)

    def capability_grant(self, capability):
        return self.grant_for(capability, None)


def conferral_plane(*, rewrites=("owner",), role_functions=None) -> P.ConferralPlane:
    """What the gates in a test are stipulated to seize, and what roles license.

    ``rewrites`` defaults to ``owner`` because ``closure_of`` labels its edges
    ``owner``: a test written before conferral existed keeps asserting the reach
    membership it meant to assert. A test exercising the conferral test itself
    passes its own.
    """
    return _StubConferral(rewrites, role_functions)


def act_as_plane(
    call_sites: dict[tuple[str, str], tuple[tuple[str, str, str, bool, str | None], ...]] | None = None,
    reads: dict[tuple[str, str], tuple[str, str, int | None]] | None = None,
    destination_acl: dict[tuple[str, str], dict[str, P.DestinationAcceptance]] | None = None,
    read_kinds: dict[tuple[str, str], str] | None = None,
    read_failures: dict[tuple[str, str], tuple[str, int | None]] | None = None,
) -> P.ActAsPlane:
    """An ``ActAsPlane`` from bare call sites, receiver reads and destination ACLs.

    Empty by default, which is the honest state for every test written before
    composition existed: nothing witnesses that a seized node can be made to act
    anywhere, so no gate-control magnitude composes and the reach keeps the
    not_determined magnitude those tests assert on.
    """
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
    """Drive the fold with stubbed planes: no database, no network."""

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
        """``signals=None`` drives the PERSISTED path, through the population read.

        ``deletability`` defaults to the bypass every principal clears
        (``CA.admits_every_principal``), because these cases are about the axes
        AROUND the composition rule — ties, chain shapes, predicate blocks — and
        would otherwise all withhold. The rule's own arms are pinned in
        ``tests/test_three_arm_composition.py``.
        """
        monkeypatch.setattr(P, "discovery_relation_entities", lambda s, p: discovery or {})
        # ``universe`` is accepted and ignored: a hand-built plane carries
        # whatever disposition its own builder set, and the fold's default is
        # None anyway, so no test plane is disposed by accident.
        monkeypatch.setattr(P, "load_value_plane", lambda s, p, universe=None: value or value_plane())
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
        # The planes are stubbed, so the fold never touches a session.
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


# The flow.out selector the destination's own witness is written against, and
# the licence that names it. One pair, reused, so each test below varies exactly
# one witness.
COMPOSED_SELECTOR = "0x18457e61"

# The CALLING function's own selector — which function of the caller the call
# site sits in. A single-hop case never constrains it (the seized gate is what
# licenses hop 1), so one value serves all of them.
CALLING_SELECTOR = "0x2ddd62ce"


def _composing_case(**over: Any) -> dict[str, Any]:
    """A gate over ``C`` whose role licenses ``exit`` at ``V``, which moves $1M.

    Everything a composed magnitude needs, assembled once: the licence (role 12
    naming ``exit`` at the vault), the destination's own ``flow.out`` witness,
    and the act-as step (a restricted, authority-gated function of ``C`` calling
    that selector on a state variable read on-chain holding ``V``).
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


# The reference corpus's own solver -> teller -> vault chain. The teller is a
# ROUTER — it holds nothing — so a chain that dies at it recovers $0 and the
# only figure ever in play is the vault's own witness.
TELLER = "0x" + "7" * 40
KEY_T = entity_key("ethereum", TELLER)
# bulkWithdraw at the teller: the selector the teller's ACL admits the solver
# for, and — the same value in the other role — the OWN selector of the teller
# function hop 2 must then be issued from.
HOP1_SELECTOR = "0x3e64ce99"

HOP1_ACCEPTED = P.DestinationAcceptance(
    roles=(12,),
    membership_quality="exact",
    destination_function="bulkWithdraw",
    function_principal_id=14279,
)


def _two_hop_case(**over: Any) -> dict[str, Any]:
    """The whole chain, every link witnessed by a different shape.

    Hop 1 is the shape only the destination's ACL can witness: a restricted,
    authority-gated function of the seized node whose callee is a PARAMETER, and
    the teller's own access-control list naming the seized node for that
    selector by role 12. Hop 2 is the state-variable shape: the teller's
    ``vault`` pointer, read on-chain holding the vault. The money is at the far
    end of both.
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
        # The router holds nothing and the seized node holds nothing; every
        # dollar in this case is the vault's.
        "value": value_plane({KEY_V: {"usdc": 5_000_000.0}}, contracts=(KEY_C, KEY_T)),
    }
    case.update(over)
    return case


# A second licensed selector at the same destination, sorting ABOVE
# COMPOSED_SELECTOR. Pairing the higher selector with the WEAKER witness state
# is what makes these cases discriminating: iteration order offers the lower
# selector first, so a rule that kept the first arrival would publish the
# stronger state, and only a rule that ranks the state can pick the other one.
TIE_SELECTOR = "0xf6e715d0"
TIE_CALLING_SELECTOR = "0x244b0f6a"


def _tied_case(**over: Any) -> dict[str, Any]:
    """One entity, two licensed selectors, equal dollars, disagreeing states.

    Each selector is reached through its OWN calling function and its OWN
    pointer read, so the published chain names which of the two the entry was
    actually taken from — a chain left pointing at the losing candidate would
    still look well-formed.
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
    """The composing population plus ``manage``, priced at ``tie_usd``.

    ``exit`` keeps ``_composing_signals``' ``proven_exact`` and ``manage`` is a
    ``proven_floor``: the weaker state on the higher selector.
    """
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
