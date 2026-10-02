""":func:`admits_every_principal` answers deletability "yes" for everyone; never use it in a test about the rule
itself.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from services.scoring import planes as P

SET_AUTHORITY_SELECTOR = "0x7a9e5e4b"

# One stamped selector on every row let a hard-coded producer pass (B2-R N4).
SETTER_SELECTORS = {
    "setAuthority": SET_AUTHORITY_SELECTOR,
    "transferOwnership": "0xf2fde38b",
    "setUserRole": "0x67aff484",
    "setRoleCapability": "0x7d40583d",
}


class _AdmitsEveryPrincipal(P.DeletabilityPlane):
    def setter_rows(
        self,
        chain: str,
        address: str,
        function_names: Iterable[str],
        principal_addresses: Iterable[str],
    ) -> tuple[P.SetterPrincipal, ...]:
        wanted = frozenset(function_names)
        if "setAuthority" not in wanted:
            return ()
        return tuple(
            P.SetterPrincipal(
                function_principal_id=1,
                chain=chain,
                contract_address=address.lower(),
                function_name="setAuthority",
                selector=SET_AUTHORITY_SELECTOR,
                principal_address=str(principal).lower(),
                membership_quality="exact",
            )
            for principal in sorted(principal_addresses)
        )


def admits_every_principal() -> P.DeletabilityPlane:
    return _AdmitsEveryPrincipal()


def deletability_plane(
    *,
    host: Iterable[tuple[str, str, str]] = (),
    authority: Iterable[tuple[str, str, str]] = (),
    gating: dict[tuple[str, str, str], tuple[str, ...]] | None = None,
    crosscheck: dict[tuple[str, str], tuple[str, ...]] | None = None,
    membership_quality: str = "exact",
) -> P.DeletabilityPlane:
    setters: dict[tuple[str, str], list[P.SetterPrincipal]] = {}
    next_id = 9000
    for rows, default_setter in ((host, "setAuthority"), (authority, "setUserRole")):
        for entity, principal, setter in rows:
            chain, _, address = entity.partition("::")
            key = (chain, address.lower())
            next_id += 1
            name = setter or default_setter
            setters.setdefault(key, []).append(
                P.SetterPrincipal(
                    function_principal_id=next_id,
                    chain=chain,
                    contract_address=address.lower(),
                    function_name=name,
                    selector=SETTER_SELECTORS[name],
                    principal_address=principal.lower(),
                    membership_quality=membership_quality,
                )
            )
    return P.DeletabilityPlane(
        setters={key: tuple(rows) for key, rows in setters.items()},
        gating=dict(gating or {}),
        crosscheck=dict(crosscheck or {}),
    )


def router_flow_plane(rows: Iterable[tuple[str, str, str, str | None, str | None]] = ()) -> P.RouterFlowPlane:
    flows: dict[tuple[str, str, str], list[P.RouterFlow]] = {}
    for entity, calling_selector, destination_selector, amount_kind, constraint in rows:
        chain, _, address = entity.partition("::")
        key = (chain, address.lower(), calling_selector.lower())
        flows.setdefault(key, []).append(
            P.RouterFlow(
                sink_id=f"{calling_selector}:sink0:external_call",
                destination_selector=destination_selector.lower(),
                amount_kind=amount_kind,
                target_constraint_state=constraint,
                target_constraint_guard=("hash_commitment" if constraint == "constrained" else None),
            )
        )
    return P.RouterFlowPlane(flows={key: tuple(rows_here) for key, rows_here in flows.items()})


def composed_document(
    fold: Any,
    *,
    signals: Any = None,
    deletability: P.DeletabilityPlane | None = None,
    routes: Iterable[tuple[str, str, str, str | None, str | None]] = (),
    case: dict[str, Any] | None = None,
) -> Any:
    # scoring_builders imports this module.
    from tests.support import scoring_builders as RT

    return fold(
        RT._composing_signals() if signals is None else signals,
        principals=RT._composing_principals(),
        deletability=deletability if deletability is not None else deletability_plane(),
        routes=router_flow_plane(routes),
        **(RT._composing_case() if case is None else case),
    )
