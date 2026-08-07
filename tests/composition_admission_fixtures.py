"""Stub planes for the two witnesses the composition rule decides an arm from.

The three-arm rule asks two questions of every composed candidate: can this
principal author the destination's calldata itself (``DeletabilityPlane``), and
what does the body the chain traverses do to that calldata
(``RouterFlowPlane``). Both are database-backed, so every fold-level test has to
supply them.

:func:`admits_every_principal` is a deliberate bypass and is named as one: it
answers the deletability question "yes" for everybody, so a test about some
OTHER axis of composition — a tie, a chain shape, a predicate block — still
composes. It must never be used by a test that is about the rule itself; those
build explicit rows with :func:`deletability_plane` and assert both arms.
"""

from __future__ import annotations

from collections.abc import Iterable

from services.scoring import planes as P

# A real Solmate ``setAuthority`` selector, so a fixture's basis block is
# checkable against the same shape the loader produces.
SET_AUTHORITY_SELECTOR = "0x7a9e5e4b"


class _AdmitsEveryPrincipal(P.DeletabilityPlane):
    """Every principal holds ``setAuthority`` at every destination it is asked about."""

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
    """The bypass. See the module docstring for when it is legitimate."""
    return _AdmitsEveryPrincipal()


def deletability_plane(
    *,
    host: Iterable[tuple[str, str, str]] = (),
    authority: Iterable[tuple[str, str, str]] = (),
    gating: dict[tuple[str, str, str], tuple[str, ...]] | None = None,
    crosscheck: dict[tuple[str, str], tuple[str, ...]] | None = None,
    membership_quality: str = "exact",
) -> P.DeletabilityPlane:
    """An explicit plane. ``host``/``authority`` are ``(entity_key, principal, setter)``."""
    setters: dict[tuple[str, str], list[P.SetterPrincipal]] = {}
    next_id = 9000
    for rows, default_setter in ((host, "setAuthority"), (authority, "setUserRole")):
        for entity, principal, setter in rows:
            chain, _, address = entity.partition("::")
            key = (chain, address.lower())
            next_id += 1
            setters.setdefault(key, []).append(
                P.SetterPrincipal(
                    function_principal_id=next_id,
                    chain=chain,
                    contract_address=address.lower(),
                    function_name=setter or default_setter,
                    selector=SET_AUTHORITY_SELECTOR,
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
    """``(intermediate entity_key, calling selector, destination selector, amount_kind, target_constraint)``."""
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
