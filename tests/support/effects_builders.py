from __future__ import annotations

from decimal import Decimal
from typing import Any

from sqlalchemy.orm import Session

from db.models import Contract, ContractBalance, EffectiveFunction, FunctionPrincipal, Protocol


def _protocol(session: Session, name: str) -> Protocol:
    p = Protocol(name=name)
    session.add(p)
    session.flush()
    return p


def _contract(session: Session, protocol_id: int, addr: str, **kw) -> Contract:
    c = Contract(protocol_id=protocol_id, address=addr, **kw)
    session.add(c)
    session.flush()
    return c


# The shape every pre-mutability row carries (1,773/1,773 local rows).
_UNSET = object()


def _fn(
    session: Session,
    contract_id: int,
    *,
    name: str,
    selector: str | None = None,
    effect_targets: list[str] | None = None,
    claims=None,
    authority_public: bool = False,
    deployment_address: str | None = None,
    state_changing: bool | None = None,
    state_writes: Any = _UNSET,
    sinks: Any = _UNSET,
    writer_selectors: list[str] | None = None,
) -> EffectiveFunction:
    f = EffectiveFunction(
        contract_id=contract_id,
        function_name=name,
        selector=selector,
        effect_targets=effect_targets,
        claims=claims,
        authority_public=authority_public,
        deployment_address=deployment_address,
        state_changing=state_changing,
        writer_selectors=writer_selectors,
    )
    # The sentinel keeps proven-none (``[]``) distinct from not-determined in the call.
    if state_writes is not _UNSET:
        f.state_writes = state_writes
    if sinks is not _UNSET:
        f.sinks = sinks
    session.add(f)
    session.flush()
    return f


def _balance(
    session: Session, contract_id: int, usd: float | Decimal | str, *, raw_balance: str = "1000000000000000000"
) -> None:
    """Both writers only insert ``> 0``; pass ``"0"`` for the unwitnessed shape a reader must refuse."""
    session.add(
        ContractBalance(
            contract_id=contract_id,
            token_address=None,  # native
            raw_balance=raw_balance,
            decimals=18,
            usd_value=usd,
        )
    )


def _principal(session: Session, function_id: int, addr: str) -> None:
    session.add(FunctionPrincipal(function_id=function_id, address=addr))
