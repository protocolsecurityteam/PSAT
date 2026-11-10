"""A Safe's threshold is published only from a read of it; its owner count is not one."""

from __future__ import annotations

import uuid

from db.models import EffectiveFunction, FunctionPrincipal
from services.aggregations.company_overview import build_company_overview
from tests.conftest import requires_postgres
from tests.support.overview_builders import _add_contract, _add_job, _add_protocol, _addr

pytestmark = requires_postgres


def _safe_gated(session, details):
    p = _add_protocol(session, f"safe-threshold-{uuid.uuid4().hex[:8]}")
    addr = _addr("vault")
    job = _add_job(session, address=addr, protocol_id=p.id, name="Vault")
    vault = _add_contract(session, address=addr, job=job, protocol_id=p.id, contract_name="Vault")
    ef = EffectiveFunction(
        contract_id=vault.id,
        function_name="pause",
        selector="0x8456cb59",
        abi_signature="pause()",
        effect_labels=["pause_toggle"],
        effect_targets=[],
        action_summary="pause",
        authority_public=False,
        authority_roles=[],
    )
    session.add(ef)
    session.flush()
    safe = _addr("safe").lower()
    session.add(
        FunctionPrincipal(
            function_id=ef.id,
            address=safe,
            resolved_type="safe",
            origin="owner",
            principal_type="direct_owner",
            details=details,
        )
    )
    session.commit()
    payload = build_company_overview(session, p.name)
    return next(pr for pr in payload["principals"] if pr["address"] == safe)


def test_unread_threshold_publishes_no_threshold(db_session):
    owners = [_addr("o1").lower(), _addr("o2").lower(), _addr("o3").lower()]
    principal = _safe_gated(db_session, {"owners": owners})
    assert principal["details"]["owners"] == owners
    assert "threshold" not in principal["details"]


def test_read_threshold_is_published(db_session):
    owners = [_addr("o1").lower(), _addr("o2").lower(), _addr("o3").lower()]
    principal = _safe_gated(db_session, {"owners": owners, "threshold": 2})
    assert principal["details"]["threshold"] == 2
