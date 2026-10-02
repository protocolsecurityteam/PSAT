"""Reconcile CLI:
verdicts recomputed from stored witnesses with EDGE VALIDITY re-verified —
zero drift on a freshly gated DB; seeded drift detected in report and fixed by
apply; the report is read-only.
"""

from __future__ import annotations

from db.models import (
    ContractCreationWitness,
)
from scripts.reconcile_membership import (
    audit,
    late_inheritance_would_admit,
)
from services.discovery import membership_gate as gate
from tests.conftest import ADDR, requires_postgres
from tests.support.membership_builders import _contract, _protocol

pytestmark = [requires_postgres]

_TX = "0x" + "ab" * 32


def _code_fact(session, address: str, *, absent: bool = False, tx: str | None = None) -> None:
    session.add(
        ContractCreationWitness(
            chain_id=1,
            address=address.lower(),
            code_probe_block=50,
            code_absent_at_probe=absent,
            creation_tx_hash=tx,
            creation_block=10 if tx else None,
        )
    )
    session.flush()


def test_report_counts_late_inheritance_candidates(db_session):
    """The report-mode observation names a pending candidate the
    late-arrival sweep would admit, admits nothing itself, and clears once the
    gate's next evaluate carries the candidate."""
    protocol = _protocol(db_session)
    deployer = ADDR(0xD7)
    for n in (0x30, 0x31):
        anchor = _contract(
            db_session, ADDR(n), protocol_id=protocol.id, nominated_protocol_id=protocol.id, deployer=deployer
        )
        _code_fact(db_session, anchor.address, tx=_TX)
        gate.write_witness(
            db_session,
            contract_id=anchor.id,
            protocol_id=protocol.id,
            rule="w1_code",
            evidence=gate.w1_evidence(chain_id=1, code_probe_block=50),
        )
        gate.write_witness(
            db_session,
            contract_id=anchor.id,
            protocol_id=protocol.id,
            rule="w6_llama_seed",
            evidence=gate.w6_evidence(adapter_slug="seed", chain_id=1, code_probe_block=50),
        )
    impl_address = ADDR(0x33)
    proxy = _contract(
        db_session, ADDR(0x32), nominated_protocol_id=protocol.id, deployer=deployer, implementation=impl_address
    )
    _code_fact(db_session, proxy.address, tx=_TX)
    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(proxy.id,)))
    assert proxy.protocol_id == protocol.id

    impl = _contract(db_session, impl_address, nominated_protocol_id=protocol.id)
    _code_fact(db_session, impl.address, tx=_TX)

    assert late_inheritance_would_admit(db_session) == [impl.id]
    assert impl.protocol_id is None
    assert audit(db_session) == []

    gate.evaluate(db_session, gate.FactsDelta(recheck_contract_ids=(impl.id,)))
    assert impl.protocol_id == protocol.id
    assert late_inheritance_would_admit(db_session) == []
