"""The performance migration recovers gaps without invalidating proven effects."""

import runpy
from pathlib import Path

from sqlalchemy import text

from db.models import EffectsPlanMarker, EffectVerdict
from tests.conftest import ADDR, requires_postgres
from tests.support.effects_builders import _contract, _fn, _protocol


@requires_postgres
def test_backfill_enrolls_unknown_effects_but_not_proven_findings(db_session):
    protocol = _protocol(db_session, "balance-backfill-scope")
    contract = _contract(db_session, protocol.id, ADDR(0x9911))
    proven = _fn(db_session, contract.id, name="withdraw", selector="0xdd000001")
    unknown = _fn(db_session, contract.id, name="mint", selector="0xdd000002")
    for fn, family, verdict in [(proven, "value_out", "proven"), (unknown, "supply", "unknown")]:
        db_session.add(
            EffectVerdict(
                function_id=fn.id,
                chain_id=1,
                contract_address=contract.address,
                selector=fn.selector,
                effect_class=family,
                verdict=verdict,
                tier="tier1",
            )
        )
    db_session.flush()
    migration = runpy.run_path(
        str(Path(__file__).resolve().parents[2] / "alembic/versions/d8e51f0a2b64_current_balance_collection.py")
    )
    rows = db_session.execute(text(migration["_AFFECTED_WORK"])).mappings().all()
    ours = {(row["function_id"], row["effect_family"]) for row in rows if row["protocol_id"] == protocol.id}
    assert ours == {(unknown.id, "supply")}
    # A stale empty-plan marker must not reenroll an already-proven function.
    db_session.add(EffectsPlanMarker(contract_id=contract.id, candidates_planned=2))
    db_session.flush()
    rows = db_session.execute(text(migration["_AFFECTED_WORK"])).mappings().all()
    ours = {(row["function_id"], row["effect_family"]) for row in rows if row["protocol_id"] == protocol.id}
    assert ours == {(unknown.id, "supply"), (unknown.id, "candidate_selection")}
