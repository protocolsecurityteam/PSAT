"""Collection migration must not enroll historical analysis for replay."""

import runpy
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations

from db.models import EffectsPlanMarker, EffectVerdict
from db.models.balance_work import PendingEffectsWork
from tests.conftest import ADDR, requires_postgres
from tests.support.effects_builders import _contract, _fn, _protocol


@requires_postgres
def test_upgrade_preserves_legacy_verdicts_and_does_not_backfill_recovery(db_session):
    protocol = _protocol(db_session, "no-balance-backfill")
    contract = _contract(db_session, protocol.id, ADDR(0x9911))
    contract.chain = None  # Unrelated legacy missing metadata must not block upgrade.
    for i, (family, verdict) in enumerate((("value_out", "proven"), ("supply", "unknown"), ("pause", "unknown"))):
        fn = _fn(db_session, contract.id, name=f"f{i}", selector=f"0xdd00000{i}")
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
    db_session.add(EffectsPlanMarker(contract_id=contract.id, candidates_planned=3))
    db_session.flush()
    migration = runpy.run_path(
        str(Path(__file__).resolve().parents[2] / "alembic/versions/d8e51f0a2b64_current_balance_collection.py")
    )
    # PostgreSQL DDL is transactional: exercise the real upgrade on legacy rows,
    # with the surrounding test transaction rolling back even if the test fails.
    migration["upgrade"].__globals__["op"] = Operations(MigrationContext.configure(db_session.connection()))
    migration["downgrade"]()
    migration["upgrade"]()
    assert db_session.query(PendingEffectsWork).count() == 0
    assert db_session.query(EffectVerdict).filter_by(contract_address=contract.address).count() == 3
    assert db_session.query(EffectsPlanMarker).filter_by(contract_id=contract.id).count() == 1
