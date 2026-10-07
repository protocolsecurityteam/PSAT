from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from sqlalchemy.orm import Session

from db.creation_witnesses import upsert_creation_witness
from db.models import ContractCreationWitness
from tests.conftest import requires_postgres


@requires_postgres
def test_concurrent_writers_merge_code_and_creation_facts(db_session):
    address = "0x" + "73" * 20
    barrier = Barrier(2)

    def write(fields):
        with Session(db_session.bind) as session:
            barrier.wait(timeout=10)
            upsert_creation_witness(session, chain_id=1, address=address, **fields)
            session.commit()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(write, fields)
            for fields in [
                {"creation_tx_hash": "0x" + "ab" * 32, "creation_block": 10},
                {"code_probe_block": 20, "code_absent_at_probe": False},
            ]
        ]
        for future in futures:
            future.result(timeout=15)
    row = db_session.get(ContractCreationWitness, (1, address))
    assert row is not None
    assert row.creation_block == 10
    assert row.code_probe_block == 20
    assert row.code_absent_at_probe is False
    # An older or unanswered probe cannot erase the current code observation.
    upsert_creation_witness(
        db_session, chain_id=1, address=address, code_probe_block=9, code_absent_at_probe=True, creation_tx_hash=None
    )
    db_session.flush()
    assert row.code_probe_block == 20
    assert row.code_absent_at_probe is False
    assert row.creation_tx_hash == "0x" + "ab" * 32
