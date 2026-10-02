"""``source_verified`` used to be ``bool(rglob("src/**/*.sol"))``, which reflects bundle paths, not verification; the
2026-07-28 run published FALSE for 9 of 90 verified contracts. It feeds the frontend confidence score.
"""

from __future__ import annotations

from services.static.contract_analysis_pipeline.core import _source_verified
from tests.cache_helpers import (  # noqa: F401
    _patch_static_worker_phases,
    db_session,
    requires_postgres,
)

_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract Subject {
    address public owner;
    uint256 public value;
    function poke(uint256 v) external { require(msg.sender == owner, "no"); value = v; }
}
"""


@requires_postgres
def test_the_static_worker_hands_the_pipeline_the_contract_rows_fact(db_session, monkeypatch):
    """NULL (410 rows at writing) especially must survive."""
    from db.models import Contract
    from db.queue import create_job, store_source_files
    from workers.static_worker import StaticWorker

    for index, fact in enumerate((True, False, None)):
        address = f"0x{index:040x}"
        job = create_job(db_session, {"address": address, "rpc_url": "https://rpc.example"})
        db_session.add(
            Contract(
                job_id=job.id,
                address=address,
                contract_name="TestContract",
                compiler_version="v0.8.24",
                language="solidity",
                evm_version="shanghai",
                source_format="flat",
                source_file_count=1,
                remappings=[],
                source_verified=fact,
            )
        )
        db_session.commit()
        store_source_files(db_session, job.id, {"src/TestContract.sol": "contract TestContract {}"})

        worker = StaticWorker()
        _patch_static_worker_phases(monkeypatch, worker)
        captured: dict = {}
        monkeypatch.setattr(
            worker,
            "_scaffold_project",
            lambda _dir, _sources, meta, *_a, **_kw: captured.update(meta),
        )
        worker.process(db_session, job)

        assert captured["source_verified"] is fact
        assert _source_verified(captured) is fact
