"""``source_verified`` used to be ``bool(rglob("src/**/*.sol"))``, which reflects bundle paths, not verification; the
2026-07-28 run published FALSE for 9 of 90 verified contracts. It feeds the frontend confidence score.
"""

from __future__ import annotations

import json
from pathlib import Path

from services.discovery.fetch import scaffold
from services.static import collect_contract_analysis
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


def test_the_discovery_scaffolder_records_the_payloads_verification_fact(tmp_path: Path):
    result = {
        "ContractName": "FlatContract",
        "CompilerVersion": "v0.8.19+commit.7dd6d404",
        "OptimizationUsed": "0",
        "Runs": "0",
        "EVMVersion": "",
        "LicenseType": "MIT",
        "SourceCode": "pragma solidity ^0.8.19; contract FlatContract {}",
    }
    project_dir = scaffold("0x1234", result, tmp_path / "FlatContract")
    meta = json.loads((project_dir / "contract_meta.json").read_text())
    assert meta["source_verified"] is True
    assert _source_verified(meta) is True

    # ``get_source`` raises first on empty ``SourceCode``, but the value is still read off the payload.
    unverified = scaffold("0x1234", {**result, "SourceCode": ""}, tmp_path / "Unverified")
    assert json.loads((unverified / "contract_meta.json").read_text())["source_verified"] is False


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


def _project(tmp_path: Path, src_dir: str, meta_extra: dict) -> Path:
    project_dir = tmp_path / f"proj_{src_dir}"
    (project_dir / src_dir).mkdir(parents=True)
    (project_dir / src_dir / "Subject.sol").write_text(_SOURCE)
    (project_dir / "foundry.toml").write_text(
        f'[profile.default]\nsrc = "{src_dir}"\nout = "out"\nlibs = ["lib"]\nsolc_version = "0.8.19"\n'
    )
    (project_dir / "contract_meta.json").write_text(
        json.dumps(
            {
                "address": "0x028271e30a695c0527a0c50ca30603fed004cdb0",
                "contract_name": "Subject",
                "compiler_version": "v0.8.19+commit.7dd6d404",
                **meta_extra,
            }
        )
        + "\n"
    )
    return project_dir


def test_a_verified_contract_with_no_src_tree_publishes_verified(tmp_path: Path):
    project_dir = _project(tmp_path, "contracts", {"source_verified": True})
    assert not list(project_dir.rglob("src/**/*.sol")), "the old expression's input must be empty here"

    assert collect_contract_analysis(project_dir)["subject"]["source_verified"] is True


def test_an_unverified_fetch_still_publishes_false_from_a_foundry_layout(tmp_path: Path):
    project_dir = _project(tmp_path, "src", {"source_verified": False})
    assert list(project_dir.rglob("src/**/*.sol")), "the old expression's input must be non-empty here"

    assert collect_contract_analysis(project_dir)["subject"]["source_verified"] is False


def test_a_project_with_no_recorded_fact_publishes_not_determined(tmp_path: Path):
    project_dir = _project(tmp_path, "src", {})

    assert collect_contract_analysis(project_dir)["subject"]["source_verified"] is None
