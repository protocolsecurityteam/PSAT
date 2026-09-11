"""``source_verified`` is the FETCH's answer, carried — never inferred from the tree.

``contract_summaries.source_verified`` used to be
``bool(project_dir.rglob("src/**/*.sol"))``: whether the scaffolder happened to write a
Foundry ``src/`` layout, which is decided by the paths inside Etherscan's own
verification bundle. On the 2026-07-28 run that published FALSE for 9 of 90 contracts
(UpgradeableBeacon, EndpointV2, OneSig, 2x TimelockController, FiatTokenV2_2,
EtherfiL1SyncPoolETH, WithdrawalQueueERC721, Lido) — all nine Etherscan-verified, all
nine analysed from that verified source in the same job, ``contracts.source_verified``
TRUE on all nine, and zero of their source files under ``src/`` (their bundles use
``contracts/``, ``@openzeppelin/``, ``@aragon/`` and ``lib/``). The field is a direct
input to the frontend data-confidence score and names the contract as an example of
unverified source.
"""

from __future__ import annotations

import json
from pathlib import Path

from services.discovery.fetch import scaffold
from services.static import collect_static_inputs
from services.static.static_analysis.core import _source_verified
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


# ---------------------------------------------------------------------------
# 1. the publisher: three states, and none of them read off the tree
# ---------------------------------------------------------------------------


def test_the_fetch_fact_is_carried_verbatim_in_all_three_states():
    assert _source_verified({"source_verified": True}) is True
    assert _source_verified({"source_verified": False}) is False
    # Key absent — an older workspace or an unreadable meta file. NOT determined, and
    # therefore not False: the column and the API payload both keep that third state.
    assert _source_verified({}) is None
    assert _source_verified({"source_verified": None}) is None
    # A non-boolean is not an answer either (a truthy string must not become True).
    assert _source_verified({"source_verified": "true"}) is None


def test_the_project_layout_cannot_decide_the_field(tmp_path: Path):
    """The 9-row reproduction, at the publisher. A verified contract whose Etherscan
    bundle uses ``contracts/`` (no ``src/`` tree at all) must publish True, and a
    contract the fetch says is unverified must publish False however Foundry-shaped its
    scaffold is."""
    lido_shaped = tmp_path / "lido"
    (lido_shaped / "contracts").mkdir(parents=True)
    (lido_shaped / "contracts" / "Lido.sol").write_text("contract Lido {}")
    assert not list(lido_shaped.rglob("src/**/*.sol")), "fixture must have no src/ tree"

    foundry_shaped = tmp_path / "foundry"
    (foundry_shaped / "src").mkdir(parents=True)
    (foundry_shaped / "src" / "Vault.sol").write_text("contract Vault {}")
    assert list(foundry_shaped.rglob("src/**/*.sol")), "fixture must have a src/ tree"

    # The layout the old expression read is now irrelevant in BOTH directions.
    assert _source_verified({"source_verified": True}) is True
    assert _source_verified({"source_verified": False}) is False


# ---------------------------------------------------------------------------
# 2. the two scaffolders that must carry it
# ---------------------------------------------------------------------------


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

    # NEGATIVE CONTROL: ``get_source`` raises before this point on an empty
    # ``SourceCode``, so this arm is not reachable through ``fetch()`` — but the value
    # is read off the payload rather than hardcoded, and it says what the payload says.
    unverified = scaffold("0x1234", {**result, "SourceCode": ""}, tmp_path / "Unverified")
    assert json.loads((unverified / "contract_meta.json").read_text())["source_verified"] is False


@requires_postgres
def test_the_static_worker_hands_the_pipeline_the_contract_rows_fact(db_session, monkeypatch):
    """``contracts.source_verified`` is written by discovery when Etherscan served the
    source. It keeps all three values on the corpus (TRUE 230 / FALSE 1 / NULL 410 at
    the time of writing) and all three must survive into ``contract_meta.json`` —
    especially NULL, which is the row that never learned the fact."""
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


# ---------------------------------------------------------------------------
# 3. end to end: what the analysis artifact publishes
# ---------------------------------------------------------------------------


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
    """The 9 rows, end to end. Etherscan's bundle for Lido / WithdrawalQueueERC721 /
    TimelockController puts everything under ``contracts/``, ``@openzeppelin/`` or
    ``lib/``, so the scaffolded project has NO ``src/`` tree — which is what the old
    expression measured, and why it published FALSE for nine verified contracts."""
    project_dir = _project(tmp_path, "contracts", {"source_verified": True})
    assert not list(project_dir.rglob("src/**/*.sol")), "the old expression's input must be empty here"

    assert collect_static_inputs(project_dir)[0]["subject"]["source_verified"] is True


def test_an_unverified_fetch_still_publishes_false_from_a_foundry_layout(tmp_path: Path):
    """NEGATIVE CONTROL — the adverse arm still fires, and the layout does not rescue
    it: a ``src/`` tree full of Solidity is exactly what the old expression called
    verified."""
    project_dir = _project(tmp_path, "src", {"source_verified": False})
    assert list(project_dir.rglob("src/**/*.sol")), "the old expression's input must be non-empty here"

    assert collect_static_inputs(project_dir)[0]["subject"]["source_verified"] is False


def test_a_project_with_no_recorded_fact_publishes_not_determined(tmp_path: Path):
    """The third state, end to end: a workspace scaffolded before the fact was carried
    publishes ``None`` — which the nullable column and the API payload both keep, and
    which the frontend now names as "not recorded" rather than as unverified. The old
    expression answered this input with a confident ``True``/``False`` read off the
    directory listing."""
    project_dir = _project(tmp_path, "src", {})

    assert collect_static_inputs(project_dir)[0]["subject"]["source_verified"] is None
