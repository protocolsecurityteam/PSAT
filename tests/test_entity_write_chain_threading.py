"""[P2-pre] entity-write chain threading (MULTICHAIN_INVARIANTS.md Appendix A).

Proves that the Contract-row chain and every resolution-spawned child/dependency
job derive their chain from the job's first-class ``jobs.chain_id`` column (via
the registry), never the ``request`` JSONB payload. A chainless ``/api/analyze``
submission historically wrote ``Contract.chain=NULL`` and duplicated against
``'ethereum'`` stubs because ``NULL ≠ NULL`` defeats ``uq_contract_address_chain``
(invariants 1, 6, 12).

Real-DB tests, because the fix hinges on the SQL-side ``coalesce(chain,'ethereum')``
dedup predicate — a mocked session can't exercise it. Jobs are created through
``create_job`` so the Phase-0 ``chain_id`` dual-write is real; the "chain_id set,
request chainless" case is built by overriding the column directly, exactly the
state a legacy chainless submission leaves behind after Phase 0 backfill.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.conftest import requires_postgres  # noqa: E402


def _addr() -> str:
    return "0x" + (uuid.uuid4().hex + uuid.uuid4().hex)[:40]


def _etherscan_result() -> dict:
    return {
        "ContractName": "Widget",
        "CompilerVersion": "v0.8.20+commit.a1b2c3",
        "SourceCode": "pragma solidity ^0.8.20; contract Widget {}",
        "OptimizationUsed": "1",
        "Runs": "200",
        "EVMVersion": "shanghai",
        "LicenseType": "MIT",
    }


def _patch_discovery(monkeypatch, worker) -> None:
    """Stub the Etherscan reads + file storage so ``_process_address`` runs
    against the real DB session without touching the network."""
    result = _etherscan_result()
    monkeypatch.setattr("workers.discovery.fetch", lambda _addr, **_kw: result)
    monkeypatch.setattr("workers.discovery._batch_get_creators", lambda addresses, **kw: {})
    monkeypatch.setattr("workers.discovery.store_source_files", lambda *a, **kw: None)
    monkeypatch.setattr("workers.discovery.store_artifact", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)


# ---------------------------------------------------------------------------
# (a) chain_id=1 + chainless request → Contract.chain='ethereum', dedups NULL row
# ---------------------------------------------------------------------------


@requires_postgres
def test_chainless_mainnet_job_writes_ethereum_and_dedups_null_row(db_session, monkeypatch):
    from db.models import Contract
    from db.queue import create_job
    from workers.discovery import DiscoveryWorker

    addr = _addr()
    # A legacy chainless submission wrote this NULL-chain row.
    seed = create_job(db_session, {"address": addr})
    db_session.add(Contract(job_id=seed.id, address=addr, chain=None, contract_name="Legacy"))
    db_session.commit()

    job = create_job(db_session, {"address": addr})
    assert job.chain_id == 1  # Phase-0 dual-write: chainless address job → mainnet.

    worker = DiscoveryWorker()
    _patch_discovery(monkeypatch, worker)
    worker._process_address(db_session, job)

    rows = db_session.query(Contract).filter(Contract.address == addr).all()
    # Deduped against the NULL row via coalesce(chain,'ethereum') — no duplicate.
    assert len(rows) == 1
    assert rows[0].job_id == job.id  # existing row adopted, proving the match fired.
    assert rows[0].chain is None  # decided: no backfill; NULL≡mainnet convention kept.


# ---------------------------------------------------------------------------
# (b) chain_id=8453 → Contract.chain='base', does NOT dedup mainnet/NULL rows
# ---------------------------------------------------------------------------


@requires_postgres
def test_base_job_writes_base_and_does_not_dedup_null_row(db_session, monkeypatch):
    from db.models import Contract
    from db.queue import create_job
    from workers.discovery import DiscoveryWorker

    addr = _addr()
    seed = create_job(db_session, {"address": addr})
    db_session.add(Contract(job_id=seed.id, address=addr, chain=None, contract_name="MainnetOrNull"))
    db_session.commit()

    job = create_job(db_session, {"address": addr, "chain": "base"})
    assert job.chain_id == 8453

    worker = DiscoveryWorker()
    _patch_discovery(monkeypatch, worker)
    worker._process_address(db_session, job)

    rows = db_session.query(Contract).filter(Contract.address == addr).all()
    # A Base deployment is a distinct contract from the NULL/mainnet row.
    assert len(rows) == 2
    assert {r.chain for r in rows} == {None, "base"}
    base_row = next(r for r in rows if r.chain == "base")
    assert base_row.job_id == job.id


@requires_postgres
def test_base_job_does_not_dedup_explicit_ethereum_row(db_session, monkeypatch):
    """coalesce leaves an explicit ``chain='ethereum'`` row unmatched for Base too."""
    from db.models import Contract
    from db.queue import create_job
    from workers.discovery import DiscoveryWorker

    addr = _addr()
    seed = create_job(db_session, {"address": addr, "chain": "ethereum"})
    db_session.add(Contract(job_id=seed.id, address=addr, chain="ethereum", contract_name="Mainnet"))
    db_session.commit()

    job = create_job(db_session, {"address": addr, "chain": "base"})
    assert job.chain_id == 8453

    worker = DiscoveryWorker()
    _patch_discovery(monkeypatch, worker)
    worker._process_address(db_session, job)

    rows = db_session.query(Contract).filter(Contract.address == addr).all()
    assert {r.chain for r in rows} == {"ethereum", "base"}


@requires_postgres
def test_chain_id_column_beats_chainless_request_payload(db_session, monkeypatch):
    """The chain comes from ``jobs.chain_id``, not the request payload: a job whose
    payload lacks a chain but whose column says Base writes a Base contract row."""
    from db.models import Contract
    from db.queue import create_job
    from workers.discovery import DiscoveryWorker

    addr = _addr()
    job = create_job(db_session, {"address": addr})  # chainless payload → chain_id=1
    job.chain_id = 8453  # the trustworthy first-class source now says Base.
    db_session.commit()

    worker = DiscoveryWorker()
    _patch_discovery(monkeypatch, worker)
    worker._process_address(db_session, job)

    row = db_session.query(Contract).filter(Contract.address == addr).one()
    assert row.chain == "base"


# ---------------------------------------------------------------------------
# (c) resolution_worker child jobs get the chain stamp even without request chain
# ---------------------------------------------------------------------------


@requires_postgres
def test_resolution_child_job_stamped_from_chain_id_not_request(db_session, monkeypatch):
    from db.models import Job
    from db.queue import create_job
    from workers.resolution_worker import ResolutionWorker

    # Models a base-enabled deployment: discovered-child spawns gate off-allowlist
    # chains (inv. 14), so make the premise explicit rather than relying on {1}.
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")
    parent_addr, child_addr = _addr(), _addr()
    # Chainless payload, first-class chain_id says Base — the P2-pre scenario.
    parent = create_job(db_session, {"address": parent_addr})
    parent.chain_id = 8453
    db_session.commit()

    resolved_graph = {
        "root_contract_address": parent_addr,
        "nodes": [
            {"address": child_addr, "analyzed": True, "node_type": "contract", "contract_name": "Child"},
        ],
    }

    ResolutionWorker()._queue_discovered_contracts(db_session, parent, resolved_graph, "http://rpc.local")

    child = db_session.query(Job).filter(Job.address == child_addr).one()
    assert child.request["chain"] == "base"
    assert child.chain_id == 8453


@requires_postgres
def test_resolution_child_job_mainnet_chainless_stamps_ethereum(db_session):
    """A chainless mainnet parent now stamps 'ethereum' onto the child (previously
    the child was left chain-less, the write-NULL bug this fixes)."""
    from db.models import Job
    from db.queue import create_job
    from workers.resolution_worker import ResolutionWorker

    parent_addr, child_addr = _addr(), _addr()
    parent = create_job(db_session, {"address": parent_addr})
    assert parent.chain_id == 1

    resolved_graph = {
        "root_contract_address": parent_addr,
        "nodes": [
            {"address": child_addr, "analyzed": True, "node_type": "contract", "contract_name": "Child"},
        ],
    }

    ResolutionWorker()._queue_discovered_contracts(db_session, parent, resolved_graph, "http://rpc.local")

    child = db_session.query(Job).filter(Job.address == child_addr).one()
    assert child.request["chain"] == "ethereum"
    assert child.chain_id == 1
