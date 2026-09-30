"""NULL-chain Contract lookups in ``workers.static_worker``.

Two lookups compared a request-JSONB chain (or none) with a raw ``chain == <value>`` predicate:

  - ``_load_contract_row`` (job_id-rebind fallback) read ``request["chain"]``, so a chainless L2 submission
    (chain only in ``jobs.chain_id``) dropped the filter and could bind a mainnet row.
  - ``_resolve_proxy`` membership: the gate's W2 proxy-edge verification is chain-scoped, so a same-address
    member impl on another chain can never be the admitting anchor.

Both now derive chain from ``jobs.chain_id`` (``_parent_chain_name``) and coalesce NULL≡mainnet: mainnet finds
legacy NULL rows, a non-mainnet job stays isolated.
"""

from __future__ import annotations

import uuid

import pytest

from tests.conftest import requires_postgres


def _addr() -> str:
    return "0x" + (uuid.uuid4().hex + uuid.uuid4().hex)[:40]


@pytest.fixture()
def proto_id(db_session):
    from db.models import Protocol

    p = Protocol(name=f"sw-coalesce-{uuid.uuid4().hex[:10]}")
    db_session.add(p)
    db_session.commit()
    return p.id


# ---------------------------------------------------------------------------
# _load_contract_row — job_id-rebind fallback
# ---------------------------------------------------------------------------


@requires_postgres
@pytest.mark.parametrize(
    ("job_chain_id", "expected_name"),
    [
        pytest.param(1, "Legacy", id="mainnet-job-finds-legacy-null-row"),
        # A Base-routed job (chain only in ``jobs.chain_id``) must not bind a legacy mainnet NULL row at the
        # same address; the request-only read used to drop the filter and bleed.
        pytest.param(8453, None, id="l2-job-does-not-bind-mainnet-row"),
    ],
)
def test_load_contract_row_coalesces_null_chain(db_session, job_chain_id, expected_name):
    from db.models import Contract
    from db.queue import create_job
    from workers.static_worker import StaticWorker

    addr = _addr()
    job = create_job(db_session, {"address": addr, "name": "Subject"})
    job.chain_id = job_chain_id  # request payload carries no chain
    db_session.add(Contract(address=addr.lower(), chain=None, contract_name="Legacy", job_id=None))
    db_session.commit()

    row = StaticWorker._load_contract_row(db_session, job)
    assert getattr(row, "contract_name", None) == expected_name


# ---------------------------------------------------------------------------
# _resolve_proxy — structural-adoption impl anchor
# ---------------------------------------------------------------------------


def _seed_adoption_graph(session, proto_id, *, impl_chain):
    """Nominated candidate proxy (mainnet, code fact persisted) + a MEMBER
    impl on *impl_chain*. Returns (job, proxy_addr, impl_addr)."""
    from db.models import Contract, ContractCreationWitness
    from db.queue import create_job

    proxy_addr = _addr()
    impl_addr = _addr()

    job = create_job(session, {"address": proxy_addr, "name": "Proxy", "rpc_url": "http://stub"})  # chain_id=1
    proxy = Contract(
        address=proxy_addr.lower(),
        chain="ethereum",
        protocol_id=None,
        nominated_protocol_id=proto_id,
        is_proxy=True,
        job_id=job.id,
    )
    impl = Contract(address=impl_addr.lower(), chain=impl_chain, protocol_id=proto_id, is_proxy=False)
    session.add_all([proxy, impl])
    session.add(
        ContractCreationWitness(chain_id=1, address=proxy_addr.lower(), code_probe_block=10, code_absent_at_probe=False)
    )
    session.commit()
    return job, proxy_addr, impl_addr


@pytest.fixture()
def _stub_resolve_proxy_seams(monkeypatch):
    """Neutralize ``_resolve_proxy``'s child-spawn tail so the test targets only the membership-gate hook."""
    monkeypatch.setattr("workers.static_worker.store_artifact", lambda *a, **kw: None)
    monkeypatch.setattr("workers.static_worker.reconcile_impl_job_for_proxy", lambda *a, **kw: "skip")
    monkeypatch.setattr("workers.static_worker._redirect_proxy_policy_dependencies", lambda *a, **kw: None)


@requires_postgres
@pytest.mark.parametrize(
    ("impl_chain", "promoted"),
    [
        pytest.param("ethereum", True, id="impl-on-same-chain-promotes"),
        # The same-address member impl exists only on Base: chain-scoped W2 verification finds no mainnet
        # member, so no promotion (the fix against cross-chain evidence bleed).
        pytest.param("base", False, id="impl-only-on-other-chain-does-not-promote"),
    ],
)
def test_resolve_proxy_promotion_is_chain_scoped(
    db_session, proto_id, monkeypatch, _stub_resolve_proxy_seams, impl_chain, promoted
):
    from db.models import Contract
    from workers.static_worker import StaticWorker

    job, proxy_addr, impl_addr = _seed_adoption_graph(db_session, proto_id, impl_chain=impl_chain)
    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {"type": "proxy", "proxy_type": "eip1967", "implementation": impl_addr},
    )

    StaticWorker()._resolve_proxy(db_session, job, proxy_addr, "Proxy")

    proxy = (
        db_session.query(Contract).filter(Contract.address == proxy_addr.lower(), Contract.chain == "ethereum").one()
    )
    assert proxy.protocol_id == (proto_id if promoted else None)
