"""NULL-chain Contract lookups in ``workers.static_worker``
(MULTICHAIN_INVARIANTS.md 1/6/12).

Two Contract lookups resolved chain from the request JSONB (or not at all) and
compared it with a raw ``chain == <value>`` predicate:

  - ``_load_contract_row`` — the job_id-rebind fallback. It read
    ``request["chain"]``, so a chainless L2 submission (chain only in the
    first-class ``jobs.chain_id`` column) dropped the filter and could bind a
    mainnet row.
  - ``_resolve_proxy`` membership on classification — the membership gate's
    W2 proxy-edge verification is chain-scoped, so a same-address member impl
    on another chain can never stand in as the admitting anchor.

Both derive the chain from ``jobs.chain_id`` (``_parent_chain_name``) and
coalesce (NULL≡mainnet). Proven both directions: mainnet finds legacy NULL
rows; a non-mainnet job stays isolated.
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
def test_load_contract_row_finds_legacy_null_row_for_mainnet_job(db_session):
    """The Contract row was orphaned from the job (job_id rebind) and persisted
    ``chain=NULL``. A mainnet job resolves it via the coalesced fallback."""
    from db.models import Contract
    from db.queue import create_job
    from workers.static_worker import StaticWorker

    addr = _addr()
    job = create_job(db_session, {"address": addr, "name": "Subject"})  # chain_id=1, no request chain
    db_session.add(Contract(address=addr.lower(), chain=None, contract_name="Legacy", job_id=None))
    db_session.commit()

    row = StaticWorker._load_contract_row(db_session, job)
    assert row is not None
    assert row.contract_name == "Legacy"


@requires_postgres
def test_load_contract_row_l2_job_does_not_bind_mainnet_row(db_session):
    """A Base-routed job (chain only in ``jobs.chain_id``, absent from the
    request JSONB) must not bind a legacy mainnet (NULL) row at the same
    address — the request-only read used to drop the filter and bleed."""
    from db.models import Contract
    from db.queue import create_job
    from workers.static_worker import StaticWorker

    addr = _addr()
    job = create_job(db_session, {"address": addr, "name": "Subject"})
    job.chain_id = 8453  # routed to Base; request payload carries no chain
    db_session.commit()

    # Only a mainnet (legacy NULL) row exists for this address.
    db_session.add(Contract(address=addr.lower(), chain=None, contract_name="Mainnet", job_id=None))
    db_session.commit()

    row = StaticWorker._load_contract_row(db_session, job)
    assert row is None


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
        ContractCreationWitness(
            chain_id=1, address=proxy_addr.lower(), code_probe_block=10, code_absent_at_probe=False
        )
    )
    session.commit()
    return job, proxy_addr, impl_addr


@pytest.fixture()
def _stub_resolve_proxy_seams(monkeypatch):
    """Neutralize the child-spawn tail of ``_resolve_proxy`` so the test targets
    only the membership-gate hook (which commits before the tail runs)."""
    monkeypatch.setattr("workers.static_worker.store_artifact", lambda *a, **kw: None)
    monkeypatch.setattr("workers.static_worker.reconcile_impl_job_for_proxy", lambda *a, **kw: "skip")
    monkeypatch.setattr("workers.static_worker._redirect_proxy_policy_dependencies", lambda *a, **kw: None)


@requires_postgres
def test_resolve_proxy_promotes_when_impl_on_same_chain(db_session, proto_id, monkeypatch, _stub_resolve_proxy_seams):
    """Mainnet job: the member impl is on ethereum, so the gate's
    chain-scoped W2 proxy edge verifies and the nominated proxy promotes."""
    from db.models import Contract
    from workers.static_worker import StaticWorker

    job, proxy_addr, impl_addr = _seed_adoption_graph(db_session, proto_id, impl_chain="ethereum")
    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {"type": "proxy", "proxy_type": "eip1967", "implementation": impl_addr},
    )

    StaticWorker()._resolve_proxy(db_session, job, proxy_addr, "Proxy")

    proxy = (
        db_session.query(Contract).filter(Contract.address == proxy_addr.lower(), Contract.chain == "ethereum").one()
    )
    assert proxy.protocol_id == proto_id


@requires_postgres
def test_resolve_proxy_does_not_promote_when_impl_only_on_other_chain(
    db_session, proto_id, monkeypatch, _stub_resolve_proxy_seams
):
    """Mainnet job: the same-address member impl exists only on Base. The
    chain-scoped W2 verification finds no mainnet member, so no promotion —
    the fix against cross-chain evidence bleed."""
    from db.models import Contract
    from workers.static_worker import StaticWorker

    job, proxy_addr, impl_addr = _seed_adoption_graph(db_session, proto_id, impl_chain="base")
    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda address, rpc_url, **_kw: {"type": "proxy", "proxy_type": "eip1967", "implementation": impl_addr},
    )

    StaticWorker()._resolve_proxy(db_session, job, proxy_addr, "Proxy")

    proxy = (
        db_session.query(Contract).filter(Contract.address == proxy_addr.lower(), Contract.chain == "ethereum").one()
    )
    assert proxy.protocol_id is None
