"""M0.2 item 2 — SQL-side chain-qualified dedup + reconcile chain-nesting fix.

Same address on two chains yields two independent jobs; dedup never returns a cross-chain match.
Complements ``test_chain_aware_cache.py`` (Python-side filtering) and
``tests/resolution/test_deployment_scoping.py`` (reconcile). Jobs go through ``create_job`` so the
chain_id dual-write is exercised end-to-end.
"""

from __future__ import annotations

import uuid

from tests.conftest import requires_postgres


def _addr() -> str:
    return "0x" + (uuid.uuid4().hex + uuid.uuid4().hex)[:40]


# ---------------------------------------------------------------------------
# find_existing_job_for_address — same address on two chains = two jobs
# ---------------------------------------------------------------------------


@requires_postgres
def test_existing_job_two_chains_are_two_jobs(db_session):
    from db.queue import create_job, find_existing_job_for_address

    addr = _addr()
    eth = create_job(db_session, {"address": addr, "chain": "ethereum"})
    base = create_job(db_session, {"address": addr, "chain": "base"})

    assert eth.id != base.id
    # The dual-write populated chain_id from request["chain"] via the registry.
    assert eth.chain_id == 1
    assert base.chain_id == 8453

    found_eth = find_existing_job_for_address(db_session, addr, chain="ethereum")
    found_base = find_existing_job_for_address(db_session, addr, chain="base")
    assert found_eth is not None and found_eth.id == eth.id
    assert found_base is not None and found_base.id == base.id


@requires_postgres
def test_existing_job_other_chain_only_is_a_miss(db_session):
    """An Ethereum job must not suppress a legitimate second-chain job for a Base lookup."""
    from db.queue import create_job, find_existing_job_for_address

    addr = _addr()
    create_job(db_session, {"address": addr, "chain": "ethereum"})
    assert find_existing_job_for_address(db_session, addr, chain="base") is None


@requires_postgres
def test_existing_job_chain_none_is_backward_compatible(db_session):
    """chain=None keeps the pre-change behaviour: no chain predicate."""
    from db.queue import create_job, find_existing_job_for_address

    addr = _addr()
    job = create_job(db_session, {"address": addr, "chain": "base"})
    found = find_existing_job_for_address(db_session, addr, chain=None)
    assert found is not None and found.id == job.id


# ---------------------------------------------------------------------------
# reconcile_impl_job_for_proxy — chain filtered even when root_job_id is None
# ---------------------------------------------------------------------------


@requires_postgres
def test_reconcile_root_none_respects_chain_same_proxy(db_session):
    """root_job_id=None: a same-(impl, proxy) job on another chain is not a duplicate (the :805 nesting bug)."""
    from db.queue import create_job, reconcile_impl_job_for_proxy

    impl, proxy = _addr(), _addr()
    create_job(db_session, {"address": impl, "chain": "ethereum", "proxy_address": proxy})

    # Different chain, no root scoping → must spawn its own deployment, not skip.
    assert reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy, chain="base") == "spawn"
    # Same chain → true duplicate → skip.
    assert reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy, chain="ethereum") == "skip"


@requires_postgres
def test_reconcile_root_none_respects_chain_standalone(db_session):
    from db.queue import create_job, reconcile_impl_job_for_proxy

    impl, proxy = _addr(), _addr()
    create_job(db_session, {"address": impl, "chain": "ethereum"})

    # Base first (pure read, no mutation): the eth standalone is a different
    # chain, so nothing to backpatch → spawn.
    assert reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy, chain="base") == "spawn"
    # Ethereum reconcile backpatches its own standalone.
    assert reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy, chain="ethereum") == "backpatched"


@requires_postgres
def test_reconcile_root_scoped_and_chain_both_apply(db_session):
    from db.queue import create_job, reconcile_impl_job_for_proxy

    impl, proxy, root = _addr(), _addr(), str(uuid.uuid4())
    create_job(
        db_session,
        {"address": impl, "chain": "ethereum", "proxy_address": proxy, "root_job_id": root},
    )

    # Same root + same chain → true duplicate within the cascade → skip.
    assert (
        reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy, chain="ethereum", root_job_id=root)
        == "skip"
    )
    # Same root, different chain → chain applies in the root branch → spawn.
    assert (
        reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy, chain="base", root_job_id=root)
        == "spawn"
    )
    # Different root, same chain → root scoping still narrows → spawn.
    assert (
        reconcile_impl_job_for_proxy(
            db_session, impl_addr=impl, proxy_addr=proxy, chain="ethereum", root_job_id=str(uuid.uuid4())
        )
        == "spawn"
    )
