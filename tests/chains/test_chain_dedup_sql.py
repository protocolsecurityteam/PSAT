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


@requires_postgres
def test_reconcile_root_scoped_and_chain_both_apply(db_session):
    from db.queue import create_job, reconcile_impl_job_for_proxy

    impl, proxy, root = _addr(), _addr(), str(uuid.uuid4())
    create_job(
        db_session,
        {"address": impl, "chain": "ethereum", "proxy_address": proxy, "root_job_id": root},
    )

    assert (
        reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy, chain="ethereum", root_job_id=root)
        == "skip"
    )
    assert (
        reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy, chain="base", root_job_id=root)
        == "spawn"
    )
    assert (
        reconcile_impl_job_for_proxy(
            db_session, impl_addr=impl, proxy_addr=proxy, chain="ethereum", root_job_id=str(uuid.uuid4())
        )
        == "spawn"
    )
