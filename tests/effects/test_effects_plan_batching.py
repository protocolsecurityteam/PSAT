"""Perf: the ``cache_lookup`` N+1 batch.

The effects worker's ``_plan`` phase used to issue several serial single-row DB
round-trips PER candidate (runtime bytecode, proxy ``Contract`` + ``UpgradeEvent``
existence, per-plan ``find_cached_verdict``) plus, on the pause path, the
function's persisted claim and the contract's principal-by-selector map. This
suite proves the batched form (bulk prefetch + one composite verdict lookup):

* returns **byte-identical** worklist items to the legacy per-candidate path
  (``PSAT_EFFECTS_BATCH_PLAN`` off), run against the SAME fixture DB state, and
* collapses the per-job query count (~N round-trips → a handful).

Fully offline: real ``default_prober`` + ``make_bytecode_hash_resolver`` over a
seeded proxy protocol; no wire, no fork (the plans' ``run`` closures are never
executed here — ``_plan`` only builds the worklist)."""

from __future__ import annotations

import os
import uuid
from unittest.mock import MagicMock

import pytest
from sqlalchemy import event

from db.effect_cache import upsert_cached_verdict
from db.models import (
    BytecodeCache,
    Contract,
    EffectBehaviorCache,
    EffectiveFunction,
    EffectVerdict,
    FunctionPrincipal,
    Protocol,
    UpgradeEvent,
)
from services.effects import calldata as calldata_synth
from services.effects import prefetch as prefetch_mod
from services.effects.config import EFFECT_CLASS_CODE_UPGRADE, SCOPE_KERNEL
from services.effects.hashing import bytecode_fallback_hash
from services.effects.orchestrator import ProbeContext, make_bytecode_hash_resolver
from services.effects.selection import Candidate
from tests.cache_helpers import requires_postgres
from workers.effects_worker import EffectsWorker, _Counters

# Distinct runtime bytecode per deployment ⇒ distinct kernel/surface hash, so
# each candidate is its own behavior. A handful of candidates makes the batched
# path's flat query count visibly beat the legacy per-candidate N+1.
N_CANDIDATES = 6
SELECTOR = "0x3659cfe6"  # upgradeTo(address)
PRINCIPAL = "0x" + "22" * 20


def _code(i: int) -> str:
    return "0x60" + f"{i + 0x11:02x}" * 40


@pytest.fixture()
def clean(db_session):
    db_session.query(EffectVerdict).delete()
    db_session.query(EffectBehaviorCache).delete()
    db_session.commit()
    yield db_session
    db_session.rollback()
    db_session.query(EffectVerdict).delete()
    db_session.query(EffectBehaviorCache).delete()
    db_session.commit()


def _seed_proxy_protocol(session) -> list[Candidate]:
    """Two upgradeable proxies (each its own contract + effective function +
    principal + indexed UpgradeEvent + cached bytecode). Returns the candidates
    the way selection would."""
    proto = Protocol(name=f"batch-{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()

    # Unique addresses per run: bytecode_cache is a global table not swept by the
    # conftest teardown, so a fixed address would pkey-collide on re-run. The
    # kernel hash keys on CODE (not address), so seeding stays deterministic.
    tag = uuid.uuid4().hex[:8]
    cands: list[Candidate] = []
    for i in range(N_CANDIDATES):
        code = _code(i)
        addr = "0x" + f"{i:x}{tag}".ljust(40, "0")[:40]
        # Each proxy names its OWN implementation, and that implementation's bytecode is
        # cached below. A proxy row carrying function rows must never be hashed
        # on its forwarding stub (one stub hash covers every implementation behind the
        # pattern — measured: 15 of them behind ``UUPSProxy``), so the resolver keys on
        # the implementation instead and this fixture has to supply it. Without the impl
        # bytecode the candidate is skipped, which is the guard working.
        impl_addr = "0x" + f"d{i:x}{tag}".ljust(40, "0")[:40]
        c = Contract(
            protocol_id=proto.id,
            address=addr,
            chain="ethereum",
            is_proxy=True,
            proxy_type="transparent",
            implementation=impl_addr,
        )
        session.add(c)
        session.flush()
        fn = EffectiveFunction(
            contract_id=c.id,
            deployment_address=addr,
            function_name="upgradeTo",
            selector=SELECTOR,
            authority_public=False,
        )
        session.add(fn)
        session.flush()
        session.add(FunctionPrincipal(function_id=fn.id, address=PRINCIPAL))
        session.add(UpgradeEvent(contract_id=c.id, proxy_address=addr, block_number=1, tx_hash="0x" + "ab" * 32))
        session.add(
            BytecodeCache(chain_id=1, address=addr, bytecode="0x363d3d373d3d3d363d73stub", code_keccak="0x" + "bb" * 32)
        )
        session.add(BytecodeCache(chain_id=1, address=impl_addr, bytecode=code, code_keccak="0x" + "cc" * 32))
        cands.append(
            Candidate(
                function_id=fn.id,
                contract_id=c.id,
                contract_address=addr,
                selector=SELECTOR,
                function_name="upgradeTo",
                authority_public=False,
                principal_addresses=(PRINCIPAL,),
                deployment_address=addr,
            )
        )
    session.commit()
    return cands


def _run_plan(session, candidates, *, batched: bool):
    """Drive ``EffectsWorker._plan`` with the real resolver + prober, counting the
    SQL statements it issues. Returns (serialized_items, query_count)."""
    worker = EffectsWorker()
    resolver = make_bytecode_hash_resolver(1)
    ctx = ProbeContext(
        chain_id=1,
        block=21_000_000,
        hardfork="prague",
        simulate=MagicMock(side_effect=AssertionError("_plan must not touch the wire")),
        simulate_supported=False,
        transcript_store=lambda tr: "ptr",
        call_batch=None,
        anvil_factory=None,
    )

    count = {"n": 0}

    def _before(conn, cursor, statement, params, context, executemany):
        count["n"] += 1

    engine = session.get_bind()
    event.listen(engine, "before_cursor_execute", _before)
    prev = os.environ.get("PSAT_EFFECTS_BATCH_PLAN")
    os.environ["PSAT_EFFECTS_BATCH_PLAN"] = "1" if batched else "0"
    try:
        items = worker._plan(session, candidates, ctx, resolver, _Counters())
    finally:
        if prev is None:
            os.environ.pop("PSAT_EFFECTS_BATCH_PLAN", None)
        else:
            os.environ["PSAT_EFFECTS_BATCH_PLAN"] = prev
        event.remove(engine, "before_cursor_execute", _before)

    serialized = [
        (
            it.candidate.function_id,
            it.effect_class,
            it.scope,
            it.gate_ref,
            it.behavior_hash,
            it.surface_hash,
            None if it.cached is None else (it.cached.id, it.cached.verdict, it.cached.audit_status),
            it.needs_audit,
        )
        for it in items
    ]
    return serialized, count["n"]


@requires_postgres
def test_plan_batched_matches_legacy_byte_identical(clean):
    """Same fixture DB state, both code paths ⇒ identical worklist. One
    candidate's code_upgrade identity is pre-seeded so the run exercises BOTH a
    cache HIT (that plan) and a MISS (the other), proving the batched composite
    lookup returns the same rows the per-plan SELECT did."""
    session = clean
    cands = _seed_proxy_protocol(session)

    # Pre-seed the code_upgrade cache identity for candidate 0 ⇒ a HIT.
    kernel_hash = bytecode_fallback_hash(_code(0), SELECTOR)
    upsert_cached_verdict(
        session,
        behavior_hash=kernel_hash,
        effect_class=EFFECT_CLASS_CODE_UPGRADE,
        scope=SCOPE_KERNEL,
        verdict="proven",
        tier="tier0",
        gate_ref="proxy:transparent",
    )
    session.commit()

    legacy, legacy_q = _run_plan(session, cands, batched=False)
    batched, batched_q = _run_plan(session, cands, batched=True)

    # (a) byte-identical worklist.
    assert batched == legacy
    # One HIT (candidate 0) and the rest MISS were exercised.
    hits = [row for row in batched if row[6] is not None]
    misses = [row for row in batched if row[6] is None]
    assert len(hits) == 1 and len(misses) == N_CANDIDATES - 1
    assert hits[0][4] == kernel_hash

    # (b) the per-job query count dropped sharply. Legacy is ~3 round-trips per
    # candidate + 1 verdict lookup per plan (grows with N); batched is a small
    # fixed set of bulk queries independent of candidate count.
    assert batched_q < legacy_q
    assert batched_q <= 8
    assert legacy_q >= 3 * N_CANDIDATES


@requires_postgres
def test_prefetch_cleared_after_plan(clean):
    """The per-session store must not leak past ``cache_lookup``."""
    session = clean
    cands = _seed_proxy_protocol(session)
    _run_plan(session, cands, batched=True)
    assert prefetch_mod.get_prefetch(session) is None


# ---------------------------------------------------------------------------
# calldata data-loading helpers: batched (prefetch) vs single-row are identical.
# These are the pause-path N+1 members (calldata.py), verified in isolation.
# ---------------------------------------------------------------------------


def _pause_claim(var: str, member: str | None):
    flag = {"var": var}
    if member is not None:
        flag["member"] = member
    return [{"claim_id": "pause.set", "witness": {"kind": "pause_flag", "flags": [flag]}}]


@requires_postgres
def test_principals_by_selector_prefetch_matches_query(clean):
    session = clean
    proto = Protocol(name=f"pbs-{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    c = Contract(protocol_id=proto.id, address="0x" + "c1" * 20, chain="ethereum", is_proxy=False)
    session.add(c)
    session.flush()
    for sel, prin in (("0xaaaaaaaa", "0x" + "a0" * 20), ("0xbbbbbbbb", "0x" + "b0" * 20)):
        fn = EffectiveFunction(contract_id=c.id, function_name="f", selector=sel, authority_public=False)
        session.add(fn)
        session.flush()
        session.add(FunctionPrincipal(function_id=fn.id, address=prin))
    session.commit()

    legacy = calldata_synth._principals_by_selector(session, c.id)
    prefetch_mod.install_prefetch(
        session,
        1,
        [
            Candidate(
                function_id=0,
                contract_id=c.id,
                contract_address=c.address,
                selector=None,
                function_name="f",
                authority_public=False,
                principal_addresses=(),
            )
        ],
    )
    try:
        batched = calldata_synth._principals_by_selector(session, c.id)
    finally:
        prefetch_mod.clear_prefetch(session)
    assert batched == legacy
    assert batched == {"0xaaaaaaaa": "0x" + "a0" * 20, "0xbbbbbbbb": "0x" + "b0" * 20}


@requires_postgres
def test_principals_by_selector_is_deterministic_with_two_principals(clean):
    """A selector with TWO principals is where the batched and unbatched reads
    could disagree: both keep the first row via ``setdefault``, but only the
    prefetch path ordered its query. The unbatched read then returned whichever
    row Postgres handed back first — a different ``from_addr`` in the simulated
    call depending on which plan path ran. Insertion order below is the reverse
    of the ordered answer, so the pre-fix single-contract query returns the HIGH
    address and the prefetch path the LOW one."""
    session = clean
    proto = Protocol(name=f"pbs2-{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    c = Contract(protocol_id=proto.id, address="0x" + "c3" * 20, chain="ethereum", is_proxy=False)
    session.add(c)
    session.flush()
    fn = EffectiveFunction(contract_id=c.id, function_name="f", selector="0xcccccccc", authority_public=False)
    session.add(fn)
    session.flush()
    high, low = "0x" + "f0" * 20, "0x" + "10" * 20
    session.add(FunctionPrincipal(function_id=fn.id, address=high))
    session.flush()
    session.add(FunctionPrincipal(function_id=fn.id, address=low))
    session.commit()

    unbatched = calldata_synth._principals_by_selector(session, c.id)
    prefetch_mod.install_prefetch(
        session,
        1,
        [
            Candidate(
                function_id=fn.id,
                contract_id=c.id,
                contract_address=c.address,
                selector="0xcccccccc",
                function_name="f",
                authority_public=False,
                principal_addresses=(),
            )
        ],
    )
    try:
        batched = calldata_synth._principals_by_selector(session, c.id)
    finally:
        prefetch_mod.clear_prefetch(session)

    assert unbatched == batched
    assert unbatched == {"0xcccccccc": low}


@requires_postgres
def test_claim_latch_pairs_prefetch_matches_query(clean):
    session = clean
    proto = Protocol(name=f"clp-{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    c = Contract(protocol_id=proto.id, address="0x" + "c2" * 20, chain="ethereum", is_proxy=False)
    session.add(c)
    session.flush()
    fn = EffectiveFunction(
        contract_id=c.id,
        function_name="pause",
        selector="0x8456cb59",
        authority_public=False,
        claims=_pause_claim("paused", None),
    )
    session.add(fn)
    session.flush()
    session.commit()

    legacy = calldata_synth._claim_latch_pairs(session, fn.id)
    prefetch_mod.install_prefetch(
        session,
        1,
        [
            Candidate(
                function_id=fn.id,
                contract_id=c.id,
                contract_address=c.address,
                selector="0x8456cb59",
                function_name="pause",
                authority_public=False,
                principal_addresses=(),
            )
        ],
    )
    try:
        batched = calldata_synth._claim_latch_pairs(session, fn.id)
    finally:
        prefetch_mod.clear_prefetch(session)
    assert batched == legacy
    assert batched == {("paused", None)}


# ---------------------------------------------------------------------------
# A proxy row's forwarding stub is never a behavioral hash
# ---------------------------------------------------------------------------


@requires_postgres
def test_a_proxy_rows_stub_bytecode_is_never_hashed(clean):
    """The unstated invariant this cache rests on — "a proxy row never carries
    ``effective_functions``" — is asserted by nothing (39 proxy rows, 0 functions, no
    constraint, no test, no comment). When it breaks, ``candidate.contract_address`` is
    a proxy and the bytecode at it is the forwarding STUB, whose hash is shared by every
    implementation behind the pattern: measured, 16 colliding surface-hash groups over
    323 mainnet ``bytecode_cache`` rows, largest group 15 distinct implementations
    behind ``UUPSProxy``.

    Two proxies of the SAME type with DIFFERENT implementations must not collide, and a
    proxy whose implementation code is unavailable must yield no hash at all rather than
    the stub's.
    """
    session = clean
    resolver = make_bytecode_hash_resolver(1)
    proto = Protocol(name=f"proxyhash-{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    tag = uuid.uuid4().hex[:8]
    stub = "0x363d3d373d3d3d363d73" + "ab" * 20  # the SAME stub for both proxies
    made: list[tuple[Candidate, str]] = []
    for i in (1, 2):
        proxy = "0x" + f"e{i:x}{tag}".ljust(40, "0")[:40]
        impl = "0x" + f"f{i:x}{tag}".ljust(40, "0")[:40]
        c = Contract(protocol_id=proto.id, address=proxy, chain="ethereum", is_proxy=True, implementation=impl)
        session.add(c)
        session.flush()
        fn = EffectiveFunction(
            contract_id=c.id,
            deployment_address=proxy,
            function_name="upgradeTo",
            selector=SELECTOR,
            authority_public=False,
        )
        session.add(fn)
        session.flush()
        session.add(BytecodeCache(chain_id=1, address=proxy, bytecode=stub, code_keccak="0x" + "b1" * 32))
        session.add(
            BytecodeCache(chain_id=1, address=impl, bytecode=_code(i + 40), code_keccak=f"0x{i:02x}" + "c1" * 31)
        )
        made.append(
            (
                Candidate(
                    function_id=fn.id,
                    contract_id=c.id,
                    contract_address=proxy,
                    selector=SELECTOR,
                    function_name="upgradeTo",
                    authority_public=False,
                    principal_addresses=(),
                    deployment_address=proxy,
                ),
                impl,
            )
        )
    session.commit()

    resolved = [resolver(session, cand) for cand, _impl in made]
    assert all(r is not None for r in resolved)
    # The stub is shared, so hashing it would make these two IDENTICAL. They are not.
    assert resolved[0] != resolved[1]
    # ...and each is exactly the hash of its OWN implementation's code.
    for (cand, impl), got in zip(made, resolved, strict=True):
        assert got is not None
        assert got[0] == bytecode_fallback_hash(_code_of(session, impl), cand.selector)
    # The stub's own hash appears nowhere.
    assert all(bytecode_fallback_hash(stub, SELECTOR) != got[0] for got in resolved if got)

    # A proxy row with no resolvable implementation code: no hash at all (skip,
    # degraded, never guess) — NEVER the stub.
    orphan_proxy = "0x" + f"a{tag}".ljust(40, "0")[:40]
    orphan = Contract(protocol_id=proto.id, address=orphan_proxy, chain="ethereum", is_proxy=True)
    session.add(orphan)
    session.flush()
    fn = EffectiveFunction(
        contract_id=orphan.id,
        deployment_address=orphan_proxy,
        function_name="upgradeTo",
        selector=SELECTOR,
        authority_public=False,
    )
    session.add(fn)
    session.flush()
    session.add(BytecodeCache(chain_id=1, address=orphan_proxy, bytecode=stub, code_keccak="0x" + "b2" * 32))
    session.commit()
    orphan_cand = Candidate(
        function_id=fn.id,
        contract_id=orphan.id,
        contract_address=orphan_proxy,
        selector=SELECTOR,
        function_name="upgradeTo",
        authority_public=False,
        principal_addresses=(),
        deployment_address=orphan_proxy,
    )
    assert resolver(session, orphan_cand) is None

    # CONTROL: a NON-proxy row still hashes its own code, unchanged.
    plain_addr = "0x" + f"c{tag}".ljust(40, "0")[:40]
    plain = Contract(protocol_id=proto.id, address=plain_addr, chain="ethereum", is_proxy=False)
    session.add(plain)
    session.flush()
    plain_fn = EffectiveFunction(
        contract_id=plain.id,
        function_name="withdraw",
        selector="0xf3fef3a3",
        authority_public=False,
    )
    session.add(plain_fn)
    session.flush()
    session.add(BytecodeCache(chain_id=1, address=plain_addr, bytecode=_code(99), code_keccak="0x" + "d9" * 32))
    session.commit()
    plain_cand = Candidate(
        function_id=plain_fn.id,
        contract_id=plain.id,
        contract_address=plain_addr,
        selector="0xf3fef3a3",
        function_name="withdraw",
        authority_public=False,
        principal_addresses=(),
    )
    got = resolver(session, plain_cand)
    assert got is not None
    assert got[0] == bytecode_fallback_hash(_code(99), "0xf3fef3a3")


def _code_of(session, address: str) -> str:
    row = session.query(BytecodeCache).filter(BytecodeCache.chain_id == 1, BytecodeCache.address == address).one()
    return row.bytecode
