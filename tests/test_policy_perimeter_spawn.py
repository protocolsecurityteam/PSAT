"""The analysis perimeter's second spawn site (C3), and its back-link witness.

Ten `ManagerWithMerkleVerification` contracts hold the sole `canCall` on a
BoringVault's `manage` — `exec.arbitrary` — and none of them has an analysis
job, so the gate terminates at an unanalysed contract and 30
`contract_gated_unknown_path` warnings stand. They are not missing by policy:
all ten sit in `control_graph_nodes` with `analyzed=true`, `node_type='contract'`
and `details->>'source' = 'semantic_capability:role_grant'`, i.e. they satisfy
every gate the spawn loop applies. They were never offered to it. The policy
stage's graph refresh — the only stage that can project role principals, because
role principals need the `effective_permissions` it computes — rewrote the graph
and never called the spawn.

Measured on the PR-161 corpus: 32 role-grant contract addresses, **19 jobless**,
every one `analyzed=true`. Only 10 carry the manager label; the other 9 are
Pausers, BoringSolvers, DelayedWithdraws and an AtomicSolverV3 — which is why
the spawn keys on the persisted provenance field and never on the label.

The witness the fix makes available is the `vault()` back-link, verified 10/10
at block 25643300 with a negative control passing 10/10. It corroborates the
(M, V) PAIRING; it does not establish that M is a manager, and a mismatch is not
a disproof. See `probe_declared_vault_backlink`.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.discovery.perimeter import (  # noqa: E402
    PERIMETER_DEPTH_KEY,
    ZERO_ADDRESS,
    queue_discovered_contracts,
)
from services.resolution.tracking import (  # noqa: E402
    _resolve_pinned_block as _REAL_RESOLVE_PINNED_BLOCK,
)
from tests.conftest import requires_postgres  # noqa: E402

pytestmark = [requires_postgres]

ROLE_GRANT = "semantic_capability:role_grant"

# The real pairing, at the real pinned height, from lane C and re-measured:
# 0x66aae0ee… `vault()` -> 0x86b5780b… (BoringGovernance), whose `manage` it gates.
MANAGER = "0x66aae0ee1f68c658401c7d8d6e417202a99545d7"
VAULT = "0x86b5780b606940eb59a062aa85a07959518c0161"
PINNED_BLOCK = 25643300


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def seed(db_session):
    from db.models import Contract, Job, JobStage, JobStatus, Protocol

    protocol = Protocol(name=f"perim-{uuid.uuid4().hex[:10]}")
    db_session.add(protocol)
    db_session.commit()
    protocol_id = protocol.id
    minted: list[str] = []

    def address_factory() -> str:
        addr = ("0x" + uuid.uuid4().hex + "0" * 8).lower()
        minted.append(addr)
        return addr

    parent_address = address_factory()
    parent = Job(
        company="perim-co",
        protocol_id=protocol_id,
        stage=JobStage.policy,
        status=JobStatus.processing,
        address=parent_address,
        chain_id=1,
        request={"address": parent_address, "chain": "ethereum", "protocol_id": protocol_id},
    )
    db_session.add(parent)
    db_session.commit()

    try:
        yield protocol_id, parent, address_factory
    finally:
        db_session.rollback()
        db_session.query(Contract).filter_by(protocol_id=protocol_id).delete()
        if minted:
            db_session.query(Contract).filter(Contract.address.in_(minted)).delete(synchronize_session=False)
            db_session.query(Job).filter(Job.address.in_(minted)).delete(synchronize_session=False)
        db_session.query(Job).filter_by(protocol_id=protocol_id).delete()
        db_session.query(Protocol).filter_by(id=protocol_id).delete()
        db_session.commit()


def _node(address, *, analyzed=True, node_type="contract", source=ROLE_GRANT, label="role principal") -> dict:
    return {
        "id": f"n:{address}",
        "address": address,
        "node_type": node_type,
        "resolved_type": "contract",
        "label": label,
        "contract_name": None,
        "depth": 1,
        "analyzed": analyzed,
        "details": {"source": source} if source else {},
    }


def _graph(root, nodes) -> dict:
    return {"root_contract_address": root, "max_depth": 6, "nodes": nodes, "edges": []}


def _spawn(session, job, graph, **kwargs) -> dict:
    kwargs.setdefault("site", "policy_refresh")
    kwargs.setdefault("chain_name", "ethereum")
    return dict(queue_discovered_contracts(session, job, graph, "https://rpc.example", **kwargs))


def _jobs_for(session, address):
    from db.models import Job

    return session.query(Job).filter(Job.address == address.lower()).all()


# ---------------------------------------------------------------------------
# The fix
# ---------------------------------------------------------------------------


def test_role_grant_node_spawns_exactly_one_child_with_inherited_scope(db_session, seed, monkeypatch):
    """The C3 fix. One role-grant contract node ⇒ exactly ONE child job, with
    the chain stamped from the parent and the protocol inherited — byte-exact
    request."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    protocol_id, parent, address_factory = seed
    manager = address_factory()

    result = _spawn(db_session, parent, _graph(parent.address, [_node(manager)]), budget=8, depth_cap=2)

    jobs = _jobs_for(db_session, manager)
    assert len(jobs) == 1
    child = jobs[0]
    assert child.protocol_id == protocol_id
    assert child.company == "perim-co"
    assert child.request == {
        "address": manager,
        "name": "role principal",
        "rpc_url": "https://rpc.example",
        "parent_job_id": str(parent.id),
        "discovered_by": "policy_refresh",
        "chain": "ethereum",
        PERIMETER_DEPTH_KEY: 1,
    }
    assert result["queued"] == [{"address": manager, "name": "role principal", "job_id": str(child.id)}]
    assert result["omitted"] == []
    assert result["budget_used"] == 1


def test_spawn_is_idempotent(db_session, seed, monkeypatch):
    """Run the refresh twice ⇒ still exactly one job. The second pass finds the
    child via ``find_existing_job_for_address`` and books it out-of-population,
    not as an omission: an address that already HAS a job was never dropped."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, address_factory = seed
    manager = address_factory()
    graph = _graph(parent.address, [_node(manager)])

    _spawn(db_session, parent, graph, budget=8, depth_cap=2)
    second = _spawn(db_session, parent, graph, budget=8, depth_cap=2)

    assert len(_jobs_for(db_session, manager)) == 1
    assert second["queued"] == []
    assert second["omitted"] == []
    assert second["out_of_population"] == [{"address": manager, "reason": "existing_job"}]


# ---------------------------------------------------------------------------
# Fail-closed arms
# ---------------------------------------------------------------------------


def test_unanalyzed_node_spawns_nothing(db_session, seed, monkeypatch):
    """``analyzed=false`` ⇒ zero jobs. The walk did not analyse it, so nothing
    is known about it — spawning would be acting on an absence."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, address_factory = seed
    addr = address_factory()

    result = _spawn(db_session, parent, _graph(parent.address, [_node(addr, analyzed=False)]), budget=8)

    assert _jobs_for(db_session, addr) == []
    assert result["queued"] == []
    assert result["omitted"] == []
    assert result["out_of_population"] == [{"address": addr, "reason": "not_analyzed"}]


def test_principal_node_spawns_nothing(db_session, seed, monkeypatch):
    """``node_type='principal'`` ⇒ zero jobs. The 7 role-grant PRINCIPAL nodes
    in the corpus are EOAs/unclassified; an analysis job on one can only fail."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, address_factory = seed
    addr = address_factory()

    result = _spawn(db_session, parent, _graph(parent.address, [_node(addr, node_type="principal")]), budget=8)

    assert _jobs_for(db_session, addr) == []
    assert result["out_of_population"] == [{"address": addr, "reason": "not_contract_node"}]


def test_disabled_chain_spawns_nothing_and_logs_the_reason(db_session, seed, monkeypatch, caplog):
    """A disabled chain ⇒ zero jobs plus an explicit skip record. This is an
    OMISSION, not a carve-out: on an enabled deployment the same node would be
    analysed."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, address_factory = seed
    addr = address_factory()

    with caplog.at_level("INFO"):
        result = _spawn(
            db_session,
            parent,
            _graph(parent.address, [_node(addr)]),
            chain_name="base",
            budget=8,
        )

    assert _jobs_for(db_session, addr) == []
    assert result["omitted"] == [{"address": addr, "reason": "chain_not_enabled"}]
    assert any(getattr(rec, "reason", None) == "chain_not_enabled" for rec in caplog.records)


def test_zero_address_spawns_nothing(db_session, seed, monkeypatch):
    """An unset controller resolves to 0x000…0; queuing it spawns a job that can
    only fail with "No verified source code"."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, _address_factory = seed

    result = _spawn(db_session, parent, _graph(parent.address, [_node(ZERO_ADDRESS)]), budget=8)

    assert _jobs_for(db_session, ZERO_ADDRESS) == []
    assert result["omitted"] == [{"address": ZERO_ADDRESS, "reason": "zero_address"}]


# ---------------------------------------------------------------------------
# The budget, and the partition invariant
# ---------------------------------------------------------------------------


def test_budget_cut_is_recorded_never_silent(db_session, seed, monkeypatch):
    """The recursive fanout's budget. A cut candidate is NAMED — the C2 defect
    was a budget that dropped 0xcd425f44 with nothing but a count to show."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, address_factory = seed
    addrs = [address_factory() for _ in range(3)]

    result = _spawn(db_session, parent, _graph(parent.address, [_node(a) for a in addrs]), budget=1, depth_cap=2)

    assert len(result["queued"]) == 1
    assert len(result["omitted"]) == 2
    assert {r["reason"] for r in result["omitted"]} == {"budget_exhausted"}
    assert result["budget_used"] == 1


def test_depth_cap_stops_the_recursion(db_session, seed, monkeypatch):
    """A manager analysed by this fix runs its own policy stage and projects its
    own role principals. Without a generation cap that recursion has no bound."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, address_factory = seed
    addr = address_factory()
    parent.request = {**parent.request, PERIMETER_DEPTH_KEY: 2}
    db_session.commit()

    result = _spawn(db_session, parent, _graph(parent.address, [_node(addr)]), budget=8, depth_cap=2)

    assert _jobs_for(db_session, addr) == []
    assert result["omitted"] == [{"address": addr, "reason": "depth_exhausted"}]
    assert result["spawn_depth"] == 2


def test_chain_gate_consumes_no_budget(db_session, seed, monkeypatch):
    """FALSIFIER (A7): ordering is not enforceable by statement order, so the
    budget is spent at ``create_job`` and nowhere else. With budget=1 and a
    chain-disabled node FIRST, the disabled node must be recorded as
    ``chain_not_enabled`` (not ``budget_exhausted``) AND the valid node must
    still be queued. A gate that consumed budget would starve it."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, address_factory = seed
    blocked, valid = address_factory(), address_factory()

    # chain_name is per-call, so drive the gate with a chain the allowlist omits
    # and assert on the ONE call where both nodes share it.
    result = _spawn(
        db_session,
        parent,
        _graph(parent.address, [_node(blocked), _node(valid)]),
        chain_name="base",
        budget=1,
    )
    assert [r["reason"] for r in result["omitted"]] == ["chain_not_enabled", "chain_not_enabled"]
    assert result["budget_used"] == 0

    # Same shape with the chain enabled: budget=1 admits exactly the first.
    result2 = _spawn(
        db_session,
        parent,
        _graph(parent.address, [_node(blocked), _node(valid)]),
        chain_name="ethereum",
        budget=1,
    )
    assert len(result2["queued"]) == 1
    assert [r["reason"] for r in result2["omitted"]] == ["budget_exhausted"]


def test_dispositions_totally_partition_the_node_list(db_session, seed, monkeypatch):
    """FALSIFIER (A4): every node lands in exactly one of the three buckets.

    This is what makes "zero UNLOGGED omissions" checkable: a node that fell out
    of the loop through an unaccounted ``continue`` would break the total.
    """
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, address_factory = seed
    already_jobbed = address_factory()
    fresh = address_factory()
    unanalyzed = address_factory()
    principal = address_factory()

    # Give one node a pre-existing job so the dedup arm is exercised.
    _spawn(db_session, parent, _graph(parent.address, [_node(already_jobbed)]), budget=8)

    nodes = [
        _node(parent.address),  # the root itself
        _node(already_jobbed),
        _node(fresh),
        _node(unanalyzed, analyzed=False),
        _node(principal, node_type="principal"),
        _node(ZERO_ADDRESS),
    ]
    result = _spawn(db_session, parent, _graph(parent.address, nodes), budget=8, depth_cap=2)

    total = len(result["queued"]) + len(result["omitted"]) + len(result["out_of_population"])
    assert total == len(nodes)

    reasons = {r["address"]: r["reason"] for r in result["out_of_population"]}
    assert reasons[parent.address] == "root_node"
    assert reasons[already_jobbed] == "existing_job"
    assert reasons[unanalyzed] == "not_analyzed"
    assert reasons[principal] == "not_contract_node"
    assert result["omitted"] == [{"address": ZERO_ADDRESS, "reason": "zero_address"}]
    assert [q["address"] for q in result["queued"]] == [fresh]


def test_resolution_site_keeps_its_unbudgeted_behaviour(db_session, seed, monkeypatch):
    """Parity: the resolution stage passes no budget, so its spawn is unchanged
    by this unit. Its bound is the walk's own ``max_depth``."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, address_factory = seed
    addrs = [address_factory() for _ in range(3)]

    result = _spawn(
        db_session,
        parent,
        _graph(parent.address, [_node(a) for a in addrs]),
        site="resolution",
        budget=None,
    )

    assert len(result["queued"]) == 3
    assert result["omitted"] == []
    assert result["budget"] is None
    # No generation key when no cap is in force — the resolution stage's
    # children must not inherit a perimeter generation they never belonged to.
    from db.models import Job

    child = db_session.query(Job).filter(Job.address == addrs[0]).one()
    assert PERIMETER_DEPTH_KEY not in child.request
    assert child.request["discovered_by"] == "resolution"


# ---------------------------------------------------------------------------
# The back-link witness
# ---------------------------------------------------------------------------


def _wire_backlink(monkeypatch, *, vault_return, control_answers=False, head: int | None = PINNED_BLOCK):
    """Stub the wire under ``probe_declared_vault_backlink``.

    ``vault_return`` is the raw ``eth_call`` result for ``vault()``, or the
    string ``"revert"`` to raise.

    ``tests/conftest.py`` neuters ``_resolve_pinned_block`` for the whole offline
    suite (the head read is unconditional and would dial out). We restore the
    REAL one here — the C1 pattern — so the height-pinning logic under test is
    the production one, and drive it from the stubbed wire instead.
    """
    from services.resolution import tracking

    monkeypatch.setattr(tracking, "_resolve_pinned_block", _REAL_RESOLVE_PINNED_BLOCK)

    def fake_rpc(rpc_url, method, params, chain_id=None):
        if method == "eth_blockNumber":
            if head is None:
                raise RuntimeError("head read failed")
            return hex(head)
        if method == "eth_call":
            data = params[0]["data"]
            block = params[1]
            # Every read must be pinned to the SAME concrete height that gets
            # published — never a moving alias. (Unreachable when head is None:
            # the head read above raises first, suppressing the whole probe.)
            assert head is not None
            assert block == hex(head), f"unpinned read at {block}"
            if data == tracking._selector(tracking._NEGATIVE_CONTROL_SIG):
                if control_answers:
                    return "0x" + "0" * 63 + "1"
                raise RuntimeError("execution reverted")
            if data == tracking._selector("vault()"):
                if vault_return == "revert":
                    raise RuntimeError("execution reverted")
                return vault_return
        raise AssertionError(f"unexpected call {method} {params}")

    monkeypatch.setattr(tracking, "_rpc_request", fake_rpc)


def _word(address: str) -> str:
    return "0x" + address[2:].lower().rjust(64, "0")


def test_backlink_confirms_the_pairing(monkeypatch):
    """The positive. Reproduces the measured 10/10 shape: M declares V, the
    nonsense selector reverts, and the height is concrete."""
    from services.resolution.tracking import probe_declared_vault_backlink

    _wire_backlink(monkeypatch, vault_return=_word(VAULT))
    out = probe_declared_vault_backlink("https://rpc.example", MANAGER, VAULT)

    assert out == {
        "probe_block": PINNED_BLOCK,
        "backlink_getter": "vault()",
        "backlink_address": VAULT,
        "negative_control": "passed",
        "declared_vault_matches_gated_contract": True,
    }


def test_mismatched_vault_is_not_determined_never_the_assumed_pairing(monkeypatch):
    """A DIFFERENT vault() answer yields ``not_determined`` — never the pairing
    the projection assumed, and never a disproof of it. The non-matching address
    is deliberately withheld so a consumer cannot reconstruct the mismatch and
    read it as an earned negative."""
    from services.resolution.tracking import probe_declared_vault_backlink

    other = "0x1111111111111111111111111111111111111111"
    _wire_backlink(monkeypatch, vault_return=_word(other))
    out = probe_declared_vault_backlink("https://rpc.example", MANAGER, VAULT)
    assert out is not None

    assert out["declared_vault_matches_gated_contract"] == "not_determined"
    assert out["backlink_address"] == "not_determined"
    assert other not in str(out)


def test_reverting_getter_is_not_determined(monkeypatch):
    """The 9 non-manager role-grant contracts (Pauser, BoringSolver, …) have no
    ``vault()``. A revert is not "no back-link exists" and not a falsification —
    it is simply undetermined, and it fires no control."""
    from services.resolution.tracking import probe_declared_vault_backlink

    _wire_backlink(monkeypatch, vault_return="revert")
    out = probe_declared_vault_backlink("https://rpc.example", MANAGER, VAULT)
    assert out is not None

    assert out["declared_vault_matches_gated_contract"] == "not_determined"
    assert out["backlink_address"] == "not_determined"
    assert out["negative_control"] == "not_determined"


def test_catch_all_fallback_cannot_mint_a_backlink(monkeypatch):
    """An address that answers a selector nothing implements is a catch-all
    fallback: its ``vault()`` answer is worthless even when it equals V."""
    from services.resolution.tracking import probe_declared_vault_backlink

    _wire_backlink(monkeypatch, vault_return=_word(VAULT), control_answers=True)
    out = probe_declared_vault_backlink("https://rpc.example", MANAGER, VAULT)
    assert out is not None

    assert out["negative_control"] == "failed"
    assert out["declared_vault_matches_gated_contract"] == "not_determined"
    assert out["backlink_address"] == "not_determined"


def test_unpinnable_height_suppresses_the_whole_witness(monkeypatch):
    """FALSIFIER (A6): a failed head read yields the key WHOLLY ABSENT, not a
    positive with an unstated height. Two facts on one node row may not carry
    different unrecorded heights."""
    from services.resolution.tracking import probe_declared_vault_backlink

    _wire_backlink(monkeypatch, vault_return=_word(VAULT), head=None)
    assert probe_declared_vault_backlink("https://rpc.example", MANAGER, VAULT) is None


def test_non_manager_backlink_publishes_true_and_attributes_nothing(monkeypatch):
    """FALSIFIER (A3): a non-manager (measured: 0x35dd2463…, a LayerZeroTeller)
    whose ``vault()`` returns the same V publishes ``True`` exactly as a manager
    does. The field therefore earns only the PAIRING, never the TYPE — nothing
    downstream may read it as "M is the manager"."""
    from services.resolution.tracking import probe_declared_vault_backlink

    teller = "0x35dd2463d67f7d0da22c4c4f6c96b7d0e6ff08b1"
    _wire_backlink(monkeypatch, vault_return=_word(VAULT))
    out = probe_declared_vault_backlink("https://rpc.example", teller, VAULT)
    assert out is not None

    assert out["declared_vault_matches_gated_contract"] is True
    # The witness carries no component type, no role, and no gate-holder claim:
    # the key set is exactly the five below, so there is nothing for a consumer
    # to read a type off.
    assert set(out) == {
        "probe_block",
        "backlink_getter",
        "backlink_address",
        "negative_control",
        "declared_vault_matches_gated_contract",
    }


def test_probe_fires_only_for_role_grant_contract_nodes(monkeypatch):
    """Provenance, not name. The gate reads ``details.source`` — a field a named
    code path wrote — so the label string never participates, and the ~88
    plain-principal nodes pay no RPC."""
    from services.resolution import recursive

    calls: list[tuple[str, str]] = []

    def fake_probe(rpc_url, principal, gated, chain_id=None) -> dict:
        calls.append((principal, gated))
        return {"probe_block": PINNED_BLOCK}

    monkeypatch.setattr(recursive, "probe_declared_vault_backlink", fake_probe)

    # A node labelled exactly like a manager but WITHOUT the provenance marker
    # must not be probed; a node with the marker and a useless label must be.
    assert (
        recursive._maybe_probe_backlink(
            "https://rpc.example",
            principal_address=MANAGER,
            gated_contract_address=VAULT,
            details={"source": "controller_value"},
            node_type="contract",
            chain_id=1,
        )
        is None
    )
    assert (
        recursive._maybe_probe_backlink(
            "https://rpc.example",
            principal_address=MANAGER,
            gated_contract_address=VAULT,
            details={"source": ROLE_GRANT},
            node_type="principal",
            chain_id=1,
        )
        is None
    )
    assert recursive._maybe_probe_backlink(
        "https://rpc.example",
        principal_address=MANAGER,
        gated_contract_address=VAULT,
        details={"source": ROLE_GRANT},
        node_type="contract",
        chain_id=1,
    ) == {"probe_block": PINNED_BLOCK}
    assert calls == [(MANAGER, VAULT)]


def test_probe_failure_never_breaks_the_walk(monkeypatch):
    """The witness is optional. A raising probe yields no witness and no
    exception — an absent back-link is honest, a failed graph walk is not."""
    from services.resolution import recursive

    def boom(*args, **kwargs):
        raise RuntimeError("rpc down")

    monkeypatch.setattr(recursive, "probe_declared_vault_backlink", boom)
    assert (
        recursive._maybe_probe_backlink(
            "https://rpc.example",
            principal_address=MANAGER,
            gated_contract_address=VAULT,
            details={"source": ROLE_GRANT},
            node_type="contract",
            chain_id=1,
        )
        is None
    )
