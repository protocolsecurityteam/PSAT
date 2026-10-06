"""The analysis perimeter's second spawn site (C3), and its back-link witness.

Ten ``ManagerWithMerkleVerification`` contracts gate a BoringVault's ``manage`` yet had no job, because the policy
stage never called the spawn. The spawn keys on ``details.source``, never the label (9 of 19 jobless role-grant
contracts are non-managers). The ``vault()`` witness corroborates only the pairing; see
``probe_declared_vault_backlink``.
"""

from __future__ import annotations

import uuid

import pytest

from services.discovery.perimeter import (
    PERIMETER_DEPTH_KEY,
    ZERO_ADDRESS,
    queue_discovered_contracts,
)
from services.resolution.tracking import (
    _resolve_pinned_block as _REAL_RESOLVE_PINNED_BLOCK,
)
from tests.conftest import requires_postgres

pytestmark = [requires_postgres]

ROLE_GRANT = "semantic_capability:role_grant"

# The real pairing at the pinned height.
MANAGER = "0x66aae0ee1f68c658401c7d8d6e417202a99545d7"
VAULT = "0x86b5780b606940eb59a062aa85a07959518c0161"
# Not a manager, but its vault() returns the same address.
TELLER = "0x35dd2463fa7a335b721400c5ad8ba40bd85c179b"
PINNED_BLOCK = 25643300


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


def test_role_grant_node_spawns_exactly_one_child_with_inherited_scope(db_session, seed, monkeypatch):
    """``name`` is the address; the node label describes the edge."""
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
        "name": manager,
        "rpc_url": "https://rpc.example",
        "parent_job_id": str(parent.id),
        "root_job_id": (parent.request or {}).get("root_job_id") or str(parent.id),
        "discovered_by": "policy_refresh",
        "chain": "ethereum",
        PERIMETER_DEPTH_KEY: 1,
    }
    assert result["queued"] == [{"address": manager, "name": manager, "job_id": str(child.id)}]
    assert result["omitted"] == []
    assert result["budget_used"] == 1


def test_disabled_chain_spawns_nothing_and_logs_the_reason(db_session, seed, monkeypatch, caplog):
    """An enabled deployment would analyse it, so it's an omission, not a carve-out."""
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


def test_budget_cut_is_recorded_never_silent(db_session, seed, monkeypatch):
    """The C2 defect dropped 0xcd425f44 with only a count to show."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, address_factory = seed
    addrs = [address_factory() for _ in range(3)]

    result = _spawn(db_session, parent, _graph(parent.address, [_node(a) for a in addrs]), budget=1, depth_cap=2)

    assert len(result["queued"]) == 1
    assert len(result["omitted"]) == 2
    assert {r["reason"] for r in result["omitted"]} == {"budget_exhausted"}
    assert result["budget_used"] == 1


def test_depth_cap_stops_the_recursion(db_session, seed, monkeypatch):
    """A newly analysed manager projects its own role principals, so recursion needs a generation cap."""
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
    """Budget is spent only at ``create_job``."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, address_factory = seed
    blocked, valid = address_factory(), address_factory()

    result = _spawn(
        db_session,
        parent,
        _graph(parent.address, [_node(blocked), _node(valid)]),
        chain_name="base",
        budget=1,
    )
    assert [r["reason"] for r in result["omitted"]] == ["chain_not_enabled", "chain_not_enabled"]
    assert result["budget_used"] == 0

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
    """An unaccounted ``continue`` breaks the total."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, address_factory = seed
    already_jobbed = address_factory()
    fresh = address_factory()
    unanalyzed = address_factory()
    principal = address_factory()

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

    assert result["walked"] is True
    total = len(result["queued"]) + len(result["omitted"]) + len(result["out_of_population"])
    assert total == len(nodes)

    reasons = {r["address"]: r["reason"] for r in result["out_of_population"]}
    assert reasons[parent.address] == "root_node"
    assert reasons[already_jobbed] == "existing_job"
    assert reasons[unanalyzed] == "not_analyzed"
    assert reasons[principal] == "not_contract_node"
    assert result["omitted"] == [{"address": ZERO_ADDRESS, "reason": "zero_address"}]
    assert [q["address"] for q in result["queued"]] == [fresh]


def test_ledger_is_written_even_when_the_refresh_produced_no_graph(db_session, seed, monkeypatch):
    """Absence would be ambiguous between "didn't run" and "omitted nothing"."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, _address_factory = seed
    from db.queue import get_artifact
    from services.discovery.perimeter import new_spawn_result
    from workers.policy_worker import _persist_spawn_summary

    ledger = new_spawn_result(site="policy_refresh", budget=8)
    _persist_spawn_summary(db_session, parent, ledger)

    stored = get_artifact(db_session, parent.id, "perimeter_spawn_summary")
    assert stored == {
        "site": "policy_refresh",
        "budget": 8,
        "budget_used": 0,
        "spawn_depth": 0,
        "queued": [],
        "omitted": [],
        "out_of_population": [],
        "walked": False,
    }


def test_never_ran_ledger_differs_from_a_walk_that_omitted_nothing(db_session, seed, monkeypatch):
    """Only the second walked the list and may license "nothing omitted"."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, address_factory = seed
    from services.discovery.perimeter import new_spawn_result

    never_ran = new_spawn_result(site="policy_refresh", budget=8)

    walked = _spawn(db_session, parent, _graph(parent.address, [_node(address_factory())]), budget=8, depth_cap=2)
    assert never_ran["omitted"] == walked["omitted"] == []
    assert never_ran["out_of_population"] == walked["out_of_population"] == []

    assert never_ran["walked"] is False
    assert walked["walked"] is True
    assert never_ran != walked


def test_ledger_survives_a_poisoned_session(db_session, seed, monkeypatch):
    """A mid-loop raise usually aborts the primary transaction."""
    from db.queue import get_artifact
    from services.discovery.perimeter import new_spawn_result
    from workers.policy_worker import _persist_spawn_summary

    _protocol_id, parent, _address_factory = seed
    ledger = new_spawn_result(site="policy_refresh", budget=8)
    ledger["queued"].append({"address": "0xabc", "name": "n", "job_id": "j"})

    calls = {"n": 0}
    import workers.policy_worker as pw

    real_store = pw.store_artifact

    def flaky_store(session, job_id, name, data=None, text_data=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transaction aborted")
        return real_store(session, job_id, name, data=data, text_data=text_data)

    monkeypatch.setattr(pw, "store_artifact", flaky_store)
    _persist_spawn_summary(db_session, parent, ledger)

    assert calls["n"] == 2  # primary failed, fresh session retried
    stored = get_artifact(db_session, parent.id, "perimeter_spawn_summary")
    assert isinstance(stored, dict)
    assert stored["queued"] == [{"address": "0xabc", "name": "n", "job_id": "j"}]


def _wire_backlink(monkeypatch, *, vault_return, control_answers=False, head: int | None = PINNED_BLOCK):
    """The conftest neuters ``_resolve_pinned_block`` offline, so the real one is restored and driven from the stub."""
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
            # Every read is pinned to the published height, never a moving alias.
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
    from services.resolution.tracking import probe_declared_vault_backlink

    _wire_backlink(monkeypatch, vault_return=_word(VAULT))
    out = probe_declared_vault_backlink("https://rpc.example", MANAGER, VAULT)

    assert out == {
        "probe_block": PINNED_BLOCK,
        "backlink_getter": "vault()",
        "gated_contract_address": VAULT,
        "backlink_address": VAULT,
        "negative_control": "passed",
        "declared_vault_matches_gated_contract": True,
    }


def test_mismatch_payload_is_byte_identical_to_the_never_read_payload(monkeypatch):
    """Any leaked key would make "declares a different vault" an earned negative this witness refuses."""
    from services.resolution.tracking import probe_declared_vault_backlink

    other = "0x1111111111111111111111111111111111111111"

    _wire_backlink(monkeypatch, vault_return=_word(other))
    mismatch = probe_declared_vault_backlink("https://rpc.example", MANAGER, VAULT)

    _wire_backlink(monkeypatch, vault_return="revert")
    never_read = probe_declared_vault_backlink("https://rpc.example", MANAGER, VAULT)

    assert mismatch == never_read
    assert mismatch == {
        "probe_block": PINNED_BLOCK,
        "backlink_getter": "vault()",
        "gated_contract_address": VAULT,
        "backlink_address": "not_determined",
        "negative_control": "not_determined",
        "declared_vault_matches_gated_contract": "not_determined",
    }
    assert other not in str(mismatch)


def test_catch_all_fallback_cannot_mint_a_backlink(monkeypatch):
    from services.resolution.tracking import probe_declared_vault_backlink

    _wire_backlink(monkeypatch, vault_return=_word(VAULT), control_answers=True)
    out = probe_declared_vault_backlink("https://rpc.example", MANAGER, VAULT)
    assert out is not None

    assert out["negative_control"] == "failed"
    assert out["declared_vault_matches_gated_contract"] == "not_determined"
    assert out["backlink_address"] == "not_determined"


def test_probe_fires_only_for_role_grant_contract_nodes(monkeypatch):
    """The ~88 plain-principal nodes pay no RPC."""
    from services.resolution import recursive

    calls: list[tuple[str, str]] = []

    def fake_probe(rpc_url, principal, gated, chain_id=None) -> dict:
        calls.append((principal, gated))
        return {"probe_block": PINNED_BLOCK}

    monkeypatch.setattr(recursive, "probe_declared_vault_backlink", fake_probe)

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
