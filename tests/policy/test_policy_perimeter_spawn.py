"""The analysis perimeter's second spawn site (C3), and its back-link witness.

Ten `ManagerWithMerkleVerification` contracts hold the sole `canCall` on a
BoringVault's `manage` yet have no analysis job, so 30 `contract_gated_unknown_path`
warnings stood. They satisfy every spawn gate (`analyzed=true`, `node_type='contract'`,
`details->>'source' = 'semantic_capability:role_grant'`) but the policy stage's graph
refresh — the only stage that can project role principals — never called the spawn.
The spawn keys on that provenance field, never the label: 9 of 19 jobless role-grant
contracts on the PR-161 corpus are non-managers (Pausers, Solvers, ...).

The `vault()` back-link witness (verified 10/10 at block 25643300, negative control
10/10) corroborates the (M, V) PAIRING only; it doesn't establish M is a manager and a
mismatch is not a disproof. See `probe_declared_vault_backlink`.
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

# The real pairing, at the real pinned height, from lane C and re-measured:
# 0x66aae0ee… `vault()` -> 0x86b5780b… (BoringGovernance), whose `manage` it gates.
MANAGER = "0x66aae0ee1f68c658401c7d8d6e417202a99545d7"
VAULT = "0x86b5780b606940eb59a062aa85a07959518c0161"
# A LayerZeroTeller, NOT a manager, whose vault() IS 0x86b5780b… — re-measured at
# 25643300, control passing. One of the TEN non-managers among the 20 pairs that
# publish `true`.
TELLER = "0x35dd2463fa7a335b721400c5ad8ba40bd85c179b"
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
    """One role-grant contract node ⇒ exactly ONE child job, chain stamped from the
    parent and protocol inherited — byte-exact request.

    ``name`` is the ADDRESS, not the node's ``label`` (display copy describing the
    EDGE, "role principal"); only ``contract_name`` may fill ``Job.name``.
    """
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
        "discovered_by": "policy_refresh",
        "chain": "ethereum",
        PERIMETER_DEPTH_KEY: 1,
    }
    assert result["queued"] == [{"address": manager, "name": manager, "job_id": str(child.id)}]
    assert result["omitted"] == []
    assert result["budget_used"] == 1


def test_a_contract_name_still_names_the_child(db_session, seed, monkeypatch):
    """The label leg is dropped; a real compiled ``contract_name`` still reaches the child."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, address_factory = seed
    manager = address_factory()
    node = {**_node(manager), "contract_name": "ManagerWithMerkleVerification"}

    result = _spawn(db_session, parent, _graph(parent.address, [node]), budget=8)

    assert result["queued"][0]["name"] == "ManagerWithMerkleVerification"
    assert _jobs_for(db_session, manager)[0].request["name"] == "ManagerWithMerkleVerification"


def test_spawn_is_idempotent(db_session, seed, monkeypatch):
    """A second pass finds the child via ``find_existing_job_for_address`` and books it
    out-of-population, not as an omission."""
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
    """``analyzed=false`` ⇒ zero jobs; spawning would be acting on an absence."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, address_factory = seed
    addr = address_factory()

    result = _spawn(db_session, parent, _graph(parent.address, [_node(addr, analyzed=False)]), budget=8)

    assert _jobs_for(db_session, addr) == []
    assert result["queued"] == []
    assert result["omitted"] == []
    assert result["out_of_population"] == [{"address": addr, "reason": "not_analyzed"}]


def test_principal_node_spawns_nothing(db_session, seed, monkeypatch):
    """``node_type='principal'`` ⇒ zero jobs; the corpus's 7 role-grant principals are
    EOAs/unclassified, so a job could only fail."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, address_factory = seed
    addr = address_factory()

    result = _spawn(db_session, parent, _graph(parent.address, [_node(addr, node_type="principal")]), budget=8)

    assert _jobs_for(db_session, addr) == []
    assert result["out_of_population"] == [{"address": addr, "reason": "not_contract_node"}]


def test_disabled_chain_spawns_nothing_and_logs_the_reason(db_session, seed, monkeypatch, caplog):
    """A disabled chain ⇒ zero jobs plus an explicit skip record (an OMISSION, not a
    carve-out: an enabled deployment would analyse it)."""
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
    """A cut candidate is NAMED — the C2 defect was a budget that dropped 0xcd425f44
    with only a count to show."""
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, address_factory = seed
    addrs = [address_factory() for _ in range(3)]

    result = _spawn(db_session, parent, _graph(parent.address, [_node(a) for a in addrs]), budget=1, depth_cap=2)

    assert len(result["queued"]) == 1
    assert len(result["omitted"]) == 2
    assert {r["reason"] for r in result["omitted"]} == {"budget_exhausted"}
    assert result["budget_used"] == 1


def test_depth_cap_stops_the_recursion(db_session, seed, monkeypatch):
    """A manager analysed by this fix runs its own policy stage and projects its own
    role principals; without a generation cap that recursion is unbounded."""
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
    """FALSIFIER (A7): budget is spent at ``create_job`` and nowhere else. With
    budget=1 and a chain-disabled node FIRST, it must be ``chain_not_enabled`` (not
    ``budget_exhausted``) AND the valid node must still be queued."""
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
    """FALSIFIER (A4): every node lands in exactly one of the three buckets, so a node
    dropped through an unaccounted ``continue`` breaks the total."""
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

    # The partition claim is only licensed by ``walked``.
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


def test_resolution_site_keeps_its_unbudgeted_behaviour(db_session, seed, monkeypatch):
    """Parity: the resolution stage passes no budget; its bound is the walk's ``max_depth``."""
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
    # No generation key when no cap is in force — children must not inherit a perimeter
    # generation they never belonged to.
    from db.models import Job

    child = db_session.query(Job).filter(Job.address == addrs[0]).one()
    assert PERIMETER_DEPTH_KEY not in child.request
    assert child.request["discovered_by"] == "resolution"


def test_partial_spawn_still_yields_a_ledger(db_session, seed, monkeypatch):
    """FALSIFIER (E1): ``create_job`` raises on the 3rd of 5 nodes; the two committed
    children must still be recorded. A raise part-way used to discard the ledger — the
    silent-drop failure in its worst form (jobs exist, accounting doesn't).
    """
    from services.discovery import perimeter as perimeter_module
    from services.discovery.perimeter import new_spawn_result

    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1")
    _protocol_id, parent, address_factory = seed
    addrs = [address_factory() for _ in range(5)]

    real_create = perimeter_module.create_job
    calls = {"n": 0}

    def flaky_create_job(session, request, **kwargs):
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("simulated create_job failure")
        return real_create(session, request, **kwargs)

    monkeypatch.setattr(perimeter_module, "create_job", flaky_create_job)

    ledger = new_spawn_result(site="policy_refresh", budget=8)
    with pytest.raises(RuntimeError, match="simulated create_job failure"):
        _spawn(
            db_session,
            parent,
            _graph(parent.address, [_node(a) for a in addrs]),
            budget=8,
            depth_cap=2,
            result=ledger,
        )

    assert len(ledger["queued"]) == 2
    assert ledger["budget_used"] == 2
    assert [q["address"] for q in ledger["queued"]] == addrs[:2]
    # The prefix is intact AND marked incomplete: three of the five nodes were
    # never placed in any disposition, so the partition claim must not hold.
    assert ledger["walked"] is False
    total = len(ledger["queued"]) + len(ledger["omitted"]) + len(ledger["out_of_population"])
    assert total < len(addrs)


def test_ledger_is_written_even_when_the_refresh_produced_no_graph(db_session, seed, monkeypatch):
    """FALSIFIER (E2): an ABSENT ledger must not be ambiguous between "refresh didn't
    happen" and "refresh omitted nothing" — absence means the job predates the ledger.
    The published ledger must not read as a COMPLETED walk: ``walked`` is False and the
    empty lists are a prefix.
    """
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
    """FALSIFIER (fix 6): both histories produce three empty omission lists, but only
    the second walked the node list and may license "nothing was omitted"."""
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
    """A mid-loop raise usually leaves the primary transaction aborted, so the
    ledger write in ``finally`` must retry on a fresh session."""
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


# ---------------------------------------------------------------------------
# The back-link witness
# ---------------------------------------------------------------------------


def _wire_backlink(monkeypatch, *, vault_return, control_answers=False, head: int | None = PINNED_BLOCK):
    """Stub the wire under ``probe_declared_vault_backlink``.

    ``vault_return`` is the raw ``eth_call`` result for ``vault()``, or ``"revert"``.
    ``tests/conftest.py`` neuters ``_resolve_pinned_block`` offline (the head read would
    dial out); we restore the REAL one (the C1 pattern) and drive it from the stub.
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
    """The positive: M declares V, the nonsense selector reverts, the height is concrete."""
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
    """FALSIFIER (the mismatch oracle). A DIFFERENT ``vault()`` answer must produce a
    payload byte-for-byte EQUAL to the never-read payload.

    An earlier cut recorded the control verdict before testing equality, making
    ``(negative_control == "passed" AND matches == "not_determined")`` reachable ONLY by
    "M declares a vault and it is not V" — the earned negative this witness refuses,
    leaked one key over. Byte-identity admits no leaking key.
    """
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


def test_reverting_getter_is_not_determined(monkeypatch):
    """The 9 non-manager role-grant contracts have no ``vault()``. A revert is
    undetermined (neither "no back-link" nor a falsification) and fires no control."""
    from services.resolution.tracking import probe_declared_vault_backlink

    _wire_backlink(monkeypatch, vault_return="revert")
    out = probe_declared_vault_backlink("https://rpc.example", MANAGER, VAULT)
    assert out is not None

    assert out["declared_vault_matches_gated_contract"] == "not_determined"
    assert out["backlink_address"] == "not_determined"
    assert out["negative_control"] == "not_determined"


def test_catch_all_fallback_cannot_mint_a_backlink(monkeypatch):
    """A catch-all fallback answers any selector, so its ``vault()`` is worthless even when it equals V."""
    from services.resolution.tracking import probe_declared_vault_backlink

    _wire_backlink(monkeypatch, vault_return=_word(VAULT), control_answers=True)
    out = probe_declared_vault_backlink("https://rpc.example", MANAGER, VAULT)
    assert out is not None

    assert out["negative_control"] == "failed"
    assert out["declared_vault_matches_gated_contract"] == "not_determined"
    assert out["backlink_address"] == "not_determined"


def test_unpinnable_height_suppresses_the_whole_witness(monkeypatch):
    """FALSIFIER (A6): a failed head read yields the key WHOLLY ABSENT, not a positive
    with an unstated height."""
    from services.resolution.tracking import probe_declared_vault_backlink

    _wire_backlink(monkeypatch, vault_return=_word(VAULT), head=None)
    assert probe_declared_vault_backlink("https://rpc.example", MANAGER, VAULT) is None


def test_non_manager_backlink_publishes_true_and_attributes_nothing(monkeypatch):
    """FALSIFIER: a non-manager whose ``vault()`` returns V publishes ``True`` like a
    manager, so the field earns only the PAIRING, never the TYPE.

    Re-measured over 37 (M, V) pairs at 25643300: 20 publish ``True`` and 10 of those
    are not managers (Tellers, solvers, vaults); ``TELLER`` publishes ``true`` today.
    """
    from services.resolution.tracking import probe_declared_vault_backlink

    teller = TELLER
    _wire_backlink(monkeypatch, vault_return=_word(VAULT))
    out = probe_declared_vault_backlink("https://rpc.example", teller, VAULT)
    assert out is not None

    assert out["declared_vault_matches_gated_contract"] is True
    # Exactly five keys: nothing for a consumer to read a type off.
    assert set(out) == {
        "probe_block",
        "backlink_getter",
        "gated_contract_address",
        "backlink_address",
        "negative_control",
        "declared_vault_matches_gated_contract",
    }


def test_probe_fires_only_for_role_grant_contract_nodes(monkeypatch):
    """Provenance, not name: the gate reads ``details.source``, never the label, and
    the ~88 plain-principal nodes pay no RPC."""
    from services.resolution import recursive

    calls: list[tuple[str, str]] = []

    def fake_probe(rpc_url, principal, gated, chain_id=None) -> dict:
        calls.append((principal, gated))
        return {"probe_block": PINNED_BLOCK}

    monkeypatch.setattr(recursive, "probe_declared_vault_backlink", fake_probe)

    # A manager-looking label WITHOUT the marker must not be probed; a marker with a
    # useless label must be.
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
    """The witness is optional: a raising probe yields no witness and no exception."""
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
