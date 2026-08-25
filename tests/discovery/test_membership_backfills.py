"""Backfill scripts (DISCOVERY_MEMBERSHIP_GATE_SPEC.md §5.3.1–§5.3.2), wire
stubbed at the transport boundary. Covers chunking, idempotence, rate-limit
override handling, and the parked-explainable posture for unroutable chains.
"""

from __future__ import annotations

import pytest

from db.models import Contract, ContractCreationWitness, ContractProbeAttempt
from scripts import backfill_code_probes, backfill_deployers
from services.clients import etherscan
from services.discovery import probes
from tests.conftest import ADDR, requires_postgres

pytestmark = [requires_postgres]

_CREATOR = ADDR(0xC0)
_TX = "0x" + "34" * 32


def _contract(session, address: str, *, chain: str = "ethereum", deployer: str | None = None) -> Contract:
    row = Contract(address=address.lower(), chain=chain, deployer=deployer)
    session.add(row)
    session.flush()
    return row


def _stub_creations(monkeypatch, *, answered: set[str]) -> list[list[str]]:
    """Stub ``etherscan.get`` for getcontractcreation; returns the per-call
    address batches so chunking is assertable."""
    batches: list[list[str]] = []

    def fake_get(module, action, chain_id=None, **params):
        assert (module, action) == ("contract", "getcontractcreation")
        batch = params["contractaddresses"].split(",")
        batches.append(batch)
        return {
            "result": [
                {"contractAddress": a, "txHash": _TX, "blockNumber": "17", "contractCreator": _CREATOR}
                for a in batch
                if a in answered
            ]
        }

    monkeypatch.setattr(probes.etherscan, "get", fake_get)
    return batches


# ---------------------------------------------------------------------------
# Deployer backfill (§5.3.1)
# ---------------------------------------------------------------------------


def test_plan_targets_null_deployer_only_and_unresolvable_reported(db_session):
    _contract(db_session, ADDR(1), deployer=ADDR(0xD0))
    _contract(db_session, ADDR(2))
    _contract(db_session, ADDR(3), chain="not-a-chain")
    targets, skipped = backfill_deployers.plan_targets(db_session)
    assert [t.address for t in targets] == [ADDR(2)]
    assert targets[0].chain_id == 1
    # canonical_chain folds hyphens to spaces before the id lookup fails.
    assert skipped == {"chain_unresolvable:not a chain": 1}


def test_plan_targets_excludes_code_absent_rows(db_session):
    # A probe proved no code at (address, chain): nothing deployable exists
    # there, so a creation fetch is spend with no witness value.
    pruned = _contract(db_session, ADDR(0x50))
    db_session.add(
        ContractCreationWitness(chain_id=1, address=pruned.address, code_probe_block=9, code_absent_at_probe=True)
    )
    live = _contract(db_session, ADDR(0x51))
    db_session.flush()
    targets, skipped = backfill_deployers.plan_targets(db_session)
    assert [t.address for t in targets] == [live.address]
    assert skipped == {"code_absent": 1}


def test_run_backfill_chunks_five_per_call_and_fills(db_session, monkeypatch):
    rows = [_contract(db_session, ADDR(0x10 + n)) for n in range(7)]
    unanswered = rows[-1].address
    batches = _stub_creations(monkeypatch, answered={r.address for r in rows[:-1]})

    targets, _ = backfill_deployers.plan_targets(db_session)
    counts = backfill_deployers.run_backfill(db_session, targets, commit=False)

    # fetch_creations chunks 5 addresses/call.
    assert [len(b) for b in batches] == [5, 2]
    assert counts == {"filled": 6, "unanswered": 1, "no_creator": 0}
    for row in rows[:-1]:
        assert row.deployer == _CREATOR
        witness = db_session.get(ContractCreationWitness, (1, row.address))
        assert witness is not None and witness.creation_tx_hash == _TX and witness.creation_block == 17
    assert rows[-1].address == unanswered and rows[-1].deployer is None


def test_run_backfill_idempotent_rerun_selects_nothing(db_session, monkeypatch):
    _contract(db_session, ADDR(0x20))
    batches = _stub_creations(monkeypatch, answered={ADDR(0x20)})
    targets, _ = backfill_deployers.plan_targets(db_session)
    backfill_deployers.run_backfill(db_session, targets, commit=False)
    assert len(batches) == 1

    targets, _ = backfill_deployers.plan_targets(db_session)
    assert targets == []
    backfill_deployers.run_backfill(db_session, targets, commit=False)
    assert len(batches) == 1  # no further wire calls


def test_run_backfill_limit_and_chain_filter(db_session, monkeypatch):
    _contract(db_session, ADDR(0x30))
    _contract(db_session, ADDR(0x31))
    _contract(db_session, ADDR(0x32), chain="base")
    _stub_creations(monkeypatch, answered=set())
    targets, _ = backfill_deployers.plan_targets(db_session, chain="base")
    assert [t.chain for t in targets] == ["base"] and targets[0].chain_id == 8453
    targets, _ = backfill_deployers.plan_targets(db_session, limit=1)
    assert len(targets) == 1


def test_rate_limit_override(monkeypatch):
    monkeypatch.setattr(etherscan, "_min_interval", etherscan._min_interval)
    backfill_deployers.apply_rate_limit_override(10)
    assert etherscan._min_interval == pytest.approx(0.1)
    with pytest.raises(ValueError):
        backfill_deployers.apply_rate_limit_override(0)


# ---------------------------------------------------------------------------
# Code-probe backfill (§5.3.2)
# ---------------------------------------------------------------------------


@pytest.fixture()
def erpc_env(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "http://erpc.test")


def _stub_probe_wire(monkeypatch, *, code: str = "0x6001") -> dict:
    seen: dict = {"rpc": []}

    def fake_rpc_request(rpc_url, method, params, *args, **kwargs):
        seen["rpc"].append((method, params))
        if method == "eth_blockNumber":
            return hex(100)
        if method == "eth_getCode":
            return code
        raise AssertionError(f"unexpected rpc method {method}")

    def fake_eth_call_batch(rpc_url, calls, block_tag="latest", **kwargs):
        from services.clients.rpc import EthCallResult

        return [EthCallResult(False, "0x", None, "execution reverted") for _ in calls]

    def fake_rpc_batch_request(rpc_url, calls, *args, **kwargs):
        return ["0x" + "0" * 64 for _ in calls]

    def fake_etherscan_get(module, action, chain_id=None, **params):
        return {"result": []}

    monkeypatch.setattr(probes, "rpc_request", fake_rpc_request)
    monkeypatch.setattr(probes, "eth_call_batch", fake_eth_call_batch)
    monkeypatch.setattr(probes, "rpc_batch_request", fake_rpc_batch_request)
    monkeypatch.setattr(probes.etherscan, "get", fake_etherscan_get)
    return seen


def test_plan_skips_rows_with_code_fact(db_session):
    probed = _contract(db_session, ADDR(0x40))
    db_session.add(
        ContractCreationWitness(chain_id=1, address=probed.address, code_probe_block=9, code_absent_at_probe=False)
    )
    missing = _contract(db_session, ADDR(0x41))
    db_session.flush()
    targets, skipped = backfill_code_probes.plan_targets(db_session)
    assert targets == [missing.id]
    assert skipped == {"has_code_fact": 1, "parked_not_routable": 0}


def test_run_probes_persists_code_fact_and_rerun_skips(db_session, monkeypatch, erpc_env):
    row = _contract(db_session, ADDR(0x42))
    _stub_probe_wire(monkeypatch)
    targets, _ = backfill_code_probes.plan_targets(db_session)
    counts = backfill_code_probes.run_probes(db_session, targets, commit=False)
    assert counts["code_present"] == 1
    witness = db_session.get(ContractCreationWitness, (1, row.address))
    assert witness is not None and witness.code_probe_block == 100 and witness.code_absent_at_probe is False

    targets, skipped = backfill_code_probes.plan_targets(db_session)
    assert targets == [] and skipped["has_code_fact"] == 1


def test_unroutable_chain_recorded_as_parked_attempt_never_silent(db_session, monkeypatch):
    # A chain name with no registry id is unroutable; the attempt row is the
    # explainable parked state (invariant 5).
    row = _contract(db_session, ADDR(0x43), chain="not-a-chain")
    targets, _ = backfill_code_probes.plan_targets(db_session)
    assert targets == [row.id]
    counts = backfill_code_probes.run_probes(db_session, targets, commit=False)
    assert counts["not_routable"] == 1
    attempt = db_session.get(ContractProbeAttempt, (row.id, backfill_code_probes.UNRESOLVABLE_CHAIN_ID))
    assert attempt is not None and attempt.results["status"] == "not_routable"

    targets, skipped = backfill_code_probes.plan_targets(db_session)
    assert targets == [] and skipped["parked_not_routable"] == 1
    targets, _ = backfill_code_probes.plan_targets(db_session, retry_parked=True)
    assert targets == [row.id]


def test_scripts_importable_without_side_effects():
    # main() guards: importing must not execute a CLI.
    for module in (backfill_deployers, backfill_code_probes):
        assert callable(module.main)


# ---------------------------------------------------------------------------
# CLI exit codes (wire-dead vs honest steady state)
# ---------------------------------------------------------------------------


def _bind_cli_session(monkeypatch, module):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from tests.conftest import DATABASE_URL

    engine = create_engine(DATABASE_URL)
    monkeypatch.setattr(module, "SessionLocal", lambda: Session(engine))


def test_deployer_backfill_exit_1_when_wire_dead(db_session, monkeypatch):
    _contract(db_session, ADDR(0x60))
    db_session.commit()
    _bind_cli_session(monkeypatch, backfill_deployers)

    def dead_get(module, action, chain_id=None, **params):
        raise RuntimeError("Etherscan error: NOTOK - Max rate limit reached")

    monkeypatch.setattr(probes.etherscan, "get", dead_get)
    assert backfill_deployers.main(["--apply"]) == 1


def test_deployer_backfill_exit_0_on_honest_no_data_steady_state(db_session, monkeypatch):
    _contract(db_session, ADDR(0x61))
    db_session.commit()
    _bind_cli_session(monkeypatch, backfill_deployers)

    def no_data_get(module, action, chain_id=None, **params):
        # Etherscan's status-0 ANSWER for a batch with no creation info — a
        # healthy wire saying "nothing here", not a failure.
        raise RuntimeError("Etherscan error: No data found - ")

    monkeypatch.setattr(probes.etherscan, "get", no_data_get)
    assert backfill_deployers.main(["--apply"]) == 0


def test_deployer_backfill_exit_0_dry_run(db_session, monkeypatch):
    _contract(db_session, ADDR(0x62))
    db_session.commit()
    _bind_cli_session(monkeypatch, backfill_deployers)
    assert backfill_deployers.main([]) == 0


def test_code_probe_backfill_exit_1_when_every_probe_errors(db_session, monkeypatch, erpc_env):
    _contract(db_session, ADDR(0x63))
    db_session.commit()
    _bind_cli_session(monkeypatch, backfill_code_probes)

    def dead_rpc(rpc_url, method, params, *args, **kwargs):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(probes, "rpc_request", dead_rpc)
    assert backfill_code_probes.main(["--apply"]) == 1


def test_code_probe_backfill_exit_0_after_successful_probes(db_session, monkeypatch, erpc_env):
    _contract(db_session, ADDR(0x64))
    db_session.commit()
    _bind_cli_session(monkeypatch, backfill_code_probes)
    _stub_probe_wire(monkeypatch)
    assert backfill_code_probes.main(["--apply"]) == 0
