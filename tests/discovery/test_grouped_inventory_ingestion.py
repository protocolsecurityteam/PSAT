"""Exercise grouped discovery through the worker and real persistence boundary."""

import uuid

import pytest

from db.models import Contract, Job, JobStage, JobStatus, Protocol
from db.queue import get_artifact
from services.discovery.inventory import _build_contracts, inventory_entries
from services.discovery.inventory_domain import _infer_chain, _is_explorer_domain
from services.discovery.inventory_extract import extract_inventory_entries_from_page_text
from tests.conftest import requires_postgres
from workers.base import JobHandledDirectly
from workers.discovery import DiscoveryWorker


def _discovery_urls(inventory):
    entries, _ = inventory_entries(inventory["contracts"], inventory["sources"])
    return {(e["chain"], e["address"]): inventory["sources"][e["source_ids"][0]] for e in entries}


def test_inventory_rerun_preserves_grouped_deployments_chains_and_source_identity():
    from services.discovery.inventory import merge_inventory

    a, b = ["0x" + byte * 20 for byte in ("41", "42")]
    previous = {
        "contracts": [
            {
                "name": "Registry",
                "chains": ["ethereum", "base"],
                "confidence": 1,
                "source_ids": ["s1"],
                "deployments": [{"address": a, "chain": "ethereum"}, {"address": a, "chain": "base"}],
            }
        ],
        "sources": {"s1": "https://docs.example/old"},
    }
    current = {
        "contracts": [
            {
                "name": "Registry",
                "confidence": 0.9,
                "source_ids": ["s1"],
                "deployments": [{"address": a, "chains": ["ethereum"]}, {"address": b, "chains": ["ethereum"]}],
            }
        ],
        "sources": {"s1": "https://docs.example/new"},
    }
    merged = merge_inventory(previous, current)
    assert _discovery_urls(merged) == {
        ("ethereum", a): "https://docs.example/new",
        ("ethereum", b): "https://docs.example/new",
        ("base", a): "https://docs.example/old",
    }
    assert previous["sources"] == {"s1": "https://docs.example/old"}
    assert len(_discovery_urls(merge_inventory(merged, current))) == 3


@requires_postgres
def test_company_worker_persists_all_grouped_deployments_with_provenance(db_session, monkeypatch):
    protocol = Protocol(name=f"Grouped-{uuid.uuid4().hex}")
    db_session.add(protocol)
    db_session.commit()
    a, b, c = ["0x" + byte * 20 for byte in ("41", "42", "43")]
    raw = [
        {"name": "Shared", "address": a, "chains": ["ethereum"], "source_ids": ["s1"]},
        {"name": "Shared", "address": b, "chains": ["ethereum"], "source_ids": ["s2"]},
        {"name": "Shared", "address": c, "chains": ["base"], "source_ids": ["s2"]},
        {"name": "Twin", "address": a, "chains": ["base"], "source_ids": ["s2"]},
    ]
    inventory = {
        "contracts": [{**r, "source": ["ai_inventory"], "confidence": 0.9} for r in raw],
        "sources": {"s1": "https://docs.example/first", "s2": "https://docs.example/second"},
        "official_domain": "docs.example",
    }
    job = Job(
        company=protocol.name,
        protocol_id=protocol.id,
        status=JobStatus.queued,
        stage=JobStage.discovery,
        request={"company": protocol.name, "chain": "ethereum"},
    )
    db_session.add(job)
    db_session.commit()
    monkeypatch.setattr("workers.discovery.find_previous_company_inventory", lambda *a, **k: None)
    monkeypatch.setattr("workers.discovery.resolve_protocol", lambda *a, **k: {})
    monkeypatch.setattr(
        "workers.discovery.run_probe_pass", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("offline"))
    )
    monkeypatch.setattr(
        "services.discovery.run_discovery.run_discovery",
        lambda *a, **k: {
            "addresses": inventory,
            "audits": {"reports": []},
            "meta": {},
        },
    )
    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "_spawn_parallel_discovery", lambda *a, **k: None)
    with pytest.raises(JobHandledDirectly):
        worker.process(db_session, job)
    rows = db_session.query(Contract).filter(Contract.nominated_protocol_id == protocol.id).all()
    assert {(r.chain, r.address) for r in rows} == {("ethereum", a), ("ethereum", b), ("base", c), ("base", a)}
    assert all(r.protocol_id is None for r in rows)  # Discovery is not proof of membership.
    assert {(r.chain, r.address): r.discovery_url for r in rows} == {
        ("ethereum", a): inventory["sources"]["s1"],
        ("ethereum", b): inventory["sources"]["s2"],
        ("base", c): inventory["sources"]["s2"],
        ("base", a): inventory["sources"]["s2"],
    }
    summary = get_artifact(db_session, job.id, "discovery_summary")
    assert isinstance(summary, dict)
    assert summary["discovered_count"] == 4


def test_official_entries_survive_higher_scored_deployer_expansion():
    entries = [
        {
            "address": "0x" + "11" * 20,
            "name": None,
            "chain": "ethereum",
            "kind": "official_inventory_text",
            "url": "https://docs.example/registry",
        }
    ] + [
        {
            "address": f"0x{i:040x}",
            "name": f"Expanded{i}",
            "chain": "ethereum",
            "kind": "deployer_expansion",
            "url": "https://etherscan.io/address/0x" + "22" * 20,
        }
        for i in range(1, 5)
    ]
    contracts, _, _ = _build_contracts(entries, limit=2)
    assert len(contracts) == 2
    assert any(c["address"] == "0x" + "11" * 20 for c in contracts)


@pytest.mark.parametrize("prefix,chain", [("eth", "ethereum"), ("arb1", "arbitrum"), ("oeth", "optimism")])
def test_safe_links_keep_chain_identity_and_explorer_evidence(prefix, chain):
    address = "0x" + "51" * 20
    url = f"https://app.safe.global/settings/setup?safe={prefix}:{address}"
    assert _is_explorer_domain("app.safe.global")
    assert _infer_chain(url, "") == chain
    html = f'<h2>Committee</h2><li>Emergency committee: <a href="{url}">{address}</a></li>'
    entries = extract_inventory_entries_from_page_text("https://docs.example/registry", html, chain)
    assert len(entries) == 1
    assert entries[0]["chain"] == chain
    assert entries[0]["explorer_url"] == url
    assert entries[0]["kind"] == "official_inventory_link"


def test_unknown_safe_chain_does_not_default_to_ethereum():
    assert _infer_chain("https://app.safe.global/?safe=not-a-chain:0x" + "51" * 20, "") == "unknown"
