"""``scripts/seed_demo_protocol``: the demo must still build a company page and fill every export section.

Breaks here when a schema change leaves the seed writing rows the aggregations no longer read.
"""

from __future__ import annotations

import csv
import io
import json

import pytest
from sqlalchemy import func, select

from db.models import Contract, Job, Protocol, ProtocolScore
from scripts import seed_demo_protocol as demo
from services.aggregations import build_company_overview
from services.exports.protocol_report import report_sections
from tests.conftest import SessionFactory, requires_postgres

pytestmark = requires_postgres

NAME = demo.DEFAULT_NAME


def _demo_contract_count(session) -> int:
    return session.execute(
        select(func.count()).select_from(Contract).where(Contract.address.in_(demo.DEMO_ADDRESSES))
    ).scalar_one()


def test_seed_builds_the_company_overview(db_session):
    demo.seed(db_session, NAME)

    payload = build_company_overview(db_session, NAME)
    contracts = {c["name"]: c for c in payload["contracts"]}
    # The implementation folds into its proxy's row.
    assert set(contracts) == {"Vault", "FeeController", "Treasury", "DemoToken"}
    assert contracts["Vault"]["is_proxy"] is True
    assert contracts["Vault"]["owner"] == demo.SAFE
    assert contracts["Treasury"]["has_timelock"] is True
    token = contracts["DemoToken"]
    assert token["source_verified"] is token["is_pausable"] is token["has_timelock"] is None

    principals = {p["address"]: p for p in payload["principals"]}
    assert principals[demo.SAFE]["type"] == "safe"
    assert principals[demo.SAFE]["details"]["threshold"] == 2
    assert principals[demo.TIMELOCK]["type"] == "timelock"
    assert principals[demo.ADMIN_EOA]["type"] == "eoa"


def test_reseeding_replaces_rather_than_duplicates(db_session):
    demo.seed(db_session, NAME)
    demo.seed(db_session, NAME)

    assert db_session.execute(select(func.count()).where(Protocol.name == NAME)).scalar_one() == 1
    assert _demo_contract_count(db_session) == len(demo.DEMO_ADDRESSES)
    protocol_id = db_session.execute(select(Protocol.id).where(Protocol.name == NAME)).scalar_one()
    assert db_session.execute(select(func.count()).where(ProtocolScore.protocol_id == protocol_id)).scalar_one() == 1


def test_remove_deletes_everything_it_seeded(db_session):
    demo.seed(db_session, NAME)
    job_ids = list(
        db_session.execute(select(Contract.job_id).where(Contract.address.in_(demo.DEMO_ADDRESSES))).scalars()
    )

    assert demo.remove(db_session, NAME) is True
    assert db_session.execute(select(Protocol).where(Protocol.name == NAME)).scalar_one_or_none() is None
    assert _demo_contract_count(db_session) == 0
    assert db_session.execute(select(func.count()).where(Job.id.in_(job_ids))).scalar_one() == 0
    assert demo.remove(db_session, NAME) is False


def test_seed_honours_a_custom_name(db_session):
    demo.seed(db_session, "demo-custom")
    assert build_company_overview(db_session, "demo-custom")["contract_count"] == 4


def test_export_fills_every_section_from_the_demo(api_client, db_session):
    demo.seed(db_session, NAME)

    response = api_client.get(f"/api/company/{NAME}/export", params={"format": "json"})
    assert response.status_code == 200, response.text
    report = json.loads(response.content)
    assert report["score_status"] == "available"
    assert report["summary"]["pausable"] == {"yes": 1, "no": 2, "not_determined": 1}
    assert report["summary"]["multisig_count"] == 1
    assert report["summary"]["timelock_principal_count"] == 1
    assert report["summary"]["eoa_principal_count"] == 1

    sections = {s.title: s for s in report_sections(report)}
    principals = {row[1]: row for row in sections["Privileged principals"].rows}
    assert principals[demo.SAFE][0] == "Ops Safe"
    assert principals[demo.SAFE][4] == "2 of 3"
    assert principals[demo.TIMELOCK][5] == "2d"
    assert len(sections["Score deductions"].rows) == 2
    assert {row[0] for row in sections["Contracts"].rows} == {"Vault", "FeeController", "Treasury", "DemoToken"}


@pytest.mark.parametrize(("fmt", "magic"), [("csv", "﻿".encode()), ("pdf", b"%PDF"), ("docx", b"PK")])
def test_export_renders_the_demo_in_each_file_format(api_client, db_session, fmt, magic):
    demo.seed(db_session, NAME)

    response = api_client.get(f"/api/company/{NAME}/export", params={"format": fmt})
    assert response.status_code == 200, response.text
    assert response.content.startswith(magic)
    if fmt == "csv":
        rows = list(csv.reader(io.StringIO(response.content.decode("utf-8-sig"))))
        assert ["Ops Safe", demo.SAFE] == next(r for r in rows if r and r[0] == "Ops Safe")[:2]


def test_cli_seeds_and_removes(monkeypatch, db_session, capsys):
    monkeypatch.setattr(demo, "SessionLocal", SessionFactory(db_session))

    assert demo.main([]) == 0
    assert f"/company/{NAME}" in capsys.readouterr().out
    assert _demo_contract_count(db_session) == len(demo.DEMO_ADDRESSES)

    assert demo.main(["--remove"]) == 0
    assert f"Removed {NAME}." in capsys.readouterr().out
    assert _demo_contract_count(db_session) == 0
