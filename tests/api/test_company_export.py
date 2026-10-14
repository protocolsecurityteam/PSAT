"""``/api/company/{name}/export``: one report, four formats, three-state fields kept three-state."""

from __future__ import annotations

import csv
import io
import json
from contextlib import nullcontext
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from services.exports import build_report, export_filename, render_report
from services.exports.protocol_report import report_sections

OVERVIEW = {
    "company": "Example",
    "protocol_id": 7,
    "contract_count": 2,
    "contracts": [
        {
            "address": "0x" + "a" * 40,
            "name": "Vault",
            "chain": "ethereum",
            "role": "value_handler",
            "is_proxy": True,
            "proxy_type": "eip1967",
            "implementation": "0x" + "b" * 40,
            "owner": "0x" + "c" * 40,
            "source_verified": True,
            "is_pausable": True,
            "has_timelock": False,
            "upgrade_count": 3,
            "capabilities": ["pause", "upgradeable"],
            "total_usd": 1234.5,
        },
        {
            "address": "0x" + "d" * 40,
            "name": "Helper",
            "chain": "ethereum",
            "is_proxy": False,
            "source_verified": None,
            "is_pausable": None,
            "has_timelock": None,
        },
    ],
    "principals": [
        {
            "address": "0x" + "c" * 40,
            "chain": "ethereum",
            "type": "safe",
            "label": "Ops Safe",
            "details": {"owners": ["0x1", "0x2", "0x3"], "threshold": 2},
            "primary_for": ["0x" + "a" * 40],
            "co_controls": [],
            "chains": {"ethereum"},
            "controls_detail": [{"capabilities": ["upgrade", "pause"]}],
        },
        {
            "address": "0x" + "e" * 40,
            "chain": "ethereum",
            "type": "timelock",
            "label": "Timelock",
            "details": {"min_delay": 172800},
            "primary_for": [],
            "co_controls": ["0x" + "a" * 40],
        },
    ],
    "ownership_hierarchy": [],
    "fund_flows": [],
    "tvl": {"total_usd": 1234.5, "defillama_tvl": None},
    "member_analysis": {"members": 2, "analyzed": 2},
}

SCORE = {
    "company": "Example",
    "grade_state": "computed",
    "grade_lambda": 71.25,
    "grade_exposure": 0.4,
    "confidence_pct": 88.0,
    "perimeter_state": "complete",
    "model_version": "1.4.1-provisional",
    "computed_at": "2026-10-01T00:00:00+00:00",
    "trigger": "job",
    "findings": [
        {
            "capability": "upgrade",
            "principal_unit": "ethereum::0x" + "c" * 40,
            "raw_points": 12.0,
            "net_points_lambda": 12.0,
            "value_at_stake_usd": 1000.0,
            "n_functions": 1,
            "n_entities": 1,
            "example_functions": ["upgradeTo(address)"],
        }
    ],
}

COVERAGE = {
    "audit_count": 1,
    "coverage": [
        {
            "address": "0x" + "a" * 40,
            "chain": "ethereum",
            "contract_name": "Vault",
            "audit_count": 1,
            "last_audit": {"auditor": "Acme", "title": "Vault review", "date": "2026-01-01"},
        }
    ],
}

GENERATED = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)


def _report(score=SCORE, score_status="available", coverage=COVERAGE):
    return build_report(
        company="Example",
        overview=OVERVIEW,
        score=score,
        score_status=score_status,
        audit_coverage=coverage,
        generated_at=GENERATED,
    )


def test_report_summary_keeps_unread_fields_undetermined():
    summary = _report()["summary"]
    assert summary["contract_count"] == 2
    assert summary["proxy_count"] == 1
    assert summary["pausable"] == {"yes": 1, "no": 0, "not_determined": 1}
    assert summary["timelocked"] == {"yes": 0, "no": 1, "not_determined": 1}
    assert summary["multisig_count"] == 1
    assert summary["timelock_principal_count"] == 1
    assert summary["contracts_with_audit_coverage"] == 1


def test_sections_render_multisig_threshold_and_timelock_delay():
    principals = next(s for s in report_sections(_report()) if s.title == "Privileged principals")
    safe, timelock = principals.rows
    assert safe[4] == "2 of 3"
    assert safe[8] == "pause, upgrade"
    assert timelock[5] == "2d"


def test_contract_rows_never_render_unread_as_no():
    contracts = next(s for s in report_sections(_report()) if s.title == "Contracts")
    helper = next(row for row in contracts.rows if row[0] == "Helper")
    assert helper[4] == helper[8] == helper[9] == "Not determined"


def test_missing_score_says_why():
    report = _report(score=None, score_status="not_scored", coverage=None)
    score = next(s for s in report_sections(report) if s.title == "Score")
    assert "No score has been computed" in (score.note or "")
    audits = next(s for s in report_sections(report) if s.title == "Audit coverage")
    assert "could not be loaded" in (audits.note or "")
    assert report["summary"]["contracts_with_audit_coverage"] is None


def test_json_is_lossless_and_serializable():
    data = json.loads(render_report(_report(), "json"))
    assert data["protocol"] == {"name": "Example", "protocol_id": 7}
    assert data["principals"][0]["chains"] == ["ethereum"]
    assert data["score"]["findings"][0]["capability"] == "upgrade"


def test_csv_has_one_block_per_section():
    text = render_report(_report(), "csv").decode("utf-8-sig")
    rows = list(csv.reader(io.StringIO(text)))
    titles = [r[0] for r in rows if r and r[0].startswith("# ")]
    assert titles == [
        "# Summary",
        "# Score",
        "# Score deductions",
        "# Contracts",
        "# Privileged principals",
        "# Audit coverage",
    ]
    assert any(r[:2] == ["Vault", "0x" + "a" * 40] for r in rows)


def test_pdf_is_readable():
    from pypdf import PdfReader

    content = render_report(_report(), "pdf")
    assert content.startswith(b"%PDF")
    text = "".join(page.extract_text() for page in PdfReader(io.BytesIO(content)).pages)
    assert "Example" in text and "Ops Safe" in text and "Not determined" in text


def test_docx_is_readable():
    from docx import Document

    document = Document(io.BytesIO(render_report(_report(), "docx")))
    headings = [p.text for p in document.paragraphs if p.style and (p.style.name or "").startswith("Heading")]
    assert "Contracts" in headings and "Privileged principals" in headings
    cells = {cell.text for table in document.tables for row in table.rows for cell in row.cells}
    assert "Vault" in cells and "2 of 3" in cells


def test_filename_is_slugged_and_stamped():
    assert export_filename("Lido / stETH", "pdf", GENERATED) == "psat-lido-steth-20261013T120000Z.pdf"


@pytest.fixture
def client(monkeypatch):
    from routers import company, deps

    monkeypatch.setattr(deps, "SessionLocal", lambda: nullcontext(None))
    monkeypatch.setattr(company, "build_company_overview", lambda _session, name: dict(OVERVIEW, company=name))
    monkeypatch.setattr(company, "company_score", lambda _name: SCORE)
    monkeypatch.setattr(company, "company_audit_coverage", lambda _name: COVERAGE)
    app = FastAPI()
    app.include_router(company.router)
    return TestClient(app)


@pytest.mark.parametrize(
    ("fmt", "media_type", "magic"),
    [
        ("json", "application/json", b"{"),
        ("csv", "text/csv", "﻿".encode()),
        ("pdf", "application/pdf", b"%PDF"),
        ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", b"PK"),
    ],
)
def test_route_serves_each_format_as_attachment(client, fmt, media_type, magic):
    response = client.get("/api/company/Example/export", params={"format": fmt})
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith(media_type)
    assert response.headers["content-disposition"].startswith('attachment; filename="psat-example-')
    assert response.headers["content-disposition"].endswith(f'.{fmt}"')
    assert response.content.startswith(magic)


def test_route_rejects_unknown_format(client):
    response = client.get("/api/company/Example/export", params={"format": "xlsx"})
    assert response.status_code == 400
    assert "json, csv, pdf, docx" in response.json()["detail"]


def test_route_404s_unknown_company(client, monkeypatch):
    from routers import company
    from services.aggregations import CompanyNotFound

    def missing(_session, name):
        raise CompanyNotFound(name)

    monkeypatch.setattr(company, "build_company_overview", missing)
    assert client.get("/api/company/Nope/export").status_code == 404


@pytest.mark.parametrize(("status", "expected"), [(404, "not_scored"), (503, "unavailable")])
def test_route_records_why_the_score_is_missing(client, monkeypatch, status, expected):
    from routers import company

    def no_score(_name):
        raise HTTPException(status_code=status, detail="x")

    monkeypatch.setattr(company, "company_score", no_score)
    body = client.get("/api/company/Example/export").json()
    assert body["score_status"] == expected
    assert body["score"] is None
