"""Downloadable report of a protocol's latest results, in JSON, CSV, PDF or DOCX.

JSON carries the full overview, score document and audit coverage, losslessly. The other formats render a curated set
of sections from that same report, so CSV, PDF and DOCX cannot disagree with each other.

Three-state fields stay three-state: an unread ``is_pausable`` renders as "Not determined", never "No".
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal
from typing import Any

EXPORT_VERSION = 1

EXPORT_FORMATS: dict[str, str] = {
    "json": "application/json",
    "csv": "text/csv; charset=utf-8",
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}

NOT_DETERMINED = "Not determined"


class UnsupportedExportFormat(ValueError):
    pass


@dataclass
class Section:
    title: str
    # Exactly one of ``pairs`` (a key/value block) or ``columns`` + ``rows`` (a table).
    pairs: list[tuple[str, str]] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)
    note: str | None = None

    @property
    def is_table(self) -> bool:
        return bool(self.columns)


def _json_default(value: Any) -> Any:
    if isinstance(value, (set, frozenset, tuple)):
        return sorted(value, key=str)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    return str(value)


def _plain(value: Any) -> Any:
    """Round-trip through JSON so the report holds only JSON types (sets, Decimals, datetimes from the DB)."""
    return json.loads(json.dumps(value, default=_json_default))


def _tri(value: Any) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return NOT_DETERMINED


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, float):
        return f"{value:,.4f}".rstrip("0").rstrip(".")
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_text(v) for v in value if v is not None)
    if isinstance(value, dict):
        return ", ".join(f"{k}: {_text(v)}" for k, v in value.items())
    return str(value)


def _usd(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return ""
    return f"${value:,.2f}"


def _duration(seconds: Any) -> str:
    if isinstance(seconds, str) and seconds.isdigit():
        seconds = int(seconds)
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
        return ""
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts = [f"{days}d" if days else "", f"{hours}h" if hours else "", f"{minutes}m" if minutes else ""]
    return " ".join(p for p in parts if p) or f"{seconds}s"


def _timelock_delay(details: dict[str, Any]) -> Any:
    for key in ("delay", "min_delay", "delay_seconds"):
        if details.get(key) is not None:
            return details[key]
    return None


def _multisig_threshold(details: dict[str, Any]) -> str:
    owners = details.get("owners") or []
    threshold = details.get("threshold")
    if isinstance(threshold, dict):
        threshold = threshold.get("m")
    if threshold is None and not owners:
        return ""
    return f"{threshold if threshold is not None else '?'} of {len(owners) if owners else '?'}"


def _summary(
    overview: dict[str, Any], score: dict[str, Any] | None, audit_coverage: dict[str, Any] | None
) -> dict[str, Any]:
    contracts = overview.get("contracts") or []
    principals = overview.get("principals") or []
    current = {((c.get("chain") or "").lower(), (c.get("address") or "").lower()) for c in contracts}
    covered = [
        row
        for row in (audit_coverage or {}).get("coverage") or []
        if ((row.get("chain") or "").lower(), (row.get("address") or "").lower()) in current and row.get("audit_count")
    ]

    def tally(key: str) -> dict[str, int]:
        return {
            "yes": sum(1 for c in contracts if c.get(key) is True),
            "no": sum(1 for c in contracts if c.get(key) is False),
            "not_determined": sum(1 for c in contracts if c.get(key) is None),
        }

    tvl = overview.get("tvl") or {}
    return {
        "contract_count": len(contracts),
        "proxy_count": sum(1 for c in contracts if c.get("is_proxy")),
        "source_verified": tally("source_verified"),
        "pausable": tally("is_pausable"),
        "timelocked": tally("has_timelock"),
        "principal_count": len(principals),
        "multisig_count": sum(1 for p in principals if p.get("type") == "safe"),
        "timelock_principal_count": sum(1 for p in principals if p.get("type") == "timelock"),
        "eoa_principal_count": sum(1 for p in principals if p.get("type") == "eoa"),
        "audit_report_count": (audit_coverage or {}).get("audit_count"),
        "contracts_with_audit_coverage": len(covered) if audit_coverage is not None else None,
        "tvl_usd": tvl.get("total_usd"),
        "defillama_tvl_usd": tvl.get("defillama_tvl"),
        "grade_state": (score or {}).get("grade_state"),
        "score_finding_count": len((score or {}).get("findings") or []) if score else None,
    }


def build_report(
    *,
    company: str,
    overview: dict[str, Any],
    score: dict[str, Any] | None,
    score_status: str,
    audit_coverage: dict[str, Any] | None,
    generated_at: datetime,
) -> dict[str, Any]:
    """``score_status`` is ``available``, ``not_scored`` or ``unavailable`` (the document couldn't be read): a missing
    score must say which.
    """
    report = {
        "export_version": EXPORT_VERSION,
        "generated_at": generated_at.isoformat(),
        "protocol": {"name": company, "protocol_id": overview.get("protocol_id")},
        "summary": _summary(overview, score, audit_coverage),
        "score_status": score_status,
        "score": score,
        "contracts": overview.get("contracts") or [],
        "principals": overview.get("principals") or [],
        "ownership_hierarchy": overview.get("ownership_hierarchy") or [],
        "fund_flows": overview.get("fund_flows") or [],
        "tvl": overview.get("tvl"),
        "member_analysis": overview.get("member_analysis"),
        "audit_coverage": audit_coverage,
    }
    return _plain(report)


def _score_section(report: dict[str, Any]) -> Section:
    score = report.get("score")
    status = report.get("score_status")
    if not score:
        note = (
            "No score has been computed for this protocol yet."
            if status == "not_scored"
            else "The score document could not be read when this export was generated."
        )
        return Section("Score", pairs=[("Status", status or NOT_DETERMINED)], note=note)
    determined = score.get("grade_state") == "computed"
    pairs = [
        ("Grade state", _text(score.get("grade_state"))),
        ("Grade (λ)", _text(score.get("grade_lambda")) if determined else NOT_DETERMINED),
        ("Exposure", _text(score.get("grade_exposure")) if determined else NOT_DETERMINED),
        ("Confidence", f"{_text(score.get('confidence_pct'))}%" if determined else NOT_DETERMINED),
        ("Perimeter", _text(score.get("perimeter_state"))),
        ("Model version", _text(score.get("model_version"))),
        ("Computed at", _text(score.get("computed_at"))),
        ("Trigger", _text(score.get("trigger"))),
    ]
    return Section("Score", pairs=pairs)


def _findings_section(report: dict[str, Any]) -> Section:
    findings = (report.get("score") or {}).get("findings") or []
    rows = []
    for index, f in enumerate(findings, start=1):
        if not isinstance(f, dict):
            continue
        rows.append(
            [
                str(index),
                _text(f.get("capability")),
                _text(f.get("principal_unit")),
                _text(f.get("raw_points")),
                _text(f.get("net_points_lambda")),
                _usd(f.get("value_at_stake_usd")),
                _text(f.get("n_functions")),
                _text(f.get("n_entities")),
                _text((f.get("example_functions") or [])[:3]),
            ]
        )
    return Section(
        "Score deductions",
        columns=[
            "#",
            "Capability",
            "Principal",
            "Raw points",
            "Net points (λ)",
            "Value at stake",
            "Functions",
            "Entities",
            "Example functions",
        ],
        rows=rows,
        note=None if rows else "No deductions.",
    )


def _contracts_section(report: dict[str, Any]) -> Section:
    coverage = {
        ((row.get("chain") or "").lower(), (row.get("address") or "").lower()): row
        for row in (report.get("audit_coverage") or {}).get("coverage") or []
    }
    rows = []
    for c in report.get("contracts") or []:
        key = ((c.get("chain") or "").lower(), (c.get("address") or "").lower())
        audits = coverage.get(key, {}).get("audit_count")
        proxy = _tri(c.get("is_proxy"))
        if c.get("is_proxy") and c.get("proxy_type"):
            proxy = f"Yes ({c['proxy_type']})"
        rows.append(
            [
                _text(c.get("name")),
                _text(c.get("address")),
                _text(c.get("chain")),
                _text(c.get("role")),
                _tri(c.get("source_verified")),
                proxy,
                _text(c.get("implementation")),
                _text(c.get("owner")),
                _tri(c.get("is_pausable")),
                _tri(c.get("has_timelock")),
                _text(c.get("upgrade_count")),
                _text(c.get("last_upgrade_timestamp")),
                _text(c.get("capabilities")),
                _usd(c.get("total_usd")),
                _text(audits if audits is not None else 0),
            ]
        )
    return Section(
        "Contracts",
        columns=[
            "Name",
            "Address",
            "Chain",
            "Role",
            "Verified",
            "Proxy",
            "Implementation",
            "Owner",
            "Pausable",
            "Timelock",
            "Upgrades",
            "Last upgrade",
            "Capabilities",
            "Holdings (USD)",
            "Audits",
        ],
        rows=rows,
        note=None if rows else "No contracts mapped.",
    )


def _principals_section(report: dict[str, Any]) -> Section:
    rows = []
    for p in report.get("principals") or []:
        details = p.get("details") if isinstance(p.get("details"), dict) else {}
        controls = p.get("controls_detail") or []
        capabilities = sorted({cap for entry in controls for cap in entry.get("capabilities") or []})
        rows.append(
            [
                _text(p.get("label")),
                _text(p.get("address")),
                _text(p.get("chain")),
                _text(p.get("type")),
                _multisig_threshold(details) if p.get("type") == "safe" else "",
                _duration(_timelock_delay(details)) if p.get("type") == "timelock" else "",
                str(len(p.get("primary_for") or [])),
                str(len(p.get("co_controls") or [])),
                _text(capabilities),
            ]
        )
    return Section(
        "Privileged principals",
        columns=[
            "Label",
            "Address",
            "Chain",
            "Type",
            "Multisig threshold",
            "Timelock delay",
            "Controls",
            "Co-controls",
            "Capabilities",
        ],
        rows=rows,
        note=None if rows else "No privileged principals resolved.",
    )


def _audits_section(report: dict[str, Any]) -> Section:
    coverage = report.get("audit_coverage")
    if coverage is None:
        return Section("Audit coverage", note="Audit coverage could not be loaded when this export was generated.")
    rows = []
    for row in coverage.get("coverage") or []:
        last = row.get("last_audit") or {}
        rows.append(
            [
                _text(row.get("contract_name")),
                _text(row.get("address")),
                _text(row.get("chain")),
                _text(row.get("audit_count")),
                _text(last.get("auditor")),
                _text(last.get("title")),
                _text(last.get("date")),
            ]
        )
    return Section(
        "Audit coverage",
        columns=["Contract", "Address", "Chain", "Audits", "Last auditor", "Last audit", "Last audit date"],
        rows=rows,
        note=None if rows else "No audit coverage on file.",
    )


def _summary_section(report: dict[str, Any]) -> Section:
    s = report.get("summary") or {}

    def tri_counts(key: str) -> str:
        t = s.get(key) or {}
        return f"{t.get('yes', 0)} yes · {t.get('no', 0)} no · {t.get('not_determined', 0)} not determined"

    pairs = [
        ("Protocol", _text((report.get("protocol") or {}).get("name"))),
        ("Generated at", _text(report.get("generated_at"))),
        ("Contracts", _text(s.get("contract_count"))),
        ("Proxies", _text(s.get("proxy_count"))),
        ("Source verified", tri_counts("source_verified")),
        ("Pausable", tri_counts("pausable")),
        ("Timelocked", tri_counts("timelocked")),
        ("Privileged principals", _text(s.get("principal_count"))),
        ("Multisigs", _text(s.get("multisig_count"))),
        ("Timelock principals", _text(s.get("timelock_principal_count"))),
        ("EOA principals", _text(s.get("eoa_principal_count"))),
        ("Audit reports on file", _text(s.get("audit_report_count")) or NOT_DETERMINED),
        ("Contracts with audit coverage", _text(s.get("contracts_with_audit_coverage")) or NOT_DETERMINED),
        ("TVL (observed holdings)", _usd(s.get("tvl_usd")) or NOT_DETERMINED),
        ("TVL (DefiLlama)", _usd(s.get("defillama_tvl_usd")) or NOT_DETERMINED),
    ]
    return Section("Summary", pairs=pairs)


def report_sections(report: dict[str, Any]) -> list[Section]:
    return [
        _summary_section(report),
        _score_section(report),
        _findings_section(report),
        _contracts_section(report),
        _principals_section(report),
        _audits_section(report),
    ]


def _title(report: dict[str, Any]) -> str:
    return f"{(report.get('protocol') or {}).get('name') or 'Protocol'} — PSAT security report"


def render_json(report: dict[str, Any]) -> bytes:
    return json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")


def render_csv(report: dict[str, Any]) -> bytes:
    """One file, one block per section: a ``# Title`` line, a header row, then rows, separated by a blank line."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    for index, section in enumerate(report_sections(report)):
        if index:
            writer.writerow([])
        writer.writerow([f"# {section.title}"])
        if section.is_table:
            writer.writerow(section.columns)
            writer.writerows(section.rows)
        else:
            writer.writerow(["Field", "Value"])
            writer.writerows([list(pair) for pair in section.pairs])
        if section.note:
            writer.writerow([section.note])
    # BOM so Excel reads UTF-8 (λ, —) instead of the system code page.
    return ("﻿" + buffer.getvalue()).encode("utf-8")


def _column_widths(section: Section, total: float) -> list[float]:
    """Widths in proportion to each column's longest unbreakable word, so cells wrap at spaces rather than mid-word.

    Capped so a 42-character address can't starve the other columns; addresses wrap once.
    """
    weights = []
    for index, header in enumerate(section.columns):
        texts = [header, *(row[index] for row in section.rows)]
        longest = max((len(word) for text in texts for word in text.split()), default=0)
        weights.append(min(max(longest, 4), 22) + 2)
    scale = total / sum(weights)
    return [w * scale for w in weights]


def render_pdf(report: dict[str, Any]) -> bytes:
    from xml.sax.saxutils import escape

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    cell = styles["BodyText"].clone("cell", fontSize=6.5, leading=8)
    head = cell.clone("head", fontName="Helvetica-Bold")
    # The built-in Helvetica is WinAnsi-encoded: no λ glyph.
    ascii_safe = lambda s: escape(s.replace("λ", "lambda"))  # noqa: E731

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        leftMargin=12 * mm,
        rightMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title=ascii_safe(_title(report)),
        author="PSAT",
    )
    story: list[Any] = [Paragraph(ascii_safe(_title(report)), styles["Title"])]
    grid = TableStyle(
        [
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ]
    )
    for section in report_sections(report):
        story.append(Paragraph(ascii_safe(section.title), styles["Heading2"]))
        if section.is_table and section.rows:
            data = [[Paragraph(ascii_safe(c), head) for c in section.columns]]
            data += [[Paragraph(ascii_safe(v), cell) for v in row] for row in section.rows]
            table = Table(data, repeatRows=1, colWidths=_column_widths(section, doc.width))
            table.setStyle(grid)
            table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0"))]))
            story.append(table)
        elif section.pairs:
            data = [[Paragraph(ascii_safe(k), head), Paragraph(ascii_safe(v), cell)] for k, v in section.pairs]
            table = Table(data, colWidths=[doc.width * 0.25, doc.width * 0.5], hAlign="LEFT")
            table.setStyle(grid)
            story.append(table)
        if section.note:
            story.append(Paragraph(ascii_safe(section.note), styles["Italic"]))
        story.append(Spacer(1, 6 * mm))
    doc.build(story)
    return buffer.getvalue()


def render_docx(report: dict[str, Any]) -> bytes:
    from docx import Document
    from docx.enum.section import WD_ORIENT
    from docx.shared import Mm, Pt

    document = Document()
    page = document.sections[0]
    page.orientation = WD_ORIENT.LANDSCAPE
    page.page_width, page.page_height = Mm(297), Mm(210)
    for margin in ("left_margin", "right_margin", "top_margin", "bottom_margin"):
        setattr(page, margin, Mm(12))
    document.core_properties.title = _title(report)
    document.core_properties.author = "PSAT"
    document.add_heading(_title(report), level=0)

    def add_table(rows: list[list[str]], *, header_row: bool, header_col: bool, size: float) -> None:
        table = document.add_table(rows=0, cols=len(rows[0]))
        table.style = "Table Grid"
        for r, values in enumerate(rows):
            cells = table.add_row().cells
            for c, value in enumerate(values):
                run = cells[c].paragraphs[0].add_run(value)
                run.font.size = Pt(size)
                run.bold = (header_row and r == 0) or (header_col and c == 0)

    for section in report_sections(report):
        document.add_heading(section.title, level=1)
        if section.is_table and section.rows:
            add_table([section.columns, *section.rows], header_row=True, header_col=False, size=7)
        elif section.pairs:
            add_table([list(pair) for pair in section.pairs], header_row=False, header_col=True, size=9)
        if section.note:
            document.add_paragraph().add_run(section.note).italic = True
    buffer = io.BytesIO()
    document.save(buffer)
    return buffer.getvalue()


_RENDERERS = {"json": render_json, "csv": render_csv, "pdf": render_pdf, "docx": render_docx}


def render_report(report: dict[str, Any], fmt: str) -> bytes:
    renderer = _RENDERERS.get(fmt)
    if renderer is None:
        raise UnsupportedExportFormat(fmt)
    return renderer(report)


def export_filename(company: str, fmt: str, generated_at: datetime) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", company).strip("-").lower() or "protocol"
    return f"psat-{slug}-{generated_at.strftime('%Y%m%dT%H%M%SZ')}.{fmt}"
