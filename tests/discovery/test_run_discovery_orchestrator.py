"""Unit tests for services.discovery.run_discovery orchestrator."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.discovery import audit_enrichment as ae
from services.discovery import run_discovery as rd

# offline: discovery validates/resolves contract chains via Alchemy (chain_resolver)
# and probes bytecode via eth_getCode — stub both so the pipeline runs without a wire.
pytestmark = pytest.mark.usefixtures("_stub_chain_resolver", "_stub_rpc_bytecode")


@pytest.fixture(autouse=True)
def _clear_cache():
    rd.reset_cache()
    yield
    rd.reset_cache()


# ---------------------------------------------------------------------------
# _Budget
# ---------------------------------------------------------------------------


def test_budget_charge_search_increments_and_costs():
    b = rd._Budget()
    b.charge_search("auto")
    b.charge_search("deep-lite")
    assert b.search_calls == 2
    # 0.007 + 0.012 = 0.019
    assert abs(b.estimated_cost_usd - 0.019) < 1e-9


def test_budget_search_cap_trips():
    b = rd._Budget()
    for _ in range(rd.MAX_SEARCH_CALLS_PER_PROTOCOL):
        b.charge_search("auto")
    with pytest.raises(RuntimeError, match="search budget"):
        b.charge_search("auto")


def test_budget_research_cap_trips():
    b = rd._Budget()
    for _ in range(rd.MAX_RESEARCH_CALLS_PER_PROTOCOL):
        b.charge_research()
    with pytest.raises(RuntimeError, match="research budget"):
        b.charge_research()


def test_budget_circuit_breaker_trips_on_cost():
    b = rd._Budget()
    # Each research is $0.20; the breaker is $2.00. Push cost over without
    # hitting the call cap by inflating cost manually.
    b.estimated_cost_usd = 1.95
    with pytest.raises(RuntimeError, match="circuit breaker"):
        b.charge_research()


# ---------------------------------------------------------------------------
# _make_search_fn
# ---------------------------------------------------------------------------


def test_search_fn_returns_seeds_on_research_plus_first_call(monkeypatch):
    seeds = [{"url": "https://seed.example.com", "title": "S"}]
    budget = rd._Budget()
    fn = rd._make_search_fn("research_plus", budget, research_seeds=seeds)
    queries_used = [0]
    errors: list[dict] = []
    out = fn("q", max_results=5, queries_used=queries_used, max_queries=4, errors=errors)
    assert out == seeds
    # Seed return is free — no exa.search called.
    assert budget.search_calls == 0
    assert queries_used[0] == 1


def test_search_fn_calls_exa_after_first_research_plus(monkeypatch):
    """Subsequent research_plus calls hit exa.search and charge as 'auto'."""
    captured = []
    monkeypatch.setattr(rd.exa, "search", lambda q, max_results, mode: captured.append(mode) or [{"url": "https://x"}])
    seeds = [{"url": "https://seed"}]
    budget = rd._Budget()
    fn = rd._make_search_fn("research_plus", budget, research_seeds=seeds)
    queries_used = [0]
    errors: list[dict] = []
    fn("q1", 5, queries_used, 4, errors)  # first: seeds
    fn("q2", 5, queries_used, 4, errors)  # second: exa
    assert captured == ["auto"]
    assert budget.search_calls == 1


def test_search_fn_respects_max_queries():
    fn = rd._make_search_fn("auto", rd._Budget())
    queries_used = [4]
    out = fn("q", 5, queries_used, max_queries=4, errors=[])
    assert out == []


def test_search_fn_records_errors_on_exa_exception(monkeypatch):
    def boom(*a, **kw):
        raise rd.exa.ExaError(rd.exa.normalize_error("boom"))

    monkeypatch.setattr(rd.exa, "search", boom)
    fn = rd._make_search_fn("auto", rd._Budget())
    errors: list[dict] = []
    out = fn("query that fails", 5, [0], 4, errors)
    assert out == []
    assert len(errors) == 1
    assert errors[0]["provider"] == "exa"


# ---------------------------------------------------------------------------
# patch / restore + classify wrapper
# ---------------------------------------------------------------------------


def test_patch_and_restore_search():
    sentinel = lambda *a, **kw: "patched"  # noqa: E731
    original = rd.audit_reports_mod._tavily_search
    try:
        rd._patch_search(sentinel)
        assert rd.audit_reports_mod._tavily_search is sentinel
        assert rd.inventory_mod._tavily_search is sentinel
        assert rd.inventory_domain_mod._tavily_search is sentinel
    finally:
        rd._restore_search(original)
    assert rd.audit_reports_mod._tavily_search is original


def test_patch_classify_with_seeds_appends_unseen_urls():
    original = rd.audit_reports_mod.classify_search_results
    seeds = [
        {"url": "https://new.example.com", "title": "new"},
        {"url": "https://dup.example.com"},
        {"url": ""},  # ignored
    ]
    try:
        rd.audit_reports_mod.classify_search_results = lambda results, company, debug=False: [
            {"url": "https://dup.example.com", "auditor": "X"}
        ]
        rd._patch_classify_with_seeds(seeds)
        out = rd.audit_reports_mod.classify_search_results([], "p")
        urls = [c["url"] for c in out]
        assert urls == ["https://dup.example.com", "https://new.example.com"]
        # Seeded entry confidence is 1.0
        added = [c for c in out if c["url"] == "https://new.example.com"][0]
        assert added["confidence"] == 1.0
    finally:
        rd.audit_reports_mod.classify_search_results = original


# ---------------------------------------------------------------------------
# known_docs / SPA overrides
# ---------------------------------------------------------------------------


def test_load_known_docs_missing_file(monkeypatch, tmp_path):
    monkeypatch.setattr(rd, "KNOWN_DOCS_PATH", tmp_path / "missing.yaml")
    assert rd._load_known_docs() == {}


def test_load_known_docs_present(monkeypatch, tmp_path):
    p = tmp_path / "k.yaml"
    p.write_text("protocols:\n  gmx:\n    audit_urls: [https://a]\n")
    monkeypatch.setattr(rd, "KNOWN_DOCS_PATH", p)
    out = rd._load_known_docs()
    assert "gmx" in out
    assert out["gmx"]["audit_urls"] == ["https://a"]


def test_apply_spa_overrides_no_known(monkeypatch):
    monkeypatch.setattr(rd, "_load_known_docs", lambda: {})
    inv = {"contracts": []}
    aud = {"reports": []}
    rd._apply_spa_overrides("nope", inv, aud)
    assert inv == {"contracts": []}
    assert aud == {"reports": []}


def test_apply_spa_overrides_injects(monkeypatch):
    monkeypatch.setattr(
        rd,
        "_load_known_docs",
        lambda: {
            "gmx": {
                "contract_docs_urls": ["https://docs.gmx/c"],
                "contract_docs_raw_urls": ["https://docs.gmx/raw"],
                "audit_urls": ["https://gmx-audit.pdf"],
            }
        },
    )
    inv: dict = {"contracts": []}
    aud: dict = {"reports": []}
    rd._apply_spa_overrides("GMX", inv, aud)
    assert any("docs.gmx/c" in n for n in inv["notes"])
    assert any("raw" in n for n in inv["notes"])
    assert len(aud["reports"]) == 1
    assert aud["reports"][0]["discovery_source"] == "spa_override"
    assert aud["reports"][0]["confidence"] == 1.0


# ---------------------------------------------------------------------------
# audit enrichment
# ---------------------------------------------------------------------------


def test_enrich_extracts_static_pdf_and_verified_github_commit(monkeypatch):
    sha = "abc123def456"
    html = f'<a href="/reports/acme.pdf">PDF</a> <a href="https://github.com/acme/protocol/commit/{sha}">commit</a>'
    monkeypatch.setattr(ae, "_fetch_html", lambda url, debug=False: html)
    monkeypatch.setattr(ae, "_commit_exists", lambda repo, commit: repo == "acme/protocol" and commit == sha)

    result = {"reports": [{"url": "https://auditor.test/acme"}]}
    ae.enrich_audit_reports(result, "Acme")

    report = result["reports"][0]
    assert report["pdf_url"] == "https://auditor.test/reports/acme.pdf"
    assert report["source_repo"] == "acme/protocol"
    assert report["reviewed_commits"] == [sha]
    assert report["classified_commits"] == [{"sha": sha, "label": "reviewed", "provenance": "html_ref"}]


def test_enrich_drops_ai_commits_that_do_not_resolve(monkeypatch):
    monkeypatch.setattr(ae, "_fetch_html", lambda url, debug=False: None)
    monkeypatch.setattr(ae, "_commit_exists", lambda repo, commit: False)
    # The repo-hosted-PDF pass would otherwise probe GitHub for audit folders.
    monkeypatch.setattr(ae, "_discover_repo_audit_folders", lambda owner, repo, debug=False: [])

    result = {
        "reports": [
            {
                "url": "https://auditor.test/acme",
                "source_repo": "acme/protocol",
                "reviewed_commits": ["abc123def456"],
            }
        ]
    }
    ae.enrich_audit_reports(result, "Acme")
    assert result["reports"][0]["reviewed_commits"] == []


def test_enrich_prefers_repo_hosted_dependency_pdf(monkeypatch):
    monkeypatch.setattr(ae, "_fetch_html", lambda url, debug=False: None)
    monkeypatch.setattr(
        ae,
        "_discover_repo_audit_folders",
        lambda owner, repo, debug=False: [{"ref": "main", "path": "audits"}],
    )
    monkeypatch.setattr(
        ae,
        "_fetch_github_tree_as_reports",
        lambda *a, **kw: {
            "reports": [
                {
                    "title": "BoringVault Audit",
                    "pdf_url": "https://raw.githubusercontent.com/veda/boring-vault/main/audits/boringvault.pdf",
                    "source_repo": "veda/boring-vault",
                }
            ]
        },
    )

    result = {
        "reports": [
            {
                "url": "https://auditor.example.com/view/boringvault",
                "source_repo": "veda/boring-vault",
                "dependency_component": "BoringVault",
            }
        ]
    }
    ae.enrich_audit_reports(result, "EtherFi")
    assert result["reports"][0]["url"].endswith("/audits/boringvault.pdf")
    assert result["reports"][0]["pdf_url"].endswith("/audits/boringvault.pdf")


# --- repo-hosted PDF adoption must be corroborated -------------------------
#
# Folder listing taken from etherfi-protocol/smart-contracts@master/audits,
# in tree order — the same set the crawl returns. The first entry is what a
# positional pick lands on.
_ETHERFI_AUDIT_FOLDER = [
    {
        "title": "Omniscia Audit",
        "auditor": "Omniscia",
        "pdf_url": "https://raw.githubusercontent.com/etherfi-protocol/smart-contracts/"
        "master/audits/2023.05.16%20-%20Omniscia.pdf",
        "source_repo": "etherfi-protocol/smart-contracts",
        "source_path": "audits/2023.05.16 - Omniscia.pdf",
    },
    {
        "title": "Nethermind Audit",
        "auditor": "Nethermind",
        "pdf_url": "https://raw.githubusercontent.com/etherfi-protocol/smart-contracts/"
        "master/audits/2023.07.05%20-%20Nethermind.pdf",
        "source_repo": "etherfi-protocol/smart-contracts",
        "source_path": "audits/2023.07.05 - Nethermind.pdf",
    },
    {
        "title": "EtherFi L2 Governance Token Smart Contract Security Assessment Report",
        "auditor": "Halborn",
        "pdf_url": "https://raw.githubusercontent.com/etherfi-protocol/smart-contracts/"
        "master/audits/2024.06.25%20-%20Halborn%20-%20EtherFi_L2_Governance_Token.pdf",
        "source_repo": "etherfi-protocol/smart-contracts",
        "source_path": "audits/2024.06.25 - Halborn - EtherFi_L2_Governance_Token.pdf",
    },
]

_NM_MD_URL = (
    "https://raw.githubusercontent.com/etherfi-protocol/smart-contracts/"
    "master/audits/NM-0217%20-%20EtherFi%20Restaking%20Of%20stETH%20Holdings.md"
)


def _stub_repo_folder(monkeypatch, listing):
    monkeypatch.setattr(ae, "_fetch_html", lambda url, debug=False: None)
    monkeypatch.setattr(
        ae,
        "_discover_repo_audit_folders",
        lambda owner, repo, debug=False: [{"ref": "master", "path": "audits"}],
    )
    monkeypatch.setattr(
        ae,
        "_fetch_github_tree_as_reports",
        lambda *a, **kw: {"reports": listing},
    )


def test_enrich_leaves_markdown_report_pdfless_when_no_candidate_corroborates(monkeypatch):
    """A .md report whose own document has no PDF in the folder keeps no
    pdf_url — and keeps its own URL, so it still persists as its own row."""
    _stub_repo_folder(monkeypatch, _ETHERFI_AUDIT_FOLDER)

    result = {
        "reports": [
            {
                "url": _NM_MD_URL,
                "auditor": "Nethermind",
                "title": "EtherFi Restaking Of stETH Holdings",
                "source_repo": "etherfi-protocol/smart-contracts",
            }
        ]
    }
    ae.enrich_audit_reports(result, "etherfi")

    report = result["reports"][0]
    assert report.get("pdf_url") is None
    assert report["url"] == _NM_MD_URL
    # Identity fields are never rewritten by the adoption pass.
    assert report["auditor"] == "Nethermind"
    assert report["title"] == "EtherFi Restaking Of stETH Holdings"


def test_enrich_does_not_adopt_a_pdf_naming_a_different_auditor(monkeypatch):
    """Title corroboration cannot override the candidate's own attribution."""
    listing = [
        {
            "title": "EtherFi L2 Governance Token Smart Contract Security Assessment Report",
            "auditor": "Certora",
            "pdf_url": "https://raw.githubusercontent.com/etherfi-protocol/smart-contracts/"
            "master/audits/2024.06.25%20-%20Certora%20-%20EtherFi_L2_Governance_Token.pdf",
            "source_repo": "etherfi-protocol/smart-contracts",
            "source_path": "audits/2024.06.25 - Certora - EtherFi_L2_Governance_Token.pdf",
        }
    ]
    _stub_repo_folder(monkeypatch, listing)

    result = {
        "reports": [
            {
                "url": "https://halborn.example/reports/etherfi-l2-governance-token",
                "auditor": "Halborn",
                "title": "EtherFi L2 Governance Token Smart Contract Security Assessment Report",
                "source_repo": "etherfi-protocol/smart-contracts",
            }
        ]
    }
    ae.enrich_audit_reports(result, "etherfi")
    assert result["reports"][0].get("pdf_url") is None


def test_enrich_adopts_repo_pdf_corroborated_by_title(monkeypatch):
    """Positive control: the folder holds this report's own document."""
    _stub_repo_folder(monkeypatch, _ETHERFI_AUDIT_FOLDER)

    result = {
        "reports": [
            {
                "url": "https://halborn.example/reports/etherfi-l2-governance-token",
                "auditor": "Halborn",
                "title": "EtherFi L2 Governance Token Smart Contract Security Assessment Report",
                "source_repo": "etherfi-protocol/smart-contracts",
            }
        ]
    }
    ae.enrich_audit_reports(result, "etherfi")

    report = result["reports"][0]
    assert report["pdf_url"].endswith("EtherFi_L2_Governance_Token.pdf")
    assert report["url"] == report["pdf_url"]
    assert report["source_path"] == "audits/2024.06.25 - Halborn - EtherFi_L2_Governance_Token.pdf"


def test_enrich_does_not_adopt_when_two_candidates_corroborate_equally(monkeypatch):
    """Two same-titled PDFs (the folder holds a v1 and a re-audit): which one
    this report is cannot be told, so neither is adopted."""
    twin = dict(
        _ETHERFI_AUDIT_FOLDER[2],
        pdf_url=_ETHERFI_AUDIT_FOLDER[2]["pdf_url"].replace(".pdf", "-v2.pdf"),
        source_path=_ETHERFI_AUDIT_FOLDER[2]["source_path"].replace(".pdf", "-v2.pdf"),
    )
    _stub_repo_folder(monkeypatch, [*_ETHERFI_AUDIT_FOLDER, twin])

    result = {
        "reports": [
            {
                "url": "https://halborn.example/reports/etherfi-l2-governance-token",
                "auditor": "Halborn",
                "title": "EtherFi L2 Governance Token Smart Contract Security Assessment Report",
                "source_repo": "etherfi-protocol/smart-contracts",
            }
        ]
    }
    ae.enrich_audit_reports(result, "etherfi")
    assert result["reports"][0].get("pdf_url") is None


def test_enrich_does_not_adopt_on_the_protocol_name_alone(monkeypatch):
    """Every file in a protocol's own audit folder carries the protocol's
    name; that is not evidence of which document a report is."""
    _stub_repo_folder(
        monkeypatch,
        [
            {
                "title": "EtherFi Berachain Native Minting Contracts",
                "auditor": "Unknown",
                "pdf_url": "https://raw.githubusercontent.com/etherfi-protocol/weETH-cross-chain/"
                "master/audit/EtherFi%20-%20Berachain%20Native%20Minting%20Contracts.pdf",
                "source_repo": "etherfi-protocol/weETH-cross-chain",
                "source_path": "audit/EtherFi - Berachain Native Minting Contracts.pdf",
            }
        ],
    )

    md_url = (
        "https://raw.githubusercontent.com/etherfi-protocol/weETH-cross-chain/"
        "master/audit/20241109-scroll-native-minting.md"
    )
    result = {
        "reports": [
            {
                "url": md_url,
                "auditor": "Unknown",
                "title": "Scroll Native Minting",
                "source_repo": "etherfi-protocol/weETH-cross-chain",
            }
        ]
    }
    ae.enrich_audit_reports(result, "etherfi")

    assert result["reports"][0].get("pdf_url") is None
    assert result["reports"][0]["url"] == md_url


def test_enrich_does_not_adopt_when_the_title_is_only_the_protocol_name(monkeypatch):
    """'EtherFi Draft Audit' is a real corpus title that survives generic-token
    stripping as the bare protocol name. Matching it against a folder in the
    protocol's own repo matches on nothing the folder does not already share."""
    _stub_repo_folder(
        monkeypatch,
        [
            {
                "title": "Certora EtherFi BeHype Audit",
                "auditor": "Certora",
                "pdf_url": "https://raw.githubusercontent.com/etherfi-protocol/beHYPE/"
                "master/audit/Certora%20EtherFi%20BeHype%20Audit.pdf",
                "source_repo": "etherfi-protocol/beHYPE",
                "source_path": "audit/Certora EtherFi BeHype Audit.pdf",
            }
        ],
    )

    result = {
        "reports": [
            {
                "url": "https://raw.githubusercontent.com/etherfi-protocol/beHYPE/master/audit/behype.md",
                "auditor": "Unknown",
                "title": "EtherFi Draft Audit",
                "source_repo": "etherfi-protocol/beHYPE",
            }
        ]
    }
    ae.enrich_audit_reports(result, "etherfi")

    assert result["reports"][0].get("pdf_url") is None
    assert result["reports"][0]["auditor"] == "Unknown"


def test_enrich_does_not_adopt_when_the_title_is_only_the_reports_own_auditor(monkeypatch):
    """A firm publishes many reports into one folder, so its name tells them
    apart from nothing — the exact shape that gave NM-0217's .md an Omniscia
    PDF, re-run with the right firm and still the wrong document."""
    _stub_repo_folder(monkeypatch, _ETHERFI_AUDIT_FOLDER)

    result = {
        "reports": [
            {
                "url": _NM_MD_URL,
                "auditor": "Nethermind",
                "title": "Nethermind Audit",
                "source_repo": "etherfi-protocol/smart-contracts",
            }
        ]
    }
    ae.enrich_audit_reports(result, "etherfi")

    report = result["reports"][0]
    assert report.get("pdf_url") is None
    assert report["url"] == _NM_MD_URL


def test_enrich_adopts_when_the_title_keeps_a_token_beyond_the_two_names(monkeypatch):
    """Positive control for the same gate: 'EtherFi Deposit Adapter Contract'
    (a real corpus title) leads with the protocol's name, but 'deposit adapter'
    survives it, so the report still earns its own document."""
    _stub_repo_folder(
        monkeypatch,
        [
            *_ETHERFI_AUDIT_FOLDER,
            {
                "title": "EtherFi Deposit Adapter Contract",
                "auditor": "Nethermind",
                "pdf_url": "https://raw.githubusercontent.com/etherfi-protocol/smart-contracts/"
                "master/audits/NM-0350%20-%20EtherFi%20Deposit%20Adapter.pdf",
                "source_repo": "etherfi-protocol/smart-contracts",
                "source_path": "audits/NM-0350 - EtherFi Deposit Adapter.pdf",
            },
        ],
    )

    result = {
        "reports": [
            {
                "url": "https://nethermind.example/reports/etherfi-deposit-adapter",
                "auditor": "Nethermind",
                "title": "EtherFi Deposit Adapter Contract",
                "source_repo": "etherfi-protocol/smart-contracts",
            }
        ]
    }
    ae.enrich_audit_reports(result, "etherfi")

    assert result["reports"][0]["pdf_url"].endswith("NM-0350%20-%20EtherFi%20Deposit%20Adapter.pdf")


def test_enrich_does_not_adopt_on_a_component_that_is_only_the_protocol_name(monkeypatch):
    """The component tier answers to the same gate as the title tier: a
    dependency whose name is the protocol's own picks out no document."""
    _stub_repo_folder(
        monkeypatch,
        [
            {
                "title": "Certora EtherFi BeHype Audit",
                "auditor": "Certora",
                "pdf_url": "https://raw.githubusercontent.com/etherfi-protocol/beHYPE/"
                "master/audit/Certora%20EtherFi%20BeHype%20Audit.pdf",
                "source_repo": "etherfi-protocol/beHYPE",
                "source_path": "audit/Certora EtherFi BeHype Audit.pdf",
            }
        ],
    )

    result = {
        "reports": [
            {
                "url": "https://auditor.example.com/view/etherfi",
                "auditor": "Unknown",
                "source_repo": "etherfi-protocol/beHYPE",
                "dependency_component": "EtherFi",
            }
        ]
    }
    ae.enrich_audit_reports(result, "etherfi")

    assert result["reports"][0].get("pdf_url") is None


def test_enrich_does_not_adopt_on_the_run_together_spelling_of_the_protocol(monkeypatch):
    """The protocol is registered as 'ether.fi' but titled 'EtherFi'; the two
    spellings are the same name, so neither one corroborates."""
    _stub_repo_folder(
        monkeypatch,
        [
            {
                "title": "Certora EtherFi BeHype Audit",
                "auditor": "Certora",
                "pdf_url": "https://raw.githubusercontent.com/etherfi-protocol/beHYPE/"
                "master/audit/Certora%20EtherFi%20BeHype%20Audit.pdf",
                "source_repo": "etherfi-protocol/beHYPE",
                "source_path": "audit/Certora EtherFi BeHype Audit.pdf",
            }
        ],
    )

    result = {
        "reports": [
            {
                "url": "https://raw.githubusercontent.com/etherfi-protocol/beHYPE/master/audit/behype.md",
                "auditor": "Unknown",
                "title": "EtherFi Audit",
                "source_repo": "etherfi-protocol/beHYPE",
            }
        ]
    }
    ae.enrich_audit_reports(result, "ether.fi")

    assert result["reports"][0].get("pdf_url") is None


def test_enrich_does_not_adopt_on_a_title_of_only_generic_audit_vocabulary(monkeypatch):
    """'Audit Report' names no document. It is a substring of most candidate
    titles, so without the generic-vocabulary strip it would corroborate the
    lone candidate in any folder."""
    _stub_repo_folder(
        monkeypatch,
        [
            {
                "title": "ether.fi Audit Report",
                "auditor": "Zellic",
                "pdf_url": "https://raw.githubusercontent.com/Zellic/publications/"
                "master/ether.fi%20-%20Zellic%20Audit%20Report.pdf",
                "source_repo": "Zellic/publications",
                "source_path": "ether.fi - Zellic Audit Report.pdf",
            }
        ],
    )

    result = {
        "reports": [
            {
                "url": "https://raw.githubusercontent.com/Zellic/publications/master/etherfi.md",
                "auditor": "Unknown",
                "title": "Audit Report",
                "source_repo": "Zellic/publications",
            }
        ]
    }
    ae.enrich_audit_reports(result, "etherfi")

    assert result["reports"][0].get("pdf_url") is None


def test_enrich_does_not_adopt_on_a_title_too_short_to_identify_a_document(monkeypatch):
    """What survives stripping has to be long enough to name something: a bare
    version fragment matches any candidate that mentions the same version."""
    _stub_repo_folder(
        monkeypatch,
        [
            {
                "title": "Liquid Vault v3 Audit",
                "auditor": "Certora",
                "pdf_url": "https://raw.githubusercontent.com/etherfi-protocol/smart-contracts/"
                "master/audits/2025.01.10%20-%20Certora%20-%20Liquid%20Vault%20v3.pdf",
                "source_repo": "etherfi-protocol/smart-contracts",
                "source_path": "audits/2025.01.10 - Certora - Liquid Vault v3.pdf",
            }
        ],
    )

    result = {
        "reports": [
            {
                "url": "https://raw.githubusercontent.com/etherfi-protocol/smart-contracts/master/audits/x.md",
                "auditor": "Certora",
                "title": "Audit v3",
                "source_repo": "etherfi-protocol/smart-contracts",
            }
        ]
    }
    ae.enrich_audit_reports(result, "etherfi")

    assert result["reports"][0].get("pdf_url") is None


def test_enrich_infers_repo_from_raw_github_pdf(monkeypatch):
    monkeypatch.setattr(ae, "_fetch_html", lambda url, debug=False: None)

    raw_pdf = (
        "https://raw.githubusercontent.com/etherfi-protocol/smart-contracts/"
        "master/audits/2026.01.29%20-%20Certora%20-%20Reaudit.pdf"
    )
    result = {"reports": [{"url": raw_pdf, "auditor": "Certora", "title": "Reaudit"}]}

    ae.enrich_audit_reports(result, "etherfi")

    report = result["reports"][0]
    assert report["pdf_url"] == raw_pdf
    assert report["source_repo"] == "etherfi-protocol/smart-contracts"
    assert report["referenced_repos"] == ["etherfi-protocol/smart-contracts"]
    assert report["source_path"] == "audits/2026.01.29 - Certora - Reaudit.pdf"


# ---------------------------------------------------------------------------
# _needs_dependency_pass
# ---------------------------------------------------------------------------


def test_needs_dependency_pass_true_from_llm(monkeypatch):
    captured = {}

    def fake_chat(messages, **kwargs):
        captured["prompt"] = messages[0]["content"]
        return (
            '{"should_run_dependency_pass": true, "confidence": 0.86, '
            '"rationale": "uses Veda", "suspected_dependencies": ["BoringVault"]}'
        )

    monkeypatch.setattr(rd.llm, "chat", fake_chat)

    assert rd._needs_dependency_pass("ether.fi", contracts=[{"name": "BoringVault Manager"}], audits=[]) is True
    assert "BoringVault Manager" in captured["prompt"]


def test_needs_dependency_pass_false_from_llm(monkeypatch):
    monkeypatch.setattr(
        rd.llm,
        "chat",
        lambda messages, **kwargs: (
            '{"should_run_dependency_pass": false, "confidence": 0.91, '
            '"rationale": "core-only", "suspected_dependencies": []}'
        ),
    )

    assert (
        rd._needs_dependency_pass(
            "foo",
            contracts=[{"name": "FooToken"}],
            audits=[{"title": "core protocol audit"}],
        )
        is False
    )


def test_needs_dependency_pass_unparseable_llm_response(monkeypatch):
    monkeypatch.setattr(rd.llm, "chat", lambda messages, **kwargs: "not json")
    assert rd._needs_dependency_pass("foo", contracts=[{"name": "FooToken"}], audits=[]) is False


def test_needs_dependency_pass_no_evidence_skips_llm(monkeypatch):
    def fail(*a, **kw):
        raise AssertionError("LLM should not be called without evidence")

    monkeypatch.setattr(rd.llm, "chat", fail)
    assert rd._needs_dependency_pass("foo", contracts=[], audits=[]) is False


# ---------------------------------------------------------------------------
# _cached_deep_research
# ---------------------------------------------------------------------------


def test_cached_deep_research_caches_by_instructions(monkeypatch):
    calls = []

    def fake_dr(instructions, schema=None, timeout_seconds=900):
        calls.append(instructions)
        return {"data": {"x": len(calls)}, "task_id": "t", "status": "completed"}

    monkeypatch.setattr(rd.exa, "deep_research", fake_dr)

    r1 = rd._cached_deep_research("instr-A", schema={"a": 1})
    r2 = rd._cached_deep_research("instr-A", schema={"a": 1})
    r3 = rd._cached_deep_research("instr-B", schema={"a": 1})
    assert r1 is r2  # cache hit returns same object
    assert r3 is not r1
    assert calls == ["instr-A", "instr-B"]


def test_cached_deep_research_invalidates_on_schema_change(monkeypatch):
    monkeypatch.setattr(
        rd.exa,
        "deep_research",
        lambda instructions, schema=None, timeout_seconds=900: {"data": {"s": schema}},
    )
    r1 = rd._cached_deep_research("same", schema={"v": 1})
    r2 = rd._cached_deep_research("same", schema={"v": 2})
    assert r1["data"]["s"] == {"v": 1}
    assert r2["data"]["s"] == {"v": 2}


# ---------------------------------------------------------------------------
# _dependency_research
# ---------------------------------------------------------------------------


def test_dependency_research_pass1_failure_returns_empty(monkeypatch):
    def fail(*a, **kw):
        raise RuntimeError("pass 1 down")

    monkeypatch.setattr(rd, "_cached_deep_research", fail)
    out = rd._dependency_research("ether.fi", rd._Budget())
    assert out == []


def test_dependency_research_full_flow(monkeypatch):
    """Pass 1 yields components; pass 2 yields per-component audits."""

    def fake(instructions, schema=None):
        if "third-party" in instructions or "third party" in instructions:
            return {"data": {"components": [{"name": "BoringVault", "author": "Veda"}]}}
        return {
            "data": {
                "auditReports": [{"auditor": "Spearbit", "url": "https://example.com/bv.pdf", "title": "BV audit"}]
            }
        }

    monkeypatch.setattr(rd, "_cached_deep_research", fake)
    out = rd._dependency_research("ether.fi", rd._Budget())
    assert len(out) == 1
    assert out[0]["url"] == "https://example.com/bv.pdf"
    assert out[0]["dependency_component"] == "BoringVault"
    assert out[0]["discovery_source"] == "dependency_two_pass"


def test_dependency_research_skips_audits_without_url(monkeypatch):
    def fake(instructions, schema=None):
        if "components" in instructions or "third-party" in instructions:
            return {"data": {"components": [{"name": "X", "author": "Y"}]}}
        return {"data": {"auditReports": [{"auditor": "Z", "url": ""}]}}

    monkeypatch.setattr(rd, "_cached_deep_research", fake)
    out = rd._dependency_research("p", rd._Budget())
    assert out == []


def test_dependency_research_pass2_failure_skipped(monkeypatch):
    state = {"calls": 0}

    def fake(instructions, schema=None):
        state["calls"] += 1
        if state["calls"] == 1:
            return {"data": {"components": [{"name": "X", "author": "Y"}]}}
        raise RuntimeError("pass 2 down")

    monkeypatch.setattr(rd, "_cached_deep_research", fake)
    out = rd._dependency_research("p", rd._Budget())
    assert out == []  # pass 2 failure is logged + skipped


def test_dependency_research_breaks_when_budget_exhausted(monkeypatch):
    """Once research budget cap is hit during pass 2, the loop stops."""
    state = {"calls": 0}

    def fake(instructions, schema=None):
        state["calls"] += 1
        if state["calls"] == 1:
            return {"data": {"components": [{"name": f"c{i}", "author": "a"} for i in range(5)]}}
        return {"data": {"auditReports": [{"auditor": "Z", "url": f"https://e/{state['calls']}.pdf"}]}}

    monkeypatch.setattr(rd, "_cached_deep_research", fake)

    # Pre-spent budget: only 1 research call left after pass 1.
    b = rd._Budget()
    b.research_calls = rd.MAX_RESEARCH_CALLS_PER_PROTOCOL - 1  # pass 1 will tip into the cap
    out = rd._dependency_research("p", b)
    # Should not run all 5 component audits.
    assert len(out) <= 1


# ---------------------------------------------------------------------------
# run_discovery — end-to-end with all underlying modules mocked
# ---------------------------------------------------------------------------


def _stub_discovery_modules(monkeypatch, *, audit_reports=None, address_contracts=None):
    """Replace the heavy pipeline functions with cheap stubs."""
    calls = {}

    def fake_search_audit_reports(protocol, official_domain=None, max_queries=4, debug=False):
        return {
            "reports": list(audit_reports or []),
            "errors": [],
            "notes": [],
        }

    def fake_search_protocol_inventory(
        protocol, chain=None, limit=500, max_queries=4, run_deployer=False, debug=False, declared_chains=None
    ):
        calls["inventory_run_deployer"] = run_deployer
        return {
            "contracts": list(address_contracts or []),
            "official_domain": "example.com",
            "pages_considered": [],
            "sources": {"exa": True},
        }

    monkeypatch.setattr(rd.audit_reports_mod, "search_audit_reports", fake_search_audit_reports)
    monkeypatch.setattr(rd.inventory_mod, "search_protocol_inventory", fake_search_protocol_inventory)
    return calls


def test_run_discovery_happy_path_no_deps(monkeypatch):
    calls = _stub_discovery_modules(
        monkeypatch,
        audit_reports=[{"url": "https://aud", "auditor": "X", "title": "core"}],
        address_contracts=[{"name": "Token", "address": "0x" + "1" * 40}],
    )

    def fake_dr(instructions, schema=None):
        if "audit reports" in instructions:
            return {"data": {"auditReports": [{"auditor": "Tob", "url": "https://seed.example.com/a.pdf"}]}}
        # address research
        return {
            "data": {
                "contracts": [
                    {
                        "name": "Vault",
                        "address": "0x" + "2" * 40,
                        "chain": "mainnet",
                    }
                ]
            }
        }

    monkeypatch.setattr(rd, "_cached_deep_research", fake_dr)
    monkeypatch.setattr(rd, "_needs_dependency_pass", lambda protocol, contracts, audits: False)

    out = rd.run_discovery("ether.fi")
    assert "audits" in out and "addresses" in out and "meta" in out
    # Address Deep Research result was appended.
    addrs = [c["address"] for c in out["addresses"]["contracts"]]
    assert "0x" + "2" * 40 in addrs
    assert out["meta"]["protocol"] == "ether.fi"
    assert out["meta"]["search_calls"] >= 0
    # Dependency classifier chose not to trigger.
    assert out["meta"]["dependency_pass_triggered"] is False
    assert calls["inventory_run_deployer"] is True


def test_run_discovery_carries_verified_ai_audit_metadata(monkeypatch):
    sha = "abc123def456"
    _stub_discovery_modules(
        monkeypatch,
        audit_reports=[{"url": "https://seed.example.com/a.pdf", "auditor": "Tob", "title": "core"}],
    )

    def fake_dr(instructions, schema=None):
        if "audit reports" in instructions:
            return {
                "data": {
                    "auditReports": [
                        {
                            "auditor": "Tob",
                            "url": "https://seed.example.com/a.pdf",
                            "source_repo": "etherfi/protocol",
                            "reviewed_commits": [sha],
                        }
                    ]
                }
            }
        return {"data": {"contracts": []}}

    monkeypatch.setattr(rd, "_cached_deep_research", fake_dr)
    monkeypatch.setattr(rd, "_needs_dependency_pass", lambda protocol, contracts, audits: False)
    monkeypatch.setattr(ae, "_commit_exists", lambda repo, commit: repo == "etherfi/protocol" and commit == sha)

    out = rd.run_discovery("ether.fi")
    report = out["audits"]["reports"][0]
    assert report["source_repo"] == "etherfi/protocol"
    assert report["reviewed_commits"] == [sha]
    assert report["classified_commits"][0]["provenance"] == "ai_returned"


def test_run_discovery_triggers_dependency_pass(monkeypatch):
    _stub_discovery_modules(
        monkeypatch,
        audit_reports=[{"url": "https://aud", "auditor": "X", "title": "core"}],
        address_contracts=[{"name": "BoringVault Manager", "address": "0x" + "1" * 40}],
    )

    dep_called = []

    def fake_dep(protocol, budget):
        dep_called.append(protocol)
        return [{"url": "https://dep.example.com", "title": "dep audit"}]

    monkeypatch.setattr(rd, "_dependency_research", fake_dep)
    monkeypatch.setattr(rd, "_needs_dependency_pass", lambda protocol, contracts, audits: True)
    monkeypatch.setattr(
        rd,
        "_cached_deep_research",
        lambda instructions, schema=None: {"data": {}},
    )

    out = rd.run_discovery("ether.fi")
    assert dep_called == ["ether.fi"]
    urls = [r["url"] for r in out["audits"]["reports"]]
    assert "https://dep.example.com" in urls


def test_run_discovery_audit_seed_failure_does_not_abort(monkeypatch):
    """Deep Research failure on audit seeds is logged but pipeline continues."""
    _stub_discovery_modules(monkeypatch)

    def fake_dr(instructions, schema=None):
        if "audit reports" in instructions:
            raise RuntimeError("seed call down")
        return {"data": {"contracts": []}}

    monkeypatch.setattr(rd, "_cached_deep_research", fake_dr)
    monkeypatch.setattr(rd, "_needs_dependency_pass", lambda protocol, contracts, audits: False)

    out = rd.run_discovery("p")
    # Pipeline still produces a meta block.
    assert out["meta"]["protocol"] == "p"


def test_run_discovery_skips_invalid_addresses_from_deep_research(monkeypatch):
    _stub_discovery_modules(monkeypatch)
    monkeypatch.setattr(
        rd,
        "_cached_deep_research",
        lambda instructions, schema=None: {
            "data": {
                "contracts": [
                    {"name": "bad-no-prefix", "address": "deadbeef"},
                    {"name": "bad-too-short", "address": "0x123"},
                    {"name": "ok", "address": "0x" + "a" * 40, "chain": "mainnet"},
                ]
            }
        },
    )
    monkeypatch.setattr(rd, "_needs_dependency_pass", lambda protocol, contracts, audits: False)
    out = rd.run_discovery("p")
    addrs = [c["address"] for c in out["addresses"]["contracts"]]
    assert addrs == ["0x" + "a" * 40]


def test_run_discovery_applies_spa_overrides(monkeypatch):
    _stub_discovery_modules(monkeypatch)
    monkeypatch.setattr(rd, "_cached_deep_research", lambda instructions, schema=None: {"data": {}})
    monkeypatch.setattr(rd, "_needs_dependency_pass", lambda protocol, contracts, audits: False)
    monkeypatch.setattr(
        rd,
        "_load_known_docs",
        lambda: {"p": {"audit_urls": ["https://known.audit/a.pdf"]}},
    )
    out = rd.run_discovery("p")
    urls = [r["url"] for r in out["audits"]["reports"]]
    assert "https://known.audit/a.pdf" in urls


def test_reset_cache_clears_entries(monkeypatch):
    monkeypatch.setattr(
        rd.exa,
        "deep_research",
        lambda instructions, schema=None, timeout_seconds=900: {"data": {}},
    )
    rd._cached_deep_research("k1", schema={})
    assert rd._research_cache  # populated
    rd.reset_cache()
    assert rd._research_cache == {}


def test_research_cache_evicts_at_max(monkeypatch):
    """Distinct instructions past the cap evict, keeping the cache size-bounded."""
    monkeypatch.setattr(rd, "_RESEARCH_CACHE_MAX", 4)
    monkeypatch.setattr(
        rd.exa,
        "deep_research",
        lambda instructions, schema=None, timeout_seconds=900: {"data": {"i": instructions}},
    )
    for i in range(20):
        rd._cached_deep_research(f"instr-{i}", schema={})
    assert len(rd._research_cache) <= rd._RESEARCH_CACHE_MAX


def test_research_cache_ttl_expiry_reprobes(monkeypatch):
    """An entry past the TTL is dropped on read and the research re-run."""
    calls: list[str] = []
    monkeypatch.setattr(
        rd.exa,
        "deep_research",
        lambda instructions, schema=None, timeout_seconds=900: calls.append(instructions) or {"data": {}},
    )
    monkeypatch.setattr(rd, "RESEARCH_CACHE_TTL_SECONDS", 0)
    rd._cached_deep_research("k", schema={})
    rd._cached_deep_research("k", schema={})
    assert len(calls) == 2


def test_research_cache_pressure_state_set_and_cleared(monkeypatch):
    """Crossing 50% records pressure; reset_cache forgets it."""
    from utils import memory

    monkeypatch.setattr(rd, "_RESEARCH_CACHE_MAX", 4)
    monkeypatch.setattr(
        rd.exa,
        "deep_research",
        lambda instructions, schema=None, timeout_seconds=900: {"data": {}},
    )
    for i in range(8):
        rd._cached_deep_research(f"instr-{i}", schema={})
    assert "research" in memory._CACHE_PRESSURE_STATE

    rd.reset_cache()
    assert rd._research_cache == {}
    assert "research" not in memory._CACHE_PRESSURE_STATE
