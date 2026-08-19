"""Unit tests for services.discovery.audit_enrichment.

Split out of ``tests/discovery/test_run_discovery_orchestrator.py``: every test
here drives ``audit_enrichment`` — PDF/commit extraction from a report page and
the corroboration rules that decide when a repo-hosted PDF may be adopted as a
report's document. The orchestrator half never imports this module.
"""

from __future__ import annotations

import pytest

from services.discovery import audit_enrichment as ae

# offline: discovery validates/resolves contract chains via Alchemy (chain_resolver)
# and probes bytecode via eth_getCode — stub both so the pipeline runs without a wire.
pytestmark = pytest.mark.usefixtures("_stub_chain_resolver", "_stub_rpc_bytecode")


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
