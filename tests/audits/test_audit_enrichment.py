
from __future__ import annotations

import pytest

from services.discovery import audit_enrichment as ae

# Offline: stub the chain resolver and eth_getCode.
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


# The etherfi-protocol/smart-contracts audits/ listing in tree order; the first entry is what a positional pick lands
# on.
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


_TWIN = dict(
    _ETHERFI_AUDIT_FOLDER[2],
    pdf_url=_ETHERFI_AUDIT_FOLDER[2]["pdf_url"].replace(".pdf", "-v2.pdf"),
    source_path=_ETHERFI_AUDIT_FOLDER[2]["source_path"].replace(".pdf", "-v2.pdf"),
)

_BEHYPE_CERTORA = {
    "title": "Certora EtherFi BeHype Audit",
    "auditor": "Certora",
    "pdf_url": "https://raw.githubusercontent.com/etherfi-protocol/beHYPE/"
    "master/audit/Certora%20EtherFi%20BeHype%20Audit.pdf",
    "source_repo": "etherfi-protocol/beHYPE",
    "source_path": "audit/Certora EtherFi BeHype Audit.pdf",
}

_HALBORN_L2_REPORT = {
    "url": "https://halborn.example/reports/etherfi-l2-governance-token",
    "auditor": "Halborn",
    "title": "EtherFi L2 Governance Token Smart Contract Security Assessment Report",
    "source_repo": "etherfi-protocol/smart-contracts",
}


# Each folder holds a tempting PDF that must not be adopted.
@pytest.mark.parametrize(
    ("listing", "report", "protocol"),
    [
        pytest.param(
            _ETHERFI_AUDIT_FOLDER,
            {
                "url": _NM_MD_URL,
                "auditor": "Nethermind",
                "title": "EtherFi Restaking Of stETH Holdings",
                "source_repo": "etherfi-protocol/smart-contracts",
            },
            "etherfi",
            id="markdown_report_no_candidate_corroborates",
        ),
        pytest.param(
            [
                {
                    "title": "EtherFi L2 Governance Token Smart Contract Security Assessment Report",
                    "auditor": "Certora",
                    "pdf_url": "https://raw.githubusercontent.com/etherfi-protocol/smart-contracts/"
                    "master/audits/2024.06.25%20-%20Certora%20-%20EtherFi_L2_Governance_Token.pdf",
                    "source_repo": "etherfi-protocol/smart-contracts",
                    "source_path": "audits/2024.06.25 - Certora - EtherFi_L2_Governance_Token.pdf",
                }
            ],
            _HALBORN_L2_REPORT,
            "etherfi",
            id="pdf_naming_a_different_auditor",
        ),
        pytest.param(
            [*_ETHERFI_AUDIT_FOLDER, _TWIN],
            _HALBORN_L2_REPORT,
            "etherfi",
            id="two_candidates_corroborate_equally",
        ),
        pytest.param(
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
            {
                "url": "https://raw.githubusercontent.com/etherfi-protocol/weETH-cross-chain/"
                "master/audit/20241109-scroll-native-minting.md",
                "auditor": "Unknown",
                "title": "Scroll Native Minting",
                "source_repo": "etherfi-protocol/weETH-cross-chain",
            },
            "etherfi",
            id="protocol_name_alone",
        ),
        pytest.param(
            [_BEHYPE_CERTORA],
            {
                "url": "https://raw.githubusercontent.com/etherfi-protocol/beHYPE/master/audit/behype.md",
                "auditor": "Unknown",
                "title": "EtherFi Draft Audit",
                "source_repo": "etherfi-protocol/beHYPE",
            },
            "etherfi",
            id="title_only_the_protocol_name",
        ),
        pytest.param(
            _ETHERFI_AUDIT_FOLDER,
            {
                "url": _NM_MD_URL,
                "auditor": "Nethermind",
                "title": "Nethermind Audit",
                "source_repo": "etherfi-protocol/smart-contracts",
            },
            "etherfi",
            id="title_only_the_reports_own_auditor",
        ),
        pytest.param(
            [_BEHYPE_CERTORA],
            {
                "url": "https://auditor.example.com/view/etherfi",
                "auditor": "Unknown",
                "source_repo": "etherfi-protocol/beHYPE",
                "dependency_component": "EtherFi",
            },
            "etherfi",
            id="component_only_the_protocol_name",
        ),
        pytest.param(
            [_BEHYPE_CERTORA],
            {
                "url": "https://raw.githubusercontent.com/etherfi-protocol/beHYPE/master/audit/behype.md",
                "auditor": "Unknown",
                "title": "EtherFi Audit",
                "source_repo": "etherfi-protocol/beHYPE",
            },
            "ether.fi",
            id="run_together_spelling_of_the_protocol",
        ),
        pytest.param(
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
            {
                "url": "https://raw.githubusercontent.com/Zellic/publications/master/etherfi.md",
                "auditor": "Unknown",
                "title": "Audit Report",
                "source_repo": "Zellic/publications",
            },
            "etherfi",
            id="title_only_generic_audit_vocabulary",
        ),
        pytest.param(
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
            {
                "url": "https://raw.githubusercontent.com/etherfi-protocol/smart-contracts/master/audits/x.md",
                "auditor": "Certora",
                "title": "Audit v3",
                "source_repo": "etherfi-protocol/smart-contracts",
            },
            "etherfi",
            id="title_too_short_to_identify_a_document",
        ),
    ],
)
def test_enrich_does_not_adopt_a_pdf(monkeypatch, listing, report, protocol):
    _stub_repo_folder(monkeypatch, listing)
    original = dict(report)
    result = {"reports": [report]}
    ae.enrich_audit_reports(result, protocol)

    out = result["reports"][0]
    assert out.get("pdf_url") is None
    assert {k: out.get(k) for k in ("url", "auditor", "title")} == {
        k: original.get(k) for k in ("url", "auditor", "title")
    }


def test_enrich_adopts_repo_pdf_corroborated_by_title(monkeypatch):
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


def test_enrich_adopts_when_the_title_keeps_a_token_beyond_the_two_names(monkeypatch):
    """A real corpus title that leads with the protocol's name but keeps 'deposit adapter'."""
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
