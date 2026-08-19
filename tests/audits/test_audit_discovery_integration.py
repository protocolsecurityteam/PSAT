"""End-to-end integration tests for the audit-discovery pipeline.

Exercises the real ``search_audit_reports`` orchestrator against stubbed
external dependencies — the multi-source fan-out, dedup, auto-hop, and
DB sync all run as they would in production. What's swapped:

    - Tavily API               → ``responses`` library (HTTP-level stub)
    - GitHub API + raw content → ``responses`` library (HTTP-level stub)
    - Solodit tRPC backend     → monkeypatch ``_solodit.search`` directly
      (Solodit's client decodes responses via a ``node`` subprocess which
      is painful to stub at the wire level; we stub the top-level function)
    - OpenRouter LLM           → monkeypatch ``utils.llm.chat`` with a
      content-aware router keyed on prompt shape

These tests are the source of truth for the discovery pipeline's behaviour.
The orchestrator-level tests that used to live in ``test_audit_reports.py``
(mock-heavy ``TestSearchAuditReports``, ``TestLLMValidateAndCluster``,
etc.) were deleted in favour of this file.

Gated by ``requires_postgres`` so it skips cleanly on a dev machine
without docker; CI brings Postgres up so the suite runs there.
"""

from __future__ import annotations

import json
import uuid
from typing import Callable

import pytest
import responses

from tests.conftest import requires_postgres

pytestmark = [requires_postgres]


# ---------------------------------------------------------------------------
# Shared plumbing: LLM router, Solodit stub, Tavily/GitHub HTTP stubs
# ---------------------------------------------------------------------------


class LLMRouter:
    """Test-side LLM client that dispatches on prompt content.

    Each stage of ``search_audit_reports`` sends a distinguishable prompt:

        - classification  : "You are analyzing web search results"
        - extraction      : "You are analyzing a webpage"
        - followup query  : "Generate a follow-up search query"
        - filename extract: "Below are file names"
        - validate+cluster: "You are reviewing"

    The router matches on those prefixes and returns canned JSON / text.
    If a prompt doesn't match any route, the router raises — an assertion
    that every LLM call we make in the pipeline has a deliberate stub.
    """

    def __init__(self):
        self._routes: list[tuple[str, Callable[[str], str]]] = []
        self.call_log: list[str] = []  # prompt bodies actually received

    def on_prompt_contains(self, marker: str, responder):
        """Register ``responder(prompt) -> str`` for any prompt containing *marker*."""
        self._routes.append((marker, responder))

    def __call__(self, messages, **kwargs):
        prompt = messages[0]["content"]
        self.call_log.append(prompt)
        for marker, responder in self._routes:
            if marker in prompt:
                return responder(prompt)
        raise AssertionError(f"No LLM stub matched prompt starting with:\n{prompt[:400]!r}")


@pytest.fixture()
def llm_router(monkeypatch):
    """Replace ``llm.chat`` at every import site.

    Every submodule does ``from utils import llm`` then calls ``llm.chat``
    — attribute lookup on the ``llm`` module object happens at call time,
    so patching ``utils.llm.chat`` propagates to all importers. The
    explicit per-module patches below guard against any future site that
    imports ``chat`` directly by name (``from utils.llm import chat``).
    """
    router = LLMRouter()
    monkeypatch.setattr("utils.llm.chat", router)
    monkeypatch.setattr("services.discovery.audit_reports_llm.llm.chat", router)
    monkeypatch.setattr("services.discovery.audit_reports._github.llm.chat", router)
    monkeypatch.setattr("services.discovery.audit_reports._dedup.llm.chat", router)
    return router


@pytest.fixture()
def solodit_stub(monkeypatch):
    """Replace ``services.discovery.solodit.search``.

    Solodit's wire format is devalue-encoded + node-decoded. Rather than
    faking both layers, we stub the top-level function: it's the only
    public entry point on that module and its output shape is simple.
    """
    from services.discovery import solodit

    results: list[dict] = []

    def fake_search(company, max_pages=40, debug=False):
        return list(results)

    monkeypatch.setattr(solodit, "search", fake_search)
    # audit_reports.py imports solodit as ``_solodit`` — patch there too.
    from services.discovery import audit_reports as ar

    monkeypatch.setattr(ar._solodit, "search", fake_search)
    return results  # tests append dicts to this list


@pytest.fixture()
def http_stubs(monkeypatch):
    """Activate ``responses`` around each test so no outbound HTTP escapes.

    Also forces ``TAVILY_API_KEY`` to a dummy value: ``services.clients.tavily.search``
    raises ``TavilyError`` when the env var is missing *before* any HTTP
    call is made, which would bypass our ``responses`` stubs entirely —
    the pipeline would see zero Tavily results and the tests would fail
    opaquely on CI machines that don't have a real key in their env.
    """
    monkeypatch.setenv("TAVILY_API_KEY", "test-tavily-stub-key")
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        yield rsps


# ---------------------------------------------------------------------------
# Reusable stub builders
# ---------------------------------------------------------------------------


def tavily_returns(http_stubs, results_by_query: dict[str, list[dict]]):
    """Install a Tavily POST stub that dispatches on query string."""

    def _match_and_respond(request):
        body = json.loads(request.body)
        query = body.get("query", "")
        hits = results_by_query.get(query)
        if hits is None:
            # No explicit mapping — return empty so the pipeline moves on.
            hits = []
        return (200, {}, json.dumps({"results": hits}))

    http_stubs.add_callback(
        responses.POST,
        "https://api.tavily.com/search",
        callback=_match_and_respond,
        content_type="application/json",
    )


def github_org_repos(http_stubs, owner: str, repos: list[str]):
    http_stubs.get(
        f"https://api.github.com/orgs/{owner}/repos",
        json=[{"name": r, "fork": False, "archived": False} for r in repos],
        status=200,
    )


def github_repo_meta(http_stubs, owner: str, repo: str, default_branch: str = "main"):
    http_stubs.get(
        f"https://api.github.com/repos/{owner}/{repo}",
        json={"name": repo, "default_branch": default_branch},
        status=200,
    )


def github_tree(http_stubs, owner: str, repo: str, branch: str, paths: list[dict]):
    """Stub the recursive-tree GitHub call.

    ``paths`` entries look like ``{"path": "audits", "type": "tree"}`` or
    ``{"path": "audits/foo.pdf", "type": "blob"}``.
    """
    http_stubs.get(
        f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}",
        json={"tree": paths, "truncated": False},
        status=200,
    )


def github_dir_contents(http_stubs, owner: str, repo: str, path: str, files: list[str], ref: str = "main"):
    """Stub the contents-API listing for a single directory."""
    items = [
        {
            "name": name,
            "type": "file",
            "download_url": f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}/{name}",
            "html_url": f"https://github.com/{owner}/{repo}/blob/{ref}/{path}/{name}",
        }
        for name in files
    ]
    http_stubs.get(
        f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
        json=items,
        status=200,
    )


def github_branch_sha(http_stubs, owner: str, repo: str, branch: str, sha: str):
    """Stub the branch-ref lookup that ``_resolve_branch_commit`` makes.

    Note the URL path is ``/git/refs/heads/`` (plural ``refs``) — not
    ``/git/ref/heads/`` as GitHub's docs sometimes render. Mismatch here
    silently yields ``source_commit=None`` on every tree-sourced entry.
    """
    http_stubs.get(
        f"https://api.github.com/repos/{owner}/{repo}/git/refs/heads/{branch}",
        json={"ref": f"refs/heads/{branch}", "object": {"sha": sha}},
        status=200,
    )


# ---------------------------------------------------------------------------
# Scenario 1: multi-source happy path
# ---------------------------------------------------------------------------


def test_multisource_discovery_merges_solodit_tavily_and_github(solodit_stub, http_stubs, llm_router):
    """All three sources produce entries; URL + filename dedup collapses the
    same-PDF mirrors; the final list carries merged provenance fields."""
    from services.discovery.audit_reports import search_audit_reports

    # --- Solodit seeds one canonical audit ---
    solodit_stub.append(
        {
            "url": "https://solodit.cyfrin.io/reviews/acme-halborn-2024",
            "pdf_url": "https://solodit.cyfrin.io/files/acme-halborn-2024.pdf",
            "auditor": "Halborn",
            "title": "Acme Protocol Audit",
            "date": "2024-06-01",
            "source_url": "https://solodit.cyfrin.io/",
            "confidence": 0.95,
        }
    )

    # --- Tavily returns a GitHub-hosted audits folder + an unrelated page ---
    tavily_returns(
        http_stubs,
        {
            '"Acme" smart contract security audit report': [
                {
                    "title": "Acme audits on GitHub",
                    "url": "https://github.com/acme-labs/acme-protocol/tree/main/audits",
                    "content": "Acme protocol audit reports",
                },
                {
                    "title": "Some unrelated page",
                    "url": "https://random.com/blog/defi-security",
                    "content": "generic security musings",
                },
            ],
            # The follow-up query never fires in this test — returning [] is fine.
        },
    )

    # --- GitHub API: the audits folder has two PDFs ---
    github_repo_meta(http_stubs, "acme-labs", "acme-protocol", default_branch="main")
    github_tree(
        http_stubs,
        "acme-labs",
        "acme-protocol",
        "main",
        [
            {"path": "audits", "type": "tree"},
        ],
    )
    github_dir_contents(
        http_stubs,
        "acme-labs",
        "acme-protocol",
        "audits",
        files=["2024-06-01-Halborn-Acme.pdf", "2024-09-15-Spearbit-Acme.pdf"],
        ref="main",
    )
    github_branch_sha(
        http_stubs,
        "acme-labs",
        "acme-protocol",
        "main",
        "a" * 40,
    )

    # --- LLM stubs ---
    llm_router.on_prompt_contains(
        "Generate a follow-up search query",
        lambda _: "",  # no follow-up — empty query skips the second Tavily call
    )
    llm_router.on_prompt_contains(
        "You are analyzing web search results",
        lambda _: json.dumps(
            [
                {
                    "url": "https://github.com/acme-labs/acme-protocol/tree/main/audits",
                    "is_audit": True,
                    "type": "listing",
                    "auditor": None,
                    "title": "Acme audits",
                    "date": None,
                    "confidence": 0.9,
                },
                {
                    "url": "https://random.com/blog/defi-security",
                    "is_audit": False,
                    "type": None,
                    "auditor": None,
                    "title": None,
                    "date": None,
                    "confidence": 0.1,
                },
            ]
        ),
    )
    llm_router.on_prompt_contains(
        "Below are file names",
        lambda prompt: json.dumps(
            [
                {
                    "filename": "2024-06-01-Halborn-Acme.pdf",
                    "auditor": "Halborn",
                    "title": "Acme Protocol Audit",
                    "date": "2024-06-01",
                },
                {
                    "filename": "2024-09-15-Spearbit-Acme.pdf",
                    "auditor": "Spearbit",
                    "title": "Acme Periphery Audit",
                    "date": "2024-09-15",
                },
            ]
        ),
    )
    llm_router.on_prompt_contains(
        "You are reviewing",  # validate+cluster
        # Keep all 3 entries, no clustering — easier to assert on.
        lambda prompt: json.dumps(
            {
                "entries": [
                    {"i": 0, "valid": True, "cluster": 1},
                    {"i": 1, "valid": True, "cluster": 2},
                    {"i": 2, "valid": True, "cluster": 3},
                ]
            }
        ),
    )

    result = search_audit_reports("Acme", official_domain="acme.xyz")

    # Three distinct audits: Solodit Halborn (Jun 2024) + two GitHub-sourced.
    # Halborn might collapse against Solodit via filename or survive as two
    # entries — we assert on the *content* rather than exact count.
    urls = [r["url"] for r in result["reports"]]
    auditors = [r.get("auditor") for r in result["reports"]]

    assert any("solodit" in u.lower() or "acme-protocol" in u for u in urls)
    assert "Halborn" in auditors
    assert "Spearbit" in auditors
    # The random.com entry was classified not-audit → must not appear.
    assert not any("random.com" in u for u in urls)

    # GitHub-sourced audits carry provenance fields.
    github_entry = next(r for r in result["reports"] if "acme-protocol" in r["url"])
    assert github_entry.get("source_repo") == "acme-labs/acme-protocol"
    assert github_entry.get("source_commit") == "a" * 40


# ---------------------------------------------------------------------------
# Scenario 2: Solodit down → Tavily path still produces output
# ---------------------------------------------------------------------------


def test_solodit_down_does_not_block_pipeline(solodit_stub, http_stubs, llm_router):
    """A Solodit outage leaves the list empty; Tavily + LLM classify + GitHub
    fan-out still deliver reports."""
    from services.discovery.audit_reports import search_audit_reports

    # solodit_stub stays empty.
    tavily_returns(
        http_stubs,
        {
            '"Beta" smart contract security audit report': [
                {
                    "title": "Beta Protocol Audit Report (Trail of Bits)",
                    "url": "https://beta.xyz/audits/tob-2024.pdf",
                    "content": "Beta protocol audit",
                },
            ],
        },
    )

    # PDF URLs short-circuit into _build_fallback_entry without needing
    # extraction / GitHub calls, so only the classifier runs.
    llm_router.on_prompt_contains(
        "Generate a follow-up search query",
        lambda _: "",
    )
    llm_router.on_prompt_contains(
        "You are analyzing web search results",
        lambda _: json.dumps(
            [
                {
                    "url": "https://beta.xyz/audits/tob-2024.pdf",
                    "is_audit": True,
                    "type": "pdf",
                    "auditor": "Trail of Bits",
                    "title": "Beta Protocol Audit Report",
                    "date": "2024-03-01",
                    "confidence": 0.9,
                },
            ]
        ),
    )
    llm_router.on_prompt_contains(
        "You are reviewing",
        lambda _: json.dumps({"entries": [{"i": 0, "valid": True, "cluster": 1}]}),
    )

    result = search_audit_reports("Beta", official_domain="beta.xyz")

    assert len(result["reports"]) == 1
    assert result["reports"][0]["auditor"] == "Trail of Bits"
    assert "pdf" in result["reports"][0]["url"]


# ---------------------------------------------------------------------------
# Scenario 3: Classification confidence threshold filters noise
# ---------------------------------------------------------------------------


def test_low_confidence_classifier_output_is_filtered(solodit_stub, http_stubs, llm_router):
    """Stage-1 classifier output below 0.5 confidence never makes it to
    Stage 2, so it can't produce a report entry."""
    from services.discovery.audit_reports import search_audit_reports

    tavily_returns(
        http_stubs,
        {
            '"Gamma" smart contract security audit report': [
                {
                    "title": "Questionable page",
                    "url": "https://spam.com/maybe.pdf",
                    "content": "vaguely mentions audit",
                },
            ],
        },
    )

    llm_router.on_prompt_contains("Generate a follow-up search query", lambda _: "")
    llm_router.on_prompt_contains(
        "You are analyzing web search results",
        lambda _: json.dumps(
            [
                {
                    "url": "https://spam.com/maybe.pdf",
                    "is_audit": True,
                    "type": "pdf",
                    "auditor": None,
                    "title": "Maybe audit",
                    "date": None,
                    "confidence": 0.2,  # below threshold
                },
            ]
        ),
    )
    # No validate call fires — zero reports to validate.
    llm_router.on_prompt_contains(
        "You are reviewing",
        lambda _: json.dumps({"entries": []}),
    )

    result = search_audit_reports("Gamma", official_domain="gamma.xyz")
    assert result["reports"] == []


# ---------------------------------------------------------------------------
# Scenario 4: malformed LLM classification → graceful empty
# ---------------------------------------------------------------------------


def test_malformed_classification_response_returns_empty(solodit_stub, http_stubs, llm_router):
    """The LLM hands back unparseable text; classifier returns ``[]``
    rather than crashing the pipeline."""
    from services.discovery.audit_reports import search_audit_reports

    tavily_returns(
        http_stubs,
        {
            '"Delta" smart contract security audit report': [
                {"title": "Some page", "url": "https://x.com/audit.pdf", "content": "audit stuff"},
            ],
        },
    )

    llm_router.on_prompt_contains("Generate a follow-up search query", lambda _: "")
    llm_router.on_prompt_contains(
        "You are analyzing web search results",
        lambda _: "this is not json at all, the LLM had a bad day",
    )
    llm_router.on_prompt_contains(
        "You are reviewing",
        lambda _: json.dumps({"entries": []}),
    )

    result = search_audit_reports("Delta", official_domain="delta.xyz")
    assert result["reports"] == []


# ---------------------------------------------------------------------------
# Scenario 5: DB sync — search results land in audit_reports with provenance
# ---------------------------------------------------------------------------


def test_search_results_sync_to_audit_reports_table(db_session, solodit_stub, http_stubs, llm_router):
    """End-to-end: discovery → ``_sync_audit_reports_to_db`` → a real row
    with protocol_id, url, auditor, title, date, confidence, source_repo."""
    from db.models import AuditReport, Protocol
    from services.discovery.audit_reports import search_audit_reports
    from workers.discovery import _sync_audit_reports_to_db

    # Seed a protocol to attach audits to.
    name = f"sync-test-{uuid.uuid4().hex[:8]}"
    protocol = Protocol(name=name)
    db_session.add(protocol)
    db_session.commit()
    protocol_id = protocol.id

    solodit_stub.append(
        {
            "url": "https://solodit.cyfrin.io/reviews/epsilon-openzeppelin-2024",
            "pdf_url": "https://oz.com/epsilon-2024.pdf",
            "auditor": "OpenZeppelin",
            "title": "Epsilon Security Review",
            "date": "2024-05-15",
            "source_url": "https://solodit.cyfrin.io/",
            "confidence": 0.95,
        }
    )
    tavily_returns(
        http_stubs,
        {
            '"Epsilon" smart contract security audit report': [],
        },
    )

    llm_router.on_prompt_contains("Generate a follow-up search query", lambda _: "")
    # No Tavily results → classifier short-circuits before LLM call;
    # the single Solodit entry flows straight into the validate step.
    llm_router.on_prompt_contains(
        "You are reviewing",
        lambda _: json.dumps({"entries": [{"i": 0, "valid": True, "cluster": 1}]}),
    )

    result = search_audit_reports("Epsilon", official_domain="epsilon.xyz")
    assert len(result["reports"]) == 1

    _sync_audit_reports_to_db(db_session, protocol_id, result["reports"])

    row = db_session.query(AuditReport).filter_by(protocol_id=protocol_id).one_or_none()
    assert row is not None
    assert row.auditor == "OpenZeppelin"
    assert row.title == "Epsilon Security Review"
    assert row.date == "2024-05-15"
    assert row.url.startswith("https://solodit.cyfrin.io/")
    # Solodit-sourced entries don't carry a GitHub source_repo.
    assert row.source_repo is None


# ---------------------------------------------------------------------------
# Scenario 6: sync is idempotent — same URL upserts, no duplicates
# ---------------------------------------------------------------------------


def test_sync_upserts_on_duplicate_url(db_session):
    """Rerunning ``_sync_audit_reports_to_db`` with the same URL updates the
    existing row (new title / confidence) instead of inserting a dup."""
    from db.models import AuditReport, Protocol
    from workers.discovery import _sync_audit_reports_to_db

    name = f"upsert-test-{uuid.uuid4().hex[:8]}"
    protocol = Protocol(name=name)
    db_session.add(protocol)
    db_session.commit()
    protocol_id = protocol.id

    r1 = [
        {
            "url": "https://ex.com/audit.pdf",
            "pdf_url": "https://ex.com/audit.pdf",
            "auditor": "Spearbit",
            "title": "Initial title",
            "date": "2024-01-01",
            "confidence": 0.7,
            "source_url": "https://ex.com/",
        }
    ]
    _sync_audit_reports_to_db(db_session, protocol_id, r1)

    r2 = [
        {
            "url": "https://ex.com/audit.pdf",  # same URL
            "pdf_url": "https://ex.com/audit.pdf",
            "auditor": "Spearbit",
            "title": "Updated title",  # richer metadata
            "date": "2024-01-01",
            "confidence": 0.95,
            "source_url": "https://ex.com/",
            "source_repo": "spearbit/portfolio",
            "reviewed_commits": ["abc123def456"],
            "referenced_repos": ["owner/protocol"],
            "classified_commits": [{"sha": "abc123def456", "label": "reviewed", "provenance": "ai_returned"}],
        }
    ]
    _sync_audit_reports_to_db(db_session, protocol_id, r2)

    rows = db_session.query(AuditReport).filter_by(protocol_id=protocol_id).all()
    assert len(rows) == 1
    assert rows[0].title == "Updated title"
    assert float(rows[0].confidence) == 0.95
    assert rows[0].source_repo == "spearbit/portfolio"
    assert rows[0].reviewed_commits == ["abc123def456"]
    assert rows[0].referenced_repos == ["owner/protocol"]
    assert rows[0].classified_commits == [{"sha": "abc123def456", "label": "reviewed", "provenance": "ai_returned"}]

    r3 = [
        {
            "url": "https://ex.com/audit.pdf",  # same URL, poorer rediscovery result
            "pdf_url": "https://ex.com/audit.pdf",
            "auditor": "Spearbit",
            "title": "Rediscovered title",
            "date": "2024-01-01",
            "confidence": 0.9,
            "source_url": "https://ex.com/rediscovered",
        }
    ]
    _sync_audit_reports_to_db(db_session, protocol_id, r3)

    rows = db_session.query(AuditReport).filter_by(protocol_id=protocol_id).all()
    assert len(rows) == 1
    assert rows[0].title == "Rediscovered title"
    assert rows[0].source_repo == "spearbit/portfolio"
    assert rows[0].reviewed_commits == ["abc123def456"]
    assert rows[0].referenced_repos == ["owner/protocol"]
    assert rows[0].classified_commits == [{"sha": "abc123def456", "label": "reviewed", "provenance": "ai_returned"}]


def test_sync_accepts_audit_date_ranges(db_session):
    """Audit discovery can return human date ranges, not just ISO dates."""
    from db.models import AuditReport, Protocol
    from workers.discovery import _sync_audit_reports_to_db

    protocol = Protocol(name=f"date-range-test-{uuid.uuid4().hex[:8]}")
    db_session.add(protocol)
    db_session.commit()

    date_range = "2023-04-28 to 2023-05-05"
    _sync_audit_reports_to_db(
        db_session,
        protocol.id,
        [
            {
                "url": "https://github.com/0xVolodya/audits/blob/main/reports/eigenlayer.md",
                "auditor": "0xVolodya, Independent Security Researcher",
                "title": "[dep: EigenLayer] EigenLayer Audit Report",
                "date": date_range,
                "confidence": 1.0,
                "source_repo": "Layr-Labs/eigenlayer-contracts",
                "reviewed_commits": ["7a23e259050fe88a179ab0345cc8cfc9b5e57221"],
                "referenced_repos": ["Layr-Labs/eigenlayer-contracts"],
            }
        ],
    )

    row = db_session.query(AuditReport).filter_by(protocol_id=protocol.id).one()
    assert row.date == date_range


# ---------------------------------------------------------------------------
# Scenario 7: sync drops entries missing required fields
# ---------------------------------------------------------------------------


def test_stage3_linked_url_triggers_org_auto_hop(solodit_stub, http_stubs, llm_router):
    """Three-hop GitHub-org auto-hop: Tavily → Stage 2 page → Stage 3
    follow → linked URL pointing at the protocol's own GitHub org. Stage 3
    must auto-hop on the URLs FOUND IN PAGES IT FETCHES, not just the
    URLs it was handed via discovered_links.

    Real-world chain (etherfi case): Halborn case-study (classified by
    Tavily) → ether.fi homepage (extracted as linked_url, becomes Stage 3
    target) → github.com/etherfi-protocol/smart-contracts/tree/master/
    audits (extracted from the ether.fi page). Pre-fix: Stage 3 only
    acted on the URL handed to it (the ether.fi homepage); the github
    URL extracted FROM ether.fi was silently dropped, the org never
    enumerated, and the entire audits/ directory was missed.

    Assert: the org's audits/ folder is enumerated, even though no Tavily
    result and no Stage-2-extracted link points directly at the github
    org — it's only reachable via a 3-hop chain.
    """
    from services.discovery.audit_reports import search_audit_reports

    # No Solodit hit.

    # Tavily returns a single non-github page (the auditor case study).
    tavily_returns(
        http_stubs,
        {
            '"Acme" smart contract security audit report': [
                {
                    "title": "Halborn — Acme case study",
                    "url": "https://halborn.com/case-studies/acme",
                    "content": "Halborn's work on Acme protocol",
                },
            ],
        },
    )

    # Stage 2 fetches the case study; the LLM extracts 0 reports + 1
    # linked URL pointing at the protocol's homepage.
    http_stubs.get(
        "https://halborn.com/case-studies/acme",
        body=(
            '<html><body><h1>Acme Case Study</h1><p>See <a href="https://acme.xyz">Acme protocol</a>.</p></body></html>'
        ),
        status=200,
        content_type="text/html",
    )
    # Stage 3 follows the homepage link; the homepage page in turn links
    # to the github audits dir. Pre-fix this URL is silently dropped.
    http_stubs.get(
        "https://acme.xyz",
        body=(
            "<html><body>"
            "<p>Audit reports live in our GitHub: "
            '<a href="https://github.com/acme-labs/acme-protocol/tree/main/audits">audits/</a>'
            "</p>"
            "</body></html>"
        ),
        status=200,
        content_type="text/html",
    )

    # GitHub stubs for the org enumeration that auto-hop should trigger.
    github_org_repos(http_stubs, "acme-labs", ["acme-protocol", "frontend"])
    # ``frontend`` has no audits/; ``acme-protocol`` does.
    github_repo_meta(http_stubs, "acme-labs", "acme-protocol", default_branch="main")
    github_tree(
        http_stubs,
        "acme-labs",
        "acme-protocol",
        "main",
        [{"path": "audits", "type": "tree"}],
    )
    github_dir_contents(
        http_stubs,
        "acme-labs",
        "acme-protocol",
        "audits",
        files=["2024-06-01-Halborn-Acme.pdf", "2024-09-15-Spearbit-Acme.pdf"],
        ref="main",
    )
    github_branch_sha(http_stubs, "acme-labs", "acme-protocol", "main", "b" * 40)
    # ``frontend`` repo: no audits/.
    github_repo_meta(http_stubs, "acme-labs", "frontend", default_branch="main")
    github_tree(http_stubs, "acme-labs", "frontend", "main", [])

    # LLM stubs.
    llm_router.on_prompt_contains(
        "Generate a follow-up search query",
        lambda _: "",  # skip the second Tavily call
    )
    llm_router.on_prompt_contains(
        "You are analyzing web search results",
        lambda _: json.dumps(
            [
                {
                    "url": "https://halborn.com/case-studies/acme",
                    "is_audit": True,
                    "type": "listing",
                    "auditor": "Halborn",
                    "title": "Acme case study",
                    "date": None,
                    "confidence": 0.85,
                }
            ]
        ),
    )

    # Page-level extraction stub: dispatches per-URL on prompt content
    # (page_text is in the prompt). Halborn page yields the homepage
    # link (Stage 3 input); homepage page yields the github audits link
    # (currently dropped → the bug).
    def _extract(prompt: str) -> str:
        if "Acme Case Study" in prompt:
            return json.dumps({"reports": [], "linked_urls": ["https://acme.xyz"]})
        if "Audit reports live in our GitHub" in prompt:
            return json.dumps(
                {
                    "reports": [],
                    "linked_urls": ["https://github.com/acme-labs/acme-protocol/tree/main/audits"],
                }
            )
        return json.dumps({"reports": [], "linked_urls": []})

    llm_router.on_prompt_contains("Identify third-party security audits", _extract)
    llm_router.on_prompt_contains(
        "Below are file names",
        lambda _: json.dumps(
            [
                {
                    "filename": "2024-06-01-Halborn-Acme.pdf",
                    "auditor": "Halborn",
                    "title": "Acme Protocol Audit",
                    "date": "2024-06-01",
                },
                {
                    "filename": "2024-09-15-Spearbit-Acme.pdf",
                    "auditor": "Spearbit",
                    "title": "Acme Periphery Audit",
                    "date": "2024-09-15",
                },
            ]
        ),
    )
    llm_router.on_prompt_contains(
        "You are reviewing",
        lambda _: json.dumps(
            {
                "entries": [
                    {"i": 0, "valid": True, "cluster": 1},
                    {"i": 1, "valid": True, "cluster": 2},
                ]
            }
        ),
    )

    result = search_audit_reports("Acme", official_domain="acme.xyz")

    auditors = [r.get("auditor") for r in result["reports"]]
    # Both PDFs from the org's audits/ directory must show up. Pre-fix,
    # auditors == [] (or only the docs page itself as a fallback) because
    # the org auto-hop never fired.
    assert "Halborn" in auditors, f"Two-hop auto-hop did not enumerate the org. Reports: {result['reports']!r}"
    assert "Spearbit" in auditors
    # Provenance carried through.
    halborn = next(r for r in result["reports"] if r.get("auditor") == "Halborn")
    assert halborn.get("source_repo") == "acme-labs/acme-protocol"


def _sync_capturing_degraded(session, protocol_id: int, reports: list[dict]) -> list:
    """Run the sync with a degraded-error accumulator bound, as a worker does."""
    from utils.logging import bind_trace_context, degraded_errors_var
    from workers.discovery import _sync_audit_reports_to_db

    accumulator: list = []
    token = degraded_errors_var.set(accumulator)
    try:
        with bind_trace_context(trace_id="t", job_id="j", stage="discovery", worker_id="DiscoveryWorker-1"):
            _sync_audit_reports_to_db(session, protocol_id, reports)
    finally:
        degraded_errors_var.reset(token)
    return accumulator


def test_sync_reports_entries_missing_required_fields(db_session):
    """Entries without url / auditor / title produce no row — and say so.
    A silent drop makes the artifact's entry count and the table's row count
    disagree with nothing to explain the gap."""
    from db.models import AuditReport, Protocol

    name = f"drop-test-{uuid.uuid4().hex[:8]}"
    protocol = Protocol(name=name)
    db_session.add(protocol)
    db_session.commit()
    protocol_id = protocol.id

    reports = [
        {"url": "", "auditor": "Foo", "title": "No URL"},
        {"url": "https://ok.com/a.pdf", "auditor": "", "title": "No auditor"},
        {"url": "https://ok.com/b.pdf", "auditor": "Foo", "title": ""},
        {"url": "https://ok.com/c.pdf", "auditor": "Foo", "title": "Kept"},
    ]
    degraded = _sync_capturing_degraded(db_session, protocol_id, reports)

    rows = db_session.query(AuditReport).filter_by(protocol_id=protocol_id).all()
    assert len(rows) == 1
    assert rows[0].title == "Kept"

    assert len(degraded) == 1
    assert degraded[0].phase == "audit_report_sync"
    assert degraded[0].message == "3 of 4 audit entries produced no row"
    assert degraded[0].context["entries"] == 4
    assert degraded[0].context["distinct_urls_upserted"] == 1
    assert [e["missing"] for e in degraded[0].context["incomplete"]] == ["url", "auditor", "title"]
    assert degraded[0].context["collisions"] == []


def test_sync_reports_url_collisions_within_one_batch(db_session):
    """Two entries claiming one URL collapse to one row (the table is keyed on
    ``(protocol_id, url)``); the overwritten entry is named, not lost."""
    from db.models import AuditReport, Protocol

    protocol = Protocol(name=f"collision-test-{uuid.uuid4().hex[:8]}")
    db_session.add(protocol)
    db_session.commit()

    shared = "https://raw.githubusercontent.com/acme/contracts/master/audits/2023.05.16%20-%20Omniscia.pdf"
    reports = [
        {"url": shared, "auditor": "Omniscia", "title": "Omniscia Audit"},
        {"url": shared, "auditor": "Nethermind", "title": "Restaking Of stETH Holdings"},
    ]
    degraded = _sync_capturing_degraded(db_session, protocol.id, reports)

    rows = db_session.query(AuditReport).filter_by(protocol_id=protocol.id).all()
    assert len(rows) == 1
    assert rows[0].auditor == "Nethermind"  # last write wins, unchanged

    assert len(degraded) == 1
    assert degraded[0].message == "1 of 2 audit entries produced no row"
    assert degraded[0].context["collisions"] == [
        {"url": shared, "overwritten_title": "Omniscia Audit", "kept_title": "Restaking Of stETH Holdings"}
    ]


def test_sync_of_a_clean_batch_records_nothing(db_session):
    """Control: every entry persisting must not report a loss."""
    from db.models import AuditReport, Protocol

    protocol = Protocol(name=f"clean-test-{uuid.uuid4().hex[:8]}")
    db_session.add(protocol)
    db_session.commit()

    reports = [
        {"url": "https://ok.com/a.pdf", "auditor": "Omniscia", "title": "Omniscia Audit"},
        {"url": "https://ok.com/b.md", "auditor": "Nethermind", "title": "Restaking Of stETH Holdings"},
    ]
    degraded = _sync_capturing_degraded(db_session, protocol.id, reports)

    assert degraded == []
    assert db_session.query(AuditReport).filter_by(protocol_id=protocol.id).count() == 2
