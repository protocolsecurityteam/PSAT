"""Unit tests for ``services.audits.scope_extraction``.

No Postgres, no minio, no LLM — every function is tested in isolation.
The LLM stub env (``PSAT_LLM_STUB_DIR``) is cleared per test so we can
drive ``_call_llm`` through different code paths deterministically.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from services.audits.scope_extraction import (
    LLMUnavailableError,
    ScopeSection,
    _build_prompt,
    _call_llm,
    _split_text_into_chunks,
    extract_contracts_regex_fallback,
    extract_date_from_pdf_text,
    extract_scope_via_chunk_scan,
    extract_scope_with_llm,
    locate_scope_section,
    validate_contracts,
)

# ---------------------------------------------------------------------------
# Helpers — build page-annotated fixture text matching extract_text_from_pdf
# ---------------------------------------------------------------------------


def _page(n: int, body: str) -> str:
    return f"\f\n--- page {n} ---\n\f\n{body}"


def _doc(*pages: str) -> str:
    return "".join(pages).strip()


@pytest.fixture(autouse=True)
def _clear_stub_env(monkeypatch):
    monkeypatch.delenv("PSAT_LLM_STUB_DIR", raising=False)
    monkeypatch.delenv("PSAT_SCOPE_LLM_MODEL", raising=False)


# ---------------------------------------------------------------------------
# locate_scope_section
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pages", "contains"),
    [
        pytest.param(
            (
                "Audit Report for Example Protocol\nExecutive Summary text.",
                "Scope\nThe following contracts were reviewed: Pool.sol, Vault.sol",
                "Findings\nNone critical.",
            ),
            ("Pool.sol",),
            id="basic-header",
        ),
        # "Smart Contracts in Scope" appears before "Scope"; both resolve to the
        # same region via the overlap-merge.
        pytest.param(
            (
                "Introduction",
                "Smart Contracts in Scope\nPool.sol\nVault.sol\nStrategy.sol",
                "End of scope",
            ),
            ("Pool.sol",),
            id="longer-phrase",
        ),
        pytest.param(("Intro", "FILES IN SCOPE\nPool.sol"), ("Pool.sol",), id="case-insensitive"),
        pytest.param(
            ("Intro", "Scope\nsome prose", "Files in scope\nPool.sol", "More prose"),
            ("Pool.sol",),
            id="merges-overlapping-slices",
        ),
        # Halborn: "5. SCOPE" -- numbered section prefix the first regex rejected.
        pytest.param(
            ("Cover", "5. SCOPE\nFILES AND REPOSITORY\n(c) Items in scope:\nsrc/Token.sol"),
            ("Token.sol",),
            id="numbered-header",
        ),
        pytest.param(
            ("Intro", "5.1 Files in scope\nPool.sol\nVault.sol"),
            ("Pool.sol",),
            id="decimal-numbered-header",
        ),
        pytest.param(
            (
                "Cover",
                "Project Scope\nProject Name\nether.fi",
                "The following contract list is included in the scope of this audit:\n- src/Pool.sol",
            ),
            ("Pool.sol",),
            id="project-scope-header",
        ),
        # Nethermind: "2 Audited Files" -- heading style of audits with file-count tables.
        pytest.param(
            ("Cover", "2 Audited Files\nContract LoC Comments\n1 src/Pool.sol 420"),
            ("Pool.sol",),
            id="audited-files-header",
        ),
        # pypdf emits "Project  Scope" (two spaces) for Certora-style PDFs; a rigid
        # single-space match would miss the header.
        pytest.param(
            ("Intro", "Project  Scope  \nProject  Name: ether.fi\nPool.sol"),
            ("Pool.sol",),
            id="double-spaces-between-words",
        ),
    ],
)
def test_locate_scope_section_finds_header_variants(pages, contains):
    text = _doc(*(_page(i, body) for i, body in enumerate(pages, start=1)))
    sections = locate_scope_section(text)
    assert len(sections) == 1
    assert sections[0].start_page == 2
    for needle in contains:
        assert needle in sections[0].text_slice


def test_locate_scope_section_returns_empty_when_no_header():
    text = _doc(
        _page(1, "Executive Summary"),
        _page(2, "We reviewed several contracts."),
        _page(3, "Conclusion"),
    )
    assert locate_scope_section(text) == []


def test_locate_scope_section_captures_three_pages_of_context():
    text = _doc(
        _page(1, "Cover"),
        _page(2, "Scope\n\nPool.sol 420 nSLOC"),
        _page(3, "Vault.sol 310 nSLOC"),
        _page(4, "Strategy.sol 180 nSLOC\nEnd of table"),
        _page(5, "Findings"),
    )
    sections = locate_scope_section(text)
    assert len(sections) == 1
    assert "Pool.sol" in sections[0].text_slice
    assert "Strategy.sol" in sections[0].text_slice
    assert "Findings" not in sections[0].text_slice


def test_merged_section_preserves_text_from_later_match():
    # Regression test for the bug that lost SettlementDispatcher at
    # idx 4 (Certora Combined Audit): the merge kept only the first
    # candidate's text_slice, dropping later content from the merged
    # range. Now the merged slice must cover everything.
    text = _doc(
        _page(1, "Cover"),
        _page(2, "Project Scope\nSubProject A"),
        _page(3, "Files in scope:\n- SubAContract.sol"),
        _page(
            4,
            "Additional scope for SubProject B\nThe following contracts are in scope:\n- SubBContract.sol",
        ),
        _page(5, "Findings"),
    )
    sections = locate_scope_section(text)
    assert len(sections) == 1
    # Both contract names must be in the final text slice; the old
    # implementation lost SubBContract.sol because the merge kept only
    # the slice from the first match.
    assert "SubAContract.sol" in sections[0].text_slice
    assert "SubBContract.sol" in sections[0].text_slice


def test_locate_scope_section_survives_no_page_markers():
    text = "Scope\nPool.sol reviewed.\nMore content."
    sections = locate_scope_section(text)
    assert len(sections) == 1
    assert sections[0].start_page == 1


# ---------------------------------------------------------------------------
# Ligature normalization
# ---------------------------------------------------------------------------


def test_locate_scope_section_normalizes_ligatures_in_headers():
    # A scope-section header containing "scope" is unaffected, but a
    # filename like "EthﬁL2Token.sol" has to survive through to the
    # caller as "EthfiL2Token.sol" so validation passes.
    text = _doc(
        _page(1, "Cover"),
        _page(2, "Scope\nItems in scope: src/EthﬁL2Token.sol"),
    )
    sections = locate_scope_section(text)
    assert len(sections) == 1
    assert "EthfiL2Token.sol" in sections[0].text_slice


# ---------------------------------------------------------------------------
# validate_contracts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("names", "raw", "expected"),
    [
        pytest.param(
            ["Pool", "Vault", "FakeContract"],
            "We audited Pool and Vault. Findings inside.",
            ["Pool", "Vault"],
            id="drops-hallucinated",
        ),
        pytest.param(["POOL", "vault"], "Pool and Vault contracts.", ["POOL", "vault"], id="case-insensitive"),
        pytest.param([], "anything", [], id="empty-input"),
        pytest.param(["", "Pool", "  "], "Pool", ["Pool"], id="drops-empty-strings"),
    ],
)
def test_validate_contracts(names, raw, expected):
    assert validate_contracts(names, raw) == expected


def test_validate_contracts_preserves_interfaces_with_matching_impls():
    # The earlier interface-collapse heuristic was rolled back — Certora
    # audits explicitly list src/interfaces/IFoo.sol as first-class scope,
    # so a blanket "drop IFoo if Foo present" over-corrected. Instead the
    # LLM's per-audit judgment decides. Pin the current behaviour: both
    # variants survive validation as long as they appear in raw_text.
    names = ["StakingManager", "IStakingManager", "LiquidityPool", "ILiquidityPool"]
    raw = "StakingManager IStakingManager LiquidityPool ILiquidityPool"
    assert validate_contracts(names, raw) == [
        "StakingManager",
        "IStakingManager",
        "LiquidityPool",
        "ILiquidityPool",
    ]


# ---------------------------------------------------------------------------
# extract_contracts_regex_fallback
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(
            "Reviewed Pool.sol and Vault.sol; also mentioned Mocks/foo.txt.", ["Pool", "Vault"], id="dotsol-names"
        ),
        pytest.param("pool.sol is a dep; Vault.sol is in scope.", ["Vault"], id="ignores-lowercase-start"),
        pytest.param("Pool.sol in repo A, Pool.sol in repo B, Vault.sol elsewhere.", ["Pool", "Vault"], id="dedupes"),
        pytest.param("CurvePool.vy and ConvexBooster.sol", ["CurvePool", "ConvexBooster"], id="vyper"),
    ],
)
def test_regex_fallback_extracts_names(text, expected):
    assert extract_contracts_regex_fallback(text) == expected


# ---------------------------------------------------------------------------
# extract_date_from_pdf_text
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param("Audit Report\nSpearbit 2024-12-19\nby Alice and Bob", "2024-12-19", id="iso"),
        pytest.param("Cover page\nPublished 19 December 2024 by Spearbit", "2024-12-19", id="day-month-year"),
        pytest.param("Cover page\nAudit delivered December 2024", "2024-12-00", id="month-year-only"),
        pytest.param("Cover page with no date anywhere on the first few lines.", None, id="no-match"),
        pytest.param("Cover page without any date\n" + ("filler " * 1200) + "2024-01-01", None, id="title-region-only"),
        pytest.param("Cover\nDelivered on 19th December 2024 by Firm", "2024-12-19", id="ordinal-day-first"),
        pytest.param("Cover\nPublished December 19th, 2024", "2024-12-19", id="ordinal-month-first"),
        pytest.param("Cover\nDelivered 1st January 2024", "2024-01-01", id="ordinal-1st"),
        pytest.param("Cover\nDelivered 2nd January 2024", "2024-01-02", id="ordinal-2nd"),
        pytest.param("Cover\nDelivered 3rd January 2024", "2024-01-03", id="ordinal-3rd"),
        pytest.param("Cover\nDelivered 4th January 2024", "2024-01-04", id="ordinal-4th"),
        # Second group > 12, so unambiguously MM/DD/YYYY.
        pytest.param("Cover\nAudit date: 12/19/2024", "2024-12-19", id="us-slash"),
        # First group > 12, so must be DD/MM/YYYY; we flip.
        pytest.param("Cover\n19/12/2024", "2024-12-19", id="slash-first-is-day"),
        # Both operands <= 12 (May 2 or Feb 5): skip rather than guess, since DD/MM
        # auditors like Certora would yield silently wrong dates.
        pytest.param("Cover\nAudit date: 05/02/2024", None, id="ambiguous-slash-skipped"),
        pytest.param(
            "Cover\nAudit: 05/02/2024\nDelivered: 10 March 2024", "2024-03-10", id="prose-over-ambiguous-slash"
        ),
    ],
)
def test_extract_date_from_pdf_text(text, expected):
    assert extract_date_from_pdf_text(text) == expected


# ---------------------------------------------------------------------------
# _call_llm stub mechanism
# ---------------------------------------------------------------------------


def test_call_llm_uses_digest_stub_when_available(tmp_path, monkeypatch):
    prompt = "Prompt one"
    digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    (tmp_path / f"{digest}.json").write_text('["Pool","Vault"]')
    monkeypatch.setenv("PSAT_LLM_STUB_DIR", str(tmp_path))
    response, model = _call_llm(prompt)
    assert response == '["Pool","Vault"]'
    assert model.startswith("stub:")


def test_call_llm_falls_back_to_default(tmp_path, monkeypatch):
    (tmp_path / "_default.json").write_text('["Default"]')
    monkeypatch.setenv("PSAT_LLM_STUB_DIR", str(tmp_path))
    response, model = _call_llm("anything")
    assert response == '["Default"]'
    assert model == "stub:_default"


def test_call_llm_raises_when_no_stub(tmp_path, monkeypatch):
    monkeypatch.setenv("PSAT_LLM_STUB_DIR", str(tmp_path))
    with pytest.raises(LLMUnavailableError):
        _call_llm("no matching fixture")


@pytest.mark.parametrize(
    ("env", "expected_model"),
    [
        pytest.param({}, "google/gemini-2.5-flash-lite", id="default-model"),
        pytest.param({"PSAT_SCOPE_LLM_MODEL": "anthropic/claude-test"}, "anthropic/claude-test", id="model-override"),
    ],
)
def test_call_llm_live_path_selects_model(monkeypatch, env, expected_model):
    """With no stub dir, ``_call_llm`` selects the model and calls OpenRouter.
    The offline suite always sets ``PSAT_LLM_STUB_DIR``, so this is the only test
    exercising the live branch (and pins the default model)."""
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    captured = {}

    def fake_chat(messages, model=None, **kwargs):
        captured["model"] = model
        return '["FromLLM"]'

    monkeypatch.setattr("utils.llm.openrouter.chat", fake_chat)
    response, model = _call_llm("a scope prompt")
    assert response == '["FromLLM"]'
    assert model == expected_model
    assert captured["model"] == expected_model


# ---------------------------------------------------------------------------
# extract_scope_with_llm — parsing tolerance
# ---------------------------------------------------------------------------


def _setup_stub(tmp_path, monkeypatch, response_body: str) -> None:
    (tmp_path / "_default.json").write_text(response_body)
    monkeypatch.setenv("PSAT_LLM_STUB_DIR", str(tmp_path))


@pytest.mark.parametrize(
    ("response_body", "section_text", "expected"),
    [
        pytest.param(
            '["Pool","Vault","Strategy"]',
            "Pool.sol Vault.sol Strategy.sol",
            ["Pool", "Vault", "Strategy"],
            id="string-array",
        ),
        pytest.param('```json\n["Pool"]\n```', "Pool.sol", ["Pool"], id="markdown-fence"),
        pytest.param(
            '["Pool.sol","pool","Vault.vy"]', "Pool Vault", ["Pool", "Vault"], id="strips-extensions-and-dedupes"
        ),
        pytest.param(
            '[{"name":"Pool"},{"contract_name":"Vault"},{"file":"Strategy.sol"}]',
            "Pool Vault Strategy.sol",
            ["Pool", "Vault", "Strategy"],
            id="object-entries",
        ),
        pytest.param("[]", "anything", [], id="empty-array"),
    ],
)
def test_extract_scope_with_llm_parses_response(tmp_path, monkeypatch, response_body, section_text, expected):
    _setup_stub(tmp_path, monkeypatch, response_body)
    sections = [ScopeSection(1, 1, "scope", section_text)]
    names, _, _, _, _ = extract_scope_with_llm(sections, "T", "A")
    assert names == expected


def test_extract_scope_with_llm_parses_classified_commits_from_object(tmp_path, monkeypatch):
    _setup_stub(
        tmp_path,
        monkeypatch,
        json.dumps(
            {
                "contracts": ["Vault"],
                "scope_entries": [
                    {
                        "name": "Pool",
                        "address": "0x1234567890abcdef1234567890abcdef12345678",
                        "commit": "ABC1234",
                        "chain": "Ethereum",
                    }
                ],
                "classified_commits": [
                    {
                        "sha": "ABC1234",
                        "label": "reviewed",
                        "context": "Audited at commit abc1234",
                    },
                    {
                        "sha": "def5678",
                        "label": "fix",
                        "context": "Resolved in def5678",
                    },
                ],
            }
        ),
    )
    sections = [ScopeSection(1, 1, "scope", "Pool.sol Vault.sol abc1234 def5678")]
    names, scope_entries, classified_commits, _, _ = extract_scope_with_llm(sections, "T", "A")
    assert names == ["Vault", "Pool"]
    assert scope_entries == [
        {
            "name": "Pool",
            "address": "0x1234567890abcdef1234567890abcdef12345678",
            "commit": "abc1234",
            "chain": "ethereum",
        }
    ]
    assert classified_commits == [
        {
            "sha": "abc1234",
            "label": "reviewed",
            "context": "Audited at commit abc1234",
        },
        {
            "sha": "def5678",
            "label": "fix",
            "context": "Resolved in def5678",
        },
    ]


def test_extract_scope_with_llm_dedupes_classified_commits_preferring_stronger_label(tmp_path, monkeypatch):
    _setup_stub(
        tmp_path,
        monkeypatch,
        json.dumps(
            {
                "contracts": ["Pool"],
                "classified_commits": [
                    {"sha": "abc1234", "label": "cited", "context": "Mentioned in appendix"},
                    {"sha": "ABC1234", "label": "reviewed", "context": "Audited at abc1234"},
                ],
            }
        ),
    )
    sections = [ScopeSection(1, 1, "scope", "Pool.sol abc1234")]
    _, _, classified_commits, _, _ = extract_scope_with_llm(sections, "T", "A")
    assert classified_commits == [
        {
            "sha": "abc1234",
            "label": "reviewed",
            "context": "Audited at abc1234",
        }
    ]


def test_extract_scope_with_llm_normalizes_unknown_commit_labels_to_unclear(tmp_path, monkeypatch):
    _setup_stub(
        tmp_path,
        monkeypatch,
        json.dumps(
            {
                "contracts": ["Pool"],
                "classified_commits": [
                    {
                        "sha": "abc1234",
                        "label": "baseline",
                        "context": "x" * 500,
                    }
                ],
            }
        ),
    )
    sections = [ScopeSection(1, 1, "scope", "Pool.sol abc1234")]
    _, _, classified_commits, _, _ = extract_scope_with_llm(sections, "T", "A")
    assert classified_commits == [
        {
            "sha": "abc1234",
            "label": "unclear",
            "context": "x" * 400,
        }
    ]


def test_extract_scope_with_llm_raises_on_unparseable(tmp_path, monkeypatch):
    _setup_stub(tmp_path, monkeypatch, "this is not JSON at all")
    sections = [ScopeSection(1, 1, "scope", "anything")]
    with pytest.raises(LLMUnavailableError):
        extract_scope_with_llm(sections, "T", "A")


# ---------------------------------------------------------------------------
# build_artifact_payload
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# build_prompt sanity
# ---------------------------------------------------------------------------


def test_build_prompt_truncates_very_large_scope_text():
    huge = "A" * 100_000
    sections = [ScopeSection(1, 1, "scope", huge)]
    prompt = _build_prompt(sections, "T", "A")
    assert len(prompt) < 60_000


# ---------------------------------------------------------------------------
# Content-pattern matching (body-prose scope intros)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "page2",
    [
        # Certora-style: scope introduced by a prose phrase, not a header; the 2-page window pulls in the bullets.
        pytest.param(
            "The following contract list is included in the scope of this audit:\n- src/Pool.sol\n- src/Vault.sol",
            id="body-prose-contract-list",
        ),
        pytest.param("We reviewed the following files:\nPool.sol\nVault.sol\nStrategy.sol", id="following-files"),
        pytest.param("Contracts reviewed:\n- Pool.sol\n- Vault.sol", id="colon-intro"),
    ],
)
def test_locate_scope_section_matches_content_pattern(page2):
    text = _doc(_page(1, "Cover"), _page(2, page2))
    sections = locate_scope_section(text)
    assert len(sections) >= 1
    assert any("Pool.sol" in s.text_slice for s in sections)


def test_content_pattern_does_not_match_mere_scope_mention():
    # Body prose like "falls outside the scope" should NOT match — that
    # would pollute the results with unrelated prose.
    text = _doc(
        _page(1, "Cover"),
        _page(2, "Certain edge cases fall outside the scope of this review."),
        _page(3, "More prose without any scope listing."),
    )
    sections = locate_scope_section(text)
    assert sections == []


# ---------------------------------------------------------------------------
# Chunk-scan fallback
# ---------------------------------------------------------------------------


def test_split_text_into_chunks_caps_at_max_chunks():
    # 10 pages × default chunk size of 5 pages → 2 chunks. But the cap is
    # 4 chunks, so a 30-page document should produce 4 chunks, not 6.
    text = _doc(*(_page(i, f"page {i} body") for i in range(1, 31)))
    chunks = _split_text_into_chunks(text)
    assert 1 <= len(chunks) <= 4


def test_split_text_into_chunks_covers_pages_contiguously():
    text = _doc(*(_page(i, f"page {i} body ") * 30 for i in range(1, 21)))
    chunks = _split_text_into_chunks(text)
    assert chunks[0].start_page == 1
    for prev, nxt in zip(chunks, chunks[1:]):
        assert nxt.start_page == prev.end_page + 1


def test_chunk_scan_stops_at_first_hit(tmp_path, monkeypatch):
    # Configure the LLM stub so chunk 1 returns [] but chunk 2 returns
    # scope. The scan should stop after chunk 2 — the fake_call's predicate
    # looks for a unique marker present ONLY in chunk 2's content, since
    # the prompt template itself mentions "Pool" as an example contract.
    prompts_seen: list[str] = []

    def fake_call(prompt):
        prompts_seen.append(prompt)
        if "UNIQUE_SCOPE_MARKER_XYZ" in prompt:
            return '["Pool", "Vault"]', "stub"
        return "[]", "stub"

    monkeypatch.setattr("services.audits.scope_extraction._llm._call_llm", fake_call)

    text = _doc(
        *(_page(i, "boilerplate " * 30) for i in range(1, 6)),
        *(_page(i, "Pool.sol Vault.sol UNIQUE_SCOPE_MARKER_XYZ reviewed") for i in range(6, 11)),
    )
    names, _, _, response, model, chunks_used, winning_chunk = extract_scope_via_chunk_scan(text, "Title", "Auditor")
    assert names == ["Pool", "Vault"]
    assert chunks_used == 2
    assert model == "stub"
    assert winning_chunk is not None
    assert "UNIQUE_SCOPE_MARKER_XYZ" in winning_chunk.text_slice
    assert len(prompts_seen) == 2


def test_chunk_scan_returns_empty_when_no_chunk_has_scope(tmp_path, monkeypatch):
    def fake_call(prompt):
        return "[]", "stub"

    monkeypatch.setattr("services.audits.scope_extraction._llm._call_llm", fake_call)

    text = _doc(*(_page(i, "no scope anywhere " * 20) for i in range(1, 11)))
    names, _, _, response, model, chunks_used, winning_chunk = extract_scope_via_chunk_scan(text, "T", "A")
    assert names == []
    assert chunks_used >= 1
    assert winning_chunk is None


def test_chunk_scan_raises_only_when_every_call_fails(monkeypatch):
    # If the LLM raises on every chunk, propagate. A single bad chunk
    # should not mask a later successful one, but all-failures must surface.
    def fake_call(prompt):
        raise LLMUnavailableError("network down")

    monkeypatch.setattr("services.audits.scope_extraction._llm._call_llm", fake_call)
    text = _doc(*(_page(i, "x") for i in range(1, 6)))
    with pytest.raises(LLMUnavailableError):
        extract_scope_via_chunk_scan(text, "T", "A")


def test_chunk_scan_rejects_findings_only_chunks_without_scope_signal(
    monkeypatch,
):
    # A chunk where the LLM extracts contract names from one-off finding
    # titles should be rejected — no scope header, no .sol listing, and
    # each name appears only once (fails the frequency fallback too).
    def fake_call(prompt):
        return '["Pool", "Vault"]', "stub"

    monkeypatch.setattr("services.audits.scope_extraction._llm._call_llm", fake_call)

    text = _doc(
        _page(1, "L-01: Pool has an edge case\nSeverity: Low\nDescription: lorem ipsum."),
        _page(2, "L-02: Vault config needs review\nSeverity: Info\nOther prose."),
    )
    names, _, _, _, _, _, winning_chunk = extract_scope_via_chunk_scan(text, "T", "A")
    assert names == []
    assert winning_chunk is None


@pytest.mark.parametrize(
    ("llm_response", "pages", "expected"),
    [
        pytest.param(
            '["Pool", "Vault"]',
            (
                "Audited Files:\nsrc/Pool.sol (420 nSLOC)\nsrc/Vault.sol (310 nSLOC)\n",
                "Findings",
            ),
            ["Pool", "Vault"],
            id="scope-signal",
        ),
        # Certora-style single-focus audit: no scope header, no .sol suffixes, but
        # the name is mentioned >=2 times, so the frequency fallback accepts it.
        pytest.param(
            '["WeETHWithdrawAdapter"]',
            (
                "L-01: WeETHWithdrawAdapter may revert\n"
                "The WeETHWithdrawAdapter contract has issue X. Recommendation: "
                "update the function. Customer response: acknowledged.",
                "L-02: WeETHWithdrawAdapter rate limit issue\nAdditional analysis of WeETHWithdrawAdapter.",
            ),
            ["WeETHWithdrawAdapter"],
            id="single-focus-frequency",
        ),
    ],
)
def test_chunk_scan_accepts_chunk_passing_signal_gate(monkeypatch, llm_response, pages, expected):
    monkeypatch.setattr("services.audits.scope_extraction._llm._call_llm", lambda prompt: (llm_response, "stub"))

    text = _doc(*(_page(i, body) for i, body in enumerate(pages, start=1)))
    names, _, _, _, _, _, winning_chunk = extract_scope_via_chunk_scan(text, "T", "A")
    assert names == expected
    assert winning_chunk is not None


def test_chunk_scan_merges_across_multiple_passing_chunks(monkeypatch):
    # Short multi-section audit: chunk 1 has one scope contract, chunk 2
    # has the main scope table. Previously chunk-scan stopped at first
    # non-empty result and missed chunk 2's contents. Now it merges
    # across all chunks that pass the scope-signal gate.
    calls = {"count": 0}

    def fake_call(prompt):
        calls["count"] += 1
        if "MAIN_SCOPE_MARKER" in prompt:
            return '["Pool", "Vault", "Strategy"]', "stub"
        if "TITLE_PAGE_MARKER" in prompt:
            return '["TitleContract"]', "stub"
        return "[]", "stub"

    monkeypatch.setattr("services.audits.scope_extraction._llm._call_llm", fake_call)

    text = _doc(
        _page(
            1,
            "Security Review TITLE_PAGE_MARKER\n"
            "Program: TitleContract\n"
            "TitleContract is the focus of this report. TitleContract.sol",
        ),
        _page(2, "boilerplate " * 10),
        _page(3, "boilerplate " * 10),
        _page(4, "boilerplate " * 10),
        _page(5, "boilerplate " * 10),
        _page(
            6,
            "Files in scope MAIN_SCOPE_MARKER:\nsrc/Pool.sol\nsrc/Vault.sol\nsrc/Strategy.sol",
        ),
        _page(7, "body"),
        _page(8, "body"),
        _page(9, "body"),
        _page(10, "body"),
    )
    names, _, _, _, _, chunks_used, winning_chunk = extract_scope_via_chunk_scan(text, "T", "A")
    assert "TitleContract" in names
    assert "Pool" in names
    assert "Vault" in names
    assert "Strategy" in names
    assert calls["count"] == 2
    assert winning_chunk is not None
    assert "TITLE_PAGE_MARKER" in winning_chunk.text_slice
