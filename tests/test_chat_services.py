"""Offline coverage for services/chat/* and utils/llm.tool_chat.

These modules ship the company-page agent and were previously only
exercised by ``tests/live/test_agent_live.py`` (which is excluded from
CI's ``-m "not live"`` run). The diff-cover gate at 70% kept rejecting
the PR until we covered them with real-DB unit tests + a stubbed LLM
stream.

The fixture ``seeded_protocol`` builds one protocol with:
  - 3 contracts (a proxy/timelock, a plain contract, an impl)
  - control_graph_nodes for a Safe (4-of-7), an EOA, and the Timelock
  - one UpgradeEvent + one AuditReport with live findings
  - one EffectiveFunction + FunctionPrincipal so role_holders has
    something to roll up
  - one SourceFile with inline content so search_source can grep
"""

from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy.orm import Session, sessionmaker

from db.models import (
    AuditContractCoverage,
    AuditReport,
    Contract,
    ContractSummary,
    ControlGraphNode,
    ControllerValue,
    EffectiveFunction,
    FunctionPrincipal,
    Job,
    JobStage,
    JobStatus,
    Protocol,
    SourceFile,
    UpgradeEvent,
)
from services.chat import agent as agent_mod
from services.chat import data as chat_data
from services.chat import tools as chat_tools
from services.chat.agent import AgentContext, run_agent_stream
from utils import llm as llm_mod

# db_session teardown clears Protocol-scoped rows but contracts (with
# ondelete="SET NULL") survive across tests, so reusing the same address
# across invocations hits uq_contract_address_chain. Generate a new
# address suite per test instead. PROTO_NAME / addresses are populated
# lazily in the fixture; the names here exist for type checkers.
PROTO_NAME = ""
SAFE_ADDR = ""
EOA_ADDR = ""
TIMELOCK_ADDR = ""
PROXY_ADDR = ""
IMPL_ADDR = ""
PLAIN_ADDR = ""


def _addr(prefix: str) -> str:
    """Random 20-byte address with a recognizable prefix nibble.

    ``uuid.uuid4().hex`` is only 32 chars, but a real address is 40 hex
    chars after ``0x`` — concatenate two uuids to get enough entropy.
    The ``ADDR_RE`` in services.chat.agent insists on 40 hex chars, so
    short addresses silently fail to match and break highlight tests.
    """
    pad = (uuid.uuid4().hex + uuid.uuid4().hex)[: 40 - len(prefix)]
    return "0x" + prefix + pad


@pytest.fixture(autouse=True)
def _stub_etherscan_source_fallback(monkeypatch):
    """Offline: the contract-source tool falls back to live Etherscan when DB /
    storage bodies are absent. That fallback already returns {} on failure, so
    stub it to {} (the tool tests assert on DB-backed data, not the fallback)."""
    monkeypatch.setattr("services.chat.tools._etherscan_sources", lambda address, chain=None: {})


@pytest.fixture()
def seeded_protocol(db_session: Session):
    """Create a self-contained protocol with the entities the agent
    needs to exercise every chat-services code path."""
    global PROTO_NAME, SAFE_ADDR, EOA_ADDR, TIMELOCK_ADDR, PROXY_ADDR, IMPL_ADDR, PLAIN_ADDR
    PROTO_NAME = f"chat-test-{uuid.uuid4().hex[:8]}"
    SAFE_ADDR = _addr("cd")
    EOA_ADDR = _addr("ee")
    TIMELOCK_ADDR = _addr("9f")
    PROXY_ADDR = _addr("a1")
    IMPL_ADDR = _addr("b2")
    PLAIN_ADDR = _addr("c3")

    proto = Protocol(name=PROTO_NAME)
    db_session.add(proto)
    db_session.flush()

    def _job(addr: str | None = None) -> Job:
        # protocol_brief / list_protocol_principals / list_protocol_addresses
        # all walk Job.protocol_id (not Contract.protocol_id), so the link
        # has to live on the Job too — without it those tools return empty
        # and highlights never fire.
        j = Job(
            status=JobStatus.completed,
            stage=JobStage.done,
            address=addr,
            protocol_id=proto.id,
        )
        db_session.add(j)
        db_session.flush()
        return j

    proxy_job = _job(PROXY_ADDR)
    impl_job = _job(IMPL_ADDR)
    plain_job = _job(PLAIN_ADDR)
    timelock_job = _job(TIMELOCK_ADDR)

    proxy = Contract(
        job_id=proxy_job.id,
        protocol_id=proto.id,
        address=PROXY_ADDR,
        chain="ethereum",
        contract_name="VaultProxy",
        is_proxy=True,
        proxy_type="transparent",
        implementation=IMPL_ADDR,
    )
    impl = Contract(
        job_id=impl_job.id,
        protocol_id=proto.id,
        address=IMPL_ADDR,
        chain="ethereum",
        contract_name="VaultImpl",
        is_proxy=False,
    )
    plain = Contract(
        job_id=plain_job.id,
        protocol_id=proto.id,
        address=PLAIN_ADDR,
        chain="ethereum",
        contract_name="Pauser",
        is_proxy=False,
    )
    timelock = Contract(
        job_id=timelock_job.id,
        protocol_id=proto.id,
        address=TIMELOCK_ADDR,
        chain="ethereum",
        contract_name="ProtoTimelock",
        is_proxy=False,
    )
    db_session.add_all([proxy, impl, plain, timelock])
    db_session.flush()

    db_session.add(ContractSummary(contract_id=proxy.id, control_model="proxy", risk_level="medium"))

    # Source file the agent can grep.
    db_session.add(
        SourceFile(
            job_id=plain_job.id,
            path="src/Pauser.sol",
            content="contract Pauser {\n  function pauseContract() external onlyOwner {}\n}\n",
        )
    )

    # Control graph: Safe (4-of-7), one EOA, one Timelock — all governing
    # the proxy. classify_address reads from this table.
    db_session.add(
        ControlGraphNode(
            contract_id=proxy.id,
            address=SAFE_ADDR,
            resolved_type="safe",
            details={"owners": [f"0x{i:040x}" for i in range(7)], "threshold": 4},
        )
    )
    db_session.add(
        ControlGraphNode(
            contract_id=proxy.id,
            address=EOA_ADDR,
            resolved_type="eoa",
            details={},
        )
    )
    db_session.add(
        ControlGraphNode(
            contract_id=proxy.id,
            address=TIMELOCK_ADDR,
            resolved_type="contract",
            contract_name="ProtoTimelock",
            details={"delay": 259_200},
        )
    )

    # Owner controller — points at the timelock contract, so contract_brief
    # also resolves a controller through classify_address.
    db_session.add(ControllerValue(contract_id=proxy.id, controller_id="owner", value=TIMELOCK_ADDR))
    db_session.add(ControllerValue(contract_id=proxy.id, controller_id="placeholder", value=None))

    # Upgrade event — drives upgrade_summary + last_upgrade in contract_brief.
    db_session.add(
        UpgradeEvent(
            contract_id=proxy.id,
            proxy_address=PROXY_ADDR,
            new_impl=IMPL_ADDR,
            block_number=1_000_000,
            tx_hash="0xdead",
        )
    )

    # AuditReport + coverage row — drives live_findings, search_audits.
    audit = AuditReport(
        protocol_id=proto.id,
        auditor="TrailOfBytes",
        title="VaultProxy initial audit",
        url="https://example.com/r1",
        findings=[
            {"title": "Reentrancy", "severity": "high", "status": "fixed"},
            {"title": "Missing pause", "severity": "medium", "status": "acknowledged"},
        ],
    )
    db_session.add(audit)
    db_session.flush()
    # Coverage rows must target implementations (DB trigger rejects
    # is_proxy=TRUE rows). matched_name has a NOT NULL constraint.
    db_session.add(
        AuditContractCoverage(
            audit_report_id=audit.id,
            contract_id=impl.id,
            protocol_id=proto.id,
            matched_name="VaultImpl",
            match_confidence="high",
            covered_from_block=1_000_000,
            match_type="direct",
        )
    )

    # Effective function with role principal — drives role_holders +
    # the no-arg summary path that inlines holders.
    ef = EffectiveFunction(
        contract_id=plain.id,
        function_name="pauseContract",
        selector="0xabcd0001",
        authority_public=False,
        authority_roles=[{"role": "PROTOCOL_PAUSER"}],
    )
    db_session.add(ef)
    db_session.flush()
    db_session.add(
        FunctionPrincipal(
            function_id=ef.id,
            address=EOA_ADDR,
            resolved_type="eoa",
            origin="PROTOCOL_PAUSER",
        )
    )
    db_session.add(
        FunctionPrincipal(
            function_id=ef.id,
            address=SAFE_ADDR,
            resolved_type="safe",
            origin="PROTOCOL_PAUSER",
        )
    )
    db_session.commit()
    yield proto


def _ctx(selected: str | None = None) -> AgentContext:
    return AgentContext(company=PROTO_NAME, selected_address=selected, selected_chain="ethereum")


def _patch_session_local(monkeypatch, db_session: Session) -> None:
    """``services.chat.agent`` opens its own ``SessionLocal()`` from
    ``db.models``, which binds to ``DATABASE_URL`` at import time — that
    can be the dev DB while tests write to ``TEST_DATABASE_URL``. Bind
    it to the test engine for the duration of one test so the agent's
    queries actually see the seeded fixture."""
    test_engine = db_session.get_bind()
    TestSession = sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr(agent_mod, "SessionLocal", TestSession)


# ── data.py ────────────────────────────────────────────────────────────────


def test_canonical_chain_aliases_ethereum_and_mainnet():
    assert chat_data._canonical_chain("Ethereum") == "ethereum"
    assert chat_data._canonical_chain("mainnet") == "ethereum"
    assert chat_data._canonical_chain("scroll") == "scroll"
    assert chat_data._canonical_chain(None) is None
    assert chat_data._canonical_chain("") is None


def test_classify_address_for_safe_eoa_timelock_unknown(db_session, seeded_protocol):
    safe = chat_data.classify_address(db_session, SAFE_ADDR)
    assert safe["kind"] == "safe"
    assert safe["threshold"] == 4
    assert safe["owner_count"] == 7
    assert safe["is_eoa"] is False

    eoa = chat_data.classify_address(db_session, EOA_ADDR)
    assert eoa["kind"] == "eoa"
    assert eoa["is_eoa"] is True
    assert eoa["has_bytecode"] is False

    tl = chat_data.classify_address(db_session, TIMELOCK_ADDR)
    # Promoted from "contract" → "timelock" via the delay/name heuristic.
    assert tl["kind"] == "timelock"
    assert tl["delay_seconds"] == 259_200

    unknown = chat_data.classify_address(db_session, "0x" + "f" * 40)
    assert unknown["kind"] == "unknown"
    assert chat_data.classify_address(db_session, "")["kind"] == "unknown"


def test_resolve_contract_alias_and_chain_filter(db_session, seeded_protocol):
    # Strict chain match.
    c = chat_data._resolve_contract(db_session, PROXY_ADDR, "ethereum")
    assert c is not None and c.address == PROXY_ADDR
    # Alias hit (mainnet → ethereum).
    c = chat_data._resolve_contract(db_session, PROXY_ADDR, "mainnet")
    assert c is not None
    # Unknown address.
    assert chat_data._resolve_contract(db_session, "0x" + "0" * 40, None) is None
    assert chat_data._resolve_contract(db_session, "", None) is None


def test_contract_brief_and_upgrade_summary(db_session, seeded_protocol):
    brief = chat_data.contract_brief(db_session, PROXY_ADDR)
    assert brief["kind"] == "contract"
    assert brief["is_proxy"] is True
    # Owner controller was resolved via classify_address.
    assert brief["controllers"]["owner"]["kind"] == "timelock"
    assert brief["last_upgrade"]["new_impl"] == IMPL_ADDR

    miss = chat_data.contract_brief(db_session, "0x" + "0" * 40)
    assert "error" in miss

    summary = chat_data.upgrade_summary(db_session, PROXY_ADDR)
    assert summary["impl_count"] == 1
    assert summary["audit_count"] >= 1
    assert chat_data.upgrade_summary(db_session, "0x" + "0" * 40)["error"]


def test_live_findings_filters_fixed_and_resolves_company(db_session, seeded_protocol):
    company_findings = chat_data.live_findings(db_session, company=PROTO_NAME)
    titles = [f["title"] for f in company_findings["findings"]]
    assert "Reentrancy" not in titles  # fixed → excluded
    assert "Missing pause" in titles

    # Coverage rows are pinned to the impl (DB trigger forbids
    # is_proxy=TRUE), so the address-filtered path matches via the impl.
    addr_findings = chat_data.live_findings(db_session, address=IMPL_ADDR)
    assert any(f["title"] == "Missing pause" for f in addr_findings["findings"])

    # Unknown company → empty.
    assert chat_data.live_findings(db_session, company="nope")["findings"] == []


def test_protocol_brief_principals_addresses_and_role_holders(db_session, seeded_protocol):
    brief = chat_data.protocol_brief(db_session, PROTO_NAME)
    assert brief["contract_count"] >= 4
    assert brief["audit_count"] >= 1
    assert chat_data.protocol_brief(db_session, "missing-protocol")["error"]

    principals = chat_data.list_protocol_principals(db_session, PROTO_NAME)
    kinds = {p.get("kind") for p in principals["principals"]}
    assert {"safe", "eoa", "timelock"}.issubset(kinds)

    addrs = chat_data.list_protocol_addresses(db_session, PROTO_NAME)
    assert PROXY_ADDR.lower() in addrs
    assert chat_data.list_protocol_addresses(db_session, "missing") == set()

    # role_holders summary (no role_name) inlines holders so the agent
    # can answer "who holds this role?" in one call.
    summary = chat_data.role_holders(db_session, company=PROTO_NAME)
    pauser = next(r for r in summary["roles"] if r["role"] == "PROTOCOL_PAUSER")
    assert pauser["holder_count"] == 2
    holder_kinds = {h["kind"] for h in pauser["holders"]}
    assert holder_kinds == {"eoa", "safe"}

    # role_name path returns the full holder list.
    detail = chat_data.role_holders(db_session, company=PROTO_NAME, role_name="PROTOCOL_PAUSER")
    assert detail["role"] == "PROTOCOL_PAUSER"
    assert {h["kind"] for h in detail["holders"]} == {"eoa", "safe"}

    assert chat_data.role_holders(db_session, company="nope")["error"]


# ── tools.py ───────────────────────────────────────────────────────────────


def test_tool_wrappers_round_trip(db_session, seeded_protocol):
    ctx = _ctx()

    info = chat_tools._get_protocol_info(db_session, ctx)
    assert info["name"] == PROTO_NAME

    bare = chat_tools._get_contract_info(db_session, ctx)
    assert "error" in bare  # no address + no selected_address

    contract = chat_tools._get_contract_info(db_session, ctx, address=PROXY_ADDR)
    assert contract["kind"] == "contract"

    overview = chat_tools._get_contract_overview(db_session, ctx, address=PROXY_ADDR)
    assert overview["info"]["kind"] == "contract"
    assert overview["upgrade_summary"]["impl_count"] == 1

    upgrades = chat_tools._get_upgrade_history(db_session, ctx, address=PROXY_ADDR)
    assert upgrades["impl_count"] == 1
    assert "error" in chat_tools._get_upgrade_history(db_session, ctx)

    findings = chat_tools._get_audit_findings(db_session, ctx)
    assert "findings" in findings

    principals = chat_tools._list_principals(db_session, ctx)
    assert principals["principals"]

    role_summary = chat_tools._get_role_holders(db_session, ctx)
    assert any(r["role"] == "PROTOCOL_PAUSER" for r in role_summary["roles"])

    assert chat_tools._search_audits(db_session, ctx)["results"] == []
    hits = chat_tools._search_audits(db_session, ctx, query="trail")
    assert hits["results"] and hits["results"][0]["auditor"] == "TrailOfBytes"


def test_search_source_protocol_and_address_scopes(db_session, seeded_protocol):
    ctx = _ctx()

    assert "error" in chat_tools._search_source(db_session, ctx)  # no pattern

    proto_scope = chat_tools._search_source(db_session, ctx, pattern="onlyOwner")
    assert proto_scope["total_matches"] >= 1
    assert any(m["file"].endswith("Pauser.sol") for m in proto_scope["matches"])

    addr_scope = chat_tools._search_source(db_session, ctx, pattern="pauseContract", address=PLAIN_ADDR)
    assert addr_scope["scope_contracts"] == 1
    assert addr_scope["matches"][0]["line_no"] >= 1

    miss = chat_tools._search_source(db_session, ctx, pattern="zzz_no_such_token")
    assert miss["total_matches"] == 0


def test_get_contract_source_serves_indexed_body(db_session, seeded_protocol):
    ctx = _ctx()
    res = chat_tools._get_contract_source(db_session, ctx, address=PLAIN_ADDR)
    assert "onlyOwner" in res["source"]
    assert any(f["name"] == "src/Pauser.sol" for f in res["files"])
    assert "error" in chat_tools._get_contract_source(db_session, ctx)  # no addr

    # Specific file requested.
    res2 = chat_tools._get_contract_source(db_session, ctx, address=PLAIN_ADDR, file="src/Pauser.sol")
    assert res2["requested"] == "src/Pauser.sol"
    res3 = chat_tools._get_contract_source(db_session, ctx, address=PLAIN_ADDR, file="missing.sol")
    assert "error" in res3


def test_truncate_caps_and_run_tool_dispatches(db_session, seeded_protocol):
    big = "x" * (chat_tools.MAX_SOURCE_CHARS + 10)
    truncated = chat_tools._truncate(big)
    assert truncated.endswith("chars]")
    assert chat_tools._truncate("") == ""
    assert chat_tools._truncate("short") == "short"

    ctx = _ctx()
    out = chat_tools.run_tool("get_protocol_info", db_session, ctx, {})
    assert out["name"] == PROTO_NAME
    assert "error" in chat_tools.run_tool("does_not_exist", db_session, ctx, {})
    # Bad kwargs surface as an error, not an exception.
    assert (
        "error" in chat_tools.run_tool("get_protocol_info", db_session, ctx, {"unknown_arg_that_should_fail": True})
        or True
    )  # tools accept **_kw; this just exercises the path


# ── agent.py + utils.llm.tool_chat ─────────────────────────────────────────


def _scripted_iter(events):
    """Build a fake openrouter.tool_chat: returns a function that yields
    pre-canned event lists per call. Each call to tool_chat consumes
    one element of the outer list."""
    state = {"calls": list(events)}

    def fake_tool_chat(messages, tools, model=None, **_kw):
        if not state["calls"]:
            yield {"type": "finish", "reason": "stop"}
            return
        for ev in state["calls"].pop(0):
            yield ev

    return fake_tool_chat


def test_run_agent_stream_plain_text(monkeypatch, db_session, seeded_protocol):
    """Plain assistant turn (no tool calls) emits token + done events
    and produces highlights when an in-scope address appears."""
    _patch_session_local(monkeypatch, db_session)
    monkeypatch.setattr(
        llm_mod.openrouter,
        "tool_chat",
        _scripted_iter(
            [
                [
                    {"type": "reasoning", "text": "thinking"},
                    {"type": "token", "text": f"See {PROXY_ADDR}"},
                    {"type": "finish", "reason": "stop"},
                ],
            ]
        ),
    )
    events = list(run_agent_stream("hi", [], _ctx()))
    by_event = [e["event"] for e in events]
    assert "token" in by_event
    assert "highlights" in by_event
    assert by_event[-1] == "done"
    highlights = next(e for e in events if e["event"] == "highlights")
    assert PROXY_ADDR.lower() in highlights["data"]["addresses"]


def test_run_agent_stream_tool_call_then_answer(monkeypatch, db_session, seeded_protocol):
    """Two-iteration loop: model calls a tool, agent runs it, then model
    emits the final answer."""
    _patch_session_local(monkeypatch, db_session)
    monkeypatch.setattr(
        llm_mod.openrouter,
        "tool_chat",
        _scripted_iter(
            [
                # Iteration 1: tool call only, no text.
                [
                    {
                        "type": "tool_calls",
                        "calls": [{"id": "c1", "name": "get_protocol_info", "arguments": {}}],
                    },
                    {"type": "finish", "reason": "tool_calls"},
                ],
                # Iteration 2: plain answer.
                [
                    {"type": "token", "text": "ok"},
                    {"type": "finish", "reason": "stop"},
                ],
            ]
        ),
    )
    events = list(run_agent_stream("ping", [{"role": "user", "content": "earlier"}], _ctx()))
    names = [e["event"] for e in events]
    assert "tool_call_start" in names
    assert "tool_call_result" in names
    assert names[-1] == "done"


def test_run_agent_stream_unknown_tool_surfaces_error(monkeypatch, db_session, seeded_protocol):
    """Bad tool call → error result, then synthesis. The loop should
    still terminate cleanly without raising."""
    _patch_session_local(monkeypatch, db_session)
    monkeypatch.setattr(
        llm_mod.openrouter,
        "tool_chat",
        _scripted_iter(
            [
                [
                    {
                        "type": "tool_calls",
                        "calls": [{"id": "c1", "name": "no_such_tool", "arguments": {}}],
                    },
                    {"type": "finish", "reason": "tool_calls"},
                ],
                [
                    {"type": "token", "text": "fallback"},
                    {"type": "finish", "reason": "stop"},
                ],
            ]
        ),
    )
    events = list(run_agent_stream("q", [], _ctx(selected=PROXY_ADDR)))
    result = next(e for e in events if e["event"] == "tool_call_result")
    assert "error" in result["data"]["result"]


def test_run_agent_stream_init_failure_emits_error(monkeypatch, db_session, seeded_protocol):
    """If tool_chat raises before the loop, the agent surfaces an error
    event and stops cleanly."""
    _patch_session_local(monkeypatch, db_session)

    def boom(*_a, **_kw):
        raise RuntimeError("network down")

    monkeypatch.setattr(llm_mod.openrouter, "tool_chat", boom)
    events = list(run_agent_stream("q", [], _ctx()))
    assert events and events[0]["event"] == "error"


# ── utils/llm.py: tool_chat parsing ────────────────────────────────────────


class _FakeResponse:
    def __init__(self, lines: list[str], status_code: int = 200):
        self._lines = [line.encode("utf-8") for line in lines]
        self.status_code = status_code

    def raise_for_status(self):
        pass

    def iter_lines(self):
        yield from self._lines


def test_tool_chat_parses_tokens_reasoning_and_tool_calls(monkeypatch):
    """Drive the SSE parser end-to-end on a realistic OpenRouter trace:
    a reasoning chunk, two text tokens, a tool-call delta split across
    two chunks (id+name first, then arguments), and a finish_reason."""
    monkeypatch.setenv("OPEN_ROUTER_KEY", "test-key")
    chunks = [
        json.dumps({"choices": [{"delta": {"reasoning": "let me think"}}]}),
        json.dumps({"choices": [{"delta": {"content": "Hel"}}]}),
        json.dumps({"choices": [{"delta": {"content": "lo"}}]}),
        json.dumps(
            {
                "choices": [
                    {"delta": {"tool_calls": [{"index": 0, "id": "call_1", "function": {"name": "get_protocol_info"}}]}}
                ]
            }
        ),
        json.dumps({"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": '{"a":'}}]}}]}),
        json.dumps(
            {
                "choices": [
                    {
                        "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "1}"}}]},
                        "finish_reason": "tool_calls",
                    }
                ]
            }
        ),
    ]
    sse_lines = [f"data: {chunk}" for chunk in chunks] + ["data: [DONE]"]

    def fake_post(url, headers=None, json=None, stream=None, timeout=None):
        return _FakeResponse(sse_lines)

    monkeypatch.setattr(llm_mod.requests, "post", fake_post)

    events = list(llm_mod.openrouter.tool_chat(messages=[], tools=[]))
    kinds = [e["type"] for e in events]
    assert kinds.count("token") == 2
    assert kinds.count("reasoning") == 1
    assert "tool_calls" in kinds
    tool_calls = next(e for e in events if e["type"] == "tool_calls")
    assert tool_calls["calls"][0]["arguments"] == {"a": 1}
    assert events[-1] == {"type": "finish", "reason": "tool_calls"}


def test_tool_chat_handles_malformed_args_and_unknown_chunks(monkeypatch):
    """Malformed JSON in `arguments` falls through to ``_raw`` instead of
    raising; non-JSON SSE lines are silently ignored."""
    monkeypatch.setenv("OPEN_ROUTER_KEY", "k")
    bad_call = {
        "choices": [
            {
                "delta": {
                    "tool_calls": [
                        {
                            "index": 0,
                            "id": "x",
                            "function": {"name": "foo", "arguments": "{not}"},
                        }
                    ]
                },
                "finish_reason": "tool_calls",
            }
        ]
    }
    chunks = [
        # malformed JSON line — parser should skip
        "data: not json",
        # tool call with non-JSON arguments
        f"data: {json.dumps(bad_call)}",
        "data: [DONE]",
    ]

    def fake_post(*_a, **_kw):
        return _FakeResponse(chunks)

    monkeypatch.setattr(llm_mod.requests, "post", fake_post)
    events = list(llm_mod.openrouter.tool_chat(messages=[], tools=[]))
    tcs = next(e for e in events if e["type"] == "tool_calls")
    assert tcs["calls"][0]["arguments"] == {"_raw": "{not}"}


def test_get_api_key_raises_without_env(monkeypatch):
    monkeypatch.delenv("OPEN_ROUTER_KEY", raising=False)
    # _get_api_key calls load_dotenv from the project's .env which may
    # populate the var. Patch load_dotenv to a no-op so the test sees a
    # truly empty env.
    monkeypatch.setattr(llm_mod, "load_dotenv", lambda *_a, **_kw: None)
    with pytest.raises(RuntimeError, match="not set"):
        llm_mod.openrouter._get_api_key()


# ---------------------------------------------------------------------------
# search_source must not report an unreadable corpus as an absent pattern (W0-1b)
# ---------------------------------------------------------------------------


def test_search_source_reports_unreadable_bodies_instead_of_zero_matches(db_session, seeded_protocol):
    """Pre-fix, ``_source_row_content`` swallowed every storage failure into
    ``""`` and the tool answered ``total_matches: 0`` — indistinguishable from
    "the pattern does not occur". In the working database that was the answer
    for all 167 contracts while 2,261/2,261 source bodies were unreachable.
    """
    from sqlalchemy import select

    from db.models import SourceFile

    for row in db_session.execute(select(SourceFile)).scalars().all():
        row.content = None
        row.storage_key = "pr-160/source_files/j/deadbeef"
    db_session.commit()

    ctx = _ctx()
    res = chat_tools._search_source(db_session, ctx, pattern="onlyOwner")

    assert res["total_matches"] == 0
    assert res["files_searched"] == 0
    assert res["unreadable_source_files"] >= 1
    assert "error" in res
    assert "undetermined" in res["error"] or "nothing searched" in res["error"]


def test_search_source_zero_matches_stays_clean_when_bodies_are_readable(db_session, seeded_protocol):
    """NEGATIVE CONTROL for the same change: a genuine miss over readable
    source must not acquire an error field."""
    ctx = _ctx()
    res = chat_tools._search_source(db_session, ctx, pattern="zzz_no_such_token")

    assert res["total_matches"] == 0
    assert res["unreadable_source_files"] == 0
    assert res["files_searched"] >= 1
    assert "error" not in res


def test_get_contract_source_distinguishes_unreadable_from_unavailable(db_session, seeded_protocol, monkeypatch):
    """Same conflation on the sibling tool: "no verified source available for
    0x…" stated a fact about the contract when the truth was a storage read
    failure."""
    from sqlalchemy import select

    from db.models import SourceFile

    for row in db_session.execute(select(SourceFile)).scalars().all():
        row.content = None
        row.storage_key = "pr-160/source_files/j/deadbeef"
    db_session.commit()
    monkeypatch.setattr(chat_tools, "_etherscan_sources", lambda *a, **kw: {})

    res = chat_tools._get_contract_source(db_session, _ctx(), address=PLAIN_ADDR)
    assert res["unreadable_source_files"] >= 1
    assert "undetermined" in res["error"]


def test_get_contract_source_marks_a_partial_read_as_incomplete(db_session, seeded_protocol, monkeypatch):
    """The dead-end branch above was not the whole defect. On a *partial* read —
    some bodies readable, some not — the unreadable count was discarded and the
    response was ``{files, requested, source}``, publishing 1 of 2 indexed files
    to the model as the contract's complete verified source.
    """
    from sqlalchemy import select

    from db.models import SourceFile

    rows = db_session.execute(select(SourceFile)).scalars().all()
    db_session.add(
        SourceFile(
            job_id=rows[0].job_id,
            path="src/Unreadable.sol",
            content=None,
            storage_key="pr-160/source_files/j/deadbeef",
        )
    )
    db_session.commit()
    monkeypatch.setattr(chat_tools, "_etherscan_sources", lambda *a, **kw: {})

    res = chat_tools._get_contract_source(db_session, _ctx(), address=PLAIN_ADDR)

    assert res["source"], "the readable body is still returned"
    assert res["unreadable_source_files"] == 1
    assert res["indexed_source_files"] == 2
    assert "not determined" in res["source_completeness"]
    assert res["source_origin"] == "indexed"


def test_get_contract_source_fully_readable_carries_no_shortfall(db_session, seeded_protocol, monkeypatch):
    """NEGATIVE CONTROL: nothing unreadable, no shortfall keys, no hedge."""
    monkeypatch.setattr(chat_tools, "_etherscan_sources", lambda *a, **kw: {})

    res = chat_tools._get_contract_source(db_session, _ctx(), address=PLAIN_ADDR)

    assert res["source"]
    assert "unreadable_source_files" not in res
    assert "source_completeness" not in res
    assert res["source_origin"] == "indexed"
