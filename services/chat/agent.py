"""Streaming agent loop for the company-page Agent sidebar.

Drives ``LLMClient.tool_chat`` (utils/llm.py): pipes assistant tokens
through, runs tools server-side when the model requests them, and emits
a final highlights event listing in-scope addresses to focus on the
canvas.

Public surface: ``run_agent_stream(message, history, ctx)`` yields plain
dicts that the FastAPI route translates to SSE frames.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Iterator

from db.models import SessionLocal
from schemas.chat_schemas import AgentContext
from services.chat.data import contract_brief, list_protocol_addresses
from services.chat.tools import TOOL_DEFINITIONS, run_tool
from utils.llm import AGENT_MODEL, openrouter

logger = logging.getLogger("services.chat.agent")

MAX_ITERATIONS = 20

ADDR_RE = re.compile(r"0x[a-fA-F0-9]{40}")


def _system_prompt(session, ctx: AgentContext) -> str:
    """Compose the agent's system prompt with auto-injected context.

    The selected contract's metadata is fetched once up front so the agent
    can answer "what does this control?" without a tool round-trip when
    the user is staring right at it. If nothing's selected, the prompt
    just frames the protocol.
    """
    parts = [
        f"You are an on-chain protocol auditor's assistant inside the PSAT app, looking at '{ctx.company}'.",
        (
            "Use the available tools to answer — they read directly from "
            "analyzed protocol data. Quote contract addresses verbatim (0x...) "
            "so the UI can highlight them."
        ),
        (
            "STYLE — answer briefly and directly:"
            "\n• Open with the specific finding in 1 sentence (the address + the risk)."
            "\n• 1 short section of supporting facts: name the principal kind "
            "(EOA / Safe with M-of-N / Timelock with delay) and the specific "
            "function or role that produces the risk."
            "\n• Optional 1-line ceiling on impact (DoS vs theft, who can revert)."
            "\n• Stop. No 'Bottom line' recap. No 'Mitigating factors' "
            "section unless the user asks for one. No fluff phrases like "
            "'reputational damage' or 'loss of user trust'."
            "\n• Total length: ~6–10 short lines for typical questions."
        ),
        (
            "LINKING — every time you mention an address or named contract "
            "in your answer, format it as a markdown link pointing at the "
            "raw address. Examples:"
            "\n  [0x9af1298993dc1f397973c62a5d47a284cf76844d](0x9af1298993dc1f397973c62a5d47a284cf76844d)"
            "\n  [EtherFiAdmin](0x0ef8fa4760db8f5cd4d993f3e3416f30f942d705)"
            "\n  [4-of-7 Safe](0xcdd57d11476c22d265722f68390b036f3da48c21)"
            "\nThe UI turns these into clickable links that focus the canvas "
            "on the address. ALWAYS use this form for in-scope addresses — "
            "do not write a bare 0x address without wrapping it in a link."
        ),
        (
            "Before answering: if a tool result contradicts an assumption "
            "you started with, surface guards (delays, thresholds, role gates) "
            "explicitly — never claim 'complete takeover' or 'unilateral' "
            "control without verifying the actual gating."
        ),
    ]
    if ctx.selected_address:
        try:
            sel = contract_brief(session, ctx.selected_address, chain_id=ctx.selected_chain_id)
            if sel.get("error"):
                raise RuntimeError(str(sel["error"]))
            parts.append("CURRENTLY SELECTED CONTRACT (auto-context):\n" + json.dumps(sel, indent=2))
        except Exception as exc:
            logger.error(
                "system prompt selected-contract lookup failed for address=%s chain_id=%s: %s",
                ctx.selected_address,
                ctx.selected_chain_id,
                exc,
            )
            raise RuntimeError("system prompt selected-contract lookup failed") from exc
    return "\n\n".join(parts)


def run_agent_stream(message: str, history: list[dict], ctx: AgentContext) -> Iterator[dict]:
    """Yield streaming events for one user turn.

    Events:
      {"event": "token", "data": {"text": str}}
      {"event": "tool_call_start", "data": {"id", "name", "arguments"}}
      {"event": "tool_call_result", "data": {"id", "name", "result"}}
      {"event": "highlights", "data": {"addresses": [str]}}
      {"event": "done", "data": {}}
      {"event": "error", "data": {"message": str}}

    The caller (FastAPI route) frames these as SSE.
    """
    session = SessionLocal()
    try:
        messages: list[dict] = [{"role": "system", "content": _system_prompt(session, ctx)}]
        # Replay prior conversation. Trust client to send sane history.
        for h in history or []:
            role = h.get("role")
            content = h.get("content") or ""
            if role in ("user", "assistant") and content:
                messages.append({"role": role, "content": content})
        messages.append({"role": "user", "content": message})

        final_text_parts: list[str] = []
        for _iteration in range(MAX_ITERATIONS):
            try:
                stream = openrouter.tool_chat(messages, tools=TOOL_DEFINITIONS, model=AGENT_MODEL)
            except Exception as exc:
                logger.warning("tool_chat init failed: %s", exc, extra={"exc_type": type(exc).__name__})
                yield {"event": "error", "data": {"message": f"LLM call failed: {exc}"}}
                return

            assistant_text_parts: list[str] = []
            tool_calls: list[dict] = []
            try:
                for chunk in stream:
                    kind = chunk.get("type")
                    if kind == "token":
                        text = chunk.get("text", "")
                        assistant_text_parts.append(text)
                        final_text_parts.append(text)
                        yield {"event": "token", "data": {"text": text}}
                    elif kind == "reasoning":
                        # Pass reasoning through as its own SSE event so the
                        # frontend can render it in a lighter style. We don't
                        # accumulate into final_text_parts — reasoning is
                        # display-only and shouldn't drive highlights.
                        yield {"event": "reasoning", "data": {"text": chunk.get("text", "")}}
                    elif kind == "tool_calls":
                        tool_calls = chunk.get("calls", [])
                    elif kind == "finish":
                        pass
            except Exception as exc:
                logger.warning("stream parse failed: %s", exc, extra={"exc_type": type(exc).__name__})
                yield {"event": "error", "data": {"message": f"stream failed: {exc}"}}
                return

            if not tool_calls:
                # Plain answer — we're done.
                break

            # Append the assistant turn (with tool_calls) and execute each.
            messages.append(
                {
                    "role": "assistant",
                    "content": "".join(assistant_text_parts) or None,
                    "tool_calls": [
                        {
                            "id": tc["id"],
                            "type": "function",
                            "function": {
                                "name": tc["name"],
                                "arguments": json.dumps(tc.get("arguments") or {}),
                            },
                        }
                        for tc in tool_calls
                    ],
                }
            )
            for tc in tool_calls:
                yield {
                    "event": "tool_call_start",
                    "data": {"id": tc["id"], "name": tc["name"], "arguments": tc.get("arguments") or {}},
                }
                result = run_tool(tc["name"], session, ctx, tc.get("arguments") or {})
                yield {
                    "event": "tool_call_result",
                    "data": {"id": tc["id"], "name": tc["name"], "result": result},
                }
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "name": tc["name"],
                        "content": json.dumps(result, default=str),
                    }
                )
        else:
            # We exhausted MAX_ITERATIONS without the model giving a
            # tool-call-free turn. Force a final synthesis call WITHOUT
            # tools so the model has to write an answer using whatever
            # context it has — a friendlier outcome than a hard error.
            try:
                final_stream = openrouter.tool_chat(
                    messages
                    + [
                        {
                            "role": "system",
                            "content": (
                                "Iteration budget reached. Write your final answer "
                                "now using only the data already gathered. Do not "
                                "request more tools."
                            ),
                        }
                    ],
                    tools=[],
                    model=AGENT_MODEL,
                )
                for chunk in final_stream:
                    if chunk.get("type") == "token":
                        text = chunk.get("text", "")
                        final_text_parts.append(text)
                        yield {"event": "token", "data": {"text": text}}
                    elif chunk.get("type") == "reasoning":
                        yield {"event": "reasoning", "data": {"text": chunk.get("text", "")}}
            except Exception as exc:
                logger.warning("synthesis fallback failed: %s", exc)
                yield {
                    "event": "error",
                    "data": {"message": f"agent exhausted tools and synthesis failed: {exc}"},
                }

        # Highlights: extract any addresses the assistant mentioned and
        # intersect with the in-scope contract set so the canvas only
        # lights up nodes it actually has.
        final_text = "".join(final_text_parts)
        addrs_in_text = {m.lower() for m in ADDR_RE.findall(final_text)}
        if addrs_in_text:
            in_scope = list_protocol_addresses(session, ctx.company)
            highlights = sorted(addrs_in_text & in_scope)
            yield {"event": "highlights", "data": {"addresses": highlights}}

        yield {"event": "done", "data": {}}
    finally:
        session.close()
