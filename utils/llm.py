import json
import logging
import os
import time
from pathlib import Path
from typing import Iterator

import requests
from dotenv import load_dotenv

from utils.logging import record_stage_metric, stage_metrics_var

logger = logging.getLogger(__name__)


def _record_llm_call() -> None:
    metrics = stage_metrics_var.get()
    prior = metrics.get("llm_calls", 0) if isinstance(metrics, dict) else 0
    record_stage_metric("llm_calls", (prior or 0) + 1)


def _raise_for_status_loud(response: requests.Response, model: str) -> None:
    """Warn loudly on 402 (out of credits) / 429 before raising: those caused silent discovery collapses."""
    status = response.status_code
    if status in (402, 429):
        kind = "payment_required" if status == 402 else "rate_limited"
        logger.warning(
            "LLM request rejected (%s)",
            kind,
            extra={"model": model, "status_code": status, "failure_kind": kind},
        )
    response.raise_for_status()


class LLMClient:
    def __init__(self, url: str, env_var: str, default_model: str):
        self.url = url
        self.env_var = env_var
        self.default_model = default_model

    def _get_api_key(self) -> str:
        load_dotenv(Path(__file__).resolve().parent.parent / ".env")
        key = os.getenv(self.env_var)
        if not key:
            raise RuntimeError(f"{self.env_var} not set in .env")
        return key

    def chat(self, messages: list[dict], model: str | None = None, **kwargs) -> str:
        api_key = self._get_api_key()

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Accept": "text/event-stream",
        }

        payload = {
            "model": model or self.default_model,
            "messages": messages,
            "max_tokens": kwargs.get("max_tokens", 16384),
            "temperature": kwargs.get("temperature", 0.2),
            "top_p": kwargs.get("top_p", 0.9),
            "stream": True,
        }

        resolved_model = model or self.default_model
        started = time.monotonic()
        response = requests.post(self.url, headers=headers, json=payload, stream=True, timeout=120)
        _raise_for_status_loud(response, resolved_model)

        content_parts = []
        finish_reason: str | None = None
        for line in response.iter_lines():
            if not line:
                continue
            decoded = line.decode("utf-8")
            if not decoded.startswith("data: "):
                continue
            data = decoded[6:]  # strip "data: "
            if data.strip() == "[DONE]":
                break
            try:
                chunk = json.loads(data)
                choices = chunk.get("choices", [])
                if not choices:
                    continue
                delta = choices[0].get("delta", {})
                content = delta.get("content")
                if content:
                    content_parts.append(content)
                if choices[0].get("finish_reason"):
                    finish_reason = choices[0]["finish_reason"]
            except json.JSONDecodeError:
                continue

        result = "".join(content_parts)
        # Otherwise an empty result is indistinguishable from a legitimately empty answer.
        duration_ms = int((time.monotonic() - started) * 1000)
        logger.info(
            "LLM completion",
            extra={
                "model": resolved_model,
                "duration_ms": duration_ms,
                "finish_reason": finish_reason,
                "content_len": len(result),
            },
        )
        _record_llm_call()
        return result

    def tool_chat(
        self,
        messages: list[dict],
        tools: list[dict],
        model: str | None = None,
        **kwargs,
    ) -> Iterator[dict]:
        """Stream a chat completion with tool calling.

        Yields ``{"type": "token", "text"}``, ``{"type": "tool_calls", "calls"}`` once on ``finish_reason ==
        "tool_calls"`` (arguments parsed, or raw on parse failure), and ``{"type": "finish", "reason"}``. The agent loop
        lives in ``services/chat/agent.py``.
        """
        api_key = self._get_api_key()

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Accept": "text/event-stream",
        }
        payload = {
            "model": model or self.default_model,
            "messages": messages,
            "tools": tools,
            "max_tokens": kwargs.get("max_tokens", 16384),
            "temperature": kwargs.get("temperature", 0.2),
            "top_p": kwargs.get("top_p", 0.9),
            "stream": True,
        }

        response = requests.post(self.url, headers=headers, json=payload, stream=True, timeout=180)
        _raise_for_status_loud(response, model or self.default_model)

        # Tool calls stream as deltas keyed by index with partial id/name/arguments; accumulate until finish.
        pending_calls: dict[int, dict] = {}
        finish_reason: str | None = None

        for line in response.iter_lines():
            if not line:
                continue
            decoded = line.decode("utf-8")
            if not decoded.startswith("data: "):
                continue
            data = decoded[6:]
            if data.strip() == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except json.JSONDecodeError:
                continue
            choices = chunk.get("choices") or []
            if not choices:
                continue
            choice = choices[0]
            delta = choice.get("delta") or {}

            content = delta.get("content")
            if content:
                yield {"type": "token", "text": content}

            # Providers use ``reasoning`` or ``reasoning_content``.
            reasoning = delta.get("reasoning") or delta.get("reasoning_content")
            if reasoning:
                yield {"type": "reasoning", "text": reasoning}

            for tc in delta.get("tool_calls") or []:
                idx = tc.get("index", 0)
                slot = pending_calls.setdefault(idx, {"id": None, "name": None, "arguments": ""})
                if tc.get("id"):
                    slot["id"] = tc["id"]
                fn = tc.get("function") or {}
                if fn.get("name"):
                    slot["name"] = fn["name"]
                if fn.get("arguments") is not None:
                    slot["arguments"] += fn["arguments"]

            if choice.get("finish_reason"):
                finish_reason = choice["finish_reason"]

        if pending_calls:
            calls = []
            for idx in sorted(pending_calls.keys()):
                slot = pending_calls[idx]
                try:
                    parsed_args = json.loads(slot["arguments"]) if slot["arguments"] else {}
                except json.JSONDecodeError:
                    parsed_args = {"_raw": slot["arguments"]}
                calls.append(
                    {
                        "id": slot["id"] or f"call_{idx}",
                        "name": slot["name"] or "",
                        "arguments": parsed_args,
                    }
                )
            yield {"type": "tool_calls", "calls": calls}

        yield {"type": "finish", "reason": finish_reason or "stop"}


openrouter = LLMClient(
    url="https://openrouter.ai/api/v1/chat/completions",
    env_var="OPEN_ROUTER_KEY",
    # gemini-2.0-flash-001 was delisted; 2.5-flash-lite is the same-price successor.
    default_model="google/gemini-2.5-flash-lite",
)

# Separate env so the agent is tuned independently of scope extraction.
AGENT_MODEL = os.getenv("PSAT_AGENT_MODEL", "z-ai/glm-4.6")


def chat(messages: list[dict], **kwargs) -> str:
    return openrouter.chat(messages, **kwargs)
