// SSE over fetch: EventSource only supports GET and the endpoint takes a JSON
// body. Calls onEvent({event, data}) per record; pass an AbortSignal to cancel.

import { adminKeyHeaders } from "./client.js";

async function postChat(body, signal) {
  const res = await fetch("/api/agent/chat", {
    method: "POST",
    headers: await adminKeyHeaders({ "Content-Type": "application/json", Accept: "text/event-stream" }),
    body: JSON.stringify(body),
    signal,
  });
  if (res.status === 401) window.dispatchEvent(new Event("psat:auth-required"));
  return res;
}

export async function streamAgentChat(body, onEvent, { signal } = {}) {
  const res = await postChat(body, signal);
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`agent chat failed: ${res.status} ${text}`);
  }
  if (!res.body) throw new Error("no response body");

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  // Records split on "\n\n"; only `event:` and `data:` fields matter.
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let sep;
    while ((sep = buffer.indexOf("\n\n")) !== -1) {
      const raw = buffer.slice(0, sep);
      buffer = buffer.slice(sep + 2);
      const evt = parseSSERecord(raw);
      if (evt) onEvent(evt);
    }
  }
}

function parseSSERecord(raw) {
  if (!raw.trim()) return null;
  let event = "message";
  const dataLines = [];
  for (const line of raw.split("\n")) {
    if (line.startsWith("event:")) event = line.slice(6).trim();
    else if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
  }
  if (!dataLines.length) return null;
  let data = null;
  try { data = JSON.parse(dataLines.join("\n")); }
  catch { data = dataLines.join("\n"); }
  return { event, data };
}
