// SSE over fetch: EventSource only supports GET and the endpoint takes a JSON
// body. Calls onEvent({event, data}) per record; pass an AbortSignal to cancel.

import { getAdminKey, setAdminKey } from "./client.js";

async function postWithAdminKey(body, signal) {
  const send = (key) =>
    fetch("/api/agent/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "text/event-stream",
        ...(key ? { "X-PSAT-Admin-Key": key } : {}),
      },
      body: JSON.stringify(body),
      signal,
    });

  let res = await send(getAdminKey());
  // Auth runs before streaming starts, so a 401 is safe to retry like
  // api/client.js.
  if (res.status === 401) {
    const entered = window.prompt(
      "Admin key required for the agent chat.\nPaste your PSAT admin key:",
      getAdminKey(),
    );
    if (!entered) {
      throw new Error("agent chat failed: 401 (admin key required)");
    }
    setAdminKey(entered);
    res = await send(entered);
  }
  return res;
}

export async function streamAgentChat(body, onEvent, { signal } = {}) {
  const res = await postWithAdminKey(body, signal);
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
