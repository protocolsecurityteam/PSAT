import { lazy, Suspense, useEffect, useMemo, useRef, useState } from "react";

import { streamAgentChat } from "../../api/agent.js";

// react-markdown + remark-gfm together are ~80 KB of compiled JS that
// only matters once the user actually opens the Agent tab AND sends a
// message. Lazy-load them so cold Surface entry doesn't pay the parse
// cost. The fallback for the suspense boundary is the raw text — good
// enough until the chunk arrives, since the bubble already has the
// content as plain text from the stream.
const MarkdownBubble = lazy(() => import("./MarkdownBubble.jsx"));

const SUGGESTIONS = [
  "What's the worst thing that can happen if 1 EOA is compromised?",
  "Who controls upgrades?",
  "What audits cover the current implementation?",
  "What can the owner do unilaterally?",
  "Are there any unaudited upgrades?",
];

// Custom markdown renderer that turns the agent's `[label](0xADDR)` links
// into in-app focus buttons. Any href matching a 40-hex address (with or
// without 0x prefix, with or without leading #) becomes a click target
// that highlights the address on the canvas. Anything else falls back to
// a normal external link.
const ADDR_HREF = /^#?(0x[a-fA-F0-9]{40})$/;

function makeMarkdownComponents(onFocusAddress) {
  return {
    a({ href = "", children, ...rest }) {
      const m = href.match(ADDR_HREF);
      if (m) {
        const addr = m[1].toLowerCase();
        return (
          <button
            type="button"
            className="agent-link agent-link-addr"
            title={addr}
            onClick={(e) => {
              e.preventDefault();
              if (onFocusAddress) onFocusAddress(addr);
            }}
          >
            {children}
          </button>
        );
      }
      return (
        <a {...rest} href={href} target="_blank" rel="noreferrer">
          {children}
        </a>
      );
    },
  };
}

// Friendly type word for a principal selection's header. Falls back to
// "Principal" for anything without a dedicated word (proxy_admin, unknown, …).
function principalTypeWord(type) {
  if (type === "safe") return "Safe";
  if (type === "timelock") return "Timelock";
  if (type === "eoa") return "EOA";
  return "Principal";
}

export function AgentPanel({ companyName, selectedMachine, selectedPrincipal, onHighlight, onFocusAddress }) {
  // Messages are flat for the LLM (role/content), but the UI also
  // interleaves tool-call cards. Each "turn" is { role, content, toolCalls }
  // where toolCalls is an ordered list of { id, name, args, result?, error? }.
  const [turns, setTurns] = useState([]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [error, setError] = useState(null);
  // expandedReasoning: Set<turnIndex> — which assistant turns have their
  // reasoning section expanded. Reasoning is collapsed by default with a
  // fixed-height preview so the chat doesn't grow unboundedly.
  const [expandedReasoning, setExpandedReasoning] = useState(() => new Set());
  const abortRef = useRef(null);
  const scrollRef = useRef(null);
  // Only auto-scroll while the user is parked at the bottom. If they've
  // scrolled up to read history, leave their position alone — otherwise
  // every streamed token yanks them back down.
  const stickToBottomRef = useRef(true);

  // The selection the chat asks about. A principal selection (safe/timelock/
  // EOA) carries no `machine`, so key off whichever facet is selected — the
  // backend chat accepts either kind of address. Header + payload both derive
  // from this so the LLM's context matches what the sidebar shows.
  const selectedAddress = selectedPrincipal?.address || selectedMachine?.address || null;
  let contextName = companyName;
  let contextMeta = null;
  if (selectedPrincipal) {
    contextName = principalTypeWord(selectedPrincipal.type);
    const short = selectedPrincipal.address ? `${selectedPrincipal.address.slice(0, 8)}…` : "";
    const threshold = selectedPrincipal.details?.threshold;
    const owners = selectedPrincipal.details?.owners?.length;
    const thr = threshold && owners ? ` (${threshold}/${owners})` : threshold ? ` (${threshold})` : "";
    contextMeta = `${short}${thr}`.trim() || null;
  } else if (selectedMachine) {
    contextName = selectedMachine.name || companyName;
    contextMeta = selectedMachine.address ? `${selectedMachine.address.slice(0, 8)}…` : null;
  }

  function handleScroll() {
    const el = scrollRef.current;
    if (!el) return;
    const slack = 40;
    stickToBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < slack;
  }

  useEffect(() => {
    if (scrollRef.current && stickToBottomRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [turns, streaming]);

  function toggleReasoning(idx) {
    setExpandedReasoning((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  }

  function stop() {
    // AbortController.abort() unwinds the fetch + ReadableStream; the
    // .catch in send() swallows the AbortError so we don't surface it as
    // a normal failure. Whatever tokens already streamed stay in the
    // turn — the user keeps the partial answer.
    if (abortRef.current) abortRef.current.abort();
  }

  // Reset highlights when the selected entity changes so the previous answer's
  // mentions don't linger on the canvas. Keyed on the selected ADDRESS (machine
  // or principal), not selectedMachine alone — a principal selection has no
  // machine, so the old key never fired for safe→safe transitions. The parent
  // also clears agent highlights on every committed selection (so the reset
  // still happens while this panel is unmounted); this covers changes that land
  // while the tab is open.
  useEffect(() => {
    if (onHighlight) onHighlight(new Set());
  }, [selectedAddress, onHighlight]);

  // Cancel any in-flight request when the panel unmounts.
  useEffect(() => () => abortRef.current?.abort(), []);

  const llmHistory = useMemo(
    () =>
      turns
        .map((t) => {
          if (t.role === "user") {
            return t.content ? { role: "user", content: t.content } : null;
          }
          // Concatenate this turn's text blocks into a single content
          // string for the LLM — the model doesn't care about visual
          // interleaving, just the cumulative text.
          const text = (t.blocks || [])
            .filter((b) => b.type === "text")
            .map((b) => b.text)
            .join("");
          return text ? { role: "assistant", content: text } : null;
        })
        .filter(Boolean),
    [turns],
  );

  async function send(text) {
    const trimmed = (text ?? input).trim();
    if (!trimmed || streaming) return;
    setError(null);
    setInput("");

    // Each assistant turn is a sequence of `blocks` interleaved in
    // chronological order: { type: "text", text } and
    // { type: "tool", id, name, args, result? }. The view just iterates
    // blocks top-down so the visual order matches the model's actual
    // pacing (text → tool → text → tool → text), instead of the prior
    // "all text first, all tools after" layout.
    const userTurn = { role: "user", content: trimmed };
    const assistantTurn = { role: "assistant", reasoning: "", blocks: [] };
    setTurns((prev) => [...prev, userTurn, assistantTurn]);
    setStreaming(true);

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      await streamAgentChat(
        {
          company: companyName,
          message: trimmed,
          selected_address: selectedAddress,
          selected_chain: selectedMachine?.chain || null,
          history: llmHistory,
        },
        (evt) => {
          if (evt.event === "token") {
            const text = evt.data?.text || "";
            setTurns((prev) => {
              const next = prev.slice();
              const last = { ...next[next.length - 1] };
              const blocks = (last.blocks || []).slice();
              const tail = blocks[blocks.length - 1];
              if (tail && tail.type === "text") {
                blocks[blocks.length - 1] = { ...tail, text: tail.text + text };
              } else {
                blocks.push({ type: "text", text });
              }
              last.blocks = blocks;
              next[next.length - 1] = last;
              return next;
            });
          } else if (evt.event === "reasoning") {
            const text = evt.data?.text || "";
            setTurns((prev) => {
              const next = prev.slice();
              const last = { ...next[next.length - 1] };
              last.reasoning = (last.reasoning || "") + text;
              next[next.length - 1] = last;
              return next;
            });
          } else if (evt.event === "tool_call_start") {
            setTurns((prev) => {
              const next = prev.slice();
              const last = { ...next[next.length - 1] };
              const blocks = (last.blocks || []).slice();
              blocks.push({
                type: "tool",
                id: evt.data.id,
                name: evt.data.name,
                args: evt.data.arguments,
              });
              last.blocks = blocks;
              next[next.length - 1] = last;
              return next;
            });
          } else if (evt.event === "tool_call_result") {
            setTurns((prev) => {
              const next = prev.slice();
              const last = { ...next[next.length - 1] };
              last.blocks = (last.blocks || []).map((b) =>
                b.type === "tool" && b.id === evt.data.id
                  ? { ...b, result: evt.data.result }
                  : b,
              );
              next[next.length - 1] = last;
              return next;
            });
          } else if (evt.event === "highlights") {
            const addrs = new Set((evt.data?.addresses || []).map((a) => a.toLowerCase()));
            if (onHighlight) onHighlight(addrs);
          } else if (evt.event === "error") {
            setError(evt.data?.message || "agent error");
          }
        },
        { signal: controller.signal },
      );
    } catch (exc) {
      if (exc.name !== "AbortError") setError(exc.message || String(exc));
    } finally {
      setStreaming(false);
      abortRef.current = null;
    }
  }

  return (
    <div className="agent-panel">
      <div className="agent-context">
        <span className="agent-context-label">Asking about</span>
        <span className="agent-context-value">
          {contextName}
          {contextMeta && (
            <span className="agent-context-meta"> · {contextMeta}</span>
          )}
        </span>
      </div>

      <div className="agent-scroll" ref={scrollRef} onScroll={handleScroll}>
        {turns.length === 0 && (
          <div className="agent-suggestions">
            <div className="agent-suggestions-hdr">Try asking</div>
            {SUGGESTIONS.map((q) => (
              <button
                key={q}
                type="button"
                className="agent-suggestion"
                onClick={() => send(q)}
                disabled={streaming}
              >
                {q}
              </button>
            ))}
          </div>
        )}

        {turns.map((turn, i) => (
          <div key={i} className={`agent-msg agent-msg-${turn.role}`}>
            {turn.role === "user" ? (
              <div className="agent-bubble">{turn.content}</div>
            ) : (
              <div className="agent-asst">
                {turn.reasoning && (
                  <Reasoning
                    text={turn.reasoning}
                    expanded={expandedReasoning.has(i)}
                    onToggle={() => toggleReasoning(i)}
                    active={streaming && i === turns.length - 1}
                  />
                )}
                {(turn.blocks || []).map((b, j) =>
                  b.type === "text" ? (
                    <div key={j} className="agent-bubble">
                      <Suspense fallback={<span className="agent-bubble-fallback">{b.text}</span>}>
                        <MarkdownBubble
                          text={b.text}
                          components={makeMarkdownComponents(onFocusAddress)}
                        />
                      </Suspense>
                    </div>
                  ) : (
                    <ToolCallCard key={b.id || j} call={b} />
                  ),
                )}
                {!turn.blocks?.length
                  && !turn.reasoning
                  && streaming
                  && i === turns.length - 1 && <ThinkingDots />}
              </div>
            )}
          </div>
        ))}

        {error && <div className="agent-error">⚠ {error}</div>}
      </div>

      <form
        className="agent-input"
        onSubmit={(e) => {
          e.preventDefault();
          send();
        }}
      >
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={streaming ? "…" : "Ask about this protocol"}
          disabled={streaming}
          rows={2}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              send();
            }
          }}
        />
        {streaming ? (
          <button type="button" className="agent-stop-btn" onClick={stop}>
            Stop
          </button>
        ) : (
          <button type="submit" disabled={!input.trim()}>
            Send
          </button>
        )}
      </form>
    </div>
  );
}

function Reasoning({ text, expanded, onToggle, active }) {
  return (
    <div className={`agent-reasoning${expanded ? " is-expanded" : ""}`}>
      <button type="button" className="agent-reasoning-hdr" onClick={onToggle}>
        <span className="agent-reasoning-toggle">{expanded ? "▾" : "▸"}</span>
        <span>Thinking</span>
        {active && (
          <span className="agent-reasoning-dots" aria-hidden="true">
            <span className="agent-thinking-dot" />
            <span className="agent-thinking-dot" />
            <span className="agent-thinking-dot" />
          </span>
        )}
      </button>
      <div className="agent-reasoning-body">{text}</div>
    </div>
  );
}

function ThinkingDots() {
  return (
    <div className="agent-thinking">
      <span className="agent-thinking-dot" />
      <span className="agent-thinking-dot" />
      <span className="agent-thinking-dot" />
    </div>
  );
}

function ToolCallCard({ call }) {
  const [open, setOpen] = useState(false);
  const argsPreview = useMemo(() => {
    if (!call.args || Object.keys(call.args).length === 0) return "";
    return JSON.stringify(call.args).replace(/[\{\}"]/g, "").slice(0, 60);
  }, [call.args]);
  const status = call.result === undefined ? "running" : call.result?.error ? "error" : "ok";
  return (
    <div className={`agent-tool agent-tool-${status}`}>
      <button type="button" className="agent-tool-hdr" onClick={() => setOpen((o) => !o)}>
        <span className="agent-tool-icon">{status === "running" ? "⏳" : status === "error" ? "✕" : "✓"}</span>
        <span className="agent-tool-name">{call.name}</span>
        {argsPreview && <span className="agent-tool-args">({argsPreview})</span>}
        <span className="agent-tool-toggle">{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <div className="agent-tool-body">
          <div className="agent-tool-section">
            <div className="agent-tool-label">arguments</div>
            <pre>{JSON.stringify(call.args || {}, null, 2)}</pre>
          </div>
          {call.result !== undefined && (
            <div className="agent-tool-section">
              <div className="agent-tool-label">result</div>
              <pre>{JSON.stringify(call.result, null, 2)}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
