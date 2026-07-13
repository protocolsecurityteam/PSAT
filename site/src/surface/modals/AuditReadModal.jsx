import { useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";

import { formatAuditDate } from "../../auditUi.jsx";
import { dedupeShas } from "../format.js";

// Proof-first read modal (Prototype C, C5). A light, single-column view of the
// verified content only: the reviewed commit(s), the audit's declared scope,
// and the report document served through our own PDF proxy.
//
// Nothing here links out. Every external URL an audit carries — its document
// AND its `referenced_repos` — comes from AI-driven discovery, so we can't
// cryptographically vouch that it belongs to this protocol. Even a
// hardcoded-host `https://github.com/${repo}` link would embed an unverified,
// attacker-influenceable repo path, so commit SHAs render as plain chips, not
// links. The only document we show is the one streamed through our own proxy.

// commit label → accent (reviewed is the proof anchor; fix/cited are context).
const COMMIT_ACCENT = { reviewed: "#4ade80", fix: "#2dd4bf", cited: "#94a3b8" };

// Reviewed commit chips from the audit's LLM-classified commit list, falling
// back to the raw reviewed_commits scrape. Cited/unclear commits are dropped —
// they are context, not proof.
function reviewedCommits(detail) {
  const classified = Array.isArray(detail?.classified_commits) ? detail.classified_commits : [];
  const out = [];
  const seen = new Set();
  for (const c of classified) {
    if (!c || (c.label !== "reviewed" && c.label !== "fix")) continue;
    const sha = String(c.sha || "").trim().toLowerCase();
    if (!/^[0-9a-f]{7,}$/.test(sha)) continue;
    const key = sha.slice(0, 12);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ sha, label: c.label });
  }
  if (!out.length) {
    for (const sha of dedupeShas(detail?.reviewed_commits || [])) {
      out.push({ sha, label: "reviewed" });
    }
  }
  return out;
}

export function AuditReadModal({ audit, coveredCount, onClose }) {
  const [detail, setDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(true);
  const [detailError, setDetailError] = useState(null);
  const [scope, setScope] = useState(null);
  const [text, setText] = useState(null);
  const [textLoading, setTextLoading] = useState(false);
  // PDF embed failure → flip to text fallback.
  const [pdfFailed, setPdfFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setDetail(null);
    setDetailLoading(true);
    setDetailError(null);
    setScope(null);
    setText(null);
    setPdfFailed(false);
    fetch(`/api/audits/${encodeURIComponent(audit.audit_id)}`)
      .then((r) => {
        if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
        return r.json();
      })
      .then((d) => {
        if (!cancelled) { setDetail(d); setDetailLoading(false); }
      })
      .catch((e) => {
        if (!cancelled) { setDetailError(String(e.message || e)); setDetailLoading(false); }
      });
    return () => { cancelled = true; };
  }, [audit.audit_id]);

  // Declared scope — the contracts the audit itself named as in-scope. 409 when
  // scope extraction never completed; treat that as "no declared scope".
  useEffect(() => {
    let cancelled = false;
    fetch(`/api/audits/${encodeURIComponent(audit.audit_id)}/scope`)
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (!cancelled) setScope(Array.isArray(d?.contracts) ? d.contracts : []);
      })
      .catch(() => {
        if (!cancelled) setScope([]);
      });
    return () => { cancelled = true; };
  }, [audit.audit_id]);

  // Close on Escape
  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const sourceUrl = detail?.url || null;
  const rawPdfUrl = detail?.pdf_url || null;
  const urlLooksLikePdf =
    !rawPdfUrl && typeof sourceUrl === "string" && sourceUrl.toLowerCase().endsWith(".pdf");
  const pdfUrl = (rawPdfUrl || urlLooksLikePdf)
    ? `/api/audits/${encodeURIComponent(audit.audit_id)}/pdf`
    : null;
  const showPdf = !!pdfUrl && !pdfFailed;
  const needsText = !detailLoading && !showPdf;

  // Only fetch the extracted text when there's no embeddable PDF (or it
  // failed) — it's the fallback view, not the default.
  useEffect(() => {
    if (!needsText) return undefined;
    let cancelled = false;
    setTextLoading(true);
    setText(null);
    fetch(`/api/audits/${encodeURIComponent(audit.audit_id)}/text`)
      .then((r) => (r.ok ? r.text() : null))
      .then((t) => {
        if (!cancelled) { setText(t); setTextLoading(false); }
      })
      .catch(() => {
        if (!cancelled) { setText(null); setTextLoading(false); }
      });
    return () => { cancelled = true; };
  }, [audit.audit_id, needsText]);

  const commits = useMemo(() => reviewedCommits(detail), [detail]);

  // Portal to <body>: the surface sidebar sets `backdrop-filter`, which makes
  // it a containing block for our `position:fixed` overlay — without the portal
  // the modal is trapped inside the ~380px sidebar instead of centering over
  // the viewport.
  return createPortal(
    <div className="ps-audit-modal-backdrop" onClick={onClose}>
      <div className="ps-audit-modal ps-audit-modal--read" onClick={(e) => e.stopPropagation()}>
        <header className="ps-audit-modal-header">
          <div className="ps-audit-modal-header-left">
            <div className="ps-audit-modal-auditor">{audit.auditor || "Unknown auditor"}</div>
            <div className="ps-audit-modal-title">{audit.title || "Untitled audit"}</div>
            <div className="ps-audit-modal-meta">
              {formatAuditDate(audit.date)} · covers {coveredCount} contract
              {coveredCount === 1 ? "" : "s"}
            </div>
          </div>
          <div className="ps-audit-modal-actions">
            <button className="ps-audit-modal-btn" onClick={onClose} aria-label="Close">✕</button>
          </div>
        </header>

        <div className="ps-audit-read-body">
          <section>
            <div className="ps-audit-read-sec-h">Reviewed commits</div>
            {commits.length ? (
              <div className="ps-audit-read-commits">
                {commits.map(({ sha, label }) => {
                  const accent = COMMIT_ACCENT[label] || "#94a3b8";
                  return (
                    <span key={sha} className="ps-audit-read-commit" title={sha}>
                      <span
                        className="ps-audit-read-commit-lbl"
                        style={{ color: accent, background: `${accent}22` }}
                      >
                        {label}
                      </span>
                      {sha.slice(0, 7)}
                    </span>
                  );
                })}
              </div>
            ) : (
              <div className="ps-audit-modal-empty" style={{ padding: 0, textAlign: "left" }}>
                No reviewed commit recorded.
              </div>
            )}
          </section>

          {scope && scope.length > 0 && (
            <section>
              <div className="ps-audit-read-sec-h">Declared scope ({scope.length})</div>
              {scope.map((name, i) => (
                <div key={`${name}-${i}`} className="ps-audit-read-scope-row">
                  <span>{name}</span>
                  <span className="ps-audit-read-scope-tie">✓ in scope</span>
                </div>
              ))}
            </section>
          )}

          <section>
            <div className="ps-audit-read-sec-h">Report document</div>
            <div className="ps-audit-read-doc">
              {detailLoading && <div className="ps-audit-modal-empty">Loading audit…</div>}
              {!detailLoading && showPdf && (
                <iframe
                  className="ps-audit-read-iframe"
                  title="Audit PDF"
                  src={pdfUrl}
                  onError={() => setPdfFailed(true)}
                />
              )}
              {!detailLoading && !showPdf && (
                <>
                  {textLoading && <div className="ps-audit-modal-empty">Loading audit text…</div>}
                  {!textLoading && text && <pre className="ps-audit-modal-pre">{text}</pre>}
                  {!textLoading && !text && (
                    <div className="ps-audit-modal-empty">
                      No verified document available for this audit.
                    </div>
                  )}
                </>
              )}
              {detailError && (
                <div className="ps-audit-modal-empty">Failed to load audit: {detailError}</div>
              )}
            </div>
          </section>
        </div>
      </div>
    </div>,
    document.body,
  );
}
