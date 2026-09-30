import { useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";

import { formatAuditDate } from "../../audits/auditUi.jsx";
import { useResource } from "../../shared/useResource.js";
import { dedupeShas } from "../format.js";

// Proof-first read modal: reviewed commits, declared scope, and the report via
// our own PDF proxy.
//
// Nothing links out. Every external URL an audit carries (document and
// `referenced_repos`) comes from AI-driven discovery and can't be vouched for;
// even a fixed-host GitHub link would embed an attacker-influenceable path. So
// SHAs render as plain chips.

// Reviewed is the proof anchor; fix/cited are context.
const COMMIT_ACCENT = { reviewed: "#4ade80", fix: "#2dd4bf", cited: "#94a3b8" };

// Cited/unclear commits are context, not proof.
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
  const auditPath = `/api/audits/${encodeURIComponent(audit.audit_id)}`;
  const detailRes = useResource(
    () => fetch(auditPath).then((r) => {
      if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
      return r.json();
    }),
    [auditPath],
  );
  const detail = detailRes.data;
  const detailLoading = detailRes.loading;
  const detailError = detailRes.error ? String(detailRes.error.message || detailRes.error) : null;

  // 409 means scope extraction never completed: treat as no declared scope.
  const { data: scope } = useResource(
    () => fetch(`${auditPath}/scope`)
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => (Array.isArray(d?.contracts) ? d.contracts : []))
      .catch(() => []),
    [auditPath],
  );

  const [pdfFailed, setPdfFailed] = useState(false);
  useEffect(() => setPdfFailed(false), [auditPath]);

  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const sourceUrl = detail?.url || null;
  const rawPdfUrl = detail?.pdf_url || null;
  const urlLooksLikePdf =
    !rawPdfUrl && typeof sourceUrl === "string" && sourceUrl.toLowerCase().endsWith(".pdf");
  const pdfUrl = rawPdfUrl || urlLooksLikePdf ? `${auditPath}/pdf` : null;
  const showPdf = !!pdfUrl && !pdfFailed;
  const needsText = !detailLoading && !showPdf;

  // Text is only the fallback when there's no embeddable PDF.
  const { data: text, loading: textLoading } = useResource(
    () => fetch(`${auditPath}/text`).then((r) => (r.ok ? r.text() : null)).catch(() => null),
    [auditPath],
    { enabled: needsText },
  );

  const commits = useMemo(() => reviewedCommits(detail), [detail]);

  // The sidebar's `backdrop-filter` makes it the containing block for
  // position:fixed; without the portal the modal is trapped in the sidebar.
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
