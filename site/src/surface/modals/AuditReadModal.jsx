import { useEffect, useMemo, useState } from "react";

import { formatAuditDate } from "../../auditUi.jsx";
import { dedupeShas, shortAddr } from "../format.js";

function AuditCommitChips({ detail, maxShown = 4 }) {
  if (!detail) return null;
  const classified = Array.isArray(detail.classified_commits) ? detail.classified_commits : [];
  const reviewedList = classified.filter((c) => c && c.label === "reviewed");
  let shas;
  if (reviewedList.length) {
    shas = dedupeShas(reviewedList.map((c) => c.sha));
  } else {
    shas = dedupeShas(detail.reviewed_commits || []);
  }
  if (!shas.length) return null;

  const repo = Array.isArray(detail.referenced_repos) && detail.referenced_repos.length
    ? detail.referenced_repos[0]
    : null;

  const shown = shas.slice(0, maxShown);
  const extra = shas.length - shown.length;

  return (
    <div className="ps-audit-modal-commits">
      <span className="ps-audit-modal-commits-label">reviewed</span>
      {shown.map((sha) => {
        const short = sha.slice(0, 7);
        const href = repo ? `https://github.com/${repo}/tree/${sha}` : null;
        if (href) {
          return (
            <a
              key={sha}
              className="ps-audit-modal-commit-chip"
              href={href}
              target="_blank"
              rel="noreferrer noopener"
              title={sha}
            >
              {short}
            </a>
          );
        }
        return (
          <span key={sha} className="ps-audit-modal-commit-chip" title={sha}>{short}</span>
        );
      })}
      {extra > 0 && (
        <span className="ps-audit-modal-commit-more">+{extra} more</span>
      )}
    </div>
  );
}

export function AuditReadModal({ audit, addresses, machines, shaByAddr, onClose }) {
  const [detail, setDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(true);
  const [detailError, setDetailError] = useState(null);
  const [text, setText] = useState(null);
  const [textLoading, setTextLoading] = useState(false);
  const [textError, setTextError] = useState(null);
  // PDF embed failure → flip to text fallback.
  const [pdfFailed, setPdfFailed] = useState(false);
  // Which page to jump to in the iframe (null = default / first page).
  const [targetPage, setTargetPage] = useState(null);

  useEffect(() => {
    let cancelled = false;
    setDetail(null);
    setDetailLoading(true);
    setDetailError(null);
    setText(null);
    setPdfFailed(false);
    setTargetPage(null);
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

  // Close on Escape
  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const sourceUrl = detail?.url || audit.url || audit.source_url || null;
  const rawPdfUrl = detail?.pdf_url || audit.pdf_url || null;
  const urlLooksLikePdf = !rawPdfUrl && typeof sourceUrl === "string" && sourceUrl.toLowerCase().endsWith(".pdf");
  // Point the iframe at our proxy — external hosts (e.g. GitHub raw
  // content) send X-Frame-Options: deny which blocks inline rendering.
  const pdfUrl = (rawPdfUrl || urlLooksLikePdf)
    ? `/api/audits/${encodeURIComponent(audit.audit_id)}/pdf`
    : null;
  const downloadUrl = rawPdfUrl || (urlLooksLikePdf ? sourceUrl : null) || sourceUrl;
  const showPdf = !!pdfUrl && !pdfFailed;
  const showText = !showPdf;

  // Always fetch text — needed both for the fallback view AND to build the
  // page index so clicking a covered contract can jump to its mention.
  // Depend only on audit.audit_id so re-renders from setting textLoading
  // don't cancel the fetch mid-flight.
  useEffect(() => {
    let cancelled = false;
    setTextLoading(true);
    setTextError(null);
    setText(null);
    fetch(`/api/audits/${encodeURIComponent(audit.audit_id)}/text`)
      .then((r) => {
        if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
        return r.text();
      })
      .then((t) => {
        if (!cancelled) { setText(t); setTextLoading(false); }
      })
      .catch((e) => {
        if (!cancelled) { setTextError(String(e.message || e)); setTextLoading(false); }
      });
    return () => { cancelled = true; };
  }, [audit.audit_id]);

  // Parse "--- page N ---" markers from the extracted text into a page index.
  // Shared by both the contract-mention lookup and the commit-SHA lookup.
  const lowerPages = useMemo(() => {
    if (!text) return [];
    const pages = [];
    const re = /--- page (\d+) ---/g;
    let m;
    let last = 0;
    let lastPage = null;
    while ((m = re.exec(text)) !== null) {
      if (lastPage != null) {
        pages.push({ page: lastPage, body: text.slice(last, m.index) });
      }
      lastPage = parseInt(m[1], 10);
      last = m.index + m[0].length;
    }
    if (lastPage != null) pages.push({ page: lastPage, body: text.slice(last) });
    return pages.map((p) => ({ page: p.page, body: p.body.toLowerCase() }));
  }, [text]);

  const mentionByAddress = useMemo(() => {
    const out = new Map();
    if (!lowerPages.length) return out;
    for (const addr of addresses) {
      const lower = addr.toLowerCase();
      const short6 = lower.slice(0, 10); // 0x + first 8 hex chars — covers most PDF abbreviations
      const m2 = machines.get ? machines.get(lower) : null;
      const name = m2?.name || null;
      const nameLower = name && name.length >= 5 ? name.toLowerCase() : null;
      let found = null;
      for (const p of lowerPages) {
        if (p.body.includes(lower)
            || p.body.includes(short6)
            || (nameLower && p.body.includes(nameLower))) {
          found = p.page;
          break;
        }
      }
      out.set(addr, found);
    }
    return out;
  }, [lowerPages, addresses, machines]);

  // For each SHA we care about (the per-contract matched_commit_sha), find
  // the first page it appears on. Audits embed the SHA in either full
  // (40-char) or abbreviated (7-char) form, so try both.
  const pageBySha = useMemo(() => {
    const out = new Map();
    if (!lowerPages.length || !shaByAddr || !shaByAddr.values) return out;
    const uniq = new Set();
    for (const s of shaByAddr.values()) if (s) uniq.add(String(s).toLowerCase());
    for (const sha of uniq) {
      const short = sha.slice(0, 7);
      let found = null;
      for (const p of lowerPages) {
        if (p.body.includes(sha) || p.body.includes(short)) {
          found = p.page;
          break;
        }
      }
      out.set(sha, found);
    }
    return out;
  }, [lowerPages, shaByAddr]);

  return (
    <div className="ps-audit-modal-backdrop" onClick={onClose}>
      <div className="ps-audit-modal" onClick={(e) => e.stopPropagation()}>
        <header className="ps-audit-modal-header">
          <div className="ps-audit-modal-header-left">
            <div className="ps-audit-modal-auditor">{audit.auditor || "Unknown auditor"}</div>
            <div className="ps-audit-modal-title">{audit.title || "Untitled audit"}</div>
            <div className="ps-audit-modal-meta">
              {formatAuditDate(audit.date)} · covers {addresses.size} contract{addresses.size === 1 ? "" : "s"}
            </div>
            <AuditCommitChips detail={detail} />
          </div>
          <div className="ps-audit-modal-actions">
            {sourceUrl && (
              <a
                className="ps-audit-modal-btn"
                href={sourceUrl}
                target="_blank"
                rel="noreferrer noopener"
              >
                Source ↗
              </a>
            )}
            {downloadUrl && (
              <a
                className="ps-audit-modal-btn primary"
                href={downloadUrl}
                target="_blank"
                rel="noreferrer noopener"
                download
              >
                Download
              </a>
            )}
            <button className="ps-audit-modal-btn" onClick={onClose} aria-label="Close">✕</button>
          </div>
        </header>
        <div className="ps-audit-modal-body">
          <aside className="ps-audit-modal-aside">
            <div className="ps-audit-modal-aside-hdr">Covered contracts</div>
            <div className="ps-audit-modal-aside-hint">
              {text && mentionByAddress.size
                ? "Click a contract to jump to where it's referenced."
                : textLoading
                  ? "Indexing references…"
                  : null}
            </div>
            <div className="ps-audit-modal-aside-list">
              {[...addresses].sort().map((addr) => {
                const m = machines.get ? machines.get(addr) : null;
                const page = mentionByAddress.get(addr);
                const hasJump = !!page && showPdf;
                const isActive = targetPage === page && hasJump;
                const Tag = hasJump ? "button" : "div";
                const sha = shaByAddr && shaByAddr.get ? shaByAddr.get(addr) : null;
                const shortSha = sha ? String(sha).slice(0, 7) : null;
                const repo = Array.isArray(detail?.referenced_repos) && detail.referenced_repos.length
                  ? detail.referenced_repos[0]
                  : null;
                return (
                  <Tag
                    key={addr}
                    className={`ps-audit-modal-aside-row ${hasJump ? "clickable" : ""} ${isActive ? "active" : ""}`}
                    onClick={hasJump ? () => setTargetPage(page) : undefined}
                    type={hasJump ? "button" : undefined}
                  >
                    <div className="ps-audit-modal-aside-row-main">
                      <div className="ps-audit-modal-aside-name">{m?.name || shortAddr(addr)}</div>
                      <div className="ps-audit-modal-aside-addr">{addr}</div>
                    </div>
                    <div className="ps-audit-modal-aside-badges">
                      {page ? (
                        <span className="ps-audit-modal-aside-page" title={`Mentioned on page ${page}`}>
                          p{page}
                        </span>
                      ) : text ? (
                        <span className="ps-audit-modal-aside-page dim" title="Not found in extracted text">—</span>
                      ) : null}
                      {shortSha && (() => {
                        const shaLower = String(sha).toLowerCase();
                        const shaPage = pageBySha.get(shaLower) ?? null;
                        const shaJumpable = !!shaPage && showPdf;
                        if (shaJumpable) {
                          // Clicking jumps the PDF to the page where the SHA
                          // is referenced (like the page badge, but for the
                          // commit mention instead of the contract mention).
                          return (
                            <button
                              type="button"
                              className="ps-audit-modal-aside-sha"
                              title={`Commit ${sha} — mentioned on page ${shaPage}`}
                              onClick={(e) => {
                                e.stopPropagation();
                                setTargetPage(shaPage);
                              }}
                            >
                              {shortSha}
                            </button>
                          );
                        }
                        // Fallback: link to GitHub when the SHA isn't in the
                        // extracted text (or PDF isn't rendered).
                        if (repo) {
                          return (
                            <a
                              href={`https://github.com/${repo}/tree/${sha}`}
                              target="_blank"
                              rel="noreferrer noopener"
                              className="ps-audit-modal-aside-sha"
                              title={`Verified against commit ${sha} — open on GitHub`}
                              onClick={(e) => e.stopPropagation()}
                            >
                              {shortSha}
                            </a>
                          );
                        }
                        return (
                          <span
                            className="ps-audit-modal-aside-sha"
                            title={`Verified against commit ${sha}`}
                          >
                            {shortSha}
                          </span>
                        );
                      })()}
                    </div>
                  </Tag>
                );
              })}
            </div>
          </aside>
          <div className="ps-audit-modal-doc">
            {detailLoading && (
              <div className="ps-audit-modal-empty">Loading audit…</div>
            )}
            {!detailLoading && showPdf && (
              <iframe
                key={targetPage ?? "default"}
                className="ps-audit-modal-iframe"
                title="Audit PDF"
                src={`${pdfUrl}${targetPage ? `#page=${targetPage}` : ""}`}
                onError={() => setPdfFailed(true)}
              />
            )}
            {!detailLoading && !showPdf && (
              <>
                {textLoading && <div className="ps-audit-modal-empty">Loading audit text…</div>}
                {textError && <div className="ps-audit-modal-empty">Failed to load text: {textError}</div>}
                {text && <pre className="ps-audit-modal-pre">{text}</pre>}
                {!textLoading && !textError && !text && detail && !detail.has_text && (
                  <div className="ps-audit-modal-empty">
                    No extracted text available for this audit.
                    {sourceUrl && <> Open the <a href={sourceUrl} target="_blank" rel="noreferrer noopener">source</a> to read it.</>}
                  </div>
                )}
              </>
            )}
            {detailError && (
              <div className="ps-audit-modal-empty">Failed to load audit metadata: {detailError}</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
