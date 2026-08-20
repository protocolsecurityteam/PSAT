import React, { useCallback, useEffect, useState } from "react";
import { api } from "../api/client.js";
import { useIsAdmin } from "../api/useIsAdmin.js";

// A link href is only safe to hand to the browser when it is http(s); a
// `javascript:`/`data:` value would execute on click. Returns the URL when it
// is safe to link, otherwise null so the caller renders it as inert text.
export function safeHttpUrl(value) {
  if (typeof value !== "string" || value.length === 0) return null;
  try {
    const scheme = new URL(value, window.location.origin).protocol;
    return scheme === "http:" || scheme === "https:" ? value : null;
  } catch {
    return null;
  }
}

// Admin-only audits manager. Lists every AuditReport for a company,
// shows extraction + scope state at a glance, and provides three
// admin actions per row: re-extract scope, refresh coverage (protocol-
// wide), delete. An add-audit form up top inserts a new row which the
// standing workers will claim on their next poll (text → scope →
// coverage pipeline). Read-only endpoints are safe for non-admin
// viewers; mutating actions prompt for the admin key on 401.
export default function AuditsAdminModal({ companyName, onClose }) {
  const isAdmin = useIsAdmin();
  const [audits, setAudits] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(null); // {auditId, kind}
  const [form, setForm] = useState({
    url: "",
    pdf_url: "",
    auditor: "",
    title: "",
    date: "",
    source_repo: "",
  });
  const [adding, setAdding] = useState(false);
  const [addResult, setAddResult] = useState(null);

  const refresh = useCallback(() => {
    let cancelled = false;
    api(`/api/company/${encodeURIComponent(companyName)}/audits`)
      .then((d) => { if (!cancelled) setAudits(d); })
      .catch((e) => { if (!cancelled) setError(e.message); });
    return () => { cancelled = true; };
  }, [companyName]);

  useEffect(() => {
    const cleanup = refresh();
    return cleanup;
  }, [refresh]);

  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose?.(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const onAdd = async (e) => {
    e.preventDefault();
    if (!form.url || !form.auditor || !form.title) return;
    setAdding(true);
    setAddResult(null);
    try {
      const payload = {
        url: form.url.trim(),
        pdf_url: form.pdf_url.trim() || null,
        auditor: form.auditor.trim(),
        title: form.title.trim(),
        date: form.date.trim() || null,
        source_repo: form.source_repo.trim() || null,
      };
      const res = await api(`/api/company/${encodeURIComponent(companyName)}/audits`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      setAddResult({ ok: true, id: res?.id });
      setForm({ url: "", pdf_url: "", auditor: "", title: "", date: "", source_repo: "" });
      refresh();
    } catch (err) {
      setAddResult({ ok: false, error: err?.message || String(err) });
    } finally {
      setAdding(false);
    }
  };

  const onReextract = async (auditId) => {
    setBusy({ auditId, kind: "reextract" });
    try {
      await api(`/api/audits/${auditId}/reextract_scope`, { method: "POST" });
      refresh();
    } catch (err) {
      window.alert(`Re-extract failed: ${err?.message || err}`);
    } finally {
      setBusy(null);
    }
  };

  const onRefreshCoverage = async () => {
    setBusy({ auditId: null, kind: "coverage" });
    try {
      await api(
        `/api/company/${encodeURIComponent(companyName)}/refresh_coverage`,
        { method: "POST" },
      );
      refresh();
    } catch (err) {
      window.alert(`Refresh coverage failed: ${err?.message || err}`);
    } finally {
      setBusy(null);
    }
  };

  const onDelete = async (audit) => {
    const ok = window.confirm(
      `Delete audit "${audit.title}" (${audit.auditor})? This also removes its coverage rows.`,
    );
    if (!ok) return;
    setBusy({ auditId: audit.id, kind: "delete" });
    try {
      await api(`/api/audits/${audit.id}`, { method: "DELETE" });
      refresh();
    } catch (err) {
      window.alert(`Delete failed: ${err?.message || err}`);
    } finally {
      setBusy(null);
    }
  };

  const statusChip = (label, value) => {
    let tone = "pending";
    if (value === "success") tone = "ok";
    else if (value === "failed") tone = "err";
    else if (value === "processing") tone = "processing";
    else if (value === "skipped") tone = "pending";
    return (
      <span className={`ps-addresses-modal-chip ${tone}`} title={value || "pending"}>
        {label}: {value || "pending"}
      </span>
    );
  };

  return (
    <div className="ps-audit-modal-backdrop" onClick={onClose}>
      <div
        className="ps-audit-modal ps-addresses-modal"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
      >
        <div className="ps-audit-modal-header">
          <div>
            <p className="eyebrow" style={{ margin: 0 }}>Audits · Admin</p>
            <h2 style={{ margin: "4px 0 0", fontSize: 18 }}>
              {audits ? `${audits.audit_count} reports` : "Loading…"}
              <span style={{ color: "#94a3b8", fontWeight: 400, marginLeft: 8 }}>
                {companyName}
              </span>
            </h2>
          </div>
          <div className="ps-audit-modal-actions">
            {isAdmin && (
              <button
                type="button"
                className="ps-audit-modal-btn"
                onClick={onRefreshCoverage}
                disabled={busy?.kind === "coverage"}
                title="Rebuild audit_contract_coverage rows for every scoped audit"
              >
                {busy?.kind === "coverage" ? "Refreshing…" : "Refresh all coverage"}
              </button>
            )}
            <button type="button" className="ps-audit-modal-btn" onClick={onClose} title="Close">
              ✕
            </button>
          </div>
        </div>

        {isAdmin && (
        <form className="ps-addresses-modal-add ps-audits-admin-add" onSubmit={onAdd}>
          <input
            type="text"
            placeholder="Audit URL (PDF or landing page) *"
            value={form.url}
            onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
            disabled={adding}
          />
          <input
            type="text"
            placeholder="Auditor *"
            value={form.auditor}
            onChange={(e) => setForm((f) => ({ ...f, auditor: e.target.value }))}
            disabled={adding}
          />
          <input
            type="text"
            placeholder="Title *"
            value={form.title}
            onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))}
            disabled={adding}
          />
          <input
            type="text"
            placeholder="Date (YYYY-MM-DD)"
            value={form.date}
            onChange={(e) => setForm((f) => ({ ...f, date: e.target.value }))}
            disabled={adding}
          />
          <input
            type="text"
            placeholder="source_repo (owner/repo)"
            value={form.source_repo}
            onChange={(e) => setForm((f) => ({ ...f, source_repo: e.target.value }))}
            disabled={adding}
          />
          <button type="submit" disabled={adding || !form.url || !form.auditor || !form.title}>
            {adding ? "Adding…" : "Add audit"}
          </button>
          {addResult && (
            <span className={`ps-addresses-modal-result ${addResult.ok ? "ok" : "err"}`}>
              {addResult.ok ? `Added audit #${addResult.id}` : addResult.error}
            </span>
          )}
        </form>
        )}

        <div className="ps-addresses-modal-body">
          {error && <p className="ps-audit-modal-empty">Failed to load: {error}</p>}
          {!error && !audits && <p className="ps-audit-modal-empty">Loading audits…</p>}
          {audits && audits.audits.length === 0 && (
            <p className="ps-audit-modal-empty">No audits on file for this protocol.</p>
          )}
          {audits && audits.audits.length > 0 && (
            <table className="ps-addresses-modal-table">
              <thead>
                <tr>
                  <th style={{ width: 55 }}>ID</th>
                  <th>Auditor / Title</th>
                  <th style={{ width: 100 }}>Date</th>
                  <th style={{ width: 260 }}>Status</th>
                  {isAdmin && <th style={{ width: 230 }}>Actions</th>}
                </tr>
              </thead>
              <tbody>
                {audits.audits.map((a) => (
                  <tr key={a.id}>
                    <td className="ps-addresses-modal-rank">{a.id}</td>
                    <td className="ps-addresses-modal-name">
                      <div className="ps-addresses-modal-name-line">
                        <span>{a.auditor}</span>
                      </div>
                      <div style={{ fontSize: 11, color: "#94a3b8", marginTop: 2 }}>
                        {a.title}
                      </div>
                      <div style={{ fontSize: 10, marginTop: 3 }}>
                        {(() => {
                          const raw = a.pdf_url || a.url;
                          const href = safeHttpUrl(raw);
                          return href ? (
                            <a
                              href={href}
                              target="_blank"
                              rel="noreferrer"
                              style={{ color: "#2dd4bf" }}
                            >
                              {raw}
                            </a>
                          ) : (
                            <span style={{ color: "#94a3b8" }}>{raw}</span>
                          );
                        })()}
                      </div>
                    </td>
                    <td style={{ fontSize: 11, color: "#94a3b8" }}>{a.date || "—"}</td>
                    <td>
                      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                        {statusChip("text", a.text_extraction_status)}
                        {statusChip("scope", a.scope_extraction_status)}
                        <span style={{ fontSize: 10, color: "#64748b" }}>
                          {a.scope_contract_count} contracts
                          {(a.reviewed_commits?.length ?? 0) > 0
                            ? ` · ${a.reviewed_commits.length} commits`
                            : ""}
                        </span>
                      </div>
                    </td>
                    {isAdmin && (
                      <td>
                        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                          <button
                            type="button"
                            className="ps-audit-modal-btn"
                            onClick={() => onReextract(a.id)}
                            disabled={
                              (busy?.auditId === a.id && busy?.kind === "reextract") ||
                              a.text_extraction_status !== "success"
                            }
                            title={
                              a.text_extraction_status !== "success"
                                ? "Text must extract successfully first"
                                : "Reset scope-extraction state; worker will re-pick"
                            }
                          >
                            {busy?.auditId === a.id && busy?.kind === "reextract"
                              ? "…"
                              : "Re-scope"}
                          </button>
                          <button
                            type="button"
                            className="ps-audit-modal-btn"
                            onClick={() => onDelete(a)}
                            disabled={busy?.auditId === a.id && busy?.kind === "delete"}
                            style={{ color: "#f87171", borderColor: "rgba(248, 113, 113, 0.35)" }}
                          >
                            {busy?.auditId === a.id && busy?.kind === "delete" ? "…" : "Delete"}
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
