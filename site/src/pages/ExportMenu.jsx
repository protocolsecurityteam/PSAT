import { useEffect, useRef, useState } from "react";

import { apiDownload } from "../api/client.js";

export const EXPORT_FORMATS = [
  { id: "pdf", label: "PDF", hint: "Formatted report" },
  { id: "docx", label: "Word (DOCX)", hint: "Editable report" },
  { id: "csv", label: "CSV", hint: "Tables for spreadsheets" },
  { id: "json", label: "JSON", hint: "Complete raw results" },
];

function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  // Revoked on the next tick: some browsers start the download asynchronously.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

export default function ExportMenu({ companyName }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);
  const rootRef = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    const onPointer = (event) => {
      if (!rootRef.current?.contains(event.target)) setOpen(false);
    };
    const onKey = (event) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  useEffect(() => {
    setOpen(false);
    setBusy(null);
    setError(null);
  }, [companyName]);

  const exportAs = async (format) => {
    setOpen(false);
    setBusy(format);
    setError(null);
    try {
      const path = `/api/company/${encodeURIComponent(companyName)}/export?format=${format}`;
      const { blob, filename } = await apiDownload(path);
      saveBlob(blob, filename || `psat-${companyName}.${format}`);
    } catch (e) {
      setError(e.message || "Export failed. Please try again.");
    } finally {
      setBusy(null);
    }
  };

  const busyLabel = EXPORT_FORMATS.find((f) => f.id === busy)?.label;
  return (
    <div className="company-export" ref={rootRef}>
      <button
        type="button"
        className="company-surface-action"
        aria-haspopup="menu"
        aria-expanded={open}
        disabled={busy !== null}
        onClick={() => setOpen((v) => !v)}
        title="Download this protocol's results"
      >
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M12 3v12" />
          <path d="m7 10 5 5 5-5" />
          <path d="M5 21h14" />
        </svg>
        <span>{busy ? `Exporting ${busyLabel}…` : "Export report"}</span>
      </button>
      {open && (
        <div className="company-export-menu" role="menu" aria-label="Export format">
          {EXPORT_FORMATS.map((f) => (
            <button
              key={f.id}
              type="button"
              role="menuitem"
              className="company-export-item"
              onClick={() => exportAs(f.id)}
            >
              <span className="company-export-item-label">{f.label}</span>
              <span className="company-export-item-hint">{f.hint}</span>
            </button>
          ))}
        </div>
      )}
      {error && <p className="company-export-error" role="alert">Export failed: {error}</p>}
    </div>
  );
}
