import React, { useEffect, useRef, useState } from "react";

import { api } from "../api/client.js";
import { Modal, ModalTitle } from "../shared/Modal.jsx";
import { LABEL_NAME_MAX, MAX_ROWS, buildPreview, mergeResults } from "./csv.js";

const CHECK_CHIP = {
  ready: ["ok", "ready"],
  chain_unchecked: ["", "chain unchecked"],
  invalid_address: ["err", "invalid address"],
  unknown_chain: ["err", "unknown chain"],
  chain_not_enabled: ["err", "chain not enabled"],
  duplicate: ["pending", "duplicate"],
};

const CHECK_WHY = {
  invalid_address: () => "not 20-byte hex",
  unknown_chain: (r) => `“${r.chain}” is not a known chain`,
  chain_not_enabled: (r) => `${r.chain} is not enabled on this deployment`,
  duplicate: (r) => `same as row ${r.duplicateOf} · not sent`,
  chain_unchecked: () => "the server checks the chain",
};

const SUMMARY_ORDER = ["ready", "chain_unchecked", "invalid_address", "unknown_chain", "chain_not_enabled", "duplicate"];

function readText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ""));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });
}

function Chip({ tone, children }) {
  return <span className={`tag tag-pill ps-addresses-modal-chip${tone ? ` ${tone}` : ""}`}>{children}</span>;
}

function Why({ children }) {
  return children ? <div className="ps-addresses-modal-addr ps-bulk-import-why">{children}</div> : null;
}

function CheckCell({ row }) {
  const [tone, text] = CHECK_CHIP[row.check];
  let why = CHECK_WHY[row.check]?.(row);
  if (!why && row.nameTooLong) why = `name over ${LABEL_NAME_MAX} characters; no label will be saved`;
  return (
    <>
      <Chip tone={tone}>{text}</Chip>
      <Why>{why}</Why>
    </>
  );
}

// The endpoint commits row by row, so a 5xx or a dropped connection can follow
// queued rows: resending the file would queue them twice.
function submitErrorMessage(err) {
  if (!err?.status || err.status >= 500) {
    return {
      partial: true,
      text: "The import stopped before the server answered. Some rows may already be queued: check the jobs list before importing this file again.",
    };
  }
  if (Array.isArray(err.detail)) {
    const parts = err.detail.map((d) => {
      const where = Array.isArray(d?.loc) ? d.loc.filter((p) => p !== "body").join(".") : "";
      return `${where ? `${where}: ` : ""}${d?.msg || JSON.stringify(d)}`;
    });
    return { partial: false, text: parts.join("; ") };
  }
  return { partial: false, text: err.message || String(err) };
}

function labelNote(label) {
  if (label === "set") return " · name saved as label";
  if (label === "kept_existing") return " · existing label kept";
  if (label === "skipped_too_long") return ` · name over ${LABEL_NAME_MAX} characters, no label saved`;
  if (label === "not_set") return " · label could not be saved";
  return "";
}

function ResultCell({ row }) {
  if (row.outcome === "queued") {
    return (
      <>
        <Chip tone="processing">queued</Chip>
        <Why>{`job ${row.result.job_id.slice(0, 8)}${labelNote(row.result.label)}`}</Why>
      </>
    );
  }
  if (row.outcome === "rejected") {
    return (
      <>
        <Chip tone="err">rejected</Chip>
        <Why>{row.result.reason}</Why>
      </>
    );
  }
  let why = CHECK_CHIP[row.check][1];
  if (row.outcome === "duplicate") why = row.result.reason;
  else if (row.check === "duplicate") why = `duplicate of row ${row.duplicateOf}`;
  return (
    <>
      <Chip>not sent</Chip>
      <Why>{why}</Why>
    </>
  );
}

function RowsTable({ rows, results }) {
  return (
    <table className="ps-addresses-modal-table">
      <thead>
        <tr>
          <th>Row</th>
          <th>Name</th>
          <th>Address</th>
          <th>Chain</th>
          <th>{results ? "Result" : "Check"}</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => {
          const flagged = results ? r.outcome !== "queued" : r.check !== "ready" && r.check !== "chain_unchecked";
          return (
            <tr key={r.line} className={flagged && r.check !== "duplicate" ? "ps-addresses-modal-row--missing" : ""}>
              <td className="ps-addresses-modal-rank">{r.line}</td>
              <td className="ps-addresses-modal-name">
                <div className="ps-addresses-modal-name-line">
                  {r.name || <span className="ps-bulk-import-muted">— (no name)</span>}
                </div>
              </td>
              <td className="ps-addresses-modal-addr">{r.address || <span className="ps-bulk-import-muted">—</span>}</td>
              <td>{r.chain || <span className="ps-bulk-import-muted">— (mainnet)</span>}</td>
              <td>{results ? <ResultCell row={r} /> : <CheckCell row={r} />}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

export default function BulkImportModal({ onClose }) {
  const [companies, setCompanies] = useState(null);
  const [companiesError, setCompaniesError] = useState(null);
  const [config, setConfig] = useState(undefined);
  const [company, setCompany] = useState("");
  const [file, setFile] = useState(null);
  const [preview, setPreview] = useState(null);
  const [results, setResults] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState(null);
  // Set after an answerless failure; only a newly chosen file clears it.
  const [maybePartial, setMaybePartial] = useState(false);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef(null);

  useEffect(() => {
    api("/api/companies")
      .then((names) => setCompanies(Array.isArray(names) ? names : []))
      .catch((err) => setCompaniesError(err?.message || String(err)));
    api("/api/config")
      .then((c) => setConfig(c && c.chain_spellings && Array.isArray(c.enabled_chains) ? c : null))
      .catch(() => setConfig(null));
  }, []);

  const [fileText, setFileText] = useState(null);
  // Re-derive when /api/config lands after the file was picked.
  useEffect(() => {
    if (fileText === null || config === undefined) return;
    setPreview(buildPreview(fileText, config));
  }, [fileText, config]);

  async function pickFile(next) {
    if (!next) return;
    setFile(next);
    setResults(null);
    setSubmitError(null);
    setMaybePartial(false);
    try {
      setFileText(await readText(next));
    } catch (err) {
      setFileText(null);
      setPreview({ error: `Couldn't read the file: ${err?.message || err}` });
    }
  }

  function reset() {
    setFile(null);
    setFileText(null);
    setPreview(null);
    setResults(null);
    setSubmitError(null);
    setMaybePartial(false);
    if (inputRef.current) inputRef.current.value = "";
  }

  async function queue() {
    if (!preview?.sendable?.length || !company || submitting || maybePartial) return;
    setSubmitting(true);
    setSubmitError(null);
    try {
      const response = await api("/api/analyze/bulk", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          company,
          rows: preview.sendable.map((r) => ({ address: r.address, chain: r.chain || null, name: r.name || null })),
        }),
      });
      setResults({ rows: mergeResults(preview, response), response });
    } catch (err) {
      const { partial, text } = submitErrorMessage(err);
      setSubmitError(text);
      if (partial) setMaybePartial(true);
    } finally {
      setSubmitting(false);
    }
  }

  const sendable = preview?.sendable?.length || 0;
  const rows = preview?.rows;
  let title = "Choose a CSV";
  if (results) title = `${results.response.results.length} sent`;
  else if (rows) title = `${rows.length} rows`;

  const actions = results ? (
    <button type="button" className="ps-audit-modal-btn" onClick={reset}>Import another</button>
  ) : (
    <button
      type="button"
      className="ps-audit-modal-btn primary"
      onClick={queue}
      disabled={!company || !sendable || submitting || maybePartial}
    >
      {submitting ? "Queuing…" : sendable ? `Queue ${sendable} ${sendable === 1 ? "analysis" : "analyses"}` : "Queue"}
    </button>
  );

  return (
    <Modal
      className="ps-addresses-modal"
      onClose={onClose}
      header={<ModalTitle eyebrow="Bulk import" subtitle={file?.name || ""}>{title}</ModalTitle>}
      actions={actions}
    >
      <div className="ps-addresses-modal-toolbar ps-bulk-import-toolbar">
        <label className="ps-bulk-import-company">
          Company
          <select
            value={company}
            onChange={(e) => setCompany(e.target.value)}
            disabled={!!results || !companies || submitting}
          >
            <option value="">{companies ? "Choose a company…" : "Loading…"}</option>
            {(companies || []).map((name) => (
              <option key={name} value={name}>{name}</option>
            ))}
          </select>
        </label>
        {file && (
          <button type="button" className="ps-audit-modal-btn" onClick={() => inputRef.current?.click()} disabled={!!results || submitting}>
            Replace file
          </button>
        )}
        <span className="ps-bulk-import-hint">
          address, chain, name (optional)
          {preview?.extraColumns ? ` · ${preview.extraColumns} extra column${preview.extraColumns === 1 ? "" : "s"} ignored` : ""}
        </span>
        {companiesError && <span className="ps-addresses-modal-result err">Couldn't load companies: {companiesError}</span>}
        {submitError && <span className="ps-addresses-modal-result err">{submitError}</span>}
      </div>
      <input
        ref={inputRef}
        type="file"
        accept=".csv,text/csv"
        hidden
        data-testid="bulk-import-file"
        onChange={(e) => pickFile(e.target.files?.[0])}
      />

      {preview?.error && (
        <div className="ps-addresses-modal-toolbar">
          <span className="ps-addresses-modal-result err">{preview.error}</span>
        </div>
      )}

      {rows && !results && (
        <div className="ps-addresses-modal-toolbar ps-bulk-import-summary">
          <span className="ps-bulk-import-lead">{rows.length} rows</span>
          {SUMMARY_ORDER.filter((k) => preview.counts[k]).map((k) => (
            <Chip key={k} tone={CHECK_CHIP[k][0]}>{`${preview.counts[k]} ${CHECK_CHIP[k][1]}`}</Chip>
          ))}
          <span className="ps-bulk-import-hint">
            {config ? "The server re-checks every row it is sent." : "Chain list unavailable; the server checks each chain."}
          </span>
        </div>
      )}

      {results && (
        <div className="ps-addresses-modal-toolbar ps-bulk-import-summary">
          <span className="ps-bulk-import-lead">{results.response.results.length} sent</span>
          <Chip tone="processing">{`${results.response.queued} queued`}</Chip>
          {results.response.rejected > 0 && <Chip tone="err">{`${results.response.rejected} rejected`}</Chip>}
          {rows.length - results.response.queued - results.response.rejected > 0 && (
            <Chip>{`${rows.length - results.response.queued - results.response.rejected} not sent`}</Chip>
          )}
        </div>
      )}

      {rows ? (
        <div className="ps-addresses-modal-body">
          <RowsTable rows={results ? results.rows : rows} results={!!results} />
        </div>
      ) : (
        <div
          className={`ps-bulk-import-drop${dragging ? " dragging" : ""}`}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => { e.preventDefault(); setDragging(false); pickFile(e.dataTransfer.files?.[0]); }}
        >
          <div>
            Drop a CSV here or{" "}
            <button type="button" className="ghost ps-bulk-import-choose" onClick={() => inputRef.current?.click()}>
              Choose file
            </button>
            <div className="ps-bulk-import-hint">
              header row required · columns: address, chain, name (optional) · max {MAX_ROWS} rows
            </div>
          </div>
        </div>
      )}
    </Modal>
  );
}
