import React, { useState } from "react";
import { api } from "../api/client.js";

export function ComputeRecovery({ job, groupJobs = [] }) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [moved, setMoved] = useState(false);
  const group = groupJobs.length ? groupJobs : [job];
  const hasLocal = group.some((row) => row.compute_target === "local");
  const processing = group.some((row) => row.status === "processing");
  async function move() {
    setBusy(true);
    setError("");
    try {
      await api(`/api/jobs/${job.job_id}/move-to-cloud`, { method: "POST", silent: true });
      setMoved(true);
    } catch (err) {
      setError(err.message || "The run could not be moved. Refresh and retry.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="job-panel-meta">
      <span>Compute: {moved ? "Cloud" : job.compute_target === "local" ? "Local" : "Cloud"}</span>
      {job.compute_group_id && <span title={job.compute_group_id}>Run group: {job.compute_group_id.slice(0, 8)}</span>}
      {hasLocal && !moved && (
        <button type="button" onClick={move} disabled={busy || processing} title={processing ? "Stop local workers and wait for active attempts to settle" : undefined}>
          {busy ? "Moving…" : "Move local run to cloud"}
        </button>
      )}
      {moved && <span role="status">Run moved to cloud.</span>}
      {error && <span role="alert">{error}</span>}
    </div>
  );
}
