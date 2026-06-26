// Shared job-pipeline vocabulary for the /monitor page: stage ordering,
// stage/status colors, and the per-stage metric humanization that drives the
// drill-in's metric chips. Imported by both the runs-table StageProgress bar
// (PipelineDashboard) and the docked stage timeline (JobDetailPanel) so the
// two surfaces never drift.

// The CORE contract path — the 6-segment progress bar in the runs tables and
// the synthesized PENDING rows in the timeline. dapp_crawl/defillama_scan are
// company-discovery child stages (not on the per-contract path) and `done` is
// terminal, so neither belongs here.
export const CORE_STAGES = ["discovery", "selection", "static", "resolution", "policy", "coverage"];

// Full pipeline order, including the company-discovery children and `done`.
// The stage timeline iterates server timings in THIS order, not alphabetical
// (the old panel's Object.entries().sort() bug).
export const JOB_STAGE_ORDER = [
  "discovery",
  "dapp_crawl",
  "defillama_scan",
  "selection",
  "static",
  "resolution",
  "policy",
  "coverage",
  "done",
];

export const STAGE_COLORS = {
  discovery: "#0f766e",
  dapp_crawl: "#0e7490",
  defillama_scan: "#0891b2",
  selection: "#6366f1",
  static: "#d97706",
  resolution: "#2563eb",
  policy: "#7c3aed",
  coverage: "#059669",
  done: "#16a34a",
};

export const STATUS_COLORS = {
  queued: "#94a3b8",
  processing: "#f59e0b",
  completed: "#22c55e",
  failed: "#ef4444",
  failed_terminal: "#b91c1c",
};

export function formatStageLabel(stage) {
  return String(stage || "").replaceAll("_", " ").toUpperCase();
}

// CORE index for the progress bar. Non-core company stages clamp to discovery
// (index 0); `done` returns CORE_STAGES.length so every segment reads filled.
export function coreIndexForStage(stage) {
  const i = CORE_STAGES.indexOf(stage);
  if (i !== -1) return i;
  if (stage === "done") return CORE_STAGES.length;
  return 0;
}

// Metric-key → chip label. Order here is also the chip render order (known
// keys first, in this sequence; unknown keys fall to the end). Matches the
// per-stage metrics catalog the workers emit via record_stage_metric.
const METRIC_LABELS = {
  // discovery
  contracts_discovered: "contracts",
  audit_reports: "audit reports",
  source_files: "source files",
  // dapp_crawl / defillama_scan
  contracts_found: "contracts found",
  // selection
  ranked_candidates: "ranked",
  queued: "queued",
  // static
  is_proxy: "is_proxy",
  static_dependencies: "static deps",
  dynamic_dependencies: "dynamic deps",
  dependencies: "unique deps",
  discovered_addresses: "discovered",
  // resolution
  controllers_resolved: "controllers",
  block_number: "block",
  graph_nodes: "nodes",
  graph_edges: "edges",
  // policy
  effective_functions: "functions",
  principals_labeled: "principals",
  enrolled: "enrolled",
  // coverage
  coverage_rows: "coverage rows",
};

const METRIC_ORDER = Object.keys(METRIC_LABELS);

export function humanizeMetricLabel(key) {
  return METRIC_LABELS[key] || String(key).replaceAll("_", " ");
}

// Compact block-number rendering, e.g. 19234567 → "19.23M".
export function formatBlockNumber(value) {
  const num = Number(value);
  if (!Number.isFinite(num)) return String(value);
  if (num >= 1e6) return `${(num / 1e6).toFixed(2)}M`;
  if (num >= 1e3) return `${(num / 1e3).toFixed(1)}K`;
  return String(num);
}

export function formatMetricValue(key, value) {
  if (key === "is_proxy") return value ? "✓" : "✗";
  if (key === "block_number") return formatBlockNumber(value);
  return String(value);
}

// Stable, catalog-ordered [key, value] pairs for a stage's metrics blob.
export function orderedMetricEntries(metrics) {
  if (!metrics || typeof metrics !== "object") return [];
  return Object.entries(metrics)
    .filter(([, v]) => v !== null && v !== undefined)
    .sort((a, b) => {
      const ia = METRIC_ORDER.indexOf(a[0]);
      const ib = METRIC_ORDER.indexOf(b[0]);
      return (ia < 0 ? 999 : ia) - (ib < 0 ? 999 : ib);
    });
}
