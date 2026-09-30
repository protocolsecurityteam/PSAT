// Job-pipeline vocabulary shared by the runs-table bar and the stage timeline
// so they can't drift.

// The per-contract path. Company-discovery children and `done` aren't on it.
// `effects` is flag-gated: in CORE for ordering, but rendered presence-based.
export const CORE_STAGES = ["discovery", "selection", "static", "resolution", "policy", "effects", "coverage"];

// Server timings iterate in this order, not alphabetically.
export const JOB_STAGE_ORDER = [
  "discovery",
  "dapp_crawl",
  "defillama_scan",
  "selection",
  "static",
  "resolution",
  "policy",
  "effects",
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
  effects: "#c026d3",
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

// Non-core stages clamp to 0; `done` fills every segment.
export function coreIndexForStage(stage) {
  const i = CORE_STAGES.indexOf(stage);
  if (i !== -1) return i;
  if (stage === "done") return CORE_STAGES.length;
  return 0;
}

// Also the chip render order; unknown keys go last.
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
  // effects: keys match record_stage_metric in workers/effects_worker.py
  candidates_in: "candidates",
  candidates_after_cascade: "after cascade",
  cache_hits_kernel: "kernel hits",
  cache_hits_projection: "projection hits",
  cache_misses: "cache misses",
  verdicts_written: "verdicts",
  discrepancies_filed: "discrepancies",
  upstream_requests: "rpc reqs",
  peak_anvil_rss_mb: "anvil rss mb",
  // coverage
  coverage_rows: "coverage rows",
};

const METRIC_ORDER = Object.keys(METRIC_LABELS);

export function humanizeMetricLabel(key) {
  return METRIC_LABELS[key] || String(key).replaceAll("_", " ");
}

// 19234567 → "19.23M"
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
