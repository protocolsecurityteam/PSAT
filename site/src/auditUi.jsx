// Shared audit badge vocabulary for the protocol surface and upgrades UI.
// Keep this file presentation-only: backend status semantics still live in
// api.py + services/audits/*.

export const AUDIT_STATUS_META = {
  audited: { label: "Audited", color: "#166534", bg: "#dcfce7", border: "#bbf7d0" },
  non_proxy_audited: { label: "Audited", color: "#166534", bg: "#dcfce7", border: "#bbf7d0" },
  unaudited_since_upgrade: { label: "Unaudited since upgrade", color: "#92400e", bg: "#fef3c7", border: "#fde68a" },
  non_proxy_unaudited: { label: "No audits", color: "#475569", bg: "#f1f5f9", border: "#e2e8f0" },
  never_audited: { label: "Never audited", color: "#991b1b", bg: "#fee2e2", border: "#fecaca" },
};

export const MATCH_TYPE_META = {
  reviewed_commit: { label: "bytecode verified", color: "#166534", bg: "#dcfce7", border: "#bbf7d0" },
  reviewed_address: { label: "address pinned", color: "#1e40af", bg: "#dbeafe", border: "#bfdbfe" },
  direct: { label: "name heuristic", color: "#475569", bg: "#f1f5f9", border: "#e2e8f0" },
  impl_era: { label: "upgrade-window heuristic", color: "#475569", bg: "#f1f5f9", border: "#e2e8f0" },
};

export const EQUIVALENCE_META = {
  proven: { label: "✓ proof", color: "#166534", bg: "#dcfce7", border: "#bbf7d0" },
  hash_mismatch: { label: "⚠ source differs", color: "#991b1b", bg: "#fee2e2", border: "#fecaca" },
  commit_not_found_in_repo: { label: "⚠ commit missing", color: "#991b1b", bg: "#fee2e2", border: "#fecaca" },
  candidate_path_missing: { label: "path unknown", color: "#92400e", bg: "#fef3c7", border: "#fde68a" },
  source_missing: { label: "source missing", color: "#475569", bg: "#f1f5f9", border: "#e2e8f0" },
  no_reviewed_commit: { label: "no commit in PDF", color: "#475569", bg: "#f1f5f9", border: "#e2e8f0" },
  no_source_repo: { label: "no repo recorded", color: "#475569", bg: "#f1f5f9", border: "#e2e8f0" },
  github_fetch_failed: { label: "github error", color: "#475569", bg: "#f1f5f9", border: "#e2e8f0" },
  not_attempted: { label: "not verified yet", color: "#475569", bg: "#f1f5f9", border: "#e2e8f0" },
  pending: { label: "verifying…", color: "#1e40af", bg: "#dbeafe", border: "#bfdbfe" },
  verifying: { label: "verifying…", color: "#1e40af", bg: "#dbeafe", border: "#bfdbfe" },
};

export const PROOF_KIND_META = {
  clean: { label: "✓ reviewed", color: "#166534", bg: "#dcfce7", border: "#bbf7d0" },
  post_fix: { label: "✓ fix deployed", color: "#065f46", bg: "#ccfbf1", border: "#99f6e4" },
  pre_fix_unpatched: { label: "🚨 FIX NOT SHIPPED", color: "#7f1d1d", bg: "#fecaca", border: "#f87171" },
  cited_only: { label: "? coincidental", color: "#475569", bg: "#f1f5f9", border: "#e2e8f0" },
  unclassified: { label: "unclassified", color: "#475569", bg: "#f1f5f9", border: "#e2e8f0" },
};

export const SEVERITY_META = {
  critical: { color: "#7f1d1d", bg: "#fee2e2", border: "#fca5a5" },
  high: { color: "#991b1b", bg: "#fee2e2", border: "#fecaca" },
  medium: { color: "#92400e", bg: "#fef3c7", border: "#fde68a" },
  low: { color: "#475569", bg: "#f1f5f9", border: "#e2e8f0" },
  info: { color: "#1e40af", bg: "#dbeafe", border: "#bfdbfe" },
};

export const STATUS_LABELS = {
  fixed: "fixed",
  partially_fixed: "partially fixed",
  acknowledged: "acknowledged",
  mitigated: "mitigated",
  wont_fix: "won't fix",
};

export const DRIFT_TRUE_META = { color: "#991b1b", bg: "#fee2e2", border: "#fecaca" };
export const DRIFT_FALSE_META = { color: "#166534", bg: "#dcfce7", border: "#bbf7d0" };

export function formatAuditDate(date) {
  if (!date) return "—";
  const parsed = new Date(date);
  if (!Number.isNaN(parsed.getTime())) {
    return parsed.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" });
  }
  return String(date);
}

export function formatAuditTimestamp(timestamp) {
  if (!timestamp) return null;
  const parsed = new Date(timestamp);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  });
}

export function proofKindTitle(proofKind) {
  if (proofKind === "pre_fix_unpatched") {
    return "Audit reviewed THIS code; fix commits exist in the audit text but deployed code doesn't match any — the fix was never shipped";
  }
  if (proofKind === "post_fix") {
    return "Deployed code matches a fix commit the audit referenced; the audit's findings were addressed";
  }
  if (proofKind === "cited_only") {
    return "Matched a commit that the audit cited for context only (not reviewed, not a fix)";
  }
  return undefined;
}

export function MetaBadge({ meta, label, title }) {
  return (
    <span
      className="ps-badge"
      title={title || undefined}
      style={{
        "--badge-accent": meta.color,
        background: meta.bg,
        color: meta.color,
        border: `1px solid ${meta.border}`,
        fontSize: 10,
      }}
    >
      {label ?? meta.label}
    </span>
  );
}
