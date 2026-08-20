// Shared audit-date formatters for the protocol surface and upgrades UI.
// The badge vocabulary that used to live here (match-type / equivalence /
// proof-kind / severity meta + MetaBadge) was retired with the proof-first
// Audits panel — it surfaced low-confidence and accusatory signals the panel
// no longer asserts. See site/prototypes/audit-panel/HANDOFF.md.

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
