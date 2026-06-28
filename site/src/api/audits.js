// Typed-enough wrappers around the /api/audits/* + /api/company/{name}/audit*
// + /api/contracts/{id}/audit_timeline endpoints. The shapes match
// api.py:_audit_report_to_dict and the endpoint return-values in api.py.
// Keep these thin — error handling + admin-key logic live in ./client.js.

import { api } from "./client.js";

export function listAudits(company) {
  return api(`/api/company/${encodeURIComponent(company)}/audits`);
}

export function getAudit(auditId) {
  return api(`/api/audits/${encodeURIComponent(auditId)}`);
}

export function getScope(auditId) {
  return api(`/api/audits/${encodeURIComponent(auditId)}/scope`);
}

// Returns plain text, not JSON — api() infers based on Content-Type.
export function getAuditText(auditId) {
  return api(`/api/audits/${encodeURIComponent(auditId)}/text`);
}

export function getCoverage(company) {
  return api(`/api/company/${encodeURIComponent(company)}/audit_coverage`);
}

export function getTimeline(contractId) {
  return api(`/api/contracts/${encodeURIComponent(contractId)}/audit_timeline`);
}

// Admin-only: both trip the 401 flow in api() if the admin key is missing.
export function refreshCoverage(company, { verifySourceEquivalence = false } = {}) {
  const params = new URLSearchParams();
  if (verifySourceEquivalence) params.set("verify_source_equivalence", "true");
  const qs = params.toString();
  const suffix = qs ? `?${qs}` : "";
  return api(`/api/company/${encodeURIComponent(company)}/refresh_coverage${suffix}`, { method: "POST" });
}

export function reextractScope(auditId) {
  return api(`/api/audits/${encodeURIComponent(auditId)}/reextract_scope`, { method: "POST" });
}
