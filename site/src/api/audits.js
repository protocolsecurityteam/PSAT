// Typed-enough wrapper around the /api/company/{name}/audit_coverage endpoint.
// The shape matches api.py:_audit_report_to_dict and the endpoint return-value
// in api.py. Keep this thin — error handling + admin-key logic live in
// ./client.js.

import { api } from "./client.js";

export function getCoverage(company) {
  return api(`/api/company/${encodeURIComponent(company)}/audit_coverage`);
}
