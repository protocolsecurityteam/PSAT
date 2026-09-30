
import { api } from "./client.js";

export function getCoverage(company) {
  return api(`/api/company/${encodeURIComponent(company)}/audit_coverage`);
}
