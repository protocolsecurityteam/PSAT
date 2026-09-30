import { useMemo, useState } from "react";

import { getCoverage } from "../../api/audits.js";
import { isBytecodeVerifiedAudit } from "../../audits/auditCoverage.js";
import { useResource } from "../../shared/useResource.js";
import { coalesceChain } from "../entityKey.js";

// Coverage rows span chains; only the active chain's contribute, so a twin
// covered elsewhere doesn't light this node (inv. 13).
export function auditHighlightSet(coverage, activeAuditId, activeChain) {
  const showAll = activeAuditId === "all";
  const out = new Set();
  for (const entry of coverage || []) {
    const addr = (entry.address || "").toLowerCase();
    if (!addr) continue;
    if (activeChain && coalesceChain(entry.chain) !== activeChain) continue;
    if ((entry.audits || []).some((a) => isBytecodeVerifiedAudit(a) && (showAll || a.audit_id === activeAuditId))) {
      out.add(addr);
    }
  }
  return out.size ? out : null;
}

// Skips the fetch when CompanyOverview supplies initialCoverage.
export function useAuditCoverage({ companyName, initialCoverage, sidebarMode, activeChain }) {
  const fetched = useResource(() => getCoverage(companyName), [companyName], {
    enabled: Boolean(companyName) && !initialCoverage,
    reset: false,
  });
  const coverageData = initialCoverage || fetched.data;
  const coverageError = initialCoverage || !fetched.error ? null : fetched.error.message || "Failed";
  const coverageLoading = !initialCoverage && fetched.loading;

  const [activeAuditId, setActiveAuditId] = useState(null);

  const auditHighlights = useMemo(() => {
    // Only while the Audits tab is open; activeAuditId persists so returning
    // re-lights it. A committed selection clears it.
    if (activeAuditId == null || !coverageData || sidebarMode !== "audits") return null;
    return auditHighlightSet(coverageData.coverage, activeAuditId, activeChain);
  }, [activeAuditId, coverageData, sidebarMode, activeChain]);

  return { coverageData, coverageError, coverageLoading, activeAuditId, setActiveAuditId, auditHighlights };
}
