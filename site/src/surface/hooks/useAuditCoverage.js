import { useEffect, useMemo, useState } from "react";

import { getCoverage } from "../../api/audits.js";
import { isBytecodeVerifiedAudit } from "../../audits/auditCoverage.js";
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
  const [coverageData, setCoverageData] = useState(initialCoverage);
  const [coverageError, setCoverageError] = useState(null);
  const [coverageLoading, setCoverageLoading] = useState(false);

  const [activeAuditId, setActiveAuditId] = useState(null);

  useEffect(() => {
    if (!companyName) return undefined;
    if (initialCoverage) {
      setCoverageData(initialCoverage);
      setCoverageError(null);
      setCoverageLoading(false);
      return undefined;
    }
    let cancelled = false;
    setCoverageLoading(true);
    setCoverageError(null);
    getCoverage(companyName)
      .then((d) => { if (!cancelled) { setCoverageData(d); setCoverageLoading(false); } })
      .catch((e) => { if (!cancelled) { setCoverageError(e?.message || "Failed"); setCoverageLoading(false); } });
    return () => { cancelled = true; };
  }, [companyName, initialCoverage]);

  const auditHighlights = useMemo(() => {
    // Only while the Audits tab is open; activeAuditId persists so returning
    // re-lights it. A committed selection clears it.
    if (activeAuditId == null || !coverageData || sidebarMode !== "audits") return null;
    return auditHighlightSet(coverageData.coverage, activeAuditId, activeChain);
  }, [activeAuditId, coverageData, sidebarMode, activeChain]);

  return { coverageData, coverageError, coverageLoading, activeAuditId, setActiveAuditId, auditHighlights };
}
