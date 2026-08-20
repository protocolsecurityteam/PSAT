import { useEffect, useMemo, useState } from "react";

import { getCoverage } from "../../api/audits.js";
import { isBytecodeVerifiedAudit } from "../../audits/auditCoverage.js";
import { coalesceChain } from "../entityKey.js";

// Audit-coverage highlight set: the bytecode-verified-covered contracts for the
// active audit pick (or the whole proven set when ``all``). Returns a Set of
// bare lowercased addresses matched against the canvas's bare node ids. Coverage
// rows are all-chain; only the active chain's rows contribute, so a twin covered
// solely on another chain does NOT light this chain's same-address node (inv. 13).
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

// Coverage payload — one call, cached locally. Used to build the audits
// list + the audit_id → address-set map for highlight propagation. When
// the embedded surface gets it from CompanyOverview via initialCoverage,
// skip the duplicate fetch.
export function useAuditCoverage({ companyName, initialCoverage, sidebarMode, activeChain }) {
  const [coverageData, setCoverageData] = useState(initialCoverage);
  const [coverageError, setCoverageError] = useState(null);
  const [coverageLoading, setCoverageLoading] = useState(false);

  // Active audit: when non-null, its covered contracts get a green ring
  // and everything else dims on the canvas.
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

  // Audit-coverage highlight set (Audits tab): the contracts a picked audit
  // bytecode-verifiably covers. Merged with agent + selection highlights into
  // highlightedAddresses below (defined after the selection/visibility derives
  // it also depends on).
  const auditHighlights = useMemo(() => {
    // The audit overlay is a function of the Audits tab being open: leaving the
    // tab suppresses it, but activeAuditId is kept so returning re-lights the
    // same pick (persist-on-return). `"all"` is the summary's whole-proven-set
    // highlight; a numeric id is one audit's covered set. Both are one radio —
    // see AuditsListPanel. A committed selection clears activeAuditId (below).
    if (activeAuditId == null || !coverageData || sidebarMode !== "audits") return null;
    return auditHighlightSet(coverageData.coverage, activeAuditId, activeChain);
  }, [activeAuditId, coverageData, sidebarMode, activeChain]);

  return { coverageData, coverageError, coverageLoading, activeAuditId, setActiveAuditId, auditHighlights };
}
