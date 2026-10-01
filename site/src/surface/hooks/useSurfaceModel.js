import { useMemo } from "react";

import { buildMachines } from "../layout/buildMachines.js";
import { buildGovernsIndex } from "../layout/governsIndex.js";
import { buildControlEdgeIndex, flowOnChain } from "../layout/governancePath.js";
import { buildEntityIndex } from "../layout/entities.js";
import { coalesceChain, principalOnChain } from "../entityKey.js";

export function useSurfaceModel({ companyData, functionData, functionsLoading, activeChain, isMultichain }) {
  // Only the active chain's contracts build machines; principals and fund_flows
  // carry their own chain fields and are filtered by principalOnChain /
  // flowOnChain.
  const scopedCompanyData = useMemo(() => {
    if (!companyData) return null;
    if (!isMultichain) return companyData;
    return {
      ...companyData,
      contracts: (companyData.contracts || []).filter(
        (c) => coalesceChain(c.chain) === activeChain,
      ),
    };
  }, [companyData, isMultichain, activeChain]);

  const allMachines = useMemo(
    () => (scopedCompanyData ? buildMachines(scopedCompanyData, functionData, { functionsLoading, activeChain }) : []),
    [scopedCompanyData, functionData, functionsLoading, activeChain]
  );


  // Built over all machines so role-filtered targets still resolve; never per
  // render inside the card.
  const governsIndex = useMemo(
    () => buildGovernsIndex(allMachines, functionData),
    [allMachines, functionData]
  );

  // Keyed so a hop can name its witnessed relation.
  const controlEdgeIndex = useMemo(
    () => buildControlEdgeIndex(companyData?.fund_flows || [], activeChain),
    [companyData, activeChain]
  );

  // SurfaceCanvas keys by bare address, so a twin's flow on another chain must
  // not draw here.
  const scopedFundFlows = useMemo(
    () => (companyData?.fund_flows || []).filter((f) => flowOnChain(f, activeChain)),
    [companyData, activeChain]
  );

  // Chain-scoped so a principal from another chain can't attach to a
  // same-address card.
  const principalsByAddress = useMemo(() => {
    const map = new Map();
    for (const p of companyData?.principals || []) {
      const addr = (p.address || "").toLowerCase();
      if (!addr) continue;
      if (!principalOnChain(p, activeChain)) continue;
      map.set(addr, p);
    }
    return map;
  }, [companyData, activeChain]);

  // Over all machines and principals so filtered-off targets still resolve.
  const entityIndex = useMemo(
    () => buildEntityIndex(allMachines, companyData?.principals || [], activeChain),
    [allMachines, companyData, activeChain]
  );

  return {
    scopedCompanyData,
    allMachines,
    governsIndex,
    controlEdgeIndex,
    scopedFundFlows,
    principalsByAddress,
    entityIndex,
  };
}
