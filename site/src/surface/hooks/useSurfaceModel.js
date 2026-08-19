import { useMemo } from "react";

import { buildMachines } from "../layout/buildMachines.js";
import { buildGovernsIndex } from "../layout/governsIndex.js";
import { buildControlEdgeIndex, flowOnChain } from "../layout/governancePath.js";
import { buildEntityIndex } from "../layout/entities.js";
import { coalesceChain, principalOnChain } from "../entityKey.js";

// The read-only derivation chain from a company payload to the canvas's data
// model: chain-scoped contracts -> machines -> governs/control-edge/entity
// indexes. Pure memos over the inputs; no state, no effects.
export function useSurfaceModel({ companyData, functionData, functionsLoading, activeChain, isMultichain }) {
  // Chain-scope every downstream derivation: only the active chain's contracts
  // build machines, so the canvas/selection/entity-index all operate on a
  // single-chain dataset. Principals (chains) and fund_flows (from_chain/
  // to_chain) carry their own chain fields, consumed by principalOnChain and
  // flowOnChain; visiblePrincipals keeps only principals that
  // control a visible (now chain-scoped) machine, and elkLayout keeps only
  // flows whose endpoints are visible contracts.
  const scopedCompanyData = useMemo(() => {
    if (!companyData) return null;
    if (!isMultichain) return companyData; // single chain: no filtering, identical to before
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


  // Authority-OUT index for the contract card's Governs tab: authority address
  // → the contracts + functions it can call. Built once over ALL machines /
  // functions (visibility-agnostic, like the entity index) so a role-filtered
  // target still resolves. Memoized here — never per-render inside the card.
  const governsIndex = useMemo(
    () => buildGovernsIndex(allMachines, functionData),
    [allMachines, functionData]
  );

  // Same control edges, keyed so a hop can name itself (type + the witnessed
  // relation/role label the payload carries). Feeds the reached-from path block
  // on the entity card; built once here, never per render inside it.
  const controlEdgeIndex = useMemo(
    () => buildControlEdgeIndex(companyData?.fund_flows || [], activeChain),
    [companyData, activeChain]
  );

  // Fund flows feeding the canvas are chain-scoped like the principals + the
  // edge index: SurfaceCanvas draws contract→contract edges keyed by bare
  // address, so a same-address twin's flow on another chain must not draw onto
  // this chain's nodes (inv. 13). Same predicate the edge index uses.
  const scopedFundFlows = useMemo(
    () => (companyData?.fund_flows || []).filter((f) => flowOnChain(f, activeChain)),
    [companyData, activeChain]
  );

  // Principal facet by address — lets a dual-facet contract card render its
  // principal strip + capability tags. Most contracts have no entry (null).
  // Chain-scoped: a principal governs on the chain(s) in its ``chains`` list
  // (backend-added), so one observed only on another chain must not attach to a
  // same-address contract card here (inv. 13). Legacy principals without
  // ``chains`` are kept as before.
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

  // Address-keyed entity index over ALL machines + ALL principals (no
  // visibility filtering). Selection state stores addresses only and resolves
  // entities through this index per render, so denormalized snapshots can
  // never go stale and role-filtered-off targets still resolve.
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
