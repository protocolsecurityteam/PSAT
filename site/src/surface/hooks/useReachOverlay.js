import { useCallback, useMemo } from "react";

import { isRoleIdAddress, principalLabel, shortAddr } from "../format.js";
import { deriveReachOverlay } from "../layout/serverReach.js";
import { edgeClaims, shortestControlPath } from "../layout/governancePath.js";
import { entityKey, principalOnChain } from "../entityKey.js";

export function useReachOverlay({
  companyData,
  activeChain,
  selection,
  reachHosts,
  allMachines,
  entityIndex,
  controlEdgeIndex,
  auditHighlights,
  agentHighlights,
}) {
  const visiblePrincipals = useMemo(() => {
    const visibleAddrs = new Set(allMachines.map((m) => m.address?.toLowerCase()));
    // Chain-scope first so another chain's principal can't ride in on a
    // same-address twin.
    return (companyData?.principals || []).filter((p) =>
      !isRoleIdAddress(p.address || "") &&
      principalOnChain(p, activeChain) &&
      (p.controls || []).some((a) => visibleAddrs.has(a.toLowerCase()))
    );
  }, [allMachines, companyData, activeChain]);

  // Union of agent and audit highlights; null falls back to selection dimming.
  // Principal reach deliberately doesn't route through here (owner decision
  // 2026-07-11).
  const highlightedAddresses = useMemo(() => {
    if (!auditHighlights && !agentHighlights) return null;
    const merged = new Set();
    if (auditHighlights) for (const a of auditHighlights) merged.add(a);
    if (agentHighlights) for (const a of agentHighlights) merged.add(a);
    return merged.size ? merged : null;
  }, [auditHighlights, agentHighlights]);

  // The server's reach record (scorer_closure_v1), rendered, never re-derived.
  // Absent means no reach (fail closed).
  const reachOverlay = useMemo(
    () => deriveReachOverlay(companyData?.reach, activeChain, selection?.address),
    [companyData, activeChain, selection],
  );
  const reachDistances = reachOverlay?.distances.size ? reachOverlay.distances : null;
  // Routes from the server's `parents` tree so hop chips have a visible line
  // back. A pair with no drawn edge lights nothing.
  const reachPathEdges = reachOverlay?.pathEdges.size ? reachOverlay.pathEdges : null;
  // Kept separate from reachDistances and not drawn (owner ruling 2026-08-12);
  // it feeds the score page and Governs count line.
  const reachFrontier = reachOverlay?.frontier.size ? reachOverlay.frontier : null;
  // Only destinations with a node on this page; off-page ones would send
  // readers hunting.
  const reachFrontierOnPage = useMemo(() => {
    if (!reachFrontier) return 0;
    const onPage = new Set(allMachines.map((m) => m.address?.toLowerCase()));
    for (const p of visiblePrincipals) onPage.add((p.address || "").toLowerCase());
    let count = 0;
    for (const addr of reachFrontier.keys()) if (onPage.has(addr)) count += 1;
    return count;
  }, [reachFrontier, allMachines, visiblePrincipals]);

  // The short address is the identity when nothing names it.
  const nameForAddress = useCallback((addr) => {
    const lc = String(addr || "").toLowerCase();
    if (!lc) return "";
    const entry = entityIndex.get(entityKey(activeChain, lc));
    if (entry?.machine?.name) return entry.machine.name;
    if (entry?.principal) return principalLabel(entry.principal.label, entry.principal.type, lc);
    return shortAddr(lc);
  }, [entityIndex, activeChain]);

  // The route a score-page click-through took, walked over the same edges as
  // the reach chips. An uncarried route stays explicit (hops: null).
  const reachPath = useMemo(() => {
    const target = selection?.address;
    if (!reachHosts?.length || !target) return null;
    const hostNames = reachHosts.map(nameForAddress);
    const { host, hops } = shortestControlPath(reachHosts, target, controlEdgeIndex);
    if (!hops) return { host: null, hostName: null, hostNames, hops: null };
    if (!hops.length) return null;
    return {
      host,
      hostName: nameForAddress(host),
      hostNames,
      hops: hops.map((hop) => ({
        from: hop.from,
        to: hop.to,
        fromName: nameForAddress(hop.from),
        toName: nameForAddress(hop.to),
        type: hop.flow?.type || null,
        claims: edgeClaims(hop.flow),
      })),
    };
  }, [reachHosts, selection, controlEdgeIndex, nameForAddress]);

  return {
    visiblePrincipals,
    highlightedAddresses,
    reachDistances,
    reachPathEdges,
    reachFrontierOnPage,
    nameForAddress,
    reachPath,
  };
}
