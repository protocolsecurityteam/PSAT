import { useCallback, useMemo } from "react";

import { isRoleIdAddress, principalLabel, shortAddr } from "../format.js";
import { deriveReachOverlay } from "../layout/serverReach.js";
import { edgeClaims, shortestControlPath } from "../layout/governancePath.js";
import { entityKey, principalOnChain } from "../entityKey.js";

// The selection-driven overlay derives: visible principals, the merged
// highlight set, the server-reach overlay (distances / path edges / frontier
// count) and the reached-from path block. Read-only memos; no state.
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
    // Chain-scope first: a principal observed only on another chain must not
    // ride in on a same-address twin among the (chain-scoped) visible machines
    // (inv. 13). Legacy principals without ``chains`` behave as before.
    return (companyData?.principals || []).filter((p) =>
      !isRoleIdAddress(p.address || "") &&
      principalOnChain(p, activeChain) &&
      (p.controls || []).some((a) => visibleAddrs.has(a.toLowerCase()))
    );
  }, [allMachines, companyData, activeChain]);

  // Highlighted addresses on the canvas: union of agent highlights (Agent tab)
  // and the audit-coverage set (Audits tab). Either source drives the green
  // ring + dim. Lowercased Set for O(1) canvas comparison; null when no source
  // is active so the canvas falls back to selection dimming. A selected
  // principal's reach is NOT routed through here — the canvas's own selection
  // path lights co_controls with the normal relatedness dim + chips, and the
  // green overlay treatment is reserved for agent/audit sets (owner decision
  // 2026-07-11).
  const highlightedAddresses = useMemo(() => {
    if (!auditHighlights && !agentHighlights) return null;
    const merged = new Set();
    if (auditHighlights) for (const a of auditHighlights) merged.add(a);
    if (agentHighlights) for (const a of agentHighlights) merged.add(a);
    return merged.size ? merged : null;
  }, [auditHighlights, agentHighlights]);

  // Reach overlay for the SELECTED entity: the SERVER's reach record
  // (companyData.reach, model scorer_closure_v1) — the scorer's own walk,
  // shipped as three distinct states. The client renders; it never re-derives.
  // An absent block or absent entity yields null everything: absence of the
  // witness is not reach (fail closed).
  const reachOverlay = useMemo(
    () => deriveReachOverlay(companyData?.reach, activeChain, selection?.address),
    [companyData, activeChain, selection],
  );
  // Walked state: hop distances the canvas chips show.
  const reachDistances = reachOverlay?.distances.size ? reachOverlay.distances : null;
  // The routes behind those hop counts, reconstructed from the server's
  // `parents` tree. The canvas lights the drawn edges matching these pairs, so
  // a "reach · 3 hops" chip has a visible line back to the selection rather
  // than asking the reader to take the number on faith. Synthesizes nothing —
  // a pair with no drawn edge (an intra-group hop inside a collapsed box)
  // simply lights nothing.
  const reachPathEdges = reachOverlay?.pathEdges.size ? reachOverlay.pathEdges : null;
  // not_determined frontier: destination → the scorer's refusal entry. A
  // distinct third state, never merged into reachDistances — and deliberately
  // NOT rendered on the canvas (owner ruling 2026-08-12: the graph shows
  // proven reach only; the unknowns' home is the score page's confidence zone
  // and the Governs tab's count line below).
  const reachFrontier = reachOverlay?.frontier.size ? reachOverlay.frontier : null;
  // The sidebar's unconfirmed count names only destinations the reader can
  // LOCATE — ones with a node on this page. The server's frontier also names
  // off-page destinations (the scorer's graph is wider than the payload's
  // contract list); advertising those as findable rows would send the reader
  // hunting for nodes the canvas cannot show.
  const reachFrontierOnPage = useMemo(() => {
    if (!reachFrontier) return 0;
    const onPage = new Set(allMachines.map((m) => m.address?.toLowerCase()));
    for (const p of visiblePrincipals) onPage.add((p.address || "").toLowerCase());
    let count = 0;
    for (const addr of reachFrontier.keys()) if (onPage.has(addr)) count += 1;
    return count;
  }, [reachFrontier, allMachines, visiblePrincipals]);

  // Human name for an address on this graph: the contract's, else the
  // principal's, else the short address. Never a bare "unknown" — the short
  // address IS the identity when nothing else names it.
  const nameForAddress = useCallback((addr) => {
    const lc = String(addr || "").toLowerCase();
    if (!lc) return "";
    const entry = entityIndex.get(entityKey(activeChain, lc));
    if (entry?.machine?.name) return entry.machine.name;
    if (entry?.principal) return principalLabel(entry.principal.label, entry.principal.type, lc);
    return shortAddr(lc);
  }, [entityIndex, activeChain]);

  // The route a score-page click-through took to this entity: the deduction row
  // named a host the controller acts on DIRECTLY, and this contract only through
  // the control graph. Walked over the same edges the canvas reach chips use, so the
  // card and the graph cannot disagree. A route this graph does not carry stays
  // an explicit third state (hops: null) — the card says so rather than drawing
  // a shorter path than the truth.
  const reachPath = useMemo(() => {
    const target = selection?.address;
    if (!reachHosts?.length || !target) return null;
    const hostNames = reachHosts.map(nameForAddress);
    const { host, hops } = shortestControlPath(reachHosts, target, controlEdgeIndex);
    if (!hops) return { host: null, hostName: null, hostNames, hops: null };
    if (!hops.length) return null; // the click landed on the host itself
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
