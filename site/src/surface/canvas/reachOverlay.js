// Hop distance → the chip a reached node wears, or null for no chip. Hop 1 is
// deliberately absent: the directly-connected node already carries the acts-on
// chip naming the concrete capability, and a reach chip beside it would state
// the same relationship a second time, more weakly. The hop count is exact at
// every distance — an overlay that stopped counting past some tier would be
// saying less than the walk proved.
export function reachChipText(hop) {
  if (!hop || hop < 2) return null;
  return `reach · ${hop} hops`;
}

// Violet of the reach chips (--ps-node-chip--reach border / legend swatch), so a
// highlighted route and the chips it ends at read as one overlay.
export const REACH_EDGE_STROKE = "#a78bfa";

// Whether a drawn edge carries one of the reach-route pairs in `pathEdges`
// (a Set of "from>to", lowercased). Cross-group edges are aggregated into
// group→group bundles that keep the underlying contract pairs in `data.samples`,
// so the samples are the truth about what a bundle carries; an unaggregated edge
// is its own single pair. ANY matching sample lights the bundle — the same rule
// that decides whether a bundle earns a connection chip.
export function edgeOnReachPath(edge, pathEdges) {
  if (!edge || !pathEdges || pathEdges.size === 0) return false;
  const samples = edge.data?.samples;
  const pairs = samples && samples.length
    ? samples.map((s) => [s.from, s.to])
    : [[edge.source, edge.target]];
  return pairs.some(
    ([from, to]) => from && to && pathEdges.has(`${from.toLowerCase()}>${to.toLowerCase()}`),
  );
}
