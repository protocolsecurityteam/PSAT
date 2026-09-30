// No chip at hop 1: the acts-on chip already names the capability. Hop counts
// are exact at every distance.
export function reachChipText(hop) {
  if (!hop || hop < 2) return null;
  return `reach · ${hop} hops`;
}

// Same violet as the reach chips so route and chips read as one overlay.
export const REACH_EDGE_STROKE = "#a78bfa";

// Bundles keep their contract pairs in `data.samples`; any matching sample
// lights the bundle.
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
