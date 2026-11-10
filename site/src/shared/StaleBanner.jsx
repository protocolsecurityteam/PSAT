// The as-of of the shown prepared sections: the oldest `preparedAt`, and
// whether any section is being rebuilt. Null when no shown section is
// prepared (a live response has no as-of). `at` is null when no section
// carries a readable time.
export function preparedAsOf(metas) {
  const shown = (metas || []).filter(Boolean);
  const prepared = shown.filter((meta) => meta.source === "prepared" || meta.source === "prepared-stale");
  if (!prepared.length) return null;
  const times = shown.map((meta) => Date.parse(meta.preparedAt)).filter(Number.isFinite);
  return {
    stale: prepared.some((meta) => meta.source === "prepared-stale"),
    at: times.length ? new Date(Math.min(...times)).toLocaleString() : null,
  };
}

// `showFresh={false}` where the banner's class is not quiet enough for a
// standing line; that mount names the fresh as-of elsewhere.
export default function StaleBanner({ metas, className, showFresh = true }) {
  const asOf = preparedAsOf(metas);
  if (!asOf || (!asOf.stale && !showFresh)) return null;
  const at = asOf.at || "not determined";
  return (
    <p className={className} role="status">
      {asOf.stale ? `Updating — data as of ${at}` : `Data as of ${at}`}
    </p>
  );
}
