// One notice for all company sections on screen, dated by the oldest build shown.
export default function StaleBanner({ metas, className }) {
  const shown = metas.filter(Boolean);
  if (!shown.some((meta) => meta.source === "prepared-stale")) return null;
  const oldest = Math.min(...shown.map((meta) => Date.parse(meta.preparedAt)).filter(Number.isFinite));
  return <p className={className} role="status">Updating — data as of {new Date(oldest).toLocaleString()}</p>;
}
