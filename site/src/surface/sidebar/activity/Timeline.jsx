import { blockExplorerAddressUrl } from "../../../blockExplorer.js";
import { shortenAddress } from "../../../graph.js";
import { relativeTime } from "../../../monitoring/format.js";

// Lean on blockExplorerAddressUrl's chain mapping by swapping the path segment.
function txUrl(txHash, chain = "ethereum") {
  if (!txHash) return null;
  const addrUrl = blockExplorerAddressUrl("0x", chain);
  if (!addrUrl) return null;
  return `${addrUrl.replace("/address/0x", "/tx/")}${txHash}`;
}

function timeLabel(ms, now) {
  if (!ms) return "—";
  // Recent events read better relative; older ones as an absolute date.
  if (now - ms < 7 * 86400 * 1000) return relativeTime(new Date(ms).toISOString(), now);
  return new Date(ms).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

function EventRow({ row, chain, now }) {
  const link = txUrl(row.txHash, chain);
  const dotClass = [
    "ps-activity-dot",
    row.backfill ? `d-${row.kind}` : "",
  ].filter(Boolean).join(" ");
  const liClass = [
    "ps-activity-ev",
    row.severity === "critical" ? "crit" : "",
    row.isCurrent ? "current" : "",
    row.backfill ? "pre" : "",
  ].filter(Boolean).join(" ");
  return (
    <li className={liClass}>
      <div className="ps-activity-rail"><span className={dotClass} /></div>
      <div className="ps-activity-ev-body">
        <div className="ps-activity-ev-top">
          <span className={`ps-activity-kind k-${row.kind}`}>{row.kindLabel}</span>
          <span className="ps-activity-ev-title">{row.title}</span>
          {row.backfill ? <span className="ps-activity-backfill">backfill</span> : null}
          <span className="ps-activity-ev-time">{timeLabel(row.timestamp, now)}</span>
        </div>
        {row.sub ? (
          <div className="ps-activity-ev-sub">
            {row.sub}
            {row.isCurrent ? <span className="ps-activity-tag"> · current</span> : null}
          </div>
        ) : null}
        <div className="ps-activity-ev-meta">
          {link ? (
            <a href={link} target="_blank" rel="noreferrer noopener">{shortenAddress(row.txHash)} ↗</a>
          ) : null}
          {row.block != null ? <span>block {row.block.toLocaleString()}</span> : null}
          {row.implAttr ? <span className="ps-activity-impl">under impl {row.implAttr}</span> : null}
        </div>
      </div>
    </li>
  );
}

// Timeline: `above` rows (live-captured), then the enrollment boundary pill
// (omitted entirely when boundaryBlock is null — a legacy row with no
// enrollment_block), then `below` upgrade-only backfill rows or the non-proxy
// empty state.
export function Timeline({ above, below, boundaryBlock, boundaryDate, isProxy, chain, now }) {
  const dateLabel = boundaryDate
    ? new Date(boundaryDate).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" })
    : null;
  const hasBoundary = boundaryBlock != null;

  if (!above.length && !below.length && !hasBoundary) {
    return <div className="ps-activity-empty">No activity recorded yet.</div>;
  }

  return (
    <ul className="ps-activity-tl">
      {above.map((row) => (
        <EventRow key={row.key} row={row} chain={chain} now={now} />
      ))}

      {hasBoundary ? (
        <div className="ps-activity-boundary">
          <span className="ps-activity-boundary-pill">
            ◔ Monitoring started{dateLabel ? ` · ${dateLabel}` : ""}
          </span>
          {isProxy && below.length ? (
            <span className="ps-activity-boundary-note">Only upgrades are back-filled below this line.</span>
          ) : null}
        </div>
      ) : null}

      {hasBoundary && below.length ? (
        below.map((row) => <EventRow key={row.key} row={row} chain={chain} now={now} />)
      ) : hasBoundary ? (
        <div className="ps-activity-empty">
          <b>No activity before the line.</b>
          <br />
          Activity beyond upgrades isn&apos;t back-filled — only tracked from{" "}
          {dateLabel || "enrollment"} on.
        </div>
      ) : null}
    </ul>
  );
}
