import { useState } from "react";

import { TargetRef } from "./TargetRef.jsx";

import { blockExplorerAddressUrl } from "../../blockExplorer.js";
import { shortenAddress } from "../../../shared/format.js";
import { SALIENCE_ROUTINE } from "./eventClass.js";
import { relativeTime } from "./format.js";

function txUrl(txHash, chain = "ethereum") {
  if (!txHash) return null;
  const addrUrl = blockExplorerAddressUrl("0x", chain);
  if (!addrUrl) return null;
  return `${addrUrl.replace("/address/0x", "/tx/")}${txHash}`;
}

function timeLabel(ms, now) {
  if (!ms) return "—";
  if (now - ms < 7 * 86400 * 1000) return relativeTime(new Date(ms).toISOString(), now);
  return new Date(ms).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

function EventRow({ row, chain, now, onPreview, onNavigate }) {
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
          <span className="ps-activity-ev-title" title={row.titleDetail || undefined}>{row.title}</span>
          {row.backfill ? <span className="ps-activity-backfill">backfill</span> : null}
          <span className="ps-activity-ev-time">{timeLabel(row.timestamp, now)}</span>
        </div>
        {row.target || row.sub ? (
          <div className="ps-activity-ev-sub">
            {row.target ? <TargetRef target={row.target} onPreview={onPreview} onNavigate={onNavigate} /> : null}
            {row.target && row.sub ? " · " : null}
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

// Only proven `routine` rows collapse; `not_determined` is unrated, and
// collapsing it would suppress from ignorance.
const MIN_COLLAPSE_RUN = 2;

function groupRoutineRuns(rows) {
  const out = [];
  let run = [];
  const flush = () => {
    if (run.length >= MIN_COLLAPSE_RUN) {
      out.push({ collapsedKey: `routine:${run[0].key}`, rows: run });
    } else {
      for (const row of run) out.push({ row });
    }
    run = [];
  };
  for (const row of rows) {
    if (row.salience === SALIENCE_ROUTINE) {
      run.push(row);
      continue;
    }
    flush();
    out.push({ row });
  }
  flush();
  return out;
}

// Expands in place so revealed rows keep their position.
function RoutineRun({ group, chain, now, expanded, onToggle, onPreview, onNavigate }) {
  if (expanded) {
    return (
      <>
        <li className="ps-activity-routine-run open">
          <div className="ps-activity-rail" />
          <button type="button" className="ps-activity-routine-toggle" onClick={onToggle}>
            {group.rows.length} routine events — hide
          </button>
        </li>
        {group.rows.map((row) => (
          <EventRow key={row.key} row={row} chain={chain} now={now} onPreview={onPreview} onNavigate={onNavigate} />
        ))}
      </>
    );
  }
  return (
    <li className="ps-activity-routine-run">
      <div className="ps-activity-rail"><span className="ps-activity-dot routine" /></div>
      <button type="button" className="ps-activity-routine-toggle" onClick={onToggle}>
        {group.rows.length} routine events — show
      </button>
    </li>
  );
}

function TimelineRows({ rows, chain, now, onPreview, onNavigate }) {
  const [open, setOpen] = useState(() => new Set());
  const toggle = (key) => setOpen((prev) => {
    const next = new Set(prev);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    return next;
  });
  return groupRoutineRuns(rows).map((group) =>
    group.collapsedKey ? (
      <RoutineRun
        key={group.collapsedKey}
        group={group}
        chain={chain}
        now={now}
        expanded={open.has(group.collapsedKey)}
        onToggle={() => toggle(group.collapsedKey)}
        onPreview={onPreview}
        onNavigate={onNavigate}
      />
    ) : (
      <EventRow key={group.row.key} row={group.row} chain={chain} now={now} onPreview={onPreview} onNavigate={onNavigate} />
    ),
  );
}

// `above` (live), the enrollment boundary (omitted when boundaryBlock is null),
// then `below` (upgrade backfill) or the non-proxy empty state.
//
// `historyState` governs only the empty states, because an empty `below` has
// four causes:
//
// "present" read; nothing before the line.
// "absent" 404 or no back-fill channel (non-proxy).
// "not_determined" a read didn't answer, or none was issued.
// "pending" in flight; may borrow neither answer nor the hedge.
//
// Defaults to "pending" so a forgotten prop claims nothing.
// `hiddenAbove`/`hiddenBelow` count filtered rows: a filter-emptied section has
// earned no empty-state claim.
export function Timeline({
  above,
  below,
  boundaryBlock,
  boundaryDate,
  isProxy,
  chain,
  now,
  historyState = "pending",
  hiddenAbove = 0,
  hiddenBelow = 0,
  onPreview,
  onNavigate,
}) {
  const dateLabel = boundaryDate
    ? new Date(boundaryDate).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" })
    : null;
  const hasBoundary = boundaryBlock != null;

  if (!above.length && !below.length && !hasBoundary) {
    const hidden = hiddenAbove + hiddenBelow;
    if (hidden > 0) {
      // The filter withheld rows; this says so rather than claiming no
      // activity.
      return (
        <div className="ps-activity-empty">
          {hidden === 1
            ? "1 event is hidden by the current filter."
            : `${hidden} events are hidden by the current filter.`}
        </div>
      );
    }
    return (
      <div className="ps-activity-empty">
        {historyState === "pending"
          ? "Checking for earlier activity…"
          : historyState === "not_determined"
            ? "Nothing to show — the upgrade history for this proxy was not read."
            : "No activity recorded yet."}
      </div>
    );
  }

  return (
    <ul className="ps-activity-tl">
      <TimelineRows rows={above} chain={chain} now={now} onPreview={onPreview} onNavigate={onNavigate} />

      {hasBoundary ? (
        <div className="ps-activity-boundary">
          <span className="tag tag-pill ps-activity-boundary-pill">
            ◔ Monitoring started{dateLabel ? ` · ${dateLabel}` : ""}
          </span>
          {isProxy && below.length ? (
            <span className="ps-activity-boundary-note">Only upgrades are back-filled below this line.</span>
          ) : null}
        </div>
      ) : null}

      {hasBoundary && below.length ? (
        <TimelineRows rows={below} chain={chain} now={now} onPreview={onPreview} onNavigate={onNavigate} />
      ) : hasBoundary && hiddenBelow > 0 ? (
        // Checked before historyState: the history answered (these rows came
        // from it), so only the filter applies.
        <div className="ps-activity-empty">
          {hiddenBelow === 1
            ? "1 back-filled upgrade is hidden by the current filter."
            : `${hiddenBelow} back-filled upgrades are hidden by the current filter.`}
        </div>
      ) : hasBoundary && historyState === "pending" ? (
        <div className="ps-activity-empty">Checking for earlier activity…</div>
      ) : hasBoundary && historyState === "not_determined" ? (
        <div className="ps-activity-empty">
          Nothing back-filled below the line — the upgrade history for this proxy
          was not read.
        </div>
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
