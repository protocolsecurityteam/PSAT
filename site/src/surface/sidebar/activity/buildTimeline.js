// Pure timeline assembly for the Activity tab. Merges two stores of
// different depth into one newest-first list, split at the enrollment
// boundary:
//   - monitored_events: captured from the enrollment block forward, ALL kinds.
//   - upgrade_history:   back-filled to deployment, UPGRADES only (proxy only).
// See site/prototypes/activity-tab/HANDOFF.md §5. No React — unit-testable.

import { shortenAddress } from "../../../graph.js";
import { decodeEvent, eventKind, eventKindLabel, eventSeverity } from "../../../monitoring/format.js";

const secToMs = (s) => (s == null ? null : Number(s) * 1000);

// Dedup key for an upgrade across both stores. The upgrade_history artifact
// carries no tx_hash/log_index (HANDOFF §5b), so a post-enrollment upgrade —
// which appears in BOTH stores — is matched on (block, new-implementation).
function upgradeKey(block, implAddr) {
  return `${block == null ? "?" : block}:${String(implAddr || "").toLowerCase()}`;
}

// [{ from, to, addr }] eras from oldest→newest impls; the current impl runs to ∞.
function implEras(proxy) {
  const impls = Array.isArray(proxy?.implementations) ? proxy.implementations : [];
  return impls.map((im) => ({
    addr: im.address,
    from: typeof im.block_introduced === "number" ? im.block_introduced : 0,
    to: typeof im.block_replaced === "number" ? im.block_replaced : Infinity,
  }));
}

function implAt(eras, block) {
  if (block == null) return null;
  for (const era of eras) {
    if (block >= era.from && block < era.to) return era.addr;
  }
  return null;
}

function upgradeSub(im, isFirst) {
  // The current-impl "current" tag is rendered separately (row.isCurrent), so
  // the sub line is just the address (first deployment) or an arrow to it.
  const addr = shortenAddress(im.address);
  return isFirst ? addr : `→ ${addr}`;
}

// buildTimeline({ events, proxy, enrollmentBlock, isProxy }) →
//   { above, below, boundaryBlock }
// `above` = live-captured rows (block ≥ enrollment); `below` = upgrade-only
// backfill rows (dimmed). When enrollmentBlock is null (a row enrolled before
// the column landed), there is NO boundary — everything renders as-is in
// `above` and boundaryBlock is null.
export function buildTimeline({ events = [], proxy = null, enrollmentBlock = null, isProxy = false }) {
  const eras = isProxy ? implEras(proxy) : [];
  const current = String(proxy?.current_implementation || "").toLowerCase();
  const seenUpgrades = new Set();
  const rows = [];

  // 1. Monitored events → rows (all kinds).
  for (const ev of events) {
    const kind = eventKind(ev);
    const decoded = decodeEvent(ev);
    const block = typeof ev.block_number === "number" ? ev.block_number : null;
    const isUpgrade = kind === "upgrade";
    const implAddr = isUpgrade ? ev.data?.implementation : null;
    if (isUpgrade && block != null) seenUpgrades.add(upgradeKey(block, implAddr));
    rows.push({
      key: `ev:${ev.id}`,
      source: "event",
      kind,
      kindLabel: eventKindLabel(ev),
      severity: eventSeverity(ev),
      title: decoded.title,
      sub: decoded.sub,
      block,
      timestamp: ev.detected_at ? Date.parse(ev.detected_at) : null,
      txHash: ev.tx_hash || null,
      isUpgrade,
      isCurrent: Boolean(isUpgrade && implAddr && current && implAddr.toLowerCase() === current),
      implAttr: null,
    });
  }

  // 2. Upgrade-history rows (proxy only), deduped against event-store upgrades.
  if (isProxy && proxy) {
    const impls = Array.isArray(proxy.implementations) ? proxy.implementations : [];
    impls.forEach((im, i) => {
      const block = typeof im.block_introduced === "number" ? im.block_introduced : null;
      if (block != null && seenUpgrades.has(upgradeKey(block, im.address))) return;
      const isFirst = i === 0;
      const isCurrent = im.address && current
        ? im.address.toLowerCase() === current
        : i === impls.length - 1;
      rows.push({
        key: `up:${im.address}:${i}`,
        source: "upgrade",
        kind: "upgrade",
        kindLabel: "Upgrade",
        severity: "critical",
        title: isFirst ? "First deployment" : "Implementation upgraded",
        sub: upgradeSub(im, isFirst),
        block,
        timestamp: secToMs(im.timestamp_introduced),
        txHash: null,
        isUpgrade: true,
        isCurrent,
        implAttr: null,
      });
    });
  }

  // 3. Per-event impl attribution: the implementation live at each non-upgrade
  //    proxy event's block. Skipped for non-proxies and upgrade rows.
  if (isProxy && eras.length) {
    for (const row of rows) {
      if (row.isUpgrade || row.block == null) continue;
      const addr = implAt(eras, row.block);
      if (addr) row.implAttr = shortenAddress(addr);
    }
  }

  // 4. Newest-first: block desc (null blocks float to the top), timestamp tiebreak.
  rows.sort((a, b) => {
    const ab = a.block == null ? Infinity : a.block;
    const bb = b.block == null ? Infinity : b.block;
    if (ab !== bb) return bb - ab;
    return (b.timestamp || 0) - (a.timestamp || 0);
  });

  // 5. Split at the enrollment boundary. Null → no boundary at all.
  if (enrollmentBlock == null) {
    return { above: rows, below: [], boundaryBlock: null };
  }
  const above = [];
  const below = [];
  for (const row of rows) {
    const block = row.block == null ? Infinity : row.block;
    if (block >= enrollmentBlock) {
      above.push(row);
    } else if (row.isUpgrade) {
      // Only upgrades are back-filled below the line; dim + tag them.
      below.push({ ...row, backfill: true });
    }
  }
  return { above, below, boundaryBlock: enrollmentBlock };
}
