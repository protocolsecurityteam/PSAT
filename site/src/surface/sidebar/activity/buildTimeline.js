// Activity timeline assembly, newest first, split at the enrollment boundary:
// - monitored_events: from enrollment forward, all kinds.
// - upgrade_history: back-filled to deployment, upgrades only (proxy only).

import { shortenAddress } from "../../../shared/format.js";
import {
  SALIENCE_NOT_DETERMINED,
  eventKind,
  eventKindLabel,
  eventSalience,
  eventSeverity,
  salienceAllows,
} from "./eventClass.js";
import { decodeEvent } from "./format.js";

const secToMs = (s) => (s == null ? null : Number(s) * 1000);

// upgrade_history has no tx_hash/log_index, so upgrades present in both stores
// match on (block, new impl).
function upgradeKey(block, implAddr) {
  return `${block == null ? "?" : block}:${String(implAddr || "").toLowerCase()}`;
}

// Eras oldest→newest; the current impl runs to ∞.
//
// Unknown boundaries are `null`, never folded to 0 or Infinity (that spread one
// era over every other; a poll-detected upgrade has `block_number: null`). The
// producer writes `block_replaced` whenever a successor exists, so the key is
// absent only on the current impl and present-but-null when a successor's block
// is unknown. `to == null` alone does NOT mean current (as in
// coverage.ImplWindow.successor).
function implEras(proxy) {
  const impls = Array.isArray(proxy?.implementations) ? proxy.implementations : [];
  return impls.map((im) => {
    const hasSuccessor = im != null && Object.prototype.hasOwnProperty.call(im, "block_replaced");
    return {
      addr: im.address,
      from: typeof im.block_introduced === "number" ? im.block_introduced : null,
      to: typeof im.block_replaced === "number" ? im.block_replaced : hasSuccessor ? null : Infinity,
    };
  });
}

function implAt(eras, block) {
  if (block == null) return null;
  // No upgrade events: one impl ever, so any block is under it.
  if (eras.length === 1 && eras[0].from == null && eras[0].to === Infinity) return eras[0].addr;
  for (const era of eras) {
    // An era with an unknown boundary can't be shown to contain a block;
    // attribution is left off.
    if (era.from == null || era.to == null) continue;
    if (block >= era.from && block < era.to) return era.addr;
  }
  return null;
}

function upgradeSub(im, isFirst) {
  const addr = shortenAddress(im.address);
  return isFirst ? addr : `→ ${addr}`;
}

// Same-transaction cause (§3.4), exactly as the backend published it.
function withCause(sub, ev) {
  const cause = ev?.data?.caused_by;
  if (!cause || typeof cause !== "object" || !cause.event_type) return sub;
  const note = `caused by ${eventKindLabel(cause.event_type)}`;
  return sub ? `${sub} · ${note}` : note;
}

// `above` = live rows (block ≥ enrollment); `below` = dimmed upgrade backfill.
// No enrollmentBlock means no boundary: everything is `above`.
export function buildTimeline({ events = [], proxy = null, enrollmentBlock = null, isProxy = false, nameFor = null }) {
  const eras = isProxy ? implEras(proxy) : [];
  const current = String(proxy?.current_implementation || "").toLowerCase();
  const seenUpgrades = new Set();
  const rows = [];

  for (const ev of events) {
    const kind = eventKind(ev);
    const decoded = decodeEvent(ev, { nameFor });
    const rawBlock = typeof ev.block_number === "number" ? ev.block_number : null;
    // Read-witnessed rows carry block 0 with no tx_hash as a placeholder; as
    // block 0 they'd fall below the boundary and be dropped.
    const block = rawBlock === 0 && !ev.tx_hash ? null : rawBlock;
    const isUpgrade = kind === "upgrade";
    const implAddr = isUpgrade ? ev.data?.implementation : null;
    if (isUpgrade && block != null) seenUpgrades.add(upgradeKey(block, implAddr));
    rows.push({
      key: `ev:${ev.id}`,
      source: "event",
      kind,
      kindLabel: eventKindLabel(ev),
      severity: eventSeverity(ev),
      salience: eventSalience(ev),
      title: decoded.title,
      titleDetail: decoded.titleDetail || null,
      target: decoded.target || null,
      sub: withCause(decoded.sub, ev),
      block,
      timestamp: ev.detected_at ? Date.parse(ev.detected_at) : null,
      txHash: ev.tx_hash || null,
      isUpgrade,
      isCurrent: Boolean(isUpgrade && implAddr && current && implAddr.toLowerCase() === current),
      implAttr: null,
    });
  }

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
        // No backend rule rated a back-filled upgrade; a borrowed `routine`
        // would collapse it.
        salience: SALIENCE_NOT_DETERMINED,
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

  // The impl live at each non-upgrade proxy event's block.
  if (isProxy && eras.length) {
    for (const row of rows) {
      if (row.isUpgrade || row.block == null) continue;
      const addr = implAt(eras, row.block);
      if (addr) row.implAttr = shortenAddress(addr);
    }
  }

  // Null blocks float to the top; timestamp tiebreak.
  rows.sort((a, b) => {
    const ab = a.block == null ? Infinity : a.block;
    const bb = b.block == null ? Infinity : b.block;
    if (ab !== bb) return bb - ab;
    return (b.timestamp || 0) - (a.timestamp || 0);
  });

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
      below.push({ ...row, backfill: true });
    }
  }
  return { above, below, boundaryBlock: enrollmentBlock };
}

// Returns surviving rows plus per-section withheld counts. Every caller shows
// the count (invariant 4), and the Timeline needs it to tell empty from
// filtered sections.
export function filterTimelineBySalience({ above = [], below = [] }, minSalience) {
  const keptAbove = above.filter((row) => salienceAllows(row.salience, minSalience));
  const keptBelow = below.filter((row) => salienceAllows(row.salience, minSalience));
  const hiddenAbove = above.length - keptAbove.length;
  const hiddenBelow = below.length - keptBelow.length;
  return {
    above: keptAbove,
    below: keptBelow,
    hiddenAbove,
    hiddenBelow,
    hidden: hiddenAbove + hiddenBelow,
  };
}
