// Pure timeline assembly for the Activity tab. Merges two stores of
// different depth into one newest-first list, split at the enrollment
// boundary:
//   - monitored_events: captured from the enrollment block forward, ALL kinds.
//   - upgrade_history:   back-filled to deployment, UPGRADES only (proxy only).
// No React — unit-testable.

import { shortenAddress } from "../../../graph.js";
import { decodeEvent, eventKind, eventKindLabel, eventSeverity } from "../../../monitoring/format.js";

const secToMs = (s) => (s == null ? null : Number(s) * 1000);

// Dedup key for an upgrade across both stores. The upgrade_history artifact
// carries no tx_hash/log_index, so a post-enrollment upgrade —
// which appears in BOTH stores — is matched on (block, new-implementation).
function upgradeKey(block, implAddr) {
  return `${block == null ? "?" : block}:${String(implAddr || "").toLowerCase()}`;
}

// [{ from, to, addr }] eras from oldest→newest impls; the current impl runs to ∞.
//
// An unknown boundary is `null`, never a boundary VALUE. `block_introduced` folded
// to 0 made a block-less impl's era start at genesis and swallow the impl
// attribution of every earlier event; `block_replaced` folded to Infinity made it
// run to now — the same ±infinity spread that was removed server-side.
// `synthesize_from_events` emits `block_number: null` for a poll-detected upgrade,
// so both are reachable.
//
// KEY PRESENCE is the successor discriminator, and it comes from the producer, not
// from a guess: `_build_implementation_timeline`
// (services/discovery/upgrade_history.py) writes `block_replaced` from the NEXT
// upgrade event unconditionally, so the key is absent only on the last record —
// the current impl, which really does run to now — and present-but-null exactly
// when a successor exists whose block was never determined. Same distinction
// `services/audits/coverage.ImplWindow.successor` makes: `to == null` alone does
// NOT mean "still current".
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
  // The no-upgrade-events shape: `_build_implementation_timeline` returns the bare
  // `{address: current_impl}` when there are no events, so this proxy has only ever
  // had one impl and any block is under it. That is a fact about the LIST, not a
  // guessed introduction block, which is why it is stated separately from the scan.
  if (eras.length === 1 && eras[0].from == null && eras[0].to === Infinity) return eras[0].addr;
  for (const era of eras) {
    // An era with an undetermined boundary cannot be SHOWN to contain a block.
    // Attribution is a positive claim ("this event ran under that implementation")
    // and it is left off rather than guessed.
    if (era.from == null || era.to == null) continue;
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
