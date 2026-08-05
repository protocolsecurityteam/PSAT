import { useCallback, useEffect, useMemo, useState } from "react";

import { api } from "../../../api/client.js";
import { proxyDisplayName } from "../../../displayName.js";
import { coalesceChain, entityKey } from "../../entityKey.js";
import { shortenAddress } from "../../../graph.js";
import {
  decodeEvent,
  eventKind,
  eventKindLabel,
  eventSalience,
  relativeTime,
  salienceAllows,
  scannerHealth,
  targetText,
} from "../../../monitoring/format.js";

const POLL_MS = 30_000;

function earliestEnrollment(contracts) {
  const stamps = (contracts || [])
    .map((c) => c.created_at)
    .filter(Boolean)
    .map((s) => new Date(s).getTime())
    .filter(Number.isFinite);
  if (!stamps.length) return null;
  return new Date(Math.min(...stamps));
}

// Nothing selected → protocol-wide activity: scanner health, a monitored-count
// summary, and the newest events across every monitored address. Absorbs the
// standalone monitoring page's overview. The canvas is the spatial protocol map;
// clicking a recent row selects that contract → the panel switches to entity mode.
export function ProtocolActivity({
  protocolId,
  companyName,
  contracts,
  machines,
  onSelect,
  now,
  chain = "ethereum",
  minSalience = "routine",
  onHiddenCount,
  nameFor,
}) {
  const [events, setEvents] = useState([]);
  const [labelMap, setLabelMap] = useState({});
  const activeChain = coalesceChain(chain);

  const refresh = useCallback(async () => {
    if (!protocolId) return;
    try {
      const evs = await api(`/api/protocols/${protocolId}/events?limit=100`);
      setEvents(Array.isArray(evs) ? evs : []);
    } catch {
      /* transient — keep the last good feed */
    }
  }, [protocolId]);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, POLL_MS);
    return () => clearInterval(t);
  }, [refresh]);

  useEffect(() => {
    let cancelled = false;
    api(`/api/company/${encodeURIComponent(companyName)}/addresses`)
      .then((addrs) => {
        if (cancelled) return;
        // The /addresses payload spans every chain, so key by (chain, address)
        // (inv. 13): a same-address cross-chain pair otherwise last-wins one
        // chain's display name onto the other. Rows carry their own chain.
        const map = {};
        for (const a of addrs?.all_addresses || []) {
          if (!a?.address) continue;
          map[entityKey(a.chain, a.address)] = {
            name: a.name || null,
            implName: a.implementation_name || null,
            isProxy: !!a.is_proxy,
          };
        }
        setLabelMap(map);
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [companyName]);

  const machineByAddress = useMemo(() => {
    const map = new Map();
    for (const m of machines || []) {
      const a = m.address?.toLowerCase();
      if (a) map.set(a, m);
    }
    return map;
  }, [machines]);

  const contractById = useMemo(() => {
    const map = new Map();
    for (const c of contracts || []) map.set(c.id, c);
    return map;
  }, [contracts]);

  // Event/contract rows carry no first-class chain field, and this panel is
  // rendered per active chain (its contracts + machines are already scoped), so
  // resolve the label with the row's own chain when known, else the active
  // chain (never a raw bare-address lookup that could cross chains). Cosmetic —
  // this drives the display name, not identity.
  const friendlyName = useCallback((addr, rowChain) => {
    if (!addr) return "Unknown";
    const entry = labelMap[entityKey(rowChain ?? activeChain, addr)];
    const machine = machineByAddress.get(addr.toLowerCase());
    const pretty = proxyDisplayName({
      name: entry?.name || machine?.name,
      isProxy: entry?.isProxy ?? machine?.is_proxy,
      implName: entry?.implName,
    });
    if (pretty && !/^0x/i.test(pretty)) return pretty;
    return shortenAddress(addr);
  }, [labelMap, machineByAddress, activeChain]);

  const health = scannerHealth(contracts, now);
  const headBlock = (contracts || []).reduce((max, c) => Math.max(max, c.last_scanned_block || 0), 0);
  const liveSince = earliestEnrollment(contracts);
  // Filtered before the slice, so the threshold changes WHICH eight rows the
  // feed shows rather than shortening it.
  const admitted = useMemo(
    () => (events || []).filter((ev) => salienceAllows(eventSalience(ev), minSalience)),
    [events, minSalience],
  );
  const hidden = (events || []).length - admitted.length;
  useEffect(() => {
    if (onHiddenCount) onHiddenCount(hidden);
  }, [hidden, onHiddenCount]);
  const recent = admitted.slice(0, 8);

  return (
    <section className="ps-activity-protocol">
      <div className="ps-activity-row-between">
        <div>
          <div className="ps-activity-eyebrow">Activity</div>
          <div className="ps-activity-protocol-name">{companyName}</div>
        </div>
        <span className={`ps-activity-health ${health.tone}`}>
          <span className="ps-activity-pulse" />{health.label}
        </span>
      </div>

      <div className="ps-activity-card">
        <div className="ps-activity-kv-line"><b>{contracts?.length || 0}</b> addresses monitored</div>
        <div className="ps-activity-kv-line mono">block {headBlock ? headBlock.toLocaleString() : "—"}</div>
        {liveSince ? (
          <div className="ps-activity-kv-line faint">
            Live since <b>{liveSince.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" })}</b>
            {/* TODO(activity): "· upgrade history back to X" needs a protocol-wide
                earliest-deployment source; not cheaply available client-side. */}
          </div>
        ) : null}
      </div>

      <div>
        <div className="ps-activity-sect-title" style={{ marginBottom: 8 }}>Recent across protocol</div>
        {recent.length === 0 && hidden > 0 ? (
          // Events exist and the threshold withheld all of them. "The scanner
          // hasn't seen an event" is a claim about the scanner; this is a
          // statement about the filter, which is the only thing that happened.
          // Checked before the absence prose for the same reason the Timeline
          // checks its own hidden counts first.
          <div className="ps-activity-empty">
            {hidden === 1
              ? "1 event is hidden by the current filter."
              : `${hidden} events are hidden by the current filter.`}
          </div>
        ) : recent.length === 0 ? (
          <div className="ps-activity-empty">Nothing captured yet — the scanner hasn&apos;t seen an event.</div>
        ) : (
          <div className="ps-activity-recent">
            {recent.map((ev) => {
              const contract = contractById.get(ev.monitored_contract_id);
              const addr = contract?.address || ev.data?.contract_address;
              const type = contract?.contract_type || "regular";
              const machine = addr ? machineByAddress.get(addr.toLowerCase()) : null;
              const kind = eventKind(ev);
              const decoded = decodeEvent(ev, { nameFor });
              return (
                <button
                  key={ev.id}
                  type="button"
                  className="ps-activity-recent-row"
                  onClick={() => onSelect && onSelect(machine || (addr ? { address: addr } : null))}
                  disabled={!addr}
                >
                  <div className="ps-activity-recent-main">
                    <div className="ps-activity-recent-id">
                      <span className={`ps-activity-badge ${type}`}>{type}</span>
                      <span className="ps-activity-recent-name">{friendlyName(addr, contract?.chain)}</span>
                    </div>
                    <div className="ps-activity-recent-line">
                      <span className={`ps-activity-kind k-${kind}`}>{eventKindLabel(ev)}</span>
                      <span
                        className="ps-activity-recent-sub"
                        title={
                          [decoded.titleDetail, decoded.target?.onGraph === false ? decoded.target.address : null]
                            .filter(Boolean)
                            .join(" · ") || undefined
                        }
                      >
                        {[decoded.title, targetText(decoded.target), decoded.sub].filter(Boolean).join(" · ")}
                      </span>
                    </div>
                  </div>
                  <div className="ps-activity-recent-time">{relativeTime(ev.detected_at, now)}</div>
                </button>
              );
            })}
          </div>
        )}
      </div>

      <div className="ps-activity-hint">
        The canvas is the spatial map of the protocol — select a node to open its full timeline.
      </div>
    </section>
  );
}
