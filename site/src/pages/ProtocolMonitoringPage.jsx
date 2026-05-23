import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { api } from "../api/client.js";
import { blockExplorerAddressUrl } from "../blockExplorer.js";
import { shortenAddress } from "../graph.js";
import {
  decodeEvent,
  eventKind,
  eventKindLabel,
  lastEventByContract,
  relativeTime,
  scannerHealth,
  stateRows,
} from "../monitoring/format.js";

// 30s — enough for the 10-minute server scan loop without burning a
// request every 10s like the old page did.
const POLL_INTERVAL_MS = 30_000;

// Event types grouped for the right-pane filter bar. Order matters; users
// scan left-to-right. Critical → less critical.
const FILTER_GROUPS = [
  { id: "upgrade", label: "Upgrade", types: ["upgraded", "new_implementation", "target_updated", "upgraded_revision", "changed_master_copy", "beacon_upgraded", "admin_changed", "diamond_cut", "new_pending_implementation"] },
  { id: "owner", label: "Ownership", types: ["ownership_transferred"] },
  { id: "pause", label: "Pause", types: ["paused", "unpaused"] },
  { id: "role", label: "Role", types: ["role_granted", "role_revoked"] },
  { id: "signer", label: "Signer", types: ["signer_added", "signer_removed", "threshold_changed"] },
  { id: "timelock", label: "Timelock", types: ["timelock_scheduled", "timelock_executed", "delay_changed"] },
  { id: "safe", label: "Safe tx", types: ["safe_tx_executed", "safe_tx_failed", "safe_module_executed", "safe_module_failed"] },
  { id: "state", label: "State", types: ["state_changed_poll"] },
];

const ALL_EVENT_TYPES = FILTER_GROUPS.flatMap((g) => g.types);

function explorerTxUrl(txHash, chain = "ethereum") {
  // Lean on blockExplorerAddressUrl's chain mapping by swapping the path segment.
  const addrUrl = blockExplorerAddressUrl("0x", chain);
  if (!addrUrl) return null;
  return `${addrUrl.replace("/address/0x", "/tx/")}${txHash}`;
}

export default function ProtocolMonitoringPage({ companyName }) {
  const [protocolId, setProtocolId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [noProtocol, setNoProtocol] = useState(false);
  const [contracts, setContracts] = useState([]);
  const [subscriptions, setSubscriptions] = useState([]);
  const [events, setEvents] = useState([]);
  const [labelMap, setLabelMap] = useState({}); // address-lower → friendly name
  const [error, setError] = useState(null);
  const [reEnrolling, setReEnrolling] = useState(false);

  // UI state
  const [selectedContractId, setSelectedContractId] = useState(null); // null = "All"
  const [activeKinds, setActiveKinds] = useState(new Set()); // empty = all
  const [search, setSearch] = useState("");
  const [showWebhookModal, setShowWebhookModal] = useState(false);

  // Modal form state
  const [webhookUrl, setWebhookUrl] = useState("");
  const [webhookLabel, setWebhookLabel] = useState("");
  const [webhookEventTypes, setWebhookEventTypes] = useState([]);
  const [showEventPicker, setShowEventPicker] = useState(false);
  const [addingWebhook, setAddingWebhook] = useState(false);

  // Tick state used to keep the "X ago" labels fresh without a re-fetch.
  const [, setNowTick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setNowTick((n) => n + 1), 30_000);
    return () => clearInterval(t);
  }, []);

  // Fetch protocol_id + friendly address labels in one shot.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [overview, addrs] = await Promise.all([
          api(`/api/company/${encodeURIComponent(companyName)}`),
          api(`/api/company/${encodeURIComponent(companyName)}/addresses`).catch(() => ({ all_addresses: [] })),
        ]);
        if (cancelled) return;
        if (overview.protocol_id) {
          setProtocolId(overview.protocol_id);
          const map = {};
          for (const a of addrs?.all_addresses || []) {
            if (!a?.address) continue;
            const key = a.address.toLowerCase();
            map[key] = {
              name: a.name || null,
              implName: a.implementation_name || null,
              chain: a.chain || "ethereum",
            };
          }
          setLabelMap(map);
        } else {
          setNoProtocol(true);
        }
      } catch {
        if (!cancelled) setNoProtocol(true);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [companyName]);

  const refresh = useMemo(() => {
    if (!protocolId) return null;
    return async () => {
      try {
        const [c, s, e] = await Promise.all([
          api(`/api/protocols/${protocolId}/monitoring`),
          api(`/api/protocols/${protocolId}/subscriptions`),
          api(`/api/protocols/${protocolId}/events?limit=100`),
        ]);
        setContracts(c);
        setSubscriptions(s);
        setEvents(e);
      } catch (err) {
        console.error("Failed to load monitoring data:", err);
      }
    };
  }, [protocolId]);

  useEffect(() => {
    if (!refresh) return;
    refresh();
    const timer = setInterval(refresh, POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [refresh]);

  const friendlyName = useCallback(
    (addr) => {
      if (!addr) return "Unknown";
      const entry = labelMap[addr.toLowerCase()];
      const raw = entry?.name || entry?.implName;
      if (raw && !/^0x/i.test(raw)) return raw;
      return shortenAddress(addr);
    },
    [labelMap],
  );

  const lastEventTimes = useMemo(() => lastEventByContract(events), [events]);

  const sortedContracts = useMemo(() => {
    // Group by contract_type priority, then by activity recency, then name.
    const TYPE_RANK = { safe: 0, timelock: 1, proxy: 2, pausable: 3, role_control: 4, regular: 5 };
    return [...contracts].sort((a, b) => {
      const ra = TYPE_RANK[a.contract_type] ?? 9;
      const rb = TYPE_RANK[b.contract_type] ?? 9;
      if (ra !== rb) return ra - rb;
      const la = lastEventTimes[a.id];
      const lb = lastEventTimes[b.id];
      if (la && lb) return new Date(lb).getTime() - new Date(la).getTime();
      if (la) return -1;
      if (lb) return 1;
      return friendlyName(a.address).localeCompare(friendlyName(b.address));
    });
  }, [contracts, lastEventTimes, friendlyName]);

  const selectedContract = useMemo(
    () => contracts.find((c) => c.id === selectedContractId) || null,
    [contracts, selectedContractId],
  );

  const filteredEvents = useMemo(() => {
    const kindsActive = activeKinds.size > 0;
    const needle = search.trim().toLowerCase();
    return events.filter((e) => {
      if (selectedContractId && e.monitored_contract_id !== selectedContractId) return false;
      if (kindsActive && !activeKinds.has(eventKind(e))) return false;
      if (needle) {
        const hay = [
          e.tx_hash,
          e.data?.contract_address,
          ...Object.values(e.data || {}).map((v) => (typeof v === "string" ? v : "")),
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
  }, [events, selectedContractId, activeKinds, search]);

  const eventsForSelected = useMemo(() => {
    if (!selectedContractId) return events;
    return events.filter((e) => e.monitored_contract_id === selectedContractId);
  }, [events, selectedContractId]);

  const toggleKind = (kind) => {
    setActiveKinds((prev) => {
      const next = new Set(prev);
      if (next.has(kind)) next.delete(kind);
      else next.add(kind);
      return next;
    });
  };

  async function addWebhook(ev) {
    ev.preventDefault();
    if (!webhookUrl.trim() || !protocolId) return;
    setAddingWebhook(true);
    setError(null);
    try {
      const body = {
        discord_webhook_url: webhookUrl.trim(),
        label: webhookLabel.trim() || null,
      };
      if (webhookEventTypes.length > 0) {
        body.event_filter = { event_types: webhookEventTypes };
      }
      await api(`/api/protocols/${protocolId}/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      setWebhookUrl("");
      setWebhookLabel("");
      setWebhookEventTypes([]);
      setShowEventPicker(false);
      if (refresh) refresh();
    } catch (err) {
      setError(String(err.message || err));
    } finally {
      setAddingWebhook(false);
    }
  }

  async function reEnroll() {
    if (!protocolId) return;
    setReEnrolling(true);
    setError(null);
    try {
      await api(`/api/protocols/${protocolId}/re-enroll`, { method: "POST" });
      if (refresh) refresh();
    } catch (err) {
      setError(String(err.message || err));
    } finally {
      setReEnrolling(false);
    }
  }

  async function toggleContractActive(contractId, currentActive, evt) {
    evt?.stopPropagation();
    try {
      // Optimistic update so the row reacts immediately. If the API call
      // fails, refresh() in the catch puts truth back.
      setContracts((prev) =>
        prev.map((c) => (c.id === contractId ? { ...c, is_active: !currentActive } : c)),
      );
      await api(`/api/monitored-contracts/${contractId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ is_active: !currentActive }),
      });
      if (refresh) refresh();
    } catch (err) {
      console.error("Failed to toggle contract:", err);
      if (refresh) refresh();
    }
  }

  async function removeSubscription(subId) {
    try {
      await api(`/api/protocol-subscriptions/${subId}`, { method: "DELETE" });
      if (refresh) refresh();
    } catch (err) {
      console.error("Failed to remove subscription:", err);
    }
  }

  if (loading) {
    return (
      <div className="pm-fullpage">Loading protocol monitoring…</div>
    );
  }

  if (noProtocol) {
    return (
      <div className="page">
        <section className="panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Protocol Monitoring</p>
              <h2>Not Available</h2>
            </div>
          </div>
          <p className="empty">No protocol monitoring available for this company. Run a protocol analysis first.</p>
        </section>
      </div>
    );
  }

  const health = scannerHealth(contracts);
  const headBlock = contracts.reduce((max, c) => Math.max(max, c.last_scanned_block || 0), 0);
  const activeCount = contracts.filter((c) => c.is_active).length;

  return (
    <>
      <div className="pm-shell">
        <StatusBar
          health={health}
          headBlock={headBlock}
          activeCount={activeCount}
          totalCount={contracts.length}
          reEnrolling={reEnrolling}
          onReEnroll={reEnroll}
        />
        <div className="pm-console">
          <ContractsPane
            contracts={sortedContracts}
            selectedId={selectedContractId}
            lastEventTimes={lastEventTimes}
            friendlyName={friendlyName}
            onSelect={(id) => setSelectedContractId(id === selectedContractId ? null : id)}
            onToggleActive={toggleContractActive}
          />
          <EventsPane
            events={filteredEvents}
            selectedContract={selectedContract}
            allEventsForSelected={eventsForSelected}
            activeKinds={activeKinds}
            onToggleKind={toggleKind}
            search={search}
            onSearch={setSearch}
            friendlyName={friendlyName}
            labelMap={labelMap}
            onClearSelection={() => setSelectedContractId(null)}
          />
        </div>
        {error && <p className="pm-err" style={{ position: "fixed", bottom: 70, right: 18 }}>{error}</p>}
      </div>

      <NotifMini
        count={subscriptions.length}
        onOpen={() => setShowWebhookModal(true)}
      />

      {showWebhookModal && (
        <WebhookModal
          subscriptions={subscriptions}
          onClose={() => setShowWebhookModal(false)}
          onRemove={removeSubscription}
          onSubmit={addWebhook}
          adding={addingWebhook}
          url={webhookUrl}
          label={webhookLabel}
          eventTypes={webhookEventTypes}
          showPicker={showEventPicker}
          onUrl={setWebhookUrl}
          onLabel={setWebhookLabel}
          onToggleType={(t) =>
            setWebhookEventTypes((prev) =>
              prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t]
            )
          }
          onTogglePicker={() => setShowEventPicker((v) => !v)}
        />
      )}
    </>
  );
}

// -------------------------------------------------------------------- subviews

function StatusBar({ health, headBlock, activeCount, totalCount, reEnrolling, onReEnroll }) {
  return (
    <div className="pm-statusbar" data-testid="pm-statusbar">
      <span className={`pm-pulse ${health.tone}`}>
        <span className="pm-dot" /> {health.label}
      </span>
      <span className="pm-meta">block {headBlock ? headBlock.toLocaleString() : "—"}</span>
      <span className="pm-meta">·</span>
      <span className="pm-meta">{activeCount} of {totalCount} contracts active</span>
      <span className="pm-spacer" />
      <button className="pm-btn" disabled={reEnrolling} onClick={onReEnroll} title="Re-run protocol enrollment to discover newly added contracts. Existing per-contract active toggles are preserved.">
        {reEnrolling ? "Re-enrolling…" : "Re-enroll"}
      </button>
    </div>
  );
}

function ContractsPane({ contracts, selectedId, lastEventTimes, friendlyName, onSelect, onToggleActive }) {
  return (
    <div className="pm-pane">
      <div className="pm-pane-head">
        <h2>Contracts</h2>
        <span className="pm-count">{contracts.length} watched</span>
      </div>
      <div className="pm-contracts">
        {contracts.length === 0 ? (
          <div className="pm-empty">
            <b>No contracts enrolled</b>
            Click <em>Re-enroll</em> above to scan this protocol's analyzed contracts and add monitorable ones.
          </div>
        ) : (
          contracts.map((c) => (
            <ContractRow
              key={c.id}
              contract={c}
              selected={c.id === selectedId}
              lastEvent={lastEventTimes[c.id]}
              friendlyName={friendlyName}
              onSelect={() => onSelect(c.id)}
              onToggleActive={(e) => onToggleActive(c.id, c.is_active, e)}
            />
          ))
        )}
      </div>
    </div>
  );
}

function ContractRow({ contract, selected, lastEvent, friendlyName, onSelect, onToggleActive }) {
  const rows = useMemo(() => stateRows(contract), [contract]);
  const badge = contract.contract_type || "regular";
  return (
    <button
      type="button"
      className={`pm-contract${selected ? " sel" : ""}${contract.is_active ? "" : " inactive"}`}
      onClick={onSelect}
      data-contract-id={contract.id}
    >
      <div className="pm-c-top">
        <span className={`pm-badge ${badge}`}>{badge}</span>
        <span className="pm-name">{friendlyName(contract.address)}</span>
        <span className="pm-c-addr">{shortenAddress(contract.address)}</span>
      </div>
      <div className="pm-kv">
        {rows.map((r) => (
          <React.Fragment key={r.k}>
            <div className="pm-k">{r.k}</div>
            <div className={`pm-v${r.tone ? " " + r.tone : ""}`}>{r.v}</div>
          </React.Fragment>
        ))}
        <div className="pm-k">Last event</div>
        <div className="pm-v muted">{lastEvent ? relativeTime(lastEvent) : "none recorded"}</div>
      </div>
      <div style={{ marginTop: 8, display: "flex", justifyContent: "flex-end" }}>
        <span
          role="button"
          tabIndex={0}
          className="pm-btn-link"
          onClick={onToggleActive}
          onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") onToggleActive(e); }}
          style={{ fontSize: 11, color: contract.is_active ? "var(--status-ok)" : "var(--muted)" }}
        >
          {contract.is_active ? "● active" : "○ paused"}
        </span>
      </div>
    </button>
  );
}

function EventsPane({
  events,
  selectedContract,
  allEventsForSelected,
  activeKinds,
  onToggleKind,
  search,
  onSearch,
  friendlyName,
  labelMap,
  onClearSelection,
}) {
  const headerTitle = selectedContract
    ? friendlyName(selectedContract.address)
    : "All contracts";
  const headerAddr = selectedContract ? selectedContract.address : null;
  const headerChain = selectedContract?.chain || "ethereum";

  return (
    <div className="pm-pane">
      <div className="pm-zone-detail">
        <div className="pm-z-name">{headerTitle}</div>
        {headerAddr && (
          <a
            className="pm-z-addr pm-z-link"
            href={blockExplorerAddressUrl(headerAddr, headerChain)}
            target="_blank"
            rel="noreferrer noopener"
          >
            {headerAddr} ↗
          </a>
        )}
        <div className="pm-z-stat">
          <b>{allEventsForSelected.length}</b> event{allEventsForSelected.length === 1 ? "" : "s"} in window
          {selectedContract && (
            <>
              {" · "}
              <button className="pm-btn-link" onClick={onClearSelection}>show all</button>
            </>
          )}
        </div>
      </div>
      <div className="pm-fbar">
        <span
          className={`pm-fchip${activeKinds.size === 0 ? " on" : ""}`}
          onClick={() => activeKinds.size > 0 && Array.from(activeKinds).forEach(onToggleKind)}
          role="button"
        >
          All
        </span>
        {FILTER_GROUPS.map((g) => (
          <span
            key={g.id}
            className={`pm-fchip${activeKinds.has(g.id) ? " on" : ""}`}
            onClick={() => onToggleKind(g.id)}
            role="button"
          >
            {g.label}
          </span>
        ))}
        <input
          className="pm-search"
          placeholder="Search by tx, address, role hash…"
          value={search}
          onChange={(e) => onSearch(e.target.value)}
        />
      </div>
      <div className="pm-stream">
        {events.length === 0 ? (
          <div className="pm-empty">
            <b>No matching events</b>
            {selectedContract
              ? "This contract hasn't fired anything in the window — or your filters are too narrow."
              : "Nothing to show. Filters too narrow, or the scanner hasn't seen anything yet."}
          </div>
        ) : (
          events.map((evt) => (
            <EventRow
              key={evt.id}
              evt={evt}
              friendlyName={friendlyName}
              chainOf={(addr) => labelMap[String(addr || "").toLowerCase()]?.chain || "ethereum"}
              isAllView={!selectedContract}
            />
          ))
        )}
      </div>
    </div>
  );
}

function EventRow({ evt, friendlyName, chainOf, isAllView }) {
  const decoded = useMemo(() => decodeEvent(evt), [evt]);
  const kind = eventKind(evt);
  const label = eventKindLabel(evt);
  const addr = evt.data?.contract_address;
  const chain = chainOf(addr);
  return (
    <div className="pm-ev">
      <div className="pm-when" title={evt.detected_at}>{relativeTime(evt.detected_at)}</div>
      <span className={`pm-type k-${kind}`}>{label}</span>
      <div className="pm-msg">
        <b>{decoded.title}</b>
        {isAllView && addr && (
          <span className="pm-msg-on">on {friendlyName(addr)}</span>
        )}
        {decoded.sub && <span className="pm-msg-sub">{decoded.sub}</span>}
      </div>
      <div className="pm-ext">
        {evt.tx_hash ? (
          <a href={explorerTxUrl(evt.tx_hash, chain)} target="_blank" rel="noreferrer noopener">
            {shortenAddress(evt.tx_hash)} ↗
          </a>
        ) : (
          <span className="pm-blk">no tx</span>
        )}
        {evt.block_number ? <span className="pm-blk">block {evt.block_number.toLocaleString()}</span> : null}
      </div>
    </div>
  );
}

function NotifMini({ count, onOpen }) {
  return (
    <div className="pm-notif" data-testid="pm-notif">
      <span>
        {count === 0 ? (
          <><b>No Discord webhook</b> — get pinged on upgrades, owner changes, pauses</>
        ) : (
          <><b>{count}</b> Discord {count === 1 ? "webhook" : "webhooks"} active</>
        )}
      </span>
      <button className="pm-notif-cta" onClick={onOpen}>
        {count === 0 ? "+ Add →" : "Manage →"}
      </button>
    </div>
  );
}

function WebhookModal({
  subscriptions,
  onClose,
  onRemove,
  onSubmit,
  adding,
  url,
  label,
  eventTypes,
  showPicker,
  onUrl,
  onLabel,
  onToggleType,
  onTogglePicker,
}) {
  const overlayRef = useRef(null);
  useEffect(() => {
    function onKey(e) { if (e.key === "Escape") onClose(); }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div
      className="pm-modal-back"
      ref={overlayRef}
      onClick={(e) => { if (e.target === overlayRef.current) onClose(); }}
    >
      <div className="pm-modal" role="dialog" aria-label="Discord webhooks">
        <div className="pm-modal-head">
          <h2>Discord notifications</h2>
          <span className="pm-modal-sub">Get pinged when governance events fire on this protocol.</span>
          <button className="pm-modal-close" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="pm-modal-body">
          <section className="pm-modal-section">
            <h3>Add a webhook</h3>
            <form onSubmit={onSubmit}>
              <div className="pm-form-row">
                <input
                  className="pm-input mono"
                  placeholder="https://discord.com/api/webhooks/…"
                  value={url}
                  onChange={(e) => onUrl(e.target.value)}
                  required
                />
                <input
                  className="pm-input"
                  placeholder="Label (optional)"
                  value={label}
                  onChange={(e) => onLabel(e.target.value)}
                />
              </div>
              <div>
                <button type="button" className="pm-btn-link" onClick={onTogglePicker}>
                  {showPicker ? "− Hide event filter" : "+ Filter by event type"}
                  {eventTypes.length > 0 && ` (${eventTypes.length} selected)`}
                </button>
                {showPicker && (
                  <div className="pm-evt-picker">
                    {ALL_EVENT_TYPES.map((et) => (
                      <button
                        key={et}
                        type="button"
                        className={`pm-fchip${eventTypes.includes(et) ? " on" : ""}`}
                        onClick={() => onToggleType(et)}
                      >
                        {et.replace(/_/g, " ")}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <div className="pm-form-actions">
                <button type="submit" className="pm-btn-primary" disabled={adding}>
                  {adding ? "Adding…" : "Add webhook"}
                </button>
                <button type="button" className="pm-btn-ghost" onClick={onClose}>Cancel</button>
              </div>
            </form>
          </section>

          <section className="pm-modal-section">
            <h3>Existing ({subscriptions.length})</h3>
            {subscriptions.length === 0 ? (
              <p className="empty">No webhooks yet. Add one above.</p>
            ) : (
              <div className="pm-sub-list">
                {subscriptions.map((s) => {
                  const filterTypes = Array.isArray(s.event_filter?.event_types) ? s.event_filter.event_types : [];
                  return (
                    <div key={s.id} className="pm-sub-row">
                      <div>
                        <div className="pm-sub-label">{s.label || "(no label)"}</div>
                        <span className="pm-sub-url">{s.discord_webhook_url || "—"}</span>
                      </div>
                      <span className="pm-sub-filter">
                        {filterTypes.length > 0 ? `${filterTypes.length} type${filterTypes.length === 1 ? "" : "s"}` : "all events"}
                      </span>
                      <button className="pm-sub-remove" onClick={() => onRemove(s.id)}>remove</button>
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}

