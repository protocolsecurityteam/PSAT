import { useEffect, useState } from "react";

import AddressLabelInline from "../../AddressLabelInline.jsx";
import { lookupLabel } from "../../api/addressLabels.js";
import { api } from "../../api/client.js";
import { formatDelay, formatEventAgo, formatUsd, shortAddr } from "../format.js";
import { EVENT_ACCENTS, EVENT_LABELS, TYPE_META } from "../meta.js";

export function PrincipalDetail({ principal, machines, onNavigate, onFocusContract, addressLabels, refreshAddressLabels }) {
  const [focusIdx, setFocusIdx] = useState(0);
  // Recent on-chain activity for safes/timelocks. Sourced from
  // /api/monitored-events keyed by address — the unified watcher writes
  // a MonitoredEvent row for every CallScheduled/CallExecuted, signer
  // change, and Safe-tx execution it sees. Lazy-loaded only when a
  // safe or timelock is selected so we don't hit the endpoint for
  // every principal click on contracts/EOAs/etc.
  const [activity, setActivity] = useState(null);
  const [activityError, setActivityError] = useState(null);
  const principalAddress = principal?.address?.toLowerCase();
  const principalType = principal?.type;
  const wantsActivity = principalType === "safe" || principalType === "timelock";

  useEffect(() => {
    if (!wantsActivity || !principalAddress) {
      setActivity(null);
      setActivityError(null);
      return;
    }
    let cancelled = false;
    setActivity(null);
    setActivityError(null);
    api(`/api/monitored-events?address=${encodeURIComponent(principalAddress)}&limit=15`)
      .then((rows) => { if (!cancelled) setActivity(Array.isArray(rows) ? rows : []); })
      .catch((e) => { if (!cancelled) setActivityError(e.message || String(e)); });
    return () => { cancelled = true; };
  }, [wantsActivity, principalAddress]);

  if (!principal) return null;
  const type = TYPE_META[principal.type] || TYPE_META.unknown;
  const principalChain = principal.chain || "ethereum";
  const controlled = (principal.controls || []);
  const controlledMachines = machines.filter((m) =>
    controlled.some((a) => a.toLowerCase() === m.address?.toLowerCase())
  );
  const owners = principal.details?.owners || [];
  const threshold = principal.details?.threshold;
  const delay = principal.details?.delay;

  // Verified call rights (server-computed principal.controls_detail): the
  // concrete functions / capability tags this principal can actually invoke,
  // per contract. Distinct from the CGN-derived "Governance Path" list below,
  // which is a reachability path and carries no direct-call-rights guarantee.
  const callDetail = principal.controls_detail || [];
  const nameByAddr = new Map(machines.map((m) => [m.address?.toLowerCase(), m.name]));

  return (
    <article className="ps-machine" style={{ borderLeft: `2px solid ${type.accent}` }}>
      <header className="ps-machine-header">
        <div className="ps-machine-name">
          {lookupLabel(addressLabels, principal.address, principalChain) || principal.label || shortAddr(principal.address)}
        </div>
        <div className="ps-machine-address">{principal.address}</div>
        {/* Only EOAs and Safes are "just an address" — add the inline label
            affordance for those. Timelocks and contracts already have a
            meaningful contract-level name. */}
        {(principal.type === "eoa" || principal.type === "safe") && (
          <div style={{ marginTop: 6 }}>
            <AddressLabelInline
              address={principal.address}
              chain={principalChain}
              labels={addressLabels}
              refreshAll={refreshAddressLabels}
            />
          </div>
        )}
        <div className="ps-machine-badges">
          <span className="ps-badge" style={{ "--badge-accent": type.accent }}>{type.label}</span>
          {principal.type === "safe" && threshold && (
            <span className="ps-badge" style={{ "--badge-accent": "#6a9e94" }}>{threshold}/{owners.length} threshold</span>
          )}
          {principal.type === "timelock" && delay > 0 && (
            <span className="ps-badge" style={{ "--badge-accent": "#9a8a6e" }}>{formatDelay(delay)} delay</span>
          )}
        </div>
      </header>

      {principal.type === "safe" && owners.length > 0 && (
        <section className="ps-principal-section">
          <div className="ps-principal-section-hdr">Signers ({owners.length})</div>
          {owners.map((addr) => {
            const labeled = lookupLabel(addressLabels, addr, principalChain);
            return (
              <div key={addr} className="ps-principal-signer">
                <span className="ps-principal-signer-row">
                  {labeled && <span className="ps-principal-signer-name">{labeled}</span>}
                  <span className="ps-principal-signer-addr">{addr}</span>
                </span>
                <AddressLabelInline
                  address={addr}
                  chain={principalChain}
                  labels={addressLabels}
                  refreshAll={refreshAddressLabels}
                  size="xs"
                />
              </div>
            );
          })}
        </section>
      )}

      {callDetail.length > 0 && (
        <section className="ps-principal-section">
          <div className="ps-principal-section-hdr">
            <span title="Verified from per-function access control (FunctionPrincipal) — the concrete privileged functions this principal can call">
              Can Call ({callDetail.length})
            </span>
          </div>
          {callDetail.map((d) => (
            <div
              key={d.address}
              className="ps-principal-controlled ps-principal-clickable"
              onClick={() => onFocusContract && onFocusContract(d.address)}
              title={d.functions?.join(", ")}
            >
              <span className="ps-principal-controlled-name">
                {nameByAddr.get(d.address?.toLowerCase()) || shortAddr(d.address)}
              </span>
              <span className="ps-principal-cancall-caps">
                {d.capabilities && d.capabilities.length
                  ? d.capabilities.join(", ")
                  : (d.functions || []).slice(0, 3).join(", ") +
                    ((d.functions || []).length > 3 ? ` +${d.functions.length - 3}` : "")}
              </span>
              <span className="ps-principal-goto">→</span>
            </div>
          ))}
        </section>
      )}

      {controlledMachines.length > 0 && (
        <section className="ps-principal-section">
          <div className="ps-principal-section-hdr" style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            {/* This list is derived from the recursive control graph, not from
                function-level permissions. Labeling it "Controls" would claim
                direct call rights — which we can't guarantee without per-
                function role-holder validation (see service/policy TODO). */}
            <span title="Computed from the recursive control graph — does not imply direct call rights on these contracts' privileged functions">
              Appears In Governance Path For ({controlledMachines.length})
            </span>
            {controlledMachines.length > 1 && (
              <div className="ps-search-arrows" style={{ marginLeft: 8 }}>
                <button onClick={() => {
                  const prev = (focusIdx - 1 + controlledMachines.length) % controlledMachines.length;
                  setFocusIdx(prev);
                  onFocusContract && onFocusContract(controlledMachines[prev].address);
                }}>◀</button>
                <span className="ps-search-counter">{focusIdx + 1} / {controlledMachines.length}</span>
                <button onClick={() => {
                  const next = (focusIdx + 1) % controlledMachines.length;
                  setFocusIdx(next);
                  onFocusContract && onFocusContract(controlledMachines[next].address);
                }}>▶</button>
              </div>
            )}
          </div>
          {controlledMachines.map((m, i) => (
            <div
              key={m.address}
              className={`ps-principal-controlled ps-principal-clickable${i === focusIdx ? " ps-principal-focused" : ""}`}
              onClick={() => {
                setFocusIdx(i);
                onFocusContract && onFocusContract(m.address);
              }}
            >
              <span className="ps-principal-controlled-name">{m.name || shortAddr(m.address)}</span>
              <span className="ps-principal-controlled-addr">{shortAddr(m.address)}</span>
              {m.total_usd ? <span className="ps-search-preview-value">{formatUsd(m.total_usd)}</span> : null}
              <span className="ps-principal-goto">→</span>
            </div>
          ))}
        </section>
      )}

      {/* Recent on-chain activity. Pulls the last 15 MonitoredEvent rows
       * for this address — the unified watcher writes one per
       * CallScheduled/CallExecuted, signer change, and Safe tx
       * execution it sees. Empty state explains what the user would
       * see once we get historical backfill working (#4c). */}
      {wantsActivity ? (
        <section className="ps-principal-section">
          <div className="ps-principal-section-hdr">Recent activity</div>
          {activityError ? (
            <div className="ps-inspector-empty">Activity lookup failed: {activityError}</div>
          ) : activity == null ? (
            <div className="ps-inspector-empty">Loading activity…</div>
          ) : activity.length === 0 ? (
            <div className="ps-inspector-empty">
              No on-chain activity recorded yet. The watcher captures events going forward from enrollment;
              historical events before then aren't backfilled yet.
            </div>
          ) : (
            <div className="ps-activity-list">
              {activity.map((evt) => {
                const label = EVENT_LABELS[evt.event_type] || evt.event_type.replace(/_/g, " ");
                const accent = EVENT_ACCENTS[evt.event_type] || "#94a3b8";
                const ago = formatEventAgo(evt.detected_at);
                const txShort = evt.tx_hash ? `${evt.tx_hash.slice(0, 10)}…${evt.tx_hash.slice(-4)}` : null;
                return (
                  <div key={evt.id} className="ps-activity-row">
                    <span className="ps-badge" style={{ "--badge-accent": accent }}>{label}</span>
                    {ago ? <span className="ps-activity-ago">{ago}</span> : null}
                    {evt.block_number ? <span className="ps-activity-block">block {evt.block_number.toLocaleString()}</span> : null}
                    {txShort ? <span className="ps-activity-tx mono">{txShort}</span> : null}
                  </div>
                );
              })}
            </div>
          )}
        </section>
      ) : null}
    </article>
  );
}
