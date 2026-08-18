import { useCallback, useEffect, useMemo, useState } from "react";

import { api } from "../../../api/client.js";
import { coalesceChain, entityKey } from "../../entityKey.js";
import { principalLabel } from "../../format.js";
import { EntityActivity } from "./EntityActivity.jsx";
import { ProtocolActivity } from "./ProtocolActivity.jsx";
import { eventTypesFromGroupKeys } from "./helpers.js";

const POLL_MS = 30_000;

// Two positions, expressed as the MINIMUM salience each admits. A middle
// "Notable+" tier existed and was removed as redundant: its only distinct
// effect was hiding proven-routine rows, which the Timeline already
// collapses into a single "N routine events — show" disclosure inside All.
//
// Default is `alert` — an owner decision (2026-08-05): the timeline's
// non-alert traffic is overwhelmingly routine operations, so the tab opens
// on what needs eyes. The tradeoff is stated, not hidden: `notable` and
// `not_determined` (unrated) rows are behind the filter by default, and the
// always-rendered hidden count plus one-click All is what keeps that from
// being silent suppression.
const SALIENCE_MODES = [
  { key: "routine", label: "All" },
  { key: "alert", label: "Alerts" },
];

const DEFAULT_MIN_SALIENCE = "alert";

// The hidden count is rendered unconditionally, including when it is zero:
// a filter that silently withholds rows is the failure this axis exists to
// prevent, and "0 hidden" is the statement that it is not doing so.
function SalienceControl({ value, onChange, hiddenCount }) {
  return (
    <div className="ps-activity-salience" role="group" aria-label="Salience filter">
      {SALIENCE_MODES.map((mode) => (
        <button
          key={mode.key}
          type="button"
          className={`ps-activity-salience-opt${value === mode.key ? " on" : ""}`}
          aria-pressed={value === mode.key}
          onClick={() => onChange(mode.key)}
        >
          {mode.label}
        </button>
      ))}
      <span className="ps-activity-salience-hidden">{hiddenCount} hidden</span>
    </div>
  );
}

// Activity tab — the collapsed Monitor + Upgrades tabs. Two modes:
//   - nothing selected → protocol-wide feed (ProtocolActivity)
//   - a contract selected → status strip + alerts + unified timeline (EntityActivity)
// A principal (safe/timelock/EOA that isn't itself a monitored contract row —
// selectedMachine null) points the user at its contracts, mirroring the other
// sidebar panels. Reading is public; alert writes gate on isAdmin.
export function ActivityPanel({
  companyData,
  companyName,
  machines,
  selectedMachine,
  selectedPrincipal,
  onSelect,
  onPreview,
  onNavigate,
  isAdmin,
  cache,
  onCache,
  chain = "ethereum",
}) {
  const protocolId = companyData?.protocol_id;
  const activeChain = coalesceChain(chain);
  const [contracts, setContracts] = useState([]);
  const [subscriptions, setSubscriptions] = useState([]);
  const [savingAddr, setSavingAddr] = useState(null);
  const [now, setNow] = useState(() => Date.now());
  // Owned here so the choice survives switching selection; the count comes
  // back UP from whichever mode is mounted, because only it knows its rows.
  const [minSalience, setMinSalience] = useState(DEFAULT_MIN_SALIENCE);
  const [hiddenCount, setHiddenCount] = useState(0);

  // Display-only address→name resolver for the row renderers: the surface's
  // own contracts and principals. Never a witness — it changes how an address
  // READS in a sub line, not what any row claims.
  const nameFor = useMemo(() => {
    const byAddr = new Map();
    // companyData.contracts is the unfiltered set — machines drops
    // zero-function contracts, which are still legitimate call targets.
    for (const c of companyData?.contracts || []) {
      if (c?.address && c?.name) byAddr.set(String(c.address).toLowerCase(), c.name);
    }
    for (const m of machines || []) {
      if (m?.address && m?.name && !byAddr.has(String(m.address).toLowerCase())) {
        byAddr.set(String(m.address).toLowerCase(), m.name);
      }
    }
    for (const p of companyData?.principals || []) {
      const label = principalLabel(p?.label, p?.type, p?.address);
      if (p?.address && label && !label.startsWith("0x")) {
        const key = String(p.address).toLowerCase();
        if (!byAddr.has(key)) byAddr.set(key, label);
      }
    }
    return (addr) => byAddr.get(String(addr || "").toLowerCase()) || null;
  }, [machines, companyData]);

  const refresh = useCallback(async () => {
    if (!protocolId) return;
    try {
      const [monitoring, subs] = await Promise.all([
        api(`/api/protocols/${protocolId}/monitoring`),
        api(`/api/protocols/${protocolId}/subscriptions`),
      ]);
      setContracts(Array.isArray(monitoring) ? monitoring : []);
      setSubscriptions(Array.isArray(subs) ? subs : []);
    } catch {
      /* transient — keep last-good state */
    }
  }, [protocolId]);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, POLL_MS);
    return () => clearInterval(t);
  }, [refresh]);

  // "X ago" ticker — refreshes relative-time labels without a re-fetch.
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), POLL_MS);
    return () => clearInterval(t);
  }, []);

  // The /monitoring payload spans every chain the protocol monitors. Key by
  // (chain, address) (inv. 13) so a contract selected on the active chain
  // resolves ITS enrollment row, not the other chain's row at the same address
  // (F4). Monitoring rows carry their own chain (NULL≡ethereum via entityKey).
  const contractByAddress = useMemo(() => {
    const map = new Map();
    for (const c of contracts) {
      if (c.address) map.set(entityKey(c.chain, c.address), c);
    }
    return map;
  }, [contracts]);

  // Protocol-wide feed is scoped to the active chain, matching the rest of the
  // chain-scoped Surface page — the other chain's monitored rows don't leak in.
  const chainScopedContracts = useMemo(
    () => contracts.filter((c) => coalesceChain(c.chain) === activeChain),
    [contracts, activeChain],
  );

  // Attach a Discord delivery target for this contract's watched events. The
  // watch set itself is fixed at enrollment (by contract type + capabilities),
  // so the only operator control here is WHERE alerts are delivered.
  const attachWebhook = useCallback(async (contract, url, label, groupKeys) => {
    if (!protocolId || !url) return;
    const eventTypes = eventTypesFromGroupKeys(groupKeys);
    setSavingAddr(contract?.address?.toLowerCase() || null);
    try {
      await api(`/api/protocols/${protocolId}/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          discord_webhook_url: url,
          label,
          // `groups` states which alert groups this filter was saved against —
          // what tells the notifier the save used the post-split vocabulary, so
          // it will be taken at its word rather than folded into the legacy
          // grouping that put Safe executions under `signers`
          // (notifier._FILTER_GROUPS_KEY). It changes nothing today: the Alerts
          // control passes the WHOLE offered group set, so this save always
          // names every group the contract offers. It is written now because a
          // save made before the key existed and one made after it are
          // otherwise indistinguishable forever; a per-group selector is what
          // would make it bite.
          event_filter: eventTypes.length ? { event_types: eventTypes, groups: groupKeys } : null,
        }),
      });
    } catch {
      /* swallow */
    } finally {
      await refresh();
      setSavingAddr(null);
    }
  }, [protocolId, refresh]);

  if (!protocolId) {
    return (
      <section className="ps-principal-section">
        <div className="ps-inspector-empty">No protocol monitoring is available for this company.</div>
      </section>
    );
  }

  // Resolve the entity to time-line. A machine is the direct case. A principal
  // (safe/timelock) is normally not a machine — but safes/timelocks ARE enrolled
  // for monitoring, so if the selected principal has a MonitoredContract row,
  // show its timeline (the prototype's "Safe selected" column). Only a principal
  // with no monitored row (e.g. an EOA) shows a "monitoring not enabled" notice.
  const principalContract = selectedPrincipal
    ? contractByAddress.get(entityKey(activeChain, selectedPrincipal.address || "")) || null
    : null;
  const entityMachine = selectedMachine
    || (principalContract
      ? {
          address: selectedPrincipal.address,
          name: principalLabel(selectedPrincipal.label, selectedPrincipal.type, selectedPrincipal.address),
          is_proxy: false,
          chain: principalContract.chain,
          job_id: null,
        }
      : null);
  const entityContract = selectedMachine
    ? contractByAddress.get(entityKey(activeChain, selectedMachine.address || "")) || null
    : principalContract;

  if (!entityMachine && selectedPrincipal) {
    const who = principalLabel(selectedPrincipal.label, selectedPrincipal.type, selectedPrincipal.address);
    return (
      <section className="ps-principal-section">
        <div className="ps-inspector-empty">
          Monitoring is not enabled for {who}.
        </div>
      </section>
    );
  }

  const control = (
    <SalienceControl value={minSalience} onChange={setMinSalience} hiddenCount={hiddenCount} />
  );

  if (!entityMachine) {
    return (
      <>
        {control}
        <ProtocolActivity
          protocolId={protocolId}
          companyName={companyName}
          contracts={chainScopedContracts}
          machines={machines}
          onSelect={onSelect}
          now={now}
          chain={activeChain}
          minSalience={minSalience}
          onHiddenCount={setHiddenCount}
          nameFor={nameFor}
        />
      </>
    );
  }

  return (
    <>
      {control}
      <EntityActivity
        machine={entityMachine}
        contract={entityContract}
        subscriptions={subscriptions}
        isAdmin={isAdmin}
        saving={savingAddr != null && savingAddr === (entityMachine.address || "").toLowerCase()}
        onAttachWebhook={attachWebhook}
        cache={cache}
        onCache={onCache}
        now={now}
        minSalience={minSalience}
        onHiddenCount={setHiddenCount}
        nameFor={nameFor}
        onPreview={onPreview}
        onNavigate={onNavigate}
      />
    </>
  );
}
