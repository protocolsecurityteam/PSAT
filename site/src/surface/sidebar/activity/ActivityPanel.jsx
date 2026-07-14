import { useCallback, useEffect, useMemo, useState } from "react";

import { api } from "../../../api/client.js";
import { principalLabel } from "../../format.js";
import { EntityActivity } from "./EntityActivity.jsx";
import { ProtocolActivity } from "./ProtocolActivity.jsx";
import { eventTypesFromGroupKeys } from "./helpers.js";

const POLL_MS = 30_000;

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
  isAdmin,
  cache,
  onCache,
}) {
  const protocolId = companyData?.protocol_id;
  const [contracts, setContracts] = useState([]);
  const [subscriptions, setSubscriptions] = useState([]);
  const [savingAddr, setSavingAddr] = useState(null);
  const [now, setNow] = useState(() => Date.now());

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

  const contractByAddress = useMemo(() => {
    const map = new Map();
    for (const c of contracts) {
      const a = c.address?.toLowerCase();
      if (a) map.set(a, c);
    }
    return map;
  }, [contracts]);

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
          event_filter: eventTypes.length ? { event_types: eventTypes } : null,
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
  // with no monitored row falls back to the pick-a-contract hint.
  const principalContract = selectedPrincipal
    ? contractByAddress.get((selectedPrincipal.address || "").toLowerCase()) || null
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
    ? contractByAddress.get((selectedMachine.address || "").toLowerCase()) || null
    : principalContract;

  if (!entityMachine && selectedPrincipal) {
    const who = principalLabel(selectedPrincipal.label, selectedPrincipal.type, selectedPrincipal.address);
    return (
      <section className="ps-principal-section">
        <div className="ps-inspector-empty">
          {who} selected — choose a contract to see its activity.
        </div>
      </section>
    );
  }

  if (!entityMachine) {
    return (
      <ProtocolActivity
        protocolId={protocolId}
        companyName={companyName}
        contracts={contracts}
        machines={machines}
        onSelect={onSelect}
        now={now}
      />
    );
  }

  return (
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
    />
  );
}
