import { useCallback, useEffect, useMemo, useState } from "react";

import { api } from "../../../api/client.js";
import { useSession } from "../../../api/session.js";
import { coalesceChain, entityKey } from "../../entityKey.js";
import { principalLabel } from "../../format.js";
import { EntityActivity } from "./EntityActivity.jsx";
import { ProtocolActivity } from "./ProtocolActivity.jsx";
import { eventTypesFromGroupKeys } from "./helpers.js";

const POLL_MS = 30_000;

// Minimum salience admitted. Default `alert` is an owner decision (2026-08-05):
// most non-alert traffic is routine. The always-shown hidden count and
// one-click All keep that from being silent suppression.
const SALIENCE_MODES = [
  { key: "routine", label: "All" },
  { key: "alert", label: "Alerts" },
];

const DEFAULT_MIN_SALIENCE = "alert";

// Shown even at zero: "0 hidden" says the filter is withholding nothing.
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

// Nothing selected → protocol feed; a contract → its timeline. A principal
// without a monitored row points at its contracts.
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
  const signedIn = useSession().status === "signed_in";
  const activeChain = coalesceChain(chain);
  const [contracts, setContracts] = useState([]);
  const [subscriptions, setSubscriptions] = useState([]);
  const [savingAddr, setSavingAddr] = useState(null);
  const [now, setNow] = useState(() => Date.now());
  // The count comes up from the mounted mode, which owns the rows.
  const [minSalience, setMinSalience] = useState(DEFAULT_MIN_SALIENCE);
  const [hiddenCount, setHiddenCount] = useState(0);

  // Display-only naming; never a witness.
  const nameFor = useMemo(() => {
    const byAddr = new Map();
    // Unfiltered: machines drop zero-function contracts, which are still call
    // targets.
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
      // Admins see every delivery target on the protocol; a signed-in user
      // sees their own; anyone else has none to see.
      const subsRequest = isAdmin
        ? api(`/api/protocols/${protocolId}/subscriptions`, { silent: true })
        : signedIn
          ? api("/api/me/subscriptions", { silent: true }).then((rows) =>
            (Array.isArray(rows) ? rows : []).filter((r) => r.protocol_id === protocolId))
          : Promise.resolve([]);
      const [monitoring, subs] = await Promise.all([
        api(`/api/protocols/${protocolId}/monitoring`),
        subsRequest,
      ]);
      setContracts(Array.isArray(monitoring) ? monitoring : []);
      setSubscriptions(Array.isArray(subs) ? subs : []);
    } catch {
      /* transient — keep last-good state */
    }
  }, [protocolId, isAdmin, signedIn]);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, POLL_MS);
    return () => clearInterval(t);
  }, [refresh]);

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), POLL_MS);
    return () => clearInterval(t);
  }, []);

  // Monitoring spans chains; key by (chain, address) so the active
  // chain's row resolves.
  const contractByAddress = useMemo(() => {
    const map = new Map();
    for (const c of contracts) {
      if (c.address) map.set(entityKey(c.chain, c.address), c);
    }
    return map;
  }, [contracts]);

  const chainScopedContracts = useMemo(
    () => contracts.filter((c) => coalesceChain(c.chain) === activeChain),
    [contracts, activeChain],
  );

  // The watch set is fixed at enrollment; only the delivery target is
  // configurable.
  // `target` is a saved account webhook ({webhookId}) or, for operators on the
  // shared admin key, a raw URL ({url, label}).
  const attachWebhook = useCallback(async (contract, target, groupKeys) => {
    if (!protocolId || !(target?.webhookId || target?.url)) return;
    const eventTypes = eventTypesFromGroupKeys(groupKeys);
    // `groups` tells the notifier the filter uses the post-split vocabulary
    // (notifier._FILTER_GROUPS_KEY). Always the whole group set today, but
    // written now because pre- and post-key saves are otherwise
    // indistinguishable forever.
    const eventFilter = eventTypes.length ? { event_types: eventTypes, groups: groupKeys } : null;
    setSavingAddr(contract?.address?.toLowerCase() || null);
    try {
      if (target.webhookId) {
        await api("/api/me/subscriptions", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ protocol_id: protocolId, webhook_id: target.webhookId, event_filter: eventFilter }),
        });
      } else {
        await api(`/api/protocols/${protocolId}/subscribe`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ discord_webhook_url: target.url, label: target.label, event_filter: eventFilter }),
        });
      }
    } catch {
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

  // Safes and timelocks are enrolled for monitoring, so a principal with a
  // monitored row shows its timeline.
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
