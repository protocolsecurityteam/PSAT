import { useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";

import { api } from "../../../api/client.js";
import { shortAddr } from "../../format.js";
import { AlertsTable } from "./AlertsTable.jsx";
import { FocusedContractAlerts } from "./FocusedContractAlerts.jsx";
import {
  configFromGroupKeys,
  contractTypeForMachine,
  eventTypesFromGroupKeys,
  groupKeysFromConfig,
  matchingWebhookCountForConfig,
  needsPollingFromGroupKeys,
} from "./helpers.js";
import { MinimizedAlertEditors } from "./MinimizedAlertEditors.jsx";
import { MonitorAlertEditor } from "./MonitorAlertEditor.jsx";
import { MonitorAlertFilters } from "./MonitorAlertFilters.jsx";

function identityKey(address, chainId) {
  const addr = String(address || "").toLowerCase();
  const parsedChainId = Number.parseInt(chainId, 10);
  if (!addr || !Number.isInteger(parsedChainId) || parsedChainId <= 0) return null;
  return `${parsedChainId}:${addr}`;
}

export function SurfaceMonitoringPanel({ companyData, machines, selectedMachine }) {
  const protocolId = companyData?.protocol_id;
  const [contracts, setContracts] = useState([]);
  const [subscriptions, setSubscriptions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [busyId, setBusyId] = useState(null);
  const [savingAlert, setSavingAlert] = useState(false);
  const [editorSessions, setEditorSessions] = useState([]);
  const [activeEditorKey, setActiveEditorKey] = useState(null);
  const [monitorQuery, setMonitorQuery] = useState("");
  const [monitorAlertFilters, setMonitorAlertFilters] = useState([]);
  const [monitorStatusFilter, setMonitorStatusFilter] = useState("active");
  const [monitorWebhookFilter, setMonitorWebhookFilter] = useState("any");

  const machineByIdentity = useMemo(() => {
    const map = new Map();
    for (const machine of machines || []) {
      const key = identityKey(machine.address, machine.chain_id);
      if (key) map.set(key, machine);
      const implementation = machine.implementation?.toLowerCase();
      const implementationKey = identityKey(implementation, machine.chain_id);
      if (implementationKey && !map.has(implementationKey)) {
        map.set(implementationKey, {
          ...machine,
          name: `${machine.name || shortAddr(machine.address)} impl`,
          address: machine.implementation,
        });
      }
    }
    return map;
  }, [machines]);

  const contractByIdentity = useMemo(() => {
    const map = new Map();
    for (const contract of contracts) {
      const key = identityKey(contract.address, contract.chain_id);
      if (key) map.set(key, contract);
    }
    return map;
  }, [contracts]);

  const refresh = useCallback(async ({ quiet = false } = {}) => {
    if (!protocolId) return;
    if (!quiet) setLoading(true);
    setError(null);
    try {
      const [monitoring, subs] = await Promise.all([
        api(`/api/protocols/${protocolId}/monitoring`),
        api(`/api/protocols/${protocolId}/subscriptions`),
      ]);
      setContracts(Array.isArray(monitoring) ? monitoring : []);
      setSubscriptions(Array.isArray(subs) ? subs : []);
    } catch (err) {
      setError(err?.message || String(err));
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [protocolId]);

  useEffect(() => {
    refresh();
    const timer = setInterval(() => refresh({ quiet: true }), 15000);
    return () => clearInterval(timer);
  }, [refresh]);

  if (!protocolId) {
    return (
      <section className="ps-principal-section">
        <div className="ps-inspector-empty">No protocol monitoring id is available.</div>
      </section>
    );
  }

  const monitoredAlerts = [...contracts]
    .sort((a, b) => {
      const aMachine = machineByIdentity.get(identityKey(a.address, a.chain_id));
      const bMachine = machineByIdentity.get(identityKey(b.address, b.chain_id));
      return String(aMachine?.name || a.address).localeCompare(String(bMachine?.name || b.address));
    });
  const activeAlerts = monitoredAlerts.filter((contract) => contract.is_active);
  const inactiveAlerts = monitoredAlerts.filter((contract) => !contract.is_active);
  const filteredMonitorAlerts = monitoredAlerts.filter((contract) => {
    const machine = machineByIdentity.get(identityKey(contract.address, contract.chain_id));
    const query = monitorQuery.trim().toLowerCase();
    const haystack = [
      machine?.name,
      contract.address,
      contract.chain_id,
      contract.contract_type,
    ].filter(Boolean).join(" ").toLowerCase();
    const statusMatches = (
      monitorStatusFilter === "all" ||
      (monitorStatusFilter === "active" && contract.is_active) ||
      (monitorStatusFilter === "inactive" && !contract.is_active)
    );
    const groups = groupKeysFromConfig(contract.monitoring_config);
    const webhookCount = matchingWebhookCountForConfig(contract.monitoring_config || {}, subscriptions);
    const alertsMatch = (
      monitorAlertFilters.length === 0 ||
      monitorAlertFilters.every((key) => groups.includes(key))
    );
    const webhookMatches = (
      monitorWebhookFilter === "any" ||
      (monitorWebhookFilter === "with" && webhookCount > 0) ||
      (monitorWebhookFilter === "without" && webhookCount === 0)
    );
    return statusMatches && alertsMatch && webhookMatches && (!query || haystack.includes(query));
  });
  const selectedMachineKey = identityKey(selectedMachine?.address, selectedMachine?.chain_id);
  const focusedAlert = selectedMachineKey
    ? activeAlerts.find((contract) => identityKey(contract.address, contract.chain_id) === selectedMachineKey) || null
    : null;
  const activeEditor = (
    editorSessions.find((session) => session.key === activeEditorKey && !session.minimized) ||
    editorSessions.find((session) => !session.minimized) ||
    null
  );
  const minimizedEditors = editorSessions.filter((session) => session.minimized);

  function openAlertEditor(machine = null, existingContract = null) {
    const existingKey = identityKey(existingContract?.address, existingContract?.chain_id);
    const target = machine || (existingKey ? machineByIdentity.get(existingKey) : null) || null;
    const targetKey = identityKey(target?.address, target?.chain_id);
    const matchedContract = targetKey ? contractByIdentity.get(targetKey) : null;
    const address = target?.address || existingContract?.address;
    const key = targetKey || existingKey || identityKey(address, existingContract?.chain_id);
    if (!key) {
      setError("Missing chain id for alert target.");
      return;
    }
    const nextSession = {
      key,
      machine: target,
      contract: existingContract || (matchedContract?.is_active ? matchedContract : null),
      minimized: false,
    };
    setEditorSessions((prev) => [
      ...prev
        .filter((session) => session.key !== key)
        .map((session) => ({ ...session, minimized: true })),
      nextSession,
    ]);
    setActiveEditorKey(key);
  }

  function minimizeAlertEditor(key) {
    setEditorSessions((prev) => prev.map((session) => (
      session.key === key ? { ...session, minimized: true } : session
    )));
    setActiveEditorKey((current) => (current === key ? null : current));
  }

  function restoreAlertEditor(key) {
    setEditorSessions((prev) => prev.map((session) => (
      { ...session, minimized: session.key !== key }
    )));
    setActiveEditorKey(key);
  }

  function closeAlertEditor(key) {
    setEditorSessions((prev) => prev.filter((session) => session.key !== key));
    setActiveEditorKey((current) => (current === key ? null : current));
  }

  function toggleMonitorAlertFilter(key) {
    setMonitorAlertFilters((prev) => (
      prev.includes(key)
        ? prev.filter((value) => value !== key)
        : [...prev, key]
    ));
  }

  function cycleMonitorWebhookFilter() {
    setMonitorWebhookFilter((prev) => {
      if (prev === "any") return "with";
      if (prev === "with") return "without";
      return "any";
    });
  }

  async function patchContract(contract, patch) {
    setBusyId(contract.id);
    setError(null);
    try {
      await api(`/api/monitored-contracts/${contract.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch),
      });
      await refresh({ quiet: true });
    } catch (err) {
      setError(err?.message || String(err));
    } finally {
      setBusyId(null);
    }
  }

  async function saveAlert(draft) {
    if (!draft.address) return;
    const draftChainId = Number.parseInt(draft.chain_id, 10);
    if (!Number.isInteger(draftChainId) || draftChainId <= 0) {
      setError("Missing chain id for alert target.");
      return;
    }
    const draftKey = identityKey(draft.address, draftChainId);
    const machine = draftKey ? machineByIdentity.get(draftKey) : null;
    const existingContract = draftKey ? contractByIdentity.get(draftKey) : null;
    const groupKeys = draft.groupKeys?.length ? draft.groupKeys : ["upgrades"];
    setSavingAlert(true);
    setError(null);
    try {
      await api(`/api/protocols/${protocolId}/monitoring`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          address: draft.address,
          chain_id: draftChainId,
          contract_type: existingContract?.contract_type || contractTypeForMachine(machine),
          monitoring_config: configFromGroupKeys(groupKeys),
          needs_polling: needsPollingFromGroupKeys(groupKeys),
          is_active: true,
        }),
      });

      if (draft.webhookMode === "new" && draft.webhookUrl?.trim()) {
        const eventTypes = eventTypesFromGroupKeys(groupKeys);
        await api(`/api/protocols/${protocolId}/subscribe`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            discord_webhook_url: draft.webhookUrl.trim(),
            label: draft.webhookLabel?.trim() || null,
            event_filter: eventTypes.length ? { event_types: eventTypes } : null,
          }),
        });
      }

      closeAlertEditor(draft.key || draftKey);
      await refresh({ quiet: true });
    } catch (err) {
      setError(err?.message || String(err));
    } finally {
      setSavingAlert(false);
    }
  }

  return (
    <section className="ps-monitor-panel">
      <div className="ps-monitor-header">
        <div>
          <div className="ps-monitor-title">{selectedMachine ? "Contract alerts" : "Monitor alerts"}</div>
          <div className="ps-monitor-subtitle">
            {selectedMachine
              ? `${selectedMachine.name || shortAddr(selectedMachine.address)} · ${focusedAlert ? "alert active" : "no alert"}`
              : `${filteredMonitorAlerts.length}/${monitoredAlerts.length} shown · ${activeAlerts.length} active · ${inactiveAlerts.length} inactive`}
          </div>
        </div>
      </div>

      {error && <div className="ps-monitor-error">{error}</div>}
      {loading && <div className="ps-inspector-empty">Loading alerts...</div>}

      {selectedMachine ? (
        <FocusedContractAlerts
          machine={selectedMachine}
          alert={focusedAlert}
          subscriptions={subscriptions}
          busyId={busyId}
          onAdd={() => openAlertEditor(selectedMachine)}
          onEdit={(contract) => openAlertEditor(selectedMachine, contract)}
          onTurnOff={(contract) => patchContract(contract, { is_active: false })}
        />
      ) : (
        <>
          <MonitorAlertFilters
            query={monitorQuery}
            status={monitorStatusFilter}
            webhookStatus={monitorWebhookFilter}
            selectedGroups={monitorAlertFilters}
            onQueryChange={setMonitorQuery}
            onStatusChange={setMonitorStatusFilter}
            onCycleWebhookStatus={cycleMonitorWebhookFilter}
            onToggleGroup={toggleMonitorAlertFilter}
            onClearGroups={() => setMonitorAlertFilters([])}
          />
          <AlertsTable
            alerts={filteredMonitorAlerts}
            machineByIdentity={machineByIdentity}
            subscriptions={subscriptions}
            busyId={busyId}
            emptyLabel="No monitored alerts match these filters."
            onEdit={(contract) => openAlertEditor(null, contract)}
            onSetActive={(contract, isActive) => patchContract(contract, { is_active: isActive })}
          />
        </>
      )}

      {editorSessions.length ? createPortal(
        <aside className={`ps-monitor-side-menu${activeEditor ? " ps-monitor-side-menu-edit" : " ps-monitor-side-menu-minimized"}`}>
          {activeEditor ? (
            <MonitorAlertEditor
              key={activeEditor.key}
              sessionKey={activeEditor.key}
              subscriptions={subscriptions}
              initialMachine={activeEditor.machine}
              initialContract={activeEditor.contract}
              saving={savingAlert}
              onMinimize={() => minimizeAlertEditor(activeEditor.key)}
              onClose={() => closeAlertEditor(activeEditor.key)}
              onSave={saveAlert}
            />
          ) : null}
          {minimizedEditors.length ? (
            <MinimizedAlertEditors
              sessions={minimizedEditors}
              onRestore={restoreAlertEditor}
              onClose={closeAlertEditor}
              inline={Boolean(activeEditor)}
            />
          ) : null}
        </aside>,
        document.body,
      ) : null}
    </section>
  );
}
