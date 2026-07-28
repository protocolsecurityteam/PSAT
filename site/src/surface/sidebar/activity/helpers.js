// Pure config helpers for the Activity tab: monitoring_config ↔ alert-group
// keys ↔ event types, plus the monitoring contract-type of a machine.

import { MONITOR_ALERT_GROUPS } from "../../meta.js";

export function groupKeysFromConfig(config = {}) {
  return MONITOR_ALERT_GROUPS
    .filter((group) => group.flags.some((flag) => config?.[flag]))
    .map((group) => group.key);
}

export function eventTypesFromGroupKeys(groupKeys) {
  const selected = new Set(groupKeys);
  const out = [];
  for (const group of MONITOR_ALERT_GROUPS) {
    if (!selected.has(group.key)) continue;
    for (const eventType of group.eventTypes) {
      if (!out.includes(eventType)) out.push(eventType);
    }
  }
  return out;
}

export function subscriptionEventTypeSet(subscription) {
  const raw = subscription?.event_filter?.event_types;
  if (!Array.isArray(raw) || raw.length === 0) return null;
  return new Set(raw.map((eventType) => String(eventType).toLowerCase()));
}

// The monitoring contract-type of a machine, for the entity badge — used only
// when the MonitoredContract row has no `contract_type` of its own.
//
// Four values, because "regular" is a positive claim (a plain contract: not a
// proxy, cannot be paused, issues no commands) and `is_pausable` is three-state
// on the payload. A null flag — no ContractSummary row, or the pause detector
// declining to answer — used to land on "regular" alongside a proven `false`,
// so a contract nobody had classified was badged as classified-and-plain.
// `unclassified` is that third state; it is never returned when any positive
// signal is present.
export function contractTypeForMachine(machine) {
  if (machine?.is_proxy) return "proxy";
  if (machine?.is_pausable === true || machine?.capabilities?.includes("pause")) return "pausable";
  if (machine?.role === "governance") return "governance";
  // A pause verdict of `false` is an answer and earns "regular"; `null` (and an
  // absent key, which is what a pre-fix payload carries) does not.
  if (machine?.is_pausable == null) return "unclassified";
  return "regular";
}
