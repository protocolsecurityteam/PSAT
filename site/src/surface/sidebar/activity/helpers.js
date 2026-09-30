
import { MONITOR_ALERT_GROUPS } from "../../meta.js";

// A plan can offer a group whose flag nothing writes (see `state` in meta.js).
// `[]` is a witnessed empty plan, and `Boolean([])` is true, hence no
// truthiness check.
function hasPlanFor(config, group) {
  return (group.planKeys || []).some((key) => Array.isArray(config?.[key]) && config[key].length > 0);
}

export function groupKeysFromConfig(config = {}) {
  return MONITOR_ALERT_GROUPS
    .filter((group) => group.flags.some((flag) => config?.[flag]) || hasPlanFor(config, group))
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

// Three states: the proxy signals can contradict (`0x3c55986c…`: `is_proxy:
// false`, `proxy_type: "beacon"`, 14 real upgrades). `not_determined` means ask
// (fetch the history), not assume either answer.
export function proxyState(machine) {
  if (machine?.is_proxy) return "proxy";
  if (machine?.proxy_type || machine?.implementation) return "not_determined";
  return "not_proxy";
}

// Badge type when the MonitoredContract row has none. "regular" is a positive
// claim, so a null `is_pausable` yields `unclassified`, never returned when any
// positive signal is present.
export function contractTypeForMachine(machine) {
  if (machine?.is_proxy) return "proxy";
  if (machine?.is_pausable === true || machine?.capabilities?.includes("pause")) return "pausable";
  if (machine?.role === "governance") return "governance";
  // `false` is an answer; `null` or absent is not.
  if (machine?.is_pausable == null) return "unclassified";
  return "regular";
}
