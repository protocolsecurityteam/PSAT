import { useEffect, useSyncExternalStore } from "react";

// /api/auth/config, read once and shared. `adminKey` says whether this
// deployment accepts the shared admin key at all (previews and local, never
// production). A failed read isn't cached, so the next caller retries.
let config = null;
let inflight = null;
const listeners = new Set();

export function loadAuthConfig() {
  if (config) return Promise.resolve(config);
  inflight ??= fetch("/api/auth/config", { headers: { Accept: "application/json" } })
    .then((response) => (response.ok ? response.json() : Promise.reject(new Error(`auth config ${response.status}`))))
    .then((data) => {
      config = {
        enabled: Boolean(data?.enabled),
        providers: Array.isArray(data?.providers) ? data.providers : [],
        devLogin: Boolean(data?.dev_login),
        adminKey: data?.admin_key === true,
      };
      for (const fn of listeners) fn();
      return config;
    })
    .finally(() => { inflight = null; });
  return inflight;
}

function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

// `null` until loaded; only fetches when `enabled`.
export function useAuthConfig(enabled = true) {
  const snapshot = useSyncExternalStore(subscribe, () => config, () => null);
  useEffect(() => {
    if (enabled && !config) loadAuthConfig().catch(() => null);
  }, [enabled]);
  return snapshot;
}

// Test-only: module state otherwise leaks between vitest cases.
export function resetAuthConfigForTests() {
  config = null;
  inflight = null;
}
