import { useSyncExternalStore } from "react";

import { useAuthConfig, useAuthConfigFailed } from "./authConfig.js";
import { getAdminKey } from "./client.js";
import { useSession } from "./session.js";

// 'psat:adminkey' covers same-tab changes; 'storage' covers other tabs.
function subscribe(callback) {
  window.addEventListener("psat:adminkey", callback);
  window.addEventListener("storage", callback);
  return () => {
    window.removeEventListener("psat:adminkey", callback);
    window.removeEventListener("storage", callback);
  };
}

const getSnapshot = () => Boolean(getAdminKey());
const getServerSnapshot = () => false;

// A stored key counts only once the server confirms it accepts keys.
export function useHasAdminKey() {
  const stored = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  const config = useAuthConfig(stored);
  return stored && config?.adminKey === true;
}

// An admin account, or an operator holding the shared key (?admin=1).
export function useIsAdmin() {
  const hasKey = useHasAdminKey();
  const { user } = useSession();
  return hasKey || Boolean(user?.is_admin);
}

// Whether useIsAdmin's answer is settled: the session read, and with a stored
// key the auth config read, have both finished. A failed config read settles
// as "key not accepted".
export function useAdminResolved() {
  const stored = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  const config = useAuthConfig(stored);
  const configFailed = useAuthConfigFailed();
  const { status } = useSession();
  return status !== "unknown" && (!stored || config !== null || configFailed);
}
