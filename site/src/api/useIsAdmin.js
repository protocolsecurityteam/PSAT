import { useSyncExternalStore } from "react";

import { useAuthConfig } from "./authConfig.js";
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

// A stored key counts until the server says keys aren't accepted (production),
// so operator UI doesn't flicker while the config loads. Requests never send
// it before then (client.js).
export function useHasAdminKey() {
  const stored = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  const config = useAuthConfig(stored);
  return stored && config?.adminKey !== false;
}

// An admin account, or an operator holding the shared key (?admin=1).
export function useIsAdmin() {
  const hasKey = useHasAdminKey();
  const { user } = useSession();
  return hasKey || Boolean(user?.is_admin);
}
