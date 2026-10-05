import { useSyncExternalStore } from "react";

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

// An admin account, or an operator holding the shared key (?admin=1).
export function useIsAdmin() {
  const hasKey = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  const { user } = useSession();
  return hasKey || Boolean(user?.is_admin);
}

export function useHasAdminKey() {
  return useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
}
