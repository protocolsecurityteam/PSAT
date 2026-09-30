import { useSyncExternalStore } from "react";

import { getAdminKey } from "./client.js";

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

export function useIsAdmin() {
  return useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
}
