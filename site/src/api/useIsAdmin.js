import { useSyncExternalStore } from "react";

import { getAdminKey } from "./client.js";

// Reactive "an admin key is present" flag for gating operator UI.
// setAdminKey() dispatches 'psat:adminkey' for same-tab login/logout;
// 'storage' covers changes made in another tab. Subscribers re-render
// the instant the key appears or clears.
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
