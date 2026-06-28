// Shared HTTP helper: injects X-PSAT-Admin-Key, prompts for a key on 401,
// and parses JSON / text based on the response Content-Type. Kept in one
// place so every new page gets the same admin-key flow as App.jsx.

const ADMIN_KEY_STORAGE = "psat_admin_key";

export function getAdminKey() {
  try {
    return window.localStorage.getItem(ADMIN_KEY_STORAGE) || "";
  } catch {
    return "";
  }
}

export function setAdminKey(key) {
  try {
    if (key) window.localStorage.setItem(ADMIN_KEY_STORAGE, key);
    else window.localStorage.removeItem(ADMIN_KEY_STORAGE);
    // Notify same-tab listeners (useIsAdmin) so gated UI re-renders on
    // login/logout; the native 'storage' event only fires in other tabs.
    window.dispatchEvent(new Event("psat:adminkey"));
  } catch {
    // localStorage unavailable (private mode, etc.) — admin actions will
    // require re-entering the key on every request.
  }
}

function buildHeadersWithKey(options, key) {
  const headers = new Headers(options.headers || {});
  if (key && !headers.has("X-PSAT-Admin-Key")) {
    headers.set("X-PSAT-Admin-Key", key);
  }
  return headers;
}

export async function api(path, options = {}) {
  // `silent: true` skips the 401 prompt. Background polls (e.g. the open
  // detail panel refreshing every 2.5s) use this so a missing/wrong admin
  // key doesn't surface a modal prompt on every tick — the caller catches
  // the thrown error and degrades the UI instead.
  const { silent, ...fetchOptions } = options;
  let response = await fetch(path, { ...fetchOptions, headers: buildHeadersWithKey(fetchOptions, getAdminKey()) });
  if (response.status === 401 && !silent) {
    const entered = window.prompt(
      "Admin key required for this action.\nPaste your PSAT admin key:",
      getAdminKey(),
    );
    if (entered) {
      setAdminKey(entered);
      response = await fetch(path, { ...fetchOptions, headers: buildHeadersWithKey(fetchOptions, entered) });
    }
  }
  if (!response.ok) {
    throw new Error(await response.text());
  }
  const type = response.headers.get("content-type") || "";
  if (type.includes("application/json")) {
    return response.json();
  }
  return response.text();
}
