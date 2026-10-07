// Lightweight fetch router for vitest. Replaces window.fetch with a
// dispatcher that runs registered handlers in reverse-registration order
// (last-registered wins, mirroring how the e2e specs layer Playwright
// page.route calls).
//
// Default handlers return `{}` for any /api/* path, so tests that don't
// care about specific shapes still won't crash. Tests that need richer
// data call setFetchHandler() to override per-test.
//
// Reset between tests is wired into src/test/setup.js's beforeEach.

import { vi } from "vitest";

const handlers = [];

function jsonResponse(body, init = {}) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return new Response(text, {
    status: init.status ?? 200,
    headers: { "Content-Type": "application/json", ...(init.headers || {}) },
  });
}

function textResponse(body, init = {}) {
  return new Response(body, {
    status: init.status ?? 200,
    headers: { "Content-Type": "text/plain", ...(init.headers || {}) },
  });
}

function defaultDispatch(url) {
  // Like local dev and previews: sign-in off, shared admin key accepted.
  if (url.pathname === "/api/auth/config") {
    return jsonResponse({ enabled: false, providers: [], dev_login: false, admin_key: true });
  }
  // Catch-all: empty JSON. Most components handle empty payloads
  // gracefully (renders an "empty state" or shows zeros).
  if (url.pathname.startsWith("/api/")) return jsonResponse({});
  // Local logo SVGs: 404 so the CoinGecko fallback kicks in.
  if (/\/logos\/.+\.svg$/.test(url.pathname)) {
    return new Response("", { status: 404 });
  }
  return jsonResponse({});
}

async function dispatch(input, init = {}) {
  const rawUrl =
    typeof input === "string" || input instanceof URL
      ? String(input)
      : input?.url ?? "";
  let url;
  try {
    url = new URL(rawUrl, "http://localhost");
  } catch {
    return textResponse("");
  }
  for (let i = handlers.length - 1; i >= 0; i--) {
    const { match, respond } = handlers[i];
    if (match(url, init)) {
      // Await first so a responder that returns a never-resolving promise
      // actually keeps the request pending instead of getting wrapped in
      // a JSON envelope of the Promise object itself.
      return await respond(url, init);
    }
  }
  return defaultDispatch(url);
}

export function setFetchHandler(matcher, responder) {
  const match =
    typeof matcher === "function"
      ? matcher
      : matcher instanceof RegExp
      ? (url) => matcher.test(url.pathname) || matcher.test(url.toString())
      : (url) => url.pathname === matcher || url.pathname.startsWith(matcher);

  const respond = async (url, init) => {
    const result = await responder(url, init);
    if (result instanceof Response) return result;
    if (typeof result === "string") return textResponse(result);
    return jsonResponse(result ?? {});
  };

  handlers.push({ match, respond });
}

export function resetFetchMock() {
  handlers.length = 0;
  if (!globalThis.fetch || !globalThis.fetch.__psatMock) {
    const mocked = vi.fn(dispatch);
    mocked.__psatMock = true;
    globalThis.fetch = mocked;
    if (typeof window !== "undefined") window.fetch = mocked;
  }
}
