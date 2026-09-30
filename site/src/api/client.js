// Shared HTTP helper: admin-key header, 401 prompt, JSON/text parsing by
// Content-Type.

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
    // The native 'storage' event only fires in other tabs.
    window.dispatchEvent(new Event("psat:adminkey"));
  } catch {
    // localStorage unavailable (private mode): admins re-enter the key per
    // request.
  }
}

function buildHeadersWithKey(options, key) {
  const headers = new Headers(options.headers || {});
  if (key && !headers.has("X-PSAT-Admin-Key")) {
    headers.set("X-PSAT-Admin-Key", key);
  }
  return headers;
}

async function request(path, options = {}) {
  // `silent: true` skips the 401 prompt, for background polls.
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
    // Callers must tell 404 (absent) from 503 (couldn't find out); a message
    // string collapsed them and drew a storage outage as an empty timeline.
    const type = response.headers.get("content-type") || "";
    let message = response.status >= 500
      ? "The server is temporarily unavailable. Please try again."
      : `Request failed (${response.status}). Please try again.`;
    let code;
    if (type.includes("application/json")) {
      try {
        const body = await response.json();
        code = body.code;
        if (typeof body.detail === "string" && body.detail.length <= 300 && !/<[^>]+>/.test(body.detail)) {
          message = body.detail;
        }
      } catch { /* malformed gateway responses use the safe fallback */ }
    } else if (type.includes("text/plain") && response.status < 500) {
      const body = await response.text();
      if (body.length <= 300 && !/<[^>]+>/.test(body)) message = body;
    }
    const err = new Error(message);
    err.status = response.status;
    err.code = code;
    throw err;
  }
  const type = response.headers.get("content-type") || "";
  const data = type.includes("application/json") ? await response.json() : await response.text();
  return { data, headers: response.headers };
}

export async function api(path, options = {}) {
  return (await request(path, options)).data;
}

// Matches PAYLOAD_SCHEMA in services/company_pages.py.
export const SUPPORTED_PAYLOAD_SCHEMA = { overview: 1, functions: 1, summary: 1 };

function companyMeta(headers) {
  const schema = headers.get("X-PSAT-Payload-Schema");
  return {
    source: headers.get("X-PSAT-Response-Source"),
    preparedAt: headers.get("X-PSAT-Prepared-At"),
    staleReason: headers.get("X-PSAT-Stale-Reason"),
    schema: schema === null ? null : Number(schema),
  };
}


// Retries only the server's explicit preparing state, bounded and cancellable.
// A schema this build can't read counts as still preparing.
export async function companyApi(path, options = {}) {
  const section = path.match(/\/(functions|summary)$/)?.[1] || "overview";
  for (let attempt = 0; ; attempt += 1) {
    try {
      const { data, headers } = await request(path, options);
      const meta = companyMeta(headers);
      if (meta.source?.startsWith("prepared") && meta.schema !== SUPPORTED_PAYLOAD_SCHEMA[section]) {
        const err = new Error("Company data is being prepared. Please retry shortly.");
        err.status = 503;
        err.code = "company_preparing";
        throw err;
      }
      return { data, meta };
    } catch (err) {
      if (err.status !== 503 || err.code !== "company_preparing" || attempt >= 15) throw err;
      await new Promise((resolve, reject) => {
        const signal = options.signal;
        const abort = () => {
          clearTimeout(timer);
          signal?.removeEventListener("abort", abort);
          reject(new DOMException("Request aborted", "AbortError"));
        };
        const timer = setTimeout(() => {
          signal?.removeEventListener("abort", abort);
          resolve();
        }, 2000);
        if (signal?.aborted) abort();
        else signal?.addEventListener("abort", abort, { once: true });
      });
    }
  }
}
