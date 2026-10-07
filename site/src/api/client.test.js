import { describe, it, expect, vi } from "vitest";
import { api, companyApi, SUPPORTED_PAYLOAD_SCHEMA } from "./client.js";
import { setFetchHandler } from "../test/fetchMock.js";

describe("API error messages", () => {
  it.each([502, 503, 504])("hides HTML gateway responses for %i and preserves the status", async (status) => {
    setFetchHandler("/api/failure", () => new Response("<!DOCTYPE html><html>Cloudflare Ray ID: private</html>", {
      status, headers: { "Content-Type": "text/html" },
    }));
    await expect(api("/api/failure")).rejects.toMatchObject({
      status, message: "The server is temporarily unavailable. Please try again.",
    });
  });

  it("preserves useful JSON errors including controlled overload", async () => {
    setFetchHandler("/api/failure", () => new Response(JSON.stringify({ detail: "Company data is busy." }), {
      status: 503, headers: { "Content-Type": "application/json" },
    }));
    await expect(api("/api/failure")).rejects.toMatchObject({ status: 503, message: "Company data is busy." });
  });

  it("handles malformed JSON without replacing the HTTP status with a parse error", async () => {
    setFetchHandler("/api/failure", () => new Response("<html>bad gateway</html>", {
      status: 502, headers: { "Content-Type": "application/json" },
    }));
    await expect(api("/api/failure")).rejects.toMatchObject({ status: 502 });
  });
});

// Unlike transient gateway failures, this response means a shared background
// preparation is pending. Readers retry; they never request a second build.
describe("company preparation", () => {
  it("retries preparing and then returns the published response", async () => {
    vi.useFakeTimers();
    let calls = 0;
    setFetchHandler("/api/company/example", () => {
      calls += 1;
      return calls === 1
        ? new Response(JSON.stringify({ code: "company_preparing", detail: "Preparing" }), {
          status: 503, headers: { "Content-Type": "application/json" },
        })
        : { company: "example" };
    });
    try {
      const pending = companyApi("/api/company/example");
      await vi.advanceTimersByTimeAsync(2000);
      await expect(pending).resolves.toMatchObject({ data: { company: "example" } });
      expect(calls).toBe(2);
    } finally { vi.useRealTimers(); }
  });

  it("cancels a pending retry on navigation", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    let calls = 0;
    setFetchHandler("/api/company/example", () => {
      calls += 1;
      return new Response(JSON.stringify({ code: "company_preparing" }), {
        status: 503, headers: { "Content-Type": "application/json" },
      });
    });
    try {
      const pending = companyApi("/api/company/example", { signal: controller.signal });
      const assertion = expect(pending).rejects.toMatchObject({ name: "AbortError" });
      await vi.advanceTimersByTimeAsync(1);
      controller.abort();
      await assertion;
      await vi.advanceTimersByTimeAsync(10000);
      expect(calls).toBe(1);
    } finally { vi.useRealTimers(); }
  });

  it("bounds preparation retries and does not retry ordinary failures", async () => {
    vi.useFakeTimers();
    let calls = 0;
    setFetchHandler("/api/company/example", () => {
      calls += 1;
      return new Response(JSON.stringify({ code: "company_preparing" }), {
        status: 503, headers: { "Content-Type": "application/json" },
      });
    });
    try {
      const assertion = expect(companyApi("/api/company/example")).rejects.toMatchObject({ status: 503 });
      await vi.advanceTimersByTimeAsync(31000);
      await assertion;
      expect(calls).toBe(16);
      calls = 0;
      setFetchHandler("/api/company/example", () => {
        calls += 1;
        return new Response("Bad gateway", { status: 502 });
      });
      await expect(companyApi("/api/company/example")).rejects.toMatchObject({ status: 502 });
      expect(calls).toBe(1);
    } finally { vi.useRealTimers(); }
  });
});

function prepared(body, headers) {
  return new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json", ...headers } });
}

describe("company provenance", () => {
  it("returns the body with its provenance headers", async () => {
    setFetchHandler("/api/company/example/summary", () => prepared({ tvl: null }, {
      "X-PSAT-Response-Source": "prepared-stale",
      "X-PSAT-Prepared-At": "2026-09-29T10:00:00+00:00",
      "X-PSAT-Stale-Reason": "data",
      "X-PSAT-Payload-Schema": String(SUPPORTED_PAYLOAD_SCHEMA.summary),
    }));
    await expect(companyApi("/api/company/example/summary")).resolves.toEqual({
      data: { tvl: null },
      meta: {
        source: "prepared-stale",
        preparedAt: "2026-09-29T10:00:00+00:00",
        staleReason: "data",
        schema: SUPPORTED_PAYLOAD_SCHEMA.summary,
      },
    });
  });

  it.each([String(SUPPORTED_PAYLOAD_SCHEMA.functions + 1), null])(
    "treats a prepared payload in schema %s as still preparing",
    async (schema) => {
      vi.useFakeTimers();
      let calls = 0;
      setFetchHandler("/api/company/example/functions", () => {
        calls += 1;
        const current = String(SUPPORTED_PAYLOAD_SCHEMA.functions);
        return prepared({ functions: { calls } }, {
          "X-PSAT-Response-Source": "prepared",
          ...(calls === 1 ? (schema === null ? {} : { "X-PSAT-Payload-Schema": schema }) : { "X-PSAT-Payload-Schema": current }),
        });
      });
      try {
        const pending = companyApi("/api/company/example/functions");
        await vi.advanceTimersByTimeAsync(2000);
        await expect(pending).resolves.toMatchObject({ data: { functions: { calls: 2 } } });
        expect(calls).toBe(2);
      } finally { vi.useRealTimers(); }
    },
  );
});

describe("shared admin key", () => {
  function recordKeyHeaders() {
    const sent = [];
    setFetchHandler("/api/jobs", (url, init) => {
      sent.push(new Headers(init?.headers).get("X-PSAT-Admin-Key"));
      return [];
    });
    return sent;
  }

  it("is sent where the deployment accepts one", async () => {
    window.localStorage.setItem("psat_admin_key", "preview-key");
    const sent = recordKeyHeaders();
    await api("/api/jobs");
    expect(sent).toEqual(["preview-key"]);
  });

  it("is never sent to production, and a stale stored key is forgotten", async () => {
    window.localStorage.setItem("psat_admin_key", "stale-key");
    setFetchHandler("/api/auth/config", () => ({ enabled: true, providers: [], dev_login: false, admin_key: false }));
    const sent = recordKeyHeaders();
    await api("/api/jobs");
    expect(sent).toEqual([null]);
    expect(window.localStorage.getItem("psat_admin_key")).toBeNull();
  });

  it("is held back but kept when the config can't be read", async () => {
    window.localStorage.setItem("psat_admin_key", "preview-key");
    setFetchHandler("/api/auth/config", () => new Response("", { status: 503 }));
    const sent = recordKeyHeaders();
    await api("/api/jobs");
    expect(sent).toEqual([null]);
    expect(window.localStorage.getItem("psat_admin_key")).toBe("preview-key");
  });
});
