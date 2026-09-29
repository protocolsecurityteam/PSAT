import { describe, it, expect, vi } from "vitest";
import { api, companyApi } from "./client.js";
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
      await expect(pending).resolves.toEqual({ company: "example" });
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
