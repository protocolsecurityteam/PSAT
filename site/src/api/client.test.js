import { describe, it, expect } from "vitest";
import { api } from "./client.js";
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
