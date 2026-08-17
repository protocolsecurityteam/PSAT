// The audit link href is attacker-influenced (an audit row's url/pdf_url).
// These tests pin the scheme guard: a `javascript:` value must never reach
// the DOM as an executable href.

import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

import AuditsAdminModal, { safeHttpUrl } from "./AuditsAdminModal.jsx";
import { setFetchHandler } from "./test/fetchMock.js";

describe("safeHttpUrl", () => {
  it("returns the URL for http(s) schemes", () => {
    expect(safeHttpUrl("https://audits.example/r.pdf")).toBe("https://audits.example/r.pdf");
    expect(safeHttpUrl("http://foo.test")).toBe("http://foo.test");
  });

  it("returns null for dangerous schemes", () => {
    expect(safeHttpUrl("javascript:alert(1)")).toBeNull();
    expect(safeHttpUrl("data:text/html,<script>")).toBeNull();
    expect(safeHttpUrl("file:///etc/passwd")).toBeNull();
  });

  it("returns null for empty or non-string input", () => {
    expect(safeHttpUrl("")).toBeNull();
    expect(safeHttpUrl(null)).toBeNull();
    expect(safeHttpUrl(undefined)).toBeNull();
  });
});

describe("AuditsAdminModal audit link", () => {
  it("does not emit a javascript: url as an href", async () => {
    const evil = "javascript:alert(document.cookie)";
    setFetchHandler("/api/company/etherfi/audits", () => ({
      audits: [
        {
          id: 1,
          auditor: "ACME",
          title: "Report",
          url: evil,
          pdf_url: evil,
          date: "2024-01-01",
          text_extraction_status: "success",
          scope_extraction_status: "success",
          scope_contract_count: 0,
          reviewed_commits: [],
        },
      ],
    }));

    render(<AuditsAdminModal companyName="etherfi" onClose={() => {}} />);

    // The raw value is still shown (as inert text), so the row isn't dropped.
    await waitFor(() => expect(screen.getByText(evil)).toBeInTheDocument());

    // But no anchor carries it as an href.
    const dangerous = Array.from(document.querySelectorAll("a[href]")).filter((el) =>
      (el.getAttribute("href") || "").toLowerCase().startsWith("javascript:"),
    );
    expect(dangerous).toHaveLength(0);
  });
});
