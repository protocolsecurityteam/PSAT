// The audit link href is attacker-influenced (an audit row's url/pdf_url).
// These tests pin the scheme guard: a `javascript:` value must never reach
// the DOM as an executable href.

import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

import AuditsAdminModal, { safeHttpUrl } from "./AuditsAdminModal.jsx";
import { setFetchHandler } from "../test/fetchMock.js";

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

  it("returns null for scheme-smuggling variants", () => {
    expect(safeHttpUrl("JavaScript:alert(1)")).toBeNull(); // case-insensitive scheme
    expect(safeHttpUrl("  javascript:alert(1)")).toBeNull(); // leading whitespace
    expect(safeHttpUrl("java\nscript:alert(1)")).toBeNull(); // embedded control char
  });

  it("returns null for empty or non-string input", () => {
    expect(safeHttpUrl("")).toBeNull();
    expect(safeHttpUrl(null)).toBeNull();
    expect(safeHttpUrl(undefined)).toBeNull();
  });
});

describe("AuditsAdminModal audit link", () => {
  it.each([
    ["plain", "javascript:alert(document.cookie)"],
    ["case-variant", "JavaScript:alert(1)"],
    ["leading-whitespace", "  javascript:alert(1)"],
    ["embedded-newline", "java\nscript:alert(1)"],
  ])("does not emit a %s script-scheme url as an href", async (_label, evil) => {
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

    // The row still renders (the value shows as inert text), so nothing is dropped.
    await waitFor(() => expect(screen.getByText("ACME")).toBeInTheDocument());

    // No anchor carries a script scheme, regardless of case/whitespace/control chars.
    const dangerous = Array.from(document.querySelectorAll("a[href]")).filter((el) => {
      const href = (el.getAttribute("href") || "").replace(/[\s]/g, "").toLowerCase();
      return href.startsWith("javascript:");
    });
    expect(dangerous).toHaveLength(0);
  });
});
