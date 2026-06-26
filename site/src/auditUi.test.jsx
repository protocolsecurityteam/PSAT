// Tests for the shared audit badge vocabulary in auditUi.jsx. The
// constants are referenced across the surface UI; if the shape changes
// during a refactor every site of use breaks at once.

import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import {
  AUDIT_STATUS_META,
  EQUIVALENCE_META,
  formatAuditDate,
  formatAuditTimestamp,
  MATCH_TYPE_META,
  MetaBadge,
  proofKindTitle,
  PROOF_KIND_META,
  SEVERITY_META,
} from "./auditUi.jsx";

describe("auditUi constants", () => {
  it("AUDIT_STATUS_META covers all server statuses", () => {
    expect(Object.keys(AUDIT_STATUS_META)).toEqual(
      expect.arrayContaining([
        "audited",
        "non_proxy_audited",
        "unaudited_since_upgrade",
        "non_proxy_unaudited",
        "never_audited",
      ]),
    );
  });

  it("MATCH_TYPE_META has entries for the four match types", () => {
    expect(Object.keys(MATCH_TYPE_META)).toEqual(
      expect.arrayContaining(["reviewed_commit", "reviewed_address", "direct", "impl_era"]),
    );
  });

  it("EQUIVALENCE_META and PROOF_KIND_META and SEVERITY_META have label+color shape", () => {
    for (const meta of [EQUIVALENCE_META, PROOF_KIND_META]) {
      for (const value of Object.values(meta)) {
        expect(value).toHaveProperty("label");
        expect(value).toHaveProperty("color");
      }
    }
    for (const value of Object.values(SEVERITY_META)) {
      expect(value).toHaveProperty("color");
    }
  });
});

describe("formatAuditDate", () => {
  it("returns em-dash for falsy input", () => {
    expect(formatAuditDate(null)).toBe("—");
    expect(formatAuditDate(undefined)).toBe("—");
    expect(formatAuditDate("")).toBe("—");
  });

  it("formats an ISO date in UTC", () => {
    expect(formatAuditDate("2024-03-15")).toMatch(/Mar 15, 2024/);
  });

  it("returns the raw string when unparseable", () => {
    expect(formatAuditDate("not-a-date")).toBe("not-a-date");
  });
});

describe("formatAuditTimestamp", () => {
  it("returns null for falsy input", () => {
    expect(formatAuditTimestamp(null)).toBeNull();
    expect(formatAuditTimestamp(0)).toBeNull();
  });

  it("formats a date string", () => {
    expect(formatAuditTimestamp("2024-03-15T00:00:00Z")).toMatch(/Mar 15, 2024/);
  });
});

describe("proofKindTitle", () => {
  it("returns a tooltip for known kinds", () => {
    expect(proofKindTitle("pre_fix_unpatched")).toMatch(/fix was never shipped/);
    expect(proofKindTitle("post_fix")).toMatch(/findings were addressed/);
    expect(proofKindTitle("cited_only")).toMatch(/cited for context/);
  });

  it("returns undefined for unknown kinds", () => {
    expect(proofKindTitle("unknown")).toBeUndefined();
  });
});

describe("MetaBadge", () => {
  it("renders a span with meta.label by default", () => {
    render(<MetaBadge meta={AUDIT_STATUS_META.audited} />);
    expect(screen.getByText("Audited")).toBeInTheDocument();
  });

  it("renders an explicit override label when provided", () => {
    render(<MetaBadge meta={AUDIT_STATUS_META.audited} label="Custom" />);
    expect(screen.getByText("Custom")).toBeInTheDocument();
  });
});
