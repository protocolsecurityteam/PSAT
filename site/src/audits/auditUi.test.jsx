// Tests for the audit-date formatters in auditUi.jsx. The badge vocabulary
// that used to live here was retired with the proof-first Audits panel.

import { describe, it, expect } from "vitest";

import { formatAuditDate, formatAuditTimestamp } from "./auditUi.jsx";

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
