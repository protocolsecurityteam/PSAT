import React from "react";
import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";

import StaleBanner, { preparedAsOf } from "./StaleBanner.jsx";

const NINE = "2026-09-29T09:00:00Z";
const TEN = "2026-09-29T10:00:00Z";
const meta = (source, preparedAt) => ({ source, preparedAt });
const text = (metas, props = {}) => render(<StaleBanner metas={metas} {...props} />).container.textContent;

describe("StaleBanner", () => {
  it("says updating, dated by the oldest section, when any section is stale", () => {
    expect(text([meta("prepared", NINE), meta("prepared-stale", TEN)])).toBe(
      `Updating — data as of ${new Date(NINE).toLocaleString()}`,
    );
  });

  it("names a quiet as-of for fresh prepared sections", () => {
    expect(text([meta("prepared", TEN), meta("prepared", NINE)])).toBe(`Data as of ${new Date(NINE).toLocaleString()}`);
  });

  it("shows nothing for live responses, which carry no as-of", () => {
    expect(text([meta("live", null), meta("live", null)])).toBe("");
    expect(text([])).toBe("");
  });

  it("keeps an unreadable prepared time as not determined", () => {
    expect(text([meta("prepared", null)])).toBe("Data as of not determined");
    expect(text([meta("prepared-stale", "garbage")])).toBe("Updating — data as of not determined");
  });

  it("leaves the fresh line to another mount when asked", () => {
    expect(text([meta("prepared", NINE)], { showFresh: false })).toBe("");
    expect(text([meta("prepared-stale", NINE)], { showFresh: false })).toMatch(/^Updating/);
  });
});

describe("preparedAsOf", () => {
  it("ignores an unknown source token", () => {
    expect(preparedAsOf([meta("cached", NINE)])).toBeNull();
  });
});
