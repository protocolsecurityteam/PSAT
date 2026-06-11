import React from "react";
import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";

import { GuardGlyph } from "./GuardGlyph.jsx";

describe("GuardGlyph", () => {
  it("renders a distinct svg glyph for a live one-shot, not the unknown fallback", () => {
    const { container } = render(<GuardGlyph kind="one_shot_live" accent="#ef4444" title="1-SHOT!" />);
    // the alert glyph is an inline <svg>; the unknown fallback is a masked <span>
    expect(container.querySelector("svg")).toBeTruthy();
    expect(container.querySelector("span.ps-guard-svg-mask")).toBeFalsy();
  });

  it("falls back to the masked glyph for an unrecognized kind", () => {
    const { container } = render(<GuardGlyph kind="totally-unknown" accent="#000" title="x" />);
    expect(container.querySelector("span.ps-guard-svg-mask")).toBeTruthy();
  });
});
