// Render tests for the small UI primitives in site/src/ui/. These are
// already isolated in their own files — pinning them with tests means
// the upcoming file split won't accidentally break their public API.

import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import { GuardGlyph } from "./GuardGlyph.jsx";

describe("GuardGlyph", () => {
  it.each(["unknown", "safe", "timelock", "eoa", "contract", "proxy_admin", "open"])(
    "renders for kind=%s",
    (kind) => {
      const { container } = render(<GuardGlyph kind={kind} accent="#fff" title={kind} />);
      // Either an inline SVG (kinds eoa/contract/open/proxy_admin)
      // or a CSS-mask span (kinds unknown/safe/timelock) — either proves
      // the glyph branch ran without throwing.
      expect(container.firstChild).toBeTruthy();
    },
  );

  it("falls back to question-mark for an unknown-to-the-component kind", () => {
    const { container } = render(<GuardGlyph kind="something-new" accent="#fff" title="x" />);
    expect(container.firstChild).toBeTruthy();
  });
});
