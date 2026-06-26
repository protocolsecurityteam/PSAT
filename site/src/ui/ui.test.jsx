// Render tests for the small UI primitives in site/src/ui/. These are
// already isolated in their own files — pinning them with tests means
// the upcoming file split won't accidentally break their public API.

import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import { StatCard } from "./StatCard.jsx";
import { GuardButton } from "./GuardButton.jsx";
import { GuardGlyph } from "./GuardGlyph.jsx";

describe("StatCard", () => {
  it("renders label + value", () => {
    render(<StatCard label="Risk" value="low" />);
    expect(screen.getByText("Risk")).toBeInTheDocument();
    expect(screen.getByText("low")).toBeInTheDocument();
  });
});

describe("GuardGlyph", () => {
  it.each(["unknown", "safe", "timelock", "eoa", "contract", "proxy_admin", "open", "many"])(
    "renders for kind=%s",
    (kind) => {
      const { container } = render(<GuardGlyph kind={kind} accent="#fff" title={kind} />);
      // Either an inline SVG (kinds eoa/contract/open/many/proxy_admin)
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

describe("GuardButton", () => {
  it("renders an unknown-kind icon-only button", () => {
    const fnView = {
      name: "withdraw",
      contractAddress: "0xabc",
      guard: { kind: "unknown", principals: [], accent: "#fff", label: "Unknown", sublabel: "" },
    };
    const { container } = render(
      <GuardButton fnView={fnView} onSelect={() => {}} onNavigate={() => {}} />,
    );
    expect(container.querySelector(".ps-guard-button.ps-guard-icon-only")).toBeInTheDocument();
  });

  it("renders a navigable button when principals exist + kind is known", () => {
    const fnView = {
      name: "pause",
      contractAddress: "0xabc",
      guard: {
        kind: "safe",
        principals: [{ address: "0x1", resolvedType: "safe" }],
        accent: "#fff",
        label: "Safe (3/5)",
        sublabel: "owners=5",
      },
    };
    const { container } = render(
      <GuardButton fnView={fnView} onSelect={() => {}} onNavigate={() => {}} />,
    );
    expect(container.querySelector(".ps-guard-navigable")).toBeInTheDocument();
    expect(screen.getByText(/Safe \(3\/5\)/)).toBeInTheDocument();
  });
});
