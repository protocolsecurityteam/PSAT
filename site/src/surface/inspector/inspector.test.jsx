// Render tests for the inspector panels in
// site/src/surface/inspector/. These ship as named exports already, so
// pinning them here ensures the upcoming ProtocolSurface split doesn't
// drift their public API.

import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

import { AgentPanel } from "./AgentPanel.jsx";
import MarkdownBubble from "./MarkdownBubble.jsx";

// Note: the former UpgradesPanel is retired (its Upgrades tab collapsed into the
// Activity tab). Its behavior is covered by activity/buildTimeline.test.js and
// activity/ActivityPanel.test.jsx.

describe("AgentPanel", () => {
  it("renders without selecting a machine", () => {
    render(
      <AgentPanel
        companyName="etherfi"
        selectedMachine={null}
        onHighlight={() => {}}
        onFocusAddress={() => {}}
      />,
    );
    // Suggestion list is rendered on first mount before any messages.
    expect(screen.getByText(/Who controls upgrades\?/i)).toBeInTheDocument();
  });
});

describe("MarkdownBubble", () => {
  it("renders markdown text", async () => {
    render(<MarkdownBubble text="**bold** and _italic_" components={{}} />);
    await waitFor(() => {
      expect(screen.getByText("bold")).toBeInTheDocument();
      expect(screen.getByText("italic")).toBeInTheDocument();
    });
  });
});
