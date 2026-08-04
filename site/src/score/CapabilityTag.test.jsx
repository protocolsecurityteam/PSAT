import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import CapabilityTag from "./CapabilityTag.jsx";
import { CAPABILITY_GLOSSARY } from "./capabilityGlossary.js";
import { CAPABILITY_PHRASE_IDS } from "../claimsVocab.js";

describe("capability glossary", () => {
  it("covers exactly the fixed capability vocabulary — no gaps, no strays", () => {
    // Both maps mirror the scorer's BASE_SEVERITY key set; if one learns a
    // new capability the other must too, or a row ships without its reading.
    expect(Object.keys(CAPABILITY_GLOSSARY).sort()).toEqual([...CAPABILITY_PHRASE_IDS].sort());
  });

  it("keeps every definition to sentence length, not an essay", () => {
    for (const definition of Object.values(CAPABILITY_GLOSSARY)) {
      expect(definition.length).toBeGreaterThan(40);
      expect(definition.length).toBeLessThan(260);
    }
  });
});

describe("CapabilityTag", () => {
  it("opens the definition on ? and closes on Escape", async () => {
    const user = userEvent.setup();
    render(<CapabilityTag capability="authority.replace" />);
    expect(screen.queryByRole("note")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /what authority\.replace means/i }));
    const note = screen.getByRole("note");
    expect(note.textContent).toContain("permission checks defer to");
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("note")).not.toBeInTheDocument();
  });

  it("closes on an outside click", async () => {
    const user = userEvent.setup();
    render(
      <div>
        <CapabilityTag capability="pause.set" />
        <span>outside</span>
      </div>,
    );
    await user.click(screen.getByRole("button"));
    expect(screen.getByRole("note")).toBeInTheDocument();
    await user.click(screen.getByText("outside"));
    expect(screen.queryByRole("note")).not.toBeInTheDocument();
  });

  it("renders an unmapped id bare — no ?, no invented definition", () => {
    render(<CapabilityTag capability="some.future_capability" />);
    expect(screen.getByText("some.future_capability")).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
