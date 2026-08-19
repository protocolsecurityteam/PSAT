// Direct render test for ProtocolLogo (split out of the old components.test.jsx).

import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import ProtocolLogo from "./ProtocolLogo.jsx";

describe("ProtocolLogo", () => {
  it("renders with a name", () => {
    render(<ProtocolLogo name="etherfi" />);
    expect(screen.queryByText(/Something went wrong/i)).not.toBeInTheDocument();
  });
});
