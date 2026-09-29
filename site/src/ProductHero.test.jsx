// Direct render test for ProductHero.

import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import ProductHero from "./ProductHero.jsx";

describe("ProductHero", () => {
  it("renders the hero title", () => {
    render(<ProductHero />);
    expect(screen.getByText(/Detect every/i)).toBeInTheDocument();
    expect(screen.queryByText(/Something went wrong/i)).not.toBeInTheDocument();
  });
});
