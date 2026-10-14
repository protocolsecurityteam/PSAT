import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import Avatar from "./Avatar.jsx";

describe("Avatar", () => {
  it("shows the initial when there is no picture", () => {
    render(<Avatar className="account-avatar" url={null} name="gnome" />);
    expect(screen.getByText("G")).toHaveClass("account-avatar-initial");
  });

  it("falls back to the initial when the picture fails to load", () => {
    const { container } = render(<Avatar className="account-avatar" url="https://avatars.githubusercontent.com/u/1" name="gnome" />);
    fireEvent.error(container.querySelector("img"));
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText("G")).toBeInTheDocument();
  });
});
