import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import ExportMenu, { EXPORT_FORMATS } from "./ExportMenu.jsx";
import { setFetchHandler } from "../test/fetchMock.js";

describe("ExportMenu", () => {
  let clicked;

  beforeEach(() => {
    clicked = [];
    URL.createObjectURL = vi.fn(() => "blob:export");
    URL.revokeObjectURL = vi.fn();
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function click() {
      clicked.push({ href: this.href, download: this.download });
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("offers JSON, CSV, PDF and DOCX", () => {
    render(<ExportMenu companyName="Lido" />);
    fireEvent.click(screen.getByRole("button", { name: /export report/i }));
    const items = screen.getAllByRole("menuitem").map((el) => el.textContent);
    expect(EXPORT_FORMATS.map((f) => f.id).sort()).toEqual(["csv", "docx", "json", "pdf"]);
    expect(items).toHaveLength(4);
    for (const label of ["PDF", "Word (DOCX)", "CSV", "JSON"]) {
      expect(items.some((text) => text.startsWith(label))).toBe(true);
    }
  });

  it.each(EXPORT_FORMATS.map((f) => [f.id, f.label]))(
    "downloads the %s export with the server's filename",
    async (format, label) => {
      const requested = [];
      setFetchHandler(
        (url) => url.pathname === "/api/company/Lido%20Finance/export",
        (url) => {
          requested.push(url.searchParams.get("format"));
          return new Response(new Blob(["file"]), {
            status: 200,
            headers: {
              "Content-Type": "application/octet-stream",
              "Content-Disposition": `attachment; filename="psat-lido-finance-20261013T120000Z.${format}"`,
            },
          });
        },
      );
      render(<ExportMenu companyName="Lido Finance" />);
      fireEvent.click(screen.getByRole("button", { name: /export report/i }));
      fireEvent.click(screen.getByRole("menuitem", { name: new RegExp(`^${label.replace(/[()]/g, "\\$&")}`) }));
      await waitFor(() => expect(clicked).toHaveLength(1));
      expect(requested).toEqual([format]);
      expect(clicked[0].download).toBe(`psat-lido-finance-20261013T120000Z.${format}`);
      expect(screen.queryByRole("menu")).not.toBeInTheDocument();
    },
  );

  it("reports a failed export instead of saving anything", async () => {
    setFetchHandler(
      (url) => url.pathname.endsWith("/export"),
      () => new Response(JSON.stringify({ detail: "Company not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      }),
    );
    render(<ExportMenu companyName="Nope" />);
    fireEvent.click(screen.getByRole("button", { name: /export report/i }));
    fireEvent.click(screen.getByRole("menuitem", { name: /^PDF/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Export failed: Company not found");
    expect(clicked).toHaveLength(0);
  });

  it("closes on Escape", () => {
    render(<ExportMenu companyName="Lido" />);
    fireEvent.click(screen.getByRole("button", { name: /export report/i }));
    expect(screen.getByRole("menu")).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });
});
