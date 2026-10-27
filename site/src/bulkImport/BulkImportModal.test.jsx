import React from "react";
import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import BulkImportModal from "./BulkImportModal.jsx";
import { setFetchHandler } from "../test/fetchMock.js";

const A = "0x" + "a".repeat(40);
const B = "0x" + "b".repeat(40);

function mockApi(posted) {
  setFetchHandler((url) => url.pathname === "/api/companies", () => ["etherfi", "lido"]);
  setFetchHandler((url) => url.pathname === "/api/config", () => ({
    default_rpc_url: "",
    enabled_chains: ["ethereum"],
    chain_spellings: { ethereum: "ethereum", mainnet: "ethereum", base: "base" },
  }));
  setFetchHandler(
    (url, init) => url.pathname === "/api/analyze/bulk" && init?.method === "POST",
    (url, init) => {
      const body = JSON.parse(init.body);
      posted.push(body);
      return {
        company: body.company,
        company_status: "existing",
        queued: 1,
        rejected: 1,
        duplicate: 0,
        results: [
          { row: 0, status: "queued", job_id: "7f3a1c09-0000", label: "skipped_too_long", reason: null },
          { row: 1, status: "rejected", job_id: null, label: null, reason: "chain went away" },
        ],
      };
    },
  );
}

async function companiesLoaded() {
  await waitFor(() => expect(document.querySelector("#bulk-import-companies option[value='lido']")).not.toBeNull());
}

function typeCompany(value) {
  fireEvent.change(screen.getByLabelText("Company"), { target: { value } });
}

async function upload(text) {
  const input = screen.getByTestId("bulk-import-file");
  fireEvent.change(input, { target: { files: [new File([text], "lido.csv", { type: "text/csv" })] } });
  await waitFor(() => expect(document.querySelector(".ps-addresses-modal-table")).not.toBeNull());
}

describe("BulkImportModal", () => {
  it("previews per-row checks, queues only sendable rows, then shows results rejected-first", async () => {
    const posted = [];
    mockApi(posted);
    render(<BulkImportModal onClose={() => {}} />);
    await companiesLoaded();
    expect(screen.getByText("Choose a CSV")).toBeInTheDocument();

    await upload(`address,chain,name\n${A},ethereum,Vault\n${B},base,Off\n0xzz,ethereum,Bad\n${A},mainnet,Dup\n${B},ethereum,`);
    expect(document.querySelector(".ps-bulk-import-lead")).toHaveTextContent("5 rows");
    expect(screen.getByText("chain not enabled")).toBeInTheDocument();
    expect(screen.getByText("invalid address")).toBeInTheDocument();
    expect(screen.getByText(/same as row 1/)).toBeInTheDocument();

    const queue = screen.getByRole("button", { name: "Queue 2 analyses" });
    expect(queue).toBeDisabled();
    typeCompany("lido");
    expect(queue).toBeEnabled();
    fireEvent.click(queue);

    await screen.findByRole("button", { name: "Import another" });
    expect(posted).toEqual([{
      company: "lido",
      rows: [
        { address: A, chain: "ethereum", name: "Vault" },
        { address: B, chain: "ethereum", name: null },
      ],
    }]);
    const bodyRows = within(document.querySelector(".ps-addresses-modal-table tbody")).getAllByRole("row");
    expect(bodyRows[0]).toHaveTextContent("rejected");
    expect(bodyRows[0]).toHaveTextContent("chain went away");
    expect(bodyRows.at(-1)).toHaveTextContent("queued");
    expect(screen.getByText(/job 7f3a1c09 · name over 255 characters, no label saved/)).toBeInTheDocument();
    expect(screen.getAllByText("not sent")).toHaveLength(3);
    expect(screen.getByText("3 not sent")).toBeInTheDocument();
    expect(screen.getByText("existing company")).toBeInTheDocument();
    expect(screen.getByTestId("bulk-import-result-company")).toHaveTextContent(/^lido$/);
    expect(screen.queryByText("company created")).not.toBeInTheDocument();
  });

  it("says whether the typed company links to an existing one or is new", async () => {
    const posted = [];
    mockApi(posted);
    render(<BulkImportModal onClose={() => {}} />);
    await companiesLoaded();
    await upload(`address,chain\n${A},ethereum`);
    const queue = screen.getByRole("button", { name: "Queue 1 analysis" });

    expect(screen.queryByText(/existing company|New company/)).not.toBeInTheDocument();
    expect(queue).toBeDisabled();
    typeCompany("   ");
    expect(screen.queryByText(/existing company|New company/)).not.toBeInTheDocument();
    expect(queue).toBeDisabled();

    typeCompany("  LIDO ");
    expect(screen.getByText("existing company")).toBeInTheDocument();
    expect(screen.getByTestId("bulk-import-company-match")).toHaveTextContent(/^lido$/);
    expect(screen.queryByText(/New company/)).not.toBeInTheDocument();
    expect(queue).toBeEnabled();

    typeCompany("Lidoo");
    expect(screen.getByText("New company — created if a row queues")).toBeInTheDocument();
    expect(screen.queryByText("existing company")).not.toBeInTheDocument();

    typeCompany("  Brand New  ");
    fireEvent.click(queue);
    await screen.findByRole("button", { name: "Import another" });
    expect(posted[0].company).toBe("Brand New");
  });

  it("says no company was created when no row queued", async () => {
    setFetchHandler((url) => url.pathname === "/api/companies", () => ["lido"]);
    setFetchHandler((url) => url.pathname === "/api/config", () => new Response("down", { status: 503 }));
    setFetchHandler((url) => url.pathname === "/api/analyze/bulk", () => ({
      company: "Fresh Co",
      company_status: "not_created",
      queued: 0,
      rejected: 1,
      duplicate: 0,
      results: [{ row: 0, status: "rejected", job_id: null, label: null, reason: "chain not enabled" }],
    }));
    render(<BulkImportModal onClose={() => {}} />);
    await companiesLoaded();
    await upload(`address,chain\n${A},arbitrum`);
    typeCompany("Fresh Co");
    fireEvent.click(screen.getByRole("button", { name: "Queue 1 analysis" }));
    await screen.findByText("not created (no row queued)");
    expect(screen.getByTestId("bulk-import-result-company")).toHaveTextContent(/^Fresh Co$/);
    expect(screen.queryByText("existing company")).not.toBeInTheDocument();
    expect(screen.queryByText("company created")).not.toBeInTheDocument();
  });

  it("works as free text without suggestions or a match claim when the company list fails", async () => {
    const posted = [];
    setFetchHandler((url) => url.pathname === "/api/companies", () => new Response("down", { status: 503 }));
    setFetchHandler((url) => url.pathname === "/api/config", () => ({
      enabled_chains: ["ethereum"], chain_spellings: { ethereum: "ethereum" },
    }));
    setFetchHandler((url) => url.pathname === "/api/analyze/bulk", (url, init) => {
      const body = JSON.parse(init.body);
      posted.push(body);
      return {
        company: "Acme",
        company_status: "created",
        queued: 1,
        rejected: 0,
        duplicate: 0,
        results: [{ row: 0, status: "queued", job_id: "7f3a1c09-0000", label: null, reason: null }],
      };
    });
    render(<BulkImportModal onClose={() => {}} />);
    await upload(`address,chain\n${A},ethereum`);
    typeCompany(" acme ");
    expect(screen.getByLabelText("Company")).toBeEnabled();
    expect(screen.getByLabelText("Company")).not.toHaveAttribute("list");
    expect(document.querySelector("datalist")).toBeNull();
    expect(screen.queryByText(/existing company|New company/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Queue 1 analysis" }));
    await screen.findByText("company created");
    expect(screen.getByTestId("bulk-import-result-company")).toHaveTextContent(/^Acme$/);
    expect(posted[0].company).toBe("acme");
  });

  it("after an answerless failure warns about partial queuing and blocks a resend until a new file", async () => {
    setFetchHandler((url) => url.pathname === "/api/companies", () => ["lido"]);
    setFetchHandler((url) => url.pathname === "/api/config", () => ({
      enabled_chains: ["ethereum"], chain_spellings: { ethereum: "ethereum" },
    }));
    setFetchHandler((url) => url.pathname === "/api/analyze/bulk", () => new Response("boom", { status: 500 }));
    render(<BulkImportModal onClose={() => {}} />);
    await companiesLoaded();
    await upload(`address,chain\n${A},ethereum`);
    typeCompany("lido");
    fireEvent.click(screen.getByRole("button", { name: "Queue 1 analysis" }));
    await screen.findByText(/Some rows may already be queued: check the jobs list/);
    expect(screen.queryByText(/try again/i)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Queue 1 analysis" })).toBeDisabled();
    await upload(`address,chain\n${B},ethereum`);
    expect(screen.getByRole("button", { name: "Queue 1 analysis" })).toBeEnabled();
  });

  it("formats a structured 422 detail", async () => {
    setFetchHandler((url) => url.pathname === "/api/companies", () => ["lido"]);
    setFetchHandler((url) => url.pathname === "/api/analyze/bulk", () => new Response(
      JSON.stringify({ detail: [{ loc: ["body", "rows"], msg: "List should have at most 500 items" }] }),
      { status: 422, headers: { "Content-Type": "application/json" } },
    ));
    render(<BulkImportModal onClose={() => {}} />);
    await companiesLoaded();
    await upload(`address,chain\n${A},ethereum`);
    typeCompany("lido");
    fireEvent.click(screen.getByRole("button", { name: /^Queue 1 analysis$/ }));
    await screen.findByText("rows: List should have at most 500 items");
    expect(screen.getByRole("button", { name: "Queue 1 analysis" })).toBeEnabled();
  });

  it("locks the company and file while a submit is in flight", async () => {
    let release;
    setFetchHandler((url) => url.pathname === "/api/companies", () => ["lido"]);
    setFetchHandler((url) => url.pathname === "/api/analyze/bulk", () => new Promise((resolve) => { release = resolve; }));
    render(<BulkImportModal onClose={() => {}} />);
    await companiesLoaded();
    await upload(`address,chain\n${A},ethereum`);
    typeCompany("lido");
    fireEvent.click(screen.getByRole("button", { name: "Queue 1 analysis" }));
    await screen.findByRole("button", { name: "Queuing…" });
    expect(screen.getByLabelText("Company")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Replace file" })).toBeDisabled();
    release({ company: "lido", queued: 0, rejected: 0, duplicate: 0, results: [] });
    await screen.findByRole("button", { name: "Import another" });
  });

  it("refuses an over-cap file in the preview with nothing to queue", async () => {
    mockApi([]);
    render(<BulkImportModal onClose={() => {}} />);
    await companiesLoaded();
    const body = Array.from({ length: 501 }, () => `${A},ethereum`).join("\n");
    fireEvent.change(screen.getByTestId("bulk-import-file"), {
      target: { files: [new File([`address,chain\n${body}`], "big.csv")] },
    });
    await waitFor(() => expect(screen.getByText(/501 rows; one import takes at most 500/)).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Queue" })).toBeDisabled();
  });
});
