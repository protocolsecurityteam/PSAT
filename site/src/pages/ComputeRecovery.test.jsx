import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ComputeRecovery } from "./ComputeRecovery.jsx";
import { api } from "../api/client.js";
vi.mock("../api/client.js", () => ({ api: vi.fn() }));
const job = { job_id: "root", compute_target: "local", compute_group_id: "group123456", status: "queued" };
describe("compute recovery", () => {
  it("displays routing and moves a settled local group", async () => {
    api.mockResolvedValue({ moved: 2 });
    render(<ComputeRecovery job={job} groupJobs={[job]} />);
    expect(screen.getByText("Compute: Local")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Move local run to cloud" }));
    await waitFor(() => expect(api).toHaveBeenCalledWith("/api/jobs/root/move-to-cloud", { method: "POST", silent: true }));
    expect(await screen.findByRole("status")).toHaveTextContent("Run moved to cloud");
  });
  it("blocks recovery while any group member is processing", () => {
    render(<ComputeRecovery job={job} groupJobs={[job, { ...job, job_id: "child", status: "processing" }]} />);
    expect(screen.getByRole("button")).toBeDisabled();
  });
  it("shows a conflict without pretending the run moved", async () => {
    api.mockRejectedValue(new Error("Active attempt; wait and retry"));
    render(<ComputeRecovery job={job} />);
    fireEvent.click(screen.getByRole("button"));
    expect(await screen.findByRole("alert")).toHaveTextContent("Active attempt");
    expect(screen.getByText("Compute: Local")).toBeInTheDocument();
  });
});
