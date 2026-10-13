import { describe, it, expect } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";

import EventsFeed, { eventTypeLabel, feedQuery } from "./EventsFeed.jsx";
import { setFetchHandler } from "../test/fetchMock.js";

const TX = `0x${"ab".repeat(32)}`;
const VAULT = "0x1111111111111111111111111111111111111111";
const BRIDGE = "0x2222222222222222222222222222222222222222";

function evt(id, overrides = {}) {
  return {
    id,
    event_type: "upgraded",
    block_number: 100,
    tx_hash: TX,
    log_index: 0,
    detected_at: "2026-03-02T10:00:00+00:00",
    data: {},
    contract: { address: VAULT, chain: "ethereum", name: "Vault" },
    protocol: { id: 7, name: "etherfi" },
    ...overrides,
  };
}

const OPTIONS = {
  protocols: [{ id: 7, name: "etherfi" }, { id: 9, name: "lido" }],
  event_types: [{ event_type: "ownership_transferred", count: 2 }, { event_type: "paused", count: 1 }],
};

function serve(pages, options = OPTIONS) {
  const requests = [];
  setFetchHandler((url) => url.pathname === "/api/me/events", (url) => {
    requests.push(url.searchParams);
    return pages(url.searchParams);
  });
  setFetchHandler((url) => url.pathname === "/api/me/events/filters", () => options);
  return requests;
}

describe("feedQuery", () => {
  it("sends local-day bounds with an inclusive end date", () => {
    const params = new URL(
      feedQuery({ protocol: "7", eventType: "paused", from: "2026-03-01", to: "2026-03-02" }, "abc"),
      "http://x",
    ).searchParams;
    expect(params.get("protocol_id")).toBe("7");
    expect(params.get("event_type")).toBe("paused");
    expect(params.get("since")).toBe(new Date(2026, 2, 1).toISOString());
    expect(params.get("until")).toBe(new Date(2026, 2, 3).toISOString());
    expect(params.get("cursor")).toBe("abc");
  });

  it("omits unset filters", () => {
    const params = new URL(feedQuery({ protocol: "", eventType: "", from: "", to: "" }), "http://x").searchParams;
    expect([...params.keys()]).toEqual(["limit"]);
  });
});

describe("eventTypeLabel", () => {
  it("names raw event types the way the activity timeline does", () => {
    expect(eventTypeLabel("ownership_transferred")).toBe("Ownership transferred");
    expect(eventTypeLabel("paused")).toBe("Contract paused");
    expect(eventTypeLabel("value_changed:state_variable:owner")).toBe("Owner changed (verified)");
  });
});

describe("EventsFeed", () => {
  it("renders each event's type, contract, timestamp, severity and explorer link in server order", async () => {
    serve(() => ({
      events: [
        evt("e1", {
          event_type: "ownership_transferred",
          data: { salience: "alert", old_owner: VAULT, new_owner: BRIDGE },
          detected_at: "2026-03-02T10:00:00+00:00",
        }),
        evt("e2", {
          event_type: "paused",
          tx_hash: null,
          contract: { address: BRIDGE, chain: "base", name: null },
          protocol: { id: 9, name: "lido" },
          data: { salience: "routine" },
          detected_at: "2026-03-01T10:00:00+00:00",
        }),
      ],
      next_cursor: null,
    }));
    render(<EventsFeed />);

    const rows = await screen.findAllByRole("listitem");
    expect(rows.map((r) => r.dataset.eventId)).toEqual(["e1", "e2"]);

    const first = within(rows[0]);
    expect(first.getByText("Critical")).toBeInTheDocument();
    expect(first.getByText("Ownership transferred")).toBeInTheDocument();
    expect(first.getByText("Vault")).toBeInTheDocument();
    expect(rows[0].querySelector("time").getAttribute("dateTime")).toBe("2026-03-02T10:00:00+00:00");
    expect(first.getByRole("link", { name: /View tx on Etherscan/ })).toHaveAttribute(
      "href",
      `https://etherscan.io/tx/${TX}`,
    );

    const second = within(rows[1]);
    expect(second.getByText("Routine")).toBeInTheDocument();
    expect(second.getByText("Contract paused")).toBeInTheDocument();
    expect(second.getByRole("link", { name: "0x2222...2222" })).toHaveAttribute(
      "href",
      `https://basescan.org/address/${BRIDGE}`,
    );
    expect(second.getByText("Detected by state read")).toBeInTheDocument();
    expect(second.queryByRole("link", { name: /View tx/ })).toBeNull();
    expect(screen.getByText(/2 events · end of history/)).toBeInTheDocument();
  });

  it("shows a clear message when there are no events yet", async () => {
    serve(() => ({ events: [], next_cursor: null }));
    render(<EventsFeed />);
    expect(await screen.findByText("No monitoring events yet")).toBeInTheDocument();
    expect(screen.queryByRole("listitem")).toBeNull();
  });

  it("sends each filter to the API and clearing restores the full list", async () => {
    const requests = serve((params) => ({
      events: params.has("protocol_id") || params.has("event_type") || params.has("since") ? [] : [evt("e1")],
      next_cursor: null,
    }));
    render(<EventsFeed />);
    await screen.findAllByRole("listitem");
    // Options arrive separately from the first page.
    await screen.findByRole("option", { name: "lido" });

    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "9" } });
    await screen.findByText(/No events match these filters/);
    expect(requests.at(-1).get("protocol_id")).toBe("9");

    fireEvent.change(screen.getByLabelText("Event type"), { target: { value: "paused" } });
    fireEvent.change(screen.getByLabelText("From"), { target: { value: "2026-03-01" } });
    await waitFor(() => expect(requests.at(-1).get("since")).toBe(new Date(2026, 2, 1).toISOString()));
    expect(requests.at(-1).get("protocol_id")).toBe("9");
    expect(requests.at(-1).get("event_type")).toBe("paused");
    expect(screen.getByRole("option", { name: "Contract paused (1)" })).toBeInTheDocument();

    fireEvent.click(screen.getAllByRole("button", { name: "Clear filters" })[0]);
    expect(await screen.findAllByRole("listitem")).toHaveLength(1);
    expect([...requests.at(-1).keys()]).toEqual(["limit"]);
    expect(screen.getByLabelText("Protocol")).toHaveValue("");
  });

  it("pages through history with the cursor and stops at the end", async () => {
    const requests = serve((params) =>
      params.get("cursor") === "c1"
        ? { events: [evt("e3"), evt("e4")], next_cursor: null }
        : { events: [evt("e1"), evt("e2")], next_cursor: "c1" },
    );
    render(<EventsFeed />);
    expect(await screen.findAllByRole("listitem")).toHaveLength(2);

    fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    await screen.findByText(/4 events · end of history/);
    expect(screen.getAllByRole("listitem").map((r) => r.dataset.eventId)).toEqual(["e1", "e2", "e3", "e4"]);
    expect(requests.map((p) => p.get("cursor"))).toEqual([null, "c1"]);
    expect(screen.queryByRole("button", { name: "Load more" })).toBeNull();
  });

  it("shows the server's error with a retry", async () => {
    let fail = true;
    setFetchHandler((url) => url.pathname === "/api/me/events", () =>
      fail
        ? new Response(JSON.stringify({ detail: "Invalid cursor" }), {
            status: 422,
            headers: { "Content-Type": "application/json" },
          })
        : { events: [evt("e1")], next_cursor: null },
    );
    render(<EventsFeed />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid cursor");
    fail = false;
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findAllByRole("listitem")).toHaveLength(1);
  });
});
