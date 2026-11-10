import { describe, expect, it } from "vitest";

import { controllerReadFor, controllerReadText, controllerValuesNote } from "./controllerReads.js";

const SAFE = "0xaaaa000000000000000000000000000000000aaa";
const read = (over = {}) => ({ value: SAFE, block_number: 21000000, block_basis: "head_before_read", observed_via: "eth_call", ...over });

describe("controllerReadText", () => {
  it("words each block_basis token", () => {
    expect(controllerReadText(read())).toBe("read at latest, head ≈ block 21000000 · via eth_call");
    expect(controllerReadText(read({ block_basis: "log_block", block_number: 123, observed_via: "event_log" }))).toBe(
      "set at block 123 · from event log",
    );
    expect(controllerReadText(read({ block_basis: "not_determined", block_number: null, observed_via: "storage_poll" }))).toBe(
      "read block not determined · from storage poll",
    );
  });

  it("words each observed_via token", () => {
    expect(controllerReadText(read({ observed_via: "eth_call_impl_fallback" }))).toMatch(/via eth_call \(implementation fallback\)$/);
    expect(controllerReadText(read({ observed_via: "beacon_owner" }))).toMatch(/via beacon owner$/);
    expect(controllerReadText(read({ observed_via: "eth_call_error" }))).toMatch(/eth_call errored$/);
  });

  it("renders unknown tokens raw", () => {
    expect(controllerReadText(read({ block_basis: "pinned_block", observed_via: "trace_call" }))).toBe("pinned_block · trace_call");
  });

  it("never names a block it wasn't given", () => {
    expect(controllerReadText(read({ block_number: null, observed_via: null }))).toBe("head_before_read");
    expect(controllerReadText(null)).toBeNull();
  });
});

describe("controllerReadFor", () => {
  const entry = { controller_reads: { owner: read() } };

  it("returns the read only when its value is the principal's address", () => {
    expect(controllerReadFor(entry, "owner", SAFE.toUpperCase().replace("0X", "0x"))).toBe(entry.controller_reads.owner);
    // A policy-stage principal can disagree with the current value.
    expect(controllerReadFor(entry, "owner", "0xbbbb000000000000000000000000000000000bbb")).toBeNull();
  });

  it("is null without an entry, a controller id or a read", () => {
    expect(controllerReadFor(null, "owner", SAFE)).toBeNull();
    expect(controllerReadFor(entry, null, SAFE)).toBeNull();
    expect(controllerReadFor(entry, "admin", SAFE)).toBeNull();
    expect(controllerReadFor({ controller_reads: { owner: read({ value: null }) } }, "owner", SAFE)).toBeNull();
  });
});

describe("controllerValuesNote", () => {
  it("words not_determined, keeps unknown tokens raw, and is null with no claim", () => {
    expect(controllerValuesNote({ controller_values_state: "not_determined" })).toEqual({
      token: "not_determined",
      word: "controller values not determined for this deployment",
      notDetermined: true,
    });
    expect(controllerValuesNote({ controller_values_state: "partial" })).toEqual({
      token: "partial",
      word: "partial",
      notDetermined: false,
    });
    expect(controllerValuesNote({ controller_values_state: null })).toBeNull();
    expect(controllerValuesNote(null)).toBeNull();
  });
});
