import { describe, expect, it } from "vitest";

import { MAX_ROWS, buildPreview, mergeResults, parseCsv } from "./csv.js";

const A = "0x" + "a".repeat(40);
const B = "0x" + "b".repeat(40);
const C = "0x" + "c".repeat(40);
const CONFIG = {
  enabled_chains: ["ethereum", "base"],
  chain_spellings: { ethereum: "ethereum", mainnet: "ethereum", base: "base", arbitrum: "arbitrum", "arbitrum one": "arbitrum" },
};

describe("parseCsv", () => {
  it("handles quoted commas, escaped quotes, embedded newlines, CRLF and a BOM", () => {
    const text = '\uFEFFaddress,name\r\n0x1,"Vault, ""v2"""\r\n0x2,"two\nlines"\n';
    expect(parseCsv(text)).toEqual({
      records: [
        ["address", "name"],
        ["0x1", 'Vault, "v2"'],
        ["0x2", "two\nlines"],
      ],
      unterminatedLine: null,
    });
  });

  it("keeps a quote that is not at the start of a field as a literal", () => {
    const { records, unterminatedLine } = parseCsv('address,chain,name\n0xa,ethereum,5" Vault\n0xb,base,B\n0xc,base,C');
    expect(unterminatedLine).toBeNull();
    expect(records).toEqual([
      ["address", "chain", "name"],
      ["0xa", "ethereum", '5" Vault'],
      ["0xb", "base", "B"],
      ["0xc", "base", "C"],
    ]);
  });

  it("reports a quoted field that never closes instead of swallowing the rest", () => {
    expect(parseCsv('address,chain,name\n0xa,ethereum,ok\n0xb,base,"open\n0xc,base,C').unterminatedLine).toBe(3);
  });
});

describe("buildPreview", () => {
  it("flags every check and ignores extra columns", () => {
    const csv = [
      "Address,Chain,Name,group",
      `${A},ethereum,Vault,x`,
      `0xzz,ethereum,Bad,x`,
      `${B},base-sepolia,Unknown,x`,
      `${B},arbitrum one,Disabled,x`,
      `${A.toUpperCase().replace("0X", "0x")},mainnet,Dup,x`,
      "",
      `${C},,Chainless,x`,
    ].join("\n");
    const p = buildPreview(csv, CONFIG);
    expect(p.error).toBeUndefined();
    expect(p.extraColumns).toBe(1);
    expect(p.rows.map((r) => r.check)).toEqual([
      "ready", "invalid_address", "unknown_chain", "chain_not_enabled", "duplicate", "ready",
    ]);
    expect(p.rows[4].duplicateOf).toBe(1);
    expect(p.rows.map((r) => r.line)).toEqual([1, 2, 3, 4, 5, 6]);
    expect(p.sendable.map((r) => r.address)).toEqual([A, C]);
    expect(p.counts).toMatchObject({ ready: 2, duplicate: 1 });
  });

  it("leaves chains unchecked, not ready, when the chain list is unavailable", () => {
    const p = buildPreview(`address,chain\n${A},base\n${B},nonsense`, null);
    expect(p.rows.map((r) => r.check)).toEqual(["chain_unchecked", "chain_unchecked"]);
    expect(p.sendable).toHaveLength(2);
  });

  it("refuses the whole file on an unterminated quote", () => {
    const p = buildPreview(`address,chain,name\n${A},ethereum,"Vault\n${B},base,B\n${C},base,C`, CONFIG);
    expect(p.error).toMatch(/Unterminated quote starting on line 2/);
    expect(p.rows).toBeUndefined();
  });

  it("judges a copy of a refused row on its own instead of calling it a duplicate", () => {
    const p = buildPreview(`address,chain\n${A},arbitrum\n${A},arbitrum one\n0xzz,base\n0xZZ,base`, CONFIG);
    expect(p.rows.map((r) => r.check)).toEqual([
      "chain_not_enabled", "chain_not_enabled", "invalid_address", "invalid_address",
    ]);
    const q = buildPreview(`address,chain\n${A},ethereum\n${A},ethereum\n${A},ethereum`, CONFIG);
    expect(q.rows.map((r) => [r.check, r.duplicateOf])).toEqual([["ready", null], ["duplicate", 1], ["duplicate", 1]]);
  });

  it("keeps over-long cells as row checks: a long name still sends, a long address or chain does not", () => {
    const longName = "n".repeat(300);
    const p = buildPreview(`address,chain,name\n${A},ethereum,${longName}\n0x${"a".repeat(500)},ethereum,x\n${B},${"c".repeat(100)},y`, CONFIG);
    expect(p.rows.map((r) => r.check)).toEqual(["ready", "invalid_address", "unknown_chain"]);
    expect(p.rows[0].nameTooLong).toBe(true);
    expect(p.sendable.map((r) => r.address)).toEqual([A]);
  });

  it("requires a header naming address and chain", () => {
    expect(buildPreview(`${A},ethereum`, CONFIG).error).toMatch(/header/);
    expect(buildPreview("address,name\nx,y", CONFIG).error).toMatch(/header/);
    expect(buildPreview("address,chain\n", CONFIG).error).toMatch(/No rows/);
    expect(buildPreview("", CONFIG).error).toMatch(/empty/);
  });

  it("rejects a file over the row cap outright", () => {
    const body = Array.from({ length: MAX_ROWS + 1 }, (_, i) => `0x${i.toString(16).padStart(40, "0")},ethereum`);
    const over = buildPreview(["address,chain", ...body].join("\n"), CONFIG);
    expect(over.error).toMatch(/501 rows/);
    expect(over.rows).toBeUndefined();
    const atCap = buildPreview(["address,chain", ...body.slice(1)].join("\n"), CONFIG);
    expect(atCap.rows).toHaveLength(MAX_ROWS);
  });
});

describe("mergeResults", () => {
  it("maps server results back by send order and sorts rejected, not sent, queued", () => {
    const p = buildPreview(`address,chain\n${A},ethereum\n0xzz,ethereum\n${B},base\n${C},mainnet`, CONFIG);
    const merged = mergeResults(p, {
      results: [
        { row: 0, status: "queued", job_id: "11111111-aaaa" },
        { row: 1, status: "rejected", reason: "nope" },
        { row: 2, status: "queued", job_id: "22222222-bbbb" },
      ],
    });
    expect(merged.map((r) => [r.line, r.outcome])).toEqual([
      [3, "rejected"], [2, "not_sent"], [1, "queued"], [4, "queued"],
    ]);
  });
});
