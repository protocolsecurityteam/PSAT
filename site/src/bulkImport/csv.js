// CSV parsing and the pre-submit preview for the bulk address import. The
// preview mirrors the server's per-row checks so the admin sees outcomes
// before queuing; the server still re-checks every row it is sent.

export const MAX_ROWS = 500;
// Longer names still queue; only the address label is skipped, as the server does.
export const LABEL_NAME_MAX = 255;

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

export const SENDABLE = new Set(["ready", "chain_unchecked"]);

// RFC 4180: a field that starts with a quote may hold commas, newlines and ""
// escapes. A quote anywhere else is a literal character. `unterminatedLine`
// is the 1-based line where a quoted field opened and never closed.
export function parseCsv(text) {
  const records = [];
  let record = [];
  let field = "";
  let quoted = false;
  let fieldStart = true;
  let line = 1;
  let quoteLine = 0;
  const src = String(text || "").replace(/^\uFEFF/, "");
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (quoted) {
      if (ch === '"') {
        if (src[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          quoted = false;
        }
      } else {
        if (ch === "\n") line++;
        field += ch;
      }
    } else if (ch === '"' && fieldStart) {
      quoted = true;
      fieldStart = false;
      quoteLine = line;
    } else if (ch === ",") {
      record.push(field);
      field = "";
      fieldStart = true;
    } else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && src[i + 1] === "\n") i++;
      line++;
      record.push(field);
      records.push(record);
      record = [];
      field = "";
      fieldStart = true;
    } else {
      field += ch;
      fieldStart = false;
    }
  }
  if (field !== "" || record.length) {
    record.push(field);
    records.push(record);
  }
  return { records, unterminatedLine: quoted ? quoteLine : null };
}

// Same folding as the server's chain_by_name.
export function normalizeChain(value) {
  return String(value || "").trim().replace(/[\s_-]+/g, " ").trim().toLowerCase();
}

function isBlank(record) {
  return record.every((cell) => !cell.trim());
}

// `config` is the admin /api/config payload, or null when it couldn't be
// read: chain checks are then "chain_unchecked" and left to the server.
export function buildPreview(text, config) {
  const parsed = parseCsv(text);
  if (parsed.unterminatedLine !== null) {
    return { error: `Unterminated quote starting on line ${parsed.unterminatedLine}; fix the file and choose it again.` };
  }
  const records = parsed.records.filter((r) => !isBlank(r));
  if (!records.length) return { error: "The file is empty." };
  const header = records[0].map((h) => h.trim().toLowerCase());
  const col = {
    address: header.indexOf("address"),
    chain: header.indexOf("chain"),
    name: header.indexOf("name"),
  };
  if (col.address < 0 || col.chain < 0) {
    return { error: "The first row must be a header naming address and chain columns (name is optional)." };
  }
  const extraColumns = header.filter((h, i) => i !== col.address && i !== col.chain && i !== col.name).length;
  const body = records.slice(1);
  if (!body.length) return { error: "No rows below the header." };
  if (body.length > MAX_ROWS) {
    return { error: `${body.length} rows; one import takes at most ${MAX_ROWS}.` };
  }

  const spellings = config?.chain_spellings || null;
  const enabled = new Set(config?.enabled_chains || []);
  const firstLine = new Map();
  const rows = body.map((record, i) => {
    // 1-based data row, blank lines skipped.
    const line = i + 1;
    const address = (record[col.address] || "").trim();
    const chain = (record[col.chain] || "").trim();
    const name = col.name >= 0 ? (record[col.name] || "").trim() : "";
    const normalized = normalizeChain(chain);
    // Blank means mainnet, as in a single submission.
    const canonical = spellings ? spellings[normalized || "ethereum"] || null : normalized || "ethereum";
    const row = {
      line, address, chain, name, check: "ready", duplicateOf: null, nameTooLong: name.length > LABEL_NAME_MAX,
    };

    // Only a row that would be sent claims its key, so a later copy of a refused row is still judged on its own.
    const key = `${address.toLowerCase()}|${canonical || normalized}`;
    if (firstLine.has(key)) {
      row.check = "duplicate";
      row.duplicateOf = firstLine.get(key);
      return row;
    }
    if (!ADDRESS_RE.test(address)) row.check = "invalid_address";
    else if (!spellings) row.check = "chain_unchecked";
    else if (!canonical) row.check = "unknown_chain";
    else if (!enabled.has(canonical)) row.check = "chain_not_enabled";
    if (SENDABLE.has(row.check)) firstLine.set(key, line);
    return row;
  });

  const counts = {};
  for (const r of rows) counts[r.check] = (counts[r.check] || 0) + 1;
  return { rows, counts, extraColumns, sendable: rows.filter((r) => SENDABLE.has(r.check)) };
}

// Server results come back in the order rows were sent; rows the preview held
// back keep their preview check. Rejected first, then not sent, then queued.
export function mergeResults(preview, response) {
  const byLine = new Map();
  preview.sendable.forEach((row, i) => {
    const result = response.results[i];
    if (result) byLine.set(row.line, result);
  });
  const merged = preview.rows.map((row) => {
    const result = byLine.get(row.line);
    if (!result) return { ...row, outcome: "not_sent" };
    return { ...row, outcome: result.status, result };
  });
  const rank = { rejected: 0, not_sent: 1, duplicate: 1, queued: 2 };
  return merged.sort((a, b) => rank[a.outcome] - rank[b.outcome] || a.line - b.line);
}
