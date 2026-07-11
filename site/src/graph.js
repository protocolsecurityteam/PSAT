export function shortenAddress(value) {
  if (!value || typeof value !== "string" || !value.startsWith("0x") || value.length < 12) {
    return value || "Unknown";
  }
  return `${value.slice(0, 6)}...${value.slice(-4)}`;
}

export function wrapText(value, maxChars, maxLines) {
  const text = String(value || "").trim();
  if (!text) {
    return [];
  }

  const words = text.split(/\s+/);
  const lines = [];
  let current = "";

  function pushCurrent() {
    if (current) {
      lines.push(current);
      current = "";
    }
  }

  for (const word of words) {
    if (word.length > maxChars) {
      pushCurrent();
      let remaining = word;
      while (remaining.length > maxChars) {
        lines.push(`${remaining.slice(0, maxChars - 1)}-`);
        remaining = remaining.slice(maxChars - 1);
        if (lines.length >= maxLines) {
          lines[maxLines - 1] = `${lines[maxLines - 1].slice(0, maxChars - 1)}…`;
          return lines.slice(0, maxLines);
        }
      }
      current = remaining;
      continue;
    }

    const candidate = current ? `${current} ${word}` : word;
    if (candidate.length <= maxChars) {
      current = candidate;
      continue;
    }

    pushCurrent();
    current = word;
    if (lines.length >= maxLines) {
      break;
    }
  }

  pushCurrent();
  if (lines.length > maxLines) {
    return [...lines.slice(0, maxLines - 1), `${lines[maxLines - 1].slice(0, maxChars - 1)}…`];
  }
  return lines;
}
