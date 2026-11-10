// A Safe's signer figure from its published threshold and owner count. A
// missing threshold is not determined; the owner count never stands in for
// it. Null with no owners.
export function safeSignersText(threshold, ownerCount) {
  if (!(ownerCount > 0)) return null;
  const t = Number(threshold);
  return Number.isFinite(t) && t > 0
    ? `${t}/${ownerCount}`
    : `${ownerCount} signer${ownerCount === 1 ? "" : "s"} · threshold not determined`;
}

export function safeDetailsSignersText(details) {
  const owners = Array.isArray(details?.owners) ? details.owners.length : 0;
  return safeSignersText(details?.threshold, owners);
}
