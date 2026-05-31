import React from "react";
import {
  upsertAddressLabel,
  deleteAddressLabel,
  lookupLabel,
} from "./api/addressLabels.js";

// Inline "label this address" affordance. Shows the current admin-set name
// with a pencil for edits; or a "+ label" button when none exists. Uses
// window.prompt() for simplicity — admin auth is handled by the shared
// api() client (401 → prompt for key → retry).
//
// Props:
// - address: string — the address to label
// - chain: string — the address's network (default "ethereum"); labels are
//   per-(address, chain) so edits target the right network's label
// - labels: Map<`${chain}:${lowercase-address}`, name> — the current label cache
// - refreshAll: () => void — called after a successful save/delete so the
//   caller can refresh its labels map
// - size: "sm" (default) | "xs"
export default function AddressLabelInline({ address, chain = "ethereum", labels, refreshAll, size = "sm" }) {
  const addrLower = String(address || "").toLowerCase();
  const current = lookupLabel(labels, addrLower, chain);

  const onEdit = async () => {
    const next = window.prompt(
      current ? "Edit label for this address:" : "Add a label for this address:",
      current || "",
    );
    if (next == null) return;
    const trimmed = next.trim();
    try {
      if (!trimmed) {
        if (!current) return;
        await deleteAddressLabel(addrLower, chain);
      } else {
        await upsertAddressLabel(addrLower, trimmed, null, chain);
      }
      refreshAll && refreshAll();
    } catch (err) {
      console.error("Address label edit failed:", err);
      window.alert(`Could not save label: ${err?.message || err}`);
    }
  };

  return (
    <span className={`ps-address-label ps-address-label-${size}`}>
      {current ? (
        <>
          <span className="ps-address-label-name">{current}</span>
          <button
            type="button"
            className="ps-address-label-edit"
            onClick={(e) => { e.stopPropagation(); onEdit(); }}
            title="Edit label"
            aria-label="Edit label"
          >
            ✎
          </button>
        </>
      ) : (
        <button
          type="button"
          className="ps-address-label-add"
          onClick={(e) => { e.stopPropagation(); onEdit(); }}
          title="Add a label"
        >
          + label
        </button>
      )}
    </span>
  );
}
