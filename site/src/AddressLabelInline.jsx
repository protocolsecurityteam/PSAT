import React from "react";
import { useIsAdmin } from "./api/useIsAdmin.js";
import {
  upsertAddressLabel,
  deleteAddressLabel,
} from "./api/addressLabels.js";

// Inline "label this address" affordance. Shows the current admin-set name
// with a pencil for edits; or a "+ label" button when none exists. Uses
// window.prompt() for simplicity — admin auth is handled by the shared
// api() client (401 → prompt for key → retry).
//
// Props:
// - address: string — the address to label
// - labels: Map<lowercase-address, name> — the current label cache
// - refreshAll: () => void — called after a successful save/delete so the
//   caller can refresh its labels map
// - size: "sm" (default) | "xs"
export default function AddressLabelInline({ address, labels, refreshAll, size = "sm" }) {
  const isAdmin = useIsAdmin();
  const addrLower = String(address || "").toLowerCase();
  const current = labels?.get ? labels.get(addrLower) : null;

  // Non-admins see the label read-only: the name when one is set, and no
  // edit affordance at all when it isn't.
  if (!isAdmin) {
    if (!current) return null;
    return (
      <span className={`ps-address-label ps-address-label-${size}`}>
        <span className="ps-address-label-name">{current}</span>
      </span>
    );
  }

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
        await deleteAddressLabel(addrLower);
      } else {
        await upsertAddressLabel(addrLower, trimmed);
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
