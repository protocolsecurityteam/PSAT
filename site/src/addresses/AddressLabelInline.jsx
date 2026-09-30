import React from "react";
import { useIsAdmin } from "../api/useIsAdmin.js";
import {
  upsertAddressLabel,
  deleteAddressLabel,
  resolveLabelName,
} from "../api/addressLabels.js";

// Inline label editor (window.prompt; auth via the shared api() client).
//
// `labels` is a legacy Map or buildLabelMaps' `{ global, byChain }`. With
// `chain` it edits the chain-qualified override (contracts); without, the
// global row (EOAs/Safe signers). Display is
// chain-specific-wins-else-global.
export default function AddressLabelInline({ address, labels, chain = null, refreshAll, size = "sm" }) {
  const isAdmin = useIsAdmin();
  const addrLower = String(address || "").toLowerCase();
  const current = resolveLabelName(labels, addrLower, chain);

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
