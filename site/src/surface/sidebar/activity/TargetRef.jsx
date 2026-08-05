import { GotoArrow } from "../../GotoArrow.jsx";

// The call target of a timeline row, as an interactive reference.
//
// Selection follows the surface's preview-vs-commit rule: clicking the name
// PREVIEWS the entity (gold dotted marker, camera unchanged), and only the
// explicit → arrow commits the selection — same contract as every other
// sidebar row (GovernsTab, controller rows).
//
// An off-graph target gets no selection affordance (there is no node to
// select) and is rendered with its FULL address plus the stated note: a
// contract this protocol's graph cannot name deserves the whole witness,
// not a truncation that looks like every resolvable row.
export function TargetRef({ target, onPreview, onNavigate }) {
  if (!target?.address) return null;
  const prep = target.prep || "on";

  if (!target.label) {
    return (
      <span className="ps-activity-target">
        {prep}{" "}
        <span className="ps-activity-target-addr">{target.address}</span>
        {target.onGraph === false ? (
          <span className="ps-activity-target-note"> · not on this protocol&apos;s graph</span>
        ) : null}
      </span>
    );
  }

  return (
    <span className="ps-activity-target">
      {prep}{" "}
      <button
        type="button"
        className="ps-activity-target-link"
        title={target.address}
        onClick={(e) => {
          e.stopPropagation();
          if (onPreview) onPreview(target.address);
        }}
      >
        {target.label}
      </button>
      {onNavigate ? (
        <GotoArrow
          onCommit={() => onNavigate({ type: "contract", address: target.address, label: target.label })}
          label={`Go to ${target.label}`}
        />
      ) : null}
    </span>
  );
}
