import { GotoArrow } from "../../GotoArrow.jsx";

// A timeline row's call target. The name previews, the arrow commits. Off-graph
// targets get no selection affordance and render the full address.
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
