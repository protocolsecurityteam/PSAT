import { formatDelay, shortAddr } from "../format.js";
import { GotoArrow } from "../GotoArrow.jsx";
import { LANE_META, TYPE_META } from "../meta.js";

// Empty-callers copy keyed by the guard's open-path shape, so a one-shot or a
// denylist/permit reads accurately instead of a flat "marked public".
const OPEN_CALLER_TEXT = {
  one_shot_consumed: "Consumed one-shot initializer — the open path is spent and can no longer be called.",
  one_shot_live: "Live one-shot initializer — anyone can call it once until it is consumed.",
  one_shot_unread: "One-shot initializer — open to anyone until its latch is consumed (on-chain state not yet read).",
  denylist: "Permissionless except a denylist — callable by anyone not on the excluded list.",
  permit: "Permissionless via signature — the affected party must have authorized it (permit-style).",
  self_service: "Self-service — each caller can act only on their own account.",
  public: "Permissionless — callable by anyone.",
};

function emptyCallerText(selected) {
  const text = OPEN_CALLER_TEXT[selected.guard?.shape];
  if (text) return text;
  if (selected.authorityPublic) return "Permissionless — callable by anyone.";
  if (selected.guard?.kind === "resolved_empty") return "No active principal can call this path right now.";
  return "No controlling principal was resolved for this path.";
}

function principalDetail(principal) {
  const ownerCount = Array.isArray(principal.details?.owners) ? principal.details.owners.length : 0;
  const threshold = Number(principal.details?.threshold);
  const delay = formatDelay(principal.details?.delay);

  if (principal.resolvedType === "safe" && ownerCount) {
    return Number.isFinite(threshold) && threshold > 0 ? `${threshold}-of-${ownerCount} safe` : `${ownerCount} safe signers`;
  }
  if (principal.resolvedType === "timelock" && delay) {
    return `${delay} delay`;
  }
  if (principal.resolvedType === "eoa") {
    return "Externally owned account";
  }
  if (principal.resolvedType === "contract") {
    return "Contract-controlled principal";
  }
  if (principal.resolvedType === "proxy_admin") {
    return "Proxy admin principal";
  }
  return "Controller path";
}

// One shared principal reference card for both inspector blocks (Direct Callers
// and Indirect Control Path). Body previews the principal on the canvas; the
// arrow commits to its card — the same peek/commit split as lane caller buttons
// and Governs rows. `indirect` swaps the origin line (governance path vs.
// direct-caller origins) and dims the card.
function PrincipalRefCard({ principal, indirect = false, onPreview, onNavigate }) {
  const type = TYPE_META[principal.resolvedType] || TYPE_META.unknown;
  const detail = principalDetail(principal);
  const target = { type: principal.resolvedType, address: principal.address, label: detail, details: principal.details };
  return (
    <div
      className={`ps-principal-card ps-principal-clickable${indirect ? " ps-principal-indirect" : ""}`}
      role="button"
      tabIndex={0}
      onClick={() => onPreview && onPreview(principal.address)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onPreview && onPreview(principal.address);
        }
      }}
    >
      <div className="ps-principal-top">
        <span className="ps-principal-type" style={{ "--principal-accent": type.accent }}>{type.label}</span>
        <span className="ps-principal-address">{shortAddr(principal.address)}</span>
        {onNavigate && <GotoArrow onCommit={() => onNavigate(target)} label={`Go to ${type.label} ${shortAddr(principal.address)}`} />}
      </div>
      <div className="ps-principal-meta">{detail}</div>
      <div className="ps-principal-origin">
        {indirect
          ? `via ${principal.path.slice(0, -1).map((p) => shortAddr(p.address)).join(" → ")}`
          : principal.origins.join(" · ")}
      </div>
    </div>
  );
}

export function InspectorCard({ selected, onNavigate, onPreview }) {
  if (!selected) {
    return null;
  }

  return (
    <aside className="ps-inspector">
      <div className="ps-inspector-eyebrow">Guard Inspector</div>
      <h3>{selected.name}</h3>
      <div className="ps-inspector-subtitle">
        <span>{selected.contractName}</span>
        <span>{shortAddr(selected.contractAddress)}</span>
      </div>

      <div className="ps-inspector-badges">
        <span className="ps-badge" style={{ "--badge-accent": LANE_META[selected.lane].tone }}>{LANE_META[selected.lane].label}</span>
        <span className="ps-badge" style={{ "--badge-accent": selected.guard.accent }}>{selected.guard.label}</span>
        {selected.effectLabels.map((label) => (
          <span key={label} className="ps-badge" style={{ "--badge-accent": "#475569" }}>{label}</span>
        ))}
      </div>

      <div className="ps-inspector-block">
        <div className="ps-inspector-label">Signature</div>
        <code className="ps-inspector-code">{selected.signature}</code>
      </div>

      <div className="ps-inspector-block">
        <div className="ps-inspector-label">Action</div>
        <p className="ps-inspector-body">{selected.action || "Permissioned path"}</p>
      </div>

      <div className="ps-inspector-block">
        <div className="ps-inspector-label">
          Direct Callers
          <span className="ps-inspector-sublabel">
            msg.sender set from function-level permissions
          </span>
        </div>
        {selected.principals.length ? (
          <div className="ps-principal-list">
            {selected.principals.map((principal) => (
              <PrincipalRefCard
                key={principal.address}
                principal={principal}
                onPreview={onPreview}
                onNavigate={onNavigate}
              />
            ))}
          </div>
        ) : (
          <p className="ps-inspector-empty">{emptyCallerText(selected)}</p>
        )}
      </div>

      {(selected.indirectPrincipals || []).length > 0 && (
        <div className="ps-inspector-block">
          <div className="ps-inspector-label">
            Indirect Control Path
            <span className="ps-inspector-sublabel">
              governance context — not a direct call right
            </span>
          </div>
          <div className="ps-principal-list">
            {selected.indirectPrincipals.map((principal) => (
              <PrincipalRefCard
                key={principal.address}
                principal={principal}
                indirect
                onPreview={onPreview}
                onNavigate={onNavigate}
              />
            ))}
          </div>
        </div>
      )}
    </aside>
  );
}
