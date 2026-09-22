import { formatDelay, shortAddr } from "../format.js";
import { GotoArrow } from "../GotoArrow.jsx";
import { LANE_META, TYPE_META } from "../meta.js";
import { claimWitnessFacts } from "../../vocab/witnessFacts.js";
import { sharedDeployerNote, signerOverlapNote, terminalControllerNote } from "../../vocab/principalNotes.js";

// Way-point / terminal-controller copy for a non-terminal principal. Mirrors the
// backend witness bar: a resolved_type=contract principal is a way-point, never a
// settled key, so the UI must never imply one where the chain didn't terminate
// (SCORING plan §4). Renders nothing for a settled key.
function TerminalNote({ principal }) {
  const note = terminalControllerNote(principal);
  if (!note) return null;
  if (note.kind === "terminated") {
    return (
      <div className="ps-principal-terminal">
        ultimate key: {shortAddr(note.address)} · {note.resolvedType}
      </div>
    );
  }
  if (note.kind === "multi_plane") {
    // Per-plane detail so a reviewer sees the weakest plane; header never implies
    // one settled key.
    return (
      <div className="ps-principal-terminal ps-principal-terminal-open">
        <div>{note.planes.length} parallel control planes — no single settled key</div>
        <ul className="ps-principal-planes">
          {note.planes.map((p, i) => (
            <li key={p.controller || i}>
              {shortAddr(p.controller)} →{" "}
              {p.outcome.resolved
                ? `ultimate key ${shortAddr(p.outcome.address)} (${p.outcome.resolvedType})`
                : `unresolved (${p.outcome.status})`}
            </li>
          ))}
        </ul>
      </div>
    );
  }
  if (note.kind === "ambiguous") {
    return (
      <div className="ps-principal-terminal ps-principal-terminal-open">
        {note.planes.length} parallel control planes witnessed — no single settled key
      </div>
    );
  }
  return (
    <div className="ps-principal-terminal ps-principal-terminal-open">
      controlled by contract — ultimate key unresolved
    </div>
  );
}

// Shared-deployer attribution HINT (Tier-1 on-chain read, but a HEURISTIC for
// attribution). Inspector-only; the copy always carries the hedge — never phrased
// as org identity or common control.
function SharedDeployerNote({ principal }) {
  const note = sharedDeployerNote(principal);
  if (!note) return null;
  return (
    <div className="ps-principal-deployer">
      shares a deployer with {note.otherCount} other address{note.otherCount === 1 ? "" : "es"}
      {note.heuristic ? " (heuristic — not proof of common control)" : ""}
    </div>
  );
}

// Signer-overlap attribution CONTEXT (Tier 1, on-chain owner reads). NOT proof of
// shared organizational identity — the copy stays factual about signers only.
function SignerOverlapNote({ principal }) {
  const note = signerOverlapNote(principal);
  if (!note || !note.strongest) return null;
  const s = note.strongest;
  const shareText = s.equal
    ? `same signer set as ${shortAddr(s.address)}`
    : s.subset
      ? `${s.sharedCount} signers all also sign ${shortAddr(s.address)}`
      : `${s.sharedCount} of ${note.selfOwnerCount} signers shared with ${shortAddr(s.address)}`;
  return <div className="ps-principal-overlap">{shareText}</div>;
}

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
      <TerminalNote principal={principal} />
      <SignerOverlapNote principal={principal} />
      <SharedDeployerNote principal={principal} />
      <div className="ps-principal-origin">
        {indirect
          ? `via ${principal.path.slice(0, -1).map((p) => shortAddr(p.address)).join(" → ")}`
          : principal.origins.join(" · ")}
      </div>
    </div>
  );
}

// Verbose witness facts for the selected function (SCORING plan §7.3): where the
// funds go + how much, freeze scope/expiry, mint backing, reach upper bound. Each
// row derives from a present, at-the-bar witness field — nothing renders from
// absence, so the block is silent when there is no witnessed fact to show.
function WitnessFacts({ fn }) {
  const facts = claimWitnessFacts(fn);
  if (!facts.length) return null;
  return (
    <div className="ps-inspector-block">
      <div className="ps-inspector-label">Witnessed facts</div>
      <dl className="ps-witness-facts">
        {facts.map((f) => (
          <div key={f.label} className="ps-witness-fact">
            <dt>{f.label}</dt>
            <dd>{f.value}</dd>
          </div>
        ))}
      </dl>
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
        {selected.claims.map((claim) => (
          <span key={claim.claim_id} className="ps-badge" style={{ "--badge-accent": "#475569" }}>{claim.claim_id}</span>
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

      <WitnessFacts fn={selected} />

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
