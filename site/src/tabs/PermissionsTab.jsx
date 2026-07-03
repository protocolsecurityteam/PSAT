import { functionEffectLine, prettyFunctionName, shortenAddress } from "../graph.js";

export default function PermissionsTab({ detail }) {
  const payload = detail?.effective_permissions;
  if (!payload?.functions?.length) {
    return <p className="empty">No permission artifact available.</p>;
  }
  return (
    <div className="card-grid">
      {payload.functions.map((entry) => {
        const principals = [
          ...(entry.direct_owner?.address ? [entry.direct_owner] : []),
          ...(entry.authority_roles || []).flatMap((role) => role.principals || []),
          ...(entry.controllers || []).flatMap((controller) => controller.principals || []),
        ];
        return (
          <article className="card" key={entry.selector}>
            <div className="card-header-row">
              <h3>{prettyFunctionName(entry.function)}</h3>
              <span className="chip alt">{functionEffectLine(entry) || "permissioned"}</span>
            </div>
            <p className="muted">{entry.action_summary}</p>
            <div className="kv-grid compact">
              <div className="kv-row">
                <span className="key">Authority public</span>
                <span>{entry.authority_public ? "Yes" : "No"}</span>
              </div>
              <div className="kv-row">
                <span className="key">Direct owner</span>
                <span>{entry.direct_owner?.address ? shortenAddress(entry.direct_owner.address) : "None"}</span>
              </div>
              <div className="kv-row">
                <span className="key">Effect targets</span>
                <span>{(entry.effect_targets || []).join(", ") || "None"}</span>
              </div>
            </div>
            <div className="subsection">
              <div className="subsection-title">Current principals</div>
              <div className="chips">
                {principals.length
                  ? principals.map((principal) => (
                      <span className="chip" key={`${entry.selector}-${principal.address}`}>
                        {shortenAddress(principal.address)}
                      </span>
                    ))
                  : <span className="chip warn">No principals resolved in artifact</span>}
              </div>
            </div>
          </article>
        );
      })}
    </div>
  );
}
