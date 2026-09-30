import { flowTypeWord, relationWord, shortAddr } from "../format.js";

// "Reached from {host} via:" for a score-page click-through to a contract only
// reached through the control graph; without it the card is a non-sequitur.
//
// Hops come from the payload's control edges and name only what was witnessed
// (flow type, plus relation/role label where present). A route the graph
// doesn't carry says so.
export function ReachPath({ reachPath }) {
  if (!reachPath) return null;
  const { hostName, hostNames, hops } = reachPath;

  if (!hops) {
    const from = (hostNames || []).join(" / ");
    return (
      <section className="ps-reach">
        <div className="ps-reach-hdr">
          Reached from <b>{from || "the deduction's host"}</b> via:
        </div>
        <div className="ps-reach-nd">path not carried by this graph</div>
      </section>
    );
  }

  return (
    <section className="ps-reach">
      <div className="ps-reach-hdr">
        Reached from <b>{hostName}</b> via:
      </div>
      <ol className="ps-reach-hops">
        {hops.map((hop, i) => (
          <li key={`${hop.from}-${hop.to}`} className="ps-reach-hop">
            <span className="ps-reach-step">{i + 1}</span>
            <span className="ps-reach-body">
              <span className="ps-reach-pair">
                <span title={hop.from}>
                  {hop.fromName || shortAddr(hop.from)}
                </span>
                <span className="ps-reach-arrow">→</span>
                <span title={hop.to}>
                  {hop.toName || shortAddr(hop.to)}
                </span>
              </span>
              <span className="ps-reach-kind">
                {flowTypeWord(hop.type)}
                {hop.claims.map((claim) => (
                  <span key={`${claim.relation}:${claim.label || ""}`} className="ps-reach-claim">
                    {" · "}
                    {relationWord(claim.relation)}
                    {claim.label ? <b> {claim.label}</b> : null}
                  </span>
                ))}
              </span>
            </span>
          </li>
        ))}
      </ol>
    </section>
  );
}
