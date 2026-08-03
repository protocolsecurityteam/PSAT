import { shortAddr } from "../format.js";

// "Reached from {host} via:" — the route a score-page click-through took to this
// contract.
//
// A deduction row names a HOST the controller acts on directly and, after the
// arrow, the contracts it only reaches through the control graph. Clicking one
// of those lands here, on a card whose own function lanes say nothing about the
// deduction: the charged action is on the host, and this contract is downstream
// of it. Without the route the card is a non-sequitur.
//
// Every hop is read off the payload's own control edges (the same ones the
// canvas reach chips walk), and each names itself with what was witnessed: the flow
// type always, plus the control-graph relation and role label where a row
// witnessed them. An edge with no witnessed relation shows its type alone —
// never an invented name. A route this graph does not carry is its own state
// and says so.
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
                {hop.type}
                {hop.claims.map((claim) => (
                  <span key={`${claim.relation}:${claim.label || ""}`} className="ps-reach-claim">
                    {" · "}
                    {claim.relation}
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
