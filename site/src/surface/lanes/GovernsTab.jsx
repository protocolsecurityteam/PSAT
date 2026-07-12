import { fnChipClass, shortAddr } from "../format.js";

// "Authority OUT" for a contract card: every function on OTHER contracts this
// entity can call, one row per governed contract. Rows mirror the Controllers
// accordion's open-row detail — contract name (click = navigate, same path the
// Control tab's caller buttons use), function chips, and capability tags when
// the entity also has a server-side principal entry (controls_detail carries
// the high-level capability vocabulary the client-side inversion lacks).
export function GovernsTab({ rows, capabilitiesByContract, onNavigate }) {
  if (!rows.length) return <div className="ps-lane-empty">Governs nothing</div>;
  return (
    <div className="ps-governs">
      {rows.map((row) => {
        const caps = capabilitiesByContract.get(row.contractAddress) || [];
        return (
          <div className="ps-governs-row" key={row.contractAddress}>
            <button
              type="button"
              className="ps-governs-name"
              title={`Go to ${row.contractName || shortAddr(row.contractAddress)}`}
              onClick={() =>
                onNavigate && onNavigate({ type: "contract", address: row.contractAddress })
              }
            >
              {row.contractName || shortAddr(row.contractAddress)}
            </button>
            {caps.length > 0 && (
              <div className="ps-governs-caps">
                {caps.map((cap) => (
                  <span className="ps-governs-cap" key={cap}>{cap}</span>
                ))}
              </div>
            )}
            <div className="ps-ctrl-fns">
              {row.functions.map((fn) => (
                <span className={`ps-ctrl-fnchip ${fnChipClass(fn)}`} key={fn}>{fn}</span>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
