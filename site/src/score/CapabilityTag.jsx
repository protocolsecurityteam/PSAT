import HelpTag from "./HelpTag.jsx";
import { capabilityDefinition } from "./capabilityGlossary.js";

// The capability id verbatim, with a "?" for its plain reading. Ids the
// glossary lacks render bare: no invented definition.
export default function CapabilityTag({ capability }) {
  const definition = capabilityDefinition(capability);
  if (!definition) return <span className="sc-cap">{capability}</span>;
  return (
    <HelpTag
      className="sc-cap sc-cap-help"
      ariaLabel={`What ${capability} means`}
      note={
        <>
          <b>{capability}</b> — {definition}
        </>
      }
    >
      {capability}
    </HelpTag>
  );
}
