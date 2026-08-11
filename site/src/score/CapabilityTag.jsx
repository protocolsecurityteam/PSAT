import HelpTag from "./HelpTag.jsx";
import { capabilityDefinition } from "./capabilityGlossary.js";

// A deduction row's capability id, kept verbatim (the id IS the claim's name)
// with a "?" that opens its plain-language reading. An id the glossary does
// not carry renders as the bare id — no button, no invented definition.
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
