import { useEffect, useRef, useState } from "react";

// A label with a "?" that opens one note beside it. The mechanics — anchoring,
// dismissal, the roles — live here so every "?" on the score page behaves the
// same way; what each one SAYS is the caller's, and a caller with nothing
// witnessed to say renders no button at all rather than an empty popover.
const POP_WIDTH = 280;

export default function HelpTag({ className, ariaLabel, note, children }) {
  // null = closed; {top, left} = open, anchored where the tag was when
  // clicked. The popover is position:fixed because the truncating lines it
  // sits in (.sc-who) are overflow:hidden — an absolutely-positioned child
  // would be clipped to two slivers. Fixed positioning goes stale on scroll,
  // so any scroll closes it rather than letting it drift off its anchor.
  const [pos, setPos] = useState(null);
  const ref = useRef(null);

  const toggle = () => {
    if (pos) {
      setPos(null);
      return;
    }
    const rect = ref.current?.getBoundingClientRect();
    if (!rect) return;
    setPos({
      top: rect.bottom + 6,
      left: Math.max(8, Math.min(rect.left, window.innerWidth - POP_WIDTH - 12)),
    });
  };

  useEffect(() => {
    if (!pos) return undefined;
    const away = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setPos(null);
    };
    const esc = (e) => {
      if (e.key === "Escape") setPos(null);
    };
    const close = () => setPos(null);
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", esc);
    // Capture-phase: scrolls of inner containers don't bubble.
    window.addEventListener("scroll", close, true);
    return () => {
      document.removeEventListener("mousedown", away);
      document.removeEventListener("keydown", esc);
      window.removeEventListener("scroll", close, true);
    };
  }, [pos]);

  return (
    <span className={className} ref={ref}>
      {children}
      <button
        type="button"
        className="sc-cap-q"
        aria-label={ariaLabel}
        aria-expanded={Boolean(pos)}
        onClick={toggle}
      >
        ?
      </button>
      {pos && (
        <span className="sc-cap-pop" role="note" style={{ top: pos.top, left: pos.left }}>
          {note}
        </span>
      )}
    </span>
  );
}
