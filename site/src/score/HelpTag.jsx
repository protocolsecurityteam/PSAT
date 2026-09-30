import { useEffect, useRef, useState } from "react";

// Shared "?" mechanics; callers supply the text, and a caller with nothing
// witnessed renders no button.
const POP_WIDTH = 280;

export default function HelpTag({ className, ariaLabel, note, children }) {
  // position:fixed because the truncating lines (.sc-who) are overflow:hidden.
  // Fixed goes stale on scroll, so scrolling closes it.
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
    // Capture phase: inner-container scrolls don't bubble.
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
