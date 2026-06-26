import React, { useEffect, useRef } from "react";
import FractalMesh from "./FractalMesh.jsx";

const CYCLE_WORDS = ["exploit", "backdoor", "privilege", "trap", "upgrade"];
const SCRAMBLE_CHARS = "abcdefghijklmnopqrstuvwxyz";
const HOLD_MS = 2400;
const SCRAMBLE_MS = 420;

function useCyclingWord(words) {
  const ref = useRef(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    let wordIdx = 0;
    let raf = 0;
    let cycleStart = performance.now();
    let inScramble = false;
    let scrambleStart = 0;
    let nextIdx = 1;
    el.textContent = words[0];

    function tick(now) {
      const elapsed = now - cycleStart;
      if (!inScramble && elapsed > HOLD_MS) {
        inScramble = true;
        scrambleStart = now;
        nextIdx = (wordIdx + 1) % words.length;
      }
      if (inScramble) {
        const sElapsed = now - scrambleStart;
        if (sElapsed >= SCRAMBLE_MS) {
          inScramble = false;
          wordIdx = nextIdx;
          el.textContent = words[wordIdx];
          cycleStart = now;
        } else {
          const target = words[nextIdx];
          const len = Math.max(words[wordIdx].length, target.length);
          const progress = sElapsed / SCRAMBLE_MS;
          let out = "";
          for (let i = 0; i < len; i++) {
            if (i / len < progress) {
              out += target[i] || "";
            } else {
              out += SCRAMBLE_CHARS[Math.floor(Math.random() * SCRAMBLE_CHARS.length)];
            }
          }
          el.textContent = out;
        }
      }
      raf = requestAnimationFrame(tick);
    }
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [words]);
  return ref;
}

export default function ProductHero() {
  const wordRef = useCyclingWord(CYCLE_WORDS);
  return (
    <section className="ph" aria-labelledby="ph-title">
      <FractalMesh />
      <div className="ph-veil" aria-hidden="true" />

      <div className="ph-content">
        <header className="ph-meta">
          <span className="ph-meta-dot" />
          <span className="ph-meta-rule" />
          <span className="ph-meta-faint">v0.1</span>
        </header>

        <h1 id="ph-title" className="ph-title">
          Detect every<br />
          <span ref={wordRef} className="ph-title-em ph-title-em-dim">exploit</span><br />
          before they do.
        </h1>

        <p className="ph-sub">
          PSAT walks every contract a protocol touches —
          exposing owner traps, upgrade backdoors, privileged paths, and{' '}
          <em>the exploits a predator would hit first.</em>
        </p>
      </div>
    </section>
  );
}
