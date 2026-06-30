import React from "react";

import hourglassIcon from "../assets/hourglass-empty.svg";
import questionMarkIcon from "../assets/question-mark.svg";
import vaultIcon from "../assets/vault.svg";

export function GuardGlyph({ kind, accent, title }) {
  const common = {
    width: 16,
    height: 16,
    viewBox: "0 0 16 16",
    fill: "none",
    xmlns: "http://www.w3.org/2000/svg",
    "aria-hidden": "true",
  };

  if (kind === "unknown") {
    return (
      <span
        className="ps-guard-svg-mask"
        style={{ "--guard-icon-accent": accent, maskImage: `url(${questionMarkIcon})` }}
        title={title}
      />
    );
  }

  if (kind === "safe") {
    return (
      <span
        className="ps-guard-svg-mask"
        style={{ "--guard-icon-accent": accent, maskImage: `url(${vaultIcon})` }}
        title={title}
      />
    );
  }

  if (kind === "timelock") {
    return (
      <span
        className="ps-guard-svg-mask"
        style={{ "--guard-icon-accent": accent, maskImage: `url(${hourglassIcon})` }}
        title={title}
      />
    );
  }

  if (kind === "eoa") {
    return (
      <svg {...common}>
        <circle cx="8" cy="5.3" r="2.2" stroke={accent} strokeWidth="1.4" fill={`${accent}18`} />
        <path d="M4.2 12.4C4.8 10.5 6.2 9.5 8 9.5C9.8 9.5 11.2 10.5 11.8 12.4" stroke={accent} strokeWidth="1.4" strokeLinecap="round" />
      </svg>
    );
  }

  if (kind === "contract" || kind === "proxy_admin") {
    return (
      <svg {...common}>
        <rect x="2.6" y="3" width="10.8" height="10" rx="1.8" stroke={accent} strokeWidth="1.4" fill={`${accent}16`} />
        <path d="M5.3 5.4H10.7M5.3 8H10.7M5.3 10.6H8.8" stroke={accent} strokeWidth="1.4" strokeLinecap="round" />
      </svg>
    );
  }

  if (kind === "address") {
    return (
      <svg {...common}>
        <rect x="2.4" y="4.2" width="11.2" height="7.6" rx="1.8" stroke={accent} strokeWidth="1.4" fill={`${accent}14`} />
        <circle cx="5.2" cy="8" r="1.1" fill={accent} opacity="0.85" />
        <path d="M7.6 6.4H11M7.6 9.6H10.2" stroke={accent} strokeWidth="1.3" strokeLinecap="round" />
      </svg>
    );
  }

  if (kind === "open") {
    return (
      <svg {...common}>
        <rect x="3.2" y="7.2" width="9.6" height="5.8" rx="1.6" stroke={accent} strokeWidth="1.4" fill={`${accent}16`} />
        <path d="M5.4 7.2V5.8C5.4 4.2 6.7 3 8.2 3C9.2 3 10 3.5 10.5 4.2" stroke={accent} strokeWidth="1.4" strokeLinecap="round" />
      </svg>
    );
  }

  if (kind === "resolved_empty") {
    return (
      <svg {...common}>
        <circle cx="8" cy="8" r="5.4" stroke={accent} strokeWidth="1.4" fill={`${accent}10`} />
        <path d="M4.8 11.2L11.2 4.8" stroke={accent} strokeWidth="1.5" strokeLinecap="round" />
      </svg>
    );
  }

  if (kind === "one_shot_live") {
    // Live, unconsumed one-shot — an alert glyph, not the generic open padlock.
    return (
      <svg {...common}>
        <path d="M8 2.4L14.6 13.2H1.4L8 2.4Z" stroke={accent} strokeWidth="1.4" strokeLinejoin="round" fill={`${accent}1c`} />
        <path d="M8 6.2V9.6" stroke={accent} strokeWidth="1.5" strokeLinecap="round" />
        <circle cx="8" cy="11.4" r="0.85" fill={accent} />
      </svg>
    );
  }

  return (
    <span
      className="ps-guard-svg-mask"
      style={{ "--guard-icon-accent": accent, maskImage: `url(${questionMarkIcon})` }}
      title={title}
    />
  );
}

export default GuardGlyph;
