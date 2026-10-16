import { useState } from "react";

// Falls back to the initial when the picture can't load (CSP, expired URL, rate limit), not just when it's absent.
export default function Avatar({ className, url, name }) {
  const [failedUrl, setFailedUrl] = useState(null);
  if (url && url !== failedUrl) {
    return <img className={className} src={url} alt="" referrerPolicy="no-referrer" onError={() => setFailedUrl(url)} />;
  }
  return <span className={`${className} ${className}-initial`} aria-hidden="true">{name[0].toUpperCase()}</span>;
}
