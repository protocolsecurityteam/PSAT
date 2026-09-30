import React, { useEffect, useState } from "react";

function initials(name) {
  const s = String(name || "").trim();
  if (!s) return "?";
  const parts = s.split(/[\s\-_.]+/).filter(Boolean);
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

function palette(name) {
  let h = 0;
  const s = String(name || "");
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  const hue = h % 360;
  return `hsl(${hue} 65% 22%)`;
}

function slugify(name) {
  return String(name || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

// CoinGecko's /search doesn't always return the protocol token first
// ("etherfi"); these override common cases.
const COINGECKO_SLUG_OVERRIDES = {
  etherfi: "ether-fi",
  "ether-fi": "ether-fi",
  weeth: "wrapped-eeth",
  eigenlayer: "eigenlayer",
  lido: "lido-dao",
  aave: "aave",
  compound: "compound-governance-token",
  makerdao: "maker",
  maker: "maker",
  uniswap: "uniswap",
  curve: "curve-dao-token",
  "curve-dao": "curve-dao-token",
  frax: "frax",
  rocketpool: "rocket-pool",
  "rocket-pool": "rocket-pool",
  synthetix: "havven",
  gmx: "gmx",
  pendle: "pendle",
  morpho: "morpho",
  balancer: "balancer",
  yearn: "yearn-finance",
  convex: "convex-finance",
};

const MEMORY_CACHE = new Map(); // slug → url | null | Promise<url | null>
const STORAGE_KEY = "psat-coingecko-logos-v1";

function readStorageCache() {
  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function writeStorageCache(entry) {
  try {
    const current = readStorageCache();
    Object.assign(current, entry);
    window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(current));
  } catch {
    // sessionStorage disabled; the in-memory cache still works
  }
}

async function fetchCoinGeckoLogo(slug) {
  if (!slug) return null;
  const override = COINGECKO_SLUG_OVERRIDES[slug];
  if (override) {
    try {
      const res = await fetch(`https://api.coingecko.com/api/v3/coins/${override}?localization=false&tickers=false&market_data=false&community_data=false&developer_data=false&sparkline=false`);
      if (res.ok) {
        const data = await res.json();
        return data?.image?.large || data?.image?.small || data?.image?.thumb || null;
      }
    } catch {
      /* fall through to search */
    }
  }
  try {
    const res = await fetch(`https://api.coingecko.com/api/v3/search?query=${encodeURIComponent(slug.replace(/-/g, " "))}`);
    if (!res.ok) return null;
    const data = await res.json();
    const coin = data?.coins?.[0];
    return coin?.large || coin?.thumb || null;
  } catch {
    return null;
  }
}

function resolveCoinGeckoLogo(slug) {
  if (MEMORY_CACHE.has(slug)) {
    const v = MEMORY_CACHE.get(slug);
    if (v && typeof v.then === "function") return v;
    return Promise.resolve(v);
  }
  const storage = readStorageCache();
  if (Object.prototype.hasOwnProperty.call(storage, slug)) {
    MEMORY_CACHE.set(slug, storage[slug]);
    return Promise.resolve(storage[slug]);
  }
  const p = fetchCoinGeckoLogo(slug).then((url) => {
    MEMORY_CACHE.set(slug, url);
    writeStorageCache({ [slug]: url });
    return url;
  });
  MEMORY_CACHE.set(slug, p);
  return p;
}

export default function ProtocolLogo({ name, size = "normal" }) {
  const slug = slugify(name);
  const localSrc = slug ? `/logos/${slug}.svg` : null;
  const [localFailed, setLocalFailed] = useState(false);
  const [remoteSrc, setRemoteSrc] = useState(null);
  const [remoteFailed, setRemoteFailed] = useState(false);
  const bg = palette(name);

  useEffect(() => {
    if (!slug || !localFailed || remoteSrc) return undefined;
    let cancelled = false;
    resolveCoinGeckoLogo(slug).then((url) => {
      if (!cancelled && url) setRemoteSrc(url);
    });
    return () => { cancelled = true; };
  }, [slug, localFailed, remoteSrc]);

  const showLocal = !!localSrc && !localFailed;
  const showRemote = !showLocal && !!remoteSrc && !remoteFailed;
  const showInitials = !showLocal && !showRemote;

  return (
    <span
      className={`protocol-logo${size === "large" ? " large" : ""}${size === "xlarge" ? " xlarge" : ""}`}
      style={showInitials ? { background: bg } : undefined}
    >
      {showLocal && (
        <img src={localSrc} alt="" onError={() => setLocalFailed(true)} />
      )}
      {showRemote && (
        <img src={remoteSrc} alt="" onError={() => setRemoteFailed(true)} />
      )}
      {showInitials && initials(name)}
    </span>
  );
}
