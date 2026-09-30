from __future__ import annotations

from urllib.parse import urlparse


def github_blob_to_raw(url: str) -> str:
    """Convert a GitHub ``/blob/`` URL to raw.githubusercontent.com; anything else passes through."""
    try:
        parsed = urlparse(url)
    except Exception:
        return url

    if parsed.netloc.lower() != "github.com":
        return url

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 5 or parts[2] != "blob":
        return url

    owner, repo, ref = parts[0], parts[1], parts[3]
    path = "/".join(parts[4:])
    if not owner or not repo or not ref or not path:
        return url

    return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
