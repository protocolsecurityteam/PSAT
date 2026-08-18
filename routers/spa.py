"""SPA static-asset mount and HTML catch-all.

Must be the LAST router registered on the app — its ``/{full_path:path}``
catch-all will swallow any route registered after it, including ``/api/*``.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.types import Scope

ROOT_DIR = Path(__file__).resolve().parents[1]
SITE_DIR = ROOT_DIR / "site"
SITE_DIST_DIR = SITE_DIR / "dist"
SITE_ASSETS_DIR = SITE_DIST_DIR / "assets"


class _ImmutableStaticFiles(StaticFiles):
    """StaticFiles that stamps a 1-year immutable Cache-Control on every
    response. Vite emits hashed filenames (``index-<hash>.js``) so the URL
    changes whenever content changes — caching forever is correct, and lets
    repeat visitors skip the ~2MB bundle download entirely.
    """

    async def get_response(self, path: str, scope: Scope):
        response = await super().get_response(path, scope)
        if response.status_code == 200:
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return response


def _site_index_response():
    # The HTML embeds hash-stamped asset URLs (`/assets/index-<hash>.js`)
    # that change on every build, so it must NOT be cached — otherwise a
    # post-deploy reload would keep pointing at old, evicted bundles.
    headers = {"Cache-Control": "no-cache, must-revalidate"}
    dist_index = SITE_DIST_DIR / "index.html"
    if dist_index.exists():
        return FileResponse(dist_index, headers=headers)
    return PlainTextResponse(
        "Frontend build not found. Run `cd site && npm run build` or start the "
        "Vite dev server with `cd site && npm run dev`.",
        status_code=503,
    )


def mount_static_assets(app: FastAPI) -> None:
    """Mount /assets/* before any router is included."""
    if SITE_ASSETS_DIR.exists():
        app.mount("/assets", _ImmutableStaticFiles(directory=SITE_ASSETS_DIR), name="assets")


router = APIRouter()


@router.get("/{full_path:path}")
def spa_fallback(full_path: str):
    if full_path == "api" or full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="Not found")
    return _site_index_response()
