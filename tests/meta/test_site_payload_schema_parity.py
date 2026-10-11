"""The site treats a prepared company payload whose schema it doesn't list as still preparing, so a server bump of
``PAYLOAD_SCHEMA`` without the matching site bump leaves the page retrying until it errors.
"""

from __future__ import annotations

import re
from pathlib import Path

from services.company_pages import PAYLOAD_SCHEMA

_CLIENT = Path(__file__).resolve().parents[2] / "site" / "src" / "api" / "client.js"


def test_site_supported_payload_schema_matches_server():
    match = re.search(r"export const SUPPORTED_PAYLOAD_SCHEMA = \{([^}]*)\};", _CLIENT.read_text(encoding="utf-8"))
    assert match, "SUPPORTED_PAYLOAD_SCHEMA not found in site/src/api/client.js"
    site = {key: int(value) for key, value in re.findall(r"(\w+):\s*(\d+)", match.group(1))}
    assert site == PAYLOAD_SCHEMA, (
        f"site/src/api/client.js SUPPORTED_PAYLOAD_SCHEMA {site} != services/company_pages.py PAYLOAD_SCHEMA "
        f"{PAYLOAD_SCHEMA}; bump both together."
    )
