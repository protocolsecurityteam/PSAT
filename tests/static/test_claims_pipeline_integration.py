"""A ``contract_deployment`` claim survives the real stack onto ``EffectiveFunction.claims`` and out through the API
payloads.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("slither")


pytestmark = pytest.mark.compile

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "contracts"
