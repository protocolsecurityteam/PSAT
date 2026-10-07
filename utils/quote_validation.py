"""Conservative bounds for a single, uncorroborated provider quote.

An outlier stays unpriced; these limits never clamp a price or assert that a token
is worthless. Raising them requires independent quote evidence/configuration.
"""

import math
import os


def quote_refusal(price: object, value: object) -> str | None:
    for name, raw, ceiling in (
        ("price", price, float(os.getenv("PSAT_MAX_UNCORROBORATED_UNIT_PRICE_USD", "1000000"))),
        ("value", value, float(os.getenv("PSAT_MAX_UNCORROBORATED_HOLDING_USD", "1000000000000000"))),
    ):
        if not math.isfinite(ceiling) or ceiling <= 0:
            raise ValueError(f"Invalid uncorroborated quote ceiling for {name}")
        if raw is None:
            continue
        try:
            number = float(str(raw))
        except (TypeError, ValueError):
            return f"invalid_{name}"
        if not math.isfinite(number) or number < 0:
            return f"invalid_{name}"
        if number > ceiling:
            return f"uncorroborated_{name}_outlier"
    return None
