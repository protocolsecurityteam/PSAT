"""
Prepares the JavaScript provider script with wallet-specific config
injected, and handles signing requests from the page context.
"""

from pathlib import Path

from services.crawlers.dapp.wallet import HoneypotWallet
from utils.rpc import require_supported_chain_id

_JS_TEMPLATE_PATH = Path(__file__).parent / "injected_provider.js"


def build_provider_script(
    wallet: HoneypotWallet,
    chain_id: int,
    eth_balance_wei: str = "0x3635C9ADC5DEA00000",  # 1000 ETH
    token_balance: str = "0x84595161401484A000000",  # 10M tokens (18 dec)
) -> str:
    """Build the JS injection script with the wallet's config baked in."""
    chain_id = require_supported_chain_id(chain_id=chain_id, context="DApp provider injection")
    template = _JS_TEMPLATE_PATH.read_text()

    chain_id_hex = hex(chain_id)

    script = template.replace("__CHAIN_ID__", chain_id_hex)
    script = script.replace("__ACCOUNT_ADDRESS__", wallet.address.lower())
    script = script.replace("__ETH_BALANCE__", eth_balance_wei)
    script = script.replace("__TOKEN_BALANCE__", token_balance)

    return script
