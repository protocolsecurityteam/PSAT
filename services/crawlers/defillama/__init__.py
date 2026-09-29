"""DefiLlama adapter crawler — extracts contract addresses from DefiLlama-Adapters repo."""

from services.crawlers.defillama.core_assets import build_address_to_chain_map, load_core_assets
from services.crawlers.defillama.extract import extract_addresses_from_file, extract_protocol
from services.crawlers.defillama.scan import scan_protocol

__all__ = [
    "extract_protocol",
    "extract_addresses_from_file",
    "load_core_assets",
    "build_address_to_chain_map",
    "scan_protocol",
]
