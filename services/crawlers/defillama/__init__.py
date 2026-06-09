"""DefiLlama adapter crawler — extracts contract addresses from DefiLlama-Adapters repo."""

from services.crawlers.defillama.extract import extract_addresses_from_file, extract_protocol
from services.crawlers.defillama.scan import scan_all_protocols, scan_protocol

__all__ = [
    "extract_protocol",
    "extract_addresses_from_file",
    "scan_protocol",
    "scan_all_protocols",
]
