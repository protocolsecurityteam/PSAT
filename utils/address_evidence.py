"""An empty code response alone does not establish an ordinary signing account."""


def special_address_reason(address: str | None) -> str | None:
    if not isinstance(address, str) or len(address) != 42 or not address.startswith("0x"):
        return None
    try:
        value = int(address, 16)
    except ValueError:
        return None
    if value == 0:
        return "zero_address"
    if 1 <= value <= 9:
        return "reserved_evm_precompile_address"
    if value == 0xDEAD:
        return "burn_address_control_not_proven"
    return None
