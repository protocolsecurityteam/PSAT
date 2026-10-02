class _DeterministicBlockHash:
    def block_hash(self, block_number: int) -> bytes:
        return block_number.to_bytes(32, "big")
