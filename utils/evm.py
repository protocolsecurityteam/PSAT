"""EVM proxy-introspection constants.

A leaf module (imports nothing) so every plane can share one copy: the same
slot spelled in two files is a divergence vector, and these values are
protocol-frozen — a change here is a correctness event, never a refactor.
"""

from __future__ import annotations

# keccak256("eip1967.proxy.implementation") - 1
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
# keccak256("eip1967.proxy.beacon") - 1
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
# keccak256("eip1967.proxy.admin") - 1
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
# keccak256("PROXIABLE") — EIP-1822 UUPS logic slot
EIP1822_LOGIC_SLOT = "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"
# keccak256("org.zeppelinos.proxy.implementation") — pre-1967 OZ proxies
OZ_LEGACY_IMPL_SLOT = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"

# GnosisSafe proxies keep the singleton/masterCopy in raw slot 0.
GNOSIS_MASTERCOPY_SLOT = "0x0"
# GnosisSafeProxy runtime bytecode prefix: PUSH20 <ff..ff>; slot-0 SLOAD wiring.
GNOSIS_SLOT0_PATTERN = "73" + "ff" * 20 + "60005416"
# masterCopy() — GnosisSafe getter (older implementations)
MASTER_COPY_SELECTOR = "0xa619486e"
# implementation() — EIP-897 / custom proxy getter
IMPLEMENTATION_SELECTOR = "0x5c60da1b"
# comptrollerImplementation() — Compound
COMPTROLLER_IMPL_SELECTOR = "0xbb82aa5e"
# target() — Synthetix
TARGET_SELECTOR = "0xd4b83992"
# owner()
OWNER_SELECTOR = "0x8da5cb5b"

# Solmate Authority / OZ AccessManager share this signature; signature alone
# does not identify the standard.
CANCALL_SIGNATURE = "canCall(address,address,bytes4)"
