Canonical Safe v1.4.1 sources and the dependencies needed to compile Safe and
SafeProxy, vendored from `safe-global/safe-smart-account` at commit
`bf943f80fec5ac647159d26161446ac5d716a294`.

`manifest.json` pins the original file hashes. `LICENSE` is the upstream LGPL-3.0
license. The regression compiles these files offline with solc 0.8.25, which CI
already provisions. Its broken twin removes only the call to `checkSignatures`
inside `execTransaction` from a temporary copy; the vendored source stays intact.

The L1/L2 version regressions also compile the pinned sources with the original
Solidity 0.7.6 compiler. Source names and versions are fixture inputs only.
