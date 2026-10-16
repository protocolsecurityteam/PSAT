Solidity fixture contracts used by the test suite live in this directory.

The fixtures are grouped by analysis theme:
- `pause/`: pause-control scenarios
- `upgrade/`: upgrade-control scenarios
- `calls/`: guarded external-call, delegatecall, and selfdestruct scenarios
- `token/`: fungible token scenarios
- `nft/`: non-fungible token scenarios
- `composed/`: mixed-pattern scenarios
- `tracking/`: controller-writer and event-to-polling tracking scenarios
- `predicates/`: gate conditions under control flow (helper return polarity, conditional reverts)

Each Solidity file starts with a short scenario comment so the purpose of the
fixture is clear when reading test failures.

`index.json` is the canonical fixture index. It maps each Solidity fixture to
its category, primary contract, short description, and the detection patterns it
is meant to exercise.
