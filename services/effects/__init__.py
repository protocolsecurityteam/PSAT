"""Effects resolution: behavioral-hash identity, selection/ordering, and the
fork/eth_call simulation harness. Feature-flagged via PSAT_EFFECTS_STAGE.
``claims_bridge`` bridges *proven* verdicts into registry claims so the frontend
renders them as observable labels; the score does not consume effect verdicts,
and how it should consume them is unspecified."""
