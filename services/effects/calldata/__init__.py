"""Per-class calldata + entry-point synthesis, one synthesizer per effect class.

Turns the STATIC facts a candidate already carries — ABI param types, sinks,
state writes, value-flow taint, predicate trees, resolved principals — into the
concrete probe inputs each recipe needs. Pure over the DB/artifact reads it does:
no RPC, no fork, no wire of its own, so the whole surface is testable against
recorded fixtures.

Every synthesizer returns ``None`` when the facts are too thin to build an
honest probe. That is the load-bearing property: a recipe fed guessed calldata
would mint a witness for a call the contract never actually performs, and the
fail-closed discipline only holds if the inputs are real. Thin facts ⇒ no plan
⇒ the class stays ``unknown``.

A class emitting NO plans across a whole protocol is a normal outcome, not a
symptom. Measured on etherfi (2026-07-21): value-out and supply produced zero
plans over all 265 candidates, because every value-moving function there already
carries a ``flow.out`` claim and the selection cascade selects BLANK-claim
functions only. The fact plumbing is fine — those functions do carry
``direction: "out"`` in the effects artifact; they are simply already explained.
That is the cascade working as designed: as the claims matchers grow, the
simulation workload shrinks.

Decision points are deliberately concentrated and named so the live-validation
loop can adjust them without re-deriving the module:

* :data:`ARG_AMOUNT` — the numeric filler for value-carrying params (1 wei, the
  amount that slips under real rate limiters; measured 2026-07-21).
* :data:`SENTINEL_ADDRESS` — the attacker identity substituted at a taint index.
* :func:`_arg_values` — the address/uint/other substitution policy.
* :data:`NEUTRAL_CALLER` — the identity a blast-radius probe uses when the entry
  point has no resolved principal.
* :func:`read_max_pause_duration` — the bound is READ off the latch's own guard
  leaf, never hardcoded and never scraped from source text.
"""

from __future__ import annotations

from services.resolution.differential_probe import _parse_arg_types

from .authority import (
    _authority_gate_target,
    _normal_state_pairs,
    synthesize_authority,
)
from .encoding import (
    _ARRAY_TYPE,
    _INTEGER_TYPE,
    _RESOLVED_ADDRESS,
    ProbeArgs,
    _arg_values,
    _array_shape,
    _element_type,
    _scalar_arg_value,
    encode_calldata,
)
from .executor import (
    _ERC20_TRANSFER_SELECTOR,
    _EXEC_ARBITRARY_CLAIM,
    _LOW_LEVEL_CALL_KIND,
    ExecutorCall,
    _erc20_transfer_calldata,
    _executor_slot_shapes_agree,
    _forwards_param_destination,
    _named_executor_slots,
    _unique_executor_slots,
    executor_call,
)
from .facts import (
    _FACTS_CACHE,
    ContractFacts,
    FunctionFacts,
    _legacy_value_flow_map,
    _load_contract_facts_uncached,
    facts_for_name,
    load_contract_facts,
    resolve_function,
)
from .flows import (
    _ADMIN_TARGET_KIND,
    _FIXED_TARGET_KINDS,
    _NATIVE_OUT_KINDS,
    _OUT_DIRECTIONS,
    _flow_directions,
    _lattice_taint_index,
    _selector_of,
    _taint_index,
    _target_member_kinds,
    function_payable,
    has_native_payout,
    static_destination_shape,
)
from .pause_window import (
    _CLOCK_KINDS,
    _CONSTANT_IS_UPPER_BOUND,
    _OPAQUE_OPERAND_SOURCES,
    _OPERAND_ABSORPTION_RECORDED,
    _SECONDS_CLOCK_KINDS,
    _absorption_recorded,
    _claim_latch_pairs,
    _compared_operands,
    _duration_from_trees,
    _entry_point_for,
    _latch_pairs,
    _parse_int,
    _pauser_identity_probes,
    _principals_by_selector,
    _state_changing_functions,
    _window_ceiling_constant,
    read_max_pause_duration,
)
from .plans import (
    _AUTHORITY_ROLES,
    _MAX_PLAUSIBLE_DURATION_S,
    ARG_AMOUNT,
    ARG_IDENTIFIER,
    FIXTURE_BALANCE_WEI,
    NEUTRAL_CALLER,
    ROLE_AMOUNT,
    ROLE_IDENTIFIER,
    ROLE_RECIPIENT,
    ROLE_TOKEN,
    SEED_AMOUNT,
    SENTINEL_ADDRESS,
    AuthorityPlanInputs,
    CandidatePlanInputs,
    PausePlanInputs,
    SupplyPlanInputs,
    TimelockPlanInputs,
    ValueOutPlanInputs,
)
from .roles import (
    _AMOUNT_WORDS,
    _IDENTIFIER_WORDS,
    _NAME_SPLIT,
    _NON_QUANTITY_WORDS,
    _RECIPIENT_WORDS,
    _TOKEN_METHOD_WORDS,
    _TOKEN_WORDS,
    _declared_param_names,
    _lattice_amount_indexes,
    _name_words,
    _token_method_targets,
    address_param_roles,
    integer_param_roles,
    substitute_address_arg,
)
from .seeding import (
    _ERC4626_ASSET_GETTER,
    _IDENTIFIER,
    _INPUT_DIRECTIONS,
    _PULL_SELECTORS,
    _TOKEN_READ_SELECTORS,
    SELF_TOKEN_HINT,
    _mapping_entry_slot,
    _seed_fixture_for_role,
    _token_seed_fixtures,
    _word_hex,
    input_token_hints,
    seeded_calldata,
    synthesize_pause,
)
from .synthesize import (
    synthesize,
)
from .synthesize_value import (
    _ERC20_BALANCE_OF_SIGNATURE,
    _MIN_DELAY_SIGNATURE,
    _SUPPLY_DIRECTIONS,
    _SUPPLY_LATTICE_DIRECTIONS,
    _dual_role_principal,
    _probe_salt,
    _ProbeInputs,
    _schedule_sibling,
    _seeded_probe_calldata,
    _sentinel_param_name,
    _token_arg_candidates,
    _value_probe_inputs,
    synthesize_supply,
    synthesize_timelock,
    synthesize_value_out,
)
from .trees import (
    _all_leaves,
    _authority_roles,
    _gate_ref,
    _mandatory_leaves,
    _mandatory_state_pairs,
    _mandatory_state_vars,
    _operands,
    _param_index_by_name,
    guarded_functions,
)

__all__ = [
    "_parse_arg_types",
    "ARG_AMOUNT",
    "ARG_IDENTIFIER",
    "AuthorityPlanInputs",
    "CandidatePlanInputs",
    "ContractFacts",
    "ExecutorCall",
    "FIXTURE_BALANCE_WEI",
    "FunctionFacts",
    "NEUTRAL_CALLER",
    "PausePlanInputs",
    "ProbeArgs",
    "ROLE_AMOUNT",
    "ROLE_IDENTIFIER",
    "ROLE_RECIPIENT",
    "ROLE_TOKEN",
    "SEED_AMOUNT",
    "SELF_TOKEN_HINT",
    "SENTINEL_ADDRESS",
    "SupplyPlanInputs",
    "TimelockPlanInputs",
    "ValueOutPlanInputs",
    "_ADMIN_TARGET_KIND",
    "_AMOUNT_WORDS",
    "_ARRAY_TYPE",
    "_AUTHORITY_ROLES",
    "_CLOCK_KINDS",
    "_CONSTANT_IS_UPPER_BOUND",
    "_ERC20_BALANCE_OF_SIGNATURE",
    "_ERC20_TRANSFER_SELECTOR",
    "_ERC4626_ASSET_GETTER",
    "_EXEC_ARBITRARY_CLAIM",
    "_FACTS_CACHE",
    "_FIXED_TARGET_KINDS",
    "_IDENTIFIER",
    "_IDENTIFIER_WORDS",
    "_INPUT_DIRECTIONS",
    "_INTEGER_TYPE",
    "_LOW_LEVEL_CALL_KIND",
    "_MAX_PLAUSIBLE_DURATION_S",
    "_MIN_DELAY_SIGNATURE",
    "_NAME_SPLIT",
    "_NATIVE_OUT_KINDS",
    "_NON_QUANTITY_WORDS",
    "_OPAQUE_OPERAND_SOURCES",
    "_OPERAND_ABSORPTION_RECORDED",
    "_OUT_DIRECTIONS",
    "_PULL_SELECTORS",
    "_ProbeInputs",
    "_RECIPIENT_WORDS",
    "_RESOLVED_ADDRESS",
    "_SECONDS_CLOCK_KINDS",
    "_SUPPLY_DIRECTIONS",
    "_SUPPLY_LATTICE_DIRECTIONS",
    "_TOKEN_METHOD_WORDS",
    "_TOKEN_READ_SELECTORS",
    "_TOKEN_WORDS",
    "_absorption_recorded",
    "_all_leaves",
    "_arg_values",
    "_array_shape",
    "_authority_gate_target",
    "_authority_roles",
    "_claim_latch_pairs",
    "_compared_operands",
    "_declared_param_names",
    "_dual_role_principal",
    "_duration_from_trees",
    "_element_type",
    "_entry_point_for",
    "_erc20_transfer_calldata",
    "_executor_slot_shapes_agree",
    "_flow_directions",
    "_forwards_param_destination",
    "_gate_ref",
    "_latch_pairs",
    "_lattice_amount_indexes",
    "_lattice_taint_index",
    "_legacy_value_flow_map",
    "_load_contract_facts_uncached",
    "_mandatory_leaves",
    "_mandatory_state_pairs",
    "_mandatory_state_vars",
    "_mapping_entry_slot",
    "_name_words",
    "_named_executor_slots",
    "_normal_state_pairs",
    "_operands",
    "_param_index_by_name",
    "_parse_int",
    "_pauser_identity_probes",
    "_principals_by_selector",
    "_probe_salt",
    "_scalar_arg_value",
    "_schedule_sibling",
    "_seed_fixture_for_role",
    "_seeded_probe_calldata",
    "_selector_of",
    "_sentinel_param_name",
    "_state_changing_functions",
    "_taint_index",
    "_target_member_kinds",
    "_token_arg_candidates",
    "_token_method_targets",
    "_token_seed_fixtures",
    "_unique_executor_slots",
    "_value_probe_inputs",
    "_window_ceiling_constant",
    "_word_hex",
    "address_param_roles",
    "encode_calldata",
    "executor_call",
    "facts_for_name",
    "function_payable",
    "guarded_functions",
    "has_native_payout",
    "input_token_hints",
    "integer_param_roles",
    "load_contract_facts",
    "read_max_pause_duration",
    "resolve_function",
    "seeded_calldata",
    "static_destination_shape",
    "substitute_address_arg",
    "synthesize",
    "synthesize_authority",
    "synthesize_pause",
    "synthesize_supply",
    "synthesize_timelock",
    "synthesize_value_out",
]
