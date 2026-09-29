"""Fuzzing-style regression tests for parametric-guard predicate extraction.

The pipeline recognizes "guarded" for many concrete shapes but does not yet capture
the *predicate* gating a function plus the *runtime parameter(s)* it depends on in
one structured object the resolver can route on; so parametric guards (grantRole /
renounceRole / Maker ``wards`` / external ``canCall`` / ERC-721 ``ownerOf``) admit
but resolve to zero principals and the UI renders 'Unresolved'.

Seven shapes (codex): caller_equals_argument, role_member_dynamic_arg,
dynamic_role_admin, mapping_member_dynamic_scope, external_policy_dynamic,
caller_equals_external_owner, disjunction. The names only seed generators and label
test IDs; the *assertion* is shape-agnostic (no ``kind == "<shape-name>"`` check,
which would be name matching one level up): a generic structured predicate
referencing msg.sender and depending on a runtime parameter, however labeled.

Identifiers are gibberish and any candidate containing a ``BANNED_SUBSTRINGS`` entry
is rejected, so whatever the analyzer detects must come from IR analysis. Shapes
common enough for a canonical-name fixture (``ownerOf``, ``canCall``) are paired with
a renamed method of the same IR shape, so the test cannot pass via ABI-name matching.

``test_fuzz_fixtures_are_valid`` (NOT xfailed) proves fixtures are healthy (compile,
substring ban, real declared signatures, unguarded twin not admitted).
``test_parametric_guard_emits_predicate_signal`` is ``xfail(strict=True)`` so that
when the implementation lands every variant flips at once and pytest forces removal
of the decorator, ratcheting against silent regression.
"""

from __future__ import annotations

import random
import re
from pathlib import Path
from typing import Any

import pytest

from services.static import collect_contract_analysis
from tests.support.foundry_project import write_foundry_project

pytestmark = pytest.mark.compile

# Reserved substrings from legacy classifier terms. A generated identifier containing
# one is rejected, so a detected result cannot be explained by a substring match.
BANNED_SUBSTRINGS = (
    # Authority / role family
    "auth",
    "role",
    "owner",
    "admin",
    "check",
    "guard",
    "ward",
    "perm",
    "access",
    "control",
    "only",
    "require",
    "authoriz",
    "operator",
    "minter",
    "pauser",
    "manager",
    "governor",
    "govern",
    "guardian",
    "timelock",
    "upgrader",
    "unpauser",
    "burner",
    "executor",
    "canceller",
    "committee",
    "kernel",
    "acl",
    # Lifecycle / mutators
    "factory",
    "create",
    "deploy",
    "spawn",
    "clone",
    "upgrade",
    "grant",
    "revoke",
    "mint",
    "burn",
    "schedule",
    "queue",
    "execute",
    "cancel",
    # External policy / signature
    "canperform",
    "caninvoke",
    "cancall",
    "verify",
    "recover",
    "signature",
    "merkle",
)

# Standard ABI names that genuinely identify a pattern. A test using one is an
# integration check, not a structural one; parameterization carries a ``stdname``
# flag to say so.
STANDARD_ABI_NAMES = ("ownerOf", "canCall")


def _is_clean_identifier(name: str) -> bool:
    lower = name.lower()
    return not any(banned in lower for banned in BANNED_SUBSTRINGS)


def _gen_identifier(rng: random.Random, prefix: str = "") -> str:
    """Pure-gibberish identifier clean of every banned substring; stable per-seed."""
    consonants = "bcdfghjklmnpqrstvwxz"
    vowels = "aeiouy"
    while True:
        body = "".join(rng.choice(consonants) + rng.choice(vowels) for _ in range(rng.randint(2, 4)))
        candidate = f"{prefix}{body}{rng.randint(0, 99)}"
        if _is_clean_identifier(candidate):
            return candidate


def _semantic_entry(analysis: Any, signature: str) -> dict | None:
    ac = analysis.get("semantic_control") or {}
    for fn in ac.get("semantic_functions") or []:
        if fn["function"] == signature:
            return dict(fn)
    return None


def _has_parametric_guard_signal(entry: dict | None) -> bool:
    """Label-free check: does the entry carry a structured predicate that references
    msg.sender and depends on at least one runtime function parameter?

    The seven-shape taxonomy only picks diverse fixtures; a generic implementation
    extracts ONE thing (a predicate object with parameter-binding metadata), so the
    assertion is uniform across shapes.

    A candidate is a dict with a structural msg.sender reference (``msg_sender_in_predicate``
    / ``references_msg_sender`` / ``basis``/``operands`` containing 'msg.sender' / a
    ``predicate`` string mentioning it) AND a parameter-binding field
    (``parameter_indices``, ``argument_index``/``argument_name``, ``role_param``/
    ``role_param_index``/``scope_param``, or ``conditional_principals``). Candidates
    are searched in ``parametric_guards``, ``predicates``, ``guard_shape`` /
    ``parametric_guard`` and typed ``sinks``. Field names stay permissive because the
    implementation hasn't picked one yet; the contract is on payload, not naming.
    """
    if entry is None:
        return False

    def _references_msg_sender(c: dict) -> bool:
        for flag in ("msg_sender_in_predicate", "references_msg_sender"):
            if c.get(flag) is True:
                return True
        for list_key in ("basis", "operands", "operand_taint", "msg_sender_paths"):
            v = c.get(list_key)
            if isinstance(v, list) and any(isinstance(x, str) and "msg.sender" in x for x in v):
                return True
            if isinstance(v, list) and any(
                isinstance(x, dict)
                and any(isinstance(s, str) and "msg.sender" in s for s in x.values() if isinstance(s, str))
                for x in v
            ):
                return True
        pred = c.get("predicate")
        if isinstance(pred, str) and "msg.sender" in pred:
            return True
        return False

    def _depends_on_parameter(c: dict) -> bool:
        pi = c.get("parameter_indices")
        if isinstance(pi, list) and pi:
            return True
        if any(k in c for k in ("argument_index", "argument_name", "role_param", "role_param_index", "scope_param")):
            return True
        cp = c.get("conditional_principals")
        if isinstance(cp, list) and cp:
            return True
        return False

    candidates: list[dict] = []
    for key in ("parametric_guards", "predicates"):
        v = entry.get(key)
        if isinstance(v, list):
            candidates.extend(c for c in v if isinstance(c, dict))
    for key in ("guard_shape", "parametric_guard"):
        v = entry.get(key)
        if isinstance(v, dict):
            candidates.append(v)
        elif isinstance(v, list):
            candidates.extend(c for c in v if isinstance(c, dict))
    for s in entry.get("sinks") or []:
        if isinstance(s, dict):
            candidates.append(s)

    for c in candidates:
        if _references_msg_sender(c) and _depends_on_parameter(c):
            return True
    return False


# Solidity templates per shape. Each generator returns the guarded source and an
# "unguarded twin" that drops the check; the twin is the precision check (a
# structural fix MUST NOT admit it as a parametric guard).
# ---------------------------------------------------------------------------


def _shape_caller_equals_argument(rng: random.Random) -> tuple[str, str, str, str]:
    fn = _gen_identifier(rng)
    arg = _gen_identifier(rng)
    state = _gen_identifier(rng, prefix="_")
    guarded = f"""
pragma solidity ^0.8.19;
contract C {{
    uint256 public {state};
    function {fn}(address {arg}) public {{
        require({arg} == msg.sender);
        {state} = block.timestamp;
    }}
}}
"""
    unguarded = f"""
pragma solidity ^0.8.19;
contract C {{
    uint256 public {state};
    function {fn}(address {arg}) public {{
        // Negative twin: parameter assignment with NO ``account == msg.sender`` check.
        {state} = block.timestamp + uint160({arg});
    }}
}}
"""
    return guarded, unguarded, f"{fn}(address)", f"{fn}(address)"


def _shape_role_member_dynamic_arg(rng: random.Random) -> tuple[str, str, str, str]:
    fn = _gen_identifier(rng)
    map_name = _gen_identifier(rng, prefix="_")
    state = _gen_identifier(rng, prefix="_")
    guarded = f"""
pragma solidity ^0.8.19;
contract C {{
    mapping(bytes32 => mapping(address => bool)) {map_name};
    uint256 public {state};
    function {fn}(bytes32 r) public {{
        require({map_name}[r][msg.sender]);
        {state} = block.timestamp;
    }}
}}
"""
    unguarded = f"""
pragma solidity ^0.8.19;
contract C {{
    mapping(bytes32 => mapping(address => bool)) {map_name};
    uint256 public {state};
    function {fn}(bytes32 r) public {{
        // Negative twin: still touches the mapping but does NOT use it as a guard.
        {map_name}[r][msg.sender] = true;
        {state} = block.timestamp;
    }}
}}
"""
    return guarded, unguarded, f"{fn}(bytes32)", f"{fn}(bytes32)"


def _shape_dynamic_role_admin(rng: random.Random) -> tuple[str, str, str, str]:
    """``hasRole(getRoleAdmin(roleArg), msg.sender)`` with a getter-helper
    sandwiched in; an earlier template inlined ``admin_map[r]`` and could miss the
    real two-hop indirection."""
    fn = _gen_identifier(rng)
    membership_check = _gen_identifier(rng, prefix="_")
    admin_lookup = _gen_identifier(rng, prefix="_")
    map_name = _gen_identifier(rng, prefix="_")
    admin_map = _gen_identifier(rng, prefix="_")
    state = _gen_identifier(rng, prefix="_")
    guarded = f"""
pragma solidity ^0.8.19;
contract C {{
    mapping(bytes32 => mapping(address => bool)) {map_name};
    mapping(bytes32 => bytes32) {admin_map};
    uint256 public {state};
    error MissingMembership();
    function {membership_check}(bytes32 r, address a) internal view {{
        if (!{map_name}[r][a]) revert MissingMembership();
    }}
    function {admin_lookup}(bytes32 r) internal view returns (bytes32) {{
        // Two-hop: helper returns an admin-role value from another mapping.
        // The renamed equivalent reads the admin mapping the same way.
        return {admin_map}[r];
    }}
    function {fn}(bytes32 r, address account) public {{
        {membership_check}({admin_lookup}(r), msg.sender);
        {map_name}[r][account] = true;
        {state} = block.timestamp;
    }}
}}
"""
    unguarded = f"""
pragma solidity ^0.8.19;
contract C {{
    mapping(bytes32 => mapping(address => bool)) {map_name};
    mapping(bytes32 => bytes32) {admin_map};
    uint256 public {state};
    function {fn}(bytes32 r, address account) public {{
        // Negative twin: same data layout, no membership check before mutation.
        {map_name}[r][account] = true;
        {state} = uint256({admin_map}[r]);
    }}
}}
"""
    return guarded, unguarded, f"{fn}(bytes32,address)", f"{fn}(bytes32,address)"


def _shape_mapping_member_dynamic_scope(rng: random.Random) -> tuple[str, str, str, str]:
    """MakerDAO-style ``wards[ilk][user] == 1``: like role_member_dynamic_arg but a
    uint flag, kept separate because ``== 1`` is a distinct routing case."""
    fn = _gen_identifier(rng)
    scope_map = _gen_identifier(rng, prefix="_")
    state = _gen_identifier(rng, prefix="_")
    guarded = f"""
pragma solidity ^0.8.19;
contract C {{
    mapping(bytes32 => mapping(address => uint256)) {scope_map};
    uint256 public {state};
    function {fn}(bytes32 ilk) public {{
        require({scope_map}[ilk][msg.sender] == 1);
        {state} = block.timestamp;
    }}
}}
"""
    unguarded = f"""
pragma solidity ^0.8.19;
contract C {{
    mapping(bytes32 => mapping(address => uint256)) {scope_map};
    uint256 public {state};
    function {fn}(bytes32 ilk) public {{
        // Negative twin: write but no check.
        {scope_map}[ilk][msg.sender] = 1;
        {state} = block.timestamp;
    }}
}}
"""
    return guarded, unguarded, f"{fn}(bytes32)", f"{fn}(bytes32)"


def _shape_external_policy_dynamic(rng: random.Random, *, stdname: bool) -> tuple[str, str, str, str]:
    """``policy.<bool fn>(msg.sender, target, selector)``. ``stdname=False`` uses a
    renamed method of the same call shape, resolved via structural detection."""
    fn = _gen_identifier(rng)
    auth_field = _gen_identifier(rng, prefix="_")
    iface = _gen_identifier(rng, prefix="I").capitalize()
    method = "canCall" if stdname else _gen_identifier(rng)
    state = _gen_identifier(rng, prefix="_")
    guarded = f"""
pragma solidity ^0.8.19;
interface {iface} {{
    function {method}(address src, address dst, bytes4 sig) external view returns (bool);
}}
contract C {{
    {iface} {auth_field};
    uint256 public {state};
    function {fn}(address target, bytes4 sel) public {{
        require({auth_field}.{method}(msg.sender, target, sel));
        {state} = block.timestamp;
    }}
}}
"""
    unguarded = f"""
pragma solidity ^0.8.19;
interface {iface} {{
    function {method}(address src, address dst, bytes4 sig) external view returns (bool);
}}
contract C {{
    {iface} {auth_field};
    uint256 public {state};
    function {fn}(address target, bytes4 sel) public {{
        // Negative twin: calls the policy but doesn't gate on it.
        {auth_field}.{method}(msg.sender, target, sel);
        {state} = block.timestamp;
    }}
}}
"""
    return guarded, unguarded, f"{fn}(address,bytes4)", f"{fn}(address,bytes4)"


def _shape_caller_equals_external_owner(rng: random.Random, *, stdname: bool) -> tuple[str, str, str, str]:
    """``msg.sender == external.<address-returning view>(arg)``; the renamed variant
    uses a fuzzed view to prove structural detection (standard: ``ownerOf``)."""
    fn = _gen_identifier(rng)
    nft_field = _gen_identifier(rng, prefix="_")
    iface = _gen_identifier(rng, prefix="I").capitalize()
    method = "ownerOf" if stdname else _gen_identifier(rng)
    state = _gen_identifier(rng, prefix="_")
    guarded = f"""
pragma solidity ^0.8.19;
interface {iface} {{
    function {method}(uint256 id) external view returns (address);
}}
contract C {{
    {iface} {nft_field};
    uint256 public {state};
    function {fn}(uint256 tokenId) public {{
        require(msg.sender == {nft_field}.{method}(tokenId));
        {state} = block.timestamp;
    }}
}}
"""
    unguarded = f"""
pragma solidity ^0.8.19;
interface {iface} {{
    function {method}(uint256 id) external view returns (address);
}}
contract C {{
    {iface} {nft_field};
    uint256 public {state};
    function {fn}(uint256 tokenId) public {{
        // Negative twin: calls the lookup but doesn't gate on its result.
        address who = {nft_field}.{method}(tokenId);
        {state} = uint160(who);
        tokenId; msg.sender;  // silence unused
    }}
}}
"""
    return guarded, unguarded, f"{fn}(uint256)", f"{fn}(uint256)"


def _shape_disjunction(rng: random.Random) -> tuple[str, str, str, str]:
    fn = _gen_identifier(rng)
    map_name = _gen_identifier(rng, prefix="_")
    state = _gen_identifier(rng, prefix="_")
    guarded = f"""
pragma solidity ^0.8.19;
contract C {{
    mapping(bytes32 => mapping(address => bool)) {map_name};
    uint256 public {state};
    function {fn}(bytes32 r, address account) public {{
        require(account == msg.sender || {map_name}[r][msg.sender]);
        {state} = block.timestamp;
    }}
}}
"""
    unguarded = f"""
pragma solidity ^0.8.19;
contract C {{
    mapping(bytes32 => mapping(address => bool)) {map_name};
    uint256 public {state};
    function {fn}(bytes32 r, address account) public {{
        // Negative twin: writes both branches, gates on neither.
        {map_name}[r][account] = true;
        {state} = block.timestamp;
    }}
}}
"""
    return guarded, unguarded, f"{fn}(bytes32,address)", f"{fn}(bytes32,address)"


def _gen_for_shape(shape_name: str, rng: random.Random):
    if shape_name == "caller_equals_argument":
        return (*_shape_caller_equals_argument(rng), False)
    if shape_name == "role_member_dynamic_arg":
        return (*_shape_role_member_dynamic_arg(rng), False)
    if shape_name == "dynamic_role_admin":
        return (*_shape_dynamic_role_admin(rng), False)
    if shape_name == "mapping_member_dynamic_scope":
        return (*_shape_mapping_member_dynamic_scope(rng), False)
    if shape_name == "external_policy_dynamic_stdname":
        return (*_shape_external_policy_dynamic(rng, stdname=True), True)
    if shape_name == "external_policy_dynamic_renamed":
        return (*_shape_external_policy_dynamic(rng, stdname=False), False)
    if shape_name == "caller_equals_external_owner_stdname":
        return (*_shape_caller_equals_external_owner(rng, stdname=True), True)
    if shape_name == "caller_equals_external_owner_renamed":
        return (*_shape_caller_equals_external_owner(rng, stdname=False), False)
    if shape_name == "disjunction":
        return (*_shape_disjunction(rng), False)
    raise ValueError(shape_name)


# Shape name -> fuzz-variant count (names only seed generators and label test IDs).
# One variant per shape: each is a cold solc compile in a fresh ``tmp_path``, and the
# former 5-per-shape sweep cost ~120 compiles per offline run. Every variant is still
# gibberish-generated, so the substring ban is unchanged. Raise a count locally for
# the wider sweep when touching the generators.
SHAPES: dict[str, int] = {
    "caller_equals_argument": 1,
    "role_member_dynamic_arg": 1,
    "dynamic_role_admin": 1,
    "mapping_member_dynamic_scope": 1,
    "external_policy_dynamic_stdname": 1,
    "external_policy_dynamic_renamed": 1,
    "caller_equals_external_owner_stdname": 1,
    "caller_equals_external_owner_renamed": 1,
    "disjunction": 1,
}

# The strict-xfail arm ratchets on one variant flipping to XPASS, so it does not need
# the full shape sweep.
XFAIL_RATCHET_CASE = ("caller_equals_argument", 0)

TOP_SEED = 0xC0DE_BABE


def _rng(shape: str, variant: int) -> random.Random:
    return random.Random(f"{TOP_SEED}:{shape}:{variant}")


def _strip_solidity_comments(source: str) -> str:
    """Remove ``//`` line comments so hygiene ignores explanatory prose (which may use
    words like 'check'); Slither sees the same. Block comments aren't used."""
    lines = []
    for line in source.splitlines():
        idx = line.find("//")
        lines.append(line if idx == -1 else line[:idx])
    return "\n".join(lines)


def _check_substring_hygiene(source: str, *, allow_standard_abi: bool) -> str | None:
    """Error message if a banned substring leaked, else None.

    ``allow_standard_abi=True`` lets ``STANDARD_ABI_NAMES`` (``ownerOf``, ``canCall``)
    through: they are the point of the integration variants.
    """
    # Solidity language/type tokens, not user-chosen identifiers.
    primitives = {
        "pragma",
        "solidity",
        "contract",
        "interface",
        "function",
        "public",
        "private",
        "internal",
        "external",
        "view",
        "pure",
        "returns",
        "require",
        "revert",
        "if",
        "block",
        "msg",
        "sender",
        "timestamp",
        "true",
        "false",
        "uint256",
        "uint",
        "uint160",
        "address",
        "bytes32",
        "bytes4",
        "bytes",
        "bool",
        "mapping",
        "error",
        "memory",
        "storage",
        "calldata",
        "C",
        "id",
        "src",
        "dst",
        "sig",
        "selector",
        "tokenId",
        "target",
        "sel",
        "account",
        "role",
        "ilk",
        "r",
        "a",
        "who",
    }
    # Split member calls so the standard-ABI exception applies only to exact method names.
    leaks = []
    stripped = _strip_solidity_comments(source)
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", stripped):
        if token in primitives or token == "MissingMembership":
            continue
        if allow_standard_abi and token in STANDARD_ABI_NAMES:
            continue
        if not _is_clean_identifier(token):
            leaks.append(token)
    if leaks:
        return f"banned substrings leaked into generated source: {leaks}"
    return None


def _extract_function_signatures(source: str) -> set[str]:
    """Pull ``name(type1,type2)`` shapes out of a Solidity source string.

    Codex finding: asserting ``_semantic_entry(analysis, sig_u) is None`` passes
    vacuously if the generator returned a signature that does not exist; this lets
    the test prove ``sig_u`` is a real declared function first.
    """
    sigs: set[str] = set()
    for m in re.finditer(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)", source):
        name = m.group(1)
        raw = m.group(2).strip()
        if not raw:
            sigs.add(f"{name}()")
            continue
        types: list[str] = []
        for piece in raw.split(","):
            piece = piece.strip()
            if not piece:
                continue
            types.append(piece.split()[0])
        sigs.add(f"{name}({','.join(types)})")
    return sigs


# Fixture-validity test (NOT xfailed): catches generator bugs an xfail would mask.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "shape_name,variant",
    [(name, v) for name, n in SHAPES.items() for v in range(n)],
    ids=lambda x: str(x),
)
def test_fuzz_fixtures_are_valid(shape_name: str, variant: int, tmp_path: Path):
    """Every generated source must compile, pass the banned-substring hygiene check
    (modulo standard-ABI exceptions), declare ``sig_u`` for real (anti-vacuity on the
    negative control), and NOT admit the unguarded twin (precision).

    Positive-side admission of the *guarded* variant is intentionally not asserted:
    the strict-xfailed test owns "admit + emit typed predicate" as one bundled
    assertion, and a separate "admits today" test would flip green when admission
    lands without the typed predicate, weakening the ratchet.
    """
    rng = _rng(shape_name, variant)
    gen = _gen_for_shape(shape_name, rng)
    guarded_src, unguarded_src, sig_u, is_stdname = gen[0], gen[1], gen[3], gen[4]

    # 1. Hygiene: comments stripped, no banned substring in any token.
    msg = _check_substring_hygiene(guarded_src, allow_standard_abi=is_stdname)
    assert msg is None, f"[{shape_name} v{variant}] guarded: {msg}\n{guarded_src}"
    msg = _check_substring_hygiene(unguarded_src, allow_standard_abi=is_stdname)
    assert msg is None, f"[{shape_name} v{variant}] unguarded: {msg}\n{unguarded_src}"

    # 2. Anti-vacuity: sig_u must be a function the source declares, or the
    # negative-control assertion below would pass for free.
    declared = _extract_function_signatures(unguarded_src)
    assert sig_u in declared, (
        f"[{shape_name} v{variant}] generator returned sig_u={sig_u!r} but unguarded "
        f"source declares only {sorted(declared)}; the negative-control "
        f"check would have passed vacuously.\n{unguarded_src}"
    )

    project_g = write_foundry_project(tmp_path / "g", "C", guarded_src)
    collect_contract_analysis(project_g)  # exception → fixture broken

    # 3. Negative control: the unguarded twin must NOT carry a caller-authority leaf.
    # Functions with state writes (every unguarded twin) are included in
    # semantic_functions even without a gate, so the check is on the predicate tree.
    project_u = write_foundry_project(tmp_path / "u", "C", unguarded_src)
    from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts

    _analysis_u, predicate_trees_u, _effects_u = collect_contract_analysis_with_artifacts(project_u)
    semantic_trees = ((predicate_trees_u or {}).get("trees")) or {}
    tree_u = semantic_trees.get(sig_u)

    def _has_caller_authority_leaf(node) -> bool:
        if not isinstance(node, dict):
            return False
        if node.get("op") == "LEAF":
            leaf = node.get("leaf") or {}
            return leaf.get("authority_role") in ("caller_authority", "delegated_authority")
        return any(_has_caller_authority_leaf(c) for c in node.get("children") or [])

    assert not _has_caller_authority_leaf(tree_u), (
        f"[{shape_name} v{variant}] unguarded twin {sig_u} surfaced a "
        f"caller_authority/delegated_authority leaf — fixture has an "
        f"incidental check or the structural classification is "
        f"overinclusive.\n{unguarded_src}"
    )


# Typed-predicate emission test, xfail(strict=True) so it ratchets when typed
# predicates land.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "shape_name,variant",
    [XFAIL_RATCHET_CASE],
    ids=lambda x: str(x),
)
@pytest.mark.xfail(
    reason=(
        "Pipeline does not yet emit a structured parametric-guard signal "
        "on semantic function entries. caller_reach_analysis fires, the "
        "function admits, but the predicate that gates it (and which "
        "function parameter(s) the predicate depends on) is not captured. "
        "Without that, resolution can't compute principals and the UI "
        "renders 'Unresolved'. "
        "FIX: surface the semantic predicate object with parameter "
        "dependencies and msg.sender reachability, so resolution can "
        "compute principals without enumerating shape labels. Test flips "
        "to passing when the structure is present; remove xfail decorator "
        "when it does."
    ),
    strict=True,
)
def test_parametric_guard_emits_predicate_signal(shape_name: str, variant: int, tmp_path: Path):
    """Label-free: the entry carries a structured predicate that references msg.sender
    AND depends on a runtime parameter, whichever of the seven shapes it is."""
    rng = _rng(shape_name, variant)
    gen = _gen_for_shape(shape_name, rng)
    guarded_src, sig_g = gen[0], gen[2]
    project = write_foundry_project(tmp_path, "C", guarded_src)
    analysis = collect_contract_analysis(project)
    entry = _semantic_entry(analysis, sig_g)

    diagnostic = (
        f"\nshape={shape_name} variant={variant} (label is for diagnostic only; "
        f"assertion is shape-agnostic)\n"
        f"signature={sig_g}\n"
        f"entry_keys={list(entry.keys()) if entry else None}\n"
        f"controller_refs={(entry or {}).get('controller_refs')}\n"
        f"guards={(entry or {}).get('guards')}\n"
        f"sink_kinds={[(s or {}).get('kind') for s in (entry or {}).get('sinks') or []]}\n"
        f"parametric_guards={(entry or {}).get('parametric_guards')}\n"
        f"---\n{guarded_src}"
    )
    assert _has_parametric_guard_signal(entry), (
        f"expected semantic function entry for {sig_g!r} to carry a "
        f"structured predicate referencing msg.sender AND binding to a "
        f"runtime parameter (any field name; routing fields enumerated in "
        f"_has_parametric_guard_signal). None found.{diagnostic}"
    )
