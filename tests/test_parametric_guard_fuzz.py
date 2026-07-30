"""Fuzzing-style regression tests for parametric-guard predicate extraction.

Background
----------
The pipeline can recognize "guarded" for many concrete shapes (owner
check, constant-role check, mapping-keyed-on-msg.sender). What it does
NOT yet do is capture the *predicate* that gates a function plus the
*runtime parameter(s)* the predicate depends on, in a single structured
object the resolver can route on. Without that, parametric guards
(grantRole / renounceRole / Maker-style ``wards`` lookups / external
``canCall`` policies / ERC-721 ``ownerOf`` ownership checks) admit but
resolve to zero principals, and the UI renders 'Unresolved'.

Why we fuzz across seven shapes
-------------------------------
Codex enumerated seven distinct parametric shapes seen in the wild:

  1. caller_equals_argument           ``account == msg.sender`` (renounceRole)
  2. role_member_dynamic_arg          ``hasRole(roleArg, msg.sender)``
  3. dynamic_role_admin               ``hasRole(getRoleAdmin(roleArg), msg.sender)``
  4. mapping_member_dynamic_scope     ``wards[scopeArg][msg.sender]`` (Maker)
  5. external_policy_dynamic          ``authority.canCall(msg.sender, target, sel)``
  6. caller_equals_external_owner     ``msg.sender == nft.ownerOf(tokenId)``
  7. disjunction                      ``a == msg.sender || hasRole(...)``

These names live in the test ONLY to give generators distinct seeds and
to label test IDs. The *assertion* is shape-agnostic: it does not
expect any ``kind == "<shape-name>"`` field — that would be name-shape
matching dressed up one level. Instead it asserts the pipeline emits a
generic structured predicate referencing msg.sender and depending on at
least one runtime function parameter, *however* labeled.

Why fuzz with gibberish identifiers
-----------------------------------
The pipeline must not depend on substring-name matching. If the test
bodies used standard-flavored names, a passing result might come from
identifier text rather than IR-shape detection. The fuzzer generates
pure-gibberish identifiers and rejects any candidate containing
substrings from ``BANNED_SUBSTRINGS``.
Anything the analyzer detects despite that has to be coming from
structural / IR analysis.

Standard-ABI coverage
---------------------
Some shapes are common enough to deserve a canonical-name fixture, such
as ERC-721's ``ownerOf(uint256)`` or MakerDAO's
``canCall(address,address,bytes4)``. Those fixtures are paired with a
renamed method that has the same IR shape. Both variants should resolve
equivalently; the renamed variant keeps the test from passing through
ABI-name matching alone.

Test layout
-----------
``test_fuzz_fixtures_are_valid`` (NOT xfailed): every generated source
is run through the analyzer to confirm fixtures are healthy — compiles,
identifiers obey the substring ban, generator-returned signatures
correspond to real declared functions (anti-vacuity), and the unguarded
twin does NOT admit (precision). This test passing today is a
pre-condition for the typed-predicate test below to be measuring the
right thing.

``test_parametric_guard_emits_predicate_signal`` (xfail strict): for
every generated source, asserts the semantic function entry carries
a structured predicate (any plausible field name) that references
msg.sender AND has at least one parameter-binding field. Marked
``xfail(strict=True)`` so when the implementation lands, every variant
flips to passing in one go and pytest forces removal of the xfail
decorator — ratcheting against silent regression.
"""

from __future__ import annotations

import json
import random
import re
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.static import collect_contract_analysis  # noqa: E402

# Reserved substrings from legacy classifier terms. Any generated
# identifier containing one is rejected, so a detected result cannot be
# explained by a substring match. Keep broad coverage for governance,
# timelock/lifecycle, and external-policy words.
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

# Standard ABI names that genuinely identify a pattern. A test
# explicitly using one of these is an integration check, not a
# structural check; the test parameterization carries a ``stdname``
# flag to make that distinction explicit.
STANDARD_ABI_NAMES = ("ownerOf", "canCall")


def _is_clean_identifier(name: str) -> bool:
    lower = name.lower()
    return not any(banned in lower for banned in BANNED_SUBSTRINGS)


def _gen_identifier(rng: random.Random, prefix: str = "") -> str:
    """Pure-gibberish identifier guaranteed clean of every banned substring.
    Stable per-seed for reproducibility on failure."""
    consonants = "bcdfghjklmnpqrstvwxz"
    vowels = "aeiouy"
    while True:
        body = "".join(rng.choice(consonants) + rng.choice(vowels) for _ in range(rng.randint(2, 4)))
        candidate = f"{prefix}{body}{rng.randint(0, 99)}"
        if _is_clean_identifier(candidate):
            return candidate


def _write_project(tmp_path: Path, contract_name: str, source: str) -> Path:
    project_dir = tmp_path / contract_name
    (project_dir / "src").mkdir(parents=True)
    (project_dir / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nout = "out"\nlibs = ["lib"]\nsolc_version = "0.8.19"\n'
    )
    (project_dir / "src" / f"{contract_name}.sol").write_text(source)
    (project_dir / "contract_meta.json").write_text(
        json.dumps(
            {
                "address": "0x1111111111111111111111111111111111111111",
                "contract_name": contract_name,
                "compiler_version": "v0.8.19+commit.7dd6d404",
            }
        )
        + "\n"
    )
    return project_dir


def _semantic_entry(analysis: Any, signature: str) -> dict | None:
    ac = analysis.get("semantic_control") or {}
    for fn in ac.get("semantic_functions") or []:
        if fn["function"] == signature:
            return dict(fn)
    return None


def _has_parametric_guard_signal(entry: dict | None) -> bool:
    """Label-free check: does the semantic function entry carry a
    structured predicate that depends on at least one runtime function
    parameter and references msg.sender?

    The point of this rewrite is that the test should not enumerate the
    seven shapes from codex's taxonomy — that taxonomy is for choosing
    diverse fuzz fixtures, not for the pipeline to pattern-match by
    label. A genuinely generic implementation extracts ONE thing
    (a predicate object with parameter-binding metadata) and the
    downstream resolver pattern-matches the IR locally. So the assertion
    here is uniform across all shapes: was the parametric structure
    captured at all?

    A candidate qualifies when it is a dict that:
      • has at least one structural reference to msg.sender — via any
        of: ``msg_sender_in_predicate`` / ``references_msg_sender`` /
        a ``basis``/``operands`` list containing 'msg.sender' /
        a ``predicate`` string mentioning ``msg.sender``, AND
      • carries at least one parameter-binding field signaling the
        guard depends on a runtime arg (so it is parametric, not
        constant-role) — any of:
          * ``parameter_indices`` non-empty
          * ``argument_index`` / ``argument_name`` present
          * ``role_param`` / ``role_param_index`` / ``scope_param`` present
          * ``conditional_principals`` non-empty (per-arg resolution)

    Candidates are searched in any of: ``parametric_guards`` (list),
    ``predicates`` (list), ``guard_shape`` / ``parametric_guard``
    (dict or list), and typed entries inside ``sinks`` (list). Field
    names are still permissive because the implementation hasn't picked
    one yet — the *contract* is on payload, not naming.
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


# ---------------------------------------------------------------------------
# Solidity templates per shape. Each generator returns
# (source_code, function_signature, *also* an "unguarded twin" that drops
# the check. The unguarded twin is the precision check — a structural
# fix MUST NOT admit it as a parametric guard).
# ---------------------------------------------------------------------------


def _shape_caller_equals_argument(rng: random.Random) -> tuple[str, str, str, str]:
    """``account == msg.sender`` — renounceRole-style."""
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
    """``mapping[runtimeRole][msg.sender]`` — direct membership check."""
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
    """``hasRole(getRoleAdmin(roleArg), msg.sender)`` shape, with a
    getter-helper sandwiched in. Earlier fuzz template inlined
    ``admin_map[r]`` directly, which could miss the real two-hop
    indirection."""
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
    """MakerDAO-style ``wards[ilk][user] == 1``. Same shape as
    role_member_dynamic_arg but the value is a uint flag rather than a
    bool — kept as a separate shape because the predicate ``== 1`` is
    a distinct routing case."""
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
    """``policy.<bool fn>(msg.sender, target, selector)``.

    ``stdname=True`` keeps coverage for a widely used ABI spelling.
    ``stdname=False`` uses a renamed boolean-returning method with the same
    call shape, which should resolve through structural detection."""
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
    """``msg.sender == external.<address-returning view>(arg)``.

    Standard-ABI variant uses ``ownerOf(uint256)`` (ERC-721). Renamed
    variant uses a fuzzed address-returning view to prove structural
    detection."""
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
    """``account == msg.sender || mapping[role][msg.sender]`` — combined."""
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
    """Per-shape dispatcher returning (guarded, unguarded, sig_g, sig_u, stdname?)."""
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


# Shape name → fuzz-variant count. The shape names live here only to give
# generators distinct seeds and to label test IDs for diagnostics; the
# *assertion* itself is shape-agnostic — it does not branch on the name.
SHAPES: dict[str, int] = {
    "caller_equals_argument": 5,
    "role_member_dynamic_arg": 5,
    "dynamic_role_admin": 5,
    "mapping_member_dynamic_scope": 5,
    "external_policy_dynamic_stdname": 3,
    "external_policy_dynamic_renamed": 5,
    "caller_equals_external_owner_stdname": 3,
    "caller_equals_external_owner_renamed": 5,
    "disjunction": 5,
}

TOP_SEED = 0xC0DE_BABE


def _rng(shape: str, variant: int) -> random.Random:
    return random.Random(f"{TOP_SEED}:{shape}:{variant}")


def _strip_solidity_comments(source: str) -> str:
    """Remove ``//`` line comments so hygiene check ignores explanatory prose
    (which is allowed to use words like 'check' / 'guard'). Slither sees the
    same with comments stripped, so this matches what the IR will see.
    Block comments not used in our templates."""
    lines = []
    for line in source.splitlines():
        idx = line.find("//")
        lines.append(line if idx == -1 else line[:idx])
    return "\n".join(lines)


def _check_substring_hygiene(source: str, *, allow_standard_abi: bool) -> str | None:
    """Returns an error message if a banned substring leaked, None if clean.

    ``allow_standard_abi=True`` lets through the canonical names listed in
    ``STANDARD_ABI_NAMES`` (e.g. ``ownerOf``, ``canCall``); those are
    the *whole point* of the integration variants and aren't fuzz fodder.
    """
    # Tokens that are part of the Solidity language or types we use —
    # not user-chosen identifiers.
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
    # Split member calls into identifier tokens so the standard-ABI exception
    # applies only to exact whitelisted method names.
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

    Codex finding: ``test_fuzz_fixtures_are_valid`` previously asserted
    `_semantic_entry(analysis, sig_u) is None` — but if the generator
    returned the wrong signature, that assertion would pass vacuously
    (the signature is missing not because the function isn't admitted,
    but because it doesn't exist under that name). This helper extracts
    actual signatures from the source so the test can prove ``sig_u``
    really is a function the analyzer would have seen, before claiming
    its absence from semantic_functions is meaningful.
    """
    sigs: set[str] = set()
    # Greedy on params is fine — we don't have nested parens in our templates.
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


# ---------------------------------------------------------------------------
# Fixture-validity test (NOT xfailed). Catches generator bugs that an
# xfail decorator would otherwise mask. Runs first (alphabetically) so a
# generator regression surfaces before the typed-predicate xfails.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "shape_name,variant",
    [(name, v) for name, n in SHAPES.items() for v in range(n)],
    ids=lambda x: str(x),
)
def test_fuzz_fixtures_are_valid(shape_name: str, variant: int, tmp_path: Path):
    """Every generated source must:
      • compile cleanly (collect_contract_analysis runs without exception)
      • pass the banned-substring hygiene check (modulo standard-ABI exceptions)
      • generator-returned ``sig_u`` is a real function declared in the
        unguarded source (anti-vacuity check on the negative control)
      • NOT admit the unguarded twin (precision: a future fix MUST NOT regress here)

    Positive-side admission of the *guarded* variant is intentionally
    not asserted here. The strict-xfailed typed-shape test owns the full
    "admit + emit typed predicate" ratchet in one bundled assertion;
    splitting "admits today" out as its own non-xfail green test would
    flip to passing whenever admission lands even if the typed predicate
    doesn't, weakening the ratchet.
    """
    rng = _rng(shape_name, variant)
    gen = _gen_for_shape(shape_name, rng)
    guarded_src, unguarded_src, sig_u, is_stdname = gen[0], gen[1], gen[3], gen[4]

    # 1. Hygiene — comments stripped, then no banned substring in any token.
    msg = _check_substring_hygiene(guarded_src, allow_standard_abi=is_stdname)
    assert msg is None, f"[{shape_name} v{variant}] guarded: {msg}\n{guarded_src}"
    msg = _check_substring_hygiene(unguarded_src, allow_standard_abi=is_stdname)
    assert msg is None, f"[{shape_name} v{variant}] unguarded: {msg}\n{unguarded_src}"

    # 2. Anti-vacuity: prove sig_u actually corresponds to a function the
    # source declares. Otherwise the negative-control assertion below
    # could pass for the wrong reason (function doesn't exist under that
    # name → also not in semantic_functions → green for free).
    declared = _extract_function_signatures(unguarded_src)
    assert sig_u in declared, (
        f"[{shape_name} v{variant}] generator returned sig_u={sig_u!r} but unguarded "
        f"source declares only {sorted(declared)}; the negative-control "
        f"check would have passed vacuously.\n{unguarded_src}"
    )

    # 3. Compilation: analysis pipeline must not throw on either source.
    project_g = _write_project(tmp_path / "g", "C", guarded_src)
    collect_contract_analysis(project_g)  # exception → fixture broken

    # 3. Negative control: unguarded twin must NOT carry a caller-authority
    # leaf in its predicate tree.
    #
    # The summary inclusion rule is "caller/delegated authority leaf OR
    # sensitive sink". Functions with state writes (every fuzz-generated
    # unguarded twin has them) are included even without a gate, so the
    # negative control is "no caller_authority / delegated_authority leaf
    # in the predicate tree", not "absent from semantic_functions".
    project_u = _write_project(tmp_path / "u", "C", unguarded_src)
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


# ---------------------------------------------------------------------------
# Typed-predicate emission test. This is what the planned fix unlocks.
# Marked xfail(strict=True) so it ratchets when typed predicates land.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "shape_name,variant",
    [(name, v) for name, n in SHAPES.items() for v in range(n)],
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
    """Label-free: assert the entry carries a structured predicate that
    references msg.sender AND depends on a runtime parameter. Does not
    care which of the seven taxonomy shapes the source represents — that
    enumeration is a fuzz-input concern, not a pipeline-output concern.
    """
    rng = _rng(shape_name, variant)
    gen = _gen_for_shape(shape_name, rng)
    guarded_src, sig_g = gen[0], gen[2]
    project = _write_project(tmp_path, "C", guarded_src)
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
