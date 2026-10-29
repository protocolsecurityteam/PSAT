"""Read-only selection reports over saved formulas. No enumeration or model calls.

Access is assessed over the complete effect guard and all observed identity dimensions.
Structural dependency evidence sets attention priority, not an invented economic severity.
Reports recommend work; they never execute expansion or remove an input formula.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any

import z3

from services.logic.expansion import Selection, formula_hash
from services.logic.model import BudgetExceeded, Formula, Issue, Limits, Reads, decode_formula
from services.logic.solver import ADDRESS, Translation, boolean, integer
from services.logic.terms import CALLER, FALSE, IDENTITY_KINDS, Term, conjuncts, contains, mk_not, stable, subterms

POLICY_VERSION = "authority-selection-v1"


def selections_from_report(artifact: dict, report: dict) -> dict[str, Selection]:
    """Validate a reviewed plan for explicit expansion; this function performs no work."""
    chain, block, address = artifact_identity(artifact)
    if (
        report.get("kind") != "expansion_selection"
        or report.get("chain_id") != chain
        or report.get("block") != block
        or int(report.get("address", "0x0"), 16) != address
    ):
        raise ValueError("selection report does not match formula artifact")
    keys = [(r["function"], r["effect_index"]) for r in report["rows"]]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate selection row")
    approved = {(r["function"], r["effect_index"]): r for r in report["rows"] if r["decision"] == "expand"}
    selections = {}
    for request in report["suggested_expansions"]:
        name = request["function"]
        if name in selections or name not in artifact["functions"]:
            raise ValueError("invalid or duplicate expansion request")
        formula = decode_formula(artifact["functions"][name])
        fingerprint = formula_hash(formula)
        if (formula.address, formula.block, formula.signature) != (address, block, name):
            raise ValueError("formula identity does not match artifact")
        selection = Selection(request["callers"], tuple(request["effect_indices"]))
        selection.validate(formula)
        targets = (*selection.effect_indices, *((None,) if selection.callers else ()))
        if request.get("formula_hash") != fingerprint or any(
            approved.get((name, i), {}).get("formula_hash") != fingerprint for i in targets
        ):
            raise ValueError("expansion request is not backed by matching selected rows")
        selections[name] = selection
    if not selections:
        raise ValueError("selection report recommends no expansions")
    return selections


@dataclass(frozen=True)
class ReportLimits:
    solver_ms: int = 250
    solver_queries: int = 256
    direct_reads: int = 64
    assessed_effects: int = 1000
    dependency_pairs: int = 10_000
    bound_queries: int = 4


class _DirectReads:
    """A hard acquisition boundary, including if a future translator tries to enumerate."""

    def __init__(self, reads: Reads, limit: int):
        self.reads, self.block, self.limit = reads, reads.block, limit
        self.memo: dict[tuple, Any] = {}

    def _read(self, name: str, *args):
        key = (name, *args)
        if key not in self.memo:
            if len(self.memo) >= self.limit:
                raise BudgetExceeded("selection direct-read budget")
            self.memo[key] = getattr(self.reads, name)(*args)
        return self.memo[key]

    def storage(self, address, slot):
        return self._read("storage", address, slot)

    def code(self, address):
        return self._read("code", address)

    def balance(self, address):
        return self._read("balance", address)

    def block_field(self, name):
        return self._read("block_field", name)

    def storage_dump(self, address):
        raise BudgetExceeded("enumeration disabled during selection")

    def key_words(self, address):
        raise BudgetExceeded("enumeration disabled during selection")

    def preimages(self, address, slots):
        raise BudgetExceeded("enumeration disabled during selection")


class _AssessmentTranslation(Translation):
    def __init__(self, reads, contracts, formula, limits):
        self.offline = reads is None
        super().__init__(reads, contracts, formula.address, formula.selector, Limits(solver_ms=limits.solver_ms))

    def _translate(self, t):
        if self.offline and t[0] in ("load", "rawload", "time", "balance", "codesize", "code", "codehash"):
            return self.missing(t, "pinned state needed", "state_required")
        return super()._translate(t)

    def _load(self, t):
        if contains(t, frozenset({*IDENTITY_KINDS, "arg", "callvalue", "calldatasize"})):
            return self.missing(t, "symbolic storage lookup needs expansion", "state_required")
        return super()._load(t)


class _Queries:
    def __init__(self, limits: ReportLimits):
        self.limits, self.used = limits, 0

    @property
    def available(self):
        return self.limits.solver_ms > 0 and self.used < self.limits.solver_queries

    def check(self, expression):
        if not self.available:
            return z3.unknown
        self.used += 1
        solver = z3.Solver()
        solver.set(timeout=self.limits.solver_ms)
        solver.add(expression)
        return solver.check()


def _dimensions(predicate: Term) -> tuple[str, ...]:
    return tuple(sorted(kind for kind in IDENTITY_KINDS if subterms(predicate, kind)))


def _access(formula, predicate, reads, contracts, limits, queries):
    dimensions = _dimensions(predicate)
    result = {
        "status": "unresolved",
        "activity": "unknown",
        "identity_dimensions": dimensions,
        "basis": "full_effect_guard",
        "domain": "joint identity values in the EVM call frame; not signing or transaction capability",
        "issues": [],
    }
    if not queries.available:
        result["issues"] = [asdict(Issue("budget", "selection solver"))]
        return result, None, None
    translation = _AssessmentTranslation(reads, contracts, formula, limits)
    goal = boolean(translation.translate(predicate))
    # Caller always belongs to the domain. Other identities are NOT free arguments that
    # can be satisfied by borrowing a privileged origin or another account's signature.
    identities = [translation.translate(CALLER)]
    for kind in sorted(IDENTITY_KINDS - {"caller"}):
        identities.extend(translation.translate(t) for t in subterms(predicate, kind))
    if translation.issues:
        result["issues"] = [asdict(i) for i in dict.fromkeys(translation.issues)]
        return result, translation, None
    whole = z3.And(goal, *translation.bounds)
    reachable = queries.check(whole)
    if reachable == z3.unsat:
        result["activity"] = "inactive_at_block"
        result["issues"] = [asdict(Issue("inactive", "no satisfying call at this block; not a severity conclusion"))]
        return result, translation, whole
    if reachable != z3.sat:
        result["issues"] = [asdict(Issue("solver", "reachability unresolved"))]
        return result, translation, whole
    result["activity"] = "reachable_in_call_frame"
    arguments = [v for t, v in translation.variables.items() if t[0] not in IDENTITY_KINDS]
    permitted = z3.Exists(arguments, whole) if arguments else whole
    identity_domain = z3.And(*(z3.And(integer(v) >= 0, integer(v) < ADDRESS) for v in identities))
    refused = queries.check(z3.And(identity_domain, z3.Not(permitted)))
    if refused == z3.unsat:
        result["status"] = "unrestricted"
    elif refused == z3.sat:
        result["status"] = "restricted"
    else:
        result["issues"] = [asdict(Issue("solver", "unrestricted-access query unresolved"))]
    return result, translation, whole


def _location(load: Term) -> tuple:
    return (load[1], load[2], load[3]) if load[0] == "load" else ("raw", load[1], load[2])


def _may_alias(write: tuple, read: tuple) -> bool:
    if write[:2] != read[:2]:
        return False
    if write[0] == "raw":
        a, b = write[2], read[2]
        return a[1] == b[1] if a[0] == b[0] == "const" else True
    for (ka, a), (kb, b) in zip(write[2], read[2]):
        if ka != kb or (ka == "f" and a != b):
            return False
        if ka == "k" and a[0] == b[0] == "const" and a[1] != b[1]:
            return False
    return True


def _necessary(guard: Term, condition: Term, queries: _Queries) -> bool:
    """Propositional over-approximation: prove a condition necessary on every branch.

    This proves an implication, not reachability or severity. Unknown diagnostics receive
    independent atoms on every occurrence so equal labels cannot create a false proof.
    """
    if guard != FALSE and condition in conjuncts(guard):
        return True
    atoms: dict[Term, Any] = {}
    serial = [0]

    def atom(t):
        serial[0] += 1
        if contains(t, frozenset({"unknown", "opaque", "assumed", "call", "delegate"})):
            return z3.Bool(f"unmodelled{serial[0]}")
        if t not in atoms:
            atoms[t] = z3.Bool(f"atom{serial[0]}")
        return atoms[t]

    def build(t):
        if t[0] == "const" and isinstance(t[1], (bool, int)):
            return z3.BoolVal(bool(t[1]))
        if t[0] in ("and", "or"):
            values = [build(v) for v in sorted(t[1], key=stable)]
            return z3.And(*values) if t[0] == "and" else z3.Or(*values)
        if t[0] == "not":
            return z3.Not(build(t[1]))
        return atom(t)

    required, predicate = build(condition), build(guard)
    return queries.check(predicate) == z3.sat and queries.check(z3.And(predicate, z3.Not(required))) == z3.unsat


def _authority_loads(guard: Term, queries: _Queries):
    """Loads compared directly to identities and required by the full Boolean guard."""
    for comparison in subterms(guard, "cmp"):
        if comparison[1] != "eq":
            continue
        for identity, value in ((comparison[2], comparison[3]), (comparison[3], comparison[2])):
            if identity[0] in IDENTITY_KINDS and value[0] in ("load", "rawload"):
                if _necessary(guard, comparison, queries):
                    yield value
    # A Boolean lookup of an identity can be required positively (membership) or
    # negatively (a blocklist). Numeric thresholds are not called authorization facts.
    for kind in ("load", "rawload"):
        for load in subterms(guard, kind):
            if contains(load, IDENTITY_KINDS) and (
                _necessary(guard, load, queries) or _necessary(guard, mk_not(load), queries)
            ):
                yield load


def _value_bound(effect, translation, whole, access, limits, queries):
    if translation is None or whole is None or access["activity"] != "reachable_in_call_frame":
        return None
    value = translation.translate(effect.value)
    if translation.issues or not isinstance(value, z3.ExprRef):
        return None
    candidates = set()
    for comparison in subterms(effect.guard, "cmp"):
        if effect.value not in subterms(comparison, effect.value[0]):
            continue
        for literal in subterms(comparison, "const"):
            if type(literal[1]) is int:
                candidates.add(literal[1])
    if effect.value[0] == "const" and isinstance(effect.value[1], (bool, int)):
        candidates.add(int(effect.value[1]))
    for upper in sorted(candidates)[: limits.bound_queries]:
        if queries.check(z3.And(whole, integer(value) > upper)) == z3.unsat:
            return {
                "upper": upper,
                "basis": "full_guard_implication_at_block",
                "meaning": "storage value bound, not an asset-loss bound",
            }
    return None


def artifact_identity(artifact: dict) -> tuple[int, int, int]:
    """Validate pinned identity before a CLI can create a provider or ask for a latest block."""
    if not isinstance(artifact, dict) or artifact.get("schema") != 2 or artifact.get("kind") != "formulas":
        raise ValueError("expected a formula-only artifact")
    chain, block = artifact.get("chain_id"), artifact.get("block")
    try:
        address = int(artifact["address"], 16)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid artifact address") from exc
    if type(chain) is not int or chain <= 0 or type(block) is not int or block < 0 or not 0 <= address < ADDRESS:
        raise ValueError("invalid artifact chain or block")
    if not isinstance(artifact.get("functions"), dict):
        raise ValueError("invalid artifact function map")
    return chain, block, address


def selection_report(
    artifact: dict, *, reads: Reads | None = None, contracts: Any = None, limits: ReportLimits = ReportLimits()
) -> dict:
    """Produce recommendations only. Unresolved functions remain in the report."""
    chain, block, address = artifact_identity(artifact)
    if any(type(v) is not int or v < 0 for v in asdict(limits).values()):
        raise ValueError("selection budgets must be non-negative integers")
    if reads is not None and reads.block != block:
        raise ValueError("selection must use the formula's pinned block")
    formulas: dict[str, Formula] = {}
    for signature, payload in sorted(artifact["functions"].items()):
        formula = decode_formula(payload)
        if (formula.address, formula.block, formula.signature) != (address, block, signature):
            raise ValueError("formula identity does not match artifact")
        formulas[signature] = formula
    limited = _DirectReads(reads, limits.direct_reads) if reads is not None else None
    contracts = contracts or {}
    fingerprints = {name: formula_hash(f) for name, f in formulas.items()}
    queries = _Queries(limits)
    references = []
    for name, f in formulas.items():
        for i, effect in enumerate(f.effects):
            required = set(_authority_loads(effect.guard, queries))
            for load in (*subterms(effect.guard, "load"), *subterms(effect.guard, "rawload")):
                references.append((name, i, _location(load), load in required))
    rows, comparisons = [], 0
    for name, f in formulas.items():
        for index, effect in enumerate(f.effects or (None,)):
            predicate = effect.guard if effect is not None else f.success
            if len(rows) >= limits.assessed_effects:
                access = {
                    "status": "unresolved",
                    "activity": "unknown",
                    "identity_dimensions": _dimensions(predicate),
                    "basis": "not_assessed",
                    "issues": [asdict(Issue("budget", "assessed effects"))],
                }
                translation, whole = None, None
            else:
                access, translation, whole = _access(f, predicate, limited, contracts, limits, queries)
            facts = []
            scan_complete = True
            if effect is not None and effect.kind == "write":
                for other, other_index, location, authority in references:
                    if comparisons >= limits.dependency_pairs:
                        scan_complete = False
                        break
                    comparisons += 1
                    if _may_alias(effect.target, location):
                        facts.append(
                            {
                                "kind": "may_change_authority_condition" if authority else "may_affect_guard",
                                "basis": "necessary_condition_and_possible_alias" if authority else "possible_alias",
                                "function": other,
                                "effect_index": other_index,
                                "formula_hash": fingerprints[other],
                            }
                        )
            elif effect is not None:
                facts.append({"kind": "external_or_unmodelled_effect", "basis": "formula_effect"})
            if effect is not None and effect.kind == "write" and effect.target[0] == "raw":
                facts.append({"kind": "raw_storage_write", "basis": "storage meaning unresolved"})
            if not scan_complete:
                facts.append({"kind": "dependency_budget", "basis": "incomplete_scan"})
            upper = _value_bound(effect, translation, whole, access, limits, queries) if effect is not None else None
            attention = (
                "high"
                if any(
                    x["kind"]
                    in ("may_change_authority_condition", "external_or_unmodelled_effect", "raw_storage_write")
                    for x in facts
                )
                else "normal"
            )
            impact = {
                "level": "unknown",
                "basis": "economic_context_not_established",
                "facts": facts,
                "dependency_scan_complete": scan_complete,
                "value_bound": upper,
            }
            issues = access["issues"]
            if effect is None and f.success == FALSE:
                decision, reason = "defer", "formula has no successful call; no holders to enumerate"
            elif effect is None:
                decision, reason = "review", "no reported effects; this is not a harmlessness proof"
            elif access["activity"] == "inactive_at_block":
                decision, reason = "review", "blocked now; retain impact and inspect enabling conditions"
            elif access["status"] == "unrestricted":
                decision, reason = "report_unrestricted", "keep visible; a universal set needs no holder list"
            elif any(d != "caller" for d in access["identity_dimensions"]):
                decision, reason = "review", "origin or signing authority must not be projected away"
            elif (
                attention == "high"
                and scan_complete
                and (
                    access["status"] == "restricted" or (issues and all(i["kind"] == "state_required" for i in issues))
                )
            ):
                decision, reason = "expand", "identify controllers of a potential authority change"
            else:
                decision, reason = "review", "impact or access unresolved; additional evidence or judgment needed"
            rows.append(
                {
                    "function": name,
                    "effect_index": index if effect is not None else None,
                    "formula_hash": fingerprints[name],
                    "access": access,
                    "impact": impact,
                    "priority": attention,
                    "decision": decision,
                    "reason": reason,
                }
            )
    rows.sort(key=lambda row: (row["priority"] != "high", row["function"], row["effect_index"] or 0))
    requests: dict[str, list[int]] = {}
    for row in rows:
        if row["decision"] == "expand":
            requests.setdefault(row["function"], []).append(row["effect_index"])
    return {
        "schema": 1,
        "kind": "expansion_selection",
        "policy": POLICY_VERSION,
        "automatic_execution": False,
        "input_status": artifact.get("status", "formulas_available"),
        "chain_id": chain,
        "block": block,
        "address": artifact["address"],
        "mode": "pinned_reads" if reads else "offline",
        "limits": asdict(limits),
        "scope": "supplied deployment formulas only; not a complete economic perimeter",
        "direct_reads": len(limited.memo) if limited is not None else 0,
        "solver_queries": queries.used,
        "rows": rows,
        "summary": dict(Counter(row["decision"] for row in rows)),
        "suggested_expansions": [
            {"function": name, "formula_hash": fingerprints[name], "callers": False, "effect_indices": sorted(indices)}
            for name, indices in sorted(requests.items())
        ],
    }
