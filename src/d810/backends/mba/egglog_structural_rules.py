"""Proof-gated fixed-count shift/rotate rules for the Egglog adapter.

This module is intentionally separate from the symbolic MBA rule catalogue.
The rules here are structural identities over :class:`TypedBvTerm`: the
literal shift count is metadata on the term, not another bit-vector child.
Only the two complementary shift/or forms that implement a fixed rotate are
admitted.  No generic shift algebra, associativity, or commutativity rewrite
is enrolled in Egglog.
"""

from __future__ import annotations

import enum
import functools
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field, replace

from d810.mba.certified_catalogue import (
    _enroll_structural_rule,
    _is_enrolled_structural_rule,
)
from d810.mba.typed_term import (
    TypedBvTerm,
    canonicalize_ac_term,
    fixed_shift_term,
    term_fingerprint,
)


STRUCTURAL_RULE_WIDTHS = (8, 16, 32, 64)
STRUCTURAL_RULE_FAMILY = "fixed_rotate"
_STRUCTURAL_VARIABLE = ("structural_var", "x")


class StructuralRuleStatus(enum.StrEnum):
    """Stable status values for one structural rule compilation attempt."""

    COMPILED = "compiled"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True, weakref_slot=True)
class CompiledEgglogStructuralRule:
    """One universally certified, width/count-specific structural identity."""

    source_name: str
    width: int
    direction: str
    count: int
    pattern: TypedBvTerm
    replacement: TypedBvTerm
    proof_verdict: bool
    family: str = STRUCTURAL_RULE_FAMILY
    aliases: tuple[str, ...] = ()

    @property
    def proof_widths(self) -> tuple[int, ...]:
        return (self.width,)

    @property
    def semantic_fingerprint(self) -> str:
        return "|".join(
            (
                self.family,
                self.source_name,
                str(self.width),
                self.direction,
                str(self.count),
                term_fingerprint(self.pattern),
                term_fingerprint(self.replacement),
            )
        )


@dataclass(frozen=True, slots=True)
class StructuralRuleCompilationReceipt:
    """Immutable evidence for one attempted structural-rule enrollment."""

    source_name: str
    status: StructuralRuleStatus
    width: int
    direction: str
    count: int
    proof_verdict: bool
    compiled_rule: CompiledEgglogStructuralRule | None = None
    refusal_reason: str | None = None

    def __post_init__(self) -> None:
        if type(self.source_name) is not str or not self.source_name:
            raise ValueError("source_name must be non-empty")
        if not isinstance(self.status, StructuralRuleStatus):
            raise ValueError("status must be a StructuralRuleStatus")
        if type(self.width) is not int or self.width not in STRUCTURAL_RULE_WIDTHS:
            raise ValueError("width must be one of 8, 16, 32, or 64")
        if self.direction not in {"rol", "ror"}:
            raise ValueError("direction must be rol or ror")
        if type(self.count) is not int or not 1 <= self.count < self.width:
            raise ValueError("count must be in [1, width)")
        if type(self.proof_verdict) is not bool:
            raise ValueError("proof_verdict must be a bool")
        if self.status is StructuralRuleStatus.COMPILED:
            if self.compiled_rule is None or not self.proof_verdict:
                raise ValueError("compiled structural rules require a true proof")
            if self.refusal_reason is not None:
                raise ValueError("compiled structural rules cannot have a refusal")
        elif self.compiled_rule is not None:
            raise ValueError("rejected structural rules cannot be enrolled")
        if self.status is StructuralRuleStatus.REJECTED and not self.refusal_reason:
            raise ValueError("rejected structural rules require a refusal reason")

    def to_dict(self) -> dict[str, object]:
        """Return the stable persisted receipt fields, excluding live terms."""

        return {
            "source_name": self.source_name,
            "status": self.status.value,
            "width": self.width,
            "direction": self.direction,
            "count": self.count,
            "proof_verdict": self.proof_verdict,
            "refusal_reason": self.refusal_reason,
        }

    @property
    def serialized_fields(self) -> tuple[tuple[str, object], ...]:
        return tuple(self.to_dict().items())


def _validate_width(width: int) -> None:
    if type(width) is not int or width not in STRUCTURAL_RULE_WIDTHS:
        raise ValueError("width must be one of 8, 16, 32, or 64")


def _validate_direction(direction: str) -> None:
    if direction not in {"rol", "ror"}:
        raise ValueError("direction must be rol or ror")


def _validate_count(width: int, count: int) -> None:
    if type(count) is not int or not 1 <= count < width:
        raise ValueError("count must be in [1, width)")


def build_rotate_identity(
    width: int, direction: str, count: int
) -> tuple[TypedBvTerm, TypedBvTerm]:
    """Build one exact complementary shift/or identity."""

    _validate_width(width)
    _validate_direction(direction)
    _validate_count(width, count)
    x = TypedBvTerm(None, width, leaf_key=_STRUCTURAL_VARIABLE)
    if direction == "rol":
        left = fixed_shift_term("shl", width, x, count)
        right = fixed_shift_term("lshr", width, x, width - count)
    else:
        left = fixed_shift_term("lshr", width, x, count)
        right = fixed_shift_term("shl", width, x, width - count)
    pattern = TypedBvTerm("or", width, children=(left, right))
    replacement = fixed_shift_term(direction, width, x, count)
    return pattern, replacement


def prove_typed_term_equivalence(
    pattern: TypedBvTerm, replacement: TypedBvTerm
) -> bool:
    """Run the shared universal fixed-width typed Z3 gate."""

    from d810.backends.mba.native_z3_proof_template import (
        prove_typed_term_equivalence as _prove_typed_term_equivalence,
    )

    return _prove_typed_term_equivalence(pattern, replacement)


def _enroll(rule: CompiledEgglogStructuralRule) -> CompiledEgglogStructuralRule:
    _enroll_structural_rule(rule)
    return rule


def is_admitted_structural_rule(rule: object) -> bool:
    return (
        type(rule) is CompiledEgglogStructuralRule
        and _is_enrolled_structural_rule(rule)
        and rule.proof_verdict is True
    )


def compile_fixed_rotate_rules(
    *, width: int, direction: str
) -> tuple[StructuralRuleCompilationReceipt, ...]:
    """Certify every nonzero fixed count, omitting failed counts exactly."""

    _validate_width(width)
    _validate_direction(direction)
    receipts: list[StructuralRuleCompilationReceipt] = []
    for count in range(1, width):
        source_name = f"{direction}_{width}_{count}"
        pattern, replacement = build_rotate_identity(width, direction, count)
        try:
            verdict = prove_typed_term_equivalence(pattern, replacement)
        except (ImportError, OSError):
            verdict = False
        if verdict is True:
            rule = _enroll(
                CompiledEgglogStructuralRule(
                    source_name=source_name,
                    width=width,
                    direction=direction,
                    count=count,
                    pattern=pattern,
                    replacement=replacement,
                    proof_verdict=True,
                )
            )
            receipts.append(
                StructuralRuleCompilationReceipt(
                    source_name=source_name,
                    status=StructuralRuleStatus.COMPILED,
                    width=width,
                    direction=direction,
                    count=count,
                    proof_verdict=True,
                    compiled_rule=rule,
                )
            )
        else:
            receipts.append(
                StructuralRuleCompilationReceipt(
                    source_name=source_name,
                    status=StructuralRuleStatus.REJECTED,
                    width=width,
                    direction=direction,
                    count=count,
                    proof_verdict=False,
                    refusal_reason="typed_z3_proof_failed",
                )
            )
    return tuple(receipts)


@functools.lru_cache(maxsize=1)
def compile_all_fixed_rotate_rules() -> tuple[StructuralRuleCompilationReceipt, ...]:
    """Return deterministic receipts for both directions and all widths."""

    return tuple(
        receipt
        for width in STRUCTURAL_RULE_WIDTHS
        for direction in ("rol", "ror")
        for receipt in compile_fixed_rotate_rules(width=width, direction=direction)
    )


def _match_term(
    pattern: TypedBvTerm,
    candidate: TypedBvTerm,
    bindings: dict[tuple[object, ...], TypedBvTerm],
    remaining_comparisons: list[int],
) -> bool:
    remaining_comparisons[0] -= 1
    if remaining_comparisons[0] < 0:
        from d810.backends.mba.compiled_pattern_catalogue import (
            CanonicalPatternComparisonBudgetExceeded,
        )

        raise CanonicalPatternComparisonBudgetExceeded(
            "structural matcher comparison budget exhausted"
        )
    if pattern.width != candidate.width:
        return False
    if pattern.operation is None:
        if pattern.leaf_key == _STRUCTURAL_VARIABLE:
            previous = bindings.get(_STRUCTURAL_VARIABLE)
            if previous is None:
                bindings[_STRUCTURAL_VARIABLE] = candidate
                return True
            return previous == candidate
        return pattern == candidate
    if pattern.operation != candidate.operation:
        return False
    if pattern.operation in {"shl", "lshr", "rol", "ror"}:
        if pattern.shift_count != candidate.shift_count:
            return False
    if len(pattern.children) != len(candidate.children):
        return False
    if pattern.operation == "or":
        for order in ((0, 1), (1, 0)):
            local = dict(bindings)
            if all(
                _match_term(
                    pattern.children[index],
                    candidate.children[order[index]],
                    local,
                    remaining_comparisons,
                )
                for index in range(2)
            ):
                bindings.clear()
                bindings.update(local)
                return True
        return False
    return all(
        _match_term(
            pattern_child,
            candidate_child,
            bindings,
            remaining_comparisons,
        )
        for pattern_child, candidate_child in zip(
            pattern.children, candidate.children, strict=True
        )
    )


def _materialize(
    term: TypedBvTerm, bindings: Mapping[tuple[object, ...], TypedBvTerm]
) -> TypedBvTerm:
    if term.operation is None:
        if term.leaf_key == _STRUCTURAL_VARIABLE:
            return bindings[_STRUCTURAL_VARIABLE]
        return term
    return TypedBvTerm(
        term.operation,
        term.width,
        children=tuple(_materialize(child, bindings) for child in term.children),
        shift_count=term.shift_count,
    )


def _canonical_rotation_result_key(
    replacement: TypedBvTerm,
) -> tuple[int, int, str]:
    """Return one direction-independent key for a rotate result."""

    if (
        replacement.operation not in {"rol", "ror"}
        or type(replacement.shift_count) is not int
        or len(replacement.children) != 1
    ):
        raise ValueError("fixed-rotate rule has a malformed replacement")
    canonical_left_count = (
        replacement.shift_count
        if replacement.operation == "rol"
        else replacement.width - replacement.shift_count
    ) % replacement.width
    return (
        replacement.width,
        canonical_left_count,
        term_fingerprint(replacement.children[0]),
    )


def _canonical_rule_application_key(
    rule: CompiledEgglogStructuralRule,
) -> tuple[str, tuple[int, int, str]]:
    """Keep only aliases with the same AC-normalized source and result."""

    return (
        term_fingerprint(canonicalize_ac_term(rule.pattern)),
        _canonical_rotation_result_key(rule.replacement),
    )


def _deduplicated_application_rules(
    rules: tuple[CompiledEgglogStructuralRule, ...],
) -> tuple[tuple[CompiledEgglogStructuralRule, int], ...]:
    """Merge semantic rotate aliases without dropping proof receipts."""

    applications: list[tuple[CompiledEgglogStructuralRule, int]] = []
    application_index_by_key: dict[tuple[str, tuple[int, int, str]], int] = {}
    for declaration_index, rule in enumerate(rules):
        key = _canonical_rule_application_key(rule)
        application_index = application_index_by_key.get(key)
        if application_index is None:
            application_index_by_key[key] = len(applications)
            applications.append((rule, declaration_index))
            continue
        primary, primary_declaration_index = applications[application_index]
        aliases = tuple(
            dict.fromkeys((*primary.aliases, rule.source_name, *rule.aliases))
        )
        applications[application_index] = (
            _enroll(replace(primary, aliases=aliases)),
            primary_declaration_index,
        )
    return tuple(applications)


@dataclass(frozen=True, slots=True)
class StructuralRuleCatalogue:
    """Immutable declaration-ordered catalogue of admitted structural rules."""

    rules: tuple[CompiledEgglogStructuralRule, ...]
    _application_rules: tuple[tuple[CompiledEgglogStructuralRule, int], ...] = field(
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        frozen = tuple(self.rules)
        if any(not is_admitted_structural_rule(rule) for rule in frozen):
            raise ValueError("structural catalogue requires admitted rules")
        object.__setattr__(self, "rules", frozen)
        object.__setattr__(
            self,
            "_application_rules",
            _deduplicated_application_rules(frozen),
        )

    def canonical_applications(
        self,
        candidate: TypedBvTerm,
        *,
        comparison_budget: int = 256,
    ) -> tuple[tuple[CompiledEgglogStructuralRule, TypedBvTerm, int], ...]:
        if type(comparison_budget) is not int or comparison_budget <= 0:
            raise ValueError("comparison_budget must be a positive integer")
        applications: list[
            tuple[CompiledEgglogStructuralRule, TypedBvTerm, int]
        ] = []
        application_index_by_result: dict[tuple[int, int, str], int] = {}

        canonical_candidate = canonicalize_ac_term(candidate)
        remaining_comparisons = [comparison_budget]
        for rule, declaration_index in self._application_rules:
            if rule.width != canonical_candidate.width:
                continue
            bindings: dict[tuple[object, ...], TypedBvTerm] = {}
            if not _match_term(
                rule.pattern,
                canonical_candidate,
                bindings,
                remaining_comparisons,
            ):
                continue
            replacement = _materialize(rule.replacement, bindings)
            result_key = _canonical_rotation_result_key(replacement)
            application_index = application_index_by_result.get(result_key)
            if application_index is None:
                application_index_by_result[result_key] = len(applications)
                applications.append((rule, replacement, declaration_index))
                continue
            primary, primary_replacement, primary_declaration_index = applications[
                application_index
            ]
            aliases = tuple(
                dict.fromkeys((*primary.aliases, rule.source_name, *rule.aliases))
            )
            applications[application_index] = (
                _enroll(replace(primary, aliases=aliases)),
                primary_replacement,
                primary_declaration_index,
            )
        return tuple(applications)


def structural_catalogue_for_rules(
    rules: Collection[CompiledEgglogStructuralRule],
) -> StructuralRuleCatalogue:
    return StructuralRuleCatalogue(tuple(rules))


__all__ = [
    "CompiledEgglogStructuralRule",
    "STRUCTURAL_RULE_FAMILY",
    "STRUCTURAL_RULE_WIDTHS",
    "StructuralRuleCatalogue",
    "StructuralRuleCompilationReceipt",
    "StructuralRuleStatus",
    "build_rotate_identity",
    "compile_all_fixed_rotate_rules",
    "compile_fixed_rotate_rules",
    "is_admitted_structural_rule",
    "prove_typed_term_equivalence",
    "structural_catalogue_for_rules",
]
