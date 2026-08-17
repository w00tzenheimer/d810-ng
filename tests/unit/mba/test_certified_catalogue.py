from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from d810.core.logging import getLogger
from d810.backends.mba.egglog_add_rule_compiler import compile_mba_rule_catalogue
from d810.mba.certified_catalogue import (
    ShadowMatcherParityLedger,
    StructuralMatcherParityCertificate,
    StructuralMatcherParityExpectation,
    build_certified_catalogue_snapshot,
    load_structural_matcher_parity_certificate,
    make_structural_matcher_parity_certificate,
)
from d810.mba.dsl import Const, Var, Zext
from d810.mba.semantic_canonicalization import CANONICALIZER_SCHEMA_VERSION


class _Rule:
    def __init__(self, name: str, pattern, family: str = "add") -> None:
        self.source_name = name
        self.pattern = pattern
        self.family = family


class _SemanticRule(_Rule):
    def __init__(
        self,
        name: str,
        pattern,
        replacement,
        *,
        constraints: tuple[str, ...] = (),
    ) -> None:
        super().__init__(name, pattern)
        self.replacement = replacement
        self.CONSTRAINTS = constraints

    def check_candidate(self, candidate) -> bool:
        return bool(candidate)


class _CanonicalIneligibleRule(_Rule):
    def __init__(self, proof_widths: tuple[int, ...]) -> None:
        super().__init__("canonical-ineligible", Zext(Var("x"), 64))
        self.replacement = Var("x")
        self.proof_widths = proof_widths


class _DifferentImplementationRule(_SemanticRule):
    def check_candidate(self, candidate) -> bool:
        return not bool(candidate)


def _runtime_bound_rule(pattern, replacement):
    """Build a rule hook whose closure retains the live rule instance."""

    class _RuntimeBoundRule(_SemanticRule):
        pass

    rule = _RuntimeBoundRule("runtime-bound", pattern, replacement)

    def check_candidate(candidate) -> bool:
        return rule._current_blk is None and bool(candidate)

    _RuntimeBoundRule.check_candidate = staticmethod(check_candidate)
    return rule


_HOOK_GLOBAL_LIMIT = 1
_UNFINGERPRINTABLE_HOOK_GLOBAL = object()
_SEMANTIC_TEST_LOGGER = getLogger(__name__)


class _GlobalConstraintRule(_SemanticRule):
    def check_candidate(self, candidate) -> bool:
        return candidate == _HOOK_GLOBAL_LIMIT


class _UnfingerprintableGlobalRule(_SemanticRule):
    def check_candidate(self, candidate) -> bool:
        return candidate is _UNFINGERPRINTABLE_HOOK_GLOBAL


class _RuntimeLoggingRule(_SemanticRule):
    """Real rule hooks may report refusals without logging state being semantic."""

    def check_candidate(self, candidate) -> bool:
        _SEMANTIC_TEST_LOGGER.debug("candidate rejected: %r", candidate)
        return bool(candidate)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _first_difference(before: object, after: object, path: tuple[object, ...] = ()):
    if type(before) is not type(after):
        return path
    if isinstance(before, dict):
        for key in sorted(set(before) | set(after), key=str):
            if key not in before or key not in after:
                return path + (key,)
            difference = _first_difference(before[key], after[key], path + (key,))
            if difference is not None:
                return difference
        return None
    if isinstance(before, (tuple, list)):
        if len(before) != len(after):
            return path
        for index, (before_item, after_item) in enumerate(zip(before, after)):
            difference = _first_difference(
                before_item, after_item, path + (index,)
            )
            if difference is not None:
                return difference
        return None
    return None if before == after else path


@dataclass(frozen=True)
class _AuthorizationCase:
    snapshot: object
    certificate: StructuralMatcherParityCertificate
    certificate_payload: dict[str, object]
    certificate_path: Path
    runtime_mode: str
    expectation: StructuralMatcherParityExpectation


def _generated_authorization_case(tmp_path: Path) -> _AuthorizationCase:
    """Build the valid baseline through the production certificate generator."""

    x, y = Var("x"), Var("y")
    snapshot = build_certified_catalogue_snapshot(
        (_SemanticRule("task5-valid", x + y, x ^ y),),
        compiler_version="task5-valid-v1",
        widths=(32,),
    )
    ledger = ShadowMatcherParityLedger(observation_count=3, legacy_match_count=2)
    corpus_digest = _digest("task5-corpus")
    toolchain_digest = _digest("task5-toolchain")
    payload = make_structural_matcher_parity_certificate(
        snapshot=snapshot,
        ledger=ledger,
        runtime_mode="python",
        corpus_digest=corpus_digest,
        toolchain_digest=toolchain_digest,
    )
    path = tmp_path / "task5-valid-certificate.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    certificate = load_structural_matcher_parity_certificate(path)
    expectation = StructuralMatcherParityExpectation(
        corpus_digest=corpus_digest,
        toolchain_digest=toolchain_digest,
        legacy_observation_count=ledger.legacy_match_count,
        observation_count=ledger.observation_count,
    )
    return _AuthorizationCase(
        snapshot=snapshot,
        certificate=certificate,
        certificate_payload=payload,
        certificate_path=path,
        runtime_mode="python",
        expectation=expectation,
    )


def _load_mutated_certificate(
    case: _AuthorizationCase, **changes: object
) -> StructuralMatcherParityCertificate | None:
    payload = dict(case.certificate_payload)
    payload.update(changes)
    path = case.certificate_path.with_name("task5-mutated-certificate.json")
    path.write_text(json.dumps(payload), encoding="utf-8")
    try:
        return load_structural_matcher_parity_certificate(path)
    except ValueError:
        return None


_MISSING_CERTIFICATE = object()
_MISSING_EXPECTATION = object()


def _inputs(
    case: _AuthorizationCase,
    certificate: StructuralMatcherParityCertificate | None | object = _MISSING_CERTIFICATE,
    *,
    snapshot: object | None = None,
    runtime_mode: str | None = None,
    expectation: StructuralMatcherParityExpectation | None | object = _MISSING_EXPECTATION,
) -> tuple[object | None, object, str, StructuralMatcherParityExpectation | None]:
    return (
        case.certificate if certificate is _MISSING_CERTIFICATE else certificate,
        case.snapshot if snapshot is None else snapshot,
        case.runtime_mode if runtime_mode is None else runtime_mode,
        case.expectation if expectation is _MISSING_EXPECTATION else expectation,
    )


def _without_certificate(case: _AuthorizationCase):
    return _inputs(case, None)


def _with_old_schema(case: _AuthorizationCase):
    return _inputs(case, _load_mutated_certificate(case, schema_version=2))


def _with_wrong_canonicalizer(case: _AuthorizationCase):
    return _inputs(
        case,
        replace(case.certificate, canonicalizer_schema_version=99),
    )


def _with_wrong_snapshot(case: _AuthorizationCase):
    return _inputs(
        case,
        replace(case.certificate, snapshot_fingerprint=_digest("wrong-snapshot")),
    )


def _with_wrong_runtime(case: _AuthorizationCase):
    return _inputs(case, replace(case.certificate, runtime_mode="cython"))


def _with_wrong_corpus(case: _AuthorizationCase):
    return _inputs(case, replace(case.certificate, corpus_digest=_digest("wrong")))


def _with_wrong_toolchain(case: _AuthorizationCase):
    return _inputs(
        case,
        replace(case.certificate, toolchain_digest=_digest("wrong-toolchain")),
    )


def _with_wrong_observation_count(case: _AuthorizationCase):
    return _inputs(
        case,
        _load_mutated_certificate(
            case,
            observation_count=int(case.certificate_payload["observation_count"]) + 1,
        ),
    )


def _with_rule_mismatch(case: _AuthorizationCase):
    return _inputs(case, _load_mutated_certificate(case, legacy_rule_mismatches=1))


def _with_binding_mismatch(case: _AuthorizationCase):
    return _inputs(
        case,
        _load_mutated_certificate(case, legacy_binding_mismatches=1),
    )


def _with_binding_unknown(case: _AuthorizationCase):
    return _inputs(case, _load_mutated_certificate(case, legacy_binding_unknown=1))


def _with_pending_coverage(case: _AuthorizationCase):
    return _inputs(case, _load_mutated_certificate(case, new_safe_coverage_pending=1))


def _with_unsafe_mutation(case: _AuthorizationCase):
    return _inputs(case, _load_mutated_certificate(case, unsafe_mutations=1))


def _with_unproved_replacement(case: _AuthorizationCase):
    return _inputs(
        case,
        _load_mutated_certificate(case, unproved_structural_replacements=1),
    )


def _with_boolean_rule_mismatch(case: _AuthorizationCase):
    return _inputs(case, _load_mutated_certificate(case, legacy_rule_mismatches=False))


def _with_non_authorizable_snapshot(case: _AuthorizationCase):
    return _inputs(
        case,
        snapshot=replace(case.snapshot, structural_authorizable=False),
    )


def _without_project_expectation(case: _AuthorizationCase):
    return _inputs(case, expectation=None)


def _unchanged_valid_evidence(case: _AuthorizationCase):
    return _inputs(case)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (_without_certificate, False),
        (_with_old_schema, False),
        (_with_wrong_canonicalizer, False),
        (_with_wrong_snapshot, False),
        (_with_wrong_runtime, False),
        (_with_wrong_corpus, False),
        (_with_wrong_toolchain, False),
        (_with_wrong_observation_count, False),
        (_with_rule_mismatch, False),
        (_with_binding_mismatch, False),
        (_with_binding_unknown, False),
        (_with_pending_coverage, False),
        (_with_unsafe_mutation, False),
        (_with_unproved_replacement, False),
        (_with_boolean_rule_mismatch, False),
        (_with_non_authorizable_snapshot, False),
        (_without_project_expectation, False),
        (_unchanged_valid_evidence, True),
    ],
)
def test_structural_authorization_fails_closed_per_bound_input(
    tmp_path: Path, mutation, expected: bool
) -> None:
    case = _generated_authorization_case(tmp_path)
    certificate, snapshot, runtime_mode, expectation = mutation(case)
    authorized = bool(
        certificate is not None
        and certificate.authorizes(snapshot, runtime_mode, expectation)
    )
    assert authorized is expected


@pytest.mark.parametrize(
    "field",
    (
        "canonicalizer_schema_version",
        "legacy_observation_count",
        "observation_count",
        "new_safe_coverage_proved",
    ),
)
def test_parity_certificate_loader_rejects_boolean_integer_fields(
    tmp_path: Path, field: str
) -> None:
    case = _generated_authorization_case(tmp_path)
    payload = dict(case.certificate_payload)
    payload[field] = True
    path = tmp_path / f"boolean-{field}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError):
        load_structural_matcher_parity_certificate(path)


def test_authorization_rejects_boolean_schema_and_count_dataclass_inputs(
    tmp_path: Path,
) -> None:
    case = _generated_authorization_case(tmp_path)

    assert not replace(
        case.certificate, canonicalizer_schema_version=True
    ).authorizes(case.snapshot, case.runtime_mode, case.expectation)
    assert not replace(
        case.certificate, legacy_observation_count=True
    ).authorizes(case.snapshot, case.runtime_mode, case.expectation)
    with pytest.raises(ValueError, match="canonicalizer schema version"):
        replace(case.snapshot, canonicalizer_schema_version=True)


def test_snapshot_is_memoized_immutable_and_preserves_declaration_order() -> None:
    x, y = Var("x"), Var("y")
    first = _Rule("later_alphabetically", x + y)
    second = _Rule("earlier_alphabetically", x ^ y)

    snapshot = build_certified_catalogue_snapshot(
        (first, second), compiler_version="v1"
    )
    same = build_certified_catalogue_snapshot((first, second), compiler_version="v1")

    assert snapshot is same
    assert snapshot.rules_in_declaration_order == (first, second)
    assert snapshot.rule_ids_by_root_shape[("add", 32, 2)] == (0,)
    assert snapshot.rule_ids_by_root_shape[("xor", 32, 2)] == (1,)
    assert ("sub", 32, 2) not in snapshot.rule_ids_by_root_shape
    try:
        snapshot.rule_ids_by_root_shape[("sub", 32, 2)] = (0,)  # type: ignore[index]
    except TypeError:
        pass
    else:
        raise AssertionError("snapshot index must be immutable")


def test_snapshot_fingerprint_changes_with_content_version_or_enabled_families() -> (
    None
):
    x, y = Var("x"), Var("y")
    first = build_certified_catalogue_snapshot(
        (_Rule("one", x + y),), compiler_version="v1"
    )
    changed_rule = build_certified_catalogue_snapshot(
        (_Rule("two", x + y),), compiler_version="v1"
    )
    changed_version = build_certified_catalogue_snapshot(
        (_Rule("one", x + y),), compiler_version="v2"
    )
    changed_widths = build_certified_catalogue_snapshot(
        (_Rule("one", x + y),), compiler_version="v1", widths=(32,)
    )
    changed_families = build_certified_catalogue_snapshot(
        (_Rule("one", x + y),), compiler_version="v1", enabled_families=("add",)
    )

    assert first.fingerprint != changed_rule.fingerprint
    assert first.fingerprint != changed_version.fingerprint
    assert first.fingerprint != changed_widths.fingerprint
    assert first.fingerprint != changed_families.fingerprint


def test_snapshot_fingerprint_binds_replacement_constraints_and_implementation() -> None:
    x, y = Var("x"), Var("y")
    baseline = build_certified_catalogue_snapshot(
        (_SemanticRule("one", x + y, x ^ y, constraints=("same",)),),
        compiler_version="v1",
    )
    changed_replacement = build_certified_catalogue_snapshot(
        (_SemanticRule("one", x + y, x | y, constraints=("same",)),),
        compiler_version="v1",
    )
    changed_constraints = build_certified_catalogue_snapshot(
        (_SemanticRule("one", x + y, x ^ y, constraints=("different",)),),
        compiler_version="v1",
    )
    changed_implementation = build_certified_catalogue_snapshot(
        (_DifferentImplementationRule("one", x + y, x ^ y, constraints=("same",)),),
        compiler_version="v1",
    )

    assert baseline.fingerprint != changed_replacement.fingerprint
    assert baseline.fingerprint != changed_constraints.fingerprint
    assert baseline.fingerprint != changed_implementation.fingerprint


def test_snapshot_fingerprint_binds_referenced_hook_global_values(monkeypatch) -> None:
    x, y = Var("x"), Var("y")
    baseline = build_certified_catalogue_snapshot(
        (_GlobalConstraintRule("one", x + y, x ^ y),),
        compiler_version="global-values-v1",
    )

    monkeypatch.setattr(
        "tests.unit.mba.test_certified_catalogue._HOOK_GLOBAL_LIMIT", 2
    )
    changed = build_certified_catalogue_snapshot(
        (_GlobalConstraintRule("one", x + y, x ^ y),),
        compiler_version="global-values-v1",
    )

    assert baseline.fingerprint != changed.fingerprint


def test_snapshot_fingerprint_ignores_transient_rule_state() -> None:
    x, y = Var("x"), Var("y")
    rule = _runtime_bound_rule(x + y, x ^ y)
    rule.config = {"generate_commutative_permutations": True}
    baseline = build_certified_catalogue_snapshot(
        (rule,), compiler_version="runtime-state-v1", widths=(8,)
    )

    rule._current_blk = object()
    rule._current_ins = object()
    rule._runtime_constant_evaluator = lambda candidate: candidate
    with_runtime_state = build_certified_catalogue_snapshot(
        (rule,), compiler_version="runtime-state-v1", widths=(8,)
    )

    assert with_runtime_state.fingerprint == baseline.fingerprint


def test_snapshot_fingerprint_binds_stable_rule_config() -> None:
    x, y = Var("x"), Var("y")
    rule = _SemanticRule("configured", x + y, x ^ y)
    rule.config = {"generate_commutative_permutations": True}
    baseline = build_certified_catalogue_snapshot(
        (rule,), compiler_version="runtime-state-v1", widths=(8,)
    )

    rule.config = {"generate_commutative_permutations": False}
    with_changed_config = build_certified_catalogue_snapshot(
        (rule,), compiler_version="runtime-state-v1", widths=(8,)
    )
    assert with_changed_config.fingerprint != baseline.fingerprint


def test_snapshot_and_template_fingerprints_ignore_operational_logger_state() -> None:
    from d810.mba import canonical_pattern
    from d810.mba.rules import _base as rule_base

    x, y = Var("x"), Var("y")
    rule = _SemanticRule("logger-state", x + y, x ^ y)

    def semantic_payload() -> dict[str, object]:
        compiled = canonical_pattern.compile_canonical_pattern(
            rule, width=8, declaration_index=0
        )
        return canonical_pattern._rule_semantic_payload(
            rule,
            width=8,
            pattern_term=compiled.pattern_term,
            replacement_template=compiled.replacement_template,
            terminal_kinds=compiled.terminal_kinds,
        )

    baseline_payload = semantic_payload()
    baseline_snapshot = build_certified_catalogue_snapshot(
        (rule,), compiler_version="logger-state-v1", widths=(8,)
    )
    logger = rule_base.logger
    previous_cache = logger.__dict__.get("_cache")
    try:
        logger.__dict__["_cache"] = {"task5": (1, 2, 3)}
        changed_payload = semantic_payload()
        changed_snapshot = build_certified_catalogue_snapshot(
            (rule,), compiler_version="logger-state-v1", widths=(8,)
        )
    finally:
        if previous_cache is None:
            logger.__dict__.pop("_cache", None)
        else:
            logger.__dict__["_cache"] = previous_cache

    difference = _first_difference(baseline_payload, changed_payload)
    assert difference is None, f"semantic payload drift at {difference}"
    assert (
        baseline_snapshot.canonical_templates_by_rule_width[(0, 8)]
        == changed_snapshot.canonical_templates_by_rule_width[(0, 8)]
    )
    assert baseline_snapshot.fingerprint == changed_snapshot.fingerprint


def test_snapshot_records_width_specific_canonical_templates_and_version() -> None:
    rule = compile_mba_rule_catalogue().receipt_for(
        "add", "Add_HackersDelightRule_2"
    ).compiled_rule
    assert rule is not None
    snapshot = build_certified_catalogue_snapshot(
        (rule,), compiler_version="canonical-v1", widths=(32,)
    )

    assert snapshot.canonicalizer_schema_version == CANONICALIZER_SCHEMA_VERSION
    template = snapshot.canonical_templates_by_rule_width[(0, 32)]
    assert template["width"] == 32
    assert template["semantic_fingerprint"]
    assert template["pattern"] != template["replacement"]


def test_snapshot_authorizes_supported_pattern_with_unsupported_replacement() -> None:
    """An unsupported replacement must not make its supported pattern opaque."""

    x = Var("x")
    rule = _SemanticRule(
        "supported-pattern-unsupported-shift-replacement",
        x + Const("one", 1),
        x << Const("shift", 1),
    )

    snapshot = build_certified_catalogue_snapshot(
        (rule,), compiler_version="unsupported-shift-replacement-v1", widths=(32,)
    )

    assert snapshot.canonical_status_by_rule_width[(0, 32)] == "unsupported"
    assert snapshot.structural_authorizable is True


def test_snapshot_fingerprint_binds_proof_widths_for_canonical_ineligible_rule() -> None:
    baseline = build_certified_catalogue_snapshot(
        (_CanonicalIneligibleRule((32,)),),
        compiler_version="canonical-ineligible-v1",
        widths=(32,),
    )
    changed = build_certified_catalogue_snapshot(
        (_CanonicalIneligibleRule((64,)),),
        compiler_version="canonical-ineligible-v1",
        widths=(32,),
    )

    assert baseline.fingerprint != changed.fingerprint
    assert baseline.canonical_templates_by_rule_width == {}
    assert baseline.canonical_status_by_rule_width[(0, 32)] == "unsupported"


def test_snapshot_with_unfingerprintable_hook_global_cannot_authorize() -> None:
    x, y = Var("x"), Var("y")
    snapshot = build_certified_catalogue_snapshot(
        (_UnfingerprintableGlobalRule("one", x + y, x ^ y),),
        compiler_version="unfingerprintable-global-v1",
    )
    expectation = StructuralMatcherParityExpectation(
        corpus_digest=_digest("native-corpus"),
        toolchain_digest=_digest("ida-9.4-cython"),
        legacy_observation_count=1,
    )
    certificate = StructuralMatcherParityCertificate(
        snapshot_fingerprint=snapshot.fingerprint,
        runtime_mode="cython",
        corpus_digest=expectation.corpus_digest,
        toolchain_digest=expectation.toolchain_digest,
        legacy_observation_count=expectation.legacy_observation_count,
    )

    assert snapshot.structural_authorizable is False
    assert not certificate.authorizes(snapshot, "cython", expectation)


def test_snapshot_ignores_the_known_operational_d810_logger() -> None:
    x, y = Var("x"), Var("y")

    snapshot = build_certified_catalogue_snapshot(
        (_RuntimeLoggingRule("one", x + y, x ^ y),),
        compiler_version="operational-logger-v1",
    )

    assert snapshot.structural_authorizable is True


def test_parity_certificate_requires_exact_expected_corpus_toolchain_and_coverage(
    tmp_path,
) -> None:
    x, y = Var("x"), Var("y")
    snapshot = build_certified_catalogue_snapshot(
        (_SemanticRule("one", x + y, x ^ y),), compiler_version="v1"
    )
    expectation = StructuralMatcherParityExpectation(
        corpus_digest=_digest("native-corpus"),
        toolchain_digest=_digest("ida-9.4-cython"),
        legacy_observation_count=17,
        observation_count=17,
    )
    certificate_path = tmp_path / "parity.json"
    payload = make_structural_matcher_parity_certificate(
        snapshot=snapshot,
        ledger=ShadowMatcherParityLedger(
            observation_count=17,
            legacy_match_count=17,
        ),
        runtime_mode="cython",
        corpus_digest=expectation.corpus_digest,
        toolchain_digest=expectation.toolchain_digest,
    )
    certificate_path.write_text(json.dumps(payload), encoding="utf-8")

    certificate = load_structural_matcher_parity_certificate(certificate_path)
    assert certificate.authorizes(snapshot, "cython", expectation)
    assert not certificate.authorizes(
        snapshot,
        "cython",
        StructuralMatcherParityExpectation(
            corpus_digest=_digest("other-corpus"),
            toolchain_digest=expectation.toolchain_digest,
            legacy_observation_count=17,
        ),
    )
    assert not certificate.authorizes(
        snapshot,
        "cython",
        StructuralMatcherParityExpectation(
            corpus_digest=expectation.corpus_digest,
            toolchain_digest=_digest("other-toolchain"),
            legacy_observation_count=17,
        ),
    )
    assert not certificate.authorizes(
        snapshot,
        "cython",
        StructuralMatcherParityExpectation(
            corpus_digest=expectation.corpus_digest,
            toolchain_digest=expectation.toolchain_digest,
            legacy_observation_count=18,
        ),
    )

    stale_payload = dict(payload)
    stale_payload["schema_version"] = 1
    certificate_path.write_text(json.dumps(stale_payload), encoding="utf-8")
    with pytest.raises(ValueError, match="schema_version must be 3"):
        load_structural_matcher_parity_certificate(certificate_path)


def test_parity_certificate_generator_refuses_nonzero_or_incomplete_ledger() -> None:
    x, y = Var("x"), Var("y")
    snapshot = build_certified_catalogue_snapshot(
        (_SemanticRule("one", x + y, x ^ y),), compiler_version="v1"
    )
    ledger = ShadowMatcherParityLedger(observation_count=7, legacy_match_count=7)

    certificate = make_structural_matcher_parity_certificate(
        snapshot=snapshot,
        ledger=ledger,
        runtime_mode="python",
        corpus_digest=_digest("manifest"),
        toolchain_digest=_digest("ida-python"),
    )

    assert certificate["schema_version"] == 3
    assert certificate["snapshot_fingerprint"] == snapshot.fingerprint
    assert certificate["legacy_observation_count"] == 7
    with pytest.raises(ValueError, match="legacy_rule_mismatches=0"):
        make_structural_matcher_parity_certificate(
                snapshot=snapshot,
                ledger=ShadowMatcherParityLedger(
                    observation_count=1,
                    legacy_match_count=1,
                    legacy_rule_mismatches=1,
                ),
            runtime_mode="python",
            corpus_digest=_digest("manifest"),
            toolchain_digest=_digest("ida-python"),
        )


def test_enabled_families_filter_rules_before_root_bucket_indexing() -> None:
    x, y = Var("x"), Var("y")
    add_rule = _Rule("add", x + y, family="add")
    xor_rule = _Rule("xor", x ^ y, family="xor")

    snapshot = build_certified_catalogue_snapshot(
        (add_rule, xor_rule),
        compiler_version="v1",
        enabled_families=("add",),
    )

    assert snapshot.rules_in_declaration_order == (add_rule,)
    assert snapshot.rule_ids_by_root_shape == {
        ("add", 8, 2): (0,),
        ("add", 16, 2): (0,),
        ("add", 32, 2): (0,),
        ("add", 64, 2): (0,),
    }


def test_shadow_ledger_counts_only_evidence_backed_legacy_parity_mismatches() -> None:
    ledger = ShadowMatcherParityLedger()

    ledger.record(
        legacy_match=False, structural_match=True, same_rule=False, same_bindings=None
    )
    ledger.record(
        legacy_match=True, structural_match=True, same_rule=True, same_bindings=True
    )
    ledger.record(
        legacy_match=True, structural_match=True, same_rule=True, same_bindings=None
    )
    ledger.record(
        legacy_match=True, structural_match=False, same_rule=False, same_bindings=False
    )
    ledger.record(
        legacy_match=False,
        structural_match=True,
        same_rule=False,
        same_bindings=None,
        structural_proven=True,
    )
    ledger.record(
        legacy_match=False,
        structural_match=True,
        same_rule=False,
        same_bindings=None,
        structural_refused=True,
    )

    assert ledger.observation_count == 6
    assert ledger.legacy_match_count == 3
    assert ledger.legacy_rule_mismatches == 1
    assert ledger.legacy_binding_mismatches == 1
    assert ledger.legacy_binding_unknown == 1
    assert ledger.new_safe_coverage_pending == 1
    assert ledger.new_safe_coverage_proved == 1
    assert ledger.new_safe_coverage_refused == 1
