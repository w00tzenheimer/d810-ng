from __future__ import annotations

import hashlib
import json

import pytest

from d810.mba.certified_catalogue import (
    ShadowMatcherParityLedger,
    StructuralMatcherParityCertificate,
    StructuralMatcherParityExpectation,
    build_certified_catalogue_snapshot,
    load_structural_matcher_parity_certificate,
    make_structural_matcher_parity_certificate,
)
from d810.mba.dsl import Var


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


class _DifferentImplementationRule(_SemanticRule):
    def check_candidate(self, candidate) -> bool:
        return not bool(candidate)


_HOOK_GLOBAL_LIMIT = 1
_UNFINGERPRINTABLE_HOOK_GLOBAL = object()


class _GlobalConstraintRule(_SemanticRule):
    def check_candidate(self, candidate) -> bool:
        return candidate == _HOOK_GLOBAL_LIMIT


class _UnfingerprintableGlobalRule(_SemanticRule):
    def check_candidate(self, candidate) -> bool:
        return candidate is _UNFINGERPRINTABLE_HOOK_GLOBAL


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


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
    )
    certificate_path = tmp_path / "parity.json"
    certificate_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "snapshot_fingerprint": snapshot.fingerprint,
                "runtime_mode": "cython",
                "corpus_digest": expectation.corpus_digest,
                "toolchain_digest": expectation.toolchain_digest,
                "legacy_observation_count": expectation.legacy_observation_count,
                "legacy_rule_mismatches": 0,
                "legacy_binding_mismatches": 0,
                "legacy_binding_unknown": 0,
                "new_safe_coverage_pending": 0,
                "new_safe_coverage_proved": 0,
            }
        ),
        encoding="utf-8",
    )

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

    certificate_path.write_text(
        json.dumps({"schema_version": 1}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="schema_version must be 2"):
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

    assert certificate["schema_version"] == 2
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

    assert ledger.observation_count == 5
    assert ledger.legacy_match_count == 3
    assert ledger.legacy_rule_mismatches == 1
    assert ledger.legacy_binding_mismatches == 1
    assert ledger.legacy_binding_unknown == 1
    assert ledger.new_safe_coverage_pending == 1
    assert ledger.new_safe_coverage_proved == 1
