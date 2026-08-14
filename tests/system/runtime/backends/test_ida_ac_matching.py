from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

import d810.backends.mba.ida as ida_backend  # noqa: E402
from d810.backends.mba.ida import (  # noqa: E402
    IDAPatternAdapter,
    attach_selected_certified_catalogue_snapshot,
)
from d810.backends.mba.native_z3 import prove_native_ast_equivalence  # noqa: E402
from d810.hexrays.expr import ast as ast_dispatcher  # noqa: E402
from d810.hexrays.ir.mop_snapshot import MopSnapshot  # noqa: E402
from d810.mba.ac_matching import (  # noqa: E402
    AcMatchBindings,
    AcMatchReport,
    AcMatchStopReason,
)
from d810.mba.certified_catalogue import (  # noqa: E402
    ShadowMatcherParityLedger,
    load_structural_matcher_parity_certificate,
)
from d810.mba.dsl import Const, Var, Zext  # noqa: E402
from d810.optimizers.microcode.instructions.pattern_matching.handler import (  # noqa: E402
    PatternOptimizer,
    RulePatternInfo,
)
from d810.optimizers.microcode.instructions.pattern_matching.engine import (  # noqa: E402
    get_engine_info,
)


def _leaf(name: str, register: int):
    leaf = ast_dispatcher.AstLeaf(name)
    leaf.mop = MopSnapshot(t=ida_hexrays.mop_r, size=4, reg=register)
    leaf.dest_size = 4
    return leaf


def _constant(value: int):
    constant = ast_dispatcher.AstConstant(str(value), value, 4)
    constant.mop = MopSnapshot(t=ida_hexrays.mop_n, size=4, value=value)
    constant.dest_size = 4
    return constant


def test_shadow_matcher_resolves_only_original_native_binding_paths() -> None:
    x = Var("x")

    class Rule:
        pattern = x + Const("one", 1)

    adapter = IDAPatternAdapter(Rule())
    adapter._attempt_destination_size = 4
    ast = ast_dispatcher.AstNode(ida_hexrays.m_add, _constant(1), _leaf("x", 1))
    ast.dest_size = 4

    report = adapter.observe_structural_match(ast)

    assert report is not None
    assert report.stop_reason is AcMatchStopReason.MATCHED
    assert report.bindings is not None
    assert report.bindings.candidate_path_by_name == {"x": (1,), "one": (0,)}


def test_native_shadow_proof_uses_fixed_width_bit_vector_semantics() -> None:
    source = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("x", 1), _constant(0))
    source.dest_size = 4

    assert prove_native_ast_equivalence(source, source.left, width=32)
    assert not prove_native_ast_equivalence(source, _constant(1), width=32)
    assert not prove_native_ast_equivalence(source, source.left, width=7)


def test_shadow_matcher_never_claims_legacy_binding_parity() -> None:
    x = Var("x")

    class Rule:
        pattern = x + Const("one", 1)

    adapter = IDAPatternAdapter(Rule())
    adapter._attempt_destination_size = 4
    ast = ast_dispatcher.AstNode(ida_hexrays.m_add, _constant(1), _leaf("x", 1))
    ast.dest_size = 4

    assert adapter.observe_structural_match(ast) is not None

    metadata = adapter._shadow_metadata(legacy_match=True)

    assert metadata == {
        "legacy_match": True,
        "structural_match": True,
        "same_rule": True,
        "same_bindings": None,
    }


def test_shadow_matcher_compares_exact_legacy_native_paths_when_available() -> None:
    x = Var("x")

    class Rule:
        pattern = x + Const("one", 1)

    adapter = IDAPatternAdapter(Rule())
    adapter._attempt_destination_size = 4
    ast = ast_dispatcher.AstNode(ida_hexrays.m_add, _constant(1), _leaf("x", 1))
    ast.dest_size = 4

    assert adapter.observe_structural_match(ast) is not None
    legacy = ast_dispatcher.AstNode(
        ida_hexrays.m_add,
        ast_dispatcher.AstConstant("one", 1, 4),
        ast_dispatcher.AstLeaf("x"),
    )
    # Nomut patterns remain frozen and do not have matcher-populated bindings.
    assert legacy.leafs_by_name == {}
    adapter.record_legacy_match_bindings(legacy, ast)

    assert adapter._shadow_metadata(legacy_match=True)["same_bindings"] is True


def test_shadow_matcher_rejects_ambiguous_legacy_mop_paths() -> None:
    """Equal live mops in two slots cannot establish exact binding parity."""

    x, y = Var("x"), Var("y")

    class Rule:
        pattern = x + y

    adapter = IDAPatternAdapter(Rule())
    adapter._attempt_destination_size = 4
    ast = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("left", 1), _leaf("right", 1))
    ast.dest_size = 4

    assert adapter.observe_structural_match(ast) is not None
    adapter.record_legacy_match_bindings(
        type(
            "LegacyCandidate", (), {"leafs_by_name": {"x": ast.left, "y": ast.right}}
        )()
    )

    assert adapter._shadow_metadata(legacy_match=True)["same_bindings"] is None


def test_shadow_matcher_accepts_a_structural_path_for_repeated_pattern_leaf() -> None:
    """A repeated declared leaf has several valid source slots, unlike aliases."""

    x = Var("x")

    class Rule:
        pattern = x + x

    adapter = IDAPatternAdapter(Rule())
    adapter._attempt_destination_size = 4
    ast = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("left", 1), _leaf("right", 1))
    ast.dest_size = 4
    legacy = ast_dispatcher.AstNode(
        ida_hexrays.m_add,
        ast_dispatcher.AstLeaf("x"),
        ast_dispatcher.AstLeaf("x"),
    )
    legacy.leafs_by_name = {"x": legacy.right}

    assert adapter.observe_structural_match(ast) is not None
    adapter.record_legacy_match_bindings(legacy, ast)

    assert adapter._shadow_metadata(legacy_match=True)["same_bindings"] is True


def test_selected_snapshot_narrows_shadow_observation_without_compilation() -> None:
    x = Var("x")

    class AddRule:
        pattern = x + Const("one", 1)

    class XorRule:
        pattern = x ^ Const("one", 1)

    add_adapter = IDAPatternAdapter(AddRule())
    xor_adapter = IDAPatternAdapter(XorRule())
    snapshot, _ledger = attach_selected_certified_catalogue_snapshot(
        (add_adapter, xor_adapter)
    )
    assert snapshot.rules_in_declaration_order == (add_adapter.rule, xor_adapter.rule)

    xor_adapter._attempt_destination_size = 4
    ast = ast_dispatcher.AstNode(ida_hexrays.m_add, _constant(1), _leaf("x", 1))
    ast.dest_size = 4

    assert xor_adapter.observe_structural_match(ast) is None


def test_certified_registration_rejects_bare_structural_opt_in(
    monkeypatch,
) -> None:
    """The experimental flag cannot bypass persisted parity evidence."""

    x = Var("x")

    class DefaultRule:
        name = "CertifiedAdd"
        pattern = x + Const("one", 1)

    monkeypatch.delenv("D810_STRUCTURAL_DSL_MATCHING", raising=False)
    monkeypatch.delenv("D810_LEGACY_DSL_PERMUTATIONS", raising=False)
    default_legacy = IDAPatternAdapter(DefaultRule())
    attach_selected_certified_catalogue_snapshot((default_legacy,))

    assert default_legacy.uses_structural_matching is False
    assert len(default_legacy.pattern_candidates) == 2

    class OptInRule:
        name = "CertifiedAddOptIn"
        pattern = x + Const("one", 1)

    monkeypatch.setenv("D810_STRUCTURAL_DSL_MATCHING", "1")
    structural = IDAPatternAdapter(OptInRule())
    attach_selected_certified_catalogue_snapshot((structural,))

    assert structural.uses_structural_matching is False
    assert len(structural.pattern_candidates) == 2

    # The existing release-scoped rollback takes precedence over opt-in.
    monkeypatch.setenv("D810_LEGACY_DSL_PERMUTATIONS", "1")
    rollback = IDAPatternAdapter(OptInRule())
    attach_selected_certified_catalogue_snapshot((rollback,))

    assert rollback.uses_structural_matching is False
    assert len(rollback.pattern_candidates) == 2


def test_structural_opt_in_requires_matching_persisted_parity_certificate(
    monkeypatch, tmp_path
) -> None:
    """A certificate authorizes exactly its snapshot and active matcher mode."""

    x = Var("x")

    class CertifiedRule:
        name = "CertifiedAdd"
        pattern = x + Const("one", 1)

    assert ida_backend._supports_structural_dsl_pattern(CertifiedRule.pattern)
    monkeypatch.setenv("D810_STRUCTURAL_DSL_MATCHING", "1")
    monkeypatch.delenv("D810_LEGACY_DSL_PERMUTATIONS", raising=False)
    runtime_mode = get_engine_info()["backend"]
    warnings: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        ida_backend.logger,
        "warning",
        lambda *args: warnings.append(args),
    )

    probe = IDAPatternAdapter(CertifiedRule())
    snapshot, _ = attach_selected_certified_catalogue_snapshot((probe,))
    certificate_path = tmp_path / "structural-parity.json"
    certificate_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "snapshot_fingerprint": "0" * 64,
                "runtime_mode": runtime_mode,
                "corpus_identity": "controlled-native-corpus",
                "legacy_observation_count": 1,
                "legacy_rule_mismatches": 0,
                "legacy_binding_mismatches": 0,
                "legacy_binding_unknown": 0,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="new_safe_coverage_pending=0"):
        load_structural_matcher_parity_certificate(certificate_path)

    wrong_snapshot = IDAPatternAdapter(CertifiedRule())
    attach_selected_certified_catalogue_snapshot(
        (wrong_snapshot,),
        parity_certificate_path=certificate_path,
        runtime_mode=runtime_mode,
    )
    assert wrong_snapshot.uses_structural_matching is False

    other_runtime_mode = "cython" if runtime_mode == "python" else "python"
    certificate_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "snapshot_fingerprint": snapshot.fingerprint,
                "runtime_mode": other_runtime_mode,
                "corpus_identity": "controlled-native-corpus",
                "legacy_observation_count": 1,
                "legacy_rule_mismatches": 0,
                "legacy_binding_mismatches": 0,
                "legacy_binding_unknown": 0,
                "new_safe_coverage_pending": 0,
                "new_safe_coverage_proved": 0,
            }
        ),
        encoding="utf-8",
    )
    wrong_runtime = IDAPatternAdapter(CertifiedRule())
    attach_selected_certified_catalogue_snapshot(
        (wrong_runtime,),
        parity_certificate_path=certificate_path,
        runtime_mode=runtime_mode,
    )
    assert wrong_runtime.uses_structural_matching is False

    certificate_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "snapshot_fingerprint": snapshot.fingerprint,
                "runtime_mode": runtime_mode,
                "corpus_identity": "controlled-native-corpus",
                "legacy_observation_count": 1,
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
    assert certificate.authorizes(snapshot, runtime_mode)
    matching_snapshot = IDAPatternAdapter(CertifiedRule())
    matching_catalogue, _ = attach_selected_certified_catalogue_snapshot(
        (matching_snapshot,),
        parity_certificate_path=certificate_path,
        runtime_mode=runtime_mode,
    )

    assert matching_catalogue.fingerprint == snapshot.fingerprint
    assert len(warnings) == 1
    assert "new_safe_coverage_pending=0" in str(warnings[0][-1])
    assert matching_snapshot._structural_parity_authorized is True
    assert matching_snapshot.uses_structural_matching is True
    assert len(matching_snapshot.pattern_candidates) == 1

    attach_selected_certified_catalogue_snapshot(
        (matching_snapshot,), runtime_mode=runtime_mode
    )
    assert matching_snapshot.uses_structural_matching is False
    assert len(matching_snapshot.pattern_candidates) == 2

    attach_selected_certified_catalogue_snapshot(
        (matching_snapshot,),
        parity_certificate_path=certificate_path,
        runtime_mode=runtime_mode,
    )
    assert matching_snapshot.uses_structural_matching is True
    assert len(matching_snapshot.pattern_candidates) == 1


def test_structural_selection_fails_closed_when_native_z3_rejects(monkeypatch) -> None:
    """A live structural candidate cannot bypass the native mutation proof."""

    x = Var("x")

    class Rule:
        pattern = x + Const("zero", 0)

    adapter = IDAPatternAdapter(Rule())
    adapter._structural_matching_enabled = True
    source = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("x", 1), _constant(0))
    source.dest_size = 4
    source.ea = 0x401000
    report = AcMatchReport(
        bindings=AcMatchBindings({"x": (0,), "zero": (1,)}),
        comparisons=1,
        commuted_branches=0,
        flattened_nodes=0,
        stop_reason=AcMatchStopReason.MATCHED,
    )
    replacement_instruction = object()
    monkeypatch.setattr(adapter, "observe_structural_match", lambda *_args, **_kwargs: report)
    adapter._shadow_structural_native_paths = {"x": (0,), "zero": (1,)}
    monkeypatch.setattr(adapter, "get_replacement", lambda _candidate: replacement_instruction)
    monkeypatch.setattr(adapter, "_record_catalogue_success", lambda *_args: None)
    adapter._replacement_pattern_cache = object()
    monkeypatch.setattr(ida_backend, "minsn_to_ast", lambda _ins: source.left)
    monkeypatch.setattr(
        ida_backend,
        "prove_native_ast_equivalence",
        lambda _original, _replacement, *, width: False,
    )

    assert (
        adapter.match_structural_and_replace(
            source,
            bucket_size=1,
            attempted_rule_count=1,
        )
        is None
    )


def test_structural_selection_fails_closed_when_emission_raises(monkeypatch) -> None:
    """A structural emitter failure remains a no-op in the live callback."""

    x = Var("x")

    class Rule:
        pattern = x + Const("zero", 0)

    adapter = IDAPatternAdapter(Rule())
    adapter._structural_matching_enabled = True
    source = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("x", 1), _constant(0))
    source.dest_size = 4
    source.ea = 0x401000
    report = AcMatchReport(
        bindings=AcMatchBindings({"x": (0,), "zero": (1,)}),
        comparisons=1,
        commuted_branches=0,
        flattened_nodes=0,
        stop_reason=AcMatchStopReason.MATCHED,
    )
    monkeypatch.setattr(adapter, "observe_structural_match", lambda *_args, **_kwargs: report)
    adapter._shadow_structural_native_paths = {"x": (0,), "zero": (1,)}

    def _raising_replacement(_candidate):
        raise RuntimeError("synthetic emitter failure")

    monkeypatch.setattr(adapter, "get_replacement", _raising_replacement)

    assert (
        adapter.match_structural_and_replace(
            source,
            bucket_size=1,
            attempted_rule_count=1,
        )
        is None
    )


@pytest.mark.parametrize(
    ("name", "pattern"),
    (
        ("ShiftRule", Var("x") >> Const("shift", 1)),
        ("CastRule", Zext(Var("x"), 32)),
        ("PredicateRule", (Var("x") != Const("zero", 0)).to_int()),
    ),
)
def test_selected_unsupported_dsl_rules_keep_legacy_dispatch_by_default(
    monkeypatch,
    name: str,
    pattern,
) -> None:
    """Unsupported typed semantics must not be starved by Task 8 selection."""

    monkeypatch.setenv("D810_STRUCTURAL_DSL_MATCHING", "1")
    monkeypatch.delenv("D810_LEGACY_DSL_PERMUTATIONS", raising=False)
    adapter = IDAPatternAdapter(SimpleNamespace(name=name, pattern=pattern))
    attach_selected_certified_catalogue_snapshot((adapter,))
    optimizer = PatternOptimizer(maturities=[7], stats=None, log_dir=None)
    assert optimizer._add_rule_internal(adapter)
    optimizer.cur_maturity = 7

    assert adapter.uses_structural_matching is False
    assert all(
        adapter not in rules
        for rules in optimizer._structural_rules_by_root_opcode.values()
    )
    assert optimizer._indexed_storage.total_patterns == len(adapter.pattern_candidates)

    class Instruction:
        ea = 0

        @staticmethod
        def _print():
            return "legacy-unsupported"

    calls: list[object] = []
    monkeypatch.setattr(
        adapter,
        "check_pattern_and_replace",
        lambda registered, candidate: calls.append((registered, candidate))
        or Instruction(),
    )
    registered = adapter.pattern_candidates[0]
    optimizer._get_candidates = lambda _candidate: [
        RulePatternInfo(adapter, registered)
    ]

    candidate = object()
    outcome = optimizer._try_matches(
        None,
        Instruction(),
        candidate,
        allowed_rule_names=None,
        scheduled_rule_names=None,
        source_label="legacy-unsupported",
    )

    assert outcome is not None
    assert calls == [(registered, candidate)]


def test_structural_pattern_capability_accepts_reused_leaves_but_rejects_cycles() -> None:
    """The symbolic rule catalogue is a DAG, not necessarily a tree."""

    x = Var("x")
    assert ida_backend._supports_structural_dsl_pattern(x + x)

    cycle = Var("cycle")
    cycle.operation = "add"
    cycle.left = cycle
    cycle.right = Const("one", 1)
    assert not ida_backend._supports_structural_dsl_pattern(cycle)


def test_structural_dispatch_is_root_bucketed_and_reports_attempt_count(
    monkeypatch,
) -> None:
    """The hot path invokes only the root bucket and publishes its measured size."""

    class Instruction:
        ea = 0x401000

        class d:
            size = 4

        @staticmethod
        def _print():
            return "unit-ins"

    class StructuralRule:
        name = "CertifiedDsl"
        maturities = [7]
        uses_structural_matching = True

        def __init__(self) -> None:
            self.calls: list[tuple[object, int, int]] = []
            self.prepared: list[tuple[object, int]] = []

        def prepare_structural_candidate(self, candidate, *, destination_size: int):
            self.prepared.append((candidate, destination_size))
            return "lowered-once"

        def match_structural_and_replace(
            self,
            candidate,
            *,
            bucket_size: int,
            attempted_rule_count: int,
            lowering,
            lowering_provided: bool,
        ):
            self.calls.append((candidate, bucket_size, attempted_rule_count))
            assert lowering == "lowered-once"
            assert lowering_provided is True
            return Instruction()

    rule = StructuralRule()
    optimizer = object.__new__(PatternOptimizer)
    optimizer.stats = None
    optimizer.cur_maturity = 7
    optimizer._use_nomut_matching = False
    optimizer._use_legacy_storage = False
    optimizer._run_later_callback = None
    optimizer._pending_replacement_rule = None
    optimizer._get_candidates = lambda _ast: [
        RulePatternInfo(rule, object()),
        RulePatternInfo(object(), object()),
    ]

    result = optimizer._try_matches(
        None,
        Instruction(),
        "candidate-ast",
        allowed_rule_names=None,
        scheduled_rule_names=None,
        source_label="unit",
    )

    assert result is not None
    assert rule.prepared == [("candidate-ast", 4)]
    assert rule.calls == [("candidate-ast", 1, 1)]


def test_structural_only_hit_is_proven_without_becoming_a_live_rewrite(monkeypatch) -> None:
    x = Var("x")

    class Rule:
        pattern = x + Const("zero", 0)

    adapter = IDAPatternAdapter(Rule())
    source = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("x", 1), _constant(0))
    source.dest_size = 4
    source.ea = 0x401000
    adapter._attempt_destination_size = 4
    adapter._shadow_source_ast = source
    adapter._shadow_structural_native_paths = {"x": (0,), "zero": (1,)}
    adapter._shadow_match_report = AcMatchReport(
        bindings=AcMatchBindings({"x": (0,), "zero": (1,)}),
        comparisons=1,
        commuted_branches=0,
        flattened_nodes=0,
        stop_reason=AcMatchStopReason.MATCHED,
    )
    adapter._shadow_parity_ledger = ShadowMatcherParityLedger()
    replacement = source.left
    seen: list[object] = []

    def _replacement(candidate):
        seen.append(candidate.leafs_by_name)
        return object()

    monkeypatch.setattr(adapter, "_get_shadow_replacement", _replacement)
    monkeypatch.setattr(
        adapter,
        "get_replacement",
        lambda _candidate: pytest.fail("shadow proof must not use live replacement cache"),
    )
    monkeypatch.setattr(ida_backend, "minsn_to_ast", lambda _ins: replacement)
    monkeypatch.setattr(
        ida_backend,
        "prove_native_ast_equivalence",
        lambda original, rebuilt, *, width: (
            original is source and rebuilt is replacement and width == 32
        ),
    )

    adapter._record_shadow_parity(legacy_match=False)

    assert seen == [{"x": source.left, "zero": source.right}]
    assert adapter._shadow_parity_ledger.new_safe_coverage_proved == 1
    assert adapter._shadow_parity_ledger.new_safe_coverage_pending == 0
    assert adapter._last_provider_outcome is None


def test_structural_only_hit_stays_pending_when_native_proof_fails(monkeypatch) -> None:
    adapter = IDAPatternAdapter(type("Rule", (), {"pattern": Var("x")})())
    adapter._shadow_match_report = AcMatchReport(
        bindings=AcMatchBindings({"x": ()}),
        comparisons=1,
        commuted_branches=0,
        flattened_nodes=0,
        stop_reason=AcMatchStopReason.MATCHED,
    )
    adapter._shadow_parity_ledger = ShadowMatcherParityLedger()
    monkeypatch.setattr(adapter, "_prove_structural_only_candidate", lambda: False)

    adapter._record_shadow_parity(legacy_match=False)

    assert adapter._shadow_parity_ledger.new_safe_coverage_proved == 0
    assert adapter._shadow_parity_ledger.new_safe_coverage_pending == 1


def test_structural_only_hit_stays_pending_for_mixed_width_replacement(monkeypatch) -> None:
    """Proof-only coverage must not erase native mixed-width semantics."""

    x = Var("x")

    class Rule:
        pattern = x + Const("zero", 0)

    adapter = IDAPatternAdapter(Rule())
    source = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("x", 1), _constant(0))
    source.dest_size = 4
    source.ea = 0x401000
    replacement = source.left.clone()
    replacement.dest_size = 2
    adapter._attempt_destination_size = 4
    adapter._shadow_source_ast = source
    adapter._shadow_structural_native_paths = {"x": (0,), "zero": (1,)}
    adapter._shadow_match_report = AcMatchReport(
        bindings=AcMatchBindings({"x": (0,), "zero": (1,)}),
        comparisons=1,
        commuted_branches=0,
        flattened_nodes=0,
        stop_reason=AcMatchStopReason.MATCHED,
    )
    adapter._shadow_parity_ledger = ShadowMatcherParityLedger()

    monkeypatch.setattr(adapter, "_get_shadow_replacement", lambda _candidate: object())
    monkeypatch.setattr(ida_backend, "minsn_to_ast", lambda _ins: replacement)

    adapter._record_shadow_parity(legacy_match=False)

    assert adapter._shadow_parity_ledger.new_safe_coverage_proved == 0
    assert adapter._shadow_parity_ledger.new_safe_coverage_pending == 1
