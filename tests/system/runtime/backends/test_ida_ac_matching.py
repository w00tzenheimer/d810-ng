from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

import d810.backends.mba.ida as ida_backend  # noqa: E402
from d810.backends.mba.ida import (  # noqa: E402
    IDAPatternAdapter,
    attach_selected_certified_catalogue_snapshot,
    canonical_fallback_rollout_requested,
)
from d810.backends.mba.native_z3 import prove_native_ast_equivalence  # noqa: E402
from d810.hexrays.expr import ast as ast_dispatcher  # noqa: E402
from d810.hexrays.ir.mop_snapshot import MopSnapshot  # noqa: E402
from d810.hexrays.ir.mop_snapshot import raw_mop_identity  # noqa: E402
from d810.hexrays.ir.number_operand import safe_make_number  # noqa: E402
from d810.mba.ac_matching import (  # noqa: E402
    AcMatchBindings,
    AcMatchReport,
    AcMatchStopReason,
)
from d810.mba.certified_catalogue import (  # noqa: E402
    ShadowMatcherParityLedger,
    StructuralMatcherParityExpectation,
    load_structural_matcher_parity_certificate,
    make_structural_matcher_parity_certificate,
)
from d810.mba.dsl import Const, Var, Zext  # noqa: E402
from d810.mba.extension_api import CanonicalFallbackError  # noqa: E402
from d810.mba.typed_term import TypedBvTerm  # noqa: E402
from d810.mba.provider_outcome import (  # noqa: E402
    MatcherSelection,
    ProviderOutcomeStatus,
    RawMatcherWorkReceipt,
)
from tools.scripts.mba_structural_matcher_certificate import (  # noqa: E402
    build_certificate,
)
from d810.optimizers.microcode.instructions.pattern_matching.handler import (  # noqa: E402
    PatternOptimizer,
    RulePatternInfo,
)
from d810.optimizers.microcode.instructions.pattern_matching.engine import (  # noqa: E402
    get_engine_info,
)


def _parity_digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


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


def _raw_number(value: int, size: int = 4):
    mop = ida_hexrays.mop_t()
    assert safe_make_number(mop, value, size, 0x401000)
    return mop


def _raw_register(register: int = 1, size: int = 4):
    mop = ida_hexrays.mop_t()
    mop.make_reg(register, size)
    return mop


def _raw_instruction(*, opcode: int, left=None, right=None, destination=None):
    instruction = ida_hexrays.minsn_t(0x401000)
    instruction.opcode = opcode
    if left is not None:
        instruction.l = left
    if right is not None:
        instruction.r = right
    if destination is not None:
        instruction.d = destination
    return instruction


def _raw_nested_instruction(value: int):
    nested = _raw_instruction(
        opcode=ida_hexrays.m_add,
        left=_raw_register(2),
        right=_raw_number(value),
        destination=_raw_register(2),
    )
    mop = ida_hexrays.mop_t()
    mop.create_from_insn(nested)
    mop.size = 4
    return mop


def _raw_adapter(instruction):
    class Rule:
        name = "raw_identity"

    adapter = IDAPatternAdapter(Rule())
    adapter._attempt_instruction = instruction
    return adapter


def _matrix_operand(operand_type: int):
    base = {"t": operand_type, "size": 4, "valnum": 0, "oprops": 0}
    if operand_type == ida_hexrays.mop_n:
        base["nnn"] = SimpleNamespace(value=1, org_value=1)
    elif operand_type == ida_hexrays.mop_r:
        base["r"] = 1
    elif operand_type == ida_hexrays.mop_S:
        base["s"] = SimpleNamespace(off=0x20)
    elif operand_type == ida_hexrays.mop_v:
        base["g"] = 0x401000
    elif operand_type == ida_hexrays.mop_b:
        base["b"] = 2
    elif operand_type == ida_hexrays.mop_h:
        base["helper"] = "__ROL4__"
    elif operand_type == ida_hexrays.mop_str:
        base["cstr"] = "literal"
    elif operand_type == ida_hexrays.mop_d:
        base["d"] = SimpleNamespace(
            opcode=ida_hexrays.m_add,
            ea=0x401000,
            iprops=0,
            l=_matrix_operand(ida_hexrays.mop_r),
            r=_matrix_operand(ida_hexrays.mop_n),
            d=_matrix_operand(ida_hexrays.mop_r),
        )
    elif operand_type == ida_hexrays.mop_a:
        base["a"] = SimpleNamespace(
            t=ida_hexrays.mop_r,
            size=4,
            valnum=0,
            oprops=0,
            r=1,
            insize=4,
            outsize=0,
        )
        base["a_insize"] = 4
        base["a_outsize"] = 0
    elif operand_type == ida_hexrays.mop_l:
        base["l"] = SimpleNamespace(idx=3, off=0x10)
    elif operand_type == ida_hexrays.mop_p:
        base["pair"] = SimpleNamespace(
            lop=_matrix_operand(ida_hexrays.mop_r),
            hop=_matrix_operand(ida_hexrays.mop_r),
        )
    return SimpleNamespace(**base)


@pytest.mark.usefixtures("ida_database")
class TestRawNativeFingerprint:
    binary_name = "libobfuscated.dll"

    def test_distinguishes_real_constants_and_is_stable(self):
        one = _raw_instruction(
            opcode=ida_hexrays.m_mov,
            left=_raw_number(1),
            destination=_raw_register(),
        )
        two = _raw_instruction(
            opcode=ida_hexrays.m_mov,
            left=_raw_number(2),
            destination=_raw_register(),
        )

        one_adapter = _raw_adapter(one)
        one_fingerprint, one_identity = one_adapter._raw_native_fingerprint()
        repeat_fingerprint, repeat_identity = one_adapter._raw_native_fingerprint()
        two_fingerprint, two_identity = _raw_adapter(two)._raw_native_fingerprint()

        assert one_fingerprint is not None
        assert one_fingerprint == repeat_fingerprint
        assert one_identity == repeat_identity
        assert one_fingerprint != two_fingerprint
        assert one_identity["left"]["value"] == 1
        assert two_identity["left"]["value"] == 2

    def test_distinguishes_full_nested_mop_d_leaf(self):
        first = _raw_instruction(
            opcode=ida_hexrays.m_xdu,
            left=_raw_nested_instruction(1),
            destination=_raw_register(),
        )
        second = _raw_instruction(
            opcode=ida_hexrays.m_xdu,
            left=_raw_nested_instruction(2),
            destination=_raw_register(),
        )

        first_fingerprint, first_identity = _raw_adapter(first)._raw_native_fingerprint()
        second_fingerprint, second_identity = _raw_adapter(second)._raw_native_fingerprint()

        assert first_fingerprint is not None
        assert first_fingerprint != second_fingerprint
        assert "instruction" in first_identity["left"], first_identity
        assert first_identity["left"]["instruction"]["r"]["value"] == 1
        assert second_identity["left"]["instruction"]["r"]["value"] == 2, second_identity

    @pytest.mark.parametrize(
        "operand_type",
        (
            ida_hexrays.mop_z,
            ida_hexrays.mop_n,
            ida_hexrays.mop_r,
            ida_hexrays.mop_S,
            ida_hexrays.mop_v,
            ida_hexrays.mop_b,
            ida_hexrays.mop_h,
            ida_hexrays.mop_str,
            ida_hexrays.mop_d,
            ida_hexrays.mop_a,
            ida_hexrays.mop_l,
            ida_hexrays.mop_p,
        ),
    )
    def test_supported_operand_matrix_is_json_pod(self, operand_type):
        import json

        identity = raw_mop_identity(_matrix_operand(operand_type))
        json.dumps(identity, sort_keys=True, allow_nan=False)
        assert isinstance(identity, dict)
        assert identity["type"] == operand_type
        assert identity["oprops"] == 0

    @pytest.mark.parametrize("operand_name", ("mop_c", "mop_f", "mop_fn", "mop_sc"))
    def test_unsupported_operand_forms_fail_closed(self, operand_name):
        operand_type = getattr(ida_hexrays, operand_name)
        with pytest.raises(ValueError):
            raw_mop_identity(_matrix_operand(operand_type))

    def test_instruction_and_operand_properties_are_identity_fields(self):
        first = _raw_instruction(
            opcode=ida_hexrays.m_mov,
            left=_raw_number(1),
            destination=_raw_register(),
        )
        second = ida_hexrays.minsn_t(first)
        first.iprops = 0
        second.iprops = 1
        first.l.oprops = 0
        second.l.oprops = 1

        first_fingerprint, first_identity = _raw_adapter(first)._raw_native_fingerprint()
        second_fingerprint, second_identity = _raw_adapter(second)._raw_native_fingerprint()

        assert first_fingerprint != second_fingerprint
        assert first_identity["iprops"] == 0
        assert second_identity["iprops"] == 1
        assert first_identity["left"]["oprops"] == 0
        assert second_identity["left"]["oprops"] == 1

    def test_incomplete_instruction_identity_fails_closed(self):
        instruction = SimpleNamespace(
            opcode=ida_hexrays.m_add,
            ea=0x401000,
            iprops=0,
        )

        assert _raw_adapter(instruction)._raw_native_fingerprint() == (None, None)


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


def test_shadow_matcher_fails_closed_for_synthetic_internal_binding_path() -> None:
    x = Var("x")

    class Rule:
        pattern = x
        replacement = x

    adapter = IDAPatternAdapter(Rule())
    candidate = TypedBvTerm(
        "add",
        32,
        children=(
            TypedBvTerm(None, 32, leaf_key=("synthetic", "left")),
            TypedBvTerm(None, 32, leaf_key=("synthetic", "right")),
        ),
    )
    lowering = SimpleNamespace(
        term=candidate,
        raw_term=candidate,
        native_nodes_by_path={(): object()},
        raw_native_nodes_by_path={},
    )

    report = adapter.observe_structural_match(
        object(), lowering=lowering, lowering_provided=True
    )

    assert report is not None
    assert report.stop_reason is AcMatchStopReason.MATCHED
    metadata = adapter._matcher_metadata()
    assert metadata is not None
    assert metadata.stop_reason == "native_path_unavailable"
    assert adapter._shadow_structural_native_paths is None


def test_shadow_reconstruction_uses_the_active_ast_binding_context() -> None:
    """The proof-only emitter must satisfy the active Cython AST signature."""

    x = Var("x")

    class Rule:
        pattern = x + Const("zero", 0)
        replacement = x

    adapter = IDAPatternAdapter(Rule())
    source = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("x", 1), _constant(0))
    source.dest_size = 4
    source.ea = 0x401000
    candidate = ida_backend._ShadowBindingCandidate(
        {"x": source.left, "zero": source.right}, source
    )

    bindings = adapter._shadow_binding_context(candidate)

    assert isinstance(bindings, ast_dispatcher.AstNode)
    assert bindings.leafs_by_name == candidate.leafs_by_name
    assert adapter.REPLACEMENT_PATTERN.clone().update_leafs_mop(bindings)


class TestShadowReplacementLiteral:
    binary_name = "libobfuscated.dll"

    def test_shadow_replacement_materializes_replacement_only_literal(
        self, ida_database
    ) -> None:
        """Shadow emission accepts concrete replacement literals in both runtimes."""

        import idautils

        x = Var("x")

        class Rule:
            pattern = x + Const("two", 2)
            replacement = x ^ Const("one", 1)

        adapter = IDAPatternAdapter(Rule())
        source = ast_dispatcher.AstNode(
            ida_hexrays.m_add, _leaf("x", 1), _constant(2)
        )
        source.dest_size = 4
        source.ea = next(iter(idautils.Functions()))
        candidate = ida_backend._ShadowBindingCandidate(
            {"x": source.left, "two": source.right}, source
        )

        replacement = adapter._get_shadow_replacement(candidate)

        assert replacement is not None
        assert replacement.opcode == ida_hexrays.m_xor
        assert replacement.r.t == ida_hexrays.mop_n
        assert replacement.r.nnn.value == 1
        assert all(
            leaf.mop is None for leaf in adapter.REPLACEMENT_PATTERN.get_leaf_list()
        )


@pytest.mark.parametrize("boundary", ("update", "materialize", "create"))
def test_shadow_replacement_boundary_failures_are_fail_closed(monkeypatch, boundary):
    """Injected adapter-boundary errors must not escape shadow observation."""

    x = Var("x")

    class Rule:
        name = "ShadowBoundaryFailure"
        pattern = x
        replacement = x

    adapter = IDAPatternAdapter(Rule())
    source = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("x", 1), _constant(0))
    source.dest_size = 4
    source.ea = 0x401000
    candidate = ida_backend._ShadowBindingCandidate({"x": source.left}, source)

    class FakeReplacement:
        def clone(self):
            return self

        def get_leaf_list(self):
            return []

        def update_leafs_mop(self, _bindings):
            if boundary == "update":
                raise TypeError("injected update failure")
            return True

        def create_minsn(self, _ea, _dst_mop):
            if boundary == "create":
                raise TypeError("injected create failure")
            return object()

    fake = FakeReplacement()
    monkeypatch.setattr(
        type(adapter),
        "REPLACEMENT_PATTERN",
        property(lambda _adapter: fake),
    )
    if boundary == "materialize":
        def _raise_materialize(*_args):
            raise TypeError("injected materialize failure")

        monkeypatch.setattr(adapter, "_materialize_replacement_constants", _raise_materialize)

    assert adapter._get_shadow_replacement(candidate) is None


def test_shadow_proof_marks_boundary_failure_as_refused(monkeypatch) -> None:
    x = Var("x")

    class Rule:
        name = "ShadowProofBoundaryFailure"
        pattern = x + Const("zero", 0)
        replacement = x

    adapter = IDAPatternAdapter(Rule())
    source = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("x", 1), _constant(0))
    source.dest_size = 4
    source.ea = 0x401000
    adapter._attempt_destination_size = 4
    adapter._shadow_source_ast = source
    adapter._shadow_structural_native_paths = {"x": (0,), "zero": (1,)}
    monkeypatch.setattr(
        adapter,
        "_get_shadow_replacement",
        lambda _candidate: (_ for _ in ()).throw(TypeError("injected boundary failure")),
    )

    assert adapter._prove_structural_only_candidate() is False
    assert adapter._shadow_structural_refused is True


def test_shadow_parity_recording_fails_closed_on_binding_error(monkeypatch) -> None:
    x = Var("x")

    class Rule:
        name = "ShadowParityBoundaryFailure"
        pattern = x
        replacement = x

    adapter = IDAPatternAdapter(Rule())
    adapter._shadow_match_report = AcMatchReport(
        bindings=AcMatchBindings({"x": ()}),
        comparisons=1,
        commuted_branches=0,
        flattened_nodes=0,
        stop_reason=AcMatchStopReason.MATCHED,
    )
    adapter._shadow_parity_ledger = ShadowMatcherParityLedger()
    monkeypatch.setattr(
        adapter,
        "_shadow_metadata",
        lambda **_kwargs: (_ for _ in ()).throw(TypeError("injected binding failure")),
    )

    adapter._record_shadow_parity(legacy_match=False)

    assert adapter._shadow_parity_recorded is True
    assert adapter._shadow_parity_ledger.observation_count == 1
    assert adapter._shadow_parity_ledger.new_safe_coverage_refused == 1


def test_native_shadow_proof_uses_fixed_width_bit_vector_semantics() -> None:
    source = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("x", 1), _constant(0))
    source.dest_size = 4

    assert prove_native_ast_equivalence(source, source.left, width=32)
    assert not prove_native_ast_equivalence(source, _constant(1), width=32)
    assert not prove_native_ast_equivalence(source, source.left, width=7)
    assert not prove_native_ast_equivalence(source, source.left, width=32, timeout_ms=0)
    assert not prove_native_ast_equivalence(
        source, source.left, width=32, timeout_ms=251
    )


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


def test_rollout_flag_precedence_and_deprecated_alias_warning(monkeypatch) -> None:
    warnings: list[tuple[object, ...]] = []
    monkeypatch.setattr(ida_backend.logger, "warning", lambda *args: warnings.append(args))
    monkeypatch.delenv("D810_CANONICAL_MATCH_FALLBACK", raising=False)
    monkeypatch.delenv("D810_LEGACY_DSL_PERMUTATIONS", raising=False)
    monkeypatch.setenv("D810_STRUCTURAL_DSL_MATCHING", "1")

    assert canonical_fallback_rollout_requested() is True
    assert canonical_fallback_rollout_requested() is True
    assert len(warnings) == 1
    assert "deprecated" in str(warnings[0]).lower()

    monkeypatch.setenv("D810_CANONICAL_MATCH_FALLBACK", "1")
    assert canonical_fallback_rollout_requested() is True
    monkeypatch.setenv("D810_LEGACY_DSL_PERMUTATIONS", "1")
    assert canonical_fallback_rollout_requested() is False


def test_portfolio_can_disable_legacy_fuzzy_permutations_without_structural_opt_in():
    x = Var("x")

    class Rule:
        name = "NoFuzzyRule"
        pattern = x + Const("one", 1)

    adapter = IDAPatternAdapter(Rule())
    assert len(adapter.pattern_candidates) == 2

    adapter.configure({"generate_commutative_permutations": False})
    assert adapter.uses_structural_matching is False
    assert len(adapter.pattern_candidates) == 1


def test_structural_opt_in_requires_matching_persisted_parity_certificate(
    monkeypatch, tmp_path
) -> None:
    """A certificate authorizes exactly its snapshot and active matcher mode."""

    x = Var("x")

    class CertifiedRule:
        name = "CertifiedAdd"
        pattern = x + Const("one", 1)
        replacement = x

    assert ida_backend._supports_structural_dsl_pattern(CertifiedRule.pattern)
    monkeypatch.setenv("D810_STRUCTURAL_DSL_MATCHING", "1")
    monkeypatch.delenv("D810_LEGACY_DSL_PERMUTATIONS", raising=False)
    runtime_mode = get_engine_info()["backend"]
    manifest_path = tmp_path / "controlled-native-corpus.json"
    manifest_path.write_text('{"cases":["controlled"]}\n', encoding="utf-8")
    toolchain_document = {"backend": runtime_mode, "ida": "9.4"}
    toolchain_path = tmp_path / "controlled-toolchain.json"
    toolchain_path.write_text(
        json.dumps(toolchain_document, sort_keys=True) + "\n", encoding="utf-8"
    )
    corpus_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    toolchain_digest = hashlib.sha256(
        json.dumps(
            toolchain_document,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    warnings: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        ida_backend.logger,
        "warning",
        lambda *args: warnings.append(args),
    )

    probe = IDAPatternAdapter(CertifiedRule())
    snapshot, _ = attach_selected_certified_catalogue_snapshot((probe,))
    expectation = StructuralMatcherParityExpectation(
        corpus_digest=corpus_digest,
        toolchain_digest=toolchain_digest,
        runtime_semantics_digest=snapshot.runtime_semantics_digest,
        legacy_observation_count=1,
        observation_count=1,
    )
    certificate_path = tmp_path / "structural-parity.json"
    generated_payload = build_certificate(
        {
            "snapshot": {
                "fingerprint": snapshot.fingerprint,
                "structural_authorizable": snapshot.structural_authorizable,
                "canonicalizer_schema_version": snapshot.canonicalizer_schema_version,
                "runtime_semantics_digest": snapshot.runtime_semantics_digest,
            },
            "ledger": {
                "observation_count": 1,
                "legacy_match_count": 1,
                "legacy_rule_mismatches": 0,
                "legacy_binding_mismatches": 0,
                "legacy_binding_unknown": 0,
                "new_safe_coverage_pending": 0,
                "new_safe_coverage_proved": 0,
                "unsafe_mutations": 0,
                "unproved_structural_replacements": 0,
            },
            "runtime_mode": runtime_mode,
        },
        manifest=manifest_path,
        toolchain=toolchain_path,
    )
    missing_pending_payload = dict(generated_payload)
    missing_pending_payload.pop("new_safe_coverage_pending")
    certificate_path.write_text(
        json.dumps(missing_pending_payload),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="new_safe_coverage_pending=0"):
        load_structural_matcher_parity_certificate(certificate_path)

    invalid_certificate = IDAPatternAdapter(CertifiedRule())
    attach_selected_certified_catalogue_snapshot(
        (invalid_certificate,),
        parity_certificate_path=certificate_path,
        parity_expectation=expectation,
        runtime_mode=runtime_mode,
    )
    assert invalid_certificate.uses_structural_matching is False

    wrong_snapshot_payload = dict(generated_payload)
    wrong_snapshot_payload["snapshot_fingerprint"] = "0" * 64
    certificate_path.write_text(
        json.dumps(wrong_snapshot_payload), encoding="utf-8"
    )
    wrong_snapshot = IDAPatternAdapter(CertifiedRule())
    attach_selected_certified_catalogue_snapshot(
        (wrong_snapshot,),
        parity_certificate_path=certificate_path,
        parity_expectation=expectation,
        runtime_mode=runtime_mode,
    )
    assert wrong_snapshot.uses_structural_matching is False

    other_runtime_mode = "cython" if runtime_mode == "python" else "python"
    wrong_runtime_payload = dict(generated_payload)
    wrong_runtime_payload["runtime_mode"] = other_runtime_mode
    certificate_path.write_text(
        json.dumps(wrong_runtime_payload),
        encoding="utf-8",
    )
    wrong_runtime = IDAPatternAdapter(CertifiedRule())
    attach_selected_certified_catalogue_snapshot(
        (wrong_runtime,),
        parity_certificate_path=certificate_path,
        parity_expectation=expectation,
        runtime_mode=runtime_mode,
    )
    assert wrong_runtime.uses_structural_matching is False

    certificate_path.write_text(json.dumps(generated_payload), encoding="utf-8")

    certificate = load_structural_matcher_parity_certificate(certificate_path)
    assert certificate.authorizes(snapshot, runtime_mode, expectation)
    matching_snapshot = IDAPatternAdapter(CertifiedRule())
    matching_catalogue, _ = attach_selected_certified_catalogue_snapshot(
        (matching_snapshot,),
        parity_certificate_path=certificate_path,
        parity_expectation=expectation,
        runtime_mode=runtime_mode,
    )

    assert matching_catalogue.fingerprint == snapshot.fingerprint
    assert len(warnings) == 1
    assert "new_safe_coverage_pending=0" in str(warnings[0][-1])
    assert matching_snapshot._structural_parity_authorized is True
    assert matching_snapshot.uses_structural_matching is True
    assert len(matching_snapshot.pattern_candidates) == 1

    mutated_runtime_payload = dict(generated_payload)
    mutated_runtime_payload["runtime_semantics_digest"] = _parity_digest(
        "changed-runtime-semantics"
    )
    certificate_path.write_text(
        json.dumps(mutated_runtime_payload), encoding="utf-8"
    )
    attach_selected_certified_catalogue_snapshot(
        (matching_snapshot,),
        parity_certificate_path=certificate_path,
        parity_expectation=expectation,
        runtime_mode=runtime_mode,
    )
    assert matching_snapshot._structural_parity_authorized is False
    assert matching_snapshot.uses_structural_matching is False
    assert matching_snapshot._pattern_candidates_cache is None
    assert len(matching_snapshot.pattern_candidates) == 2

    certificate_path.write_text(json.dumps(generated_payload), encoding="utf-8")

    attach_selected_certified_catalogue_snapshot(
        (matching_snapshot,), runtime_mode=runtime_mode
    )
    assert matching_snapshot.uses_structural_matching is False
    assert len(matching_snapshot.pattern_candidates) == 2

    attach_selected_certified_catalogue_snapshot(
        (matching_snapshot,),
        parity_certificate_path=certificate_path,
        parity_expectation=expectation,
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
    monkeypatch.setattr(
        adapter, "_get_shadow_replacement", lambda _candidate: replacement_instruction
    )
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
            comparison_budget=64,
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

    monkeypatch.setattr(adapter, "_get_shadow_replacement", _raising_replacement)

    with pytest.raises(CanonicalFallbackError, match="emitter"):
        adapter.match_structural_and_replace(
            source,
            bucket_size=1,
            attempted_rule_count=1,
            comparison_budget=64,
        )


def _canonical_probe_lowering(adapter, source):
    """Build a minimal callback-local lowering for stage-boundary tests."""

    from d810.mba.island_profile import profile_typed_term
    from d810.mba.semantic_canonicalization import canonicalize_mba_term

    typed = TypedBvTerm(
        "add",
        32,
        children=(
            TypedBvTerm(None, 32, leaf_key=("mop", "x")),
            TypedBvTerm(None, 32, value=0),
        ),
    )
    adapter._attempt_destination_size = 4
    adapter._prepare_shadow_canonical_templates()
    return SimpleNamespace(
        term=canonicalize_mba_term(typed).canonical_term,
        raw_term=typed,
        native_nodes_by_path={},
        raw_native_nodes_by_path={},
        profile=profile_typed_term(typed),
    )


def test_structural_matcher_error_is_terminal_and_typed(monkeypatch) -> None:
    from d810.mba import ac_matching

    x = Var("x")

    class Rule:
        pattern = x + Const("zero", 0)
        replacement = x

    adapter = IDAPatternAdapter(Rule())
    source = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("x", 1), _constant(0))
    lowering = _canonical_probe_lowering(adapter, source)

    def fail(*_args, **_kwargs):
        raise RuntimeError("matcher defect")

    monkeypatch.setattr(ac_matching, "match_canonical_term_pattern", fail)
    with pytest.raises(CanonicalFallbackError, match="matcher"):
        adapter.observe_structural_match(
            source, lowering=lowering, lowering_provided=True
        )


def test_structural_constraint_error_is_terminal_and_typed(monkeypatch) -> None:
    from d810.mba import canonical_pattern
    from d810.mba.ac_matching import match_canonical_term_pattern

    x = Var("x")

    class Rule:
        pattern = x + Const("zero", 0)
        replacement = x

    adapter = IDAPatternAdapter(Rule())
    source = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("x", 1), _constant(0))
    lowering = _canonical_probe_lowering(adapter, source)
    template = adapter._shadow_canonical_templates[32]
    report = match_canonical_term_pattern(
        template, lowering.term, comparison_budget=64
    )
    assert report.matches

    def fail(*_args, **_kwargs):
        raise RuntimeError("constraint defect")

    monkeypatch.setattr(canonical_pattern, "evaluate_frozen_constraints", fail)
    with pytest.raises(CanonicalFallbackError, match="constraint"):
        adapter.observe_structural_match(
            source, lowering=lowering, lowering_provided=True
        )


def test_structural_provenance_error_is_terminal_and_typed(monkeypatch) -> None:
    from d810.mba import canonical_pattern

    x = Var("x")

    class Rule:
        pattern = x + Const("zero", 0)
        replacement = x

    adapter = IDAPatternAdapter(Rule())
    source = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("x", 1), _constant(0))
    lowering = _canonical_probe_lowering(adapter, source)
    native_x = object()
    native_zero = object()
    lowering.native_nodes_by_path = {(0,): native_x, (1,): native_zero}
    lowering.raw_native_nodes_by_path = {(0,): native_x, (1,): native_zero}

    def fail(*_args, **_kwargs):
        raise RuntimeError("provenance defect")

    monkeypatch.setattr(canonical_pattern, "resolve_canonical_match_paths", fail)
    with pytest.raises(CanonicalFallbackError, match="provenance"):
        adapter.observe_structural_match(
            source, lowering=lowering, lowering_provided=True
        )


def test_structural_candidate_error_is_terminal_and_typed(monkeypatch) -> None:
    x = Var("x")

    class Rule:
        pattern = x + Const("zero", 0)
        replacement = x

    adapter = IDAPatternAdapter(Rule())
    adapter._canonical_fallback_enabled = True
    source = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("x", 1), _constant(0))
    source.dest_size = 4
    source.ea = 0x401000
    report = SimpleNamespace(
        bindings=object(),
        comparisons=1,
        stop_reason=AcMatchStopReason.MATCHED,
    )
    monkeypatch.setattr(
        adapter, "observe_structural_match", lambda *_args, **_kwargs: report
    )
    adapter._shadow_structural_native_paths = {"x": (0,)}
    monkeypatch.setattr(
        adapter,
        "_check_candidate",
        lambda _candidate: (_ for _ in ()).throw(RuntimeError("candidate defect")),
    )
    with pytest.raises(CanonicalFallbackError, match="candidate"):
        adapter.match_structural_and_replace(
            source, bucket_size=1, attempted_rule_count=1, comparison_budget=64
        )


@pytest.mark.parametrize(
    "stage", ["matcher", "constraint", "provenance", "candidate", "emitter", "equivalence"]
)
def test_handler_records_truthful_terminal_receipt_for_active_stage_error(
    monkeypatch, stage: str
) -> None:
    """Production handler error recording retains work done before stage failure."""

    from d810.mba import ac_matching, canonical_pattern

    x = Var("x")

    class Rule:
        name = f"{stage}-failure"
        maturities = (7,)
        canonical_fallback_enabled = True
        pattern = x + Const("zero", 0)
        replacement = x

    adapter = IDAPatternAdapter(Rule())
    adapter._canonical_fallback_enabled = True
    adapter._structural_matching_enabled = True
    adapter._canonical_fallback_root_shapes = (("add", 32, 2),)
    adapter._provider_outcome_capture_depth = 1
    source = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("x", 1), _constant(0))
    source.dest_size = 4
    source.ea = 0x401000
    lowering = _canonical_probe_lowering(adapter, source)
    if stage in {"provenance", "candidate", "emitter", "equivalence"}:
        native_x = object()
        native_zero = object()
        lowering.native_nodes_by_path = {(0,): native_x, (1,): native_zero}
        lowering.raw_native_nodes_by_path = {(0,): native_x, (1,): native_zero}

    if stage == "matcher":
        def fail(*_args, **_kwargs):
            raise RuntimeError("matcher defect")

        monkeypatch.setattr(ac_matching, "match_canonical_term_pattern", fail)
    elif stage == "constraint":
        def fail(*_args, **_kwargs):
            raise RuntimeError("constraint defect")

        monkeypatch.setattr(canonical_pattern, "evaluate_frozen_constraints", fail)
    elif stage == "provenance":
        def fail(*_args, **_kwargs):
            raise RuntimeError("provenance defect")

        monkeypatch.setattr(canonical_pattern, "resolve_canonical_match_paths", fail)
    elif stage == "candidate":
        def fail(*_args, **_kwargs):
            raise RuntimeError("candidate defect")

        monkeypatch.setattr(adapter, "_check_candidate", fail)
    elif stage == "emitter":
        def fail(*_args, **_kwargs):
            raise RuntimeError("emitter defect")

        monkeypatch.setattr(adapter, "_get_shadow_replacement", fail)
    else:
        monkeypatch.setattr(adapter, "_get_shadow_replacement", lambda _candidate: object())
        monkeypatch.setattr(ida_backend, "minsn_to_ast", lambda _replacement: source)

        def fail(*_args, **_kwargs):
            raise RuntimeError("equivalence defect")

        monkeypatch.setattr(ida_backend, "prove_native_ast_equivalence", fail)

    class Instruction:
        ea = 0x401000

        class d:
            size = 4

        @staticmethod
        def _print():
            return "stage-failure"

    class LaterRule:
        name = "must-not-run"
        maturities = (7,)
        canonical_fallback_enabled = True

        def __init__(self):
            self.invoked = False

        def match_structural_and_replace(self, *_args, **_kwargs):
            self.invoked = True
            return "must-not-mutate"

    later = LaterRule()
    optimizer = object.__new__(PatternOptimizer)
    optimizer.stats = None
    optimizer.cur_maturity = 7
    optimizer._use_nomut_matching = False
    optimizer._use_legacy_storage = False
    optimizer._run_later_callback = None
    optimizer._pending_replacement_rule = None
    optimizer._get_candidates = lambda _candidate: []
    monkeypatch.setattr(
        optimizer,
        "_prepare_canonical_fallback",
        lambda *_args, **_kwargs: (lowering, (adapter, later)),
    )

    assert (
        optimizer._try_matches(
            None,
            Instruction(),
            source,
            allowed_rule_names=None,
            scheduled_rule_names=None,
            source_label=f"{stage}-failure",
        )
        is None
    )
    assert later.invoked is False
    outcomes = adapter.provider_outcomes()
    assert len(outcomes) == 1
    outcome = outcomes[0]
    assert outcome.status is ProviderOutcomeStatus.ERROR
    assert outcome.fingerprint == lowering.profile.fingerprint
    assert outcome.metadata["native_profile"]["fingerprint"] == outcome.fingerprint
    assert outcome.metadata["error_stage"] == stage
    assert outcome.matcher is not None
    assert outcome.matcher.fallback_comparisons >= 0
    if stage != "matcher":
        assert outcome.matcher.fallback_comparisons > 0
    assert outcome.matcher.terminal_stop_reason == f"error:{stage}"


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
        for rules in optimizer._canonical_fallback_rules_by_root_shape.values()
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


def test_supported_pattern_with_unsupported_replacement_keeps_legacy_dispatch(
    monkeypatch, tmp_path
) -> None:
    """A valid certificate must not starve a rule lacking a structural template."""

    x = Var("x")

    class UnsupportedReplacementRule:
        name = "SupportedPatternUnsupportedReplacement"
        pattern = x + Const("one", 1)
        replacement = x << Const("shift", 1)

    monkeypatch.setenv("D810_STRUCTURAL_DSL_MATCHING", "1")
    monkeypatch.delenv("D810_LEGACY_DSL_PERMUTATIONS", raising=False)
    probe = IDAPatternAdapter(UnsupportedReplacementRule())
    snapshot, _ = attach_selected_certified_catalogue_snapshot((probe,))
    runtime_mode = get_engine_info()["backend"]
    corpus_digest = _parity_digest("unsupported-replacement-corpus")
    toolchain_digest = _parity_digest(f"ida-9.4-{runtime_mode}")
    payload = make_structural_matcher_parity_certificate(
        snapshot=snapshot,
        ledger=ShadowMatcherParityLedger(observation_count=1, legacy_match_count=1),
        runtime_mode=runtime_mode,
        corpus_digest=corpus_digest,
        toolchain_digest=toolchain_digest,
        runtime_semantics_digest=snapshot.runtime_semantics_digest,
    )
    certificate_path = tmp_path / "unsupported-replacement.certificate.json"
    certificate_path.write_text(json.dumps(payload), encoding="utf-8")
    expectation = StructuralMatcherParityExpectation(
        corpus_digest=corpus_digest,
        toolchain_digest=toolchain_digest,
        runtime_semantics_digest=snapshot.runtime_semantics_digest,
        legacy_observation_count=1,
        observation_count=1,
    )

    attach_selected_certified_catalogue_snapshot(
        (probe,),
        parity_certificate_path=certificate_path,
        parity_expectation=expectation,
        runtime_mode=runtime_mode,
    )

    assert probe._structural_parity_authorized is True
    assert probe.uses_structural_matching is False
    assert len(probe.pattern_candidates) == 2

    optimizer = PatternOptimizer(maturities=[7], stats=None, log_dir=None)
    assert optimizer._add_rule_internal(probe)
    optimizer.cur_maturity = 7

    class Instruction:
        ea = 0

        @staticmethod
        def _print():
            return "legacy-unsupported-replacement"

    calls: list[object] = []
    monkeypatch.setattr(
        probe,
        "check_pattern_and_replace",
        lambda registered, candidate: calls.append((registered, candidate))
        or Instruction(),
    )
    registered = probe.pattern_candidates[0]
    optimizer._get_candidates = lambda _candidate: [
        RulePatternInfo(probe, registered)
    ]

    candidate = object()
    outcome = optimizer._try_matches(
        None,
        Instruction(),
        candidate,
        allowed_rule_names=None,
        scheduled_rule_names=None,
        source_label="legacy-unsupported-replacement",
    )

    assert outcome is not None
    assert calls == [(registered, candidate)]


def test_legacy_dispatch_does_not_shadow_or_collect_outcomes_by_default(
    monkeypatch,
) -> None:
    """Normal legacy matching must not pay portfolio-observation costs."""

    monkeypatch.delenv("D810_SHADOW_DSL_MATCHING", raising=False)

    class Instruction:
        ea = 0x401000

        class d:
            size = 4

        @staticmethod
        def _print():
            return "legacy-default"

    class LegacyRule:
        name = "LegacyRule"
        maturities = [7]
        uses_structural_matching = False

        @staticmethod
        def observe_structural_match(_candidate):
            pytest.fail("default legacy matching must not invoke shadow observation")

        @staticmethod
        def check_pattern_and_replace(_pattern, _candidate):
            return Instruction()

    rule = LegacyRule()
    optimizer = object.__new__(PatternOptimizer)
    optimizer.stats = None
    optimizer.cur_maturity = 7
    optimizer._use_nomut_matching = False
    optimizer._use_legacy_storage = False
    optimizer._run_later_callback = None
    optimizer._pending_replacement_rule = None
    optimizer._get_candidates = lambda _candidate: [RulePatternInfo(rule, object())]

    assert (
        optimizer._try_matches(
            None,
            Instruction(),
            object(),
            allowed_rule_names=None,
            scheduled_rule_names=None,
            source_label="legacy-default",
        )
        is not None
    )


def test_pattern_optimizer_publishes_typed_raw_work_receipt(monkeypatch) -> None:
    """The actual legacy AstNode handler boundary records one attempted comparison."""

    class Instruction:
        ea = 0x401000

        class d:
            size = 4

        @staticmethod
        def _print():
            return "raw-receipt"

    class LegacyRule:
        name = "LegacyReceiptRule"
        maturities = [7]
        uses_structural_matching = False

        def __init__(self) -> None:
            self.receipts: list[RawMatcherWorkReceipt] = []

        def bind_match_context(self, _blk, _ins):
            return None

        def record_raw_match_receipt(self, receipt):
            self.receipts.append(receipt)

        def check_pattern_and_replace(self, _pattern, _candidate):
            return Instruction()

    rule = LegacyRule()
    optimizer = object.__new__(PatternOptimizer)
    optimizer.stats = None
    optimizer.cur_maturity = 7
    optimizer._use_nomut_matching = False
    optimizer._use_legacy_storage = False
    optimizer._run_later_callback = None
    optimizer._pending_replacement_rule = None
    optimizer._get_candidates = lambda _candidate: [RulePatternInfo(rule, object())]

    assert optimizer._try_matches(
        None,
        Instruction(),
        object(),
        allowed_rule_names=None,
        scheduled_rule_names=None,
        source_label="raw-receipt",
    ) is not None
    assert rule.receipts == [RawMatcherWorkReceipt(1, 0, "legacy_ast")]


@pytest.mark.parametrize("expected_backend", ("python", "cython"))
def test_nomut_handler_receipt_uses_selected_engine_backend(
    monkeypatch, expected_backend: str
) -> None:
    """The non-mutating handler reports the selected Python/Cython engine."""

    from d810.optimizers.microcode.instructions.pattern_matching import handler as handler_module

    class Instruction:
        ea = 0x401000

        class d:
            size = 4

        @staticmethod
        def _print():
            return "nomut-receipt"

    class NomutRule:
        name = "NomutReceiptRule"
        maturities = [7]
        uses_structural_matching = False

        def __init__(self) -> None:
            self.receipts: list[RawMatcherWorkReceipt] = []

        def bind_match_context(self, _blk, _ins):
            return None

        def record_raw_match_receipt(self, receipt):
            self.receipts.append(receipt)

        @staticmethod
        def check_candidate(_candidate):
            return True

        @staticmethod
        def get_replacement(_candidate):
            return Instruction()

    monkeypatch.setattr(
        handler_module, "get_engine_info", lambda: {"backend": expected_backend}
    )
    monkeypatch.setattr(handler_module, "_match_nomut", lambda *_args: True)
    rule = NomutRule()
    optimizer = object.__new__(PatternOptimizer)
    optimizer.stats = None
    optimizer.cur_maturity = 7
    optimizer._use_nomut_matching = True
    optimizer._use_legacy_storage = False
    optimizer._run_later_callback = None
    optimizer._pending_replacement_rule = None
    optimizer._match_bindings = handler_module.MatchBindings()
    optimizer._get_candidates = lambda _candidate: [RulePatternInfo(rule, object())]

    assert optimizer._try_matches(
        None,
        Instruction(),
        object(),
        allowed_rule_names=None,
        scheduled_rule_names=None,
        source_label="nomut-receipt",
    ) is not None
    assert rule.receipts == [RawMatcherWorkReceipt(1, 0, expected_backend)]


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
        canonical_fallback_enabled = True

        def __init__(self) -> None:
            self.calls: list[tuple[object, int, int]] = []
            self.prepared: list[tuple[object, int]] = []

        def check_pattern_and_replace(self, _pattern, _candidate):
            return None

        def prepare_structural_candidate(self, candidate, *, destination_size: int):
            self.prepared.append((candidate, destination_size))
            leaf = TypedBvTerm(None, 32, leaf_key=("mop", "x"))
            return SimpleNamespace(
                term=TypedBvTerm("add", 32, children=(leaf, leaf)),
            )

        def match_structural_and_replace(
            self,
            candidate,
            *,
            bucket_size: int,
            attempted_rule_count: int,
            comparison_budget: int,
            lowering,
            lowering_provided: bool,
        ):
            self.calls.append((candidate, bucket_size, attempted_rule_count))
            assert lowering.term.operation == "add"
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
    optimizer._canonical_fallback_rules_by_root_shape = {
        ("add", 32, 2): [rule]
    }
    optimizer._get_candidates = lambda _ast: [RulePatternInfo(rule, object())]

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


def test_canonical_fallback_registration_keeps_declared_raw_base_shape() -> None:
    """Fallback-enabled adapters register one raw base and a separate shape bucket."""

    x = Var("x")

    class Rule:
        name = "CanonicalFallbackRule"
        maturities = [7]
        pattern = x + Const("one", 1)

    adapter = IDAPatternAdapter(Rule())
    adapter._canonical_fallback_enabled = True
    adapter._structural_matching_enabled = True
    adapter._canonical_fallback_root_shapes = (("add", 32, 2),)
    optimizer = PatternOptimizer(maturities=[7], stats=None, log_dir=None)

    assert optimizer._add_rule_internal(adapter)
    assert len(adapter.pattern_candidates) == 1
    assert optimizer._indexed_storage.total_patterns == 1
    assert optimizer._canonical_fallback_rules_by_root_shape[("add", 32, 2)] == [
        adapter
    ]


def test_canonical_fallback_registration_sorts_certified_declaration_order() -> None:
    """Registration order cannot override the frozen catalogue declaration order."""

    optimizer = PatternOptimizer(maturities=[7], stats=None, log_dir=None)
    adapters = []
    for rule_id in (1, 0):
        adapter = object.__new__(IDAPatternAdapter)
        adapter.rule = SimpleNamespace(
            name=f"rule-{rule_id}", pattern=None, maturities=[7]
        )
        adapter._canonical_fallback_enabled = True
        adapter._structural_matching_enabled = True
        adapter._canonical_fallback_root_shapes = (("add", 32, 2),)
        adapter._certified_catalogue_rule_id = rule_id
        adapter._pattern_candidates_cache = []
        adapters.append(adapter)

    for adapter in adapters:
        optimizer._add_rule_internal(adapter)

    assert optimizer._canonical_fallback_rules_by_root_shape[("add", 32, 2)] == [
        adapters[1],
        adapters[0],
    ]


def test_adapter_clears_structural_attempt_state_on_context_reset() -> None:
    """A failed/reloaded adapter cannot retain AST, report, path, or native refs."""

    adapter = IDAPatternAdapter(SimpleNamespace(name="cleanup", maturities=[7]))
    stale = object()
    adapter._shadow_structural_lowering = stale
    adapter._shadow_lowering = stale
    adapter._shadow_source_ast = stale
    adapter._shadow_match_report = stale
    adapter._shadow_structural_native_paths = {"x": (0,)}
    adapter._shadow_native_path_unavailable = True
    adapter._shadow_structural_refused = True
    adapter.clear_match_context()

    assert adapter._shadow_structural_lowering is None
    assert adapter._shadow_lowering is None
    assert adapter._shadow_source_ast is None
    assert adapter._shadow_match_report is None
    assert adapter._shadow_structural_native_paths is None
    assert adapter._shadow_native_path_unavailable is False
    assert adapter._shadow_structural_refused is False


def test_clear_match_context_clears_every_field_when_telemetry_raises(
    monkeypatch,
) -> None:
    """Telemetry failure cannot retain borrowed adapter or rule state."""

    rule = SimpleNamespace(name="cleanup-raises", maturities=[7])
    adapter = IDAPatternAdapter(rule)
    stale = object()
    adapter._attempt_started = 1.0
    adapter._attempt_destination_size = 4
    adapter._attempt_input_ast = stale
    adapter._attempt_instruction = stale
    adapter._legacy_binding_paths = {"x": frozenset({(0,)})}
    adapter._shadow_lowering = stale
    adapter._shadow_structural_lowering = stale
    adapter._shadow_source_ast = stale
    adapter._shadow_match_report = stale
    adapter._shadow_structural_native_paths = {"x": (0,)}
    rule._current_blk = stale
    rule._current_ins = stale
    rule._runtime_constant_evaluator = lambda *_args, **_kwargs: 1

    def raise_telemetry() -> None:
        raise RuntimeError("telemetry failure")

    monkeypatch.setattr(adapter, "_record_catalogue_nonmatch", raise_telemetry)
    with pytest.raises(RuntimeError, match="telemetry failure"):
        adapter.clear_match_context()

    assert adapter._attempt_started is None
    assert adapter._attempt_destination_size is None
    assert adapter._attempt_input_ast is None
    assert adapter._attempt_instruction is None
    assert adapter._legacy_binding_paths is None
    assert adapter._shadow_lowering is None
    assert adapter._shadow_structural_lowering is None
    assert adapter._shadow_source_ast is None
    assert adapter._shadow_match_report is None
    assert adapter._shadow_structural_native_paths is None
    assert rule._current_blk is None
    assert rule._current_ins is None
    assert rule._runtime_constant_evaluator is None


def test_handler_clears_raw_rule_context_when_later_callback_raises() -> None:
    """The raw handler finally path clears a rule before propagating later errors."""

    class Instruction:
        ea = 0x401000

        class d:
            size = 4

        @staticmethod
        def _print():
            return "raw-later-error"

    class Rule:
        name = "raw-later-error"
        maturities = [7]
        uses_structural_matching = False

        def __init__(self) -> None:
            self.bound = False
            self.cleared = False

        def bind_match_context(self, _blk, _ins):
            self.bound = True

        def clear_match_context(self):
            self.cleared = True

        def check_pattern_and_replace(self, _pattern, _candidate):
            return None

    rule = Rule()
    optimizer = object.__new__(PatternOptimizer)
    optimizer.stats = None
    optimizer.cur_maturity = 7
    optimizer._use_nomut_matching = False
    optimizer._use_legacy_storage = False
    optimizer._run_later_callback = lambda *_args: (_ for _ in ()).throw(
        RuntimeError("later callback failure")
    )
    optimizer._pending_replacement_rule = None
    optimizer._get_candidates = lambda _candidate: [RulePatternInfo(rule, object())]

    with pytest.raises(RuntimeError, match="later callback failure"):
        optimizer._try_matches(
            None,
            Instruction(),
            object(),
            allowed_rule_names=None,
            scheduled_rule_names=None,
            source_label="raw-later-error",
        )
    assert rule.bound is True
    assert rule.cleared is True


def test_handler_clears_fallback_rule_context_when_later_callback_raises(
    monkeypatch,
) -> None:
    """The structural fallback finally path also clears before propagation."""

    class Instruction:
        ea = 0x401000

        class d:
            size = 4

        @staticmethod
        def _print():
            return "fallback-later-error"

    class Rule:
        name = "fallback-later-error"
        maturities = [7]
        uses_structural_matching = True
        canonical_fallback_enabled = True

        def __init__(self) -> None:
            self.bound = False
            self.cleared = False

        def bind_match_context(self, _blk, _ins):
            self.bound = True

        def clear_match_context(self):
            self.cleared = True

        def match_structural_and_replace(self, *_args, **_kwargs):
            return None

    rule = Rule()
    optimizer = object.__new__(PatternOptimizer)
    optimizer.stats = None
    optimizer.cur_maturity = 7
    optimizer._use_nomut_matching = False
    optimizer._use_legacy_storage = False
    optimizer._run_later_callback = lambda *_args: (_ for _ in ()).throw(
        RuntimeError("fallback later callback failure")
    )
    optimizer._pending_replacement_rule = None
    optimizer._get_candidates = lambda _candidate: []
    monkeypatch.setattr(
        optimizer,
        "_prepare_canonical_fallback",
        lambda *_args, **_kwargs: (SimpleNamespace(term=object()), (rule,)),
    )

    with pytest.raises(RuntimeError, match="fallback later callback failure"):
        optimizer._try_matches(
            None,
            Instruction(),
            object(),
            allowed_rule_names=None,
            scheduled_rule_names=None,
            source_label="fallback-later-error",
        )
    assert rule.bound is True
    assert rule.cleared is True


def test_handler_shares_canonical_budget_across_multiple_fallback_adapters(
    monkeypatch,
) -> None:
    """One root callback cannot give every eligible fallback adapter 64 comparisons."""

    class Instruction:
        ea = 0x401000

        class d:
            size = 4

        @staticmethod
        def _print():
            return "shared-fallback-budget"

    class Rule:
        canonical_fallback_enabled = True
        maturities = (7,)

        def __init__(self, name, consumed, replacement=None):
            self.name = name
            self.consumed = consumed
            self.replacement = replacement
            self.budgets = []
            self.canonical_fallback_comparisons = 0
            self.canonical_fallback_budget_exhausted = False

        def match_structural_and_replace(self, *_args, comparison_budget, **_kwargs):
            self.budgets.append(comparison_budget)
            self.canonical_fallback_comparisons = self.consumed
            self.canonical_fallback_budget_exhausted = (
                self.consumed >= comparison_budget
            )
            return self.replacement

    first = Rule("first-fallback", 40)
    second = Rule("second-fallback", 20, replacement="replacement")
    optimizer = object.__new__(PatternOptimizer)
    optimizer.stats = None
    optimizer.cur_maturity = 7
    optimizer._use_nomut_matching = False
    optimizer._use_legacy_storage = False
    optimizer._run_later_callback = None
    optimizer._pending_replacement_rule = None
    optimizer._get_candidates = lambda _candidate: []
    monkeypatch.setattr(
        optimizer,
        "_prepare_canonical_fallback",
        lambda *_args, **_kwargs: (object(), (first, second)),
    )

    assert (
        optimizer._try_matches(
            None,
            Instruction(),
            object(),
            allowed_rule_names=None,
            scheduled_rule_names=None,
            source_label="shared-fallback-budget",
        )
        == "replacement"
    )
    assert first.budgets == [64]
    assert second.budgets == [24]
    assert first.canonical_fallback_comparisons + second.canonical_fallback_comparisons <= 64


def test_fallback_budget_exhaustion_discards_partial_report_before_emission(
    monkeypatch,
) -> None:
    """A report with matches and COMPARISON_BUDGET is a root-level no-op."""

    x = Var("x")

    class Rule:
        pattern = x + Const("zero", 0)
        replacement = x

    adapter = IDAPatternAdapter(Rule())
    adapter._canonical_fallback_enabled = True
    adapter._structural_matching_enabled = True
    source = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("x", 1), _constant(0))
    source.dest_size = 4
    source.ea = 0x401000
    partial_report = SimpleNamespace(
        matches=(object(),),
        bindings=object(),
        comparisons=64,
        commuted_branches=0,
        flattened_nodes=0,
        stop_reason=AcMatchStopReason.COMPARISON_BUDGET,
    )
    monkeypatch.setattr(
        adapter,
        "observe_structural_match",
        lambda *_args, **_kwargs: partial_report,
    )
    adapter._shadow_structural_native_paths = {"x": (0,)}
    monkeypatch.setattr(
        adapter,
        "_get_shadow_replacement",
        lambda _candidate: pytest.fail("budget exhaustion must not emit"),
    )

    assert (
        adapter.match_structural_and_replace(
            source,
            bucket_size=2,
            attempted_rule_count=1,
            comparison_budget=64,
        )
        is None
    )
    assert adapter.canonical_fallback_budget_exhausted is True
    assert adapter.canonical_fallback_comparisons == 64


def test_terminal_fallback_error_abstains_root_before_later_adapter(monkeypatch) -> None:
    """An active fallback defect cannot let a later adapter mutate the root."""

    class Instruction:
        ea = 0x401000

        class d:
            size = 4

        @staticmethod
        def _print():
            return "terminal-fallback-error"

    class FailingRule:
        name = "failing-fallback"
        maturities = (7,)
        canonical_fallback_enabled = True

        def __init__(self):
            self.errors = []

        def match_structural_and_replace(self, *_args, **_kwargs):
            raise CanonicalFallbackError("matcher", RuntimeError("active defect"))

        def record_attempt_error(self, error):
            self.errors.append(error)

    class LaterRule:
        name = "later-fallback"
        maturities = (7,)
        canonical_fallback_enabled = True

        def __init__(self):
            self.invoked = False

        def match_structural_and_replace(self, *_args, **_kwargs):
            self.invoked = True
            return "must-not-mutate"

    failing = FailingRule()
    later = LaterRule()
    optimizer = object.__new__(PatternOptimizer)
    optimizer.stats = None
    optimizer.cur_maturity = 7
    optimizer._use_nomut_matching = False
    optimizer._use_legacy_storage = False
    optimizer._run_later_callback = None
    optimizer._pending_replacement_rule = None
    optimizer._get_candidates = lambda _candidate: []
    monkeypatch.setattr(
        optimizer,
        "_prepare_canonical_fallback",
        lambda *_args, **_kwargs: (object(), (failing, later)),
    )

    assert (
        optimizer._try_matches(
            None,
            Instruction(),
            object(),
            allowed_rule_names=None,
            scheduled_rule_names=None,
            source_label="terminal-fallback-error",
        )
        is None
    )
    assert later.invoked is False
    assert len(failing.errors) == 1
    assert failing.errors[0].stage == "matcher"


def test_structural_selection_failure_publishes_terminal_receipt() -> None:
    """Unavailable fallback matching remains observable as a terminal refusal."""

    x = Var("x")
    rule = SimpleNamespace(
        name="terminal-fallback",
        description="terminal-fallback",
        pattern=x + Const("one", 1),
        replacement=x,
        maturities=[7],
    )
    adapter = IDAPatternAdapter(rule)
    adapter._canonical_fallback_enabled = True
    adapter._structural_matching_enabled = True
    adapter._provider_outcome_capture_depth = 1
    source = ast_dispatcher.AstNode(ida_hexrays.m_add, _leaf("x", 1), _constant(1))
    source.dest_size = 4
    source.ea = 0x401000
    adapter._attempt_input_ast = source
    adapter._attempt_destination_size = 4

    adapter.observe_structural_match = lambda *_args, **_kwargs: None
    assert (
        adapter.match_structural_and_replace(
            source,
            bucket_size=1,
            attempted_rule_count=1,
            comparison_budget=64,
            lowering=None,
            lowering_provided=True,
        )
        is None
    )
    outcomes = adapter.provider_outcomes()
    assert outcomes
    terminal = outcomes[-1]
    assert terminal.status is ProviderOutcomeStatus.RECONSTRUCTION_FAILED
    assert terminal.refusal_reason == "profile_unavailable"
    assert terminal.matcher is not None
    assert terminal.matcher.terminal_stop_reason == "fallback_unavailable"


@pytest.mark.parametrize("preparer_outcome", ["raises", "none"])
def test_try_matches_publishes_one_terminal_receipt_when_preparation_fails(
    monkeypatch, preparer_outcome: str
) -> None:
    """A production fallback attempt records preparation failure exactly once."""

    class Instruction:
        class d:
            size = 4

    x = Var("x")
    rule = SimpleNamespace(
        name="preparation-failure",
        description="preparation-failure",
        pattern=x + Const("one", 1),
        replacement=x,
        maturities=[7],
    )
    adapter = IDAPatternAdapter(rule)
    adapter._canonical_fallback_enabled = True
    adapter._structural_matching_enabled = True
    adapter._provider_outcome_capture_depth = 1
    adapter._canonical_fallback_root_shapes = (("add", 32, 2),)
    adapter.observe_structural_match = lambda *_args, **_kwargs: None

    prepare_calls = 0

    def prepare(*_args, **_kwargs):
        nonlocal prepare_calls
        prepare_calls += 1
        if preparer_outcome == "raises":
            raise RuntimeError("preparation failed")
        return None

    monkeypatch.setattr(adapter, "prepare_structural_candidate", prepare)
    optimizer = object.__new__(PatternOptimizer)
    optimizer.stats = None
    optimizer.cur_maturity = 7
    optimizer._use_nomut_matching = False
    optimizer._use_legacy_storage = False
    optimizer._run_later_callback = None
    optimizer._pending_replacement_rule = None
    optimizer._canonical_fallback_rules_by_root_shape = {
        ("add", 32, 2): [adapter]
    }
    optimizer._get_candidates = lambda _ast: []

    assert (
        optimizer._try_matches(
            None,
            Instruction(),
            object(),
            allowed_rule_names=None,
            scheduled_rule_names=None,
            source_label="preparation-failure",
        )
        is None
    )
    assert prepare_calls == 1
    outcomes = adapter.provider_outcomes()
    assert len(outcomes) == 1
    terminal = outcomes[0]
    assert terminal.status is ProviderOutcomeStatus.RECONSTRUCTION_FAILED
    assert terminal.refusal_reason == "profile_unavailable"
    assert terminal.matcher is not None
    assert terminal.matcher.selection is MatcherSelection.CANONICAL_FALLBACK
    assert terminal.matcher.terminal_stop_reason == "fallback_unavailable"
    assert terminal.matcher.native_equivalence_verdict is None
    assert adapter._attempt_input_ast is None
    assert adapter._attempt_instruction is None
    assert adapter._shadow_lowering is None
    assert adapter._structural_selection_active is False
    assert rule._current_blk is None
    assert rule._current_ins is None
    assert rule._runtime_constant_evaluator is None


def test_profile_for_ast_reuses_exact_structural_lowering(monkeypatch) -> None:
    """Telemetry must not lower a structural fallback root a second time."""

    from d810.backends.mba import hexrays_island

    adapter = IDAPatternAdapter(SimpleNamespace(name="profile-reuse", maturities=[7]))
    source_ast = object()
    profile = SimpleNamespace(fingerprint="reused-profile")
    adapter._shadow_source_ast = source_ast
    adapter._shadow_lowering = SimpleNamespace(profile=profile)

    def unexpected_lowering(*_args, **_kwargs):
        raise AssertionError("exact structural profile should be reused")

    monkeypatch.setattr(
        hexrays_island,
        "lower_hexrays_island",
        unexpected_lowering,
    )
    assert adapter._profile_for_ast(source_ast) is profile

    adapter._canonical_fallback_enabled = True
    adapter._shadow_source_ast = None
    adapter._shadow_lowering = None
    assert adapter._profile_for_ast(object()) is None

    replacement_profile = SimpleNamespace(fingerprint="fresh-profile")
    adapter._canonical_fallback_enabled = False
    adapter._attempt_destination_size = 4
    monkeypatch.setattr(
        hexrays_island,
        "lower_hexrays_island",
        lambda *_args, **_kwargs: SimpleNamespace(
            profile=replacement_profile,
            term=object(),
        ),
    )
    assert adapter._profile_for_ast(object()) is replacement_profile


@pytest.mark.usefixtures("ida_database")
class TestRawSuccessTelemetry:
    binary_name = "libobfuscated.dll"

    @pytest.mark.parametrize("nomut", (False, True))
    def test_real_adapter_does_not_lower(self, monkeypatch, nomut) -> None:
        """Raw adapter success telemetry uses native identity without canonical lowering."""

        class Rule:
            name = "raw-success"
            CANONICAL_NAME = "raw-success"
            ALIASES = ()
            replacement = None

        adapter = IDAPatternAdapter(Rule())
        adapter.begin_provider_outcome_capture()
        instruction = _raw_instruction(
            opcode=ida_hexrays.m_add,
            left=_raw_register(1),
            right=_raw_register(2),
            destination=_raw_register(3),
        )
        monkeypatch.setattr(
            "d810.backends.mba.ida.minsn_to_ast",
            lambda _instruction: SimpleNamespace(is_node=lambda: False),
        )
        adapter.bind_match_context(None, instruction)

        def forbidden_lowering(*_args, **_kwargs):
            raise AssertionError("raw success telemetry must not lower canonical island")

        monkeypatch.setattr(
            "d810.backends.mba.hexrays_island.lower_hexrays_island",
            forbidden_lowering,
        )
        if nomut:
            adapter.record_bound_replacement_outcome(
                SimpleNamespace(is_node=lambda: False)
            )
        else:
            candidate = SimpleNamespace(
                check_pattern_and_copy_mops=lambda _ast: True,
                ea=instruction.ea,
                dst_mop=None,
            )
            adapter._check_candidate = lambda _candidate: True
            adapter.get_replacement = lambda _candidate: SimpleNamespace(
                is_node=lambda: False
            )
            adapter.check_pattern_and_replace(
                candidate, SimpleNamespace(is_node=lambda: False)
            )

        outcome = adapter.provider_outcomes()[0]
        assert outcome.status is ProviderOutcomeStatus.IMPROVED
        assert outcome.fingerprint.startswith("raw:")


def test_fallback_miss_publishes_dispatch_telemetry_before_clearing_refs() -> None:
    """Fallback miss retains POD dispatch/matcher telemetry but no borrowed refs."""

    from d810.mba.ac_matching import AcMatchStopReason

    adapter = IDAPatternAdapter(SimpleNamespace(name="fallback-miss", maturities=[7]))
    adapter._canonical_fallback_enabled = True
    adapter._structural_matching_enabled = True
    adapter.begin_provider_outcome_capture()
    adapter._attempt_destination_size = 4
    adapter._attempt_input_ast = SimpleNamespace(is_node=lambda: False, ea=0x401020)
    lowering = SimpleNamespace(
        profile=SimpleNamespace(fingerprint="fallback-profile"),
        term=SimpleNamespace(width=32),
        raw_term=SimpleNamespace(width=32),
    )
    report = SimpleNamespace(
        bindings=object(),
        comparisons=5,
        commuted_branches=2,
        flattened_nodes=3,
        stop_reason=AcMatchStopReason.MISS,
    )
    adapter._shadow_structural_native_paths = {"x": ()}
    adapter._shadow_lowering = lowering
    adapter._shadow_match_report = report
    adapter._native_profile_metadata = lambda _profile: {
        "native_profile": {"fingerprint": "fallback-profile"}
    }
    adapter.observe_structural_match = lambda *_args, **_kwargs: report
    adapter._check_candidate = lambda _candidate: False

    assert adapter.match_structural_and_replace(
        SimpleNamespace(ea=0x401020),
        bucket_size=3,
        attempted_rule_count=2,
        comparison_budget=64,
        lowering=lowering,
        lowering_provided=True,
    ) is None

    outcome = adapter.provider_outcomes()[0]
    assert outcome.metadata["structural_dispatch"] == {
        "bucket_size": 3,
        "attempted_rule_count": 2,
    }
    assert outcome.metadata["canonical_source"] == "fallback-miss"
    assert outcome.matcher.stop_reason == "miss"
    assert outcome.matcher.selection is MatcherSelection.CANONICAL_FALLBACK
    assert outcome.matcher.terminal_stop_reason == "miss"
    assert outcome.matcher.native_equivalence_verdict is None
    assert adapter._shadow_lowering is None
    assert adapter._shadow_match_report is None
    assert adapter._shadow_structural_native_paths is None


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


def test_structural_only_hit_is_refused_for_mixed_width_replacement(monkeypatch) -> None:
    """A completed native width rejection is not unresolved safe coverage."""

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
    assert adapter._shadow_parity_ledger.new_safe_coverage_pending == 0
    assert adapter._shadow_parity_ledger.new_safe_coverage_refused == 1
