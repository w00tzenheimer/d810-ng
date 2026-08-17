"""End-to-end semantic and structural evidence for Task 13 corpus rows.

The native corpus runner owns IDA/provider history capture.  These focused
oracles keep the source/truth contract executable even when GCC or Hex-Rays
elides a source shape before a provider can observe it.
"""

from __future__ import annotations

import ctypes
from dataclasses import replace
import json
import random
import shutil
import subprocess
from types import SimpleNamespace
from pathlib import Path

import pytest

from d810.backends.mba.egglog_structural_rules import (
    StructuralRuleStatus,
    compile_fixed_rotate_rules,
    structural_catalogue_for_rules,
)
from d810.mba.island_profile import IslandBlocker
from d810.mba.semantic_canonicalization import (
    CanonicalizationKind,
    canonicalize_mba_term,
)
from d810.mba.typed_term import TypedBvTerm, fixed_shift_term, term_fingerprint


_ROOT = Path(__file__).resolve().parents[3]
_SOURCE = _ROOT / "samples/src/c/mba_compiler_shapes.c"
_MANIFEST = _ROOT / "tests/fixtures/mba_portfolio/compiler_shapes.json"
_TASK13_CASE_IDS = (
    "canonical_xor_negative_coefficient_32",
    "equivalent_xor_replay_32",
    "fixed_rotate_complementary_32",
    "fixed_shift_noncomplementary_32",
    "fixed_shift_arithmetic_right_32",
    "fixed_shift_variable_count_32",
)


def _manifest_cases() -> dict[str, dict[str, object]]:
    payload = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    return {
        case["case_id"]: case
        for case in payload["cases"]
        if case["case_id"] in _TASK13_CASE_IDS
    }


def _leaf(name: str) -> TypedBvTerm:
    return TypedBvTerm(None, 32, leaf_key=("task13", name))


def _constant(value: int) -> TypedBvTerm:
    return TypedBvTerm(None, 32, value=value)


def _binary(
    operation: str, left: TypedBvTerm, right: TypedBvTerm
) -> TypedBvTerm:
    return TypedBvTerm(operation, 32, children=(left, right))


def _eval(term: TypedBvTerm, values: dict[tuple[object, ...], int]) -> int:
    mask = (1 << term.width) - 1
    if term.operation is None:
        if term.value is not None:
            return term.value & mask
        assert term.leaf_key is not None
        return values[term.leaf_key] & mask
    child_values = tuple(_eval(child, values) for child in term.children)
    if term.operation == "add":
        result = child_values[0] + child_values[1]
    elif term.operation == "sub":
        result = child_values[0] - child_values[1]
    elif term.operation == "mul":
        result = child_values[0] * child_values[1]
    elif term.operation == "and":
        result = child_values[0] & child_values[1]
    elif term.operation == "or":
        result = child_values[0] | child_values[1]
    elif term.operation == "xor":
        result = child_values[0] ^ child_values[1]
    elif term.operation == "neg":
        result = -child_values[0]
    elif term.operation == "shl":
        result = child_values[0] << term.shift_count
    elif term.operation == "lshr":
        result = child_values[0] >> term.shift_count
    elif term.operation == "rol":
        count = term.shift_count
        result = (child_values[0] << count) | (child_values[0] >> (term.width - count))
    else:  # pragma: no cover - the test terms use only the operations above.
        raise AssertionError(term.operation)
    return result & mask


def _task13_terms() -> tuple[TypedBvTerm, TypedBvTerm]:
    x = _leaf("x")
    y = _leaf("y")
    and_xy = _binary("and", x, y)
    sum_xy = _binary("add", x, y)
    historical = _binary("sub", sum_xy, _binary("mul", _constant(2), and_xy))
    negative = _binary(
        "add",
        sum_xy,
        _binary("mul", _constant(-2), and_xy),
    )
    return historical, negative


def test_historical_and_modular_negative_forms_share_canonical_fingerprint() -> None:
    historical, negative = _task13_terms()
    historical_view = canonicalize_mba_term(historical)
    negative_view = canonicalize_mba_term(negative)

    assert term_fingerprint(historical_view.canonical_term) == term_fingerprint(
        negative_view.canonical_term
    )
    assert {step.kind for step in negative_view.steps} >= {
        CanonicalizationKind.NEGATIVE_COEFFICIENT,
        CanonicalizationKind.ADD_NEG_TO_SUB,
    }
    assert historical_view.canonical_term.operation == "sub"
    assert negative_view.raw_term.operation == "add"

    rng = random.Random(880)
    for _ in range(32):
        values = {
            ("task13", "x"): rng.randrange(1 << 32),
            ("task13", "y"): rng.randrange(1 << 32),
        }
        expected = values[("task13", "x")] ^ values[("task13", "y")]
        assert _eval(historical_view.canonical_term, values) == expected
        assert _eval(negative_view.canonical_term, values) == expected


def test_complementary_rotate_residual_uses_only_width_correct_certified_rule() -> None:
    x = _leaf("x")
    residual = _binary(
        "or",
        fixed_shift_term("shl", 32, x, 7),
        fixed_shift_term("lshr", 32, x, 25),
    )
    receipts = compile_fixed_rotate_rules(width=32, direction="rol")
    receipt = receipts[6]
    assert receipt.source_name == "rol_32_7"
    assert receipt.status is StructuralRuleStatus.COMPILED
    assert receipt.compiled_rule is not None
    catalogue = structural_catalogue_for_rules((receipt.compiled_rule,))
    applications = catalogue.canonical_applications(residual)
    assert len(applications) == 1
    _rule, replacement, _comparisons = applications[0]
    assert replacement.operation == "rol"
    assert replacement.width == 32
    assert replacement.shift_count == 7


def test_refusal_rows_are_explicit_and_never_provider_yield() -> None:
    cases = _manifest_cases()
    assert tuple(cases) == _TASK13_CASE_IDS
    assert cases["fixed_rotate_complementary_32"]["expected_route"] == ["egglog"]
    for case_id, blocker in (
        (
            "fixed_shift_noncomplementary_32",
            "no_degree_eligible_improvement",
        ),
        ("fixed_shift_arithmetic_right_32", "ambiguous_shift"),
        ("fixed_shift_variable_count_32", "ambiguous_shift"),
    ):
        case = cases[case_id]
        assert case["expected_route"] == []
        assert case["expected_blocker"] == blocker


def _native_fixed_shift_case(
    operation: int,
    *,
    count: int | None,
    variable_count: bool = False,
    root_or: bool = False,
    right_count: int | None = None,
):
    """Build one exact fixed-shift shape in the native AST layer."""

    import ida_hexrays
    from d810.hexrays.expr import ast as ast_dispatcher
    from d810.hexrays.ir.mop_snapshot import MopSnapshot

    base = ast_dispatcher.AstLeaf("shift_base")
    base.mop = MopSnapshot(t=ida_hexrays.mop_r, size=4, reg=3)
    base.dest_size = 4

    def shift(opcode, shift_count):
        right = (
            ast_dispatcher.AstLeaf("shift_count")
            if variable_count
            else ast_dispatcher.AstConstant(str(shift_count), shift_count, 1)
        )
        if variable_count:
            right.mop = MopSnapshot(t=ida_hexrays.mop_r, size=1, reg=4)
        else:
            right.mop = MopSnapshot(t=ida_hexrays.mop_n, size=1, value=shift_count)
        right.dest_size = 1
        node = ast_dispatcher.AstNode(opcode, base.clone(), right)
        node.dest_size = 4
        return node

    if root_or:
        assert count is not None
        left = shift(ida_hexrays.m_shl, count)
        right = shift(
            ida_hexrays.m_shr,
            32 - count if right_count is None else right_count,
        )
        root = ast_dispatcher.AstNode(ida_hexrays.m_or, left, right)
        root.dest_size = 4
        return root
    if operation == ida_hexrays.m_sar:
        return shift(operation, count)
    return shift(operation, count)


def test_native_ast_negative_fixed_shifts_are_noops_with_stable_blockers() -> None:
    """Lower native refusal shapes and keep the manifest blocker vocabulary exact."""

    import ida_hexrays
    from d810.backends.mba.egglog_saturation import (
        EgglogExtractionBudget,
        ExtractionSkipReason,
        extract_bounded_candidate,
    )
    from d810.backends.mba.egglog_structural_rules import (
        compile_all_fixed_rotate_rules,
        structural_catalogue_for_rules,
    )
    from d810.backends.mba.hexrays_island import lower_hexrays_island

    rules = tuple(
        receipt.compiled_rule
        for receipt in compile_all_fixed_rotate_rules()
        if receipt.compiled_rule is not None
    )
    noncomplementary = _native_fixed_shift_case(
        ida_hexrays.m_or,
        count=5,
        root_or=True,
        right_count=26,
    )
    noncomplementary_lowering = lower_hexrays_island(
        noncomplementary,
        destination_size=4,
    )
    assert noncomplementary_lowering.term is not None
    catalogue = structural_catalogue_for_rules(rules)
    assert catalogue.canonical_applications(noncomplementary_lowering.term) == ()
    no_rule = extract_bounded_candidate(
        noncomplementary,
        rules,
        EgglogExtractionBudget(
            max_leaves=2,
            max_operator_nodes=4,
            max_eclasses=128,
            max_enodes=256,
            time_budget_ms=1000,
        ),
        4,
        catalogue=catalogue,
    )
    assert no_rule.replacement_ast is None
    assert (
        no_rule.receipt.skip_reason
        is ExtractionSkipReason.NO_DEGREE_ELIGIBLE_IMPROVEMENT
    )

    arithmetic_lowering = lower_hexrays_island(
        _native_fixed_shift_case(ida_hexrays.m_sar, count=5),
        destination_size=4,
    )
    variable_lowering = lower_hexrays_island(
        _native_fixed_shift_case(ida_hexrays.m_shl, count=None, variable_count=True),
        destination_size=4,
    )
    assert arithmetic_lowering.term is None
    assert arithmetic_lowering.profile.blockers == (IslandBlocker.AMBIGUOUS_SHIFT,)
    assert variable_lowering.term is None
    assert variable_lowering.profile.blockers == (IslandBlocker.AMBIGUOUS_SHIFT,)

    cases = _manifest_cases()
    assert no_rule.receipt.skip_reason.value == cases[
        "fixed_shift_noncomplementary_32"
    ]["expected_blocker"]
    assert arithmetic_lowering.profile.blockers[0].value == cases[
        "fixed_shift_arithmetic_right_32"
    ]["expected_blocker"]
    assert variable_lowering.profile.blockers[0].value == cases[
        "fixed_shift_variable_count_32"
    ]["expected_blocker"]


def _find_compiler() -> str:
    compiler = next(
        (candidate for candidate in ("clang", "gcc", "cc") if shutil.which(candidate)),
        None,
    )
    if compiler is None:
        raise RuntimeError("Task 13 native truth evidence needs a C compiler")
    return compiler


def test_task13_native_source_truth_vectors(tmp_path: Path) -> None:
    """Compile every appended pair before making any provider-yield claim."""

    compiler = _find_compiler()
    library_path = tmp_path / "libmba_task13_shapes.so"
    flags = (
        "-shared",
        "-fPIC",
        "-O0",
        "-fno-inline",
        "-fno-builtin",
        "-fno-omit-frame-pointer",
    )
    if Path(compiler).name.startswith("clang"):
        flags += ("-fno-vectorize", "-fno-slp-vectorize")
    subprocess.run(
        [
            compiler,
            *flags,
            "-I",
            str(_ROOT / "samples/include"),
            "-o",
            str(library_path),
            str(_SOURCE),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    library = ctypes.CDLL(str(library_path))
    cases = _manifest_cases()
    scalar = ctypes.c_uint32
    rng = random.Random(880)
    vectors = tuple(
        tuple(rng.randrange(1 << 32) for _ in range(8))
        for _ in range(24)
    )
    for case_id in _TASK13_CASE_IDS:
        case = cases[case_id]
        shape = getattr(library, case["function"])
        truth = getattr(library, case["ground_truth_function"])
        shape.argtypes = [scalar] * 8
        truth.argtypes = [scalar] * 8
        shape.restype = scalar
        truth.restype = scalar
        for arguments in vectors:
            assert shape(*arguments) == truth(*arguments), (case_id, arguments)


class _NoDirectNativeCatalogue:
    """Hand-built native route fixture with all direct catalogue matches disabled."""

    def match_root(self, _view, *, comparison_budget):
        del comparison_budget
        return SimpleNamespace(
            matches=(),
            comparisons=0,
            lazy_swaps=0,
            comparison_budget_exceeded=False,
        )

    def match_canonical_root(self, _term, *, comparison_budget):
        del comparison_budget
        from d810.mba.ac_matching import AcMatchStopReason

        return SimpleNamespace(
            matches=(),
            comparisons=0,
            commuted_branches=0,
            flattened_nodes=0,
            stop_reason=AcMatchStopReason.MISS,
        )


class _NativeDestination:
    size = 4


class _NativeInstruction:
    opcode = 0
    ea = 0x401000
    d = _NativeDestination()


def _native_semantic_candidate(*, historical: bool = False):
    """Build one raw compiler-shaped XOR AST in the IDA AST layer."""

    import ida_hexrays
    from d810.hexrays.expr import ast as ast_dispatcher
    from d810.hexrays.ir.mop_snapshot import MopSnapshot

    def leaf(name: str, register: int):
        value = ast_dispatcher.AstLeaf(name)
        value.mop = MopSnapshot(
            t=ida_hexrays.mop_r,
            size=4,
            reg=register,
        )
        value.dest_size = 4
        return value

    def constant(value: int):
        result = ast_dispatcher.AstConstant(str(value), value & 0xFFFFFFFF, 4)
        result.mop = MopSnapshot(
            t=ida_hexrays.mop_n,
            size=4,
            value=value & 0xFFFFFFFF,
        )
        result.dest_size = 4
        return result

    x = leaf("x", 1)
    y = leaf("y", 2)
    common_sum = ast_dispatcher.AstNode(
        ida_hexrays.m_add,
        x,
        y,
    )
    common_and = ast_dispatcher.AstNode(
        ida_hexrays.m_and,
        x.clone(),
        y.clone(),
    )
    coefficient = ast_dispatcher.AstNode(
        ida_hexrays.m_mul,
        constant(2 if historical else -2),
        common_and,
    )
    candidate = ast_dispatcher.AstNode(
        ida_hexrays.m_sub if historical else ida_hexrays.m_add,
        common_sum,
        coefficient,
    )
    for node in (common_sum, common_and, coefficient, candidate):
        node.dest_size = 4
    return candidate


def _native_candidate_terms(candidate):
    from d810.backends.mba.hexrays_island import lower_hexrays_island

    lowering = lower_hexrays_island(candidate, destination_size=4)
    assert lowering.term is not None, lowering.profile
    leaves = []

    def visit(term):
        if term.operation is None:
            if term.leaf_key is not None and term.leaf_key not in leaves:
                leaves.append(term.leaf_key)
            return
        for child in term.children:
            visit(child)

    visit(lowering.term)
    assert len(leaves) == 2
    from d810.mba.typed_term import TypedBvTerm

    replacement = TypedBvTerm(
        "xor",
        lowering.term.width,
        children=tuple(
            TypedBvTerm(None, lowering.term.width, leaf_key=leaf_key)
            for leaf_key in leaves
        ),
    )
    return lowering, replacement


def _prepare_native_route_handler(monkeypatch, *, candidate=None):
    """Return a real handler fed by a hand-built native AST and fake Egglog seam."""

    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module
    from d810.backends.mba.egglog_saturation import (
        EgglogExtractionReceipt,
        EgglogExtractionResult,
    )
    from d810.backends.mba.hexrays_island import lower_hexrays_island
    from d810.mba.island_profile import profile_to_dict
    from d810.mba.typed_term import term_cost
    from d810.optimizers.microcode.instructions.egraph.egglog_handler import (
        EgglogOptimizer,
    )

    if candidate is None:
        candidate = _native_semantic_candidate()
    lowering, replacement_term = _native_candidate_terms(candidate)
    handler = EgglogOptimizer()
    handler.configure(
        {
            "families": ["xor"],
            "maturities": ["GLOBAL_OPTIMIZED"],
            "max_leaves": 2,
            "max_operator_nodes": 16,
            "max_degree": 1,
            "saturation_rounds": 1,
            "max_eclasses": 128,
            "max_enodes": 256,
            "max_rule_firings": 32,
            "time_budget_ms": 1000,
            "learned_replay_enabled": True,
            "require_proof": True,
        }
    )
    handler.cross_block_constant_preparation = True
    handler._native_pattern_catalogue = _NoDirectNativeCatalogue()

    monkeypatch.setattr(handler_module, "minsn_to_ast", lambda _ins: candidate)
    monkeypatch.setattr(handler, "_candidate_skip_reason", lambda *_args: None)
    monkeypatch.setattr(handler, "_create_egglog_runtime", lambda: object())
    monkeypatch.setattr(
        handler_module,
        "rebuild_hexrays_island",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(handler, "_create_instruction", lambda *_args: object())
    monkeypatch.setattr(
        handler,
        "_node_count",
        lambda node: 100 if node is candidate else 0,
    )
    monkeypatch.setattr(
        handler,
        "_prove_selected_replacement",
        lambda *_args, **_kwargs: (True, "task13", None, True, True, 0.1, 0.1),
    )

    fresh_calls = []

    def fake_select(ast, *, destination_size, budget, egglog_runtime):
        del budget, egglog_runtime
        current = lower_hexrays_island(ast, destination_size=destination_size)
        assert current.term is not None
        fresh_calls.append(current.term)
        receipt = EgglogExtractionReceipt(
            input_cost=term_cost(current.term),
            extracted_cost=term_cost(replacement_term),
            selected_family="xor",
            selected_source="Xor_HackersDelightRule_3",
            derivation_trace=(("xor", "Xor_HackersDelightRule_3", ()),),
            island_class=current.profile.island_class.value,
            island_fingerprint=current.profile.fingerprint,
            operator_count=current.profile.operator_count,
            distinct_leaf_count=current.profile.distinct_leaf_count,
            nonlinear_product_count=current.profile.nonlinear_product_count,
            native_profile=profile_to_dict(current.profile),
            execution_path="fresh_saturation",
            cache_status="miss",
            egglog_run_count=1,
        )
        return EgglogExtractionResult(
            replacement_ast=None,
            replacement_term=replacement_term,
            receipt=receipt,
            selected_provenance=("xor", "Xor_HackersDelightRule_3", ()),
            derivation_trace=(("xor", "Xor_HackersDelightRule_3", ()),),
        )

    monkeypatch.setattr(handler, "_select_extraction", fake_select)
    return handler, candidate, lowering, replacement_term, fresh_calls


def test_native_ast_first_fresh_composite_then_replay_has_zero_runs(
    monkeypatch, copy_of_idb
):
    """Replay a distinct raw form through the copied IDB's durable cache."""

    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    assert copy_of_idb.working_path.exists()
    first_candidate = _native_semantic_candidate()
    first_handler, _candidate, first_lowering, _replacement, first_fresh_calls = (
        _prepare_native_route_handler(monkeypatch, candidate=first_candidate)
    )
    first_raw = first_lowering.raw_term or first_lowering.term
    assert first_raw is not None
    assert first_raw.operation == "add"

    # No mapping is injected: both adapters below resolve the production
    # netnode in this disposable copied IDB.  The accepted rewrite therefore
    # crosses the real persistence seam rather than a process-local fixture.
    first_handler._composite_cache = EgglogIdbCompositeCache()
    block = SimpleNamespace(mba=None)
    instruction = _NativeInstruction()
    first_handler.begin_provider_outcome_capture()
    try:
        first = first_handler._check_and_replace(instruction, blk=block)
        assert first is not None
        assert first_handler.last_extraction_receipt.execution_path == "fresh_saturation"
        assert first_handler.last_extraction_receipt.egglog_run_count == 1
        assert first_handler._pending_composite_rewrite is not None
        first_handler.record_mutation_accepted()
        assert first_handler._pending_composite_rewrite is None
        assert first_handler.provider_outcomes()[-1].status.value == "applied"
    finally:
        first_handler.end_provider_outcome_capture()

    second_candidate = _native_semantic_candidate(historical=True)
    second_handler, _candidate, second_lowering, _replacement, second_fresh_calls = (
        _prepare_native_route_handler(monkeypatch, candidate=second_candidate)
    )
    second_raw = second_lowering.raw_term or second_lowering.term
    assert second_raw is not None
    assert second_raw.operation == "sub"
    assert term_fingerprint(first_raw) != term_fingerprint(second_raw)
    assert term_fingerprint(
        canonicalize_mba_term(first_raw).canonical_term
    ) == term_fingerprint(canonicalize_mba_term(second_raw).canonical_term)

    second_handler._composite_cache = EgglogIdbCompositeCache()
    second_handler.begin_provider_outcome_capture()
    try:
        second = second_handler._check_and_replace(instruction, blk=block)
        assert second is not None
        assert second_handler.last_extraction_receipt.execution_path == "learned_replay"
        assert second_handler.last_extraction_receipt.egglog_run_count == 0
        assert len(first_fresh_calls) == 1
        assert not second_fresh_calls
        second_handler.record_mutation_accepted()
        assert second_handler.provider_outcomes()[-1].status.value == "applied"
        assert sum(
            outcome.status.value == "applied"
            for outcome in second_handler.provider_outcomes()
        ) == 1
    finally:
        second_handler.end_provider_outcome_capture()


@pytest.mark.parametrize(
    "stale_field",
    ("catalogue_digest", "profile_digest", "canonicalizer_version"),
)
def test_native_ast_stale_replay_fields_fall_through_to_fresh(
    monkeypatch,
    stale_field: str,
):
    from d810.mba.egglog_composite_rewrite import EgglogCompositeRewrite

    handler, _candidate, lowering, replacement, fresh_calls = (
        _prepare_native_route_handler(monkeypatch)
    )
    assert lowering.term is not None
    current = handler._current_replay_semantics()
    stale_value = (
        current.canonicalizer_version + 1
        if stale_field == "canonicalizer_version"
        else "0" * 64
    )
    stale_semantics = replace(current, **{stale_field: stale_value})
    stale = EgglogCompositeRewrite.from_extraction(
        input_term=lowering.term,
        output_term=replacement,
        derivation_trace=(("xor", "Xor_HackersDelightRule_3", ()),),
        semantics=stale_semantics,
    )

    class _StaleCache:
        def lookup(self, _bucket_key):
            return "hit", (stale,)

    handler._composite_cache = _StaleCache()
    handler.begin_provider_outcome_capture()
    try:
        result = handler._check_and_replace(
            _NativeInstruction(),
            blk=SimpleNamespace(mba=None),
        )
        assert result is not None
        receipt = handler.last_extraction_receipt
        assert receipt.execution_path == "fresh_saturation"
        assert receipt.cache_status == "stale"
        assert receipt.egglog_run_count == 1
        assert len(fresh_calls) == 1
        assert not any(
            outcome.status.value == "applied" for outcome in handler.provider_outcomes()
        )
    finally:
        handler.end_provider_outcome_capture()


class TestNativeFixedShiftResidual:
    """Use a real native block for helper materialization after direct abstention."""

    binary_name = "libobfuscated.dll"

    def test_complementary_shift_ast_abstains_direct_and_reaches_rol_helper(
        self,
        ida_database,
        configure_hexrays,
        setup_libobfuscated_funcs,
    ):
        del ida_database, configure_hexrays, setup_libobfuscated_funcs
        import ida_hexrays
        import idautils
        from d810.backends.mba.egglog_saturation import (
            EgglogExtractionBudget,
            extract_bounded_candidate,
        )
        from d810.backends.mba.egglog_structural_rules import (
            compile_all_fixed_rotate_rules,
            structural_catalogue_for_rules,
        )
        from d810.hexrays.expr import ast as ast_dispatcher
        from d810.hexrays.ir.mop_snapshot import MopSnapshot
        from d810.optimizers.microcode.instructions.peephole.rotate_idiom_recovery_native import (
            RotateIdiomRecoveryRule,
            _expression_from_instruction,
            _validated_native_match,
        )
        from tests.system.runtime.conftest import gen_microcode_at_maturity

        # The compiler fixture is not required to preserve a 64-bit root for
        # this proof.  Obtain only a live MBA allocator from the opened IDB;
        # the candidate itself is deliberately hand-built in the native AST
        # layer so elision cannot turn a mechanism assertion into a yield claim.
        block = None
        for function_ea in idautils.Functions():
            mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_GLBOPT2)
            if mba is None:
                continue
            if mba.qty:
                block = mba.get_mblock(0)
                if block is not None:
                    break
            if block is not None:
                break
        assert block is not None
        output = ida_hexrays.mop_t()
        output.make_reg(0, 8)

        # The direct fast path recognizes the multiply/shift idiom only.  A
        # hand-built native mop tree for complementary shift/or must abstain,
        # leaving the residual for the certified provider below.
        def number(value: int, size: int = 1):
            mop = ida_hexrays.mop_t()
            mop.make_number(value, size)
            return mop

        def nested(opcode, left, right, size: int = 8):
            inner = ida_hexrays.minsn_t(0x401000)
            inner.opcode = opcode
            inner.l = left
            inner.r = right
            inner.d = ida_hexrays.mop_t()
            inner.d.make_number(0, size)
            mop = ida_hexrays.mop_t()
            mop.create_from_insn(inner)
            mop.size = size
            return mop

        direct_candidate = ida_hexrays.minsn_t(0x401000)
        direct_candidate.opcode = ida_hexrays.m_or
        direct_candidate.l = nested(
            ida_hexrays.m_shl,
            output,
            number(31),
        )
        direct_candidate.r = nested(
            ida_hexrays.m_shr,
            output,
            number(33),
        )
        direct_candidate.d = output
        # Exercise the exact native direct-matcher seam on this same
        # complementary-shift instruction. The fast path admits only the
        # multiply/shift idiom, so it must abstain before the fixed-rotate
        # Egglog route handles the residual.
        direct_expression = _expression_from_instruction(direct_candidate)
        assert _validated_native_match(direct_expression) is None
        assert RotateIdiomRecoveryRule().check_and_replace(
            block,
            direct_candidate,
        ) is None

        base = ast_dispatcher.AstLeaf("rotate_base")
        base.mop = MopSnapshot.from_mop(output)
        base.dest_size = 8
        left = ast_dispatcher.AstNode(
            ida_hexrays.m_shl,
            base,
            ast_dispatcher.AstConstant("31", 31, 1),
        )
        left.right.mop = MopSnapshot(t=ida_hexrays.mop_n, size=1, value=31)
        left.right.dest_size = 1
        right = ast_dispatcher.AstNode(
            ida_hexrays.m_shr,
            base.clone(),
            ast_dispatcher.AstConstant("33", 33, 1),
        )
        right.right.mop = MopSnapshot(t=ida_hexrays.mop_n, size=1, value=33)
        right.right.dest_size = 1
        candidate = ast_dispatcher.AstNode(ida_hexrays.m_or, left, right)
        for node in (left, right, candidate):
            node.dest_size = 8

        from d810.backends.mba.hexrays_island import lower_hexrays_island

        lowering = lower_hexrays_island(candidate, destination_size=8)
        assert lowering.term is not None
        rules = tuple(
            receipt.compiled_rule
            for receipt in compile_all_fixed_rotate_rules()
            if receipt.compiled_rule is not None
        )
        result = extract_bounded_candidate(
            candidate,
            rules,
            EgglogExtractionBudget(
                max_leaves=2,
                max_operator_nodes=4,
                max_eclasses=128,
                max_enodes=256,
                time_budget_ms=1000,
            ),
            8,
            catalogue=structural_catalogue_for_rules(rules),
            block=block,
            destination=output,
        )
        assert result.replacement_ast is not None, result.receipt
        assert result.replacement_ast.l.d.l.helper == "__ROL8__"
        assert result.receipt.selected_family == "fixed_rotate"
        assert result.receipt.selected_source == "rol_64_31"
        assert result.receipt.degree == 1
        assert result.receipt.rule_firings == 1
        assert result.receipt.egglog_run_count is not None
        assert result.receipt.egglog_run_count >= 1
