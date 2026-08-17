from __future__ import annotations

from functools import lru_cache
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

egglog = pytest.importorskip("egglog")
ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.backends.mba.egglog_add_rule_compiler import (  # noqa: E402
    CERTIFICATE_WIDTHS,
    compiled_rules_for_families,
)
from d810.backends.mba.egglog_saturation import (  # noqa: E402
    EgglogExtractionBudget,
    EgglogExtractionReceipt,
    EgglogExtractionResult,
    ExtractionSkipReason,
    TypedBvTerm,
    extract_bounded_term,
    extract_bounded_candidate,
)
from d810.backends.mba.hexrays_island import lower_hexrays_island  # noqa: E402
from d810.backends.mba.native_mba_term_view import (  # noqa: E402
    NativeMbaTermView,
    NativeMbaViewResult,
)
from d810.hexrays.expr import ast as ast_dispatcher  # noqa: E402
from d810.hexrays.expr import p_ast  # noqa: E402
from d810.hexrays.ir.mop_snapshot import MopSnapshot  # noqa: E402
from d810.optimizers.microcode.instructions.egraph.egglog_handler import (  # noqa: E402
    EgglogOptimizer,
)
from d810.mba.semantic_canonicalization import canonicalize_mba_term  # noqa: E402
from d810.mba.typed_term import term_cost  # noqa: E402


def _view_from_typed_term(term):
    if term.operation is None:
        if term.value is not None:
            return NativeMbaTermView(None, term.width, constant_value=term.value)
        return NativeMbaTermView(None, term.width, leaf_key=term.leaf_key)
    return NativeMbaTermView(
        term.operation,
        term.width,
        children=tuple(_view_from_typed_term(child) for child in term.children),
    )


def _first_typed_operator_child(term):
    for child in term.children:
        if child.operation is not None:
            return child
    raise AssertionError("expected an operator child")


@pytest.fixture(autouse=True)
def _legacy_ast_fixture_bridge(monkeypatch):
    """Keep legacy handler seams focused while native E2E owns live mops."""

    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    def from_instruction(ins, *, destination_size, runtime=None):
        del runtime
        ast = handler_module.minsn_to_ast(ins)
        lowering = lower_hexrays_island(ast, destination_size=destination_size)
        return NativeMbaViewResult(
            view=None
            if lowering.term is None
            else _view_from_typed_term(lowering.term),
            profile=lowering.profile,
        )

    monkeypatch.setattr(
        handler_module.NativeMbaTermView,
        "from_instruction",
        from_instruction,
    )


@lru_cache(maxsize=1)
def _rules():
    return compiled_rules_for_families(
        ("add", "and", "bnot", "mul", "neg", "or", "sub", "xor")
    )


def _rule(family: str, source_name: str):
    matches = tuple(
        rule
        for rule in _rules()
        if rule.family == family and rule.source_name == source_name
    )
    assert len(matches) == 1
    return matches[0]


def _leaf(name: str, register: int, size: int = 4, ast_module=ast_dispatcher):
    leaf = ast_module.AstLeaf(name)
    leaf.mop = MopSnapshot(t=ida_hexrays.mop_r, size=size, reg=register)
    leaf.dest_size = size
    return leaf


def _constant(value: int, size: int = 4, ast_module=ast_dispatcher):
    wrapped = value & ((1 << (size * 8)) - 1)
    constant = ast_module.AstConstant(str(value), wrapped, size)
    constant.mop = MopSnapshot(t=ida_hexrays.mop_n, size=size, value=wrapped)
    constant.dest_size = size
    return constant


def _node(opcode: int, left, right=None, size: int = 4, ast_module=ast_dispatcher):
    node = ast_module.AstNode(opcode, left, right)
    node.dest_size = size
    return node


def _direct_add_candidate(size: int = 4, ast_module=ast_dispatcher):
    x = _leaf("x", 1, size, ast_module)
    y = _leaf("y", 2, size, ast_module)
    return _node(
        ida_hexrays.m_add,
        _node(ida_hexrays.m_xor, x, y, size=size, ast_module=ast_module),
        _node(
            ida_hexrays.m_mul,
            _constant(2, size, ast_module),
            _node(
                ida_hexrays.m_and,
                x.clone(),
                y.clone(),
                size=size,
                ast_module=ast_module,
            ),
            size=size,
            ast_module=ast_module,
        ),
        size=size,
        ast_module=ast_module,
    )


def _mixed_width_add_candidate():
    wide = _leaf("wide", 1, 4)
    narrow = _leaf("narrow", 2, 2)
    return _node(
        ida_hexrays.m_add,
        _node(ida_hexrays.m_xor, wide, narrow, size=4),
        _node(
            ida_hexrays.m_mul,
            _constant(2, 4),
            _node(ida_hexrays.m_and, wide.clone(), narrow.clone(), size=4),
            size=4,
        ),
        size=4,
    )


def _degree_two_candidate(size: int = 4) -> ast_dispatcher.AstNode:
    # BnotXor_FactorRule_1 keeps cost equal at degree 1:
    #   (~x) ^ (~y) -> ~((~x) ^ y)
    # Bnot_FactorRule_5 then strictly reduces at degree 2:
    #   ~((~x) ^ y) -> x ^ y
    return _node(
        ida_hexrays.m_xor,
        _node(ida_hexrays.m_bnot, _leaf("x", 1, size), size=size),
        _node(ida_hexrays.m_bnot, _leaf("y", 2, size), size=size),
        size=size,
    )


def _typed_leaf(name: str, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(None, width, leaf_key=("register", name))


def _typed_constant(value: int, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(None, width, value=value)


def _typed_node(
    operation: str,
    left: TypedBvTerm,
    right: TypedBvTerm | None = None,
) -> TypedBvTerm:
    return TypedBvTerm(
        operation,
        left.width,
        children=(left,) if right is None else (left, right),
    )


def _historical_xor_forms() -> tuple[TypedBvTerm, TypedBvTerm]:
    x, y = _typed_leaf("x"), _typed_leaf("y")
    common_sum = _typed_node("add", x, y)
    common_and = _typed_node("and", x, y)
    subtraction = _typed_node(
        "sub",
        common_sum,
        _typed_node("mul", _typed_constant(2), common_and),
    )
    negative_coefficient = _typed_node(
        "add",
        common_sum,
        _typed_node("mul", _typed_constant(-2), common_and),
    )
    return subtraction, negative_coefficient


@pytest.mark.parametrize("source", _historical_xor_forms(), ids=("subtraction", "negative-coefficient"))
def test_degree_one_extracts_xor_from_both_historical_forms(source: TypedBvTerm):
    rule = _rule("xor", "Xor_HackersDelightRule_3")
    result = extract_bounded_term(
        source,
        (rule,),
        EgglogExtractionBudget(time_budget_ms=1000),
        destination_size=4,
    )

    expected = _typed_node("xor", _typed_leaf("x"), _typed_leaf("y"))
    canonical = canonicalize_mba_term(source)
    assert result.replacement_term == expected
    assert result.receipt.input_cost == term_cost(source)
    assert result.receipt.canonical_input_cost == term_cost(canonical.canonical_term)
    assert result.receipt.canonicalizer_version == 1


def test_three_ms_telemetry_path_records_path_without_loading_egglog(monkeypatch):
    source, _negative_coefficient = _historical_xor_forms()

    def forbidden_load():
        raise AssertionError("telemetry-only extraction must not load Egglog")

    monkeypatch.setattr("d810.backends.mba.egglog_saturation._load_egglog_module", forbidden_load)
    result = extract_bounded_term(
        source,
        (),
        EgglogExtractionBudget(),
        destination_size=4,
    )

    assert result.receipt.execution_path == "telemetry_only"
    assert result.receipt.cache_status == "disabled"


@pytest.mark.parametrize("size", (1, 2, 4, 8))
def test_one_catalogue_rewrite_extracts_at_degree_one_and_proves_all_widths(size):
    candidate = _direct_add_candidate(size)
    rule = _rule("add", "Add_HackersDelightRule_2")

    result = extract_bounded_candidate(
        candidate,
        (rule,),
        EgglogExtractionBudget(time_budget_ms=1000),
        size,
    )

    assert rule.proof_widths == CERTIFICATE_WIDTHS
    assert result.replacement_ast is not None
    assert result.receipt.degree == 1
    assert result.receipt.skip_reason is None
    assert result.selected_provenance == (
        "add",
        "Add_HackersDelightRule_2",
        ("Add_OllvmRule_3",),
    )
    assert EgglogOptimizer._prove_ast_equivalence(
        candidate,
        result.replacement_ast,
        width=size * 8,
    )


@pytest.mark.parametrize("size", (1, 2, 4, 8))
def test_active_runtime_proxy_extracts_and_reconstructs_all_widths(size):
    candidate = _direct_add_candidate(size)
    rule = _rule("add", "Add_HackersDelightRule_2")

    result = extract_bounded_candidate(
        ast_dispatcher.AstProxy(candidate),
        (rule,),
        EgglogExtractionBudget(time_budget_ms=1000),
        size,
    )

    assert result.replacement_ast is not None
    assert result.receipt.degree == 1
    assert result.receipt.skip_reason is None
    assert EgglogOptimizer._prove_ast_equivalence(
        candidate,
        result.replacement_ast,
        width=size * 8,
    )


def test_non_active_python_ast_is_rejected_by_cython_dispatcher():
    if not ast_dispatcher._USING_CYTHON:
        pytest.skip("Cython AST dispatcher is not active")

    result = extract_bounded_candidate(
        p_ast.AstProxy(_direct_add_candidate(ast_module=p_ast)),
        (_rule("add", "Add_HackersDelightRule_2"),),
        EgglogExtractionBudget(time_budget_ms=1000),
        4,
    )

    assert result.replacement_ast is None
    assert (
        result.receipt.skip_reason is ExtractionSkipReason.UNSUPPORTED_WIDTH_SEMANTICS
    )


@pytest.mark.parametrize("size", (1, 2, 4, 8))
def test_active_cython_proxy_uses_real_c_ast_types(size):
    if not ast_dispatcher._USING_CYTHON:
        pytest.skip("Cython AST dispatcher is not active")
    c_ast = pytest.importorskip("d810.speedups.expr.c_ast")
    assert ast_dispatcher.AstProxy is c_ast.AstProxy
    assert ast_dispatcher.AstNode is c_ast.AstNode

    candidate = _direct_add_candidate(size, c_ast)
    result = extract_bounded_candidate(
        c_ast.AstProxy(candidate),
        (_rule("add", "Add_HackersDelightRule_2"),),
        EgglogExtractionBudget(time_budget_ms=1000),
        size,
    )

    assert isinstance(result.replacement_ast, c_ast.AstNode)
    assert result.receipt.skip_reason is None


def test_direct_ast_composed_catalogue_rewrite_needs_degree_two():
    """Exercise the extractor directly; this is not compiler-corpus evidence."""
    candidate = _degree_two_candidate()
    rules = (
        _rule("bnot", "BnotXor_FactorRule_1"),
        _rule("bnot", "Bnot_FactorRule_5"),
    )
    common = dict(
        saturation_rounds=2,
        time_budget_ms=1000,
        max_eclasses=256,
        max_enodes=512,
    )

    degree_one = extract_bounded_candidate(
        candidate,
        rules,
        EgglogExtractionBudget(max_degree=1, **common),
        4,
    )
    degree_two = extract_bounded_candidate(
        candidate,
        rules,
        EgglogExtractionBudget(max_degree=2, **common),
        4,
    )

    assert degree_one.replacement_ast is None
    assert (
        degree_one.receipt.skip_reason
        is ExtractionSkipReason.NO_DEGREE_ELIGIBLE_IMPROVEMENT
    )
    assert degree_two.replacement_ast is not None
    assert degree_two.receipt.degree == 2
    assert degree_two.selected_provenance == (
        "bnot",
        "Bnot_FactorRule_5",
        (),
    )
    expected_trace = (
        ("bnot", "BnotXor_FactorRule_1", ()),
        ("bnot", "Bnot_FactorRule_5", ()),
    )
    assert degree_two.derivation_trace == expected_trace
    assert degree_two.receipt.derivation_trace == expected_trace
    with pytest.raises(FrozenInstanceError):
        degree_two.derivation_trace = ()
    assert EgglogOptimizer._prove_ast_equivalence(
        candidate,
        degree_two.replacement_ast,
        width=32,
    )


def test_rule_firing_cap_returns_receipt_not_exception():
    result = extract_bounded_candidate(
        _degree_two_candidate(),
        (
            _rule("bnot", "BnotXor_FactorRule_1"),
            _rule("bnot", "Bnot_FactorRule_5"),
        ),
        EgglogExtractionBudget(
            max_degree=2,
            saturation_rounds=2,
            max_rule_firings=1,
            max_eclasses=256,
            max_enodes=512,
            time_budget_ms=1000,
        ),
        4,
    )

    assert result.replacement_ast is None
    # The cap rejects the projected rewrite frontier before registration or
    # execution, so no native rule firing has occurred yet.
    assert result.receipt.rule_firings == 0
    assert result.receipt.skip_reason is ExtractionSkipReason.RULE_FIRING_BUDGET


def test_ac_operand_order_uses_no_variant_catalogue_rewrite():
    direct = _direct_add_candidate()
    swapped = _node(ida_hexrays.m_add, direct.right, direct.left)
    rule = _rule("add", "Add_HackersDelightRule_2")

    result = extract_bounded_candidate(
        swapped,
        (rule,),
        EgglogExtractionBudget(time_budget_ms=1000),
        4,
    )

    assert result.replacement_ast is not None
    assert result.receipt.degree == 1
    assert result.receipt.rule_firings == 1
    assert result.selected_provenance == (
        "add",
        "Add_HackersDelightRule_2",
        ("Add_OllvmRule_3",),
    )


def test_ac_reassociation_uses_no_associativity_rewrite():
    x, y, z = _leaf("x", 1), _leaf("y", 2), _leaf("z", 3)
    candidate = _node(
        ida_hexrays.m_sub,
        _node(
            ida_hexrays.m_mul,
            _constant(2),
            _node(
                ida_hexrays.m_or,
                z,
                _node(ida_hexrays.m_or, y, x),
            ),
        ),
        _node(
            ida_hexrays.m_xor,
            x.clone(),
            _node(ida_hexrays.m_or, z.clone(), y.clone()),
        ),
    )
    rule = _rule("add", "Add_HackersDelightRule_5")

    result = extract_bounded_candidate(
        candidate,
        (rule,),
        EgglogExtractionBudget(max_leaves=3, time_budget_ms=1000),
        4,
    )

    assert result.replacement_ast is not None
    assert result.receipt.degree == 1
    assert result.receipt.rule_firings == 1
    assert result.selected_provenance == (
        "add",
        "Add_HackersDelightRule_5",
        (),
    )
    assert EgglogOptimizer._prove_ast_equivalence(
        candidate,
        result.replacement_ast,
        width=32,
    )


def test_grounded_constant_guard_fires_only_when_constraint_holds():
    rule = _rule("add", "Add_SpecialConstantRule_1")

    def candidate(second_constant: int) -> ast_dispatcher.AstNode:
        x = _leaf("x", 1)
        return _node(
            ida_hexrays.m_add,
            _node(ida_hexrays.m_xor, x, _constant(5)),
            _node(
                ida_hexrays.m_mul,
                _constant(2),
                _node(
                    ida_hexrays.m_and,
                    x.clone(),
                    _constant(second_constant),
                ),
            ),
        )

    valid_candidate = candidate(5)
    valid = extract_bounded_candidate(
        valid_candidate,
        (rule,),
        EgglogExtractionBudget(time_budget_ms=1000),
        4,
    )
    invalid = extract_bounded_candidate(
        candidate(6),
        (rule,),
        EgglogExtractionBudget(time_budget_ms=1000),
        4,
    )

    assert valid.replacement_ast is not None
    assert valid.receipt.rule_firings == 1
    assert valid.selected_provenance == (
        "add",
        "Add_SpecialConstantRule_1",
        (),
    )
    assert EgglogOptimizer._prove_ast_equivalence(
        valid_candidate,
        valid.replacement_ast,
        width=32,
    )
    assert invalid.replacement_ast is None
    assert invalid.receipt.rule_firings == 0
    assert (
        invalid.receipt.skip_reason
        is ExtractionSkipReason.NO_DEGREE_ELIGIBLE_IMPROVEMENT
    )


@pytest.mark.parametrize(
    ("budget", "reason"),
    [
        (
            EgglogExtractionBudget(max_operator_nodes=1),
            ExtractionSkipReason.CANDIDATE_BUDGET,
        ),
        (
            EgglogExtractionBudget(max_eclasses=1, time_budget_ms=1000),
            ExtractionSkipReason.ECLASS_BUDGET,
        ),
        (
            EgglogExtractionBudget(max_enodes=1, time_budget_ms=1000),
            ExtractionSkipReason.ENODE_BUDGET,
        ),
    ],
)
def test_resource_caps_abort_without_materializing_a_mop(budget, reason):
    result = extract_bounded_candidate(
        _direct_add_candidate(),
        (_rule("add", "Add_HackersDelightRule_2"),),
        budget,
        4,
    )

    assert result.replacement_ast is None
    assert result.receipt.skip_reason is reason


def test_one_schedule_round_cannot_authorize_a_degree_two_chain():
    result = extract_bounded_candidate(
        _degree_two_candidate(),
        (
            _rule("bnot", "BnotXor_FactorRule_1"),
            _rule("bnot", "Bnot_FactorRule_5"),
        ),
        EgglogExtractionBudget(
            max_degree=2,
            saturation_rounds=1,
            max_eclasses=256,
            max_enodes=512,
            time_budget_ms=1000,
        ),
        4,
    )

    assert result.replacement_ast is None
    assert (
        result.receipt.skip_reason
        is ExtractionSkipReason.NO_DEGREE_ELIGIBLE_IMPROVEMENT
    )


class _Destination:
    size = 4


class _Instruction:
    opcode = ida_hexrays.m_add
    ea = 0x401000
    d = _Destination()


def _configured_live_handler(**overrides) -> EgglogOptimizer:
    handler = EgglogOptimizer()
    config = {
        "max_leaves": 2,
        "max_operator_nodes": 10,
        "max_degree": 1,
        "saturation_rounds": 2,
        "max_eclasses": 256,
        "max_enodes": 512,
        "max_rule_firings": 32,
        "time_budget_ms": 1000,
        "require_proof": True,
        "families": ["add"],
    }
    config.update(overrides)
    handler.configure(config)
    return handler


def test_native_z3_timeout_requires_explicit_noninteractive_execution_mode():
    interactive = _configured_live_handler(time_budget_ms=1000)
    noninteractive = _configured_live_handler(
        time_budget_ms=1000,
        execution_mode="noninteractive",
    )

    assert interactive._native_z3_timeout_ms() == 50
    assert noninteractive._native_z3_timeout_ms() == 250


@pytest.mark.parametrize("execution_mode", ([], {}))
def test_live_handler_rejects_non_string_execution_mode(execution_mode):
    with pytest.raises(ValueError, match="execution_mode"):
        _configured_live_handler(execution_mode=execution_mode)


def test_live_handler_admits_and_extracts_real_degree_two_boolean_candidate():
    candidate = _degree_two_candidate()
    handler = _configured_live_handler(
        max_degree=2,
        families=["bnot"],
    )
    handler._catalogue = SimpleNamespace(
        compiled_rules=(
            _rule("bnot", "BnotXor_FactorRule_1"),
            _rule("bnot", "Bnot_FactorRule_5"),
        )
    )
    assert handler._is_candidate(candidate, _Instruction())
    extraction = handler._select_extraction(candidate, destination_size=4)

    assert extraction.replacement_ast is not None
    assert extraction.receipt.degree == 2
    assert extraction.receipt.skip_reason is None
    assert handler._prove_ast_equivalence(
        candidate,
        extraction.replacement_ast,
        width=32,
    )


def test_live_handler_receipts_candidate_budget_before_extraction(monkeypatch):
    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    candidate = _direct_add_candidate()
    handler = _configured_live_handler(max_operator_nodes=1)
    extraction_calls = []
    monkeypatch.setattr(handler_module, "minsn_to_ast", lambda _ins: candidate)
    monkeypatch.setattr(
        handler_module,
        "extract_bounded_candidate",
        lambda *args: extraction_calls.append(args),
    )

    assert handler._check_and_replace(_Instruction()) is None
    assert extraction_calls == []
    receipt = handler.last_extraction_receipt
    assert receipt is not None
    assert receipt.skip_reason is ExtractionSkipReason.CANDIDATE_BUDGET
    assert receipt.island_class == "linear_mba"
    assert receipt.island_fingerprint is not None


def test_live_handler_receipts_non_mba_candidate_before_extraction(monkeypatch):
    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    candidate = _node(ida_hexrays.m_mov, _leaf("x", 1))
    handler = _configured_live_handler()
    extraction_calls = []
    monkeypatch.setattr(handler_module, "minsn_to_ast", lambda _ins: candidate)
    monkeypatch.setattr(
        handler_module,
        "extract_bounded_candidate",
        lambda *args: extraction_calls.append(args),
    )

    assert handler._check_and_replace(_Instruction()) is None
    assert extraction_calls == []
    receipt = handler.last_extraction_receipt
    assert receipt is not None
    assert receipt.skip_reason is ExtractionSkipReason.UNSUPPORTED_WIDTH_SEMANTICS
    assert receipt.island_class == "unsupported"
    assert receipt.blockers == ("unsupported_opcode",)


def test_live_handler_unsupported_root_replaces_prior_invocation_metadata(monkeypatch):
    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    handler = _configured_live_handler()
    handler.last_extraction_receipt = EgglogExtractionReceipt(
        selected_family="add",
        selected_source="PriorRule",
    )
    handler.last_rule_family = "add"
    handler.last_rule_provenance = ("PriorRule",)
    handler.last_derivation_trace = (("add", "PriorRule", ()),)
    unsupported = SimpleNamespace(
        opcode=ida_hexrays.m_mov,
        ea=0x401004,
        d=_Destination(),
    )
    extraction_calls = []
    proof_calls = []
    monkeypatch.setattr(
        handler_module,
        "minsn_to_ast",
        lambda _ins: extraction_calls.append(_ins),
    )
    monkeypatch.setattr(
        handler,
        "_prove_ast_equivalence",
        lambda *args, **kwargs: proof_calls.append((args, kwargs)),
    )
    assert handler.check_and_replace(None, unsupported) is None
    receipt = handler.last_extraction_receipt
    assert receipt == EgglogExtractionReceipt(
        skip_reason=ExtractionSkipReason.NON_MBA_CANDIDATE
    )
    with pytest.raises(FrozenInstanceError):
        receipt.skip_reason = None
    assert handler.last_rule_family is None
    assert handler.last_rule_provenance is None
    assert handler.last_derivation_trace is None
    assert "derivation_trace" not in handler.execution_metadata()
    assert handler.execution_metadata()["skip_reason"] == "non_mba_candidate"
    assert extraction_calls == []
    assert proof_calls == []


def test_live_handler_exception_before_first_receipt_records_immutable_internal_error(
    monkeypatch,
):
    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    handler = _configured_live_handler()
    monkeypatch.setattr(
        handler_module,
        "minsn_to_ast",
        lambda _ins: (_ for _ in ()).throw(RuntimeError("conversion failed")),
    )

    assert handler.check_and_replace(None, _Instruction()) is None
    receipt = handler.last_extraction_receipt
    assert receipt == EgglogExtractionReceipt(
        skip_reason=ExtractionSkipReason.INTERNAL_ERROR
    )
    with pytest.raises(FrozenInstanceError):
        receipt.skip_reason = None


def test_live_handler_preflight_exception_preserves_lowered_profile(monkeypatch):
    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    handler = _configured_live_handler()
    monkeypatch.setattr(
        handler_module, "minsn_to_ast", lambda _ins: _direct_add_candidate()
    )
    monkeypatch.setattr(
        handler,
        "_native_view_skip_reason",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("preflight failed")),
    )

    assert handler.check_and_replace(None, _Instruction()) is None

    receipt = handler.last_extraction_receipt
    assert receipt is not None
    assert receipt.skip_reason is ExtractionSkipReason.INTERNAL_ERROR
    assert receipt.island_class == "linear_mba"
    assert receipt.island_fingerprint is not None
    assert receipt.operator_count == 4
    assert receipt.distinct_leaf_count == 2


def test_live_handler_receipts_mixed_width_candidate_without_extraction_or_mutation(
    monkeypatch,
):
    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    candidate = _mixed_width_add_candidate()
    handler = _configured_live_handler()
    extraction_calls = []
    proof_calls = []

    monkeypatch.setattr(handler_module, "minsn_to_ast", lambda _ins: candidate)
    monkeypatch.setattr(
        handler_module,
        "extract_bounded_candidate",
        lambda *args: extraction_calls.append(args),
    )
    monkeypatch.setattr(
        handler,
        "_prove_ast_equivalence",
        lambda *args, **kwargs: proof_calls.append((args, kwargs)),
    )
    assert handler._check_and_replace(_Instruction()) is None

    assert extraction_calls == []
    assert proof_calls == []
    receipt = handler.last_extraction_receipt
    assert receipt is not None
    assert receipt.skip_reason is ExtractionSkipReason.UNSUPPORTED_WIDTH_SEMANTICS
    assert receipt.island_class == "unsupported"
    assert receipt.blockers == ("mixed_width",)
    assert handler.execution_metadata()["skip_reason"] == "unsupported_width_semantics"


def test_live_handler_extracts_once_with_exact_configured_rules_then_proves_before_mop(
    monkeypatch,
):
    if ast_dispatcher._USING_CYTHON:
        pytest.skip(
            "Cython AstNode methods cannot be monkeypatched to observe ordering"
        )

    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    candidate = _direct_add_candidate()
    handler = _configured_live_handler()
    configured_rules = handler._compiled_rules
    real_extract = handler._select_native_extraction
    extraction_calls = []
    events = []

    def observe_extract(*args, **kwargs):
        extraction_calls.append((args, kwargs))
        events.append("extract")
        return real_extract(*args, **kwargs)

    monkeypatch.setattr(handler, "_select_native_extraction", observe_extract)
    monkeypatch.setattr(handler_module, "minsn_to_ast", lambda _ins: candidate)
    monkeypatch.setattr(
        handler,
        "_prove_ast_equivalence",
        lambda *_args, **_kwargs: events.append("native_z3") or True,
    )
    monkeypatch.setattr(
        ast_dispatcher.AstNode,
        "create_mop",
        lambda _self, _ea: events.append("create_mop") or object(),
    )

    class _ReplacementInstruction:
        def __init__(self, ea):
            self.ea = ea

    monkeypatch.setattr(ida_hexrays, "minsn_t", _ReplacementInstruction)

    replacement = handler._check_and_replace(_Instruction())

    assert len(extraction_calls) == 1
    assert extraction_calls[0][0][0].width == 32
    assert handler._compiled_rules is configured_rules
    assert handler.extraction_budget == EgglogExtractionBudget(
        max_eclasses=256,
        max_enodes=512,
        time_budget_ms=1000,
    )
    assert extraction_calls[0][1]["destination_size"] == 4
    assert events == ["extract", "native_z3", "create_mop"]
    assert replacement is not None
    assert replacement.opcode == ida_hexrays.m_mov
    receipt = handler.last_extraction_receipt
    assert receipt is not None
    assert receipt.skip_reason is None
    assert receipt.derivation_trace == (
        ("add", "Add_HackersDelightRule_2", ("Add_OllvmRule_3",)),
    )
    metadata = handler.execution_metadata()
    assert metadata["input_cost"] == receipt.input_cost
    assert metadata["extracted_cost"] == receipt.extracted_cost
    assert metadata["degree"] == 1
    assert metadata["eclass_count"] == receipt.eclass_count
    assert metadata["enode_count"] == receipt.enode_count
    assert metadata["rule_firings"] == receipt.rule_firings
    assert metadata["elapsed_ms"] == receipt.elapsed_ms
    assert metadata["selected_family"] == "add"
    assert metadata["selected_source"] == "Add_HackersDelightRule_2"
    assert metadata["selected_aliases"] == ("Add_OllvmRule_3",)
    assert metadata["island_class"] == "linear_mba"
    assert metadata["island_fingerprint"] == receipt.island_fingerprint
    assert metadata["operator_count"] == receipt.operator_count
    assert metadata["distinct_leaf_count"] == 2
    assert metadata["nonlinear_product_count"] == 0
    assert metadata["blockers"] == ()
    assert metadata["derivation_trace"] == (
        ("add", "Add_HackersDelightRule_2", ("Add_OllvmRule_3",)),
    )
    assert metadata["skip_reason"] is None


def test_shadow_template_and_legacy_proofs_agree_before_mop(monkeypatch):
    if ast_dispatcher._USING_CYTHON:
        pytest.skip("Cython AstNode methods cannot be monkeypatched for ordering")
    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    candidate = _direct_add_candidate()
    handler = _configured_live_handler(native_proof_mode="shadow")
    events = []
    monkeypatch.setattr(handler_module, "minsn_to_ast", lambda _ins: candidate)
    monkeypatch.setattr(
        handler,
        "_prove_ast_equivalence",
        lambda *_args, **_kwargs: events.append("native_z3") or True,
    )
    monkeypatch.setattr(
        ast_dispatcher.AstNode,
        "create_mop",
        lambda _self, _ea: events.append("create_mop") or object(),
    )
    monkeypatch.setattr(ida_hexrays, "minsn_t", lambda _ea: SimpleNamespace())

    assert handler._check_and_replace(_Instruction()) is not None
    # The template proof is a separate typed-term solver; this patched legacy
    # AST proof therefore records exactly one invocation before reconstruction.
    assert events == ["native_z3", "create_mop"]
    receipt = handler.last_extraction_receipt
    assert receipt is not None
    assert receipt.proof_mode == "shadow"
    assert receipt.template_source_name == "Add_HackersDelightRule_2"
    assert receipt.template_fallback_reason is None


def test_enforced_mode_is_rejected_until_shadow_corpus_parity_is_authorized():
    with pytest.raises(ValueError, match="not rollout-authorized"):
        _configured_live_handler(native_proof_mode="enforced")


def test_shadow_proof_divergence_is_a_noop_before_reconstruction(monkeypatch):
    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    candidate = _direct_add_candidate()
    handler = _configured_live_handler(native_proof_mode="shadow")
    verdicts = iter((False,))
    mop_calls = []
    monkeypatch.setattr(handler_module, "minsn_to_ast", lambda _ins: candidate)
    monkeypatch.setattr(
        handler,
        "_prove_ast_equivalence",
        lambda *_args, **_kwargs: next(verdicts),
    )
    rule = next(
        rule
        for rule in handler._compiled_rules
        if rule.source_name == "Add_HackersDelightRule_2"
    )
    handler._proof_templates = {
        (id(rule), 32): SimpleNamespace(
            source_name=rule.source_name,
            validate_terms=lambda *_args: object(),
            prove_validation=lambda _validation: True,
        )
    }
    monkeypatch.setattr(
        handler,
        "_create_instruction",
        lambda *_args: mop_calls.append("create_mop"),
    )

    assert handler._check_and_replace(_Instruction()) is None
    assert mop_calls == []
    receipt = handler.last_extraction_receipt
    assert receipt is not None
    assert receipt.skip_reason is ExtractionSkipReason.NATIVE_Z3_FAILED
    assert receipt.template_fallback_reason == "shadow_divergence"


def test_shadow_proves_real_native_terms_in_active_ast_runtime():
    candidate = _direct_add_candidate(ast_module=ast_dispatcher)
    handler = _configured_live_handler(native_proof_mode="shadow")
    original = lower_hexrays_island(candidate, destination_size=4)
    assert original.term is not None
    x = _leaf("x", 1, ast_module=ast_dispatcher)
    y = _leaf("y", 2, ast_module=ast_dispatcher)
    replacement = _node(ida_hexrays.m_add, x, y, ast_module=ast_dispatcher)
    replacement_lowering = lower_hexrays_island(replacement, destination_size=4)
    assert replacement_lowering.term is not None

    (
        proved,
        source_name,
        fallback_reason,
        template_verdict,
        legacy_verdict,
        template_elapsed_ms,
        legacy_elapsed_ms,
    ) = handler._prove_selected_replacement(
        candidate,
        replacement,
        original_term=original.term,
        replacement_term=replacement_lowering.term,
        selected=("add", "Add_HackersDelightRule_2", ("Add_OllvmRule_3",)),
        width=32,
    )

    assert proved is True
    assert source_name == "Add_HackersDelightRule_2"
    assert fallback_reason is None
    assert template_verdict is True
    assert legacy_verdict is True
    assert template_elapsed_ms is not None
    assert legacy_elapsed_ms is not None


def test_shadow_template_uses_selected_replacement_term_without_relowering(
    monkeypatch,
):
    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    candidate = _direct_add_candidate(ast_module=ast_dispatcher)
    handler = _configured_live_handler(native_proof_mode="shadow")
    original = lower_hexrays_island(candidate, destination_size=4)
    assert original.term is not None
    x = _leaf("x", 1, ast_module=ast_dispatcher)
    y = _leaf("y", 2, ast_module=ast_dispatcher)
    replacement = _node(ida_hexrays.m_add, x, y, ast_module=ast_dispatcher)
    replacement_lowering = lower_hexrays_island(replacement, destination_size=4)
    assert replacement_lowering.term is not None
    monkeypatch.setattr(
        handler_module,
        "lower_hexrays_island",
        lambda *_args, **_kwargs: pytest.fail(
            "template shadow must consume the selected replacement term"
        ),
    )

    proved, *_rest = handler._prove_selected_replacement(
        candidate,
        replacement,
        original_term=original.term,
        replacement_term=replacement_lowering.term,
        selected=("add", "Add_HackersDelightRule_2", ("Add_OllvmRule_3",)),
        width=32,
    )

    assert proved is True


def test_live_handler_native_z3_failure_records_skip_without_creating_mop(monkeypatch):
    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    candidate = _direct_add_candidate()
    handler = _configured_live_handler()
    real_extract = handler._select_native_extraction
    extracted = []
    minsn_calls = []

    def observe_extract(*args, **kwargs):
        result = real_extract(*args, **kwargs)
        extracted.append(result)
        return result

    monkeypatch.setattr(handler, "_select_native_extraction", observe_extract)
    monkeypatch.setattr(handler_module, "minsn_to_ast", lambda _ins: candidate)
    monkeypatch.setattr(handler, "_candidate_skip_reason", lambda _ast, _ins: None)
    monkeypatch.setattr(
        handler, "_prove_ast_equivalence", lambda *_args, **_kwargs: False
    )
    monkeypatch.setattr(
        ida_hexrays,
        "minsn_t",
        lambda ea: minsn_calls.append(ea),
    )

    assert handler._check_and_replace(_Instruction()) is None

    assert len(extracted) == 1
    assert extracted[0].replacement_term is not None
    assert minsn_calls == []
    receipt = handler.last_extraction_receipt
    assert receipt is not None
    assert receipt.skip_reason is ExtractionSkipReason.NATIVE_Z3_FAILED
    assert receipt.derivation_trace == ()
    metadata = handler.execution_metadata()
    assert metadata["selected_family"] == "add"
    assert metadata["selected_source"] == "Add_HackersDelightRule_2"
    assert metadata["selected_aliases"] == ("Add_OllvmRule_3",)
    assert "derivation_trace" not in metadata
    assert metadata["skip_reason"] == "native_z3_failed"


def test_live_handler_lowering_failure_clears_uncommitted_derivation_trace(monkeypatch):
    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    candidate = _direct_add_candidate()
    handler = _configured_live_handler()
    monkeypatch.setattr(handler_module, "minsn_to_ast", lambda _ins: candidate)
    monkeypatch.setattr(handler, "_candidate_skip_reason", lambda _ast, _ins: None)
    monkeypatch.setattr(
        handler, "_prove_ast_equivalence", lambda *_args, **_kwargs: True
    )
    monkeypatch.setattr(handler, "_create_instruction", lambda *_args: None)

    assert handler._check_and_replace(_Instruction()) is None

    receipt = handler.last_extraction_receipt
    assert receipt is not None
    assert receipt.skip_reason is ExtractionSkipReason.LOWERING_FAILED
    assert receipt.derivation_trace == ()
    assert "derivation_trace" not in handler.execution_metadata()


def test_live_handler_records_extractor_unavailability_for_supported_candidate(
    monkeypatch,
):
    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    candidate = _direct_add_candidate()
    handler = _configured_live_handler()
    receipt = EgglogExtractionReceipt(
        skip_reason=ExtractionSkipReason.EGGLOG_UNAVAILABLE
    )
    calls = []
    log_calls = []

    monkeypatch.setattr(handler_module, "EGGLOG_AVAILABLE", False, raising=False)
    monkeypatch.setattr(
        handler_module.logger,
        "info",
        lambda *args, **kwargs: log_calls.append((args, kwargs)),
    )
    monkeypatch.setattr(handler_module, "minsn_to_ast", lambda _ins: candidate)
    monkeypatch.setattr(handler, "_candidate_skip_reason", lambda _ast, _ins: None)
    monkeypatch.setattr(
        handler,
        "_select_native_extraction",
        lambda *args, **kwargs: (
            calls.append((args, kwargs))
            or EgglogExtractionResult(replacement_ast=None, receipt=receipt)
        ),
    )

    assert handler.check_and_replace(None, _Instruction()) is None
    assert len(calls) == 1
    recorded = handler.last_extraction_receipt
    assert recorded is not None
    # Native matching is now measured before extraction.  The receipt is
    # therefore immutable-but-enriched rather than the exact test double.
    assert recorded.skip_reason is ExtractionSkipReason.EGGLOG_UNAVAILABLE
    assert recorded.native_matcher_backend is not None
    assert recorded.native_matcher_comparisons is not None
    assert handler.execution_metadata()["skip_reason"] == "egglog_unavailable"
    assert any("extraction receipt" in args[0] for args, _kwargs in log_calls)
    assert any("egglog_unavailable" in args for args, _kwargs in log_calls)


def test_live_handler_default_time_budget_overrun_is_clean_noop(monkeypatch):
    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    candidate = _direct_add_candidate()
    handler = EgglogOptimizer()
    receipt = EgglogExtractionReceipt(
        input_cost=(4, 9),
        elapsed_ms=4.25,
        skip_reason=ExtractionSkipReason.TIME_BUDGET,
    )
    observed_budgets = []

    def time_budget_result(_term, *, destination_size, profile, initial_replacements):
        del destination_size, profile, initial_replacements
        observed_budgets.append(handler.extraction_budget)
        return EgglogExtractionResult(replacement_ast=None, receipt=receipt)

    monkeypatch.setattr(handler, "_select_native_extraction", time_budget_result)
    monkeypatch.setattr(handler_module, "minsn_to_ast", lambda _ins: candidate)
    assert handler.check_and_replace(None, _Instruction()) is None
    assert observed_budgets == [EgglogExtractionBudget()]
    assert observed_budgets[0].time_budget_ms == 3
    recorded = handler.last_extraction_receipt
    assert recorded is not None
    assert recorded.skip_reason is ExtractionSkipReason.TIME_BUDGET
    assert recorded.input_cost == receipt.input_cost
    assert recorded.elapsed_ms == receipt.elapsed_ms
    assert recorded.native_matcher_backend is not None
    assert handler.execution_metadata()["skip_reason"] == "time_budget"


def test_live_handler_opt_in_stage_timings_publish_after_reconstruction(monkeypatch):
    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
    from d810.backends.mba.native_pod_matcher import matcher_backend

    candidate = _direct_add_candidate()
    replacement = _first_typed_operator_child(
        lower_hexrays_island(_direct_add_candidate(), destination_size=4).term
    )
    handler = _configured_live_handler(collect_stage_timings=True)
    receipt = EgglogExtractionReceipt(
        input_cost=(4, 9),
        extracted_cost=(0, 1),
        degree=1,
        selected_family="add",
        selected_source="Add_HackersDelightRule_2",
        selected_aliases=("Add_OllvmRule_3",),
    )
    events = []
    original_match_root = CompiledPatternCatalogue.match_root
    original_finish_stage = handler._finish_stage

    def observed_match_root(*args, **kwargs):
        events.append("native_match")
        return original_match_root(*args, **kwargs)

    def observed_finish_stage(name):
        if name == "native_preflight":
            events.append("native_preflight_finished")
        return original_finish_stage(name)

    monkeypatch.setattr(handler_module, "minsn_to_ast", lambda _ins: candidate)
    monkeypatch.setattr(CompiledPatternCatalogue, "match_root", observed_match_root)
    monkeypatch.setattr(handler, "_finish_stage", observed_finish_stage)
    monkeypatch.setattr(
        handler,
        "_select_native_extraction",
        lambda *_args, **_kwargs: EgglogExtractionResult(
            replacement_ast=None,
            replacement_term=replacement,
            receipt=receipt,
            selected_provenance=(
                "add",
                "Add_HackersDelightRule_2",
                ("Add_OllvmRule_3",),
            ),
        ),
    )
    monkeypatch.setattr(
        handler,
        "_prove_ast_equivalence",
        lambda *_args, **_kwargs: events.append("native_z3") or True,
    )
    monkeypatch.setattr(
        handler,
        "_create_instruction",
        lambda *_args: events.append("reconstruction") or object(),
    )

    assert handler.check_and_replace(None, _Instruction()) is not None
    assert events == [
        "native_match",
        "native_preflight_finished",
        "native_z3",
        "reconstruction",
    ]
    metadata = handler.execution_metadata()
    assert tuple(metadata["stage_timings_ms"]) == (
        "root_eligibility",
        "native_preflight",
        "egglog_extraction",
        "ast_construction",
        "native_z3",
        "reconstruction",
    )
    assert handler.provider_outcome() is not None
    assert (
        handler.provider_outcome().metadata["stage_timings_ms"]
        == metadata["stage_timings_ms"]
    )
    assert metadata["native_matcher_backend"] == matcher_backend()
    assert type(metadata["native_matcher_comparisons"]) is int
    assert type(metadata["native_matcher_lazy_swaps"]) is int
    assert type(metadata["native_fixed_binding_count"]) is int
    assert type(metadata["native_matcher_elapsed_ms"]) is float
    assert metadata["native_matcher_elapsed_ms"] >= 0.0
    assert (
        handler.provider_outcome().metadata["native_matcher_backend"]
        == metadata["native_matcher_backend"]
    )


def test_live_handler_disabled_stage_timings_do_not_construct_timer(monkeypatch):
    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    handler = _configured_live_handler()

    def forbidden_timer(*_args, **_kwargs):
        raise AssertionError("disabled stage timings must not construct a timer")

    monkeypatch.setattr(handler_module, "MbaStageTimer", forbidden_timer)
    unsupported = SimpleNamespace(opcode=ida_hexrays.m_mov, ea=0x401000)

    assert handler.check_and_replace(None, unsupported) is None
    assert handler.execution_metadata()["skip_reason"] == "non_mba_candidate"
    assert "stage_timings_ms" not in handler.execution_metadata()
