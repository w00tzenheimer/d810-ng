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
    extract_bounded_candidate,
)
from d810.hexrays.expr import ast as ast_dispatcher  # noqa: E402
from d810.hexrays.expr.p_ast import (  # noqa: E402
    AstConstant,
    AstLeaf,
    AstNode,
    AstProxy,
)
from d810.hexrays.ir.mop_snapshot import MopSnapshot  # noqa: E402
from d810.optimizers.microcode.instructions.egraph.egglog_handler import (  # noqa: E402
    EgglogOptimizer,
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


def _leaf(name: str, register: int, size: int = 4, ast_module=None):
    leaf_type = AstLeaf if ast_module is None else ast_module.AstLeaf
    leaf = leaf_type(name)
    leaf.mop = MopSnapshot(t=ida_hexrays.mop_r, size=size, reg=register)
    leaf.dest_size = size
    return leaf


def _constant(value: int, size: int = 4, ast_module=None):
    wrapped = value & ((1 << (size * 8)) - 1)
    constant_type = AstConstant if ast_module is None else ast_module.AstConstant
    constant = constant_type(str(value), wrapped, size)
    constant.mop = MopSnapshot(t=ida_hexrays.mop_n, size=size, value=wrapped)
    constant.dest_size = size
    return constant


def _node(opcode: int, left, right=None, size: int = 4, ast_module=None):
    node_type = AstNode if ast_module is None else ast_module.AstNode
    node = node_type(opcode, left, right)
    node.dest_size = size
    return node


def _direct_add_candidate(size: int = 4, ast_module=None):
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


def _degree_two_candidate(size: int = 4) -> AstNode:
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
def test_real_python_runtime_proxy_extracts_and_reconstructs_all_widths(size):
    candidate = _direct_add_candidate(size)
    rule = _rule("add", "Add_HackersDelightRule_2")

    result = extract_bounded_candidate(
        AstProxy(candidate),
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


def test_composed_catalogue_rewrite_needs_degree_two():
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
    assert result.receipt.rule_firings > 1
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

    def candidate(second_constant: int) -> AstNode:
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
        (EgglogExtractionBudget(max_operator_nodes=1), ExtractionSkipReason.CANDIDATE_BUDGET),
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
def test_resource_caps_abort_without_materializing_a_mop(monkeypatch, budget, reason):
    create_mop_calls = []
    monkeypatch.setattr(
        AstNode,
        "create_mop",
        lambda self, ea: create_mop_calls.append((self, ea)),
    )

    result = extract_bounded_candidate(
        _direct_add_candidate(),
        (_rule("add", "Add_HackersDelightRule_2"),),
        budget,
        4,
    )

    assert result.replacement_ast is None
    assert result.receipt.skip_reason is reason
    assert create_mop_calls == []


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


def test_live_handler_admits_and_extracts_real_degree_two_boolean_candidate(
):
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
    assert handler.last_extraction_receipt == EgglogExtractionReceipt(
        skip_reason=ExtractionSkipReason.CANDIDATE_BUDGET
    )


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
    assert handler.last_extraction_receipt == EgglogExtractionReceipt(
        skip_reason=ExtractionSkipReason.NON_MBA_CANDIDATE
    )


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


def test_live_handler_receipts_mixed_width_candidate_without_extraction_or_mutation(
    monkeypatch,
):
    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    candidate = _mixed_width_add_candidate()
    handler = _configured_live_handler()
    extraction_calls = []
    proof_calls = []
    create_mop_calls = []

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
    monkeypatch.setattr(
        AstNode,
        "create_mop",
        lambda self, ea: create_mop_calls.append((self, ea)),
    )

    assert handler._check_and_replace(_Instruction()) is None

    assert extraction_calls == []
    assert proof_calls == []
    assert create_mop_calls == []
    receipt = handler.last_extraction_receipt
    assert receipt == EgglogExtractionReceipt(
        skip_reason=ExtractionSkipReason.UNSUPPORTED_WIDTH_SEMANTICS
    )
    assert handler.execution_metadata()["skip_reason"] == "unsupported_width_semantics"


def test_live_handler_extracts_once_with_exact_configured_rules_then_proves_before_mop(
    monkeypatch,
):
    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    candidate = _direct_add_candidate()
    handler = _configured_live_handler()
    configured_rules = handler._compiled_rules
    real_extract = extract_bounded_candidate
    extraction_calls = []
    events = []

    def observe_extract(ast, rules, budget, destination_size):
        extraction_calls.append((ast, rules, budget, destination_size))
        events.append("extract")
        return real_extract(ast, rules, budget, destination_size)

    monkeypatch.setattr(handler_module, "extract_bounded_candidate", observe_extract)
    monkeypatch.setattr(handler_module, "minsn_to_ast", lambda _ins: candidate)
    monkeypatch.setattr(handler, "_is_candidate", lambda _ast, _ins: True)
    monkeypatch.setattr(
        handler,
        "_prove_ast_equivalence",
        lambda *_args, **_kwargs: events.append("native_z3") or True,
    )
    monkeypatch.setattr(
        AstNode,
        "create_mop",
        lambda _self, _ea: events.append("create_mop") or object(),
    )

    class _ReplacementInstruction:
        def __init__(self, ea):
            self.ea = ea

    monkeypatch.setattr(ida_hexrays, "minsn_t", _ReplacementInstruction)

    replacement = handler._check_and_replace(_Instruction())

    assert len(extraction_calls) == 1
    assert extraction_calls[0][0] is candidate
    assert extraction_calls[0][1] is configured_rules
    assert extraction_calls[0][2] is handler.extraction_budget
    assert extraction_calls[0][2] == EgglogExtractionBudget(
        max_eclasses=256,
        max_enodes=512,
        time_budget_ms=1000,
    )
    assert extraction_calls[0][3] == 4
    assert events == ["extract", "native_z3", "create_mop"]
    assert replacement is not None
    assert replacement.opcode == ida_hexrays.m_mov
    receipt = handler.last_extraction_receipt
    assert receipt is not None
    assert receipt.skip_reason is None
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
    assert metadata["skip_reason"] is None


def test_live_handler_native_z3_failure_records_skip_without_creating_mop(monkeypatch):
    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    candidate = _direct_add_candidate()
    handler = _configured_live_handler()
    real_extract = extract_bounded_candidate
    extracted = []
    create_mop_calls = []
    minsn_calls = []

    def observe_extract(*args):
        result = real_extract(*args)
        extracted.append(result)
        return result

    monkeypatch.setattr(handler_module, "extract_bounded_candidate", observe_extract)
    monkeypatch.setattr(handler_module, "minsn_to_ast", lambda _ins: candidate)
    monkeypatch.setattr(handler, "_is_candidate", lambda _ast, _ins: True)
    monkeypatch.setattr(handler, "_prove_ast_equivalence", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(
        AstNode,
        "create_mop",
        lambda self, ea: create_mop_calls.append((self, ea)),
    )
    monkeypatch.setattr(
        ida_hexrays,
        "minsn_t",
        lambda ea: minsn_calls.append(ea),
    )

    assert handler._check_and_replace(_Instruction()) is None

    assert len(extracted) == 1
    assert extracted[0].replacement_ast is not None
    assert create_mop_calls == []
    assert minsn_calls == []
    receipt = handler.last_extraction_receipt
    assert receipt is not None
    assert receipt.skip_reason is ExtractionSkipReason.NATIVE_Z3_FAILED
    metadata = handler.execution_metadata()
    assert metadata["selected_family"] == "add"
    assert metadata["selected_source"] == "Add_HackersDelightRule_2"
    assert metadata["selected_aliases"] == ("Add_OllvmRule_3",)
    assert metadata["skip_reason"] == "native_z3_failed"


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
    monkeypatch.setattr(handler, "_is_candidate", lambda _ast, _ins: True)
    monkeypatch.setattr(
        handler_module,
        "extract_bounded_candidate",
        lambda *args: calls.append(args)
        or EgglogExtractionResult(replacement_ast=None, receipt=receipt),
    )

    assert handler.check_and_replace(None, _Instruction()) is None
    assert len(calls) == 1
    assert handler.last_extraction_receipt is receipt
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
    create_mop_calls = []

    def time_budget_result(_ast, _rules, budget, _destination_size):
        observed_budgets.append(budget)
        return EgglogExtractionResult(replacement_ast=None, receipt=receipt)

    monkeypatch.setattr(handler_module, "extract_bounded_candidate", time_budget_result)
    monkeypatch.setattr(handler_module, "minsn_to_ast", lambda _ins: candidate)
    monkeypatch.setattr(handler, "_is_candidate", lambda _ast, _ins: True)
    monkeypatch.setattr(
        AstNode,
        "create_mop",
        lambda self, ea: create_mop_calls.append((self, ea)),
    )

    assert handler.check_and_replace(None, _Instruction()) is None
    assert observed_budgets == [EgglogExtractionBudget()]
    assert observed_budgets[0].time_budget_ms == 3
    assert create_mop_calls == []
    assert handler.last_extraction_receipt is receipt
    assert handler.execution_metadata()["skip_reason"] == "time_budget"
