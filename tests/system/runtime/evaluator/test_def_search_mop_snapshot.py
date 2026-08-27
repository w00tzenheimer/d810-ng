"""Regression coverage for MopSnapshot inputs to def_search."""

import os
from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.evaluator.hexrays_microcode import def_search


def _call_result_test_parts(
    *,
    call_ea=0x401000,
    opcode=None,
    width=4,
    destination_type=None,
    reg=0,
    valnum=0,
    callee_ea=0x402000,
):
    from d810.hexrays.ir.mop_snapshot import MopSnapshot

    opcode = ida_hexrays.m_call if opcode is None else opcode
    destination_type = (
        ida_hexrays.mop_r if destination_type is None else destination_type
    )
    destination = MopSnapshot(
        t=destination_type,
        size=width,
        reg=reg if destination_type == ida_hexrays.mop_r else None,
        stkoff=0x40 if destination_type == ida_hexrays.mop_S else None,
        valnum=valnum,
    )
    callinfo = SimpleNamespace(args=(), callee=callee_ea)
    nested_call = SimpleNamespace(
        opcode=opcode,
        ea=call_ea,
        l=SimpleNamespace(t=ida_hexrays.mop_v, g=callee_ea),
        r=SimpleNamespace(t=ida_hexrays.mop_z),
        d=SimpleNamespace(t=ida_hexrays.mop_f, size=0, f=callinfo),
    )
    assignment = SimpleNamespace(
        opcode=ida_hexrays.m_mov,
        ea=call_ea,
        l=SimpleNamespace(t=ida_hexrays.mop_d, size=width, d=nested_call),
        d=destination,
    )
    mba = SimpleNamespace(entry_ea=0x400000, maturity=ida_hexrays.MMAT_LOCOPT)
    block = SimpleNamespace(mba=mba, serial=7)
    if destination_type == ida_hexrays.mop_S:
        use = SimpleNamespace(
            t=ida_hexrays.mop_S,
            size=width,
            s=SimpleNamespace(off=0x40),
            valnum=valnum,
        )
    else:
        use = SimpleNamespace(t=ida_hexrays.mop_r, size=width, r=reg, valnum=valnum)
    return assignment, nested_call, destination, block, use


def test_call_destination_resolves_to_top_definition_scoped_leaf(monkeypatch):
    assignment, call, destination, block, use = _call_result_test_parts()
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)

    result = def_search.resolve_mop_via_predecessors(
        use,
        block,
        SimpleNamespace(ea=0x401100),
    )

    assert def_search.is_call_result_leaf(result)
    assert result.value_ref.location.key == destination.reg
    assert result.value_ref.location.width == destination.size
    assert result.value_ref.def_site == call.ea
    assert result.value_ref.location.kind.name == "REGISTER"
    assert result.concolic_value.status.name == "TOP"
    assert result.concolic_value.width == destination.size * 8


def test_call_leaf_does_not_rebind_to_later_return_register_write(monkeypatch):
    assignment, call, _destination, block, use = _call_result_test_parts()
    later_write = SimpleNamespace(ea=0x401200)
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)
    call_leaf = def_search.resolve_mop_via_predecessors(
        use,
        block,
        SimpleNamespace(ea=0x401100),
    )

    monkeypatch.setattr(
        def_search,
        "resolve_mop_to_ast",
        lambda *_args, **_kwargs: later_write,
    )
    result = def_search._py_slow_recursively_resolve_ast(
        call_leaf,
        block,
        SimpleNamespace(ea=0x401300),
    )

    assert result is call_leaf
    assert result.value_ref.def_site == call.ea


@pytest.mark.parametrize("resolver_name", ["_py_slow_recursively_resolve_ast", "recursively_resolve_ast"])
def test_production_resolver_keeps_assigned_call_leaf_through_copy_shift_mask(
    monkeypatch, resolver_name
):
    """A real recursive chain must stop at the assigned call result."""

    from d810.hexrays.expr.ast import AstLeaf, AstNode
    from d810.hexrays.ir.mop_snapshot import MopSnapshot

    assignment, call, destination, block, use = _call_result_test_parts()
    predicate = SimpleNamespace(ea=0x401300)
    shift = SimpleNamespace(ea=0x401200, opcode=ida_hexrays.m_shl)
    copy = SimpleNamespace(ea=0x401100, opcode=ida_hexrays.m_mov)
    later_write = SimpleNamespace(ea=0x401400, opcode=ida_hexrays.m_mov)
    searched = []

    def leaf(name, mop):
        result = AstLeaf(name)
        result.mop = mop
        result.dest_size = mop.size
        return result

    shift_ast = AstNode(
        ida_hexrays.m_shl,
        leaf(
            "return_register",
            MopSnapshot(t=ida_hexrays.mop_r, size=4, reg=0, valnum=0),
        ),
        leaf(
            "shift_count",
            MopSnapshot(t=ida_hexrays.mop_n, size=1, value=1, valnum=0),
        ),
    )
    shift_ast.dest_size = 4
    shift_ast.ea = shift.ea
    shift_ast.ins = shift
    copy_ast = leaf(
        "copied_return",
        MopSnapshot(t=ida_hexrays.mop_r, size=4, reg=0, valnum=0),
    )
    copy_ast.ea = copy.ea
    copy_ast.ins = copy
    mask = AstNode(
        ida_hexrays.m_and,
        leaf("masked_return", MopSnapshot(t=ida_hexrays.mop_r, size=4, reg=1)),
        leaf("mask", MopSnapshot(t=ida_hexrays.mop_n, size=4, value=0xFF)),
    )
    mask.dest_size = 4

    def find_definition(_mop, _block, before):
        searched.append(before)
        if before is predicate:
            return shift
        if before is shift:
            return copy
        if before is copy:
            return assignment
        if before is assignment:
            # This is the physical return-register/global write that must not
            # be reached after the call leaf has become definition-scoped.
            return later_write
        return None

    def build_ast(instruction, _node_budget=None, **_kwargs):
        if instruction is shift:
            return shift_ast
        if instruction is copy:
            return copy_ast
        return None

    monkeypatch.setattr(def_search, "find_def_in_block", find_definition)
    monkeypatch.setattr(def_search, "_minsn_to_ast_with_budget", build_ast)
    # The fixture uses immutable MopSnapshots rather than live IDA mops.  Keep
    # the production resolver path while bypassing only native arena
    # materialization, which is unsafe without a real microcode owner.
    monkeypatch.setattr(
        def_search, "_materialize_mop_for_tracking", lambda mop, *_a, **_k: mop
    )

    root = mask
    root.left.mop = MopSnapshot(t=ida_hexrays.mop_r, size=4, reg=1, valnum=0)
    result = getattr(def_search, resolver_name)(root, block, predicate)

    assert def_search.is_call_result_leaf(result.left.left)
    assert result.left.left.value_ref.def_site == call.ea
    assert result.left.left.value_ref.location.key == destination.reg
    assert [id(anchor) for anchor in searched] == [
        id(predicate),
        id(shift),
        id(copy),
    ]
    assert all(anchor is not assignment for anchor in searched)


def test_call_result_accepted_widths_agree_across_leaf_concolic_and_query(
    monkeypatch,
):
    from d810.analyses.data_flow.concolic.values import ConcolicValue
    from d810.analyses.value_flow.call_return_value import (
        CallResultRefinement,
        CallResultRefinementStatus,
    )

    for width in (1, 2, 4, 8, 16):
        assignment, _call, _destination, block, use = _call_result_test_parts(width=width)
        seen = []

        def refine(query):
            seen.append(query)
            return CallResultRefinement(
                ConcolicValue.top(query.result_width_bits),
                CallResultRefinementStatus.REFINED,
            )

        monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)
        result = def_search.resolve_mop_via_predecessors(
            use,
            block,
            SimpleNamespace(ea=0x401100),
            call_result_refiner=refine,
        )

        assert def_search.is_call_result_leaf(result)
        assert result.value_ref.location.width == width
        assert result.concolic_value.width == width * 8
        assert seen[0].result_width_bits == width * 8


def test_two_calls_returning_in_same_register_have_distinct_value_refs(monkeypatch):
    first, first_call, _destination, block, use = _call_result_test_parts(call_ea=0x401000)
    second, second_call, _destination, _block, _use = _call_result_test_parts(call_ea=0x401010)
    definitions = iter((first, second))
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: next(definitions))

    first_leaf = def_search.resolve_mop_via_predecessors(
        use, block, SimpleNamespace(ea=0x401100)
    )
    second_leaf = def_search.resolve_mop_via_predecessors(
        use, block, SimpleNamespace(ea=0x401100)
    )

    assert first_leaf.value_ref.location == second_leaf.value_ref.location
    assert first_leaf.value_ref != second_leaf.value_ref
    assert first_leaf.value_ref.def_site == first_call.ea
    assert second_leaf.value_ref.def_site == second_call.ea


def test_call_destination_valnum_match_is_accepted_when_identity_matches(monkeypatch):
    assignment, _call, destination, block, use = _call_result_test_parts(valnum=13)
    use.r = 99
    monkeypatch.setattr(def_search, "_USE_NATIVE_DEF_SEARCH", False)

    class Tracker:
        @staticmethod
        def reset():
            return None

        def __init__(self, *_args, **_kwargs):
            return None

        def search_backward(self, *_args):
            return [
                SimpleNamespace(
                    history=[SimpleNamespace(blk=block, ins_list=(assignment,))]
                )
            ]

    monkeypatch.setitem(
        def_search.sys.modules,
        "d810.evaluator.hexrays_microcode.tracker",
        SimpleNamespace(MopTracker=Tracker),
    )

    result = def_search.resolve_mop_to_ast(use, block, SimpleNamespace(ea=0x401100))

    assert def_search.is_call_result_leaf(result)
    assert result.value_ref.location.key == destination.reg


def test_rotate_helper_call_uses_pure_evaluator_not_generic_call_leaf(monkeypatch):
    assignment, call, _destination, block, use = _call_result_test_parts()
    call.l = SimpleNamespace(t=ida_hexrays.mop_h, helper="__ROL4")
    from d810.hexrays.expr.ast import AstLeaf

    evaluator_ast = AstLeaf("rotate_result")
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)
    monkeypatch.setattr(def_search, "minsn_to_ast", lambda *_args, **_kwargs: evaluator_ast)

    def refine(_query):
        raise AssertionError("rotate helpers must not invoke the call refiner")

    result = def_search.resolve_mop_via_predecessors(
        use,
        block,
        SimpleNamespace(ea=0x401100),
        call_result_refiner=refine,
    )

    assert result is evaluator_ast


def test_refiner_receives_exact_call_query_and_refines_leaf(monkeypatch):
    from d810.analyses.data_flow.concolic.values import ConcolicValue
    from d810.analyses.value_flow.call_return_value import (
        CallResultRefinement,
        CallResultRefinementStatus,
    )

    assignment, call, _destination, block, use = _call_result_test_parts()
    seen = []

    def refine(query):
        seen.append(query)
        return CallResultRefinement(
            ConcolicValue.of(0x40, 32), CallResultRefinementStatus.REFINED
        )

    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)
    result = def_search.resolve_mop_via_predecessors(
        use,
        block,
        SimpleNamespace(ea=0x401100),
        call_result_refiner=refine,
    )

    assert result.concolic_value.concrete == 0x40
    assert seen[0].function_ea == block.mba.entry_ea
    assert seen[0].maturity == block.mba.maturity
    assert seen[0].call_ea == call.ea
    assert seen[0].callee_ea == 0x402000
    assert seen[0].result_width_bits == 32


def test_python_and_compiled_resolvers_produce_equivalent_call_leaf(monkeypatch):
    assignment, _call, _destination, block, use = _call_result_test_parts()
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)
    leaf = def_search.resolve_mop_via_predecessors(
        use, block, SimpleNamespace(ea=0x401100)
    )

    python_result = def_search._py_slow_recursively_resolve_ast(
        leaf, block, SimpleNamespace(ea=0x401100)
    )
    compiled_result = def_search.recursively_resolve_ast(
        leaf, block, SimpleNamespace(ea=0x401100)
    )

    assert def_search.is_call_result_leaf(python_result)
    assert def_search.is_call_result_leaf(compiled_result)
    assert python_result.value_ref == compiled_result.value_ref
    assert python_result.concolic_value == compiled_result.concolic_value
    if os.environ.get("D810_NO_CYTHON") == "0":
        assert def_search.get_recursive_resolver_backend() == "cython"


@pytest.mark.parametrize(
    "destination_type,width",
    [
        (ida_hexrays.mop_r, 1),
        (ida_hexrays.mop_r, 2),
        (ida_hexrays.mop_r, 4),
        (ida_hexrays.mop_r, 8),
        (ida_hexrays.mop_r, 16),
        (ida_hexrays.mop_S, 4),
    ],
)
def test_call_result_leaf_preserves_destination_location_and_width(
    monkeypatch, destination_type, width
):
    assignment, _call, destination, block, use = _call_result_test_parts(
        destination_type=destination_type, width=width
    )
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)

    result = def_search.resolve_mop_via_predecessors(
        use, block, SimpleNamespace(ea=0x401100)
    )

    assert def_search.is_call_result_leaf(result)
    assert result.value_ref.location.width == width
    assert result.concolic_value.width == width * 8
    if destination_type == ida_hexrays.mop_S:
        assert result.value_ref.location.kind.name == "STACK"
        assert result.value_ref.location.key == destination.stkoff


def test_call_result_invalid_ea_identity_uses_nested_call_object(monkeypatch):
    first, first_call, _destination, block, use = _call_result_test_parts(call_ea=0)
    second, second_call, _destination, _block, _use = _call_result_test_parts(call_ea=0)
    definitions = iter((first, second))
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: next(definitions))

    first_leaf = def_search.resolve_mop_via_predecessors(
        use, block, SimpleNamespace(ea=0x401100)
    )
    second_leaf = def_search.resolve_mop_via_predecessors(
        use, block, SimpleNamespace(ea=0x401100)
    )

    assert first_call.ea == second_call.ea == 0
    assert first_leaf.value_ref.def_site < 0
    assert second_leaf.value_ref.def_site < 0
    assert first_leaf.value_ref.def_site != second_leaf.value_ref.def_site
    assert first_leaf.value_ref.def_site == id(first_call) * -1 - (block.serial << 64)


@pytest.mark.parametrize("width", [0, 3, 32])
def test_call_result_rejects_unsupported_destination_width(monkeypatch, width):
    assignment, _call, _destination, block, use = _call_result_test_parts(width=width)
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)
    seen = []

    def refine(query):
        seen.append(query)
        raise AssertionError("unsupported width reached the refiner")

    result = def_search.resolve_mop_via_predecessors(
        use,
        block,
        SimpleNamespace(ea=0x401100),
        call_result_refiner=refine,
    )

    assert result is None
    assert seen == []


def test_indirect_call_assignment_retains_optional_callee(monkeypatch):
    assignment, call, _destination, block, use = _call_result_test_parts(
        opcode=ida_hexrays.m_icall, callee_ea=None
    )
    call.l = SimpleNamespace(t=ida_hexrays.mop_r, r=4)
    call.d.f.callee = None
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)

    result = def_search.resolve_mop_via_predecessors(
        use, block, SimpleNamespace(ea=0x401100)
    )

    assert def_search.is_call_result_leaf(result)
    query = def_search._call_result_query(assignment, block, result.value_ref)
    assert query.callee_ea is None
    assert query.call_ea == call.ea


def test_compiled_resolver_propagates_refiner_to_valid_call_assignment(monkeypatch):
    from d810.analyses.data_flow.concolic.values import ConcolicValue
    from d810.analyses.value_flow.call_return_value import (
        CallResultRefinement,
        CallResultRefinementStatus,
    )
    from d810.hexrays.expr.ast import AstLeaf

    assignment, _call, _destination, block, use = _call_result_test_parts()
    source = AstLeaf("return_register")
    source.mop = use
    source.dest_size = use.size
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)
    seen = []

    def refine(query):
        seen.append(query)
        return CallResultRefinement(
            ConcolicValue.of(0x40, 32), CallResultRefinementStatus.REFINED
        )

    result = def_search.recursively_resolve_ast(
        source,
        block,
        SimpleNamespace(ea=0x401100),
        call_result_refiner=refine,
    )

    assert def_search.is_call_result_leaf(result)
    assert result.concolic_value.concrete == 0x40
    assert seen and seen[0].call_ea == assignment.l.d.ea


def test_call_result_leaf_clone_preserves_terminal_metadata(monkeypatch):
    assignment, _call, _destination, block, use = _call_result_test_parts()
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)
    leaf = def_search.resolve_mop_via_predecessors(
        use, block, SimpleNamespace(ea=0x401100)
    )

    clone = leaf.clone()

    assert def_search.is_call_result_leaf(clone)
    assert clone.value_ref == leaf.value_ref
    assert clone.concolic_value == leaf.concolic_value


def test_malformed_refiner_value_keeps_call_leaf_terminal(monkeypatch):
    """Invalid callback evidence must not reopen physical definition search."""

    assignment, call, _destination, block, use = _call_result_test_parts()
    later_write = SimpleNamespace(ea=0x401200)
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)
    monkeypatch.setattr(
        def_search,
        "resolve_mop_to_ast",
        lambda *_args, **_kwargs: later_write,
    )

    def malformed(_query):
        return SimpleNamespace(value="not-a-concolic-value")

    result = def_search.resolve_mop_via_predecessors(
        use,
        block,
        SimpleNamespace(ea=0x401100),
        call_result_refiner=malformed,
    )

    assert def_search.is_call_result_leaf(result)
    assert result.value_ref.def_site == call.ea
    assert result.concolic_value.status.name == "TOP"
    assert result.refinement.status.name == "INVALID_EVIDENCE"


@pytest.mark.parametrize(
    "resolver_name", ["_py_slow_recursively_resolve_ast", "recursively_resolve_ast"]
)
def test_malformed_refiner_leaf_stays_terminal_in_recursive_resolvers(
    monkeypatch, resolver_name
):
    assignment, call, _destination, block, use = _call_result_test_parts()
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)

    def malformed(_query):
        return SimpleNamespace(value=object())

    leaf = def_search.resolve_mop_via_predecessors(
        use,
        block,
        SimpleNamespace(ea=0x401100),
        call_result_refiner=malformed,
    )
    monkeypatch.setattr(
        def_search,
        "resolve_mop_to_ast",
        lambda *_args, **_kwargs: SimpleNamespace(ea=0x401300),
    )

    result = getattr(def_search, resolver_name)(
        leaf,
        block,
        SimpleNamespace(ea=0x401400),
        call_result_refiner=malformed,
    )

    assert def_search.is_call_result_leaf(result)
    assert result.value_ref.def_site == call.ea
    assert result.refinement.status.name == "INVALID_EVIDENCE"


def test_call_result_leaf_clone_preserves_refinement_metadata(monkeypatch):
    from d810.analyses.data_flow.concolic.values import ConcolicValue
    from d810.analyses.value_flow.call_return_value import (
        CallResultRefinement,
        CallResultRefinementStatus,
    )

    assignment, _call, _destination, block, use = _call_result_test_parts()
    refinement = CallResultRefinement(
        ConcolicValue.top(32),
        CallResultRefinementStatus.INVALID_EVIDENCE,
        used_fact_ids=("used-1",),
        rejected_fact_ids=("rejected-1",),
        reasons=("bounded reason",),
    )
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)
    result = def_search.resolve_mop_via_predecessors(
        use,
        block,
        SimpleNamespace(ea=0x401100),
        call_result_refiner=lambda _query: refinement,
    )
    clone = result.clone()

    assert clone.refinement == result.refinement
    assert clone.refinement is result.refinement
    assert clone.concolic_value == result.refinement.value


@pytest.mark.parametrize(
    "status",
    [
        "NO_EVIDENCE",
        "INVALID_EVIDENCE",
        "INCOMPATIBLE_EVIDENCE",
        "CONFLICTING_EVIDENCE",
    ],
)
def test_non_refined_evidence_is_forced_to_top_before_abstract_proof(
    monkeypatch, status
):
    from d810.analyses.data_flow.concolic.values import ConcolicValue
    from d810.analyses.value_flow.call_return_value import (
        CallResultRefinement,
        CallResultRefinementStatus,
    )
    from d810.evaluator.hexrays_microcode.abstract_ast import (
        AbstractZeroStatus,
        decide_zero_status,
    )

    assignment, call, _destination, block, use = _call_result_test_parts()
    original = CallResultRefinement(
        ConcolicValue.of(1, 32),
        CallResultRefinementStatus[status],
        used_fact_ids=("used",),
        rejected_fact_ids=("rejected",),
        reasons=("diagnostic",),
    )
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)
    leaf = def_search.resolve_mop_via_predecessors(
        use,
        block,
        SimpleNamespace(ea=0x401100),
        call_result_refiner=lambda _query: original,
    )

    assert def_search.is_call_result_leaf(leaf)
    assert leaf.value_ref.def_site == call.ea
    assert leaf.refinement.status is original.status
    assert leaf.refinement.used_fact_ids == original.used_fact_ids
    assert leaf.refinement.rejected_fact_ids == original.rejected_fact_ids
    assert leaf.refinement.reasons == original.reasons
    assert leaf.concolic_value.status.name == "TOP"
    assert decide_zero_status(leaf) is AbstractZeroStatus.UNKNOWN


def test_refined_inconsistent_concolic_value_is_invalid_top(monkeypatch):
    from d810.analyses.abstract_domains.known_bits import KnownBits
    from d810.analyses.abstract_domains.wrapped_interval import WrappedInterval
    from d810.analyses.data_flow.concolic.abstract_evidence import AbstractEvidence
    from d810.analyses.data_flow.concolic.values import ConcolicValue, PrecisionStatus
    from d810.analyses.value_flow.call_return_value import (
        CallResultRefinement,
        CallResultRefinementStatus,
    )

    assignment, _call, _destination, block, use = _call_result_test_parts()
    inconsistent = ConcolicValue(
        1,
        None,
        AbstractEvidence(
            16,
            KnownBits(16, zero=0, one=1),
            WrappedInterval.top(16),
        ),
        32,
        PrecisionStatus.CONCRETE,
    )
    refinement = CallResultRefinement(inconsistent, CallResultRefinementStatus.REFINED)
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)
    leaf = def_search.resolve_mop_via_predecessors(
        use,
        block,
        SimpleNamespace(ea=0x401100),
        call_result_refiner=lambda _query: refinement,
    )

    assert leaf.refinement.status is CallResultRefinementStatus.INVALID_EVIDENCE
    assert leaf.concolic_value.status.name == "TOP"


def test_refined_same_width_contradictory_product_is_invalid_top(monkeypatch):
    from d810.analyses.abstract_domains.known_bits import KnownBits
    from d810.analyses.abstract_domains.wrapped_interval import WrappedInterval
    from d810.analyses.data_flow.concolic.abstract_evidence import AbstractEvidence
    from d810.analyses.data_flow.concolic.values import ConcolicValue, PrecisionStatus
    from d810.analyses.value_flow.call_return_value import (
        CallResultRefinement,
        CallResultRefinementStatus,
    )
    from d810.evaluator.hexrays_microcode.abstract_ast import (
        AbstractZeroStatus,
        decide_zero_status,
    )

    assignment, _call, _destination, block, use = _call_result_test_parts()
    raw = ConcolicValue(
        None,
        None,
        AbstractEvidence(
            32,
            KnownBits(32, zero=((1 << 32) - 2), one=1),
            WrappedInterval(32, lo=2, hi=2, kind="range"),
        ),
        32,
        PrecisionStatus.ABSTRACT,
    )
    refinement = CallResultRefinement(raw, CallResultRefinementStatus.REFINED)
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)
    leaf = def_search.resolve_mop_via_predecessors(
        use,
        block,
        SimpleNamespace(ea=0x401100),
        call_result_refiner=lambda _query: refinement,
    )

    assert leaf.refinement.status is CallResultRefinementStatus.INVALID_EVIDENCE
    assert leaf.concolic_value.status.name == "TOP"
    assert decide_zero_status(leaf) is AbstractZeroStatus.UNKNOWN


def test_refined_same_width_product_is_canonicalized(monkeypatch):
    from d810.analyses.abstract_domains.known_bits import KnownBits
    from d810.analyses.abstract_domains.wrapped_interval import WrappedInterval
    from d810.analyses.data_flow.concolic.abstract_evidence import AbstractEvidence
    from d810.analyses.data_flow.concolic.values import ConcolicValue, PrecisionStatus
    from d810.analyses.value_flow.call_return_value import (
        CallResultRefinement,
        CallResultRefinementStatus,
    )

    assignment, _call, _destination, block, use = _call_result_test_parts()
    raw_evidence = AbstractEvidence(
        32,
        KnownBits(32, zero=((1 << 32) - 2), one=1),
        WrappedInterval(32, lo=0, hi=3, kind="range"),
    )
    raw = ConcolicValue(None, None, raw_evidence, 32, PrecisionStatus.ABSTRACT)
    refinement = CallResultRefinement(raw, CallResultRefinementStatus.REFINED)
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)
    leaf = def_search.resolve_mop_via_predecessors(
        use,
        block,
        SimpleNamespace(ea=0x401100),
        call_result_refiner=lambda _query: refinement,
    )

    assert leaf.refinement.status is CallResultRefinementStatus.REFINED
    assert leaf.concolic_value.abstract.to_const() == 1


def test_stack_mop_tracker_refiner_attribute_error_propagates(monkeypatch):
    assignment, _call, _destination, block, _use = _call_result_test_parts(
        destination_type=ida_hexrays.mop_S
    )
    assignment.d = SimpleNamespace(
        t=ida_hexrays.mop_S,
        size=4,
        s=SimpleNamespace(off=0x40),
        stkoff=0x40,
        valnum=0,
    )
    stack_use = SimpleNamespace(
        t=ida_hexrays.mop_S,
        size=4,
        s=SimpleNamespace(off=0x40),
        stkoff=0x40,
        valnum=0,
    )
    stack_block = SimpleNamespace(
        mba=SimpleNamespace(maturity=ida_hexrays.MMAT_LOCOPT), serial=7
    )

    class Tracker:
        @staticmethod
        def reset():
            return None

        def __init__(self, *_args, **_kwargs):
            return None

        def search_backward(self, *_args):
            return [SimpleNamespace(history=[SimpleNamespace(blk=stack_block, ins_list=(assignment,))])]

    monkeypatch.setattr(def_search, "_USE_NATIVE_DEF_SEARCH", False)
    monkeypatch.setattr(def_search, "_materialize_mop_for_tracking", lambda mop, *_a, **_k: mop)
    monkeypatch.setitem(def_search.sys.modules, "d810.evaluator.hexrays_microcode.tracker", SimpleNamespace(MopTracker=Tracker))
    sentinel = AttributeError("refiner sentinel")

    def malformed(_query):
        raise sentinel

    with pytest.raises(AttributeError) as caught:
        def_search.resolve_mop_to_ast(
            stack_use,
            stack_block,
            SimpleNamespace(ea=0x401100),
            call_result_refiner=malformed,
        )
    assert caught.value is sentinel


@pytest.mark.parametrize("known_bits", [False, True])
def test_valid_refined_evidence_remains_decisive(monkeypatch, known_bits):
    from d810.analyses.abstract_domains.known_bits import KnownBits
    from d810.analyses.abstract_domains.wrapped_interval import WrappedInterval
    from d810.analyses.data_flow.concolic.abstract_evidence import AbstractEvidence
    from d810.analyses.data_flow.concolic.values import (
        ConcolicValue,
        PrecisionStatus,
        reduce,
    )
    from d810.analyses.value_flow.call_return_value import (
        CallResultRefinement,
        CallResultRefinementStatus,
    )
    from d810.evaluator.hexrays_microcode.abstract_ast import (
        AbstractZeroStatus,
        decide_zero_status,
    )

    assignment, _call, _destination, block, use = _call_result_test_parts()
    if known_bits:
        value = reduce(
            ConcolicValue(
                None,
                None,
                AbstractEvidence(
                    32,
                    KnownBits(32, zero=((1 << 32) - 1) ^ 1, one=1),
                    WrappedInterval.top(32),
                ),
                32,
                PrecisionStatus.ABSTRACT,
            )
        )
    else:
        value = ConcolicValue.of(1, 32)
    refinement = CallResultRefinement(value, CallResultRefinementStatus.REFINED)
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)
    leaf = def_search.resolve_mop_via_predecessors(
        use,
        block,
        SimpleNamespace(ea=0x401100),
        call_result_refiner=lambda _query: refinement,
    )

    assert leaf.refinement.status is CallResultRefinementStatus.REFINED
    assert decide_zero_status(leaf) is AbstractZeroStatus.ALWAYS_NONZERO


def test_bare_call_with_callinfo_destination_is_not_a_result_leaf(monkeypatch):
    _assignment, call, _destination, block, use = _call_result_test_parts()
    bare_call = call
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: bare_call)

    result = def_search.resolve_mop_via_predecessors(
        use, block, SimpleNamespace(ea=0x401100)
    )

    assert result is None


def test_terminal_origin_rejects_non_native_before_mlist(monkeypatch):
    def explode():
        raise AssertionError("native mlist must not be constructed")

    monkeypatch.setattr(ida_hexrays, "mlist_t", explode)
    mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=1, valnum=0, this=1)
    block = SimpleNamespace(serial=1, start=0, end=1, this=2, mba=None)
    assert not def_search._proof_operand_has_location(mop, block)


def test_proof_mba_identity_rejects_missing_mba():
    assert def_search._proof_mba_identity(None) is None


def test_terminal_origin_materializes_real_snapshot_before_location_check(monkeypatch):
    """A real snapshot must be materialized before native location validation."""

    from d810.hexrays.ir.mop_snapshot import MopSnapshot

    class FakeLocations:
        def __init__(self):
            self._empty = True

        def empty(self):
            return self._empty

    class Mba:
        this = 0x1234

    class Block:
        serial = 7
        start = 0x4000
        end = 0x4020
        this = 0x5678
        mba = Mba()

        def npred(self):
            return 0

        def append_use_list(self, locations, mop, _access):
            assert hasattr(mop, "this")
            assert not isinstance(mop, MopSnapshot)
            locations._empty = False

    snapshot = MopSnapshot(
        t=ida_hexrays.mop_r,
        size=4,
        reg=1,
        valnum=0,
    )
    assert not hasattr(snapshot, "this")

    live_mop = SimpleNamespace(
        t=ida_hexrays.mop_r,
        size=4,
        r=1,
        valnum=0,
        this=0xDEAD,
    )
    materialization_calls = []

    def materialize(mop, context, *, mba):
        materialization_calls.append((mop, context, mba))
        return live_mop

    # Constructing a native mop_t without an active microcode arena can fault
    # inside IDA.  Keep this regression focused on the proof gate's ordering:
    # a real snapshot must reach the materializer before the native location
    # API sees the returned live mop.
    monkeypatch.setattr(def_search, "_materialize_mop_for_tracking", materialize)
    monkeypatch.setattr(def_search.ida_hexrays, "mlist_t", FakeLocations)
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_a: None)

    origin = def_search._terminal_proof_origin(
        snapshot,
        Block(),
        SimpleNamespace(this=0x9ABC),
        max_predecessor_blocks=1,
        scope=object(),
    )

    assert origin is not None
    assert materialization_calls == [(snapshot, "_terminal_proof_origin", Block.mba)]


@pytest.mark.parametrize(
    "snapshot",
    [
        # Complex snapshots without an owned native operand are not safe to
        # materialize for a proof-location query.
        lambda MopSnapshot: MopSnapshot(
            t=ida_hexrays.mop_d,
            size=4,
            valnum=0,
        ),
        lambda MopSnapshot: MopSnapshot(
            t=ida_hexrays.mop_l,
            size=4,
            lvar_idx=1,
            lvar_off=0,
            valnum=0,
        ),
    ],
    ids=["missing-owned-complex-mop", "missing-owned-local-mop"],
)
def test_terminal_origin_fails_closed_for_unmaterializable_snapshot(
    monkeypatch, snapshot
):
    """A snapshot that cannot become a live mop must not create proof input."""

    from d810.hexrays.ir.mop_snapshot import MopSnapshot

    class Mba:
        this = 0x1234

    class Block:
        serial = 7
        start = 0x4000
        end = 0x4020
        this = 0x5678
        mba = Mba()

        def npred(self):
            return 0

        def append_use_list(self, *_args):
            raise AssertionError("unmaterializable snapshot reached native mlist")

    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_a: None)

    assert (
        def_search._terminal_proof_origin(
            snapshot(MopSnapshot),
            Block(),
            SimpleNamespace(this=0x9ABC),
            max_predecessor_blocks=1,
            scope=object(),
        )
        is None
    )


class FakeSnapshot:
    def __init__(self, *, t, size, reg=None, stkoff=None, owned_mop=None):
        self.t = t
        self.size = size
        self.reg = reg
        self.r = reg
        self.stkoff = stkoff
        self.owned_mop = owned_mop
        self.materialized_mba = None

    def to_mop(self, mba=None):
        self.materialized_mba = mba
        return SimpleNamespace(t=self.t, size=self.size, r=self.reg)


def test_materialize_stack_snapshot_rebinds_to_destination_mba(monkeypatch):
    monkeypatch.setattr(def_search, "MopSnapshot", FakeSnapshot)
    destination_mba = object()
    snapshot = FakeSnapshot(
        t=ida_hexrays.mop_S,
        size=4,
        stkoff=0xA4,
    )

    materialized = def_search._materialize_mop_for_tracking(
        snapshot,
        "test",
        mba=destination_mba,
    )

    assert materialized is not None
    assert snapshot.materialized_mba is destination_mba


def test_resolve_mop_to_ast_materializes_snapshot_before_tracker(monkeypatch):
    class RecordingTracker:
        seen_mop = None

        @staticmethod
        def reset():
            return None

        def __init__(self, searched_mop_list, **_kwargs):
            self.__class__.seen_mop = searched_mop_list[0]

        def search_backward(self, _blk, _ins):
            return []

    tracker_module = SimpleNamespace(MopTracker=RecordingTracker)
    monkeypatch.setattr(def_search, "MopSnapshot", FakeSnapshot)
    monkeypatch.setitem(
        def_search.sys.modules,
        "d810.evaluator.hexrays_microcode.tracker",
        tracker_module,
    )
    monkeypatch.setattr(def_search, "_USE_NATIVE_DEF_SEARCH", False)

    snapshot = FakeSnapshot(t=ida_hexrays.mop_r, size=4, reg=0)
    result = def_search.resolve_mop_to_ast(
        snapshot,
        blk=object(),
        ins=SimpleNamespace(ea=0x1000),
    )

    assert result is None
    assert RecordingTracker.seen_mop is not None
    assert not isinstance(RecordingTracker.seen_mop, FakeSnapshot)
    assert RecordingTracker.seen_mop.t == ida_hexrays.mop_r
    assert RecordingTracker.seen_mop.r == 0
    assert RecordingTracker.seen_mop.size == 4


def test_resolve_mop_to_ast_forwards_explicit_cross_block_tracker_budget(monkeypatch):
    class RecordingTracker:
        received_budget = None

        @staticmethod
        def reset():
            return None

        def __init__(self, _searched_mop_list, *, max_nb_block, max_path):
            self.__class__.received_budget = (max_nb_block, max_path)

        def search_backward(self, _blk, _ins):
            return []

    monkeypatch.setitem(
        def_search.sys.modules,
        "d810.evaluator.hexrays_microcode.tracker",
        SimpleNamespace(MopTracker=RecordingTracker),
    )
    monkeypatch.setattr(def_search, "_USE_NATIVE_DEF_SEARCH", False)

    result = def_search.resolve_mop_to_ast(
        SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=0),
        blk=object(),
        ins=SimpleNamespace(ea=0x1000),
        max_predecessor_blocks=2,
        max_paths=3,
    )

    assert result is None
    assert RecordingTracker.received_budget == (2, 3)


def test_resolve_mop_to_ast_rejects_tracker_fallback_before_locopt(monkeypatch):
    calls = []

    class UnexpectedTracker:
        @staticmethod
        def reset():
            calls.append("reset")

        def __init__(self, *_args, **_kwargs):
            calls.append("init")

        def search_backward(self, *_args, **_kwargs):
            calls.append("search")
            return []

    monkeypatch.setitem(
        def_search.sys.modules,
        "d810.evaluator.hexrays_microcode.tracker",
        SimpleNamespace(MopTracker=UnexpectedTracker),
    )
    monkeypatch.setattr(def_search, "_USE_NATIVE_DEF_SEARCH", False)

    result = def_search.resolve_mop_to_ast(
        SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=0),
        blk=SimpleNamespace(
            mba=SimpleNamespace(maturity=ida_hexrays.MMAT_PREOPTIMIZED)
        ),
        ins=SimpleNamespace(ea=0x1000),
    )

    assert result is None
    assert calls == []


def test_resolve_mop_to_ast_forwards_native_def_search_budget(monkeypatch):
    received_budgets = []

    def native_resolver(
        _mop,
        _blk,
        _ins,
        *,
        max_predecessor_blocks,
        max_paths,
        node_budget=None,
    ):
        received_budgets.append((max_predecessor_blocks, max_paths))
        return None

    monkeypatch.setattr(def_search, "resolve_mop_via_predecessors", native_resolver)
    monkeypatch.setattr(def_search, "_USE_NATIVE_DEF_SEARCH", True)
    monkeypatch.setitem(
        def_search.sys.modules,
        "d810.evaluator.hexrays_microcode.tracker",
        SimpleNamespace(),
    )
    mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=0)
    block = object()
    instruction = SimpleNamespace(ea=0x1000)

    assert def_search.resolve_mop_to_ast(mop, block, instruction) is None
    assert (
        def_search.resolve_mop_to_ast(
            mop,
            block,
            instruction,
            max_predecessor_blocks=2,
            max_paths=3,
        )
        is None
    )

    assert received_budgets == [(1, 1), (2, 3)]


def test_native_predecessor_walk_honors_predecessor_budget(monkeypatch):
    searched_blocks = []
    predecessor_lookups = []

    class Block:
        def __init__(self, serial, predecessor):
            self.serial = serial
            self._predecessor = predecessor
            self.mba = None

        def npred(self):
            return 0 if self._predecessor is None else 1

        def pred(self, index):
            assert index == 0
            return self._predecessor

    blocks = {
        serial: Block(serial, serial + 1 if serial < 2 else None) for serial in range(3)
    }

    class Mba:
        def get_mblock(self, serial):
            predecessor_lookups.append(serial)
            return blocks[serial]

    mba = Mba()
    for block in blocks.values():
        block.mba = mba

    monkeypatch.setattr(
        def_search,
        "find_def_in_block",
        lambda _mop, block, _before: searched_blocks.append(block.serial) or None,
    )
    mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=0)

    assert (
        def_search.resolve_mop_via_predecessors(
            mop,
            blocks[0],
            SimpleNamespace(ea=0x1000),
            max_predecessor_blocks=2,
            max_paths=1,
        )
        is None
    )
    assert searched_blocks == [0, 1, 2]
    assert predecessor_lookups == [1, 2]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_predecessor_blocks": 0},
        {"max_predecessor_blocks": 9},
        {"max_predecessor_blocks": True},
        {"max_paths": 0},
        {"max_paths": 33},
        {"max_paths": True},
    ],
)
def test_native_predecessor_walk_rejects_invalid_budget(monkeypatch, kwargs):
    monkeypatch.setattr(
        def_search,
        "find_def_in_block",
        lambda *_args: pytest.fail("invalid budget must fail before searching"),
    )
    mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=0)
    block = SimpleNamespace(serial=0)

    assert (
        def_search.resolve_mop_via_predecessors(
            mop,
            block,
            SimpleNamespace(ea=0x1000),
            **kwargs,
        )
        is None
    )


def test_recursive_cache_distinguishes_same_ea_microinstructions(monkeypatch):
    class Leaf:
        def __init__(self):
            self.mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=0)

        @staticmethod
        def is_leaf():
            return True

    calls = []

    def unresolved(_mop, _blk, ins, **_kwargs):
        calls.append(ins)
        return None

    monkeypatch.setattr(def_search, "get_mop_key", lambda _mop: ("reg", 0))
    monkeypatch.setattr(def_search, "resolve_mop_to_ast", unresolved)
    block = SimpleNamespace(serial=7)
    first = SimpleNamespace(ea=0x401000, this=object())
    second = SimpleNamespace(ea=0x401000, this=object())
    cache = {}

    for resolver in (
        def_search._py_slow_recursively_resolve_ast,
        def_search.recursively_resolve_ast,
    ):
        calls.clear()
        cache.clear()
        resolver(Leaf(), block, first, cache=cache)
        resolver(Leaf(), block, second, cache=cache)
        assert calls == [first, second]


class _ProofOriginBlock:
    """Minimal single-entry block model for proof-origin tests."""

    def __init__(self, serial, *, start=0x4000):
        self.serial = serial
        self.start = start
        self.end = start + 0x20
        self.mba = object()

    def npred(self):
        return 0


def _proof_origin_leaf(name, *, register=1, size=4, valnum=0):
    from d810.hexrays.expr.ast import AstLeaf

    leaf = AstLeaf(name)
    leaf.mop = SimpleNamespace(
        t=ida_hexrays.mop_r,
        size=size,
        r=register,
        valnum=valnum,
    )
    leaf.dest_size = size
    return leaf


@pytest.mark.parametrize(
    "resolver_name",
    ["_py_slow_recursively_resolve_ast", "recursively_resolve_ast"],
)
def test_recursive_resolver_attaches_same_origin_to_rebuilt_entry_leaves(
    monkeypatch, resolver_name
):
    """One proof-root register rebuilt through separate chains shares one token."""

    monkeypatch.setattr(def_search, "resolve_mop_to_ast", lambda *_a, **_k: None)
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_a: None)
    monkeypatch.setattr(def_search, "_proof_operand_has_location", lambda *_a: True)
    block = _ProofOriginBlock(7)
    cache = {}
    resolver = getattr(def_search, resolver_name)

    first = resolver(
        _proof_origin_leaf("first"),
        block,
        SimpleNamespace(ea=0x5000, this=object()),
        cache=cache,
    )
    second = resolver(
        _proof_origin_leaf("second"),
        block,
        SimpleNamespace(ea=0x5000, this=object()),
        cache=cache,
    )

    assert first.proof_origin is not None
    assert second.proof_origin == first.proof_origin


def test_proof_origins_separate_distinct_entry_blocks(monkeypatch):
    """An unversioned register at different block entries stays distinct."""

    from d810.backends.ast.z3 import create_z3_vars

    monkeypatch.setattr(def_search, "resolve_mop_to_ast", lambda *_a, **_k: None)
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_a: None)
    monkeypatch.setattr(def_search, "_proof_operand_has_location", lambda *_a: True)
    cache = {}
    first = _proof_origin_leaf("first")
    second = _proof_origin_leaf("second")
    resolver = def_search._py_slow_recursively_resolve_ast

    resolver(first, _ProofOriginBlock(7), SimpleNamespace(this=object()), cache=cache)
    resolver(second, _ProofOriginBlock(8), SimpleNamespace(this=object()), cache=cache)

    assert first.proof_origin is not None
    assert second.proof_origin is not None
    assert first.proof_origin != second.proof_origin
    assert len(create_z3_vars([first, second])) == 2


def test_terminal_origin_normalizes_distinct_mba_wrappers(monkeypatch):
    """Equivalent SWIG MBA wrappers use their native pointer identity."""

    monkeypatch.setattr(def_search, "_proof_operand_has_location", lambda *_a: True)
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_a: None)
    first_block = _ProofOriginBlock(7)
    second_block = _ProofOriginBlock(7)

    class MbaWrapper:
        this = 0x1234

    first_block.mba = MbaWrapper()
    second_block.mba = MbaWrapper()
    leaf = _proof_origin_leaf("entry")
    scope = object()
    first = def_search._terminal_proof_origin(
        leaf.mop,
        first_block,
        SimpleNamespace(this=object()),
        max_predecessor_blocks=1,
        scope=scope,
    )
    second = def_search._terminal_proof_origin(
        leaf.mop,
        second_block,
        SimpleNamespace(this=object()),
        max_predecessor_blocks=1,
        scope=scope,
    )

    assert first is not None
    assert second == first


@pytest.mark.parametrize("predecessor_location", ["empty", "raises"])
def test_terminal_origin_validates_location_in_each_walk_block(
    monkeypatch, predecessor_location
):
    """A use-site location cannot certify an invalid predecessor location."""

    calls = []

    class FakeLocations:
        def __init__(self):
            self._empty = True

        def empty(self):
            return self._empty

    class Mba:
        this = 0x1234

        def __init__(self):
            self.blocks = {}

        def get_mblock(self, serial):
            return self.blocks[serial]

    class Block:
        def __init__(self, serial, *, predecessor=None, location="valid"):
            self.serial = serial
            self.start = 0x4000 + serial * 0x20
            self.end = self.start + 0x20
            self.this = object()
            self.mba = mba
            self.predecessor = predecessor
            self.location = location

        def append_use_list(self, locations, _mop, _access):
            calls.append(self.serial)
            if self.location == "raises":
                raise RuntimeError("predecessor location failed")
            locations._empty = self.location == "empty"

        def npred(self):
            return 0 if self.predecessor is None else 1

        def pred(self, index):
            assert index == 0
            return self.predecessor.serial

    mba = Mba()
    predecessor = Block(11, location=predecessor_location)
    use_block = Block(10, predecessor=predecessor, location="valid")
    mba.blocks[use_block.serial] = use_block
    mba.blocks[predecessor.serial] = predecessor

    monkeypatch.setattr(def_search.ida_hexrays, "mlist_t", FakeLocations)
    monkeypatch.setattr(
        def_search,
        "_materialize_mop_for_tracking",
        lambda mop, *_a, **_k: mop,
    )
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_a: None)

    mop = SimpleNamespace(
        t=ida_hexrays.mop_r,
        size=4,
        r=1,
        valnum=0,
        this=object(),
    )
    origin = def_search._terminal_proof_origin(
        mop,
        use_block,
        SimpleNamespace(this=object()),
        max_predecessor_blocks=1,
        scope=object(),
    )

    assert origin is None
    assert calls == [use_block.serial, predecessor.serial]


def test_resolver_move_ast_preserves_source_operand(monkeypatch):
    """Resolver definitions must not overwrite a move's source with its dst."""

    from d810.hexrays.expr.ast import AstLeaf

    source = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=16, valnum=0)
    destination = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=8, valnum=0)
    source_ast = AstLeaf("source")
    source_ast.mop = source
    monkeypatch.setattr(def_search, "mop_to_ast", lambda mop, **_kwargs: source_ast)
    instruction = SimpleNamespace(
        opcode=ida_hexrays.m_mov,
        l=source,
        d=destination,
        ea=0x401000,
    )

    result = def_search._minsn_to_ast_with_budget(instruction, None)

    assert result is source_ast
    assert result.mop is source


def test_resolver_move_ast_preserves_source_width_anchor_and_budget(monkeypatch):
    """Resolver-only moves use the source value, width, anchors, and budget."""

    from d810.hexrays.expr.ast import AstLeaf

    source = SimpleNamespace(t=ida_hexrays.mop_r, size=2, r=16, valnum=0)
    destination = SimpleNamespace(t=ida_hexrays.mop_r, size=8, r=8, valnum=0)
    instruction = SimpleNamespace(
        opcode=ida_hexrays.m_mov,
        l=source,
        d=destination,
        ea=0x401234,
    )

    class Budget:
        def __init__(self):
            self.consumed = 0
            self.charged = []

        def consume(self):
            self.consumed += 1

        def mark_charged(self, occurrence):
            self.charged.append(occurrence)

    budget = Budget()
    seen = []

    def build_source(mop, *, node_budget):
        seen.append((mop, node_budget))
        node_budget.consume()
        ast = AstLeaf("source")
        ast.mop = mop
        ast.dest_size = mop.size
        node_budget.mark_charged(ast)
        return ast

    monkeypatch.setattr(def_search, "mop_to_ast", build_source)
    result = def_search._minsn_to_ast_with_budget(instruction, budget)

    assert result.mop is source
    assert result.dest_size == source.size
    assert result.ea == instruction.ea
    assert result.ins is instruction
    assert seen == [(source, budget)]
    assert budget.consumed == 1
    assert budget.charged == [result]


def test_ast_leaf_update_clears_stale_origin_without_replacement():
    """A failed binding cannot retain provenance from a previous AST."""

    from d810.hexrays.expr.ast import AstLeaf, AstNode

    target = AstLeaf("x")
    target.proof_origin = ("stale",)
    source = AstLeaf("x")
    candidate = AstNode(ida_hexrays.m_add, source, None)
    candidate._check_implicit_equalities()

    assert target.update_leafs_mop(candidate) is False
    assert target.proof_origin is None


def test_ast_leaf_update_copies_only_source_origin_with_source_mop():
    """A successful binding takes provenance from its matching source leaf."""

    from d810.hexrays.expr.ast import AstLeaf, AstNode

    source_mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=16, valnum=0)
    target = AstLeaf("x")
    target.proof_origin = ("stale",)
    source = AstLeaf("x")
    source.mop = source_mop
    source.proof_origin = ("source",)
    candidate = AstNode(ida_hexrays.m_add, source, None)
    candidate._check_implicit_equalities()

    assert target.update_leafs_mop(candidate) is True
    assert target.mop is source_mop
    assert target.proof_origin == source.proof_origin


def test_recursive_origin_fixture_uses_compiled_backend_when_enabled():
    """The parity fixture must not silently exercise Python in Cython mode."""

    from d810.core.cymode import CythonMode

    if CythonMode().is_enabled():
        assert def_search.get_recursive_resolver_backend() == "cython"


def test_terminal_origin_fails_closed_for_ambiguous_or_exhausted_paths(monkeypatch):
    """Joins and depth cutoffs are not unique block-entry proofs."""

    monkeypatch.setattr(def_search, "_proof_operand_has_location", lambda *_a: True)
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_a: None)
    leaf = _proof_origin_leaf("entry")

    class JoinBlock(_ProofOriginBlock):
        def npred(self):
            return 2

    assert (
        def_search._terminal_proof_origin(
            leaf.mop,
            JoinBlock(7),
            SimpleNamespace(this=object()),
            max_predecessor_blocks=1,
            scope=object(),
        )
        is None
    )

    class ChainBlock(_ProofOriginBlock):
        def __init__(self, serial, predecessor):
            super().__init__(serial)
            self._predecessor = predecessor

        def npred(self):
            return 1

        def pred(self, index):
            assert index == 0
            return self._predecessor.serial

    terminal = _ProofOriginBlock(9)

    class Mba:
        def get_mblock(self, serial):
            assert serial == terminal.serial
            return terminal

    chain = ChainBlock(8, terminal)
    chain.mba = Mba()
    assert (
        def_search._terminal_proof_origin(
            leaf.mop,
            chain,
            SimpleNamespace(this=object()),
            max_predecessor_blocks=0,
            scope=object(),
        )
        is None
    )


def test_terminal_origin_fails_closed_for_reaching_definition_or_location_error(
    monkeypatch,
):
    """A definition, empty location, or API error cannot create provenance."""

    leaf = _proof_origin_leaf("entry")
    block = _ProofOriginBlock(7)
    ins = SimpleNamespace(this=object())
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_a: object())
    monkeypatch.setattr(def_search, "_proof_operand_has_location", lambda *_a: True)
    assert (
        def_search._terminal_proof_origin(
            leaf.mop, block, ins, max_predecessor_blocks=1, scope=object()
        )
        is None
    )

    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_a: None)
    monkeypatch.setattr(def_search, "_proof_operand_has_location", lambda *_a: False)
    assert (
        def_search._terminal_proof_origin(
            leaf.mop, block, ins, max_predecessor_blocks=1, scope=object()
        )
        is None
    )

    monkeypatch.setattr(
        def_search,
        "_proof_operand_has_location",
        lambda *_a: (_ for _ in ()).throw(RuntimeError("location")),
    )
    assert (
        def_search._terminal_proof_origin(
            leaf.mop, block, ins, max_predecessor_blocks=1, scope=object()
        )
        is None
    )


def _resolver_width_test_leaf(name: str, size: int):
    """Build a register AST leaf with an explicit Hex-Rays byte width."""

    from d810.hexrays.expr.ast import AstLeaf

    leaf = AstLeaf(name)
    leaf.mop = SimpleNamespace(
        t=ida_hexrays.mop_r,
        size=size,
        r=1,
        valnum=0,
    )
    leaf.dest_size = size
    return leaf


def _resolver_width_test_definition(size: int):
    """Build a definition AST whose result width is *size* bytes."""

    from d810.hexrays.expr.ast import AstLeaf, AstNode

    definition = AstNode(
        ida_hexrays.m_add,
        AstLeaf("definition_left"),
        AstLeaf("definition_right"),
    )
    definition.dest_size = size
    return definition


@pytest.mark.parametrize(
    "resolver_name",
    ["_py_slow_recursively_resolve_ast", "recursively_resolve_ast"],
)
def test_recursive_resolver_truncates_wider_definition_to_use_width(
    monkeypatch, resolver_name
):
    """A wider producer must be explicitly narrowed at a narrower use site."""

    from d810.hexrays.expr.ast import AstNode

    replacement = _resolver_width_test_definition(8)
    use = _resolver_width_test_leaf("use", 4)

    monkeypatch.setattr(
        def_search,
        "resolve_mop_to_ast",
        lambda *_args, **_kwargs: replacement,
    )
    result = getattr(def_search, resolver_name)(
        use,
        SimpleNamespace(serial=7),
        SimpleNamespace(this=1),
        cache={},
    )

    assert isinstance(result, AstNode)
    assert result.opcode == ida_hexrays.m_low
    assert result.left is replacement
    assert result.right is None
    assert result.dest_size == 4


@pytest.mark.parametrize(
    "resolver_name",
    ["_py_slow_recursively_resolve_ast", "recursively_resolve_ast"],
)
def test_recursive_resolver_keeps_equal_width_definition_unchanged(
    monkeypatch, resolver_name
):
    """Equal-width replacement keeps the original definition shape."""

    replacement = _resolver_width_test_definition(4)
    use = _resolver_width_test_leaf("use", 4)

    monkeypatch.setattr(
        def_search,
        "resolve_mop_to_ast",
        lambda *_args, **_kwargs: replacement,
    )
    result = getattr(def_search, resolver_name)(
        use,
        SimpleNamespace(serial=7),
        SimpleNamespace(this=1),
        cache={},
    )

    assert result is replacement


@pytest.mark.parametrize(
    "resolver_name",
    ["_py_slow_recursively_resolve_ast", "recursively_resolve_ast"],
)
def test_recursive_resolver_rejects_narrower_definition_for_wider_use(
    monkeypatch, resolver_name
):
    """A partial-register definition is never widened by recursive resolution."""

    replacement = _resolver_width_test_definition(4)
    use = _resolver_width_test_leaf("use", 8)

    monkeypatch.setattr(
        def_search,
        "resolve_mop_to_ast",
        lambda *_args, **_kwargs: replacement,
    )
    result = getattr(def_search, resolver_name)(
        use,
        SimpleNamespace(serial=7),
        SimpleNamespace(this=1),
        cache={},
    )

    assert result is use


@pytest.mark.parametrize(
    "resolver_name",
    ["_py_slow_recursively_resolve_ast", "recursively_resolve_ast"],
)
def test_recursive_resolver_cache_includes_use_width(monkeypatch, resolver_name):
    """One storage identity cannot reuse a replacement at another width."""

    replacement = _resolver_width_test_definition(8)
    narrow_use = _resolver_width_test_leaf("narrow_use", 4)
    wide_use = _resolver_width_test_leaf("wide_use", 8)
    calls = []

    def resolve(*_args, **_kwargs):
        calls.append(1)
        return replacement

    monkeypatch.setattr(def_search, "get_mop_key", lambda _mop: ("r", 1))
    monkeypatch.setattr(def_search, "resolve_mop_to_ast", resolve)
    block = SimpleNamespace(serial=7)
    instruction = SimpleNamespace(this=1)
    cache = {}
    resolver = getattr(def_search, resolver_name)

    narrow_result = resolver(narrow_use, block, instruction, cache=cache)
    wide_result = resolver(wide_use, block, instruction, cache=cache)

    assert len(calls) == 2
    assert narrow_result.opcode == ida_hexrays.m_low
    assert wide_result is replacement


@pytest.mark.parametrize(
    "resolver_name",
    ["_py_slow_recursively_resolve_ast", "recursively_resolve_ast"],
)
def test_recursive_resolver_fails_closed_when_definition_width_unknown(
    monkeypatch, resolver_name
):
    """Unknown producer width must not be guessed from the use site."""

    from d810.hexrays.expr.ast import AstLeaf, AstNode

    replacement = AstNode(
        ida_hexrays.m_add,
        AstLeaf("definition_left"),
        AstLeaf("definition_right"),
    )
    use = _resolver_width_test_leaf("use", 4)

    monkeypatch.setattr(
        def_search,
        "resolve_mop_to_ast",
        lambda *_args, **_kwargs: replacement,
    )
    result = getattr(def_search, resolver_name)(
        use,
        SimpleNamespace(serial=7),
        SimpleNamespace(this=1),
        cache={},
    )

    assert result is use


@pytest.mark.parametrize(
    "resolver_name",
    ["_py_slow_recursively_resolve_ast", "recursively_resolve_ast"],
)
def test_recursive_resolver_charges_synthetic_truncation(monkeypatch, resolver_name):
    """The inserted low-part node participates in the caller's node budget."""

    replacement = _resolver_width_test_definition(8)
    use = _resolver_width_test_leaf("use", 4)

    class Budget:
        def __init__(self):
            self.consumed = 0
            self.charged = []

        def consume(self):
            self.consumed += 1

        def mark_charged(self, occurrence):
            self.charged.append(occurrence)

    monkeypatch.setattr(
        def_search,
        "resolve_mop_to_ast",
        lambda *_args, **_kwargs: replacement,
    )
    budget = Budget()
    result = getattr(def_search, resolver_name)(
        use,
        SimpleNamespace(serial=7),
        SimpleNamespace(this=1),
        cache={},
        node_budget=budget,
    )

    assert result.opcode == ida_hexrays.m_low
    assert budget.consumed == 1
    assert budget.charged == [result]


def test_resolve_mop_to_ast_fails_closed_for_unowned_stack_snapshot(monkeypatch):
    class ExplodingTracker:
        @staticmethod
        def reset():
            raise AssertionError("tracker should not run for unowned stack snapshots")

    tracker_module = SimpleNamespace(MopTracker=ExplodingTracker)
    monkeypatch.setattr(def_search, "MopSnapshot", FakeSnapshot)
    monkeypatch.setitem(
        def_search.sys.modules,
        "d810.evaluator.hexrays_microcode.tracker",
        tracker_module,
    )
    monkeypatch.setattr(def_search, "_USE_NATIVE_DEF_SEARCH", False)

    snapshot = FakeSnapshot(t=ida_hexrays.mop_S, size=4, stkoff=0x10)
    result = def_search.resolve_mop_to_ast(
        snapshot,
        blk=object(),
        ins=SimpleNamespace(ea=0x1000),
    )

    assert result is None


def test_find_def_in_block_uses_destination_owned_stack_operand(monkeypatch):
    calls = []

    class ImportedBlock:
        mba = object()
        tail = None

        def append_use_list(self, _ml, mop, _access):
            calls.append(mop)

    monkeypatch.setattr(
        def_search.ida_hexrays,
        "mlist_t",
        lambda: SimpleNamespace(empty=lambda: True),
    )

    assert (
        def_search.find_def_in_block(
            SimpleNamespace(t=ida_hexrays.mop_r),
            ImportedBlock(),
            None,
        )
        is None
    )
    assert len(calls) == 1
