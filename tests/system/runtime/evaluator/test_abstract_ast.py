"""Runtime tests for the cheap abstract AST zero/nonzero evaluator."""

import ida_hexrays
import pytest

from d810.analyses.abstract_domains.known_bits import KnownBits
from d810.analyses.abstract_domains.wrapped_interval import WrappedInterval
from d810.analyses.data_flow.concolic.abstract_evidence import AbstractEvidence
from d810.analyses.data_flow.concolic.refs import LocationRef, ValueRef
from d810.analyses.data_flow.concolic.values import ConcolicValue, PrecisionStatus, reduce
from d810.evaluator.hexrays_microcode.def_search import CallResultAstLeaf
from d810.hexrays.expr.ast import AstConstant, AstLeaf, AstNode
from d810.hexrays.ir.mop_snapshot import MopSnapshot


def _constant(value: int, size: int = 1):
    leaf = AstConstant(f"c{value:x}", expected_value=value, expected_size=size)
    leaf.mop = MopSnapshot(t=ida_hexrays.mop_n, size=size, value=value)
    return leaf


def _leaf(name: str = "x", size: int = 1):
    leaf = AstLeaf(name)
    leaf.mop = MopSnapshot(t=ida_hexrays.mop_r, size=size, reg=1)
    return leaf


def _node(opcode, left, right=None, size=None):
    node = AstNode(opcode, left, right)
    if size is not None:
        node.dest_size = size
    return node


def _call(value: ConcolicValue, size: int = 1):
    leaf = CallResultAstLeaf(
        "call-result",
        ValueRef(LocationRef.reg(1, size), def_site=0x401000),
        value,
    )
    leaf.mop = MopSnapshot(t=ida_hexrays.mop_r, size=size, reg=1)
    return leaf


def _abstract(width: int, *, zero=0, one=0, lo=0, hi=0, interval_kind=None):
    if interval_kind is None:
        interval_kind = "range" if (lo or hi) else "top"
    bits = KnownBits(width, zero=zero, one=one)
    interval = WrappedInterval(width, lo=lo, hi=hi, kind=interval_kind)
    return reduce(
        ConcolicValue(
            None,
            None,
            AbstractEvidence(width, bits, interval),
            width,
            PrecisionStatus.ABSTRACT,
        )
    )


def test_exact_zero_is_always_zero():
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    assert decide_zero_status(_constant(0, 1)) is AbstractZeroStatus.ALWAYS_ZERO


def test_exact_nonzero_is_always_nonzero():
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    assert decide_zero_status(_constant(7, 4)) is AbstractZeroStatus.ALWAYS_NONZERO


def test_known_one_bit_survives_and_mask_and_proves_nonzero():
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    value = _call(_abstract(32, one=0x40, zero=((1 << 32) - 1) ^ 0x40), 4)
    root = _node(ida_hexrays.m_and, value, _constant(0x40, 4), size=4)
    assert decide_zero_status(root) is AbstractZeroStatus.ALWAYS_NONZERO


def test_known_zero_mask_proves_zero_after_and():
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    value = _call(_abstract(8, zero=0x40), 1)
    root = _node(ida_hexrays.m_and, value, _constant(0x40, 1), size=1)
    assert decide_zero_status(root) is AbstractZeroStatus.ALWAYS_ZERO


def test_interval_excluding_zero_proves_nonzero():
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    assert decide_zero_status(_call(_abstract(8, lo=3, hi=7), 1)) is AbstractZeroStatus.ALWAYS_NONZERO


def test_wrapped_interval_containing_zero_is_unknown():
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    value = _call(_abstract(8, lo=0xF0, hi=0x0F), 1)
    assert decide_zero_status(value) is AbstractZeroStatus.UNKNOWN


@pytest.mark.parametrize("opcode", [ida_hexrays.m_add, ida_hexrays.m_sub, ida_hexrays.m_xor, ida_hexrays.m_or, ida_hexrays.m_and])
def test_add_sub_xor_or_and_use_existing_domain_transfers(opcode):
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    root = _node(opcode, _constant(1, 1), _constant(1, 1), size=1)
    expected = AbstractZeroStatus.ALWAYS_ZERO if opcode in (ida_hexrays.m_sub, ida_hexrays.m_xor) else AbstractZeroStatus.ALWAYS_NONZERO
    assert decide_zero_status(root) is expected


def test_constant_shl_and_logical_shr_are_width_masked():
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    shl = _node(ida_hexrays.m_shl, _constant(0x81, 1), _constant(7, 1), size=1)
    shr = _node(ida_hexrays.m_shr, _constant(0x81, 1), _constant(7, 1), size=1)
    assert decide_zero_status(shl) is AbstractZeroStatus.ALWAYS_NONZERO
    assert decide_zero_status(shr) is AbstractZeroStatus.ALWAYS_NONZERO


@pytest.mark.parametrize("width", [8, 32, 64])
def test_shift_count_at_operand_width_is_unknown(width):
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    size = width // 8
    for opcode in (ida_hexrays.m_shl, ida_hexrays.m_shr):
        root = _node(opcode, _constant(1 << (width - 1), size), _constant(width, size), size=size)
        assert decide_zero_status(root) is AbstractZeroStatus.UNKNOWN


def test_variable_shift_is_unknown():
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    root = _node(ida_hexrays.m_shl, _call(ConcolicValue.top(8), 1), _leaf("shift", 1), size=1)
    assert decide_zero_status(root) is AbstractZeroStatus.UNKNOWN


def test_unsupported_opcode_is_unknown():
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    root = _node(ida_hexrays.m_mul, _constant(1, 1), _constant(1, 1), size=1)
    assert decide_zero_status(root) is AbstractZeroStatus.UNKNOWN


def test_top_call_leaf_is_unknown():
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    assert decide_zero_status(_call(ConcolicValue.top(64), 8)) is AbstractZeroStatus.UNKNOWN


def test_supported_extension_node_is_evaluated():
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    source = _call(ConcolicValue.of(0x80, 8), 1)
    extension = _node(ida_hexrays.m_xdu, source, size=4)
    assert decide_zero_status(extension) is AbstractZeroStatus.ALWAYS_NONZERO


def test_call_evidence_width_must_match_structural_width():
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    structurally_32 = _call(ConcolicValue.of(1 << 40, 64), size=4)
    assert decide_zero_status(structurally_32) is AbstractZeroStatus.UNKNOWN


def test_conversion_with_missing_result_width_is_unknown():
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    source = _call(ConcolicValue.of(0x80, 8), size=1)
    malformed = AstNode(ida_hexrays.m_high, source)
    assert decide_zero_status(malformed) is AbstractZeroStatus.UNKNOWN


def test_m_high_requires_supported_two_to_one_width_ratio():
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    source = _call(ConcolicValue.of(0x8000, 64), size=8)
    unsupported = _node(ida_hexrays.m_high, source, size=1)
    assert decide_zero_status(unsupported) is AbstractZeroStatus.UNKNOWN


def test_out_of_range_known_bit_is_unknown():
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    value = _call(_abstract(32, one=1 << 40), size=4)
    assert decide_zero_status(value) is AbstractZeroStatus.UNKNOWN


def test_component_width_mismatch_is_unknown():
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    evidence = AbstractEvidence(32, KnownBits.top(64), WrappedInterval.top(64))
    value = ConcolicValue(None, None, evidence, 32, PrecisionStatus.ABSTRACT)
    assert decide_zero_status(_call(value, size=4)) is AbstractZeroStatus.UNKNOWN


def test_inconsistent_singletons_are_reduced_to_unknown():
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    evidence = AbstractEvidence(32, KnownBits.of(1, 32), WrappedInterval.of(0, 32))
    value = ConcolicValue(None, None, evidence, 32, PrecisionStatus.ABSTRACT)
    assert decide_zero_status(_call(value, size=4)) is AbstractZeroStatus.UNKNOWN


def test_out_of_width_interval_nested_under_outer_width_is_unknown():
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    evidence = AbstractEvidence(32, KnownBits.top(32), WrappedInterval.of(0x1_0000_0000, 64))
    value = ConcolicValue(None, None, evidence, 32, PrecisionStatus.ABSTRACT)
    root = _node(ida_hexrays.m_mov, _call(value, size=4), size=4)
    assert decide_zero_status(root) is AbstractZeroStatus.UNKNOWN


def test_valid_reduced_evidence_is_preserved():
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    evidence = AbstractEvidence(32, KnownBits(32, zero=0xFFFFFFFF ^ 0x40, one=0x40), WrappedInterval.top(32))
    value = ConcolicValue(None, None, evidence, 32, PrecisionStatus.ABSTRACT)
    assert decide_zero_status(_call(value, size=4)) is AbstractZeroStatus.ALWAYS_NONZERO


@pytest.mark.parametrize(
    ("source_width", "target_width", "value"),
    ((64, 8, 0x101), (128, 32, 0x1_0000_0001)),
)
def test_m_low_accepts_supported_wider_to_narrower_truncation(source_width, target_width, value):
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    source = _call(ConcolicValue.of(value, source_width), size=source_width // 8)
    root = _node(ida_hexrays.m_low, source, size=target_width // 8)
    assert decide_zero_status(root) is AbstractZeroStatus.ALWAYS_NONZERO


@pytest.mark.parametrize("target_width", [32, 64])
def test_m_low_equal_or_wider_target_is_unknown(target_width):
    from d810.evaluator.hexrays_microcode.abstract_ast import AbstractZeroStatus, decide_zero_status

    source = _call(ConcolicValue.of(1, 32), size=4)
    root = _node(ida_hexrays.m_low, source, size=target_width // 8)
    assert decide_zero_status(root) is AbstractZeroStatus.UNKNOWN
