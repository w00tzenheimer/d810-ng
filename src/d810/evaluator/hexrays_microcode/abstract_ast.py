"""Cheap, sound zero/nonzero decisions for prepared Hex-Rays ASTs.

This module is deliberately a decision-only adapter.  It consumes abstract
call-result evidence already attached to definition-scoped leaves and reuses
the portable value-domain transfer functions; it does not create a solver or
add constraints to one.
"""

from __future__ import annotations

import enum

import ida_hexrays

from d810.core import typing
from d810.analyses.abstract_domains.operations import BinaryOp
from d810.analyses.abstract_domains.value_domain import (
    KnownBitsValueDomain,
    WrappedIntervalValueDomain,
)
from d810.analyses.data_flow.concolic.abstract_evidence import AbstractEvidence
from d810.analyses.data_flow.concolic.values import ConcolicValue

__all__ = ["AbstractZeroStatus", "decide_zero_status"]


class AbstractZeroStatus(str, enum.Enum):
    """The only conclusions this evaluator is allowed to make."""

    ALWAYS_ZERO = "always_zero"
    ALWAYS_NONZERO = "always_nonzero"
    UNKNOWN = "unknown"


_SUPPORTED_WIDTHS = frozenset({8, 16, 32, 64, 128})
_KNOWN_BITS = KnownBitsValueDomain()
_INTERVALS = WrappedIntervalValueDomain()


def _width_bits(value: typing.Any) -> int | None:
    """Read an AST width in bits without trusting arbitrary native objects."""

    evidence = getattr(value, "concolic_value", None)
    if isinstance(evidence, ConcolicValue):
        width = evidence.width
        if type(width) is int and width in _SUPPORTED_WIDTHS:
            return width

    # AstNode.dest_size and mop.size are byte counts in Hex-Rays.
    for candidate in (
        getattr(value, "dest_size", None),
        getattr(getattr(value, "mop", None), "size", None),
        getattr(getattr(value, "mop", None), "d", None),
    ):
        if candidate is not None and not isinstance(candidate, (int, bool)):
            candidate = getattr(candidate, "size", None)
        if type(candidate) is int and candidate > 0:
            width = candidate * 8
            if width in _SUPPORTED_WIDTHS:
                return width

    # A normal AstNode may not have a destination mop in a directly-constructed
    # test tree.  Infer only when both children agree; this is not an aliasing
    # or partial-register inference.
    children = [getattr(value, "left", None), getattr(value, "right", None)]
    child_widths = {_width_bits(child) for child in children if child is not None}
    child_widths.discard(None)
    if len(child_widths) == 1:
        return next(iter(child_widths))
    return None


def _constant_evidence(value: typing.Any, width: int) -> AbstractEvidence | None:
    if not bool(getattr(value, "is_constant", lambda: False)()):
        return None
    raw = getattr(value, "value", None)
    if type(raw) is not int:
        return None
    return AbstractEvidence.singleton(raw, width)


def _call_evidence(value: typing.Any, width: int) -> AbstractEvidence | None:
    if not bool(getattr(value, "_is_call_result_leaf", False)):
        return None
    concolic = getattr(value, "concolic_value", None)
    if not isinstance(concolic, ConcolicValue) or concolic.width != width:
        return None
    evidence = concolic.abstract
    if evidence.width != width or evidence.is_bottom():
        return None
    return evidence


def _resize_evidence(
    opcode: int, source: AbstractEvidence, target_width: int
) -> AbstractEvidence:
    """Transfer the supported extraction/extension nodes conservatively."""

    source_width = source.width
    if source_width == target_width:
        return source
    if target_width <= 0 or target_width not in _SUPPORTED_WIDTHS:
        return AbstractEvidence.bottom(1)
    if opcode in (ida_hexrays.m_xdu, ida_hexrays.m_xds) and target_width < source_width:
        return AbstractEvidence.bottom(1)
    if opcode in (ida_hexrays.m_low, ida_hexrays.m_high) and target_width > source_width:
        return AbstractEvidence.bottom(1)

    concrete = source.to_const()
    if concrete is not None:
        if opcode == ida_hexrays.m_high:
            value = concrete >> target_width
        elif opcode == ida_hexrays.m_xds and concrete & (1 << (source_width - 1)):
            value = concrete | (((1 << (target_width - source_width)) - 1) << source_width)
        else:
            value = concrete
        return AbstractEvidence.singleton(value, target_width)

    target_mask = (1 << target_width) - 1
    if opcode == ida_hexrays.m_low:
        bits = type(source.bits)(
            target_width,
            source.bits.zero & target_mask,
            source.bits.one & target_mask,
        )
        return AbstractEvidence(target_width, bits, _INTERVALS.top(target_width))._reduce()

    if opcode == ida_hexrays.m_high:
        shift = target_width
        bits = type(source.bits)(
            target_width,
            source.bits.zero >> shift,
            source.bits.one >> shift,
        )
        return AbstractEvidence(target_width, bits, _INTERVALS.top(target_width))._reduce()

    if opcode == ida_hexrays.m_xdu:
        upper = ((1 << (target_width - source_width)) - 1) << source_width
        bits = type(source.bits)(
            target_width,
            (source.bits.zero & ((1 << source_width) - 1)) | upper,
            source.bits.one & ((1 << source_width) - 1),
        )
        return AbstractEvidence(target_width, bits, _INTERVALS.top(target_width))._reduce()

    if opcode == ida_hexrays.m_xds:
        sign = 1 << (source_width - 1)
        known_zero = source.bits.zero
        known_one = source.bits.one
        upper = ((1 << (target_width - source_width)) - 1) << source_width
        if source.bits.zero & sign:
            known_zero |= upper
        elif source.bits.one & sign:
            known_one |= upper
        else:
            upper &= target_mask
        return AbstractEvidence(
            target_width,
            type(source.bits)(target_width, known_zero & target_mask, known_one & target_mask),
            _INTERVALS.top(target_width),
        )._reduce()

    return AbstractEvidence.bottom(1)


def _evaluate(node: typing.Any) -> AbstractEvidence | None:
    """Evaluate one supported AST shape, or return ``None`` for unknown."""

    if node is None:
        return None
    width = _width_bits(node)
    if width is None:
        return None

    constant = _constant_evidence(node, width)
    if constant is not None:
        return constant
    call = _call_evidence(node, width)
    if call is not None:
        return call
    if bool(getattr(node, "is_leaf", lambda: False)()):
        return None
    if not bool(getattr(node, "is_node", lambda: False)()):
        return None

    opcode = getattr(node, "opcode", None)
    left = getattr(node, "left", None)
    right = getattr(node, "right", None)
    if left is None:
        return None

    if opcode in (ida_hexrays.m_xdu, ida_hexrays.m_xds, ida_hexrays.m_low, ida_hexrays.m_high):
        source = _evaluate(left)
        source_width = _width_bits(left)
        if source is None or source_width is None or source.width != source_width:
            return None
        return _resize_evidence(opcode, source, width)

    operation_map = {
        ida_hexrays.m_mov: None,
        ida_hexrays.m_and: BinaryOp.AND,
        ida_hexrays.m_or: BinaryOp.OR,
        ida_hexrays.m_xor: BinaryOp.XOR,
        ida_hexrays.m_add: BinaryOp.ADD,
        ida_hexrays.m_sub: BinaryOp.SUB,
        ida_hexrays.m_shl: BinaryOp.SHL,
        ida_hexrays.m_shr: BinaryOp.SHR_U,
    }
    operation = operation_map.get(opcode, ...)
    if operation is ...:
        return None
    if operation is None:
        source = _evaluate(left)
        return source if source is not None and source.width == width else None
    if right is None:
        return None
    left_evidence, right_evidence = _evaluate(left), _evaluate(right)
    if left_evidence is None or right_evidence is None:
        return None
    if left_evidence.width != width:
        return None
    # Variable shifts are explicitly unsupported.  Domain transfer itself
    # returns Top, but rejecting here prevents a future domain widening from
    # accidentally changing this safety boundary.
    if operation in (BinaryOp.SHL, BinaryOp.SHR_U) and right_evidence.to_const() is None:
        return None
    if operation in (BinaryOp.SHL, BinaryOp.SHR_U):
        # Hex-Rays may represent a shift count in a narrower constant mop.  A
        # constant count is width-independent; normalize it to the value
        # width before invoking the existing transfer functions.
        shift = right_evidence.to_const()
        assert shift is not None
        right_evidence = AbstractEvidence.singleton(shift, width)
    elif right_evidence.width != width:
        return None
    bits = _KNOWN_BITS.eval_binary(operation, left_evidence.bits, right_evidence.bits, width)
    interval = _INTERVALS.eval_binary(operation, left_evidence.interval, right_evidence.interval, width)
    return AbstractEvidence(width, bits, interval)._reduce()


def decide_zero_status(root: typing.Any) -> AbstractZeroStatus:
    """Return a sound zero/nonzero conclusion for *root*."""

    evidence = _evaluate(root)
    if evidence is None or evidence.is_bottom():
        return AbstractZeroStatus.UNKNOWN
    exact = evidence.to_const()
    if exact is not None:
        return AbstractZeroStatus.ALWAYS_ZERO if exact == 0 else AbstractZeroStatus.ALWAYS_NONZERO
    if evidence.bits.one:
        return AbstractZeroStatus.ALWAYS_NONZERO
    if not evidence.interval.contains(0):
        return AbstractZeroStatus.ALWAYS_NONZERO
    if evidence.bits.zero == (1 << evidence.width) - 1:
        return AbstractZeroStatus.ALWAYS_ZERO
    return AbstractZeroStatus.UNKNOWN
