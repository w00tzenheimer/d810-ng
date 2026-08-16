"""Hex-Rays lowering for the exact 64-bit multiply/shift rotate idiom."""

from __future__ import annotations

import ida_hexrays
import ida_typeinf

from d810.core import typing
from d810.hexrays.ir_maturity import ir_maturity_to_ida
from d810.hexrays.utils.hexrays_helpers import dup_mop, structural_mop_hash
from d810.ir.maturity import IRMaturity
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeSimplificationRule,
)
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule
from d810.optimizers.microcode.instructions.peephole.rotate_idiom_recovery import (
    Binary,
    Constant,
    Expression,
    RotateIdiomMatch,
    Variable,
    match_rol64_idiom,
)


_BINARY_OPCODE_NAMES = {
    ida_hexrays.m_or: "or",
    ida_hexrays.m_mul: "mul",
    ida_hexrays.m_shr: "shr",
}


def _fresh_uint_type(declaration: int) -> ida_typeinf.tinfo_t:
    """Create a type handle owned by the currently open IDB.

    IDA type handles do not survive disposable-database teardown.  Keeping one
    at module scope makes later databases fail helper construction depending on
    test or plugin load order.
    """

    type_info = ida_typeinf.tinfo_t()
    type_info.create_simple_type(declaration)
    return type_info


def _width_of(mop: ida_hexrays.mop_t | None) -> int:
    return 0 if mop is None else int(mop.size) * 8


def _expression_from_mop(mop: ida_hexrays.mop_t | None) -> Expression | None:
    width = _width_of(mop)
    if mop is None or width == 0 or width > 64:
        return None
    if mop.t == ida_hexrays.mop_n:
        # Hex-Rays' Python binding may surface high-bit 64-bit immediates as
        # signed integers.  The matcher is explicitly BV64, so normalize the
        # representation without widening or accepting a different constant.
        return Constant(int(mop.nnn.value) & ((1 << width) - 1), width, source=mop)
    if mop.t == ida_hexrays.mop_d and mop.d is not None:
        instruction = mop.d
        opcode_name = _BINARY_OPCODE_NAMES.get(instruction.opcode)
        if opcode_name is not None:
            left = _expression_from_mop(instruction.l)
            right = _expression_from_mop(instruction.r)
            if left is None or right is None:
                return None
            return Binary(opcode_name, width, left, right, source=mop)
    # The native gate rechecks the original mops with Hex-Rays equality before
    # it mutates anything, so a structural-hash collision cannot authorize a
    # rewrite.
    return Variable(str(structural_mop_hash(mop)), width, source=mop)


def _expression_from_instruction(ins: ida_hexrays.minsn_t) -> Expression | None:
    opcode_name = _BINARY_OPCODE_NAMES.get(ins.opcode)
    if opcode_name is not None and _width_of(ins.d) == 64:
        left = _expression_from_mop(ins.l)
        right = _expression_from_mop(ins.r)
        if left is None or right is None:
            return None
        return Binary(opcode_name, 64, left, right, source=ins)
    # At GLBOPT2 Hex-Rays commonly exposes the value expression as
    # ``mov mop_d(m_or(...)), destination``.  The `mov` itself is not part of
    # the identity; it is only the value-producing container that owns the
    # destination needed by create_helper_call.
    if (
        ins.opcode == ida_hexrays.m_mov
        and _width_of(ins.d) == 64
        and ins.l.t == ida_hexrays.mop_d
    ):
        return _expression_from_mop(ins.l)
    return None


def _same_effect_free_value(left: ida_hexrays.mop_t, right: ida_hexrays.mop_t) -> bool:
    """Require exact duplicate, non-effectful operands before coalescing."""

    if _width_of(left) != 64 or _width_of(right) != 64:
        return False
    try:
        if left.has_side_effects(False) or right.has_side_effects(False):
            return False
        return bool(left.equal_mops(right, 0))
    except Exception:
        return False


def make_rol8_helper_call(
    block: ida_hexrays.mblock_t,
    *,
    ea: int,
    base: ida_hexrays.mop_t,
    rotation: int,
    output: ida_hexrays.mop_t,
) -> ida_hexrays.minsn_t | None:
    """Build Hex-Rays' value-producing ``mov __ROL8__(base, count), out``."""

    if (
        block is None
        or not 1 <= int(rotation) < 64
        or _width_of(base) != 64
        or _width_of(output) != 64
    ):
        return None
    try:
        uint64_type = _fresh_uint_type(ida_typeinf.BTF_UINT64)
        uint8_type = _fresh_uint_type(ida_typeinf.BTF_UINT8)
        value_arg = ida_hexrays.mcallarg_t()
        value_arg.copy_mop(dup_mop(base))
        value_arg.type = uint64_type
        count_arg = ida_hexrays.mcallarg_t()
        count_arg.make_number(int(rotation), 1, ea)
        count_arg.type = uint8_type
        args = ida_hexrays.mcallargs_t()
        args.push_back(value_arg)
        args.push_back(count_arg)
        return block.mba.create_helper_call(
            ea,
            "__ROL8__",
            uint64_type,
            args,
            dup_mop(output),
        )
    except Exception:
        return None


def _validated_native_match(
    expression: Expression | None,
) -> tuple[RotateIdiomMatch, ida_hexrays.mop_t] | None:
    """Return only a structurally exact, effect-free native candidate."""

    if expression is None:
        return None
    match = match_rol64_idiom(expression)
    if match is None:
        return None
    base_mop = match.base.source
    duplicate_mop = match.duplicated_value.source
    base_value = match.base.right.source
    if (
        not isinstance(base_mop, ida_hexrays.mop_t)
        or not isinstance(duplicate_mop, ida_hexrays.mop_t)
        or not isinstance(base_value, ida_hexrays.mop_t)
        or not _same_effect_free_value(base_value, duplicate_mop)
    ):
        return None
    return match, base_mop


def _helper_call_from_validated_match(
    block: ida_hexrays.mblock_t,
    *,
    ea: int,
    match: RotateIdiomMatch,
    base_mop: ida_hexrays.mop_t,
    output: ida_hexrays.mop_t,
) -> ida_hexrays.minsn_t | None:
    """Lower a candidate already admitted by ``_validated_native_match``."""

    return make_rol8_helper_call(
        block,
        ea=ea,
        base=base_mop,
        rotation=match.rotation,
        output=output,
    )


def _helper_call_from_match(
    block: ida_hexrays.mblock_t,
    *,
    ea: int,
    expression: Expression | None,
    output: ida_hexrays.mop_t,
) -> ida_hexrays.minsn_t | None:
    """Validate a root value and lower it without changing allocator state."""

    candidate = _validated_native_match(expression)
    if candidate is None:
        return None
    match, base_mop = candidate
    return _helper_call_from_validated_match(
        block,
        ea=ea,
        match=match,
        base_mop=base_mop,
        output=output,
    )


def _fresh_kreg_output(
    block: ida_hexrays.mblock_t,
    size: int = 8,
) -> ida_hexrays.mop_t | None:
    """Allocate a typed temporary for one helper result."""

    try:
        kreg = block.mba.alloc_kreg(size, True)
        if kreg == ida_hexrays.mr_none:
            return None
        result = ida_hexrays.mop_t()
        result.make_reg(kreg, size)
        return result
    except Exception:
        return None


def _recover_nested_value_mop(
    block: ida_hexrays.mblock_t,
    *,
    ea: int,
    mop: ida_hexrays.mop_t,
) -> tuple[ida_hexrays.mop_t, tuple[ida_hexrays.minsn_t, ...]]:
    """Clone ``mop`` and materialize exact nested rotates into fresh kregs.

    Hex-Rays accepts helper calls in the established value-producing form
    ``mov call !__ROL8__(...), kreg``.  A raw ``m_call`` nested beneath an
    arithmetic ``mop_d`` is printable, but fails ``mba.verify()``.  Keep calls
    as sibling instructions and let the rebuilt SSA expression consume their
    value registers instead.
    """

    if mop.t != ida_hexrays.mop_d or mop.d is None:
        return dup_mop(mop), ()
    expression = _expression_from_mop(mop)
    # Allocating a kreg changes the MBA allocator state even when no rewrite
    # follows. The walker visits every nested value in a block, so allocation
    # must be strictly behind the exact structural/effect-free gate.
    candidate = _validated_native_match(expression)
    output = _fresh_kreg_output(block) if candidate is not None else None
    helper = (
        _helper_call_from_validated_match(
            block,
            ea=ea,
            match=candidate[0],
            base_mop=candidate[1],
            output=output,
        )
        if output is not None
        else None
    )
    if helper is not None:
        return dup_mop(output), (helper,)

    nested = ida_hexrays.minsn_t(mop.d)
    left, left_helpers = _recover_nested_value_mop(block, ea=ea, mop=nested.l)
    right, right_helpers = _recover_nested_value_mop(block, ea=ea, mop=nested.r)
    if not left_helpers and not right_helpers:
        return dup_mop(mop), ()
    nested.l = left
    nested.r = right
    result = ida_hexrays.mop_t()
    result.create_from_insn(nested)
    return result, left_helpers + right_helpers


class RotateIdiomRecoveryRule(PeepholeSimplificationRule):
    """Lift exactly ``(C<<r)*x | (C*x >> (64-r))`` into ``__ROL8__``."""

    DESCRIPTION = "Recover exact 64-bit multiply/shift rotate idioms as __ROL8__"
    TARGET_OPCODES = frozenset({ida_hexrays.m_mov, ida_hexrays.m_or, ida_hexrays.m_xor})

    def __init__(self) -> None:
        super().__init__()
        self.maturities = [ida_hexrays.MMAT_GLBOPT2]

    def configure(self, kwargs) -> None:
        config = dict(kwargs or {})
        maturity_names = config.pop("maturities", None)
        super().configure(config)
        if maturity_names is not None:
            try:
                self.maturities = [
                    ir_maturity_to_ida(IRMaturity[str(name)]) for name in maturity_names
                ]
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(
                    "RotateIdiomRecoveryRule maturities must be IRMaturity names"
                ) from exc

    @typing.override
    def check_and_replace(
        self,
        block: ida_hexrays.mblock_t | None,
        instruction: ida_hexrays.minsn_t,
    ) -> ida_hexrays.minsn_t | None:
        if block is None or instruction.opcode not in self.TARGET_OPCODES:
            return None
        expression = _expression_from_instruction(instruction)
        direct_replacement = _helper_call_from_match(
            block,
            ea=instruction.ea,
            expression=expression,
            output=instruction.d,
        )
        if direct_replacement is not None:
            return direct_replacement
        return None


class RotateIdiomRecoveryBlockRule(FlowOptimizationRule):
    """Visit every GLBOPT2 instruction so nested value expressions are seen."""

    DESCRIPTION = "Recover exact 64-bit multiply/shift rotate idioms as __ROL8__"

    def __init__(self) -> None:
        super().__init__()
        self.maturities = [ida_hexrays.MMAT_GLBOPT2]
        self._rewriter = RotateIdiomRecoveryRule()
        self._active_mba_scope: tuple[int, int] | None = None
        self._applied_instruction_eas: set[int] = set()

    def configure(self, kwargs) -> None:
        config = dict(kwargs or {})
        maturity_names = config.pop("maturities", None)
        super().configure(config)
        if maturity_names is not None:
            try:
                self.maturities = [
                    ir_maturity_to_ida(IRMaturity[str(name)]) for name in maturity_names
                ]
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(
                    "RotateIdiomRecoveryBlockRule maturities must be IRMaturity names"
                ) from exc

    def optimize(self, block: ida_hexrays.mblock_t) -> int:
        if block is None:
            return 0
        mba = block.mba
        if mba is None:
            return 0
        try:
            scope = (int(mba.this), int(mba.maturity))
        except (AttributeError, TypeError, ValueError):
            # A missing native identity is not a reason to risk repeated
            # value materialization in an optblock callback.
            return 0
        if scope != self._active_mba_scope:
            self._active_mba_scope = scope
            self._applied_instruction_eas.clear()
        changed = 0
        instruction = block.head
        while instruction is not None:
            next_instruction = instruction.next
            if int(instruction.ea) in self._applied_instruction_eas:
                instruction = next_instruction
                continue
            replacement = self._rewriter.check_and_replace(block, instruction)
            if replacement is not None:
                instruction.swap(replacement)
                changed += 1
                self._applied_instruction_eas.add(int(instruction.ea))
            else:
                replacement = ida_hexrays.minsn_t(instruction)
                left, left_helpers = _recover_nested_value_mop(
                    block,
                    ea=instruction.ea,
                    mop=instruction.l,
                )
                right, right_helpers = _recover_nested_value_mop(
                    block,
                    ea=instruction.ea,
                    mop=instruction.r,
                )
                helpers = left_helpers + right_helpers
                if helpers:
                    replacement.l = left
                    replacement.r = right
                    anchor = instruction.prev
                    for helper in helpers:
                        block.insert_into_block(helper, anchor)
                        anchor = helper
                    instruction.swap(replacement)
                    changed += len(helpers)
                    self._applied_instruction_eas.add(int(instruction.ea))
            instruction = next_instruction
        # Even though this rule rewrites values only, the def/use lists belong
        # to the enclosing block.  Leaving them stale after an optblock-level
        # swap can make the following global-optimization iteration reject the
        # MBA without reporting a Python exception.
        if changed:
            block.mark_lists_dirty()
        return changed
