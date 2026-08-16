"""Native lowering for Z3-proven modular-product nonzero predicates."""

from __future__ import annotations

import ida_hexrays
import ida_typeinf

from d810.hexrays.ir_maturity import ir_maturity_to_ida
from d810.hexrays.utils.hexrays_helpers import dup_mop
from d810.ir.maturity import IRMaturity
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule
from d810.optimizers.microcode.instructions.peephole.modular_product_nonzero import (
    ModularProductNonzeroMatch,
    recover_modular_product_nonzero,
    z3_proves_modular_product_nonzero,
)
from d810.optimizers.microcode.instructions.peephole.predicate_root_recovery import (
    Binary,
    Constant,
    Predicate,
)
from d810.optimizers.microcode.instructions.peephole.predicate_root_recovery_native import (
    _effect_free_variable,
    _expression_from_mop,
)


_UINT32 = ida_typeinf.tinfo_t()
_UINT32.create_simple_type(ida_typeinf.BTF_UINT32)


def _width(mop: ida_hexrays.mop_t | None) -> int:
    return 0 if mop is None else int(mop.size) * 8


def _predicate_from_instruction(ins: ida_hexrays.minsn_t) -> Predicate | None:
    """Admit only the native form ``setnz(product, 0)``."""

    if ins.opcode != ida_hexrays.m_setnz or _width(ins.d) != 8:
        return None
    left = _expression_from_mop(ins.l)
    if left is None or left.width != 32:
        return None
    if ins.r.t != ida_hexrays.mop_n or _width(ins.r) != 32 or int(ins.r.nnn.value) != 0:
        return None
    return Predicate("ne", left, Constant(0, 32), 1, source=ins)


def _fresh_kreg(block: ida_hexrays.mblock_t, size: int) -> ida_hexrays.mop_t | None:
    try:
        register = block.mba.alloc_kreg(size, True)
        if register == ida_hexrays.mr_none:
            return None
        output = ida_hexrays.mop_t()
        output.make_reg(register, size)
        return output
    except Exception:
        return None


def _number(value: int, size: int, ea: int) -> ida_hexrays.mop_t:
    result = ida_hexrays.mop_t()
    result.make_number(value & ((1 << (size * 8)) - 1), size, ea)
    return result


def make_ctz_helper_call(
    block: ida_hexrays.mblock_t,
    *,
    ea: int,
    value: ida_hexrays.mop_t,
    output: ida_hexrays.mop_t,
) -> ida_hexrays.minsn_t | None:
    """Build the value-only 32-bit ``__ctz(value)`` helper call."""

    if block is None or _width(value) != 32 or _width(output) != 32:
        return None
    try:
        argument = ida_hexrays.mcallarg_t()
        argument.copy_mop(dup_mop(value))
        argument.type = _UINT32
        arguments = ida_hexrays.mcallargs_t()
        arguments.push_back(argument)
        return block.mba.create_helper_call(ea, "__ctz", _UINT32, arguments, dup_mop(output))
    except Exception:
        return None


def _binary(
    opcode: int,
    ea: int,
    left: ida_hexrays.mop_t,
    right: ida_hexrays.mop_t,
    output: ida_hexrays.mop_t,
) -> ida_hexrays.minsn_t:
    result = ida_hexrays.minsn_t(ea)
    result.opcode = opcode
    result.l = dup_mop(left)
    result.r = dup_mop(right)
    result.d = dup_mop(output)
    return result


def _materialize_budget_predicate(
    block: ida_hexrays.mblock_t,
    *,
    ea: int,
    match: ModularProductNonzeroMatch,
) -> tuple[ida_hexrays.mop_t, tuple[ida_hexrays.minsn_t, ...]] | None:
    """Materialize ``sum(ctz(factor)) < budget`` before the root instruction."""

    source_factors = tuple(factor.source for factor in match.factors)
    if any(not isinstance(factor, ida_hexrays.mop_t) or _width(factor) != 32 for factor in source_factors):
        return None
    try:
        if any(factor.has_side_effects(False) for factor in source_factors):
            return None
    except Exception:
        return None
    ctz_outputs = tuple(_fresh_kreg(block, 4) for _ in source_factors)
    if any(output is None for output in ctz_outputs):
        return None
    helpers = tuple(
        make_ctz_helper_call(block, ea=ea, value=factor, output=output)
        for factor, output in zip(source_factors, ctz_outputs, strict=True)
    )
    if any(helper is None for helper in helpers):
        return None
    instructions = [helper for helper in helpers if helper is not None]
    total = ctz_outputs[0]
    for value in ctz_outputs[1:]:
        output = _fresh_kreg(block, 4)
        if output is None:
            return None
        instructions.append(_binary(ida_hexrays.m_add, ea, total, value, output))
        total = output
    predicate_output = _fresh_kreg(block, 1)
    if predicate_output is None:
        return None
    instructions.append(
        _binary(
            ida_hexrays.m_setb,
            ea,
            total,
            _number(match.trailing_zero_budget, 4, ea),
            predicate_output,
        )
    )
    return predicate_output, tuple(instructions)


class ModularProductNonzeroBlockRule(FlowOptimizationRule):
    """Lift a proven product predicate to an explicit trailing-zero budget."""

    DESCRIPTION = "Recover bounded modular-product nonzero predicates"

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
                    "ModularProductNonzeroBlockRule maturities must be IRMaturity names"
                ) from exc

    def optimize(self, block: ida_hexrays.mblock_t) -> int:
        if block is None:
            return 0
        changed = 0
        instruction = block.head
        while instruction is not None:
            next_instruction = instruction.next
            if (
                instruction.opcode != ida_hexrays.m_xdu
                or instruction.l.t != ida_hexrays.mop_d
                or instruction.l.d is None
            ):
                instruction = next_instruction
                continue
            extension = ida_hexrays.minsn_t(instruction)
            predicate = _predicate_from_instruction(extension.l.d)
            match = recover_modular_product_nonzero(predicate) if predicate is not None else None
            if (
                match is None
                or not _effect_free_variable(match.variable)
                or not z3_proves_modular_product_nonzero(predicate, match)
            ):
                instruction = next_instruction
                continue
            materialized = _materialize_budget_predicate(block, ea=instruction.ea, match=match)
            if materialized is None:
                instruction = next_instruction
                continue
            output, helpers = materialized
            anchor = instruction.prev
            for helper in helpers:
                block.insert_into_block(helper, anchor)
                anchor = helper
            extension.l = dup_mop(output)
            instruction.swap(extension)
            changed += 1
            instruction = next_instruction
        if changed:
            block.mark_lists_dirty()
        return changed


__all__ = ["ModularProductNonzeroBlockRule", "make_ctz_helper_call"]
