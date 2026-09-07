"""Native lowering for Z3-proven modular-product nonzero predicates."""

from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays
import ida_typeinf

from d810.core.pass_ids import PassId
from d810.hexrays.mutation.block_instruction_commit import (
    BlockInstructionAnchor,
    BlockInstructionBatchCandidate,
    BlockInstructionEditIntent,
    BlockInstructionMaterializationContext,
    MaterializedBlockInstructionEdit,
    fingerprint_minsn,
)
from d810.hexrays.ir_maturity import ir_maturity_to_ida
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.hexrays.utils.hexrays_helpers import dup_mop
from d810.ir.maturity import IRMaturity
from d810.hexrays.mutation.instruction_commit import NativeEpoch
from d810.optimizers.microcode.instructions.block_handler import (
    HostedBlockInstructionRule,
)
from d810.optimizers.microcode.instructions.peephole.modular_product_nonzero import (
    ModularProductNonzeroMatch,
    certifies_modular_product_nonzero,
    recover_modular_product_nonzero,
)
from d810.optimizers.microcode.instructions.peephole.predicate_root_recovery import (
    Constant,
    Predicate,
)
from d810.optimizers.microcode.instructions.peephole.predicate_root_recovery_native import (
    _effect_free_variable,
    _expression_from_mop,
)


def _uint32_type() -> ida_typeinf.tinfo_t:
    """Create type information owned by the currently open IDB lifetime."""

    result = ida_typeinf.tinfo_t()
    result.create_simple_type(ida_typeinf.BTF_UINT32)
    return result


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


def _fresh_kreg(
    context: BlockInstructionMaterializationContext,
    size: int,
) -> ida_hexrays.mop_t | None:
    try:
        register = context.alloc_kreg(size)
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
        uint32_type = _uint32_type()
        argument = ida_hexrays.mcallarg_t()
        argument.copy_mop(dup_mop(value))
        argument.type = uint32_type
        arguments = ida_hexrays.mcallargs_t()
        arguments.push_back(argument)
        return block.mba.create_helper_call(
            ea,
            "__ctz",
            uint32_type,
            arguments,
            dup_mop(output),
        )
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
    context: BlockInstructionMaterializationContext,
    *,
    ea: int,
    match: "_DetachedModularProductMatch",
) -> tuple[ida_hexrays.mop_t, tuple[ida_hexrays.minsn_t, ...]] | None:
    """Materialize ``sum(ctz(factor)) < budget`` before the root instruction."""

    try:
        source_factors = tuple(
            factor.to_mop(getattr(context.block, "mba", None))
            for factor in match.factors
        )
    except Exception:
        return None
    if any(not isinstance(factor, ida_hexrays.mop_t) or _width(factor) != 32 for factor in source_factors):
        return None
    try:
        if any(factor.has_side_effects(False) for factor in source_factors):
            return None
    except Exception:
        return None
    ctz_outputs = tuple(_fresh_kreg(context, 4) for _ in source_factors)
    if any(output is None for output in ctz_outputs):
        return None
    helpers = tuple(
        make_ctz_helper_call(context.block, ea=ea, value=factor, output=output)
        for factor, output in zip(source_factors, ctz_outputs, strict=True)
    )
    if any(helper is None for helper in helpers):
        return None
    instructions = [helper for helper in helpers if helper is not None]
    total = ctz_outputs[0]
    for value in ctz_outputs[1:]:
        output = _fresh_kreg(context, 4)
        if output is None:
            return None
        instructions.append(_binary(ida_hexrays.m_add, ea, total, value, output))
        total = output
    predicate_output = _fresh_kreg(context, 1)
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


@dataclass(frozen=True, slots=True)
class _DetachedModularProductMatch:
    trailing_zero_budget: int
    factors: tuple[MopSnapshot, ...]


@dataclass(frozen=True, slots=True)
class _ModularProductMaterializer:
    """Materialize one already-proven modular-product replacement."""

    evidence: _DetachedModularProductMatch

    def materialize(
        self,
        context: BlockInstructionMaterializationContext,
    ) -> MaterializedBlockInstructionEdit | None:
        instruction = context.instruction
        materialized = _materialize_budget_predicate(
            context,
            ea=int(instruction.ea),
            match=self.evidence,
        )
        if materialized is None:
            return None
        output, helpers = materialized
        replacement = ida_hexrays.minsn_t(instruction)
        replacement.l = dup_mop(output)
        return MaterializedBlockInstructionEdit(
            replacement=replacement,
            insert_before=helpers,
        )


def _block_instructions(block: ida_hexrays.mblock_t) -> tuple[ida_hexrays.minsn_t, ...]:
    instructions: list[ida_hexrays.minsn_t] = []
    instruction = block.head
    seen: set[int] = set()
    while instruction is not None and id(instruction) not in seen:
        seen.add(id(instruction))
        instructions.append(instruction)
        if instruction is block.tail:
            break
        instruction = instruction.next
    return tuple(instructions)


class ModularProductNonzeroBlockRule(HostedBlockInstructionRule):
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

    def propose_instruction_batch(
        self,
        block: ida_hexrays.mblock_t,
        *,
        epoch: NativeEpoch,
    ) -> BlockInstructionBatchCandidate | None:
        if (
            block is None
            or getattr(block, "mba", None) is None
            or not isinstance(epoch, NativeEpoch)
        ):
            return None
        for ordinal, instruction in enumerate(_block_instructions(block)):
            if (
                instruction.opcode != ida_hexrays.m_xdu
                or instruction.l.t != ida_hexrays.mop_d
                or instruction.l.d is None
            ):
                continue
            predicate = _predicate_from_instruction(instruction.l.d)
            match = (
                recover_modular_product_nonzero(predicate)
                if predicate is not None
                else None
            )
            if (
                match is None
                or not _effect_free_variable(match.variable)
                or not certifies_modular_product_nonzero(predicate, match)
            ):
                continue
            try:
                evidence = _DetachedModularProductMatch(
                    trailing_zero_budget=int(match.trailing_zero_budget),
                    factors=tuple(
                        MopSnapshot.from_mop(factor.source)
                        for factor in match.factors
                        if isinstance(factor.source, ida_hexrays.mop_t)
                    ),
                )
            except Exception:
                continue
            if len(evidence.factors) != len(match.factors):
                continue
            anchor = BlockInstructionAnchor(
                block_serial=int(block.serial),
                block_start_ea=int(block.start),
                ordinal=ordinal,
                instruction_ea=int(instruction.ea),
                opcode=int(instruction.opcode),
                before_fingerprint=fingerprint_minsn(
                    instruction,
                    epoch.function_ea,
                ),
            )
            return BlockInstructionBatchCandidate(
                edits=(
                    BlockInstructionEditIntent(
                        anchor=anchor,
                        materializer=_ModularProductMaterializer(evidence),
                        description="modular-product nonzero recovery",
                    ),
                ),
                epoch_before=epoch,
                pass_id=PassId.MBA_SIMPLIFY.value,
                stage_id="modular-product-nonzero",
                rule_id=self.name,
            )
        return None


__all__ = ["ModularProductNonzeroBlockRule", "make_ctz_helper_call"]
