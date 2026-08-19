"""Fail-closed native lowering for bounded finite-zero-set predicates."""

from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

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
from d810.hexrays.utils.hexrays_helpers import dup_mop, structural_mop_hash
from d810.ir.maturity import IRMaturity
from d810.hexrays.mutation.instruction_commit import NativeEpoch
from d810.optimizers.microcode.instructions.block_handler import (
    HostedBlockInstructionRule,
)
from d810.optimizers.microcode.instructions.peephole.predicate_root_recovery import (
    Binary,
    Constant,
    Expression,
    FiniteZeroSetPredicateRule,
    Predicate,
    Unary,
    Variable,
    recover_finite_zero_set_predicate,
    z3_proves_finite_zero_set_predicate,
)


_BINARY_OPS = {
    ida_hexrays.m_add: "add",
    ida_hexrays.m_sub: "sub",
    ida_hexrays.m_mul: "mul",
    ida_hexrays.m_and: "and",
    ida_hexrays.m_or: "or",
}


def _width(mop: ida_hexrays.mop_t | None) -> int:
    return 0 if mop is None else int(mop.size) * 8


def _expression_from_mop(mop: ida_hexrays.mop_t | None) -> Expression | None:
    """Lift only the typed vocabulary admitted by the pure rule."""

    width = _width(mop)
    if mop is None or width not in {8, 32}:
        return None
    if mop.t == ida_hexrays.mop_n:
        return Constant(int(mop.nnn.value) & ((1 << width) - 1), width, source=mop)
    # Hex-Rays represents `low8(ecx)` as the physical `cl` register, not as a
    # nested m_low in this fixture. Reconstruct that *typed* relation only for
    # a byte register with an exact 32-bit parent register identity.
    if width == 8 and mop.t == ida_hexrays.mop_r:
        try:
            parent = ida_hexrays.mop_t()
            parent.make_reg(mop.r, 4)
            return Unary(
                "low8",
                8,
                Variable(str(structural_mop_hash(parent)), 32, source=parent),
                source=mop,
            )
        except Exception:
            return None
    if mop.t == ida_hexrays.mop_d and mop.d is not None:
        ins = mop.d
        if ins.opcode in _BINARY_OPS:
            left = _expression_from_mop(ins.l)
            right = _expression_from_mop(ins.r)
            if left is None or right is None or left.width != width or right.width != width:
                return None
            return Binary(_BINARY_OPS[ins.opcode], width, left, right, source=mop)
        if ins.opcode == ida_hexrays.m_bnot:
            operand = _expression_from_mop(ins.l)
            return Unary("bnot", width, operand, source=mop) if operand is not None else None
        if ins.opcode == ida_hexrays.m_low and width == 8:
            operand = _expression_from_mop(ins.l)
            return Unary("low8", 8, operand, source=mop) if operand is not None and operand.width == 32 else None
        if ins.opcode == ida_hexrays.m_xdu and width == 32:
            operand = _expression_from_mop(ins.l)
            if operand is None or operand.width != 8:
                return None
            return Binary("zext", 32, operand, None, source=mop)
    return Variable(str(structural_mop_hash(mop)), width, source=mop)


def _predicate_from_instruction(ins: ida_hexrays.minsn_t) -> Predicate | None:
    if ins.opcode != ida_hexrays.m_setnz or _width(ins.d) != 8:
        return None
    left = _expression_from_mop(ins.l)
    right = _expression_from_mop(ins.r)
    if left is None or right is None or left.width != 32 or right.width != 32:
        return None
    # The microcode builder may canonicalize `(left - right) != 0` into the
            # comparison form `left != right`. Keep the pure contract rooted at zero.
    return Predicate(
        "ne",
        Binary("sub", 32, left, right, source=ins),
        Constant(0, 32),
        1,
        source=ins,
    )


def _effect_free_variable(variable: Variable) -> bool:
    source = variable.source
    if not isinstance(source, ida_hexrays.mop_t) or _width(source) != 32:
        return False
    try:
        return not source.has_side_effects(False)
    except Exception:
        return False


def _fresh_byte_kreg(
    context: BlockInstructionMaterializationContext,
) -> ida_hexrays.mop_t | None:
    try:
        register = context.alloc_kreg(1)
        if register == ida_hexrays.mr_none:
            return None
        output = ida_hexrays.mop_t()
        output.make_reg(register, 1)
        return output
    except Exception:
        return None


def _number(value: int, ea: int) -> ida_hexrays.mop_t:
    result = ida_hexrays.mop_t()
    result.make_number(value & 0xFFFFFFFF, 4, ea)
    return result


def _setnz(
    ea: int,
    variable: ida_hexrays.mop_t,
    excluded: int,
    output: ida_hexrays.mop_t,
) -> ida_hexrays.minsn_t:
    result = ida_hexrays.minsn_t(ea)
    result.opcode = ida_hexrays.m_setnz
    result.l = dup_mop(variable)
    result.r = _number(excluded, ea)
    result.d = dup_mop(output)
    return result


def _and(
    ea: int,
    left: ida_hexrays.mop_t,
    right: ida_hexrays.mop_t,
    output: ida_hexrays.mop_t,
) -> ida_hexrays.minsn_t:
    result = ida_hexrays.minsn_t(ea)
    result.opcode = ida_hexrays.m_and
    result.l = dup_mop(left)
    result.r = dup_mop(right)
    result.d = dup_mop(output)
    return result


@dataclass(frozen=True, slots=True)
class _DetachedFiniteZeroSetMatch:
    source: MopSnapshot
    excluded_values: tuple[int, int]
    extension_kind: str | None


@dataclass(frozen=True, slots=True)
class _FiniteZeroSetMaterializer:
    """Materialize one already-proven finite-zero-set replacement."""

    evidence: _DetachedFiniteZeroSetMatch

    def materialize(
        self,
        context: BlockInstructionMaterializationContext,
    ) -> MaterializedBlockInstructionEdit | None:
        instruction = context.instruction
        try:
            source = self.evidence.source.to_mop(getattr(context.block, "mba", None))
        except Exception:
            return None
        if not isinstance(source, ida_hexrays.mop_t):
            return None
        first = _fresh_byte_kreg(context)
        second = _fresh_byte_kreg(context)
        if first is None or second is None:
            return None

        comparisons = (
            _setnz(
                instruction.ea,
                source,
                self.evidence.excluded_values[0],
                first,
            ),
            _setnz(
                instruction.ea,
                source,
                self.evidence.excluded_values[1],
                second,
            ),
        )
        if self.evidence.extension_kind is None:
            replacement = _and(
                instruction.ea,
                first,
                second,
                instruction.d,
            )
            return MaterializedBlockInstructionEdit(
                replacement=replacement,
                insert_before=comparisons,
            )

        if self.evidence.extension_kind == "direct":
            extension = ida_hexrays.minsn_t(instruction)
        else:
            child = getattr(getattr(instruction, "l", None), "d", None)
            if child is None:
                return None
            extension = ida_hexrays.minsn_t(child)
        predicate_output = _fresh_byte_kreg(context)
        if predicate_output is None:
            return None
        replacement = _and(
            instruction.ea,
            first,
            second,
            predicate_output,
        )
        extension.l = dup_mop(predicate_output)
        if self.evidence.extension_kind == "direct":
            root = extension
        else:
            wrapped = ida_hexrays.mop_t()
            wrapped.create_from_insn(extension)
            root = ida_hexrays.minsn_t(instruction)
            root.l = wrapped
        return MaterializedBlockInstructionEdit(
            replacement=root,
            insert_before=comparisons + (replacement,),
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


class FiniteZeroSetPredicateBlockRule(HostedBlockInstructionRule):
    """Lower proven ``E(x) != 0`` into the recovered exclusion predicate."""

    DESCRIPTION = "Recover bounded finite-zero-set predicates"
    PATTERN = FiniteZeroSetPredicateRule.PATTERN
    CONSTRAINTS = FiniteZeroSetPredicateRule.CONSTRAINTS
    REPLACEMENT = FiniteZeroSetPredicateRule.REPLACEMENT

    def __init__(self) -> None:
        super().__init__()
        # A plain function may not receive another optblock callback after
        # CALLS if Hex-Rays has no later block-level work to request.  The
        # proven predicate is already in its admissible typed form at CALLS,
        # so schedule the lift at the first callback maturity and retain the
        # later passes as a fail-safe for shapes that canonicalize later.
        self.maturities = [
            ida_hexrays.MMAT_CALLS,
            ida_hexrays.MMAT_GLBOPT1,
            ida_hexrays.MMAT_GLBOPT2,
        ]

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
                    "FiniteZeroSetPredicateBlockRule maturities must be IRMaturity names"
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
            # At GLBOPT2 this often arrives as
            # `mov xdu(m_setnz(...)), result64`, so identify the comparison
            # under the legal width extension rather than assuming it is a
            # standalone instruction.
            extension_kind: str | None = None
            predicate_instruction = instruction
            if (
                instruction.opcode == ida_hexrays.m_xdu
                and instruction.l.t == ida_hexrays.mop_d
                and instruction.l.d is not None
            ):
                extension_kind = "direct"
                predicate_instruction = instruction.l.d
            elif (
                instruction.opcode == ida_hexrays.m_mov
                and instruction.l.t == ida_hexrays.mop_d
                and instruction.l.d is not None
                and instruction.l.d.opcode == ida_hexrays.m_xdu
                and instruction.l.d.l.t == ida_hexrays.mop_d
                and instruction.l.d.l.d is not None
            ):
                extension_kind = "wrapped"
                predicate_instruction = instruction.l.d.l.d
            predicate = _predicate_from_instruction(predicate_instruction)
            match = (
                recover_finite_zero_set_predicate(predicate)
                if predicate is not None
                else None
            )
            if (
                match is None
                or len(match.excluded_values) != 2
                or not _effect_free_variable(match.variable)
                or not z3_proves_finite_zero_set_predicate(predicate, match)
            ):
                continue
            source = getattr(match.variable, "source", None)
            if not isinstance(source, ida_hexrays.mop_t):
                continue
            try:
                evidence = _DetachedFiniteZeroSetMatch(
                    source=MopSnapshot.from_mop(source),
                    excluded_values=tuple(
                        int(value) for value in match.excluded_values
                    ),
                    extension_kind=extension_kind,
                )
            except Exception:
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
                        materializer=_FiniteZeroSetMaterializer(evidence),
                        description="finite-zero-set predicate recovery",
                    ),
                ),
                epoch_before=epoch,
                pass_id="finite-zero-set-predicate",
                stage_id="finite-zero-set-predicate",
                rule_id=self.name,
            )
        return None


__all__ = ["FiniteZeroSetPredicateBlockRule"]
