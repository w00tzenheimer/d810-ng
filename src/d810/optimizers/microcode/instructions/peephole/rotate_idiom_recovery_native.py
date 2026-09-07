"""Hex-Rays lowering for the exact 64-bit multiply/shift rotate idiom."""

from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.core import typing
from d810.hexrays.ir_maturity import ir_maturity_to_ida
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.hexrays.mutation.block_instruction_commit import (
    BlockInstructionAnchor,
    BlockInstructionBatchCandidate,
    BlockInstructionEditIntent,
    BlockInstructionMaterializationContext,
    MaterializedBlockInstructionEdit,
)
from d810.hexrays.utils.hexrays_helpers import dup_mop, structural_mop_hash
from d810.hexrays.mutation.instruction_commit import (
    NativeEpoch,
    fingerprint_minsn,
)
from d810.backends.mba.native_rotate_helper import (
    make_rol8_helper_call as _make_rol8_helper_call,
)
from d810.ir.maturity import IRMaturity
from d810.optimizers.microcode.instructions.block_handler import (
    HostedBlockInstructionRule,
)
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeSimplificationRule,
)
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

    try:
        normalized_rotation = int(rotation)
    except (TypeError, ValueError, OverflowError):
        return None
    if not 1 <= normalized_rotation < 64:
        return None
    return _make_rol8_helper_call(
        block,
        ea=ea,
        base=base,
        rotation=normalized_rotation,
        output=output,
    )


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


@dataclass(frozen=True, slots=True)
class _DetachedRotateRoot:
    """Callback-local rotate evidence with no borrowed native source object."""

    path: tuple[str, ...] | None
    base: MopSnapshot
    rotation: int
    instruction_ea: int


def _detached_rotate_root(
    *,
    path: tuple[str, ...] | None,
    match: RotateIdiomMatch,
    base_mop: ida_hexrays.mop_t,
    instruction_ea: int,
) -> _DetachedRotateRoot | None:
    """Capture the exact native helper input before the callback returns."""

    try:
        base = MopSnapshot.from_mop(base_mop)
    except Exception:
        return None
    return _DetachedRotateRoot(
        path=path,
        base=base,
        rotation=int(match.rotation),
        instruction_ea=int(instruction_ea),
    )


def _nested_rotate_roots(
    mop: ida_hexrays.mop_t | None,
    *,
    path: tuple[str, ...],
    instruction_ea: int,
) -> tuple[_DetachedRotateRoot, ...]:
    """Find exact rotate values below one instruction without native writes."""

    if mop is None or mop.t != ida_hexrays.mop_d or mop.d is None:
        return ()
    candidate = _validated_native_match(_expression_from_mop(mop))
    if candidate is not None:
        match, base_mop = candidate
        root = _detached_rotate_root(
            path=path,
            match=match,
            base_mop=base_mop,
            instruction_ea=instruction_ea,
        )
        return () if root is None else (root,)

    nested: list[_DetachedRotateRoot] = []
    nested.extend(
        _nested_rotate_roots(
            mop.d.l,
            path=path + ("d", "l"),
            instruction_ea=instruction_ea,
        )
    )
    nested.extend(
        _nested_rotate_roots(
            mop.d.r,
            path=path + ("d", "r"),
            instruction_ea=instruction_ea,
        )
    )
    return tuple(nested)


def _rotate_roots_for_instruction(
    instruction: ida_hexrays.minsn_t,
) -> tuple[_DetachedRotateRoot, ...]:
    """Collect one instruction's direct or nested rotate roots."""

    instruction_ea = int(instruction.ea)
    direct = _validated_native_match(_expression_from_instruction(instruction))
    if direct is not None:
        match, base_mop = direct
        root = _detached_rotate_root(
            path=None,
            match=match,
            base_mop=base_mop,
            instruction_ea=instruction_ea,
        )
        return () if root is None else (root,)

    roots: list[_DetachedRotateRoot] = []
    roots.extend(
        _nested_rotate_roots(
            instruction.l,
            path=("l",),
            instruction_ea=instruction_ea,
        )
    )
    roots.extend(
        _nested_rotate_roots(
            instruction.r,
            path=("r",),
            instruction_ea=instruction_ea,
        )
    )
    return tuple(roots)


def _fresh_kreg_output_from_context(
    context: BlockInstructionMaterializationContext,
    size: int = 8,
) -> ida_hexrays.mop_t | None:
    """Allocate a helper result through the backend-owned ledger port."""

    try:
        kreg = context.alloc_kreg(size)
        if kreg is None or kreg == ida_hexrays.mr_none:
            return None
        result = ida_hexrays.mop_t()
        result.make_reg(kreg, size)
        return result
    except Exception:
        return None


def _helper_call_from_detached_root(
    block: ida_hexrays.mblock_t,
    *,
    root: _DetachedRotateRoot,
    output: ida_hexrays.mop_t,
) -> ida_hexrays.minsn_t | None:
    """Materialize a helper from snapshots, never from proposal-time mops."""

    try:
        base = root.base.to_mop(getattr(block, "mba", None))
    except Exception:
        return None
    return make_rol8_helper_call(
        block,
        ea=root.instruction_ea,
        base=base,
        rotation=root.rotation,
        output=output,
    )


def _replace_mop_at_path(
    instruction: ida_hexrays.minsn_t,
    path: tuple[str, ...],
    replacement: ida_hexrays.mop_t,
) -> bool:
    """Replace one nested operand in a detached instruction copy."""

    if not path:
        return False
    owner: object = instruction
    try:
        for attribute in path[:-1]:
            owner = getattr(owner, attribute)
        setattr(owner, path[-1], replacement)
    except Exception:
        return False
    return True


@dataclass(frozen=True, slots=True)
class _RotateInstructionMaterializer:
    """Backend-owned materializer for all rotate roots in one source instruction."""

    roots: tuple[_DetachedRotateRoot, ...]

    def materialize(
        self,
        context: BlockInstructionMaterializationContext,
    ) -> MaterializedBlockInstructionEdit | None:
        if not self.roots:
            return None
        instruction = context.instruction
        block = context.block
        if any(root.path is None for root in self.roots):
            if len(self.roots) != 1 or self.roots[0].path is not None:
                return None
            root = self.roots[0]
            replacement = _helper_call_from_detached_root(
                block,
                root=root,
                output=instruction.d,
            )
            if replacement is None:
                return None
            return MaterializedBlockInstructionEdit(replacement=replacement)

        try:
            replacement = ida_hexrays.minsn_t(instruction)
        except Exception:
            return None
        helpers: list[ida_hexrays.minsn_t] = []
        for root in self.roots:
            if root.path is None:
                return None
            output = _fresh_kreg_output_from_context(context)
            if output is None:
                return None
            helper = _helper_call_from_detached_root(
                block,
                root=root,
                output=output,
            )
            if helper is None or not _replace_mop_at_path(
                replacement,
                root.path,
                dup_mop(output),
            ):
                return None
            helpers.append(helper)
        return MaterializedBlockInstructionEdit(
            replacement=replacement,
            insert_before=tuple(helpers),
        )


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


class RotateIdiomRecoveryBlockRule(HostedBlockInstructionRule):
    """Propose hosted edits for every GLBOPT2 instruction with a rotate root."""

    DESCRIPTION = "Recover exact 64-bit multiply/shift rotate idioms as __ROL8__"

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
                    "RotateIdiomRecoveryBlockRule maturities must be IRMaturity names"
                ) from exc

    def propose_instruction_batch(
        self,
        block: ida_hexrays.mblock_t,
        *,
        epoch: NativeEpoch,
    ) -> BlockInstructionBatchCandidate | None:
        """Capture a complete block proposal without allocating or mutating."""

        if block is None or getattr(block, "mba", None) is None:
            return None
        if not isinstance(epoch, NativeEpoch):
            return None

        edits: list[BlockInstructionEditIntent] = []
        instruction = getattr(block, "head", None)
        ordinal = 0
        seen: set[int] = set()
        while instruction is not None and id(instruction) not in seen:
            seen.add(id(instruction))
            roots = _rotate_roots_for_instruction(instruction)
            if roots:
                try:
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
                except (AttributeError, TypeError, ValueError):
                    return None
                edits.append(
                    BlockInstructionEditIntent(
                        anchor=anchor,
                        materializer=_RotateInstructionMaterializer(roots),
                        description="recover 64-bit rotate idiom",
                    )
                )
            if instruction is getattr(block, "tail", None):
                break
            instruction = getattr(instruction, "next", None)
            ordinal += 1

        if not edits:
            return None
        return BlockInstructionBatchCandidate(
            edits=tuple(edits),
            epoch_before=epoch,
            pass_id="rotate-idiom-recovery",
            stage_id="rotate-idiom-recovery",
            rule_id=self.name,
        )
