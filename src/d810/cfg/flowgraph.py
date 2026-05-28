"""Backend-agnostic IR for CFG snapshots (pure model layer)."""
from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType

from d810.core.logging import getLogger

logger = getLogger(__name__)


class BlockKind(Enum):
    """Backend-neutral block topology semantics."""

    UNKNOWN = "unknown"
    NONE = "none"
    STOP = "stop"
    EXTERNAL = "external"
    ZERO_WAY = "zero_way"
    ONE_WAY = "one_way"
    TWO_WAY = "two_way"
    N_WAY = "n_way"


class InsnKind(Enum):
    """Backend-neutral instruction semantics used by CFG planning."""

    UNKNOWN = "unknown"
    NOP = "nop"
    MOV = "mov"
    LOAD = "load"
    XDU = "xdu"
    XDS = "xds"
    ADD = "add"
    SUB = "sub"
    AND = "and"
    STORE = "store"
    GOTO = "goto"
    COND_JUMP = "cond_jump"
    EQUALITY_JUMP = "equality_jump"
    # E3-prep: portable kind for multi-target jump-table tails
    # (Hex-Rays ``m_jtbl``).  Dispatcher analyses key off this to
    # detect switch-table-style dispatchers without reaching for
    # vendor opcode constants.
    TABLE_JUMP = "table_jump"
    CALL = "call"
    RET = "ret"


class BranchPredicate(Enum):
    """Backend-neutral conditional branch predicate semantics."""

    TRUTHY = "truthy"
    EQUAL = "eq"
    NOT_EQUAL = "ne"
    UNSIGNED_GE = "uge"
    UNSIGNED_GT = "ugt"
    UNSIGNED_LE = "ule"
    UNSIGNED_LT = "ult"
    SIGNED_GE = "sge"
    SIGNED_GT = "sgt"
    SIGNED_LE = "sle"
    SIGNED_LT = "slt"


class OperandKind(Enum):
    """Backend-neutral operand semantics used by CFG planning."""

    UNKNOWN = "unknown"
    EMPTY = "empty"
    REGISTER = "register"
    NUMBER = "number"
    STRING = "string"
    SUBINSN = "subinsn"
    STACK = "stack"
    GLOBAL = "global"
    BLOCK = "block"
    ARG_LIST = "arg_list"
    LVAR = "lvar"
    ADDRESS = "address"
    HELPER = "helper"
    CASE_LIST = "case_list"
    FP_CONST = "fp_const"
    PAIR = "pair"
    SCATTERED = "scattered"


@dataclass(frozen=True, slots=True)
class MopSnapshot:
    """Frozen, backend-agnostic snapshot of an operand (pure model layer).

    This is a lightweight value type that lives in ``d810.cfg`` and carries
    no IDA imports.  The richer ``d810.hexrays.ir.mop_snapshot.MopSnapshot``
    (which owns an IDA mop_t clone) is a *superset* and satisfies the same
    structural interface.

    Capture helpers that bridge live IDA objects to this type live in
    ``d810.hexrays.mutation.ir_translator``.
    """

    t: int = -1                   # raw backend operand type; diagnostic only
    size: int = 0
    value: int | None = None      # mop_n: nnn.value
    stkoff: int | None = None     # mop_S/mop_str: s.off
    reg: int | None = None        # mop_r: r
    block_ref: int | None = None  # mop_b: b
    # E2a portable identity for dispatcher state-variable analysis.
    # Field names intentionally match the rich
    # ``d810.hexrays.ir.mop_snapshot.MopSnapshot`` variant so the
    # structural-superset claim in the docstring above stays true.
    gaddr: int | None = None      # mop_v: g (global address)
    lvar_off: int | None = None   # mop_l: l.off (lvar offset)
    # Switch-table case rows. Each row is ``(case_values, target_block)``;
    # an empty ``case_values`` tuple represents the default target.
    switch_cases: tuple[tuple[tuple[int, ...], int], ...] = ()
    # Stack offsets referenced by this operand, including nested expression
    # operands. This lets portable analyses find state variables inside
    # expression trees without retaining backend-owned sub-instructions.
    stack_refs: tuple[int, ...] = ()
    kind: OperandKind = OperandKind.UNKNOWN
    raw_operand_type: int | None = None

    def __post_init__(self) -> None:
        if self.raw_operand_type is None and self.t >= 0:
            object.__setattr__(self, "raw_operand_type", int(self.t))


@dataclass(frozen=True, slots=True)
class InsnSnapshot:
    """Snapshot of a single microcode instruction."""

    opcode: int
    ea: int
    operands: tuple[object, ...]
    operand_slots: tuple[tuple[str, object], ...] = ()
    # Human-readable backend rendering captured at lift time.  This is
    # transitional evidence for fact collectors that still parse rendered
    # microcode text while their structural operands are being ported.
    display_text: str = ""
    # Rich typed operand fields (populated by capture_insn_snapshot).
    l: MopSnapshot | None = None   # left operand
    r: MopSnapshot | None = None   # right operand
    d: MopSnapshot | None = None   # dest operand
    kind: InsnKind = InsnKind.UNKNOWN
    raw_opcode: int | None = None
    branch_predicate: BranchPredicate | None = None
    compare_width: int | None = None
    is_conditional_jump: bool = False
    is_unconditional_jump: bool = False
    is_call: bool = False

    def __post_init__(self) -> None:
        if self.raw_opcode is None and self.opcode >= 0:
            object.__setattr__(self, "raw_opcode", int(self.opcode))
        if self.opcode < 0 and self.raw_opcode is not None:
            object.__setattr__(self, "opcode", int(self.raw_opcode))
        if (
            self.branch_predicate is not None
            or self.kind in {InsnKind.COND_JUMP, InsnKind.EQUALITY_JUMP}
        ) and not self.is_conditional_jump:
            object.__setattr__(self, "is_conditional_jump", True)
        if self.kind is InsnKind.GOTO and not self.is_unconditional_jump:
            object.__setattr__(self, "is_unconditional_jump", True)
        if self.kind is InsnKind.CALL and not self.is_call:
            object.__setattr__(self, "is_call", True)
        if self.compare_width is None:
            operand_sizes: list[int] = []
            for operand in (self.l, self.r):
                try:
                    size = int(getattr(operand, "size", 0) or 0)
                except (TypeError, ValueError):
                    size = 0
                if size > 0:
                    operand_sizes.append(size)
            if operand_sizes:
                object.__setattr__(self, "compare_width", max(operand_sizes))
        if self.opcode < 0 and self.kind is InsnKind.UNKNOWN:
            raise ValueError(f"InsnSnapshot: opcode must be non-negative, got {self.opcode}")
        if self.ea < 0:
            raise ValueError(f"InsnSnapshot: ea must be non-negative, got {self.ea}")
        if not isinstance(self.operands, tuple):
            raise TypeError(f"InsnSnapshot: operands must be tuple, got {type(self.operands)}")
        if not isinstance(self.operand_slots, tuple):
            raise TypeError(
                f"InsnSnapshot: operand_slots must be tuple, got {type(self.operand_slots)}"
            )
        for slot_name, _operand in self.operand_slots:
            if slot_name not in ("l", "r", "d"):
                raise ValueError(
                    f"InsnSnapshot: operand_slots contains invalid slot {slot_name!r}"
                )

    def __repr__(self) -> str:
        op = self.raw_opcode if self.raw_opcode is not None else self.opcode
        return f"InsnSnapshot(kind={self.kind.value}, op=0x{op:x}, ea=0x{self.ea:x}, nops={len(self.operands)})"


@dataclass(frozen=True, slots=True)
class BlockSnapshot:
    """Snapshot of a single basic block topology and instructions."""

    serial: int
    block_type: int
    succs: tuple[int, ...]
    preds: tuple[int, ...]
    flags: int
    start_ea: int
    insn_snapshots: tuple[InsnSnapshot, ...]
    tail_opcode: int | None = None
    kind: BlockKind = BlockKind.UNKNOWN
    tail_kind: InsnKind | None = None
    raw_block_type: int | None = None
    raw_tail_opcode: int | None = None

    def __post_init__(self) -> None:
        if self.serial < 0:
            raise ValueError(f"BlockSnapshot: serial must be non-negative, got {self.serial}")
        if self.raw_block_type is None and self.block_type >= 0:
            object.__setattr__(self, "raw_block_type", int(self.block_type))
        if self.block_type < 0 and self.raw_block_type is not None:
            object.__setattr__(self, "block_type", int(self.raw_block_type))
        if self.block_type < 0 and self.kind is BlockKind.UNKNOWN:
            raise ValueError(f"BlockSnapshot: block_type must be non-negative, got {self.block_type}")
        if self.start_ea < 0:
            raise ValueError(f"BlockSnapshot: start_ea must be non-negative, got {self.start_ea}")
        if not isinstance(self.succs, tuple):
            raise TypeError(f"BlockSnapshot: succs must be tuple, got {type(self.succs)}")
        if not isinstance(self.preds, tuple):
            raise TypeError(f"BlockSnapshot: preds must be tuple, got {type(self.preds)}")
        if not isinstance(self.insn_snapshots, tuple):
            raise TypeError(
                f"BlockSnapshot: insn_snapshots must be tuple, got {type(self.insn_snapshots)}"
            )
        if self.kind is BlockKind.UNKNOWN:
            if len(self.succs) == 2:
                object.__setattr__(self, "kind", BlockKind.TWO_WAY)
            elif len(self.succs) == 1:
                object.__setattr__(self, "kind", BlockKind.ONE_WAY)
            elif len(self.succs) == 0:
                object.__setattr__(self, "kind", BlockKind.ZERO_WAY)
        if self.tail_opcode is None and self.insn_snapshots:
            object.__setattr__(self, "tail_opcode", int(self.insn_snapshots[-1].opcode))
        if self.raw_tail_opcode is None and self.tail_opcode is not None:
            object.__setattr__(self, "raw_tail_opcode", int(self.tail_opcode))
        if self.tail_kind is None and self.insn_snapshots:
            object.__setattr__(self, "tail_kind", self.insn_snapshots[-1].kind)

    @property
    def nsucc(self) -> int:
        return len(self.succs)

    @property
    def npred(self) -> int:
        return len(self.preds)

    def iter_insns(self) -> Iterator[InsnSnapshot]:
        """Iterate over instruction snapshots in this block."""
        return iter(self.insn_snapshots)

    @property
    def head(self) -> InsnSnapshot | None:
        """First instruction snapshot, or ``None`` if the block is empty."""
        return self.insn_snapshots[0] if self.insn_snapshots else None

    @property
    def tail(self) -> InsnSnapshot | None:
        """Last instruction snapshot, or ``None`` if the block is empty."""
        return self.insn_snapshots[-1] if self.insn_snapshots else None

    def __repr__(self) -> str:
        return (
            f"BlockSnapshot(serial={self.serial}, kind={self.kind.value}, type={self.block_type}, "
            f"succs={self.succs}, preds={self.preds}, "
            f"ninsns={len(self.insn_snapshots)})"
        )


@dataclass(frozen=True, slots=True)
class FlowGraph:
    """Complete snapshot of a control flow graph."""

    blocks: Mapping[int, BlockSnapshot]
    entry_serial: int
    func_ea: int
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.func_ea < 0:
            raise ValueError(f"PortableCFG: func_ea must be non-negative, got {self.func_ea}")

        object.__setattr__(self, "blocks", MappingProxyType(dict(self.blocks)))
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

        if self.blocks and self.entry_serial not in self.blocks:
            raise ValueError(
                f"PortableCFG: entry_serial {self.entry_serial} not in blocks {list(self.blocks.keys())}"
            )

        for serial, blk in self.blocks.items():
            for succ in blk.succs:
                if succ not in self.blocks:
                    logger.warning(
                        "PortableCFG: block %s references non-existent successor %s", serial, succ
                    )
            for pred in blk.preds:
                if pred not in self.blocks:
                    logger.warning(
                        "PortableCFG: block %s references non-existent predecessor %s", serial, pred
                    )

    @property
    def num_blocks(self) -> int:
        return len(self.blocks)

    @property
    def block_count(self) -> int:
        """Alias for :attr:`num_blocks` (K3 compatibility with mba.qty)."""
        return len(self.blocks)

    def get_block(self, serial: int) -> BlockSnapshot | None:
        return self.blocks.get(serial)

    def successors(self, serial: int) -> tuple[int, ...]:
        blk = self.blocks.get(serial)
        return blk.succs if blk else ()

    def predecessors(self, serial: int) -> tuple[int, ...]:
        blk = self.blocks.get(serial)
        return blk.preds if blk else ()

    def as_adjacency_dict(self) -> dict[int, list[int]]:
        return {s: list(b.succs) for s, b in self.blocks.items()}

    def __repr__(self) -> str:
        return (
            f"PortableCFG(nblocks={self.num_blocks}, "
            f"entry={self.entry_serial}, func_ea=0x{self.func_ea:x})"
        )


__all__ = [
    "BranchPredicate",
    "BlockKind",
    "InsnKind",
    "OperandKind",
    "MopSnapshot",
    "InsnSnapshot",
    "BlockSnapshot",
    "FlowGraph",
]
