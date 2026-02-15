"""Backend-agnostic IR for CFG snapshots.

PortableCFG provides frozen dataclass representations of control flow graphs
with no IDA dependency. Used for snapshot-based rollback and cross-backend
pass sharing.

The dataclasses in this module capture:
- Block topology (successors, predecessors, block type)
- Instruction sequences (via InsnSnapshot)
- Metadata for pass state tracking

All types are frozen (immutable) to ensure snapshot integrity.
"""
from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from d810.hexrays.mop_snapshot import MopSnapshot

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class InsnSnapshot:
    """Snapshot of a single microcode instruction.

    Captures opcode, address, and operands. Operands are stored as a tuple
    of MopSnapshot instances for immutability.

    Attributes:
        opcode: Microcode opcode (e.g., m_mov, m_add).
        ea: Effective address of the instruction.
        operands: Tuple of operand snapshots (MopSnapshot).

    Example:
        >>> snap = InsnSnapshot(opcode=0x01, ea=0x401000, operands=())
        >>> snap.opcode
        1
    """
    opcode: int
    ea: int
    operands: tuple[MopSnapshot, ...]

    def __post_init__(self) -> None:
        """Validate instruction snapshot."""
        if self.opcode < 0:
            raise ValueError(f"InsnSnapshot: opcode must be non-negative, got {self.opcode}")
        if self.ea < 0:
            raise ValueError(f"InsnSnapshot: ea must be non-negative, got {self.ea}")
        if not isinstance(self.operands, tuple):
            raise TypeError(f"InsnSnapshot: operands must be tuple, got {type(self.operands)}")

    def __repr__(self) -> str:
        return f"InsnSnapshot(op=0x{self.opcode:x}, ea=0x{self.ea:x}, nops={len(self.operands)})"


@dataclass(frozen=True)
class BlockSnapshot:
    """Snapshot of a single basic block's topology and instructions.

    Captures block metadata, control flow edges, and instruction sequence.
    Block type constants:
        BLT_0WAY = 0  (no successors, e.g., return)
        BLT_1WAY = 1  (unconditional jump)
        BLT_2WAY = 2  (conditional branch)
        BLT_NWAY = 3  (switch statement)

    Attributes:
        serial: Block serial number (unique within a function).
        block_type: Block type (0=0WAY, 1=1WAY, 2=2WAY, 3=NWAY).
        succs: Tuple of successor block serials.
        preds: Tuple of predecessor block serials.
        flags: Block flags (e.g., MBL_FAKE, MBL_GOTO).
        start_ea: Effective address of the first instruction.
        insn_snapshots: Tuple of instruction snapshots in block order.

    Example:
        >>> blk = BlockSnapshot(serial=0, block_type=1, succs=(1,), preds=(),
        ...                     flags=0, start_ea=0x401000, insn_snapshots=())
        >>> blk.nsucc
        1
    """
    serial: int
    block_type: int
    succs: tuple[int, ...]
    preds: tuple[int, ...]
    flags: int
    start_ea: int
    insn_snapshots: tuple[InsnSnapshot, ...]

    def __post_init__(self) -> None:
        """Validate block snapshot."""
        if self.serial < 0:
            raise ValueError(f"BlockSnapshot: serial must be non-negative, got {self.serial}")
        if self.block_type < 0 or self.block_type > 3:
            raise ValueError(f"BlockSnapshot: block_type must be 0-3, got {self.block_type}")
        if self.start_ea < 0:
            raise ValueError(f"BlockSnapshot: start_ea must be non-negative, got {self.start_ea}")
        if not isinstance(self.succs, tuple):
            raise TypeError(f"BlockSnapshot: succs must be tuple, got {type(self.succs)}")
        if not isinstance(self.preds, tuple):
            raise TypeError(f"BlockSnapshot: preds must be tuple, got {type(self.preds)}")
        if not isinstance(self.insn_snapshots, tuple):
            raise TypeError(f"BlockSnapshot: insn_snapshots must be tuple, got {type(self.insn_snapshots)}")

    @property
    def nsucc(self) -> int:
        """Number of successor blocks."""
        return len(self.succs)

    @property
    def npred(self) -> int:
        """Number of predecessor blocks."""
        return len(self.preds)

    def __repr__(self) -> str:
        return (f"BlockSnapshot(serial={self.serial}, type={self.block_type}, "
                f"succs={self.succs}, preds={self.preds}, "
                f"ninsns={len(self.insn_snapshots)})")


@dataclass(frozen=True)
class PortableCFG:
    """Complete snapshot of a control flow graph.

    Backend-agnostic representation that captures block topology,
    instructions, and metadata. Used for snapshot-based rollback
    and cross-backend pass sharing.

    Attributes:
        blocks: Mapping from block serial to BlockSnapshot.
        entry_serial: Serial number of the entry block.
        func_ea: Function effective address.
        metadata: Optional metadata dict for pass state tracking.

    Example:
        >>> entry = BlockSnapshot(serial=0, block_type=1, succs=(1,), preds=(),
        ...                       flags=0, start_ea=0x401000, insn_snapshots=())
        >>> exit_blk = BlockSnapshot(serial=1, block_type=0, succs=(), preds=(0,),
        ...                          flags=0, start_ea=0x401010, insn_snapshots=())
        >>> cfg = PortableCFG(blocks={0: entry, 1: exit_blk}, entry_serial=0, func_ea=0x401000)
        >>> cfg.num_blocks
        2
    """
    blocks: Mapping[int, BlockSnapshot]
    entry_serial: int
    func_ea: int
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate CFG snapshot and freeze mutable fields."""
        if self.func_ea < 0:
            raise ValueError(f"PortableCFG: func_ea must be non-negative, got {self.func_ea}")

        # Freeze mutable dict fields with MappingProxyType for true immutability
        object.__setattr__(self, 'blocks', MappingProxyType(dict(self.blocks)))
        object.__setattr__(self, 'metadata', MappingProxyType(dict(self.metadata)))

        # Entry serial must exist in blocks (unless empty CFG for test construction)
        if self.blocks and self.entry_serial not in self.blocks:
            raise ValueError(
                f"PortableCFG: entry_serial {self.entry_serial} not in blocks {list(self.blocks.keys())}"
            )

        # Warn about dangling edges (successors/predecessors not in blocks)
        # This is not an error since partial snapshots may omit some blocks
        for serial, blk in self.blocks.items():
            for succ in blk.succs:
                if succ not in self.blocks:
                    logger.warning(
                        f"PortableCFG: block {serial} references non-existent successor {succ}"
                    )
            for pred in blk.preds:
                if pred not in self.blocks:
                    logger.warning(
                        f"PortableCFG: block {serial} references non-existent predecessor {pred}"
                    )

    @property
    def num_blocks(self) -> int:
        """Number of blocks in the CFG."""
        return len(self.blocks)

    def get_block(self, serial: int) -> BlockSnapshot | None:
        """Retrieve block snapshot by serial number.

        Args:
            serial: Block serial number.

        Returns:
            BlockSnapshot if found, else None.
        """
        return self.blocks.get(serial)

    def successors(self, serial: int) -> tuple[int, ...]:
        """Get successor serials for a block.

        Args:
            serial: Block serial number.

        Returns:
            Tuple of successor serials (empty if block not found).
        """
        blk = self.blocks.get(serial)
        return blk.succs if blk else ()

    def predecessors(self, serial: int) -> tuple[int, ...]:
        """Get predecessor serials for a block.

        Args:
            serial: Block serial number.

        Returns:
            Tuple of predecessor serials (empty if block not found).
        """
        blk = self.blocks.get(serial)
        return blk.preds if blk else ()

    def as_adjacency_dict(self) -> dict[int, list[int]]:
        """Return adjacency dict (serial -> list of successor serials).

        Useful for graph algorithms that expect mutable adjacency representation.

        Returns:
            Dict mapping each block serial to a list of successor serials.
        """
        return {s: list(b.succs) for s, b in self.blocks.items()}

    def __repr__(self) -> str:
        return (f"PortableCFG(nblocks={self.num_blocks}, "
                f"entry={self.entry_serial}, func_ea=0x{self.func_ea:x})")


__all__ = [
    "InsnSnapshot",
    "BlockSnapshot",
    "PortableCFG",
]
