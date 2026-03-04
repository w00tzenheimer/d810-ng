"""Backend-agnostic IR for CFG snapshots (pure model layer)."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from d810.core.logging import getLogger

logger = getLogger(__name__)


@dataclass(frozen=True, slots=True)
class InsnSnapshot:
    """Snapshot of a single microcode instruction."""

    opcode: int
    ea: int
    operands: tuple[object, ...]

    def __post_init__(self) -> None:
        if self.opcode < 0:
            raise ValueError(f"InsnSnapshot: opcode must be non-negative, got {self.opcode}")
        if self.ea < 0:
            raise ValueError(f"InsnSnapshot: ea must be non-negative, got {self.ea}")
        if not isinstance(self.operands, tuple):
            raise TypeError(f"InsnSnapshot: operands must be tuple, got {type(self.operands)}")

    def __repr__(self) -> str:
        return f"InsnSnapshot(op=0x{self.opcode:x}, ea=0x{self.ea:x}, nops={len(self.operands)})"


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

    def __post_init__(self) -> None:
        if self.serial < 0:
            raise ValueError(f"BlockSnapshot: serial must be non-negative, got {self.serial}")
        if self.block_type < 0 or self.block_type > 6:
            raise ValueError(f"BlockSnapshot: block_type must be 0-6, got {self.block_type}")
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

    @property
    def nsucc(self) -> int:
        return len(self.succs)

    @property
    def npred(self) -> int:
        return len(self.preds)

    def __repr__(self) -> str:
        return (
            f"BlockSnapshot(serial={self.serial}, type={self.block_type}, "
            f"succs={self.succs}, preds={self.preds}, "
            f"ninsns={len(self.insn_snapshots)})"
        )


@dataclass(frozen=True, slots=True)
class PortableCFG:
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


__all__ = ["InsnSnapshot", "BlockSnapshot", "PortableCFG"]
